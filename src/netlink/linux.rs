//! Linux nl80211 socket and [`Link`] implementation.

#![cfg(target_os = "linux")]

use std::io;
use std::os::unix::io::RawFd;
use std::time::{Duration, Instant};

use super::msg::{self, Attr, GenlMessage};
use super::*;
use crate::dot11;
use crate::raw_frames::Link;

/// A generic-netlink socket bound to a unique port id.
struct NetlinkSocket {
    fd: RawFd,
    pid: u32,
    seq: u32,
}

impl Drop for NetlinkSocket {
    fn drop(&mut self) {
        // Close the fd so kernel objects owned via NL80211_ATTR_SOCKET_OWNER
        // (interfaces, started APs) are torn down promptly, not only at exit.
        unsafe { libc::close(self.fd) };
    }
}

impl NetlinkSocket {
    fn open() -> io::Result<NetlinkSocket> {
        unsafe {
            let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_GENERIC);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // Bind with pid 0 -> the kernel assigns a unique port id.
            let mut sa: libc::sockaddr_nl = std::mem::zeroed();
            sa.nl_family = libc::AF_NETLINK as u16;
            if libc::bind(
                fd,
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            ) < 0
            {
                libc::close(fd);
                return Err(io::Error::last_os_error());
            }
            // Read back the assigned pid.
            let mut len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            libc::getsockname(fd, &mut sa as *mut _ as *mut libc::sockaddr, &mut len);
            // Ask the kernel for extended ACK (human-readable error strings).
            const SOL_NETLINK: libc::c_int = 270;
            const NETLINK_EXT_ACK: libc::c_int = 11;
            let on: libc::c_int = 1;
            libc::setsockopt(
                fd,
                SOL_NETLINK,
                NETLINK_EXT_ACK,
                &on as *const _ as *const libc::c_void,
                4,
            );
            Ok(NetlinkSocket {
                fd,
                pid: sa.nl_pid,
                seq: 1,
            })
        }
    }

    fn next_seq(&mut self) -> u32 {
        let s = self.seq;
        self.seq += 1;
        s
    }

    fn send(&self, bytes: &[u8]) -> io::Result<()> {
        unsafe {
            // destination: the kernel (pid 0, groups 0)
            let mut dst: libc::sockaddr_nl = std::mem::zeroed();
            dst.nl_family = libc::AF_NETLINK as u16;
            let n = libc::sendto(
                self.fd,
                bytes.as_ptr() as *const libc::c_void,
                bytes.len(),
                0,
                &dst as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            );
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    /// Receive one datagram, waiting up to `timeout`. Returns the raw buffer.
    fn recv(&self, timeout: Duration) -> Option<Vec<u8>> {
        unsafe {
            let mut pfd = libc::pollfd {
                fd: self.fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
            if libc::poll(&mut pfd, 1, ms) <= 0 {
                return None;
            }
            if pfd.revents & libc::POLLIN == 0 {
                // POLLERR/POLLHUP without data: poll returns immediately forever,
                // so sleep out the interval instead of spinning on a dead fd.
                std::thread::sleep(timeout);
                return None;
            }
            // GET_WIPHY replies can be substantially larger than ordinary MLME
            // events. A short receive buffer silently truncates the datagram and
            // loses the nested HE/EHT capabilities near its tail.
            let mut buf = vec![0u8; 65536];
            let n = libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);
            if n <= 0 {
                return None;
            }
            buf.truncate(n as usize);
            Some(buf)
        }
    }

    fn join_multicast(&self, group: u32) -> io::Result<()> {
        unsafe {
            let g = group as libc::c_int;
            if libc::setsockopt(
                self.fd,
                libc::SOL_NETLINK,
                libc::NETLINK_ADD_MEMBERSHIP,
                &g as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as u32,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    /// Send a request and wait for its ACK / error, returning the error code.
    fn request_ack(&mut self, mut m: GenlMessage) -> io::Result<()> {
        m.flags |= msg::NLM_F_ACK;
        let seq = m.seq;
        self.send(&m.to_bytes(self.pid))?;
        for _ in 0..16 {
            let Some(buf) = self.recv(Duration::from_millis(500)) else {
                break;
            };
            for parsed in msg::parse_messages(&buf) {
                if parsed.seq != seq {
                    continue;
                }
                if let Some(code) = parsed.error_code() {
                    if code == 0 {
                        return Ok(());
                    }
                    // Extended ACK: error(4) + echoed request (its nlmsg_len) + TLVs;
                    // NLMSGERR_ATTR_MSG (type 1) carries the kernel's reason string.
                    let p = parsed.payload;
                    if p.len() >= 8 {
                        let orig_len = u32::from_ne_bytes([p[4], p[5], p[6], p[7]]) as usize;
                        let off = 4 + orig_len;
                        if off < p.len() {
                            for (typ, data) in msg::parse_attrs(&p[off..]) {
                                if typ == 1 {
                                    let s = String::from_utf8_lossy(
                                        data.split(|&b| b == 0).next().unwrap_or(data),
                                    );
                                    return Err(io::Error::other(format!(
                                        "{} ({s})",
                                        io::Error::from_raw_os_error(-code)
                                    )));
                                }
                            }
                        }
                    }
                    return Err(io::Error::from_raw_os_error(-code));
                }
            }
        }
        Err(io::Error::new(io::ErrorKind::TimedOut, "no netlink ACK"))
    }
}

/// Resolve a generic-netlink family id and the id of one of its multicast
/// groups (by name).
fn resolve_family(
    sock: &mut NetlinkSocket,
    family: &str,
    mcast_group: &str,
) -> io::Result<(u16, Option<u32>)> {
    let seq = sock.next_seq();
    let req = GenlMessage::new(msg::GENL_ID_CTRL, msg::CTRL_CMD_GETFAMILY, 0, seq)
        .attr(Attr::string(msg::CTRL_ATTR_FAMILY_NAME, family));
    sock.send(&req.to_bytes(sock.pid))?;

    for _ in 0..16 {
        let Some(buf) = sock.recv(Duration::from_millis(500)) else {
            break;
        };
        for parsed in msg::parse_messages(&buf) {
            if parsed.seq != seq || parsed.typ < msg::NLMSG_MIN_TYPE {
                continue;
            }
            let attrs = msg::parse_attrs(parsed.genl_attrs());
            let Some(fid) = msg::find_attr(&attrs, msg::CTRL_ATTR_FAMILY_ID) else {
                continue;
            };
            let family_id = u16::from_ne_bytes([fid[0], fid[1]]);

            // Search the nested multicast groups for the requested name.
            let mut gid = None;
            if let Some(groups) = msg::find_attr(&attrs, msg::CTRL_ATTR_MCAST_GROUPS) {
                for (_, grp) in msg::parse_attrs(groups) {
                    let ga = msg::parse_attrs(grp);
                    let name = msg::find_attr(&ga, msg::CTRL_ATTR_MCAST_GRP_NAME);
                    let id = msg::find_attr(&ga, msg::CTRL_ATTR_MCAST_GRP_ID);
                    if let (Some(name), Some(id)) = (name, id) {
                        let n = name
                            .iter()
                            .take_while(|&&c| c != 0)
                            .cloned()
                            .collect::<Vec<u8>>();
                        if n == mcast_group.as_bytes() {
                            gid = Some(u32::from_ne_bytes([id[0], id[1], id[2], id[3]]));
                        }
                    }
                }
            }
            return Ok((family_id, gid));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "nl80211 family not found",
    ))
}

/// An nl80211-backed [`Link`] for management-frame I/O and radio setup.
pub struct NetlinkLink {
    sock: NetlinkSocket,
    family_id: u16,
    ifindex: u32,
    freq: u32,
}

impl NetlinkLink {
    /// Open nl80211, put `iface` into AP mode on `channel`, register for the
    /// management subtypes the AP handles, and subscribe to frame events.
    pub fn open(iface: &str, channel: u8) -> io::Result<NetlinkLink> {
        let mut sock = NetlinkSocket::open()?;
        let (family_id, mlme_group) = resolve_family(&mut sock, "nl80211", "mlme")?;

        let ifindex =
            unsafe { libc::if_nametoindex(format!("{iface}\0").as_ptr() as *const libc::c_char) };
        if ifindex == 0 {
            return Err(io::Error::last_os_error());
        }
        let freq = msg::freq_for_channel(channel);

        // Put the interface into AP mode.
        let seq = sock.next_seq();
        let set_if = GenlMessage::new(family_id, NL80211_CMD_SET_INTERFACE, 0, seq)
            .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
            .attr(Attr::u32(NL80211_ATTR_IFTYPE, NL80211_IFTYPE_AP));
        let _ = sock.request_ack(set_if); // best-effort; some drivers want START_AP

        // Set the operating channel/frequency.
        let seq = sock.next_seq();
        let set_ch = GenlMessage::new(family_id, NL80211_CMD_SET_CHANNEL, 0, seq)
            .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
            .attr(Attr::u32(NL80211_ATTR_WIPHY_FREQ, freq));
        let _ = sock.request_ack(set_ch);

        // Subscribe to the mlme multicast group so we receive frame events.
        if let Some(group) = mlme_group {
            let _ = sock.join_multicast(group);
        }

        // Register for the management subtypes we want delivered to userspace.
        for &subtype in &REGISTER_SUBTYPES {
            let seq = sock.next_seq();
            let reg = GenlMessage::new(family_id, NL80211_CMD_REGISTER_FRAME, 0, seq)
                .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
                .attr(Attr::u16v(NL80211_ATTR_FRAME_TYPE, subtype))
                .attr(Attr::bytes(NL80211_ATTR_FRAME_MATCH, &[]));
            let _ = sock.request_ack(reg);
        }

        Ok(NetlinkLink {
            sock,
            family_id,
            ifindex,
            freq,
        })
    }
}

impl Link for NetlinkLink {
    fn try_recv(&mut self, timeout: Duration) -> Option<Vec<u8>> {
        let buf = self.sock.recv(timeout)?;
        for parsed in msg::parse_messages(&buf) {
            if parsed.typ != self.family_id {
                continue;
            }
            if parsed.genl_cmd() != Some(NL80211_CMD_FRAME) {
                continue;
            }
            let attrs = msg::parse_attrs(parsed.genl_attrs());
            if let Some(frame) = msg::find_attr(&attrs, NL80211_ATTR_FRAME) {
                // Hand the rest of the stack a radiotap-prefixed frame.
                let mut out = dot11::RADIOTAP_TX.to_vec();
                out.extend_from_slice(frame);
                return Some(out);
            }
        }
        None
    }

    fn send(&mut self, frame: &[u8]) {
        // Strip the radiotap header; nl80211 carries the bare 802.11 frame.
        let Some(dot11_frame) = dot11::strip_radiotap(frame) else {
            return;
        };
        let seq = self.sock.next_seq();
        let m = GenlMessage::new(self.family_id, NL80211_CMD_FRAME, 0, seq)
            .attr(Attr::u32(NL80211_ATTR_IFINDEX, self.ifindex))
            .attr(Attr::u32(NL80211_ATTR_WIPHY_FREQ, self.freq))
            .attr(Attr::bytes(NL80211_ATTR_FRAME, dot11_frame));
        let _ = self.sock.send(&m.to_bytes(self.sock.pid));
    }
}

// ---------------------------------------------------------------------------
// Kernel-offload AP (the "netlink way"): the kernel beacons (NL80211_CMD_START_AP)
// and does data-plane CCMP (NL80211_CMD_NEW_KEY); the 4-way handshake itself runs
// in `Ap`, with management frames exchanged over NL80211_CMD_FRAME.
// ---------------------------------------------------------------------------

/// Split a bare 802.11 beacon into the head (through the IEs preceding the TIM)
/// and the tail (IEs after the TIM). The kernel inserts its own TIM between them.
fn split_beacon_at_tim(beacon: &[u8]) -> (&[u8], &[u8]) {
    let mut i = 36; // 24-byte MAC header + timestamp(8) + interval(2) + capability(2)
    while i + 2 <= beacon.len() {
        let len = beacon[i + 1] as usize;
        if i + 2 + len > beacon.len() {
            break;
        }
        if beacon[i] == 5 {
            return (&beacon[..i], &beacon[i + 2 + len..]);
        }
        i += 2 + len;
    }
    (beacon, &[])
}

/// Send a single management frame off-channel (auth/assoc responses, deauth).
fn nl_send_mgmt(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    freq: u32,
    frame: &[u8],
    link_id: Option<u8>,
) {
    let seq = sock.next_seq();
    let mut m = GenlMessage::new(family, NL80211_CMD_FRAME, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::u32(NL80211_ATTR_WIPHY_FREQ, freq))
        .attr(Attr::bytes(NL80211_ATTR_FRAME, frame));
    if let Some(link_id) = link_id {
        m = m.attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id));
    }
    let _ = sock.send(&m.to_bytes(sock.pid));
}

fn nl_add_link(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    link_id: u8,
    link_mac: &[u8; 6],
) -> io::Result<()> {
    let seq = sock.next_seq();
    let m = GenlMessage::new(family, NL80211_CMD_ADD_LINK, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id))
        .attr(Attr::bytes(NL80211_ATTR_MAC, link_mac));
    sock.request_ack(m)
}

/// Send an EAPOL payload to `dst` over the nl80211 control port (unencrypted,
/// pre-key). The kernel wraps it into an 802.11 data frame to the station.
fn nl_send_eapol(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    dst: &[u8; 6],
    eapol: &[u8],
    link_id: Option<u8>,
) {
    let seq = sock.next_seq();
    let mut m = GenlMessage::new(family, NL80211_CMD_CONTROL_PORT_FRAME, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_MAC, dst))
        .attr(Attr::u16v(NL80211_ATTR_CONTROL_PORT_ETHERTYPE, ETH_P_PAE))
        .attr(Attr::bytes(NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT, &[]))
        .attr(Attr::bytes(NL80211_ATTR_FRAME, eapol));
    if let Some(link_id) = link_id {
        m = m.attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id));
    }
    // Synchronous send (NLM_F_ACK), like hostapd's send_and_recv: a fire-and-
    // forget send() never surfaces a kernel rejection — the error lands on the
    // socket unread and the EAPOL silently vanishes. NOTE: must be called on the
    // command socket, not the event socket (request_ack drains unrelated
    // messages while waiting for its ack, which would drop frame events).
    let r = sock.request_ack(m);
    if let Err(ref e) = r {
        eprintln!(
            "netlink AP: TX EAPOL to {} len={} FAILED: {e}",
            crate::util::bytes_to_mac(dst),
            eapol.len(),
        );
    }
    if std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
        let ki = if eapol.len() >= 7 {
            u16::from_be_bytes([eapol[5], eapol[6]])
        } else {
            0
        };
        // (The TX-STATUS event is multicast to the mlme group — the main recv
        // loop logs it as "EAPOL TX-STATUS acked=..".)
        eprintln!(
            "netlink AP: TX EAPOL to {} len={} key_info=0x{ki:04x} send={:?}",
            crate::util::bytes_to_mac(dst),
            eapol.len(),
            r.as_ref().map(|_| "ok").map_err(|e| e.kind()),
        );
    }
}

/// 500-kbps-unit OFDM rates (6..54 Mbps), no basic-rate bit — the format
/// NL80211_ATTR_STA_SUPPORTED_RATES expects (not the beacon IE format).
const STA_OFDM_RATES: [u8; 8] = [0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c];

/// 8-byte nl80211_sta_flag_update { mask, set } (host byte order).
fn sta_flags(mask: u32, set: u32) -> Vec<u8> {
    let mut v = mask.to_ne_bytes().to_vec();
    v.extend_from_slice(&set.to_ne_bytes());
    v
}

/// Add a station to the kernel in the *unassociated* state. hwsim lacks
/// `FULL_AP_CLIENT_STATE`, so — like hostapd's "UNASSOC_STA workaround" — the
/// station must be added with AUTH/ASSOC explicitly cleared (set=0, mask=0xa0),
/// then promoted to associated via SET_STATION.
fn nl_new_station(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    sta: &[u8; 6],
    mld_mac: Option<&[u8; 6]>,
    link_id: Option<u8>,
) {
    // Add the station UNASSOCIATED (flags cleared). SET_STATION then marks it
    // associated AND carries the HT/VHT caps — rate control only picks caps up
    // from SET_STATION, and applying them to an already-associated station fails
    // EINVAL, so the station must start unassociated here.
    let unassoc = (1u32 << NL80211_STA_FLAG_AUTHENTICATED) | (1u32 << NL80211_STA_FLAG_ASSOCIATED);
    let seq = sock.next_seq();
    // CCK (1/2/5.5/11) + OFDM (6..54), 500-kbps units, no basic bit.
    let rates: &[u8] = &[
        0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c,
    ];
    let _ = STA_OFDM_RATES;
    let mut m = GenlMessage::new(family, NL80211_CMD_NEW_STATION, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_MAC, sta))
        .attr(Attr::u16v(NL80211_ATTR_STA_AID, 1))
        .attr(Attr::u16v(NL80211_ATTR_STA_LISTEN_INTERVAL, 0))
        .attr(Attr::bytes(NL80211_ATTR_STA_SUPPORTED_RATES, rates))
        .attr(Attr::bytes(NL80211_ATTR_STA_FLAGS2, &sta_flags(unassoc, 0)));
    if let Some(link_id) = link_id {
        m = m.attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id));
    }
    if let Some(mld_mac) = mld_mac {
        m = m.attr(Attr::bytes(NL80211_ATTR_MLD_ADDR, mld_mac));
    }
    match sock.request_ack(m) {
        Ok(()) => eprintln!(
            "netlink AP: NEW_STATION {} ok (unassoc)",
            crate::util::bytes_to_mac(sta)
        ),
        Err(e) => eprintln!(
            "netlink AP: NEW_STATION {} failed: {e}",
            crate::util::bytes_to_mac(sta)
        ),
    }
}

/// Promote a station to the associated state (SET_STATION with the real aid,
/// capability and AUTH/ASSOC flags) once it has (re)associated.
/// Find the payload of an Element-ID-Extension IE (id 255) with extension id
/// `ext_id` (e.g. HE Capabilities = 35), excluding the ext-id byte.
fn find_ext_ie(ies: &[u8], ext_id: u8) -> Option<&[u8]> {
    let mut i = 0;
    while i + 2 <= ies.len() {
        let len = ies[i + 1] as usize;
        if i + 2 + len > ies.len() {
            break;
        }
        if ies[i] == 255 && len >= 1 && ies[i + 2] == ext_id {
            return Some(&ies[i + 3..i + 2 + len]);
        }
        i += 2 + len;
    }
    None
}

/// Extract the QoS Info byte from the station's WMM Information element (vendor
/// element 221, OUI 00:50:f2, OUI-type 2, subtype 0). Iterates all vendor IEs
/// since a station may carry several. Used to enable A-MPDU aggregation.
fn find_wmm_qosinfo(ies: &[u8]) -> Option<u8> {
    let mut i = 0;
    while i + 2 <= ies.len() {
        let len = ies[i + 1] as usize;
        if i + 2 + len > ies.len() {
            break;
        }
        let body = &ies[i + 2..i + 2 + len];
        if ies[i] == 221 && body.len() >= 7 && body.starts_with(&[0x00, 0x50, 0xf2, 0x02, 0x00]) {
            return Some(body[6]);
        }
        i += 2 + len;
    }
    None
}

fn nl_set_station_assoc(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    sta: &[u8; 6],
    aid: u16,
    listen_interval: u16,
    capability: u16,
    assoc_ies: Option<&[u8]>,
    mld_mac: Option<&[u8; 6]>,
    link_id: Option<u8>,
    force_wme: bool,
    mfp: bool,
) {
    let seq = sock.next_seq();
    // Real supported rates from the assoc request (Supported Rates id 1 + Extended
    // Rates id 50), basic-rate bits preserved, like hostapd; fall back to OFDM.
    let mut rates: Vec<u8> = Vec::new();
    if let Some(ies) = assoc_ies {
        if let Some(sr) = dot11::find_ie(ies, 1) {
            rates.extend_from_slice(sr);
        }
        if let Some(er) = dot11::find_ie(ies, 50) {
            rates.extend_from_slice(er);
        }
    }
    if rates.is_empty() {
        rates.extend_from_slice(&STA_OFDM_RATES);
    }
    let qosinfo = assoc_ies.and_then(find_wmm_qosinfo);
    let mut assoc =
        (1u32 << NL80211_STA_FLAG_AUTHENTICATED) | (1u32 << NL80211_STA_FLAG_ASSOCIATED);
    if force_wme || qosinfo.is_some() {
        assoc |= 1u32 << NL80211_STA_FLAG_WME;
    }
    if mfp {
        assoc |= 1u32 << NL80211_STA_FLAG_MFP;
    }
    let mut m = GenlMessage::new(family, NL80211_CMD_SET_STATION, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_MAC, sta))
        .attr(Attr::u16v(NL80211_ATTR_STA_AID, aid))
        .attr(Attr::u16v(
            NL80211_ATTR_STA_LISTEN_INTERVAL,
            listen_interval,
        ))
        .attr(Attr::bytes(NL80211_ATTR_STA_SUPPORTED_RATES, &rates))
        .attr(Attr::u16v(NL80211_ATTR_STA_CAPABILITY, capability))
        .attr(Attr::bytes(
            NL80211_ATTR_STA_FLAGS2,
            &sta_flags(assoc, assoc),
        ));
    if let Some(link_id) = link_id {
        m = m.attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id));
    }
    if let Some(mld_mac) = mld_mac {
        m = m.attr(Attr::bytes(NL80211_ATTR_MLD_ADDR, mld_mac));
    }
    // Carry the station's HT/VHT/HE capabilities (from its Assoc Request) so the
    // driver's rate control can use MCS rates — without these it is treated as a
    // legacy station stuck on the 6 Mbps basic rate.
    if let Some(ies) = assoc_ies {
        if let Some(ht) = dot11::find_ie(ies, 45) {
            m = m.attr(Attr::bytes(NL80211_ATTR_HT_CAPABILITY, ht));
        }
        if let Some(vht) = dot11::find_ie(ies, 191) {
            m = m.attr(Attr::bytes(NL80211_ATTR_VHT_CAPABILITY, vht));
        }
        // Pass the station's HE Capabilities (the element body after the ext-id,
        // exactly what the kernel + hostapd expect) so the driver can set up HE
        // downlink rates + A-MPDU aggregation for it. Without this, an HE-
        // associated station gives the driver no HE info: on real HE hardware
        // (e.g. mt7915e) the AP can't TX HE to it and *downlink* stalls near 0,
        // while uplink — driven by the station's own TX aggregation — still works.
        // Default on, matching hostapd; escape hatch RUSTAP_NO_HE_CAP=1 disables
        // it if a particular driver ever regresses.
        if let Some(he) = find_ext_ie(ies, 35) {
            if std::env::var_os("RUSTAP_NO_HE_CAP").is_none() {
                m = m.attr(Attr::bytes(NL80211_ATTR_HE_CAPABILITY, he));
            }
        }
        // Mark the station QoS/WMM-capable so the kernel enables A-MPDU
        // aggregation. The QoS Info byte comes from the station's WMM Information
        // element; without this nest a VHT/HE station negotiates a high MCS but
        // moves almost no data (every MPDU goes out unaggregated). hostapd sends
        // the identical nested attribute.
        if let Some(qosinfo) = qosinfo {
            m = m.attr(Attr::nested(
                NL80211_ATTR_STA_WME,
                &[
                    Attr::bytes(NL80211_STA_WME_UAPSD_QUEUES, &[qosinfo & 0x0f]),
                    Attr::bytes(NL80211_STA_WME_MAX_SP, &[(qosinfo >> 5) & 0x03]),
                ],
            ));
        }
    }
    if force_wme && qosinfo.is_none() {
        m = m.attr(Attr::nested(
            NL80211_ATTR_STA_WME,
            &[
                Attr::bytes(NL80211_STA_WME_UAPSD_QUEUES, &[0]),
                Attr::bytes(NL80211_STA_WME_MAX_SP, &[0]),
            ],
        ));
    }
    if let Err(e) = sock.request_ack(m) {
        eprintln!(
            "netlink AP: SET_STATION(assoc) {} failed: {e}",
            crate::util::bytes_to_mac(sta)
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn nl_add_link_station(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    mld_mac: &[u8; 6],
    link_id: u8,
    link_sta: &[u8; 6],
    aid: u16,
    listen_interval: u16,
    capability: u16,
    assoc_ies: Option<&[u8]>,
    mfp: bool,
) {
    let mut rates: Vec<u8> = Vec::new();
    if let Some(ies) = assoc_ies {
        if let Some(sr) = dot11::find_ie(ies, 1) {
            rates.extend_from_slice(sr);
        }
        if let Some(er) = dot11::find_ie(ies, 50) {
            rates.extend_from_slice(er);
        }
    }
    if rates.is_empty() {
        rates.extend_from_slice(&STA_OFDM_RATES);
    }
    let mut flags = (1u32 << NL80211_STA_FLAG_AUTHENTICATED)
        | (1u32 << NL80211_STA_FLAG_ASSOCIATED)
        | (1u32 << NL80211_STA_FLAG_WME);
    if mfp {
        flags |= 1u32 << NL80211_STA_FLAG_MFP;
    }
    let seq = sock.next_seq();
    let mut m = GenlMessage::new(family, NL80211_CMD_ADD_LINK_STA, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id))
        .attr(Attr::bytes(NL80211_ATTR_MLD_ADDR, mld_mac))
        .attr(Attr::bytes(NL80211_ATTR_MAC, link_sta))
        .attr(Attr::u16v(NL80211_ATTR_STA_AID, aid))
        .attr(Attr::u16v(
            NL80211_ATTR_STA_LISTEN_INTERVAL,
            listen_interval,
        ))
        .attr(Attr::bytes(NL80211_ATTR_STA_SUPPORTED_RATES, &rates))
        .attr(Attr::u16v(NL80211_ATTR_STA_CAPABILITY, capability))
        .attr(Attr::bytes(
            NL80211_ATTR_STA_FLAGS2,
            &sta_flags(flags, flags),
        ))
        .attr(Attr::nested(
            NL80211_ATTR_STA_WME,
            &[
                Attr::bytes(NL80211_STA_WME_UAPSD_QUEUES, &[0]),
                Attr::bytes(NL80211_STA_WME_MAX_SP, &[0]),
            ],
        ));
    if let Some(ies) = assoc_ies {
        if let Some(ht) = dot11::find_ie(ies, 45) {
            m = m.attr(Attr::bytes(NL80211_ATTR_HT_CAPABILITY, ht));
        }
        if let Some(vht) = dot11::find_ie(ies, 191) {
            m = m.attr(Attr::bytes(NL80211_ATTR_VHT_CAPABILITY, vht));
        }
    }
    match sock.request_ack(m) {
        Ok(()) => eprintln!(
            "netlink AP: ADD_LINK_STA link_id={} mld={} link_sta={} ok",
            link_id,
            crate::util::bytes_to_mac(mld_mac),
            crate::util::bytes_to_mac(link_sta)
        ),
        Err(e) => eprintln!(
            "netlink AP: ADD_LINK_STA link_id={} link_sta={} failed: {e}",
            link_id,
            crate::util::bytes_to_mac(link_sta)
        ),
    }
}

fn nl_authorize_link_station(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    mld_mac: &[u8; 6],
    link_id: u8,
    link_sta: &[u8; 6],
    mfp: bool,
) {
    let mut flags = (1u32 << NL80211_STA_FLAG_AUTHORIZED)
        | (1u32 << NL80211_STA_FLAG_AUTHENTICATED)
        | (1u32 << NL80211_STA_FLAG_ASSOCIATED)
        | (1u32 << NL80211_STA_FLAG_WME);
    if mfp {
        flags |= 1u32 << NL80211_STA_FLAG_MFP;
    }
    let seq = sock.next_seq();
    let m = GenlMessage::new(family, NL80211_CMD_MODIFY_LINK_STA, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id))
        .attr(Attr::bytes(NL80211_ATTR_MLD_ADDR, mld_mac))
        .attr(Attr::bytes(NL80211_ATTR_MAC, link_sta))
        .attr(Attr::bytes(
            NL80211_ATTR_STA_FLAGS2,
            &sta_flags(flags, flags),
        ));
    if let Err(e) = sock.request_ack(m) {
        eprintln!(
            "netlink AP: MODIFY_LINK_STA(authorize) link_id={} link_sta={} failed: {e}",
            link_id,
            crate::util::bytes_to_mac(link_sta)
        );
    }
}

/// Select an already-installed GTK as the default key for multicast traffic.
/// This must be a separate SET_KEY request: KEY_DEFAULT and
/// KEY_DEFAULT_TYPES are not valid top-level NEW_KEY attributes.
fn nl_set_default_group_key(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    idx: u8,
    link_id: Option<u8>,
) {
    let seq = sock.next_seq();
    let mut m = GenlMessage::new(family, NL80211_CMD_SET_KEY, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(default_multicast_key_attr(idx));
    if let Some(link_id) = link_id {
        m = m.attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id));
    }
    if let Err(e) = sock.request_ack(m) {
        eprintln!("netlink AP: SET_KEY multicast default (idx {idx}) failed: {e}");
    }
}

/// Install a CCMP key into the kernel (pairwise PTK or group GTK).
fn nl_new_key(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    sta: Option<&[u8; 6]>,
    idx: u8,
    key: &[u8],
    pairwise: bool,
    link_id: Option<u8>,
) {
    let seq = sock.next_seq();
    let mut m = GenlMessage::new(family, NL80211_CMD_NEW_KEY, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_KEY_DATA, key))
        .attr(Attr::u32(NL80211_ATTR_KEY_CIPHER, WLAN_CIPHER_SUITE_CCMP))
        .attr(Attr::bytes(NL80211_ATTR_KEY_IDX, &[idx]))
        .attr(Attr::u32(
            NL80211_ATTR_KEY_TYPE,
            if pairwise {
                NL80211_KEYTYPE_PAIRWISE
            } else {
                NL80211_KEYTYPE_GROUP
            },
        ));
    if let Some(s) = sta {
        m = m.attr(Attr::bytes(NL80211_ATTR_MAC, s));
    }
    if let Some(link_id) = link_id {
        m = m.attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id));
    }
    match sock.request_ack(m) {
        Ok(()) if !pairwise => {
            nl_set_default_group_key(sock, family, ifindex, idx, link_id);
        }
        Ok(()) => {}
        Err(e) => {
            eprintln!("netlink AP: NEW_KEY (idx {idx}, pairwise {pairwise}) failed: {e}");
        }
    }
}

/// Install the IGTK (BIP-CMAC-128) into the kernel and make it the default
/// management key, so mac80211 can TX/validate BIP-protected robust management
/// frames. `idx` is the IGTK key index (4/5) and `ipn` the 6-octet receive
/// sequence counter (little-endian, as in the MME).
fn nl_install_igtk(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    idx: u8,
    igtk: &[u8; 16],
    ipn: &[u8; 6],
    link_id: Option<u8>,
) {
    let seq = sock.next_seq();
    let mut m = GenlMessage::new(family, NL80211_CMD_NEW_KEY, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_KEY_DATA, igtk))
        .attr(Attr::u32(
            NL80211_ATTR_KEY_CIPHER,
            WLAN_CIPHER_SUITE_BIP_CMAC_128,
        ))
        .attr(Attr::bytes(NL80211_ATTR_KEY_IDX, &[idx]))
        .attr(Attr::bytes(NL80211_ATTR_KEY_SEQ, ipn))
        .attr(Attr::u32(NL80211_ATTR_KEY_TYPE, NL80211_KEYTYPE_GROUP))
        .attr(Attr::bytes(NL80211_ATTR_KEY_DEFAULT_MGMT, &[]));
    if let Some(link_id) = link_id {
        m = m.attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id));
    }
    if let Err(e) = sock.request_ack(m) {
        eprintln!("netlink AP: NEW_KEY IGTK (idx {idx}) failed: {e}");
    }
}

/// Install the BIGTK (Beacon Protection, BIP-CMAC-128) into the kernel at the
/// beacon key index (6/7) so mac80211 itself stamps + increments the per-beacon
/// MME — instead of us baking a single fixed-IPN MME into a kernel-repeated
/// (hence replayable) beacon. mac80211 recognises the 6/7 index range plus the
/// BIP cipher as the beacon-protection key; `ipn` seeds its sequence counter.
/// Returns whether the kernel accepted the key (an old kernel without beacon-
/// protection offload rejects it, in which case the caller disables the feature
/// rather than emit any MME).
fn nl_install_bigtk(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    idx: u8,
    bigtk: &[u8; 16],
    ipn: &[u8; 6],
    link_id: Option<u8>,
) -> bool {
    let seq = sock.next_seq();
    // No KEY_DEFAULT/DEFAULT_MGMT flag: mac80211 recognises the 6/7 index range
    // plus the BIP cipher as the beacon-protection key on its own (there is no
    // "default beacon key" nl80211 attribute, unlike the IGTK's DEFAULT_MGMT).
    let mut m = GenlMessage::new(family, NL80211_CMD_NEW_KEY, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_KEY_DATA, bigtk))
        .attr(Attr::u32(
            NL80211_ATTR_KEY_CIPHER,
            WLAN_CIPHER_SUITE_BIP_CMAC_128,
        ))
        .attr(Attr::bytes(NL80211_ATTR_KEY_IDX, &[idx]))
        .attr(Attr::bytes(NL80211_ATTR_KEY_SEQ, ipn))
        .attr(Attr::u32(NL80211_ATTR_KEY_TYPE, NL80211_KEYTYPE_GROUP));
    if let Some(link_id) = link_id {
        m = m.attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id));
    }
    match sock.request_ack(m) {
        Ok(_) => true,
        Err(e) => {
            eprintln!("netlink AP: NEW_KEY BIGTK (idx {idx}) failed: {e}");
            false
        }
    }
}

/// Remove a group/management key index from the kernel (the old GTK/IGTK after a
/// two-phase rekey, once stations have the new one). Best-effort.
fn nl_del_key(sock: &mut NetlinkSocket, family: u16, ifindex: u32, idx: u8, link_id: Option<u8>) {
    let seq = sock.next_seq();
    let mut m = GenlMessage::new(family, NL80211_CMD_DEL_KEY, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_KEY_IDX, &[idx]))
        .attr(Attr::u32(NL80211_ATTR_KEY_TYPE, NL80211_KEYTYPE_GROUP));
    if let Some(link_id) = link_id {
        m = m.attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id));
    }
    let _ = sock.request_ack(m);
}

/// Mark a station 802.1X-authorized so the kernel forwards its data frames.
fn nl_authorize(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    sta: &[u8; 6],
    link_id: Option<u8>,
) {
    let bit = 1u32 << NL80211_STA_FLAG_AUTHORIZED;
    let mut flags = bit.to_ne_bytes().to_vec(); // mask
    flags.extend_from_slice(&bit.to_ne_bytes()); // set
    let seq = sock.next_seq();
    let mut m = GenlMessage::new(family, NL80211_CMD_SET_STATION, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_MAC, sta))
        .attr(Attr::bytes(NL80211_ATTR_STA_FLAGS2, &flags));
    if let Some(link_id) = link_id {
        m = m.attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id));
    }
    if let Err(e) = sock.request_ack(m) {
        eprintln!(
            "netlink AP: SET_STATION(authorize) {} failed: {e}",
            crate::util::bytes_to_mac(sta)
        );
    }
}

/// Reconstruct a station's uplink EAPOL into a ToDS 802.11 data frame so the
/// `Ap` state machine (which speaks raw 802.11) can process it.
fn reconstruct_eapol(bssid: &[u8; 6], sta: &[u8; 6], eapol: &[u8]) -> Vec<u8> {
    let mut v = dot11::RADIOTAP_TX.to_vec();
    v.extend_from_slice(&[0x08, 0x01, 0x00, 0x00]); // FC: data, ToDS; duration
    v.extend_from_slice(bssid); // addr1 = RA = BSSID
    v.extend_from_slice(sta); // addr2 = TA = STA
    v.extend_from_slice(bssid); // addr3 = DA = BSSID
    v.extend_from_slice(&[0x00, 0x00]); // sequence control
    v.extend_from_slice(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e]); // LLC/SNAP, EAPOL
    v.extend_from_slice(eapol);
    v
}

/// Run the AP with the kernel offloading beaconing and data-plane CCMP — the
/// nl80211 "netlink" path (vs the userspace-CCMP raw/monitor path). The 4-way
/// handshake stays in `Ap`; the interface must already be AP-type and up.
///
/// Flow: `START_AP` (kernel beacons) → register for auth/(re)assoc → for each
/// peer run the userspace MLME in `Ap`, sending responses over `CMD_FRAME`,
/// registering the station (`NEW_STATION`/`SET_STATION`), shuttling the 4-way
/// EAPOL over the nl80211 control port, then installing the PTK/GTK with
/// `NEW_KEY` and authorizing with `SET_STATION`.
///
/// STATUS: verified end-to-end against `wpa_supplicant` (`wpa_state=COMPLETED`,
/// **ping works**): beacon, auth, assoc, the two-step station add (NEW_STATION
/// unassoc → SET_STATION assoc, the hostapd "UNASSOC_STA workaround" for
/// non-`FULL_AP_CLIENT_STATE` drivers), the 4-way over the nl80211 control port,
/// PTK/GTK install (`NEW_KEY`), authorization, and CCMP data both directions.
/// See `tools/hwsim/README.md`.
/// The `NL80211_ATTR_RADAR_EVENT` value, if present.
fn radar_event(attrs: &[(u16, &[u8])]) -> Option<u32> {
    msg::find_attr(attrs, NL80211_ATTR_RADAR_EVENT)
        .and_then(|b| b.get(..4))
        .map(|b| u32::from_ne_bytes(b.try_into().unwrap()))
}

/// Run the Channel Availability Check on a DFS channel: ask the kernel to start
/// radar detection, then block until it reports CAC finished (channel clear) —
/// the kernel won't let us `START_AP` on a radar channel before this. ~60 s.
fn do_cac(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    freq: u32,
    chan_width: u32,
    center_freq1: u32,
) -> io::Result<()> {
    let seq = sock.next_seq();
    sock.request_ack(
        GenlMessage::new(family, NL80211_CMD_RADAR_DETECT, 0, seq)
            .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
            .attr(Attr::u32(NL80211_ATTR_WIPHY_FREQ, freq))
            .attr(Attr::u32(NL80211_ATTR_CHANNEL_WIDTH, chan_width))
            .attr(Attr::u32(NL80211_ATTR_CENTER_FREQ1, center_freq1)),
    )
    .map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("DFS RADAR_DETECT rejected on {freq} MHz ({e}); the driver may not support userspace CAC"),
        )
    })?;
    eprintln!("netlink AP: DFS — running CAC (radar listen) on {freq} MHz, ~60 s...");
    // Standard DFS CAC is 60 s; ETSI weather-radar channels (120-128) take 600 s.
    // Bound the wait at ~650 s so a legitimate weather CAC completes but a missed
    // event can't hang us forever.
    for _ in 0..130 {
        let Some(buf) = sock.recv(Duration::from_secs(5)) else {
            continue;
        };
        for parsed in msg::parse_messages(&buf) {
            if parsed.typ != family || parsed.genl_cmd() != Some(NL80211_CMD_RADAR_DETECT) {
                continue;
            }
            match radar_event(&msg::parse_attrs(parsed.genl_attrs())) {
                Some(NL80211_RADAR_CAC_FINISHED) => {
                    eprintln!("netlink AP: CAC finished — channel clear, beaconing");
                    return Ok(());
                }
                Some(NL80211_RADAR_CAC_ABORTED) => {
                    return Err(io::Error::other("DFS CAC aborted"));
                }
                Some(NL80211_RADAR_DETECTED) => {
                    return Err(io::Error::other(
                        "radar detected during CAC; channel unusable",
                    ));
                }
                _ => {}
            }
        }
    }
    Err(io::Error::other("DFS CAC timed out"))
}

/// The interface's own MAC as the kernel reports it (`/sys/class/net/<if>/address`).
fn read_iface_mac(iface: &str) -> Option<[u8; 6]> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{iface}/address")).ok()?;
    crate::util::try_mac_to_bytes(s.trim())
}

/// Capability element payloads derived from this radio's nl80211 GET_WIPHY
/// response. hostapd builds its beacon/response capability IEs from the same
/// attributes. Keeping the driver's bytes is important: an internally
/// inconsistent synthetic HE/EHT advertisement is tolerated by some Linux
/// scanners but rejected by stricter clients (notably macOS).
#[derive(Default, Debug)]
struct WiphyCapabilities {
    ht: Option<Vec<u8>>,
    vht: Option<Vec<u8>>,
    he: Option<Vec<u8>>,
    eht: Option<Vec<u8>>,
}

fn he_ppe_len(header: u8, phy: &[u8]) -> usize {
    if phy.get(6).copied().unwrap_or(0) & 0x80 == 0 {
        return 0;
    }
    let ru_count = ((header >> 3) & 0x0f).count_ones() as usize;
    let nss = 1 + (header & 0x07) as usize;
    (7 + 6 * ru_count * nss).div_ceil(8)
}

fn build_he_capability(attrs: &[(u16, &[u8])]) -> Option<Vec<u8>> {
    let mac = msg::find_attr(attrs, NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC)?;
    let raw_phy = msg::find_attr(attrs, NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY)?;
    let mcs = msg::find_attr(attrs, NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET)?;
    if mac.len() < 6 || raw_phy.len() < 11 {
        return None;
    }
    let mut phy = raw_phy[..11].to_vec();
    // RustAP does not currently configure SU/MU beamforming. Match hostapd's
    // default mask so we advertise only features enabled by the AP, not every
    // feature the radio could support under a different configuration.
    phy[3] &= !0x80; // SU beamformer
    phy[4] &= !(0x01 | 0x02); // SU beamformee + MU beamformer
                              // Base <=80 MHz RX/TX maps are four bytes. 160 and 80+80 each add four,
                              // based on the channel-width bits in HE PHY capability octet zero.
    let mut mcs_len = 4;
    if phy[0] & 0x10 != 0 {
        mcs_len += 4;
    }
    if phy[0] & 0x08 != 0 {
        mcs_len += 4;
    }
    if mcs.len() < mcs_len {
        return None;
    }
    let ppe = msg::find_attr(attrs, NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE).unwrap_or(&[]);
    let ppe_len = ppe.first().map_or(0, |header| he_ppe_len(*header, &phy));
    if ppe.len() < ppe_len {
        return None;
    }
    let mut out = Vec::with_capacity(6 + 11 + mcs_len + ppe_len);
    out.extend_from_slice(&mac[..6]);
    out.extend_from_slice(&phy);
    out.extend_from_slice(&mcs[..mcs_len]);
    out.extend_from_slice(&ppe[..ppe_len]);
    Some(out)
}

fn eht_ppe_len(header: u16, phy: &[u8]) -> usize {
    if phy.get(5).copied().unwrap_or(0) & 0x08 == 0 {
        return 0;
    }
    let ru_count = ((header >> 4) & 0x1f).count_ones() as usize;
    let nss = 1 + (header & 0x0f) as usize;
    (9 + 6 * ru_count * nss).div_ceil(8)
}

fn build_eht_capability(attrs: &[(u16, &[u8])], he: &[u8], band: u16) -> Option<Vec<u8>> {
    let mac = msg::find_attr(attrs, NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC)?;
    let raw_phy = msg::find_attr(attrs, NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY)?;
    let mcs = msg::find_attr(attrs, NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET)?;
    if mac.len() < 2 || raw_phy.len() < 9 || he.len() < 17 {
        return None;
    }
    let he_width = he[6]; // HE body = MAC[6] || PHY[11] || optional fields
    let mut phy = raw_phy[..9].to_vec();
    let mcs_len = if band == 0 && he_width & 0x02 == 0 {
        4 // 20 MHz-only encoding
    } else {
        let mut len = 3; // <=80 MHz
        if band == 1 && he_width & (0x08 | 0x10) != 0 {
            len += 3; // 160/80+80 MHz
        }
        if band == 4 && phy[0] & 0x02 != 0 {
            len += 3; // 320 MHz in 6 GHz
        }
        len
    };
    if mcs.len() < mcs_len {
        return None;
    }
    // The 320 MHz bit is meaningful only in the 6 GHz band; hostapd clears it
    // in lower-band beacons even when the same radio supports 320 MHz elsewhere.
    if band != 4 {
        phy[0] &= !0x02;
    }
    phy[0] &= !(0x20 | 0x40); // SU beamformer + SU beamformee
    phy[7] &= !(0x10 | 0x20 | 0x40); // MU beamformer at 80/160/320 MHz
    let ppe = msg::find_attr(attrs, NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PPE).unwrap_or(&[]);
    let ppe_header = ppe
        .get(..2)
        .map(|v| u16::from_le_bytes(v.try_into().unwrap()))
        .unwrap_or(0);
    let ppe_len = eht_ppe_len(ppe_header, &phy);
    if ppe.len() < ppe_len {
        return None;
    }
    let mut out = Vec::with_capacity(2 + 9 + mcs_len + ppe_len);
    out.extend_from_slice(&mac[..2]);
    out.extend_from_slice(&phy);
    out.extend_from_slice(&mcs[..mcs_len]);
    out.extend_from_slice(&ppe[..ppe_len]);
    Some(out)
}

#[cfg(test)]
mod wiphy_capability_tests {
    use super::*;

    #[test]
    fn trims_and_masks_driver_he_eht_arrays_like_hostapd() {
        let he_mac = [0x0d, 0x00, 0x08, 0x9a, 0x40, 0x18];
        let he_phy = [
            0x0c, 0x63, 0x40, 0x88, 0xff, 0xd9, 0x9f, 0x1c, 0x11, 0x0e, 0x00,
        ];
        let he_mcs = [0xfa, 0xff, 0xfa, 0xff, 0xfa, 0xff, 0xfa, 0xff, 0, 0, 0, 0];
        let he_ppe = [
            0x79, 0x1c, 0xc7, 0x71, 0x1c, 0xc7, 0x71, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let eht_mac = [0x37, 0x00];
        let eht_phy = [0xe2, 0xff, 0xdb, 0xe0, 0x18, 0x75, 0x00, 0x7e, 0x04];
        let eht_mcs = [0x22; 9];
        let attrs = vec![
            (NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC, he_mac.as_slice()),
            (NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY, he_phy.as_slice()),
            (NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET, he_mcs.as_slice()),
            (NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE, he_ppe.as_slice()),
            (NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC, eht_mac.as_slice()),
            (NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY, eht_phy.as_slice()),
            (NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET, eht_mcs.as_slice()),
        ];

        let he = build_he_capability(&attrs).expect("HE capability");
        assert_eq!(he.len(), 32, "fixed kernel arrays must be trimmed");
        assert_eq!(
            &he[6..17],
            &[0x0c, 0x63, 0x40, 0x08, 0xfc, 0xd9, 0x9f, 0x1c, 0x11, 0x0e, 0x00]
        );

        let eht = build_eht_capability(&attrs, &he, 1).expect("5 GHz EHT capability");
        assert_eq!(eht.len(), 17, "5 GHz omits the 320 MHz MCS map");
        assert_eq!(
            eht,
            [
                0x37, 0x00, 0x80, 0xff, 0xdb, 0xe0, 0x18, 0x75, 0x00, 0x0e, 0x04, 0x22, 0x22, 0x22,
                0x22, 0x22, 0x22,
            ]
        );
    }
}

fn parse_wiphy_capabilities(attrs: &[(u16, &[u8])], band: u16) -> Option<WiphyCapabilities> {
    let bands = msg::find_attr(attrs, NL80211_ATTR_WIPHY_BANDS)?;
    let band_data = msg::parse_attrs(bands)
        .into_iter()
        .find_map(|(typ, data)| (typ == band).then_some(data))?;
    let band_attrs = msg::parse_attrs(band_data);
    let types: Vec<u16> = band_attrs.iter().map(|(typ, _)| *typ).collect();
    if std::env::var_os("RUSTAP_NL_DEBUG").is_some()
        && (types.len() > 1 || types.first() != Some(&1))
    {
        eprintln!("netlink AP: GET_WIPHY band={band} attr_types={types:?}");
    }

    // HT and VHT capabilities are band-wide. Construct their element payloads
    // from the kernel attributes instead of advertising a fixed stream count.
    let ht = (|| {
        let capa = msg::find_attr(&band_attrs, NL80211_BAND_ATTR_HT_CAPA)?;
        let factor = *msg::find_attr(&band_attrs, NL80211_BAND_ATTR_HT_AMPDU_FACTOR)?.first()?;
        let density = *msg::find_attr(&band_attrs, NL80211_BAND_ATTR_HT_AMPDU_DENSITY)?.first()?;
        let mcs = msg::find_attr(&band_attrs, NL80211_BAND_ATTR_HT_MCS_SET)?;
        if capa.len() < 2 || mcs.len() < 16 {
            return None;
        }
        let mut body = Vec::with_capacity(26);
        body.extend_from_slice(&capa[..2]);
        body.push((factor & 0x03) | ((density & 0x07) << 2));
        body.extend_from_slice(&mcs[..16]);
        body.extend_from_slice(&[0u8; 7]); // ext caps, TXBF caps, ASEL caps
        Some(body)
    })();
    let vht = (|| {
        let capa = msg::find_attr(&band_attrs, NL80211_BAND_ATTR_VHT_CAPA)?;
        let mcs = msg::find_attr(&band_attrs, NL80211_BAND_ATTR_VHT_MCS_SET)?;
        if capa.len() < 4 || mcs.len() < 8 {
            return None;
        }
        let mut body = Vec::with_capacity(12);
        body.extend_from_slice(&capa[..4]);
        body.extend_from_slice(&mcs[..8]);
        Some(body)
    })();

    let mut he = None;
    let mut eht = None;
    if let Some(iftypes) = msg::find_attr(&band_attrs, NL80211_BAND_ATTR_IFTYPE_DATA) {
        for (_, entry) in msg::parse_attrs(iftypes) {
            let entry_attrs = msg::parse_attrs(entry);
            if std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
                let entry_types: Vec<u16> = entry_attrs.iter().map(|(typ, _)| *typ).collect();
                let iftype_types: Vec<u16> =
                    msg::find_attr(&entry_attrs, NL80211_BAND_IFTYPE_ATTR_IFTYPES)
                        .map(msg::parse_attrs)
                        .unwrap_or_default()
                        .iter()
                        .map(|(typ, _)| *typ)
                        .collect();
                eprintln!(
                    "netlink AP: GET_WIPHY iftype entry attrs={entry_types:?} iftypes={iftype_types:?}"
                );
            }
            let Some(types) = msg::find_attr(&entry_attrs, NL80211_BAND_IFTYPE_ATTR_IFTYPES) else {
                continue;
            };
            if !msg::parse_attrs(types)
                .iter()
                .any(|(typ, _)| *typ == NL80211_IFTYPE_AP as u16)
            {
                continue;
            }
            he = build_he_capability(&entry_attrs);
            eht = he
                .as_deref()
                .and_then(|he_body| build_eht_capability(&entry_attrs, he_body, band));
            break;
        }
    }
    Some(WiphyCapabilities { ht, vht, he, eht })
}

fn nl_get_wiphy_capabilities(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    band: u16,
) -> Option<WiphyCapabilities> {
    fn merge(dst: &mut WiphyCapabilities, mut src: WiphyCapabilities) {
        if src.ht.is_some() {
            dst.ht = src.ht.take();
        }
        if src.vht.is_some() {
            dst.vht = src.vht.take();
        }
        if src.he.is_some() {
            dst.he = src.he.take();
        }
        if src.eht.is_some() {
            dst.eht = src.eht.take();
        }
    }

    // Resolve the interface's wiphy first. The compact GET_WIPHY response also
    // carries band-wide HT/VHT data, but modern kernels intentionally omit the
    // much larger per-iftype HE/EHT nests unless userspace requests a split
    // wiphy dump.
    let seq = sock.next_seq();
    let request = GenlMessage::new(family, NL80211_CMD_GET_WIPHY, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex));
    if let Err(e) = sock.send(&request.to_bytes(sock.pid)) {
        eprintln!("netlink AP: GET_WIPHY send failed: {e}");
        return None;
    }
    let mut caps = WiphyCapabilities::default();
    let mut wiphy = None;
    'compact: for _ in 0..16 {
        let Some(buf) = sock.recv(Duration::from_millis(500)) else {
            continue;
        };
        for parsed in msg::parse_messages(&buf) {
            if parsed.seq != seq {
                continue;
            }
            if parsed.typ == msg::NLMSG_ERROR {
                let code = parsed.error_code().unwrap_or(-libc::EIO);
                eprintln!("netlink AP: GET_WIPHY failed: {code}");
                return None;
            }
            if parsed.typ == family {
                let attrs = msg::parse_attrs(parsed.genl_attrs());
                wiphy = msg::find_attr(&attrs, NL80211_ATTR_WIPHY)
                    .and_then(|v| v.get(..4))
                    .map(|v| u32::from_ne_bytes(v.try_into().unwrap()));
                if let Some(found) = parse_wiphy_capabilities(&attrs, band) {
                    merge(&mut caps, found);
                }
                break 'compact;
            }
        }
    }
    let Some(wiphy) = wiphy else {
        eprintln!("netlink AP: GET_WIPHY timed out");
        return None;
    };

    // Ask for the split dump hostapd/iw use and merge every response belonging
    // to this wiphy. HE/EHT per-iftype data commonly arrives in a later message
    // than HT/VHT, so returning after the first multipart record drops it.
    let seq = sock.next_seq();
    let request = GenlMessage::new(family, NL80211_CMD_GET_WIPHY, msg::NLM_F_DUMP, seq)
        .attr(Attr::u32(NL80211_ATTR_WIPHY, wiphy))
        .attr(Attr::bytes(NL80211_ATTR_SPLIT_WIPHY_DUMP, &[]));
    if let Err(e) = sock.send(&request.to_bytes(sock.pid)) {
        eprintln!("netlink AP: split GET_WIPHY send failed: {e}");
        return Some(caps);
    }
    for _ in 0..64 {
        let Some(buf) = sock.recv(Duration::from_millis(500)) else {
            break;
        };
        for parsed in msg::parse_messages(&buf) {
            if parsed.seq != seq {
                continue;
            }
            if parsed.typ == msg::NLMSG_DONE {
                return Some(caps);
            }
            if parsed.typ == msg::NLMSG_ERROR {
                let code = parsed.error_code().unwrap_or(-libc::EIO);
                eprintln!("netlink AP: split GET_WIPHY failed: {code}");
                return Some(caps);
            }
            if parsed.typ != family {
                continue;
            }
            let attrs = msg::parse_attrs(parsed.genl_attrs());
            let same_wiphy = msg::find_attr(&attrs, NL80211_ATTR_WIPHY)
                .and_then(|v| v.get(..4))
                .map(|v| u32::from_ne_bytes(v.try_into().unwrap()) == wiphy)
                .unwrap_or(false);
            if same_wiphy {
                if let Some(found) = parse_wiphy_capabilities(&attrs, band) {
                    merge(&mut caps, found);
                }
            }
        }
    }
    Some(caps)
}

fn replace_ie_payload(
    frame: &mut Vec<u8>,
    mut pos: usize,
    id: u8,
    ext_id: Option<u8>,
    body: &[u8],
) {
    while pos + 2 <= frame.len() {
        let len = frame[pos + 1] as usize;
        let end = pos + 2 + len;
        if end > frame.len() {
            return;
        }
        let matches = frame[pos] == id
            && match ext_id {
                Some(ext) => len >= 1 && frame[pos + 2] == ext,
                None => true,
            };
        if matches {
            let extra = usize::from(ext_id.is_some());
            if body.len() + extra > u8::MAX as usize {
                return;
            }
            let mut replacement = Vec::with_capacity(2 + extra + body.len());
            replacement.push(id);
            replacement.push((extra + body.len()) as u8);
            if let Some(ext) = ext_id {
                replacement.push(ext);
            }
            replacement.extend_from_slice(body);
            frame.splice(pos..end, replacement);
            return;
        }
        pos = end;
    }
}

fn apply_wiphy_capabilities(frame: &mut Vec<u8>, caps: &WiphyCapabilities) {
    if frame.len() < 24 || frame[0] & 0x0c != 0 {
        return;
    }
    let ies = match frame[0] & 0xf0 {
        // Beacon and Probe Response: timestamp + interval + capabilities.
        0x80 | 0x50 => 24 + 12,
        // Association and Reassociation Response: capabilities + status + AID.
        0x10 | 0x30 => 24 + 6,
        _ => return,
    };
    if let Some(ht) = &caps.ht {
        replace_ie_payload(frame, ies, 45, None, ht);
    }
    if let Some(vht) = &caps.vht {
        replace_ie_payload(frame, ies, 191, None, vht);
    }
    if let Some(he) = &caps.he {
        replace_ie_payload(frame, ies, 255, Some(35), he);
    }
    if let Some(eht) = &caps.eht {
        replace_ie_payload(frame, ies, 255, Some(108), eht);
    }
}

/// hostapd's nl80211 flush operation: DEL_STATION without NL80211_ATTR_MAC
/// removes every station left by a previous AP instance. This must happen even
/// after SIGKILL/SIGTERM, where userspace destructors cannot be relied upon.
fn nl_flush_stations(sock: &mut NetlinkSocket, family: u16, ifindex: u32) -> io::Result<()> {
    let seq = sock.next_seq();
    sock.request_ack(
        GenlMessage::new(family, NL80211_CMD_DEL_STATION, 0, seq)
            .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex)),
    )
}

/// Read the same live station measurements hostapd exposes from `STA` and
/// `all_sta`. Keeping this on the existing command netlink socket avoids an
/// `iw`/process spawn for every SPR API poll.
fn nl_get_station_telemetry(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    mac: &[u8; 6],
) -> Option<crate::control::StationTelemetry> {
    fn rate(info: &[(u16, &[u8])], kind: u16) -> Option<u32> {
        let nested = msg::parse_attrs(msg::find_attr(info, kind)?);
        if let Some(v) = msg::find_attr(&nested, NL80211_RATE_INFO_BITRATE32) {
            return v
                .get(..4)
                .map(|v| u32::from_ne_bytes(v.try_into().unwrap()));
        }
        msg::find_attr(&nested, NL80211_RATE_INFO_BITRATE)
            .and_then(|v| v.get(..2))
            .map(|v| u16::from_ne_bytes(v.try_into().unwrap()) as u32)
    }

    let seq = sock.next_seq();
    let request = GenlMessage::new(family, NL80211_CMD_GET_STATION, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_MAC, mac));
    sock.send(&request.to_bytes(sock.pid)).ok()?;

    for _ in 0..4 {
        let Some(buf) = sock.recv(Duration::from_millis(100)) else {
            continue;
        };
        for parsed in msg::parse_messages(&buf) {
            if parsed.seq != seq {
                continue;
            }
            if parsed.typ == msg::NLMSG_ERROR {
                return None;
            }
            if parsed.typ != family {
                continue;
            }
            let attrs = msg::parse_attrs(parsed.genl_attrs());
            let info = msg::parse_attrs(msg::find_attr(&attrs, NL80211_ATTR_STA_INFO)?);
            return Some(crate::control::StationTelemetry {
                signal: msg::find_attr(&info, NL80211_STA_INFO_SIGNAL)
                    .and_then(|v| v.first())
                    .map(|v| *v as i8),
                signal_avg: msg::find_attr(&info, NL80211_STA_INFO_SIGNAL_AVG)
                    .and_then(|v| v.first())
                    .map(|v| *v as i8),
                tx_rate_info: rate(&info, NL80211_STA_INFO_TX_BITRATE),
                rx_rate_info: rate(&info, NL80211_STA_INFO_RX_BITRATE),
            });
        }
    }
    None
}

pub fn run_offload_ap(
    mut ap: crate::ap::Ap,
    iface: &str,
    channel: u8,
    ctrl_path: Option<&str>,
    psk_file: Option<&str>,
    spr_api_socket: Option<&str>,
    spr_dhcp_helper: Option<&str>,
) -> io::Result<()> {
    use std::collections::HashSet;

    let mut sock = NetlinkSocket::open()?;
    let (family_id, mlme_group) = resolve_family(&mut sock, "nl80211", "mlme")?;
    let ifindex =
        unsafe { libc::if_nametoindex(format!("{iface}\0").as_ptr() as *const libc::c_char) };
    if ifindex == 0 {
        return Err(io::Error::last_os_error());
    }
    let mld_links = ap.active_mld_links();
    // Primary frequency: 6 GHz is 5950 + 5*chan, otherwise the 2.4/5 GHz table.
    let band6 = ap.band6();
    let nl_band = if band6 {
        4 // NL80211_BAND_6GHZ
    } else if dot11::is_5ghz(channel) {
        1 // NL80211_BAND_5GHZ
    } else {
        0 // NL80211_BAND_2GHZ
    };
    let wiphy_caps =
        nl_get_wiphy_capabilities(&mut sock, family_id, ifindex, nl_band).unwrap_or_default();
    eprintln!(
        "netlink AP: radio capabilities HT={} VHT={} HE={} EHT={} bytes",
        wiphy_caps.ht.as_ref().map_or(0, Vec::len),
        wiphy_caps.vht.as_ref().map_or(0, Vec::len),
        wiphy_caps.he.as_ref().map_or(0, Vec::len),
        wiphy_caps.eht.as_ref().map_or(0, Vec::len),
    );
    let freq: u32 = if band6 {
        5950 + 5 * channel as u32
    } else {
        msg::freq_for_channel(channel)
    };
    // In kernel-offload mode the on-air BSSID is the interface's own MAC:
    // mac80211 stamps addr2/addr3 of the beacon and only forwards management
    // frames whose addr1 == the interface MAC. A non-MLD AP must therefore key
    // its address filter *and* the SAE/PTK addressing off the actual interface
    // MAC, not the config default (02:00:00:00:00:00). On mac80211_hwsim the
    // first radio happens to be 02:00:00:00:00:00, which coincidentally matched
    // the default and hid this bug on virtual radios; on a real card (mt7915,
    // ath12k) the mismatch made the AP silently drop every STA's Authentication
    // frame, so clients saw "unable to join" / auth timeout. For an MLD AP,
    // `ap.mac` is deliberately the association-link MAC (set via ADD_LINK) and
    // `ap.mld_mac` is the interface MAC, so leave the addressing untouched.
    if !ap.mld {
        if let Some(hw) = read_iface_mac(iface) {
            if hw != ap.mac {
                eprintln!(
                    "netlink AP: adopting interface MAC {} as BSSID (config was {})",
                    crate::util::bytes_to_mac(&hw),
                    crate::util::bytes_to_mac(&ap.mac)
                );
                ap.mac = hw;
                ap.mld_mac = hw;
            }
        }
    }
    let bssid = ap.mac;

    // NL80211_CMD_SET_INTERFACE is not a best-effort hint: START_AP requires an
    // NL80211_IFTYPE_AP netdev. Linux rejects a type change while the interface
    // is UP (the exact EOPNOTSUPP seen when SPR renamed an active managed wlan1
    // to wlan3), so mirror `ip link down; iw set type __ap; ip link up` and fail
    // at the real operation if the driver cannot provide AP mode.
    iface_set_state(iface, false)?;
    let seq = sock.next_seq();
    if let Err(e) = sock.request_ack(
        GenlMessage::new(family_id, NL80211_CMD_SET_INTERFACE, 0, seq)
            .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
            .attr(Attr::u32(NL80211_ATTR_IFTYPE, NL80211_IFTYPE_AP)),
    ) {
        let _ = iface_set_state(iface, true);
        return Err(io::Error::other(format!(
            "set {iface} type __ap failed: {e}"
        )));
    }
    iface_set_state(iface, true)?;
    eprintln!("netlink AP: {iface} set type __ap and brought up");
    // Match hostapd's i802_flush(): remove every kernel station left by a
    // previous process before bringing up a new BSS. Without this, a client can
    // remain associated to the old SSID while this BSSID advertises a new one.
    match nl_flush_stations(&mut sock, family_id, ifindex) {
        Ok(()) => eprintln!("netlink AP: flushed stale kernel stations"),
        Err(e) => eprintln!("netlink AP: station flush failed (continuing): {e}"),
    }
    // Register for auth + (re)assoc BEFORE START_AP, the order hostapd uses. On
    // MLO-capable drivers (ath12k) registering only after START_AP leaves the BSS
    // beaconing but never delivers the STA's Authentication/Association frames to
    // userspace — the client sees "unable to join". Registering pre-START_AP binds
    // the subscription to the wdev while the interface is in AP mode. (Repeated
    // post-START_AP registration below is harmless/idempotent.)
    for &st in &REGISTER_SUBTYPES {
        let seq = sock.next_seq();
        let _ = sock.request_ack(
            GenlMessage::new(family_id, NL80211_CMD_REGISTER_FRAME, 0, seq)
                .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
                .attr(Attr::u16v(NL80211_ATTR_FRAME_TYPE, st))
                .attr(Attr::bytes(NL80211_ATTR_FRAME_MATCH, &[])),
        );
    }
    if ap.mld {
        for link in &mld_links {
            nl_add_link(&mut sock, family_id, ifindex, link.link_id, &link.mac).map_err(|e| {
                io::Error::other(format!(
                    "ADD_LINK link_id={} mac={} failed: {e}",
                    link.link_id,
                    crate::util::bytes_to_mac(&link.mac)
                ))
            })?;
            eprintln!(
                "netlink AP: ADD_LINK link_id={} mac={} ok",
                link.link_id,
                crate::util::bytes_to_mac(&link.mac)
            );
        }
    }

    // Derive the nl80211 auth type + RSN AKM suite(s) from the AP's configured
    // security mode, instead of hardcoding open-system + WPA2-PSK. The AKM suite
    // list distinguishes the modes; Transition advertises BOTH PSK and SAE AKMs so
    // WPA2 and WPA3 clients can each pick their AKM.
    //
    // AUTH_TYPE for START_AP must stay OPEN_SYSTEM for every mode here: barely-ap
    // runs the SAE/OWE exchange in *userspace* (the kernel hands auth frames up via
    // REGISTER_FRAME), so it never offloads SAE to the driver. Passing
    // NL80211_AUTHTYPE_SAE asserts driver SAE-offload (NL80211_EXT_FEATURE_SAE_-
    // OFFLOAD_AP); a driver without it (e.g. mac80211_hwsim) rejects START_AP with
    // EINVAL. This is what blocked WPA3-SAE — and therefore the PMF-protected EHT
    // (--phy be) config that 802.11be mandates — on the netlink path.
    let (auth_type, akm_suites): (u32, Vec<u8>) = match ap.security_mode() {
        dot11::SecurityMode::Wpa2 => (
            NL80211_AUTHTYPE_OPEN_SYSTEM,
            WLAN_AKM_SUITE_PSK.to_ne_bytes().to_vec(),
        ),
        dot11::SecurityMode::Wpa3Sae => (
            NL80211_AUTHTYPE_OPEN_SYSTEM,
            WLAN_AKM_SUITE_SAE.to_ne_bytes().to_vec(),
        ),
        dot11::SecurityMode::Transition => {
            let mut a = WLAN_AKM_SUITE_PSK.to_ne_bytes().to_vec();
            a.extend_from_slice(&WLAN_AKM_SUITE_SAE.to_ne_bytes());
            (NL80211_AUTHTYPE_OPEN_SYSTEM, a)
        }
        dot11::SecurityMode::Owe => (
            NL80211_AUTHTYPE_OPEN_SYSTEM,
            WLAN_AKM_SUITE_OWE.to_ne_bytes().to_vec(),
        ),
    };
    // Management Frame Protection is required for SAE and OWE, and mandatory on
    // 6 GHz regardless of AKM.
    let mfp_required = ap.band6()
        || matches!(
            ap.security_mode(),
            dot11::SecurityMode::Wpa3Sae
                | dot11::SecurityMode::Owe
                | dot11::SecurityMode::Transition
        );

    // START_AP: the kernel beacons + (after NEW_KEY) does data CCMP. We keep the
    // 802.1X control port in userspace, delivered over nl80211. The kernel
    // repeats this one beacon, so it must NOT carry a fixed-IPN BIP MME (it would
    // replay forever) — build it without the MME and, when Beacon Protection is
    // on, install the BIGTK so mac80211 generates + increments the per-beacon MME.
    // Join the MLME multicast group first so we receive radar/CAC events, then —
    // on a DFS channel — run the CAC before the kernel will let us beacon.
    if let Some(g) = mlme_group {
        let _ = sock.join_multicast(g);
    }
    for link in &mld_links {
        let link_freq: u32 = if band6 {
            5950 + 5 * link.channel as u32
        } else {
            msg::freq_for_channel(link.channel)
        };
        let link_width = link.width;
        let link_chan_width = match link_width {
            40 => NL80211_CHAN_WIDTH_40,
            80 => NL80211_CHAN_WIDTH_80,
            160 => NL80211_CHAN_WIDTH_160,
            320 => NL80211_CHAN_WIDTH_320,
            _ => NL80211_CHAN_WIDTH_20,
        };
        let link_center_freq1: u32 = if link_width >= 40 {
            dot11::channel_to_center_freq(
                dot11::center_channel(link.channel, link_width, band6),
                band6,
            )
        } else {
            link_freq
        };
        let link_center_chan = if link_width >= 40 {
            dot11::center_channel(link.channel, link_width, band6)
        } else {
            link.channel
        };
        if !band6 && chandef_is_dfs(link_center_chan, link_width) {
            do_cac(
                &mut sock,
                family_id,
                ifindex,
                link_freq,
                link_chan_width,
                link_center_freq1,
            )?;
        }
        let beacon_rt = if ap.mld {
            ap.beacon_frame_unprotected_for_link(link)
        } else {
            ap.beacon_frame_unprotected()
        };
        let mut beacon = dot11::strip_radiotap(&beacon_rt)
            .map(<[u8]>::to_vec)
            .unwrap_or(beacon_rt);
        apply_wiphy_capabilities(&mut beacon, &wiphy_caps);
        let (head, tail) = split_beacon_at_tim(&beacon);
        let seq = sock.next_seq();
        let mut start = GenlMessage::new(family_id, NL80211_CMD_START_AP, 0, seq)
            .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
            .attr(Attr::bytes(NL80211_ATTR_BEACON_HEAD, head))
            .attr(Attr::bytes(NL80211_ATTR_BEACON_TAIL, tail))
            .attr(Attr::u32(NL80211_ATTR_BEACON_INTERVAL, 100))
            .attr(Attr::u32(NL80211_ATTR_DTIM_PERIOD, 2))
            .attr(Attr::bytes(NL80211_ATTR_SSID, &ap.ssid))
            .attr(Attr::u32(NL80211_ATTR_HIDDEN_SSID, 0))
            .attr(Attr::u32(NL80211_ATTR_AUTH_TYPE, auth_type))
            .attr(Attr::bytes(NL80211_ATTR_PRIVACY, &[]))
            .attr(Attr::u32(NL80211_ATTR_WPA_VERSIONS, NL80211_WPA_VERSION_2))
            .attr(Attr::bytes(
                NL80211_ATTR_CIPHER_SUITES_PAIRWISE,
                &WLAN_CIPHER_SUITE_CCMP.to_ne_bytes(),
            ))
            .attr(Attr::u32(
                NL80211_ATTR_CIPHER_SUITE_GROUP,
                WLAN_CIPHER_SUITE_CCMP,
            ))
            .attr(Attr::bytes(NL80211_ATTR_AKM_SUITES, &akm_suites))
            .attr(Attr::bytes(NL80211_ATTR_CONTROL_PORT, &[]))
            .attr(Attr::u16v(NL80211_ATTR_CONTROL_PORT_ETHERTYPE, ETH_P_PAE))
            .attr(Attr::bytes(NL80211_ATTR_CONTROL_PORT_OVER_NL80211, &[]))
            .attr(Attr::bytes(NL80211_ATTR_SOCKET_OWNER, &[]))
            .attr(Attr::u32(NL80211_ATTR_WIPHY_FREQ, link_freq))
            .attr(Attr::u32(NL80211_ATTR_CHANNEL_WIDTH, link_chan_width))
            .attr(Attr::u32(NL80211_ATTR_CENTER_FREQ1, link_center_freq1));
        if mfp_required {
            start = start.attr(Attr::u32(NL80211_ATTR_USE_MFP, NL80211_MFP_REQUIRED));
        }
        if ap.mld {
            start = start.attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link.link_id));
        }
        sock.request_ack(start)?;
        eprintln!(
            "netlink AP: START_AP ok — kernel beaconing {:?} link_id={} on {} MHz (ifindex {ifindex})",
            String::from_utf8_lossy(&ap.ssid),
            link.link_id,
            link_freq
        );
        // hostapd follows its pre-start station flush with a broadcast Deauth
        // once the new beacon is live. The flush removes stale AP-side state;
        // this frame makes clients that survived the restart immediately leave
        // their old association instead of caching the previous SSID on this
        // BSSID until an inactivity timeout.
        const WLAN_REASON_PREV_AUTH_NOT_VALID: u16 = 2;
        let broadcast = [0xff; 6];
        let tx_bssid = if ap.mld { link.mac } else { bssid };
        let deauth = dot11::build_deauth(&tx_bssid, &broadcast, WLAN_REASON_PREV_AUTH_NOT_VALID);
        nl_send_mgmt(
            &mut sock,
            family_id,
            ifindex,
            link_freq,
            &deauth,
            ap.mld.then_some(link.link_id),
        );
        eprintln!("netlink AP: broadcast Deauth sent after BSS restart");
    }
    if ap.mld {
        eprintln!(
            "netlink AP: MLD canonical bssid (ap.mac) = {}",
            crate::util::bytes_to_mac(&bssid)
        );
    }
    // mac80211 needs userspace MLME for an AP: register for auth + (re)assoc so
    // the kernel hands them up (it answers probe requests from the beacon itself).
    for &st in &REGISTER_SUBTYPES {
        let seq = sock.next_seq();
        let _ = sock.request_ack(
            GenlMessage::new(family_id, NL80211_CMD_REGISTER_FRAME, 0, seq)
                .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
                .attr(Attr::u16v(NL80211_ATTR_FRAME_TYPE, st))
                .attr(Attr::bytes(NL80211_ATTR_FRAME_MATCH, &[])),
        );
    }

    let mut stations: Vec<[u8; 6]> = Vec::new();
    let mut keyed: HashSet<[u8; 6]> = HashSet::new();
    // hostapd does not start WPA until the successful Association Response is
    // MAC-ACKed. Track its sequence-control value so a stale TX-status event for
    // an older response cannot release the current handshake's EAPOL frame.
    let mut assoc_tx: std::collections::HashMap<[u8; 6], u16> = std::collections::HashMap::new();
    let mut held_assoc_eapol: std::collections::HashMap<[u8; 6], Vec<u8>> =
        std::collections::HashMap::new();
    // MLD per-link routing: each affiliated link's (BSSID, freq), and the
    // client->link_id route learned from received frames. The core `Ap` runs a
    // single-address (canonical `bssid`) state machine; we translate the wire
    // MPDU addresses at this netlink boundary — incoming link-BSSID -> canonical
    // on RX, canonical -> the client's link-BSSID on TX — and send each response
    // on the link the client is actually using. SAE/4-way crypto is unaffected
    // (it keys off the MLD MAC addresses, not the MPDU addresses).
    let link_params: std::collections::HashMap<u8, ([u8; 6], u32)> = mld_links
        .iter()
        .map(|l| {
            (
                l.link_id,
                (l.mac, crate::netlink::msg::freq_for_channel(l.channel)),
            )
        })
        .collect();
    let mut link_route: std::collections::HashMap<[u8; 6], u8> = std::collections::HashMap::new();
    // The BSS-wide GTK/IGTK installed in the kernel, tracked as (key index,
    // bytes). We install once a station is keyed, then re-install whenever the
    // AP rotates the key (group rekey toggles the GTK index 1<->2 and the IGTK
    // index 4<->5), removing the stale index — a hostapd-style two-phase rekey.
    // (Per-STA-VIF mode installs each station's own GTK on its AP_VLAN instead.)
    let mut gtk_state: std::collections::HashMap<Option<u8>, (u8, [u8; 16])> =
        std::collections::HashMap::new();
    let mut igtk_state: std::collections::HashMap<Option<u8>, (u8, [u8; 16])> =
        std::collections::HashMap::new();
    // BIGTK (Beacon Protection): the (key index, bytes) installed in the kernel,
    // re-installed on rotation (group rekey toggles the IGTK/BIGTK indices). The
    // static START_AP beacon carries NO MME; mac80211 stamps the per-beacon MME
    // from this key. `beacon_prot_on` latches false if the kernel rejects the
    // BIGTK (no offload support) so we never fall back to a fixed-IPN MME.
    let mut bigtk_state: std::collections::HashMap<Option<u8>, (u8, [u8; 16])> =
        std::collections::HashMap::new();
    let mut beacon_prot_on = ap.beacon_prot();
    // Per-STA-VIF: the GTK (key index, bytes) currently installed on each
    // station's AP_VLAN. Re-installed whenever the AP rotates that station's own
    // per-station GTK (group rekey toggles its index 1<->2), removing the stale
    // index — the per-AP_VLAN analogue of the BSS-wide two-phase rekey, so an
    // AP_VLAN never keeps a stale kernel key and isolation is preserved.
    let mut vlan_gtk: std::collections::HashMap<[u8; 6], (u8, [u8; 16])> =
        std::collections::HashMap::new();
    let mut vlan = VlanState {
        enabled: ap.per_sta_vif(),
        base_iface: iface.to_string(),
        map: std::collections::HashMap::new(),
    };

    // hostapd uses separate netlink sockets for synchronous commands vs async
    // events. We do the same: `cmd` issues request/ACK commands (NEW_STATION,
    // NEW_KEY, AP_VLAN, …) so their ACK read-loop never swallows a frame event
    // (auth/assoc/EAPOL) that belongs to the event socket `sock`. Sharing one
    // socket dropped EAPOL frames mid-handshake and made rejoins fail.
    let mut cmd = NetlinkSocket::open()?;

    // Optional hostapd-style runtime control socket (STATUS / STA-DUMP / DEAUTH /
    // FAILURES / ATTACH) carrying live AP-STA-* events to attached clients.
    let mut control =
        ctrl_path.and_then(
            |p| match crate::control::ControlServer::bind(p, iface, psk_file) {
                Ok(c) => {
                    eprintln!("netlink AP: control interface on {p}");
                    Some(c)
                }
                Err(e) => {
                    eprintln!("netlink AP: control interface bind {p} failed: {e}");
                    None
                }
            },
        );
    let spr_notifier = spr_api_socket.map(|path| {
        eprintln!("netlink AP: direct SPR events on Unix socket {path}");
        if let Some(helper) = spr_dhcp_helper {
            eprintln!("netlink AP: SPR DHCP/XDP helper {helper}");
        }
        crate::spr::SprNotifier::new(path, spr_dhcp_helper.map(std::path::PathBuf::from))
    });

    loop {
        // Management frames (auth/assoc) and EAPOL (control port over nl80211)
        // arrive on the event socket. Poll at 20 ms so the tick() below can fire
        // the fast (~30 ms) first EAPOL retransmit promptly on an idle loop.
        if let Some(buf) = sock.recv(Duration::from_millis(20)) {
            for parsed in msg::parse_messages(&buf) {
                if parsed.typ != family_id {
                    continue;
                }
                let attrs = msg::parse_attrs(parsed.genl_attrs());
                if std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
                    if let Some(c) = parsed.genl_cmd() {
                        if c == NL80211_CMD_FRAME || c == NL80211_CMD_CONTROL_PORT_FRAME {
                            let sub = msg::find_attr(&attrs, NL80211_ATTR_FRAME)
                                .and_then(|f| f.get(0).copied())
                                .map(|b| b & 0xfc)
                                .unwrap_or(0xff);
                            eprintln!("netlink AP: RX cmd={c} frame_subtype=0x{sub:02x}");
                        }
                    }
                }
                // 802.11 ACK status for a control-port EAPOL we sent. The event
                // carries the sent frame (Ethernet-framed: dst||src||etype||PDU),
                // so the destination MAC is its first 6 bytes; NL80211_ATTR_ACK is
                // present iff the STA acknowledged it. Feed this to the AP so its
                // retransmit is ACK-driven (resend fast until the STA got it).
                if parsed.genl_cmd() == Some(NL80211_CMD_CONTROL_PORT_FRAME_TX_STATUS) {
                    if let Some(fr) = msg::find_attr(&attrs, NL80211_ATTR_FRAME) {
                        if fr.len() >= 6 && msg::find_attr(&attrs, NL80211_ATTR_ACK).is_some() {
                            let mut dst = [0u8; 6];
                            dst.copy_from_slice(&fr[..6]);
                            // Non-MLD: dst is the station MAC. MLD: dst is the MLD
                            // MAC, so map it to the link station the core tracks.
                            let sta = ap.station_link_for_mld(&dst).unwrap_or(dst);
                            ap.note_eapol_acked(&sta);
                        }
                    }
                    if std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
                        let acked = msg::find_attr(&attrs, NL80211_ATTR_ACK).is_some();
                        let flen = msg::find_attr(&attrs, NL80211_ATTR_FRAME)
                            .map(|f| f.len())
                            .unwrap_or(0);
                        eprintln!("netlink AP: EAPOL TX-STATUS acked={acked} frame_len={flen}");
                    }
                    continue;
                }
                // hostapd pre-adds the kernel station, sends the successful
                // (Re)Association Response, and starts WPA only from this TX-
                // status callback. Mirror that ordering: release the held m1/m3
                // only after an 802.11 ACK. If the response was not ACKed, remove
                // the station we added early so a later association starts clean.
                if parsed.genl_cmd() == Some(NL80211_CMD_FRAME_TX_STATUS) {
                    let acked = msg::find_attr(&attrs, NL80211_ATTR_ACK).is_some();
                    let Some(fr) = msg::find_attr(&attrs, NL80211_ATTR_FRAME) else {
                        continue;
                    };
                    let Some(tx) = dot11::Dot11::parse(fr) else {
                        continue;
                    };
                    let is_assoc_resp = matches!(
                        tx.subtype(),
                        dot11::SUBTYPE_ASSOC_RESP | dot11::SUBTYPE_REASSOC_RESP
                    );
                    let success = is_assoc_resp
                        && tx.body.len() >= 6
                        && u16::from_le_bytes([tx.body[2], tx.body[3]]) == 0;
                    if !success || fr.len() < 24 {
                        continue;
                    }
                    let sta = tx.addr1;
                    let sc = u16::from_le_bytes([fr[22], fr[23]]);
                    if assoc_tx.get(&sta).copied() != Some(sc) {
                        continue;
                    }
                    assoc_tx.remove(&sta);
                    if std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
                        eprintln!(
                            "netlink AP: ASSOC-RESP TX-STATUS sta={} acked={acked} sc={sc}",
                            crate::util::bytes_to_mac(&sta)
                        );
                    }
                    if acked {
                        if let Some(frame) = held_assoc_eapol.remove(&sta) {
                            ap.note_eapol_transmitted(&sta);
                            let released = crate::ap::Outgoing {
                                frames: vec![frame],
                                to_network: Vec::new(),
                            };
                            route_outputs(
                                &mut sock,
                                &mut cmd,
                                family_id,
                                ifindex,
                                freq,
                                &released,
                                &mut stations,
                                &mut keyed,
                                &mut vlan,
                                &ap,
                                &link_route,
                                &link_params,
                                &wiphy_caps,
                                &mut assoc_tx,
                                &mut held_assoc_eapol,
                            );
                        }
                    } else {
                        held_assoc_eapol.remove(&sta);
                        ap.note_assoc_response_not_acked(&sta);
                        let old_vlan = if vlan.enabled {
                            vlan.map.remove(&sta)
                        } else {
                            None
                        };
                        match old_vlan {
                            Some(assignment) => {
                                nl_del_station(&mut cmd, family_id, assignment.ifindex, &sta);
                                nl_del_iface(&mut cmd, family_id, assignment.ifindex);
                            }
                            None => nl_del_station(&mut cmd, family_id, ifindex, &sta),
                        }
                        stations.retain(|s| s != &sta);
                        keyed.remove(&sta);
                    }
                    continue;
                }
                // DFS: radar on the operating channel — vacate within the move time.
                if parsed.genl_cmd() == Some(NL80211_CMD_RADAR_DETECT) {
                    if radar_event(&attrs) == Some(NL80211_RADAR_DETECTED) {
                        let fallback = fallback_channel(channel);
                        eprintln!("netlink AP: RADAR DETECTED on {freq} MHz — vacating (DFS); restart on non-DFS channel {fallback}");
                        let seq = cmd.next_seq();
                        let _ = cmd.request_ack(
                            GenlMessage::new(family_id, NL80211_CMD_STOP_AP, 0, seq)
                                .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex)),
                        );
                        return Err(io::Error::other(format!(
                            "radar detected on channel {channel}; vacated — restart on non-DFS channel {fallback}"
                        )));
                    }
                    continue;
                }
                let rt = match parsed.genl_cmd() {
                    Some(c) if c == NL80211_CMD_FRAME => {
                        let Some(f) = msg::find_attr(&attrs, NL80211_ATTR_FRAME) else {
                            continue;
                        };
                        if ap.mld && std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
                            let attr_summary = attrs
                                .iter()
                                .map(|(typ, data)| format!("{typ}:{}", data.len()))
                                .collect::<Vec<_>>()
                                .join(",");
                            let mac = msg::find_attr(&attrs, NL80211_ATTR_MAC)
                                .filter(|m| m.len() == 6)
                                .map(|m| {
                                    let mut a = [0u8; 6];
                                    a.copy_from_slice(m);
                                    crate::util::bytes_to_mac(&a)
                                })
                                .unwrap_or_else(|| "-".to_string());
                            let mld = msg::find_attr(&attrs, NL80211_ATTR_MLD_ADDR)
                                .filter(|m| m.len() == 6)
                                .map(|m| {
                                    let mut a = [0u8; 6];
                                    a.copy_from_slice(m);
                                    crate::util::bytes_to_mac(&a)
                                })
                                .unwrap_or_else(|| "-".to_string());
                            let link_id = msg::find_attr(&attrs, NL80211_ATTR_MLO_LINK_ID)
                                .and_then(|v| v.first())
                                .map(|v| v.to_string())
                                .unwrap_or_else(|| "-".to_string());
                            eprintln!(
                                "netlink AP: MLD frame attrs mac={mac} mld={mld} link_id={link_id}"
                            );
                            eprintln!("netlink AP: MLD frame attr_ids={attr_summary}");
                            let head_len = f.len().min(48);
                            let mut head = String::new();
                            for b in &f[..head_len] {
                                use std::fmt::Write as _;
                                let _ = write!(&mut head, "{b:02x}");
                            }
                            eprintln!("netlink AP: MLD frame head={head}");
                        }
                        // MLD RX translation: learn which link the client is on
                        // (from MLO_LINK_ID) and rewrite the target link-BSSID
                        // (addr1 RA + addr3 BSSID) to the canonical `bssid` so the
                        // single-address `Ap` matches it. addr2 (the client) is
                        // left untouched.
                        let mut fbytes = f.to_vec();
                        if ap.mld {
                            if fbytes.len() < 22 {
                                continue;
                            }
                            // Validate before translating: only accept a frame whose
                            // reported link is configured and whose RA (addr1) and
                            // BSSID (addr3) match that link's BSSID (or the AP MLD
                            // MAC). This keeps bogus MLO_LINK_ID/BSSID metadata from
                            // steering the per-link route or being rewritten to us.
                            let lid = msg::find_attr(&attrs, NL80211_ATTR_MLO_LINK_ID)
                                .and_then(|v| v.first())
                                .copied();
                            let mut ra = [0u8; 6];
                            ra.copy_from_slice(&fbytes[4..10]);
                            let mut frame_bssid = [0u8; 6];
                            frame_bssid.copy_from_slice(&fbytes[16..22]);
                            let Some((link_bssid, _)) = lid.and_then(|l| link_params.get(&l))
                            else {
                                continue;
                            };
                            let link_ok = (*link_bssid == ra || ra == ap.mld_mac)
                                && (*link_bssid == frame_bssid || frame_bssid == ap.mld_mac);
                            if !link_ok {
                                continue;
                            }
                            let mut client = [0u8; 6];
                            client.copy_from_slice(&fbytes[10..16]);
                            link_route.insert(client, lid.unwrap());
                            fbytes[4..10].copy_from_slice(&bssid);
                            fbytes[16..22].copy_from_slice(&bssid);
                        }
                        let mut v = dot11::RADIOTAP_TX.to_vec();
                        v.extend_from_slice(&fbytes);
                        v
                    }
                    Some(c) if c == NL80211_CMD_CONTROL_PORT_FRAME => {
                        let (Some(eapol), Some(src)) = (
                            msg::find_attr(&attrs, NL80211_ATTR_FRAME),
                            msg::find_attr(&attrs, NL80211_ATTR_MAC),
                        ) else {
                            continue;
                        };
                        if src.len() != 6 {
                            continue;
                        }
                        let mut sta = [0u8; 6];
                        sta.copy_from_slice(src);
                        if ap.mld {
                            if let Some(link_sta) = ap.station_link_for_mld(&sta) {
                                sta = link_sta;
                            }
                            if let Some(&lid) = msg::find_attr(&attrs, NL80211_ATTR_MLO_LINK_ID)
                                .and_then(|v| v.first())
                                .filter(|lid| link_params.contains_key(lid))
                            {
                                link_route.insert(sta, lid);
                            }
                        }
                        if std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
                            let mut s = [0u8; 6];
                            s.copy_from_slice(src);
                            eprintln!(
                                "netlink AP: CTRL_PORT eapol src={} -> sta={} link={:?}",
                                crate::util::bytes_to_mac(&s),
                                crate::util::bytes_to_mac(&sta),
                                msg::find_attr(&attrs, NL80211_ATTR_MLO_LINK_ID)
                                    .and_then(|v| v.first())
                            );
                        }
                        reconstruct_eapol(&bssid, &sta, eapol)
                    }
                    _ => continue,
                };
                let out = ap.handle_incoming(&rt);
                route_outputs(
                    &mut sock,
                    &mut cmd,
                    family_id,
                    ifindex,
                    freq,
                    &out,
                    &mut stations,
                    &mut keyed,
                    &mut vlan,
                    &ap,
                    &link_route,
                    &link_params,
                    &wiphy_caps,
                    &mut assoc_tx,
                    &mut held_assoc_eapol,
                );
            }
        }

        // Handshake-reliability maintenance: retransmit pending EAPOL m1/m3
        // whose m2/m4 was lost, and deauth a station whose 4-way times out. The
        // recv() above blocks ~200 ms, so this runs several times a second.
        let tick_out = ap.tick();
        if !tick_out.frames.is_empty() {
            route_outputs(
                &mut sock,
                &mut cmd,
                family_id,
                ifindex,
                freq,
                &tick_out,
                &mut stations,
                &mut keyed,
                &mut vlan,
                &ap,
                &link_route,
                &link_params,
                &wiphy_caps,
                &mut assoc_tx,
                &mut held_assoc_eapol,
            );
        }

        // Prune bookkeeping for stations the AP has dropped (deauth / 4-way
        // timeout), so `stations`/`keyed` don't grow unbounded over connect/
        // disconnect cycles (and the key-install loop below doesn't iterate dead
        // entries). Keep a disconnected station's AP_VLAN briefly: SPR's
        // hostapd action calls `STA <mac>` after receiving AP-STA-DISCONNECTED,
        // then uses the returned vlan_id to remove DHCP/firewall state.
        let live: HashSet<[u8; 6]> = ap.station_macs().into_iter().collect();
        stations.retain(|s| live.contains(s));
        keyed.retain(|s| live.contains(s));
        assoc_tx.retain(|s, _| live.contains(s));
        held_assoc_eapol.retain(|s, _| live.contains(s));
        if vlan.enabled {
            vlan_gtk.retain(|s, _| live.contains(s));
            let gone: Vec<[u8; 6]> = vlan
                .map
                .keys()
                .copied()
                .filter(|s| !live.contains(s))
                .collect();
            for s in gone {
                let now = Instant::now();
                let remove = match vlan.map.get_mut(&s) {
                    Some(assignment) => match assignment.retire_at {
                        Some(deadline) => now >= deadline,
                        None => {
                            nl_del_station(&mut cmd, family_id, assignment.ifindex, &s);
                            assignment.retire_at = Some(now + VLAN_EVENT_GRACE);
                            false
                        }
                    },
                    None => false,
                };
                if remove {
                    if let Some(assignment) = vlan.map.remove(&s) {
                        nl_del_iface(&mut cmd, family_id, assignment.ifindex);
                    }
                }
            }
        }

        // Install keys for any station that just completed the 4-way. With
        // per-station VIFs the PTK + GTK + authorize go on the station's AP_VLAN
        // (each gets its own group key); otherwise the pairwise key goes on the
        // main AP and the BSS-wide GTK/IGTK is (re)installed below.
        let mut newly_keyed = false;
        for sta in &stations {
            if keyed.contains(sta) || !ap.is_associated(sta) {
                continue;
            }
            let key_if = if vlan.enabled {
                match vlan.map.get(sta) {
                    Some(v) => v.ifindex,
                    None => continue, // VLAN not set up yet; try again next pass
                }
            } else {
                ifindex
            };
            if let Some(tk) = ap.station_tk(sta) {
                let mld_mac = ap.mld.then(|| ap.station_mld_mac(sta)).flatten();
                let key_sta = mld_mac.as_ref().unwrap_or(sta);
                let key_link_id = mld_mac.map(|_| ap.link_id);
                // MLO pairwise keys are addressed to the peer MLD. The kernel
                // rejects MLO_LINK_ID on pairwise NEW_KEY; per-link scoping only
                // applies to group/management keys.
                nl_new_key(
                    &mut cmd,
                    family_id,
                    key_if,
                    Some(key_sta),
                    0,
                    &tk,
                    true,
                    None,
                );
                if vlan.enabled {
                    // The GTK index is BSS-wide (the advertised key id, shared by
                    // every station); only the per-station GTK *value* differs.
                    let gidx = ap.gtk_key_id();
                    let gkey = ap.station_gtk(sta);
                    nl_new_key(
                        &mut cmd,
                        family_id,
                        key_if,
                        None,
                        gidx,
                        &gkey,
                        false,
                        key_link_id,
                    );
                    vlan_gtk.insert(*sta, (gidx, gkey));
                }
                nl_authorize(&mut cmd, family_id, key_if, key_sta, key_link_id);
                if let Some(mld) = mld_mac {
                    for (peer_link_id, peer_link_mac) in ap.station_mld_link_macs(sta) {
                        if peer_link_id == ap.link_id {
                            continue;
                        }
                        nl_authorize_link_station(
                            &mut cmd,
                            family_id,
                            key_if,
                            &mld,
                            peer_link_id,
                            &peer_link_mac,
                            ap.is_pmf(),
                        );
                    }
                }
                keyed.insert(*sta);
                newly_keyed = true;
                eprintln!(
                    "netlink AP: station {} keyed + authorized",
                    crate::util::bytes_to_mac(sta)
                );
            }
        }

        // BSS-wide GTK: install once a station is keyed, and re-install whenever
        // the AP rotates it (group rekey). The kernel must end up using exactly
        // the GTK bytes + index that rekey_gtk() handed the stations — otherwise
        // a departed STA can still read kernel group traffic. (Per-STA-VIF mode
        // has no BSS-wide group key; each AP_VLAN is keyed below instead.)
        if !vlan.enabled && (newly_keyed || !keyed.is_empty()) {
            let gtk_idx = ap.gtk_key_id();
            let gtk = ap.gtk();
            let group_links: Vec<Option<u8>> = if ap.mld {
                ap.active_mld_links()
                    .into_iter()
                    .map(|l| Some(l.link_id))
                    .collect()
            } else {
                vec![None]
            };
            for link_id in group_links {
                if gtk_state.get(&link_id) != Some(&(gtk_idx, gtk)) {
                    // Install the (new) GTK at its index and make it the multicast
                    // default TX key, then remove the previous index.
                    nl_new_key(
                        &mut cmd, family_id, ifindex, None, gtk_idx, &gtk, false, link_id,
                    );
                    if let Some((old_idx, _)) = gtk_state.get(&link_id).copied() {
                        if old_idx != gtk_idx {
                            nl_del_key(&mut cmd, family_id, ifindex, old_idx, link_id);
                        }
                    }
                    gtk_state.insert(link_id, (gtk_idx, gtk));
                }
            }
        }

        // Per-STA-VIF rekey: re-install each station's own rotated GTK on its
        // AP_VLAN at the new (toggled) index, dropping the stale index — the
        // per-AP_VLAN two-phase rekey. Without this, a periodic/strict rekey
        // would hand stations a new key while the AP_VLAN kernel key stayed
        // stale. The initial install above seeds vlan_gtk, so this only fires on
        // an actual rotation.
        if vlan.enabled {
            for sta in &stations {
                if !keyed.contains(sta) {
                    continue;
                }
                let Some(assignment) = vlan.map.get(sta) else {
                    continue;
                };
                let vidx = assignment.ifindex;
                // Shared BSS-wide index, per-station value (see initial install).
                let gidx = ap.gtk_key_id();
                let gkey = ap.station_gtk(sta);
                if vlan_gtk.get(sta) != Some(&(gidx, gkey)) {
                    let link_id = ap.mld.then_some(ap.link_id);
                    nl_new_key(&mut cmd, family_id, vidx, None, gidx, &gkey, false, link_id);
                    if let Some(&(old_idx, _)) = vlan_gtk.get(sta) {
                        if old_idx != gidx {
                            nl_del_key(&mut cmd, family_id, vidx, old_idx, link_id);
                        }
                    }
                    vlan_gtk.insert(*sta, (gidx, gkey));
                }
            }
        }

        // IGTK for PMF (SAE/OWE): BSS-wide (one BIP key for the radio's robust
        // management frames), installed on the main AP interface in both modes so
        // the kernel can BIP-protect/validate them; re-install on rotation.
        if ap.is_pmf() && (newly_keyed || !keyed.is_empty()) {
            let igtk_idx = ap.igtk_key_id() as u8;
            let igtk = ap.igtk();
            let mgmt_links: Vec<Option<u8>> = if ap.mld {
                ap.active_mld_links()
                    .into_iter()
                    .map(|l| Some(l.link_id))
                    .collect()
            } else {
                vec![None]
            };
            for link_id in mgmt_links {
                if igtk_state.get(&link_id) != Some(&(igtk_idx, igtk)) {
                    nl_install_igtk(
                        &mut cmd,
                        family_id,
                        ifindex,
                        igtk_idx,
                        &igtk,
                        &ap.igtk_ipn(),
                        link_id,
                    );
                    if let Some((old_idx, _)) = igtk_state.get(&link_id).copied() {
                        if old_idx != igtk_idx {
                            nl_del_key(&mut cmd, family_id, ifindex, old_idx, link_id);
                        }
                    }
                    igtk_state.insert(link_id, (igtk_idx, igtk));
                }
            }

            // BIGTK (Beacon Protection): install into the kernel so mac80211
            // generates the per-beacon MME. If the kernel rejects it (no offload
            // support), latch beacon protection off — the static beacon already
            // carries no MME, so beacons simply go unprotected rather than ship a
            // replayable fixed-IPN MME.
            if beacon_prot_on {
                let bigtk_idx = ap.bigtk_key_id() as u8;
                let bigtk = ap.bigtk();
                let beacon_links: Vec<Option<u8>> = if ap.mld {
                    ap.active_mld_links()
                        .into_iter()
                        .map(|l| Some(l.link_id))
                        .collect()
                } else {
                    vec![None]
                };
                for link_id in beacon_links {
                    if bigtk_state.get(&link_id) == Some(&(bigtk_idx, bigtk)) {
                        continue;
                    }
                    if nl_install_bigtk(
                        &mut cmd,
                        family_id,
                        ifindex,
                        bigtk_idx,
                        &bigtk,
                        &ap.bigtk_ipn(),
                        link_id,
                    ) {
                        if let Some((old_idx, _)) = bigtk_state.get(&link_id).copied() {
                            if old_idx != bigtk_idx {
                                nl_del_key(&mut cmd, family_id, ifindex, old_idx, link_id);
                            }
                        }
                        bigtk_state.insert(link_id, (bigtk_idx, bigtk));
                        eprintln!("netlink AP: Beacon Protection enabled (BIGTK idx {bigtk_idx} installed; kernel stamps per-beacon MME)");
                    } else {
                        beacon_prot_on = false;
                        eprintln!("netlink AP: kernel rejected BIGTK — Beacon Protection DISABLED (beacons unprotected; no MME emitted)");
                        break;
                    }
                }
            }
        }

        // Control interface: service pending commands (sending any frames they
        // produce, e.g. an admin DEAUTH), then surface AP-STA-* events to the
        // log and to any attached clients.
        if let Some(ctrl) = control.as_mut() {
            let ctrl_frames = {
                // The resolver's public shape is `Fn` because most metadata is
                // an in-memory lookup. RefCell gives that closure narrowly
                // scoped mutable access to the synchronous nl80211 command
                // socket for GET_STATION telemetry; the borrow is gone before
                // route_outputs uses `cmd` below.
                let stats_sock = std::cell::RefCell::new(&mut cmd);
                let station_info = |mac: &[u8; 6]| {
                    vlan.map.get(mac).map(|assignment| {
                        let telemetry = nl_get_station_telemetry(
                            &mut stats_sock.borrow_mut(),
                            family_id,
                            ifindex,
                            mac,
                        );
                        crate::control::StationControlInfo {
                            vlan_id: assignment.vlan_id,
                            ifname: assignment.ifname.clone(),
                            telemetry,
                        }
                    })
                };
                ctrl.service(&mut ap, &station_info)
            };
            if !ctrl_frames.is_empty() {
                let out = crate::ap::Outgoing {
                    frames: ctrl_frames,
                    to_network: Vec::new(),
                };
                route_outputs(
                    &mut sock,
                    &mut cmd,
                    family_id,
                    ifindex,
                    freq,
                    &out,
                    &mut stations,
                    &mut keyed,
                    &mut vlan,
                    &ap,
                    &link_route,
                    &link_params,
                    &wiphy_caps,
                    &mut assoc_tx,
                    &mut held_assoc_eapol,
                );
            }
        }
        for ev in ap.drain_events() {
            // hostapd adds `vlanid` (no underscore) to the connect event. SPR's
            // action script ignores that extra argv today and synchronously asks
            // `STA <mac>` for `vlan_id`, which the control responder above serves.
            let line = match &ev {
                crate::ap::ApEvent::Connected { mac } => match vlan.map.get(mac) {
                    Some(assignment) => format!("{} vlanid={}", ev.to_line(), assignment.vlan_id),
                    None => ev.to_line(),
                },
                _ => ev.to_line(),
            };
            eprintln!("{line}");
            if let Some(ctrl) = control.as_mut() {
                ctrl.broadcast(&line);
            }
            if let Some(notifier) = spr_notifier.as_ref() {
                use crate::ap::ApEvent;
                use crate::spr::SprEvent;

                let mac = match &ev {
                    ApEvent::Connected { mac }
                    | ApEvent::Disconnected { mac, .. }
                    | ApEvent::AuthFailed { mac, .. } => mac,
                };
                let iface = vlan
                    .map
                    .get(mac)
                    .map(|assignment| assignment.ifname.clone())
                    .unwrap_or_else(|| vlan.base_iface.clone());
                let mac = crate::util::bytes_to_mac(mac);
                let spr_event = match &ev {
                    ApEvent::Connected { .. } => Some(SprEvent::Connected { iface, mac }),
                    ApEvent::Disconnected { .. } => Some(SprEvent::Disconnected { iface, mac }),
                    ApEvent::AuthFailed { kind, .. } => SprEvent::auth_failure(iface, mac, *kind),
                };
                if let Some(event) = spr_event {
                    notifier.notify(event);
                }
            }
        }
    }
}

/// Remove a station from the kernel (on disconnect, or before re-adding a
/// rejoining client). Best-effort: a no-op if the station does not exist.
fn nl_del_station(sock: &mut NetlinkSocket, family: u16, ifindex: u32, sta: &[u8; 6]) {
    let seq = sock.next_seq();
    let m = GenlMessage::new(family, NL80211_CMD_DEL_STATION, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_MAC, sta));
    let _ = sock.request_ack(m);
}

/// Bring a network interface up (set IFF_UP) via an ioctl, like hostapd's
/// `linux_set_iface_flags`. Needed after creating an AP_VLAN interface.
fn iface_set_state(name: &str, up: bool) -> io::Result<()> {
    #[repr(C)]
    struct IfReq {
        name: [u8; 16],
        flags: libc::c_short,
        _pad: [u8; 22],
    }
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut req: IfReq = std::mem::zeroed();
        for (i, &b) in name.as_bytes().iter().take(15).enumerate() {
            req.name[i] = b;
        }
        let mut rc = libc::ioctl(fd, libc::SIOCGIFFLAGS as _, &mut req as *mut IfReq);
        if rc >= 0 {
            if up {
                req.flags |= libc::IFF_UP as libc::c_short;
            } else {
                req.flags &= !(libc::IFF_UP as libc::c_short);
            }
            rc = libc::ioctl(fd, libc::SIOCSIFFLAGS as _, &req as *const IfReq);
        }
        let err = io::Error::last_os_error();
        libc::close(fd);
        if rc < 0 {
            return Err(err);
        }
    }
    Ok(())
}

fn iface_set_up(name: &str) -> io::Result<()> {
    iface_set_state(name, true)
}

/// Create an `AP_VLAN` interface beneath the AP (NEW_INTERFACE), bring it up,
/// and return its ifindex. Each per-station VIF gets its own such interface.
fn nl_create_ap_vlan(
    sock: &mut NetlinkSocket,
    family: u16,
    ap_ifindex: u32,
    name: &str,
) -> io::Result<u32> {
    let seq = sock.next_seq();
    let m = GenlMessage::new(family, NL80211_CMD_NEW_INTERFACE, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ap_ifindex))
        .attr(Attr::string(NL80211_ATTR_IFNAME, name))
        .attr(Attr::u32(NL80211_ATTR_IFTYPE, NL80211_IFTYPE_AP_VLAN))
        // Per-station VIFs are process-scoped. Tying them to the command socket
        // makes the kernel remove them on clean shutdown or a crash, preventing
        // stale interfaces from exhausting the radio's interface limit.
        .attr(Attr::bytes(NL80211_ATTR_SOCKET_OWNER, &[]));
    sock.request_ack(m)?;
    let cname = format!("{name}\0");
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr() as *const libc::c_char) };
    if idx == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "AP_VLAN ifindex lookup failed",
        ));
    }
    iface_set_up(name)?;
    Ok(idx)
}

/// Create an additional standalone AP interface on the same radio as the primary
/// (NEW_INTERFACE keyed by the primary's ifindex resolves to its wiphy), assign
/// it the BSS's BSSID, bring it up, and return its ifindex. The interface is
/// created with NL80211_ATTR_SOCKET_OWNER, so the kernel deletes it when `sock`
/// closes — no leaked netdevs on shutdown, even on SIGKILL.
fn nl_create_ap_bss(
    sock: &mut NetlinkSocket,
    family: u16,
    primary_ifindex: u32,
    name: &str,
    mac: &[u8; 6],
) -> io::Result<u32> {
    let seq = sock.next_seq();
    let m = GenlMessage::new(family, NL80211_CMD_NEW_INTERFACE, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, primary_ifindex))
        .attr(Attr::string(NL80211_ATTR_IFNAME, name))
        .attr(Attr::u32(NL80211_ATTR_IFTYPE, NL80211_IFTYPE_AP))
        .attr(Attr::bytes(NL80211_ATTR_MAC, mac))
        .attr(Attr::bytes(NL80211_ATTR_SOCKET_OWNER, &[]));
    sock.request_ack(m)?;
    let cname = format!("{name}\0");
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr() as *const libc::c_char) };
    if idx == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "BSS ifindex lookup failed",
        ));
    }
    iface_set_up(name)?;
    Ok(idx)
}

/// Run a primary AP plus any additional co-hosted BSSes on the same radio. Each
/// extra BSS gets its own AP netdev (distinct BSSID) and runs an independent
/// [`run_offload_ap`] on its own thread — its own 4-way, keys, and stations —
/// so the verified single-BSS path is reused unchanged. The primary runs in the
/// caller's thread (and owns the control interface).
pub fn run_offload_aps(
    primary: crate::ap::Ap,
    extra: Vec<crate::ap::Ap>,
    iface: &str,
    channel: u8,
    ctrl_path: Option<&str>,
    psk_file: Option<&str>,
    spr_api_socket: Option<&str>,
    spr_dhcp_helper: Option<&str>,
) -> io::Result<()> {
    // The creator socket must outlive the BSSes it makes: each extra netdev is
    // SOCKET_OWNER-tied to it, so the kernel deletes the netdev when this socket
    // closes — on clean return (its Drop) or process exit (incl. SIGKILL). Bind
    // it to `_bss_owner` so it lives for the whole run rather than dropping after
    // the setup loop (which would delete the netdevs out from under the threads).
    let _bss_owner = if extra.is_empty() {
        None
    } else {
        let mut setup = NetlinkSocket::open()?;
        let (family, _) = resolve_family(&mut setup, "nl80211", "mlme")?;
        let cname = format!("{iface}\0");
        let primary_ifindex =
            unsafe { libc::if_nametoindex(cname.as_ptr() as *const libc::c_char) };
        if primary_ifindex == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("interface {iface} not found"),
            ));
        }
        for (i, ap) in extra.into_iter().enumerate() {
            let name = format!("{iface}.ap{i}");
            let mac = ap.mac;
            if let Err(e) = nl_create_ap_bss(&mut setup, family, primary_ifindex, &name, &mac) {
                eprintln!("netlink AP: create BSS interface {name} failed: {e}");
                continue;
            }
            eprintln!(
                "netlink AP: BSS {:?} on {name} (bssid {})",
                String::from_utf8_lossy(&ap.ssid),
                crate::util::bytes_to_mac(&mac)
            );
            let spr_api_socket = spr_api_socket.map(str::to_owned);
            let spr_dhcp_helper = spr_dhcp_helper.map(str::to_owned);
            let psk_file = psk_file.map(str::to_owned);
            let bss_ctrl = ctrl_path.and_then(|primary| {
                let path = std::path::Path::new(primary);
                let dir = path.parent()?;
                let expected_dir = format!("control_{iface}");
                if path.file_name()?.to_str()? != iface
                    || dir.file_name()?.to_str()? != expected_dir
                {
                    return None;
                }
                Some(
                    dir.parent()?
                        .join(format!("control_{name}"))
                        .join(&name)
                        .to_string_lossy()
                        .into_owned(),
                )
            });
            std::thread::spawn(move || {
                if let Err(e) = run_offload_ap(
                    ap,
                    &name,
                    channel,
                    bss_ctrl.as_deref(),
                    psk_file.as_deref(),
                    spr_api_socket.as_deref(),
                    spr_dhcp_helper.as_deref(),
                ) {
                    eprintln!("netlink AP: BSS {name} exited: {e}");
                }
            });
        }
        Some(setup)
    };
    run_offload_ap(
        primary,
        iface,
        channel,
        ctrl_path,
        psk_file,
        spr_api_socket,
        spr_dhcp_helper,
    )
}

/// Move a station into an AP_VLAN (SET_STATION + NL80211_ATTR_STA_VLAN), so its
/// data path and group key live on that per-station interface.
fn nl_set_sta_vlan(
    sock: &mut NetlinkSocket,
    family: u16,
    ap_ifindex: u32,
    sta: &[u8; 6],
    vlan_ifindex: u32,
) -> io::Result<()> {
    let seq = sock.next_seq();
    let m = GenlMessage::new(family, NL80211_CMD_SET_STATION, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ap_ifindex))
        .attr(Attr::bytes(NL80211_ATTR_MAC, sta))
        .attr(Attr::u32(NL80211_ATTR_STA_VLAN, vlan_ifindex));
    sock.request_ack(m)
}

/// Delete a dynamically-created interface (an AP_VLAN) by ifindex.
fn nl_del_iface(sock: &mut NetlinkSocket, family: u16, ifindex: u32) {
    let seq = sock.next_seq();
    let m = GenlMessage::new(family, NL80211_CMD_DEL_INTERFACE, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex));
    let _ = sock.request_ack(m);
}

/// Allow an attached hostapd_cli action enough time to query `STA <mac>` and
/// remove SPR DHCP/firewall state after a disconnect event.
const VLAN_EVENT_GRACE: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
struct VlanAssignment {
    ifindex: u32,
    vlan_id: u32,
    ifname: String,
    retire_at: Option<Instant>,
}

/// Per-station-VIF bookkeeping. IDs and names follow hostapd's wildcard VLAN
/// convention (`wlan3.#` -> `wlan3.4096`, `wlan3.4097`, ...).
struct VlanState {
    enabled: bool,
    base_iface: String,
    map: std::collections::HashMap<[u8; 6], VlanAssignment>,
}

impl VlanState {
    fn allocate(&self) -> io::Result<(u32, String)> {
        let vlan_id = first_free_per_sta_vlan_id(self.map.values().map(|v| v.vlan_id))
            .ok_or_else(|| io::Error::other("no free per-station VIF id"))?;
        let ifname = per_sta_vif_name(&self.base_iface, vlan_id).map_err(io::Error::other)?;
        Ok((vlan_id, ifname))
    }
}

/// Route the AP state machine's output frames to the kernel: management frames
/// over nl80211, EAPOL over the packet socket, and add a station on association.
#[allow(clippy::too_many_arguments)]
/// Resolve the (freq, MLO link id) a response to `dest` must be sent on. For a
/// non-MLD AP this is just the primary freq with no link id; for an MLD AP it is
/// the link the client was last seen on (learned into `link_route`), defaulting
/// to the association link.
fn mld_route(
    ap: &crate::ap::Ap,
    link_route: &std::collections::HashMap<[u8; 6], u8>,
    link_params: &std::collections::HashMap<u8, ([u8; 6], u32)>,
    default_freq: u32,
    dest: &[u8; 6],
) -> (u32, Option<u8>) {
    if !ap.mld {
        return (default_freq, None);
    }
    let lid = link_route
        .get(dest)
        .copied()
        .filter(|lid| link_params.contains_key(lid))
        .unwrap_or(ap.link_id);
    match link_params.get(&lid) {
        Some((_bssid, freq)) => (*freq, Some(lid)),
        None => link_params
            .get(&ap.link_id)
            .map(|(_bssid, freq)| (*freq, Some(ap.link_id)))
            .unwrap_or((default_freq, None)),
    }
}

#[allow(clippy::too_many_arguments)]
fn route_outputs(
    sock: &mut NetlinkSocket,
    cmd: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    freq: u32,
    out: &crate::ap::Outgoing,
    stations: &mut Vec<[u8; 6]>,
    keyed: &mut std::collections::HashSet<[u8; 6]>,
    vlan: &mut VlanState,
    ap: &crate::ap::Ap,
    link_route: &std::collections::HashMap<[u8; 6], u8>,
    link_params: &std::collections::HashMap<u8, ([u8; 6], u32)>,
    wiphy_caps: &WiphyCapabilities,
    assoc_tx: &mut std::collections::HashMap<[u8; 6], u16>,
    held_assoc_eapol: &mut std::collections::HashMap<[u8; 6], Vec<u8>>,
) {
    for f in &out.frames {
        let Some(body) = dot11::strip_radiotap(f) else {
            continue;
        };
        let Some(d) = dot11::Dot11::parse(body) else {
            continue;
        };
        if d.frame_type() == dot11::TYPE_MGMT {
            if d.subtype() == dot11::SUBTYPE_BEACON {
                continue; // the kernel beacons
            }
            let is_assoc_resp = matches!(
                d.subtype(),
                dot11::SUBTYPE_ASSOC_RESP | dot11::SUBTYPE_REASSOC_RESP
            );
            let assoc_succeeded = is_assoc_resp
                && d.body.len() >= 6
                && u16::from_le_bytes([d.body[2], d.body[3]]) == 0;

            // hostapd's add_associated_sta() runs before send_assoc_resp(). It
            // deliberately puts the kernel station into associated state early:
            // otherwise cfg80211/the driver can drop EAPOL data before the
            // Association Response TX-status is processed. Our old order was the
            // reverse (send response, DEL/NEW/SET station, send m1), so ath12k
            // could apply the DEL_STATION after accepting the response for TX and
            // leave the ensuing 4-way frames queued against a torn-down peer.
            // Configure only successful responses; rejected associations must
            // never create a kernel station.
            if assoc_succeeded && !(stations.contains(&d.addr1) && !keyed.contains(&d.addr1)) {
                let cap = u16::from_le_bytes([d.body[0], d.body[1]]);
                let aid = u16::from_le_bytes([d.body[4], d.body[5]]) & 0x3fff;
                // (Re-)association: tear down any prior incarnation of this
                // station and rebuild it, and drop it from `keyed` so the fresh
                // 4-way re-installs keys (a rejoining client derives new keys).
                // A station that previously lived in an AP_VLAN must be removed
                // from *that* interface, then its VLAN torn down — deleting it on
                // the main AP leaves a stale station on the old VLAN.
                let old_vlan = if vlan.enabled {
                    vlan.map.remove(&d.addr1)
                } else {
                    None
                };
                match old_vlan {
                    Some(assignment) => {
                        nl_del_station(cmd, family, assignment.ifindex, &d.addr1);
                        nl_del_iface(cmd, family, assignment.ifindex);
                    }
                    None => nl_del_station(cmd, family, ifindex, &d.addr1),
                }
                // HT/VHT caps go in SET_STATION (the only place rate control reads
                // them); NEW_STATION adds the station unassociated first so SET can
                // apply them without EINVAL. RUSTAP_NO_STA_CAPS=1 disables caps
                // entirely as a driver-compatibility escape hatch.
                let sta_caps = if std::env::var_os("RUSTAP_NO_STA_CAPS").is_some() {
                    None
                } else {
                    ap.station_assoc_ies(&d.addr1)
                };
                let listen_interval = ap.station_listen_interval(&d.addr1).unwrap_or(0);
                let mld_mac = ap.mld.then(|| ap.station_mld_mac(&d.addr1)).flatten();
                let link_id = mld_mac.map(|_| ap.link_id);
                nl_new_station(cmd, family, ifindex, &d.addr1, mld_mac.as_ref(), link_id);
                nl_set_station_assoc(
                    cmd,
                    family,
                    ifindex,
                    &d.addr1,
                    aid,
                    listen_interval,
                    cap,
                    sta_caps,
                    mld_mac.as_ref(),
                    link_id,
                    mld_mac.is_some(),
                    ap.is_pmf(),
                );
                if let Some(mld) = mld_mac {
                    for (peer_link_id, peer_link_mac) in ap.station_mld_link_macs(&d.addr1) {
                        if peer_link_id == ap.link_id {
                            continue;
                        }
                        nl_add_link_station(
                            cmd,
                            family,
                            ifindex,
                            &mld,
                            peer_link_id,
                            &peer_link_mac,
                            aid,
                            listen_interval,
                            cap,
                            sta_caps,
                            ap.is_pmf(),
                        );
                    }
                }
                keyed.remove(&d.addr1);
                if !stations.contains(&d.addr1) {
                    stations.push(d.addr1);
                }
                if vlan.enabled {
                    // Per-station VIF: give this station its own AP_VLAN so its
                    // group key is isolated from other stations. Match hostapd's
                    // `<base>.#` naming and lowest-free id allocation.
                    let (vlan_id, name) = match vlan.allocate() {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("netlink AP: allocate per-station VIF failed: {e}");
                            continue;
                        }
                    };
                    match nl_create_ap_vlan(cmd, family, ifindex, &name) {
                        Ok(vidx) => {
                            if let Err(e) = nl_set_sta_vlan(cmd, family, ifindex, &d.addr1, vidx) {
                                eprintln!("netlink AP: set_sta_vlan failed: {e}");
                                nl_del_iface(cmd, family, vidx);
                            } else {
                                vlan.map.insert(
                                    d.addr1,
                                    VlanAssignment {
                                        ifindex: vidx,
                                        vlan_id,
                                        ifname: name.clone(),
                                        retire_at: None,
                                    },
                                );
                                eprintln!(
                                    "netlink AP: station {} -> {name} (vlan_id {vlan_id}, ifindex {vidx})",
                                    crate::util::bytes_to_mac(&d.addr1)
                                );
                            }
                        }
                        Err(e) => eprintln!("netlink AP: create AP_VLAN {name} failed: {e}"),
                    }
                }
            }
            if assoc_succeeded && body.len() >= 24 {
                let sc = u16::from_le_bytes([body[22], body[23]]);
                assoc_tx.insert(d.addr1, sc);
            }
            // MLD TX translation: send on the client's link, and rewrite the
            // source (addr2 TA + addr3 BSSID) from the canonical `bssid` to that
            // link's BSSID so the client sees the response from the address it
            // targeted.
            let (tfreq, tlink) = mld_route(ap, link_route, link_params, freq, &d.addr1);
            let mut tx = body.to_vec();
            if let Some(lb) = tlink.and_then(|l| link_params.get(&l)).map(|(b, _)| *b) {
                if tx.len() >= 22 {
                    tx[10..16].copy_from_slice(&lb);
                    tx[16..22].copy_from_slice(&lb);
                }
            }
            apply_wiphy_capabilities(&mut tx, wiphy_caps);
            nl_send_mgmt(sock, family, ifindex, tfreq, &tx, tlink);
        } else if d.frame_type() == dot11::TYPE_DATA && d.body.len() > 8 {
            if assoc_tx.contains_key(&d.addr1) {
                // Keep only the newest copy. tick() may produce a retry while the
                // management-frame TX status is pending; queueing every copy here
                // would recreate the stale-frame flood this gate is meant to stop.
                held_assoc_eapol.insert(d.addr1, f.clone());
                if std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
                    eprintln!(
                        "netlink AP: hold EAPOL for ASSOC-RESP ACK sta={}",
                        crate::util::bytes_to_mac(&d.addr1)
                    );
                }
                continue;
            }
            let mld_mac = ap.mld.then(|| ap.station_mld_mac(&d.addr1)).flatten();
            let dst = mld_mac.as_ref().unwrap_or(&d.addr1);
            // Send the EAPOL on the client's link (the kernel builds the MPDU
            // with that link's address from the link id). Uses the command socket:
            // the send is synchronous (NLM_F_ACK) so kernel rejections surface,
            // and waiting on the event socket would drop frame events.
            let (_f, link_id) = mld_route(ap, link_route, link_params, freq, &d.addr1);
            let eapol = &d.body[8..];
            nl_send_eapol(cmd, family, ifindex, dst, eapol, link_id);
        }
    }
}
