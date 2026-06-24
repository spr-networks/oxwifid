//! Linux nl80211 socket and [`Link`] implementation.

#![cfg(target_os = "linux")]

use std::io;
use std::os::unix::io::RawFd;
use std::time::Duration;

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
            if libc::bind(fd, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_nl>() as u32) < 0 {
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
            libc::setsockopt(fd, SOL_NETLINK, NETLINK_EXT_ACK, &on as *const _ as *const libc::c_void, 4);
            Ok(NetlinkSocket { fd, pid: sa.nl_pid, seq: 1 })
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
            let mut pfd = libc::pollfd { fd: self.fd, events: libc::POLLIN, revents: 0 };
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
            let mut buf = vec![0u8; 8192];
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
                                    let s = String::from_utf8_lossy(data.split(|&b| b == 0).next().unwrap_or(data));
                                    return Err(io::Error::other(format!("{} ({s})", io::Error::from_raw_os_error(-code))));
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
fn resolve_family(sock: &mut NetlinkSocket, family: &str, mcast_group: &str) -> io::Result<(u16, Option<u32>)> {
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
                        let n = name.iter().take_while(|&&c| c != 0).cloned().collect::<Vec<u8>>();
                        if n == mcast_group.as_bytes() {
                            gid = Some(u32::from_ne_bytes([id[0], id[1], id[2], id[3]]));
                        }
                    }
                }
            }
            return Ok((family_id, gid));
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "nl80211 family not found"))
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

        let ifindex = unsafe { libc::if_nametoindex(format!("{iface}\0").as_ptr() as *const libc::c_char) };
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

        Ok(NetlinkLink { sock, family_id, ifindex, freq })
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
fn nl_send_mgmt(sock: &mut NetlinkSocket, family: u16, ifindex: u32, freq: u32, frame: &[u8]) {
    let seq = sock.next_seq();
    let m = GenlMessage::new(family, NL80211_CMD_FRAME, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::u32(NL80211_ATTR_WIPHY_FREQ, freq))
        .attr(Attr::bytes(NL80211_ATTR_FRAME, frame));
    let _ = sock.send(&m.to_bytes(sock.pid));
}

/// Send an EAPOL payload to `dst` over the nl80211 control port (unencrypted,
/// pre-key). The kernel wraps it into an 802.11 data frame to the station.
fn nl_send_eapol(sock: &mut NetlinkSocket, family: u16, ifindex: u32, dst: &[u8; 6], eapol: &[u8]) {
    let seq = sock.next_seq();
    let m = GenlMessage::new(family, NL80211_CMD_CONTROL_PORT_FRAME, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_MAC, dst))
        .attr(Attr::u16v(NL80211_ATTR_CONTROL_PORT_ETHERTYPE, ETH_P_PAE))
        .attr(Attr::bytes(NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT, &[]))
        .attr(Attr::bytes(NL80211_ATTR_FRAME, eapol));
    let _ = sock.send(&m.to_bytes(sock.pid));
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
fn nl_new_station(sock: &mut NetlinkSocket, family: u16, ifindex: u32, sta: &[u8; 6]) {
    // Add the station UNASSOCIATED (flags cleared). SET_STATION then marks it
    // associated AND carries the HT/VHT caps — rate control only picks caps up
    // from SET_STATION, and applying them to an already-associated station fails
    // EINVAL, so the station must start unassociated here.
    let unassoc = (1u32 << NL80211_STA_FLAG_AUTHENTICATED) | (1u32 << NL80211_STA_FLAG_ASSOCIATED);
    let seq = sock.next_seq();
    // CCK (1/2/5.5/11) + OFDM (6..54), 500-kbps units, no basic bit.
    let rates: &[u8] = &[0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c];
    let _ = STA_OFDM_RATES;
    let m = GenlMessage::new(family, NL80211_CMD_NEW_STATION, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_MAC, sta))
        .attr(Attr::u16v(NL80211_ATTR_STA_AID, 1))
        .attr(Attr::u16v(NL80211_ATTR_STA_LISTEN_INTERVAL, 0))
        .attr(Attr::bytes(NL80211_ATTR_STA_SUPPORTED_RATES, rates))
        .attr(Attr::bytes(NL80211_ATTR_STA_FLAGS2, &sta_flags(unassoc, 0)));
    match sock.request_ack(m) {
        Ok(()) => eprintln!("netlink AP: NEW_STATION {} ok (unassoc)", crate::util::bytes_to_mac(sta)),
        Err(e) => eprintln!("netlink AP: NEW_STATION {} failed: {e}", crate::util::bytes_to_mac(sta)),
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

fn nl_set_station_assoc(sock: &mut NetlinkSocket, family: u16, ifindex: u32, sta: &[u8; 6], aid: u16, capability: u16, assoc_ies: Option<&[u8]>) {
    let assoc = (1u32 << NL80211_STA_FLAG_AUTHENTICATED) | (1u32 << NL80211_STA_FLAG_ASSOCIATED);
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
    let mut m = GenlMessage::new(family, NL80211_CMD_SET_STATION, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_MAC, sta))
        .attr(Attr::u16v(NL80211_ATTR_STA_AID, aid))
        .attr(Attr::u16v(NL80211_ATTR_STA_LISTEN_INTERVAL, 200))
        .attr(Attr::bytes(NL80211_ATTR_STA_SUPPORTED_RATES, &rates))
        .attr(Attr::u16v(NL80211_ATTR_STA_CAPABILITY, capability))
        .attr(Attr::bytes(NL80211_ATTR_STA_FLAGS2, &sta_flags(assoc, assoc)));
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
        // HE caps break this driver's offload data path (the station associates at
        // an HE rate but is unpingable); off by default. RUSTAP_HE_CAP=1 re-enables.
        if let Some(he) = find_ext_ie(ies, 35) {
            if std::env::var_os("RUSTAP_HE_CAP").is_some() {
                m = m.attr(Attr::bytes(NL80211_ATTR_HE_CAPABILITY, he));
            }
        }
        // Mark the station QoS/WMM-capable so the kernel enables A-MPDU
        // aggregation. The QoS Info byte comes from the station's WMM Information
        // element; without this nest a VHT/HE station negotiates a high MCS but
        // moves almost no data (every MPDU goes out unaggregated). hostapd sends
        // the identical nested attribute.
        if let Some(qosinfo) = find_wmm_qosinfo(ies) {
            m = m.attr(Attr::nested(
                NL80211_ATTR_STA_WME,
                &[
                    Attr::bytes(NL80211_STA_WME_UAPSD_QUEUES, &[qosinfo & 0x0f]),
                    Attr::bytes(NL80211_STA_WME_MAX_SP, &[(qosinfo >> 5) & 0x03]),
                ],
            ));
        }
    }
    if let Err(e) = sock.request_ack(m) {
        eprintln!("netlink AP: SET_STATION(assoc) {} failed: {e}", crate::util::bytes_to_mac(sta));
    }
}

/// Install a CCMP key into the kernel (pairwise PTK or group GTK).
fn nl_new_key(sock: &mut NetlinkSocket, family: u16, ifindex: u32, sta: Option<&[u8; 6]>, idx: u8, key: &[u8], pairwise: bool) {
    let seq = sock.next_seq();
    let mut m = GenlMessage::new(family, NL80211_CMD_NEW_KEY, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_KEY_DATA, key))
        .attr(Attr::u32(NL80211_ATTR_KEY_CIPHER, WLAN_CIPHER_SUITE_CCMP))
        .attr(Attr::bytes(NL80211_ATTR_KEY_IDX, &[idx]))
        .attr(Attr::u32(NL80211_ATTR_KEY_TYPE, if pairwise { NL80211_KEYTYPE_PAIRWISE } else { NL80211_KEYTYPE_GROUP }));
    if let Some(s) = sta {
        m = m.attr(Attr::bytes(NL80211_ATTR_MAC, s));
    } else {
        // The group key is the default TX key for group-addressed frames; the
        // kernel needs this set for the AP data path to come up. Scope the
        // default to multicast so it doesn't clobber the pairwise (unicast)
        // default key.
        m = m
            .attr(Attr::bytes(NL80211_ATTR_KEY_DEFAULT, &[]))
            .attr(Attr::nested(NL80211_ATTR_KEY_DEFAULT_TYPES, &[Attr::bytes(NL80211_KEY_DEFAULT_TYPE_MULTICAST, &[])]));
    }
    if let Err(e) = sock.request_ack(m) {
        eprintln!("netlink AP: NEW_KEY (idx {idx}, pairwise {pairwise}) failed: {e}");
    }
}

/// Install the IGTK (BIP-CMAC-128) into the kernel and make it the default
/// management key, so mac80211 can TX/validate BIP-protected robust management
/// frames. `idx` is the IGTK key index (4/5) and `ipn` the 6-octet receive
/// sequence counter (little-endian, as in the MME).
fn nl_install_igtk(sock: &mut NetlinkSocket, family: u16, ifindex: u32, idx: u8, igtk: &[u8; 16], ipn: &[u8; 6]) {
    let seq = sock.next_seq();
    let m = GenlMessage::new(family, NL80211_CMD_NEW_KEY, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_KEY_DATA, igtk))
        .attr(Attr::u32(NL80211_ATTR_KEY_CIPHER, WLAN_CIPHER_SUITE_BIP_CMAC_128))
        .attr(Attr::bytes(NL80211_ATTR_KEY_IDX, &[idx]))
        .attr(Attr::bytes(NL80211_ATTR_KEY_SEQ, ipn))
        .attr(Attr::u32(NL80211_ATTR_KEY_TYPE, NL80211_KEYTYPE_GROUP))
        .attr(Attr::bytes(NL80211_ATTR_KEY_DEFAULT_MGMT, &[]));
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
fn nl_install_bigtk(sock: &mut NetlinkSocket, family: u16, ifindex: u32, idx: u8, bigtk: &[u8; 16], ipn: &[u8; 6]) -> bool {
    let seq = sock.next_seq();
    // No KEY_DEFAULT/DEFAULT_MGMT flag: mac80211 recognises the 6/7 index range
    // plus the BIP cipher as the beacon-protection key on its own (there is no
    // "default beacon key" nl80211 attribute, unlike the IGTK's DEFAULT_MGMT).
    let m = GenlMessage::new(family, NL80211_CMD_NEW_KEY, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_KEY_DATA, bigtk))
        .attr(Attr::u32(NL80211_ATTR_KEY_CIPHER, WLAN_CIPHER_SUITE_BIP_CMAC_128))
        .attr(Attr::bytes(NL80211_ATTR_KEY_IDX, &[idx]))
        .attr(Attr::bytes(NL80211_ATTR_KEY_SEQ, ipn))
        .attr(Attr::u32(NL80211_ATTR_KEY_TYPE, NL80211_KEYTYPE_GROUP));
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
fn nl_del_key(sock: &mut NetlinkSocket, family: u16, ifindex: u32, idx: u8) {
    let seq = sock.next_seq();
    let m = GenlMessage::new(family, NL80211_CMD_DEL_KEY, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_KEY_IDX, &[idx]))
        .attr(Attr::u32(NL80211_ATTR_KEY_TYPE, NL80211_KEYTYPE_GROUP));
    let _ = sock.request_ack(m);
}

/// Mark a station 802.1X-authorized so the kernel forwards its data frames.
fn nl_authorize(sock: &mut NetlinkSocket, family: u16, ifindex: u32, sta: &[u8; 6]) {
    let bit = 1u32 << NL80211_STA_FLAG_AUTHORIZED;
    let mut flags = bit.to_ne_bytes().to_vec(); // mask
    flags.extend_from_slice(&bit.to_ne_bytes()); // set
    let seq = sock.next_seq();
    let m = GenlMessage::new(family, NL80211_CMD_SET_STATION, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_MAC, sta))
        .attr(Attr::bytes(NL80211_ATTR_STA_FLAGS2, &flags));
    let _ = sock.request_ack(m);
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
fn do_cac(sock: &mut NetlinkSocket, family: u16, ifindex: u32, freq: u32, chan_width: u32, center_freq1: u32) -> io::Result<()> {
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
        let Some(buf) = sock.recv(Duration::from_secs(5)) else { continue };
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
                    return Err(io::Error::other("radar detected during CAC; channel unusable"));
                }
                _ => {}
            }
        }
    }
    Err(io::Error::other("DFS CAC timed out"))
}

pub fn run_offload_ap(mut ap: crate::ap::Ap, iface: &str, channel: u8, ctrl_path: Option<&str>) -> io::Result<()> {
    use std::collections::HashSet;

    let mut sock = NetlinkSocket::open()?;
    let (family_id, mlme_group) = resolve_family(&mut sock, "nl80211", "mlme")?;
    let ifindex = unsafe { libc::if_nametoindex(format!("{iface}\0").as_ptr() as *const libc::c_char) };
    if ifindex == 0 {
        return Err(io::Error::last_os_error());
    }
    // Primary frequency: 6 GHz is 5950 + 5*chan, otherwise the 2.4/5 GHz table.
    let band6 = ap.band6();
    let freq: u32 = if band6 {
        5950 + 5 * channel as u32
    } else {
        msg::freq_for_channel(channel)
    };
    let bssid = ap.mac;

    // Channel width: map the configured width to the nl80211 enum and compute
    // the center frequency of the wide block (band-aware). For 20 MHz the center
    // is the primary channel itself.
    let width = ap.width();
    let chan_width = match width {
        40 => NL80211_CHAN_WIDTH_40,
        80 => NL80211_CHAN_WIDTH_80,
        160 => NL80211_CHAN_WIDTH_160,
        320 => NL80211_CHAN_WIDTH_320,
        _ => NL80211_CHAN_WIDTH_20,
    };
    let center_freq1: u32 = if width >= 40 {
        dot11::channel_to_center_freq(dot11::center_channel(channel, width, band6), band6)
    } else {
        freq
    };
    let center_chan = if width >= 40 { dot11::center_channel(channel, width, band6) } else { channel };
    // 6 GHz has no DFS; only 5 GHz radar channels need a CAC.
    let needs_cac = !band6 && chandef_is_dfs(center_chan, width);

    let seq = sock.next_seq();
    let _ = sock.request_ack(
        GenlMessage::new(family_id, NL80211_CMD_SET_INTERFACE, 0, seq)
            .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
            .attr(Attr::u32(NL80211_ATTR_IFTYPE, NL80211_IFTYPE_AP)),
    );

    // Derive the nl80211 auth type + RSN AKM suite(s) from the AP's configured
    // security mode, instead of hardcoding open-system + WPA2-PSK. SAE uses the
    // SAE auth type (the kernel/driver expects it for a WPA3 BSS); OWE and PSK use
    // open-system. Transition advertises BOTH PSK and SAE AKMs so WPA2 and WPA3
    // clients can each pick their AKM. (6 GHz mandates WPA3/SAE, so this is also
    // what makes a 6 GHz / 320 MHz AP possible at all.)
    let (auth_type, akm_suites): (u32, Vec<u8>) = match ap.security_mode() {
        dot11::SecurityMode::Wpa2 => (NL80211_AUTHTYPE_OPEN_SYSTEM, WLAN_AKM_SUITE_PSK.to_ne_bytes().to_vec()),
        dot11::SecurityMode::Wpa3Sae => (NL80211_AUTHTYPE_SAE, WLAN_AKM_SUITE_SAE.to_ne_bytes().to_vec()),
        dot11::SecurityMode::Transition => {
            let mut a = WLAN_AKM_SUITE_PSK.to_ne_bytes().to_vec();
            a.extend_from_slice(&WLAN_AKM_SUITE_SAE.to_ne_bytes());
            (NL80211_AUTHTYPE_SAE, a)
        }
        dot11::SecurityMode::Owe => (NL80211_AUTHTYPE_OPEN_SYSTEM, WLAN_AKM_SUITE_OWE.to_ne_bytes().to_vec()),
    };
    // Management Frame Protection is required for SAE and OWE, and mandatory on
    // 6 GHz regardless of AKM.
    let mfp_required = ap.band6()
        || matches!(ap.security_mode(), dot11::SecurityMode::Wpa3Sae | dot11::SecurityMode::Owe | dot11::SecurityMode::Transition);

    // START_AP: the kernel beacons + (after NEW_KEY) does data CCMP. We keep the
    // 802.1X control port in userspace, delivered over nl80211. The kernel
    // repeats this one beacon, so it must NOT carry a fixed-IPN BIP MME (it would
    // replay forever) — build it without the MME and, when Beacon Protection is
    // on, install the BIGTK so mac80211 generates + increments the per-beacon MME.
    let beacon_rt = ap.beacon_frame_unprotected();
    let beacon = dot11::strip_radiotap(&beacon_rt).map(<[u8]>::to_vec).unwrap_or(beacon_rt);
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
        .attr(Attr::bytes(NL80211_ATTR_CIPHER_SUITES_PAIRWISE, &WLAN_CIPHER_SUITE_CCMP.to_ne_bytes()))
        .attr(Attr::u32(NL80211_ATTR_CIPHER_SUITE_GROUP, WLAN_CIPHER_SUITE_CCMP))
        .attr(Attr::bytes(NL80211_ATTR_AKM_SUITES, &akm_suites))
        .attr(Attr::bytes(NL80211_ATTR_CONTROL_PORT, &[]))
        .attr(Attr::u16v(NL80211_ATTR_CONTROL_PORT_ETHERTYPE, ETH_P_PAE))
        .attr(Attr::bytes(NL80211_ATTR_CONTROL_PORT_OVER_NL80211, &[]))
        .attr(Attr::bytes(NL80211_ATTR_SOCKET_OWNER, &[]))
        .attr(Attr::u32(NL80211_ATTR_WIPHY_FREQ, freq))
        .attr(Attr::u32(NL80211_ATTR_CHANNEL_WIDTH, chan_width))
        .attr(Attr::u32(NL80211_ATTR_CENTER_FREQ1, center_freq1));
    if mfp_required {
        start = start.attr(Attr::u32(NL80211_ATTR_USE_MFP, NL80211_MFP_REQUIRED));
    }
    // Join the MLME multicast group first so we receive radar/CAC events, then —
    // on a DFS channel — run the CAC before the kernel will let us beacon.
    if let Some(g) = mlme_group {
        let _ = sock.join_multicast(g);
    }
    if needs_cac {
        do_cac(&mut sock, family_id, ifindex, freq, chan_width, center_freq1)?;
    }
    sock.request_ack(start)?;
    eprintln!("netlink AP: START_AP ok — kernel beaconing {:?} on {freq} MHz (ifindex {ifindex})", String::from_utf8_lossy(&ap.ssid));
    // mac80211 needs userspace MLME for an AP: register for auth + (re)assoc so
    // the kernel hands them up (it answers probe requests from the beacon itself).
    for &st in &[0x00b0u16, 0x0000, 0x0020] {
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
    // The BSS-wide GTK/IGTK installed in the kernel, tracked as (key index,
    // bytes). We install once a station is keyed, then re-install whenever the
    // AP rotates the key (group rekey toggles the GTK index 1<->2 and the IGTK
    // index 4<->5), removing the stale index — a hostapd-style two-phase rekey.
    // (Per-STA-VIF mode installs each station's own GTK on its AP_VLAN instead.)
    let mut gtk_state: Option<(u8, [u8; 16])> = None;
    let mut igtk_state: Option<(u8, [u8; 16])> = None;
    // BIGTK (Beacon Protection): the (key index, bytes) installed in the kernel,
    // re-installed on rotation (group rekey toggles the IGTK/BIGTK indices). The
    // static START_AP beacon carries NO MME; mac80211 stamps the per-beacon MME
    // from this key. `beacon_prot_on` latches false if the kernel rejects the
    // BIGTK (no offload support) so we never fall back to a fixed-IPN MME.
    let mut bigtk_state: Option<(u8, [u8; 16])> = None;
    let mut beacon_prot_on = ap.beacon_prot();
    // Per-STA-VIF: the GTK (key index, bytes) currently installed on each
    // station's AP_VLAN. Re-installed whenever the AP rotates that station's own
    // per-station GTK (group rekey toggles its index 1<->2), removing the stale
    // index — the per-AP_VLAN analogue of the BSS-wide two-phase rekey, so an
    // AP_VLAN never keeps a stale kernel key and isolation is preserved.
    let mut vlan_gtk: std::collections::HashMap<[u8; 6], (u8, [u8; 16])> = std::collections::HashMap::new();
    let mut vlan = VlanState {
        enabled: ap.per_sta_vif(),
        map: std::collections::HashMap::new(),
        seq: 0,
    };

    // hostapd uses separate netlink sockets for synchronous commands vs async
    // events. We do the same: `cmd` issues request/ACK commands (NEW_STATION,
    // NEW_KEY, AP_VLAN, …) so their ACK read-loop never swallows a frame event
    // (auth/assoc/EAPOL) that belongs to the event socket `sock`. Sharing one
    // socket dropped EAPOL frames mid-handshake and made rejoins fail.
    let mut cmd = NetlinkSocket::open()?;

    // Optional hostapd-style runtime control socket (STATUS / STA-DUMP / DEAUTH /
    // FAILURES / ATTACH) carrying live AP-STA-* events to attached clients.
    let mut control = ctrl_path.and_then(|p| match crate::control::ControlServer::bind(p) {
        Ok(c) => {
            eprintln!("netlink AP: control interface on {p}");
            Some(c)
        }
        Err(e) => {
            eprintln!("netlink AP: control interface bind {p} failed: {e}");
            None
        }
    });

    loop {
        // Management frames (auth/assoc) and EAPOL (control port over nl80211)
        // arrive on the event socket.
        if let Some(buf) = sock.recv(Duration::from_millis(200)) {
            for parsed in msg::parse_messages(&buf) {
                if parsed.typ != family_id {
                    continue;
                }
                let attrs = msg::parse_attrs(parsed.genl_attrs());
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
                        let Some(f) = msg::find_attr(&attrs, NL80211_ATTR_FRAME) else { continue };
                        let mut v = dot11::RADIOTAP_TX.to_vec();
                        v.extend_from_slice(f);
                        v
                    }
                    Some(c) if c == NL80211_CMD_CONTROL_PORT_FRAME => {
                        let (Some(eapol), Some(src)) = (msg::find_attr(&attrs, NL80211_ATTR_FRAME), msg::find_attr(&attrs, NL80211_ATTR_MAC)) else { continue };
                        if src.len() != 6 {
                            continue;
                        }
                        let mut sta = [0u8; 6];
                        sta.copy_from_slice(src);
                        reconstruct_eapol(&bssid, &sta, eapol)
                    }
                    _ => continue,
                };
                let out = ap.handle_incoming(&rt);
                route_outputs(&mut sock, &mut cmd, family_id, ifindex, freq, &out, &mut stations, &mut keyed, &mut vlan, &ap);
            }
        }

        // Handshake-reliability maintenance: retransmit pending EAPOL m1/m3
        // whose m2/m4 was lost, and deauth a station whose 4-way times out. The
        // recv() above blocks ~200 ms, so this runs several times a second.
        let tick_out = ap.tick();
        if !tick_out.frames.is_empty() {
            route_outputs(&mut sock, &mut cmd, family_id, ifindex, freq, &tick_out, &mut stations, &mut keyed, &mut vlan, &ap);
        }

        // Prune bookkeeping for stations the AP has dropped (deauth / 4-way
        // timeout), so `stations`/`keyed` don't grow unbounded over connect/
        // disconnect cycles (and the key-install loop below doesn't iterate dead
        // entries), and any leaked AP_VLAN interface is torn down.
        let live: HashSet<[u8; 6]> = ap.station_macs().into_iter().collect();
        stations.retain(|s| live.contains(s));
        keyed.retain(|s| live.contains(s));
        if vlan.enabled {
            vlan_gtk.retain(|s, _| live.contains(s));
            let gone: Vec<[u8; 6]> = vlan.map.keys().copied().filter(|s| !live.contains(s)).collect();
            for s in gone {
                if let Some(vidx) = vlan.map.remove(&s) {
                    nl_del_station(&mut cmd, family_id, vidx, &s);
                    nl_del_iface(&mut cmd, family_id, vidx);
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
                    Some(&v) => v,
                    None => continue, // VLAN not set up yet; try again next pass
                }
            } else {
                ifindex
            };
            if let Some(tk) = ap.station_tk(sta) {
                nl_new_key(&mut cmd, family_id, key_if, Some(sta), 0, &tk, true);
                if vlan.enabled {
                    // The GTK index is BSS-wide (the advertised key id, shared by
                    // every station); only the per-station GTK *value* differs.
                    let gidx = ap.gtk_key_id();
                    let gkey = ap.station_gtk(sta);
                    nl_new_key(&mut cmd, family_id, key_if, None, gidx, &gkey, false);
                    vlan_gtk.insert(*sta, (gidx, gkey));
                }
                nl_authorize(&mut cmd, family_id, key_if, sta);
                keyed.insert(*sta);
                newly_keyed = true;
                eprintln!("netlink AP: station {} keyed + authorized", crate::util::bytes_to_mac(sta));
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
            if gtk_state != Some((gtk_idx, gtk)) {
                // Install the (new) GTK at its index and make it the multicast
                // default TX key, then remove the previous index.
                nl_new_key(&mut cmd, family_id, ifindex, None, gtk_idx, &gtk, false);
                if let Some((old_idx, _)) = gtk_state {
                    if old_idx != gtk_idx {
                        nl_del_key(&mut cmd, family_id, ifindex, old_idx);
                    }
                }
                gtk_state = Some((gtk_idx, gtk));
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
                let Some(&vidx) = vlan.map.get(sta) else { continue };
                // Shared BSS-wide index, per-station value (see initial install).
                let gidx = ap.gtk_key_id();
                let gkey = ap.station_gtk(sta);
                if vlan_gtk.get(sta) != Some(&(gidx, gkey)) {
                    nl_new_key(&mut cmd, family_id, vidx, None, gidx, &gkey, false);
                    if let Some(&(old_idx, _)) = vlan_gtk.get(sta) {
                        if old_idx != gidx {
                            nl_del_key(&mut cmd, family_id, vidx, old_idx);
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
            if igtk_state != Some((igtk_idx, igtk)) {
                nl_install_igtk(&mut cmd, family_id, ifindex, igtk_idx, &igtk, &ap.igtk_ipn());
                if let Some((old_idx, _)) = igtk_state {
                    if old_idx != igtk_idx {
                        nl_del_key(&mut cmd, family_id, ifindex, old_idx);
                    }
                }
                igtk_state = Some((igtk_idx, igtk));
            }

            // BIGTK (Beacon Protection): install into the kernel so mac80211
            // generates the per-beacon MME. If the kernel rejects it (no offload
            // support), latch beacon protection off — the static beacon already
            // carries no MME, so beacons simply go unprotected rather than ship a
            // replayable fixed-IPN MME.
            if beacon_prot_on {
                let bigtk_idx = ap.bigtk_key_id() as u8;
                let bigtk = ap.bigtk();
                if bigtk_state != Some((bigtk_idx, bigtk)) {
                    if nl_install_bigtk(&mut cmd, family_id, ifindex, bigtk_idx, &bigtk, &ap.bigtk_ipn()) {
                        if let Some((old_idx, _)) = bigtk_state {
                            if old_idx != bigtk_idx {
                                nl_del_key(&mut cmd, family_id, ifindex, old_idx);
                            }
                        }
                        bigtk_state = Some((bigtk_idx, bigtk));
                        eprintln!("netlink AP: Beacon Protection enabled (BIGTK idx {bigtk_idx} installed; kernel stamps per-beacon MME)");
                    } else {
                        beacon_prot_on = false;
                        eprintln!("netlink AP: kernel rejected BIGTK — Beacon Protection DISABLED (beacons unprotected; no MME emitted)");
                    }
                }
            }
        }

        // Control interface: service pending commands (sending any frames they
        // produce, e.g. an admin DEAUTH), then surface AP-STA-* events to the
        // log and to any attached clients.
        if let Some(ctrl) = control.as_mut() {
            let ctrl_frames = ctrl.service(&mut ap);
            if !ctrl_frames.is_empty() {
                let out = crate::ap::Outgoing { frames: ctrl_frames, to_network: Vec::new() };
                route_outputs(&mut sock, &mut cmd, family_id, ifindex, freq, &out, &mut stations, &mut keyed, &mut vlan, &ap);
            }
        }
        for ev in ap.drain_events() {
            let line = ev.to_line();
            eprintln!("{line}");
            if let Some(ctrl) = control.as_mut() {
                ctrl.broadcast(&line);
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
fn iface_set_up(name: &str) -> io::Result<()> {
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
            req.flags |= libc::IFF_UP as libc::c_short;
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

/// Create an `AP_VLAN` interface beneath the AP (NEW_INTERFACE), bring it up,
/// and return its ifindex. Each per-station VIF gets its own such interface.
fn nl_create_ap_vlan(sock: &mut NetlinkSocket, family: u16, ap_ifindex: u32, name: &str) -> io::Result<u32> {
    let seq = sock.next_seq();
    let m = GenlMessage::new(family, NL80211_CMD_NEW_INTERFACE, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ap_ifindex))
        .attr(Attr::string(NL80211_ATTR_IFNAME, name))
        .attr(Attr::u32(NL80211_ATTR_IFTYPE, NL80211_IFTYPE_AP_VLAN));
    sock.request_ack(m)?;
    let cname = format!("{name}\0");
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr() as *const libc::c_char) };
    if idx == 0 {
        return Err(io::Error::new(io::ErrorKind::NotFound, "AP_VLAN ifindex lookup failed"));
    }
    iface_set_up(name)?;
    Ok(idx)
}

/// Create an additional standalone AP interface on the same radio as the primary
/// (NEW_INTERFACE keyed by the primary's ifindex resolves to its wiphy), assign
/// it the BSS's BSSID, bring it up, and return its ifindex. The interface is
/// created with NL80211_ATTR_SOCKET_OWNER, so the kernel deletes it when `sock`
/// closes — no leaked netdevs on shutdown, even on SIGKILL.
fn nl_create_ap_bss(sock: &mut NetlinkSocket, family: u16, primary_ifindex: u32, name: &str, mac: &[u8; 6]) -> io::Result<u32> {
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
        return Err(io::Error::new(io::ErrorKind::NotFound, "BSS ifindex lookup failed"));
    }
    iface_set_up(name)?;
    Ok(idx)
}

/// Run a primary AP plus any additional co-hosted BSSes on the same radio. Each
/// extra BSS gets its own AP netdev (distinct BSSID) and runs an independent
/// [`run_offload_ap`] on its own thread — its own 4-way, keys, and stations —
/// so the verified single-BSS path is reused unchanged. The primary runs in the
/// caller's thread (and owns the control interface).
pub fn run_offload_aps(primary: crate::ap::Ap, extra: Vec<crate::ap::Ap>, iface: &str, channel: u8, ctrl_path: Option<&str>) -> io::Result<()> {
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
        let primary_ifindex = unsafe { libc::if_nametoindex(cname.as_ptr() as *const libc::c_char) };
        if primary_ifindex == 0 {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("interface {iface} not found")));
        }
        for (i, ap) in extra.into_iter().enumerate() {
            let name = format!("{iface}-{}", i + 1);
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
            std::thread::spawn(move || {
                if let Err(e) = run_offload_ap(ap, &name, channel, None) {
                    eprintln!("netlink AP: BSS {name} exited: {e}");
                }
            });
        }
        Some(setup)
    };
    run_offload_ap(primary, iface, channel, ctrl_path)
}

/// Move a station into an AP_VLAN (SET_STATION + NL80211_ATTR_STA_VLAN), so its
/// data path and group key live on that per-station interface.
fn nl_set_sta_vlan(sock: &mut NetlinkSocket, family: u16, ap_ifindex: u32, sta: &[u8; 6], vlan_ifindex: u32) -> io::Result<()> {
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

/// Per-station-VIF bookkeeping: maps each station to its AP_VLAN ifindex.
struct VlanState {
    enabled: bool,
    map: std::collections::HashMap<[u8; 6], u32>,
    seq: u32,
}

/// Route the AP state machine's output frames to the kernel: management frames
/// over nl80211, EAPOL over the packet socket, and add a station on association.
#[allow(clippy::too_many_arguments)]
fn route_outputs(sock: &mut NetlinkSocket, cmd: &mut NetlinkSocket, family: u16, ifindex: u32, freq: u32, out: &crate::ap::Outgoing, stations: &mut Vec<[u8; 6]>, keyed: &mut std::collections::HashSet<[u8; 6]>, vlan: &mut VlanState, ap: &crate::ap::Ap) {
    for f in &out.frames {
        let Some(body) = dot11::strip_radiotap(f) else { continue };
        let Some(d) = dot11::Dot11::parse(body) else { continue };
        if d.frame_type() == dot11::TYPE_MGMT {
            if d.subtype() == dot11::SUBTYPE_BEACON {
                continue; // the kernel beacons
            }
            nl_send_mgmt(sock, family, ifindex, freq, body);
            if d.subtype() == dot11::SUBTYPE_ASSOC_RESP && d.body.len() >= 6 {
                let cap = u16::from_le_bytes([d.body[0], d.body[1]]);
                let aid = u16::from_le_bytes([d.body[4], d.body[5]]) & 0x3fff;
                // (Re-)association: tear down any prior incarnation of this
                // station and rebuild it, and drop it from `keyed` so the fresh
                // 4-way re-installs keys (a rejoining client derives new keys).
                // A station that previously lived in an AP_VLAN must be removed
                // from *that* interface, then its VLAN torn down — deleting it on
                // the main AP leaves a stale station on the old VLAN.
                let old_vlan = if vlan.enabled { vlan.map.remove(&d.addr1) } else { None };
                match old_vlan {
                    Some(ov) => {
                        nl_del_station(cmd, family, ov, &d.addr1);
                        nl_del_iface(cmd, family, ov);
                    }
                    None => nl_del_station(cmd, family, ifindex, &d.addr1),
                }
                // HT/VHT caps go in SET_STATION (the only place rate control reads
                // them); NEW_STATION adds the station unassociated first so SET can
                // apply them without EINVAL. HE caps are dropped inside SET — they
                // break this driver's offload data path, so run the BSS as VHT
                // (--phy ac). RUSTAP_NO_STA_CAPS=1 disables caps entirely (legacy).
                let sta_caps = if std::env::var_os("RUSTAP_NO_STA_CAPS").is_some() {
                    None
                } else {
                    ap.station_assoc_ies(&d.addr1)
                };
                nl_new_station(cmd, family, ifindex, &d.addr1);
                nl_set_station_assoc(cmd, family, ifindex, &d.addr1, aid, cap, sta_caps);
                keyed.remove(&d.addr1);
                if !stations.contains(&d.addr1) {
                    stations.push(d.addr1);
                }
                if vlan.enabled {
                    // Per-station VIF: give this station its own AP_VLAN so its
                    // group key is isolated from other stations.
                    vlan.seq += 1;
                    let name = format!("apvlan{}", vlan.seq);
                    match nl_create_ap_vlan(cmd, family, ifindex, &name) {
                        Ok(vidx) => {
                            if let Err(e) = nl_set_sta_vlan(cmd, family, ifindex, &d.addr1, vidx) {
                                eprintln!("netlink AP: set_sta_vlan failed: {e}");
                                nl_del_iface(cmd, family, vidx);
                            } else {
                                vlan.map.insert(d.addr1, vidx);
                                eprintln!("netlink AP: station {} -> {name} (ifindex {vidx})", crate::util::bytes_to_mac(&d.addr1));
                            }
                        }
                        Err(e) => eprintln!("netlink AP: create AP_VLAN {name} failed: {e}"),
                    }
                }
            }
        } else if d.frame_type() == dot11::TYPE_DATA && d.body.len() > 8 {
            nl_send_eapol(sock, family, ifindex, &d.addr1, &d.body[8..]);
        }
    }
}
