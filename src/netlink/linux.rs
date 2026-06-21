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
    let unassoc = (1u32 << NL80211_STA_FLAG_AUTHENTICATED) | (1u32 << NL80211_STA_FLAG_ASSOCIATED);
    let seq = sock.next_seq();
    // 2.4 GHz: CCK (1/2/5.5/11) + OFDM (6..54), all in 500-kbps units, no basic bit.
    let rates: &[u8] = &[0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c];
    let m = GenlMessage::new(family, NL80211_CMD_NEW_STATION, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_MAC, sta))
        .attr(Attr::u16v(NL80211_ATTR_STA_AID, 1))
        .attr(Attr::u16v(NL80211_ATTR_STA_LISTEN_INTERVAL, 0))
        .attr(Attr::bytes(NL80211_ATTR_STA_SUPPORTED_RATES, rates))
        .attr(Attr::bytes(NL80211_ATTR_STA_FLAGS2, &sta_flags(unassoc, 0)));
    let _ = STA_OFDM_RATES;
    match sock.request_ack(m) {
        Ok(()) => eprintln!("netlink AP: NEW_STATION {} ok (unassoc)", crate::util::bytes_to_mac(sta)),
        Err(e) => eprintln!("netlink AP: NEW_STATION {} failed: {e}", crate::util::bytes_to_mac(sta)),
    }
}

/// Promote a station to the associated state (SET_STATION with the real aid,
/// capability and AUTH/ASSOC flags) once it has (re)associated.
fn nl_set_station_assoc(sock: &mut NetlinkSocket, family: u16, ifindex: u32, sta: &[u8; 6], aid: u16, capability: u16) {
    let assoc = (1u32 << NL80211_STA_FLAG_AUTHENTICATED) | (1u32 << NL80211_STA_FLAG_ASSOCIATED);
    let seq = sock.next_seq();
    let m = GenlMessage::new(family, NL80211_CMD_SET_STATION, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_MAC, sta))
        .attr(Attr::u16v(NL80211_ATTR_STA_AID, aid))
        .attr(Attr::u16v(NL80211_ATTR_STA_LISTEN_INTERVAL, 200))
        .attr(Attr::bytes(NL80211_ATTR_STA_SUPPORTED_RATES, &STA_OFDM_RATES))
        .attr(Attr::u16v(NL80211_ATTR_STA_CAPABILITY, capability))
        .attr(Attr::bytes(NL80211_ATTR_STA_FLAGS2, &sta_flags(assoc, assoc)));
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
        // kernel needs this set for the AP data path to come up.
        m = m.attr(Attr::bytes(NL80211_ATTR_KEY_DEFAULT, &[]));
    }
    if let Err(e) = sock.request_ack(m) {
        eprintln!("netlink AP: NEW_KEY (idx {idx}, pairwise {pairwise}) failed: {e}");
    }
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
pub fn run_offload_ap(mut ap: crate::ap::Ap, iface: &str, channel: u8) -> io::Result<()> {
    use std::collections::HashSet;

    let mut sock = NetlinkSocket::open()?;
    let (family_id, mlme_group) = resolve_family(&mut sock, "nl80211", "mlme")?;
    let ifindex = unsafe { libc::if_nametoindex(format!("{iface}\0").as_ptr() as *const libc::c_char) };
    if ifindex == 0 {
        return Err(io::Error::last_os_error());
    }
    let freq = msg::freq_for_channel(channel);
    let bssid = ap.mac;

    let seq = sock.next_seq();
    let _ = sock.request_ack(
        GenlMessage::new(family_id, NL80211_CMD_SET_INTERFACE, 0, seq)
            .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
            .attr(Attr::u32(NL80211_ATTR_IFTYPE, NL80211_IFTYPE_AP)),
    );

    // START_AP: the kernel beacons + (after NEW_KEY) does data CCMP. We keep the
    // 802.1X control port in userspace, delivered over nl80211.
    let beacon_rt = ap.beacon_frame();
    let beacon = dot11::strip_radiotap(&beacon_rt).map(<[u8]>::to_vec).unwrap_or(beacon_rt);
    let (head, tail) = split_beacon_at_tim(&beacon);
    let seq = sock.next_seq();
    let start = GenlMessage::new(family_id, NL80211_CMD_START_AP, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_BEACON_HEAD, head))
        .attr(Attr::bytes(NL80211_ATTR_BEACON_TAIL, tail))
        .attr(Attr::u32(NL80211_ATTR_BEACON_INTERVAL, 100))
        .attr(Attr::u32(NL80211_ATTR_DTIM_PERIOD, 2))
        .attr(Attr::bytes(NL80211_ATTR_SSID, &ap.ssid))
        .attr(Attr::u32(NL80211_ATTR_HIDDEN_SSID, 0))
        .attr(Attr::u32(NL80211_ATTR_AUTH_TYPE, NL80211_AUTHTYPE_OPEN_SYSTEM))
        .attr(Attr::bytes(NL80211_ATTR_PRIVACY, &[]))
        .attr(Attr::u32(NL80211_ATTR_WPA_VERSIONS, NL80211_WPA_VERSION_2))
        .attr(Attr::bytes(NL80211_ATTR_CIPHER_SUITES_PAIRWISE, &WLAN_CIPHER_SUITE_CCMP.to_ne_bytes()))
        .attr(Attr::u32(NL80211_ATTR_CIPHER_SUITE_GROUP, WLAN_CIPHER_SUITE_CCMP))
        .attr(Attr::bytes(NL80211_ATTR_AKM_SUITES, &WLAN_AKM_SUITE_PSK.to_ne_bytes()))
        .attr(Attr::bytes(NL80211_ATTR_CONTROL_PORT, &[]))
        .attr(Attr::u16v(NL80211_ATTR_CONTROL_PORT_ETHERTYPE, ETH_P_PAE))
        .attr(Attr::bytes(NL80211_ATTR_CONTROL_PORT_OVER_NL80211, &[]))
        .attr(Attr::bytes(NL80211_ATTR_SOCKET_OWNER, &[]))
        .attr(Attr::u32(NL80211_ATTR_WIPHY_FREQ, freq))
        .attr(Attr::u32(NL80211_ATTR_CHANNEL_WIDTH, NL80211_CHAN_WIDTH_20))
        .attr(Attr::u32(NL80211_ATTR_CENTER_FREQ1, freq));
    sock.request_ack(start)?;
    eprintln!("netlink AP: START_AP ok — kernel beaconing {:?} on {freq} MHz (ifindex {ifindex})", String::from_utf8_lossy(&ap.ssid));

    if let Some(g) = mlme_group {
        let _ = sock.join_multicast(g);
    }
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
    // The GTK is BSS-wide: install it once. Re-installing it (e.g. on a client
    // rejoin) resets the group-key PN and breaks broadcast for every station.
    let mut gtk_installed = false;
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

    loop {
        // Management frames (auth/assoc) and EAPOL (control port over nl80211)
        // arrive on the event socket.
        if let Some(buf) = sock.recv(Duration::from_millis(200)) {
            for parsed in msg::parse_messages(&buf) {
                if parsed.typ != family_id {
                    continue;
                }
                let attrs = msg::parse_attrs(parsed.genl_attrs());
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
                route_outputs(&mut sock, &mut cmd, family_id, ifindex, freq, &out, &mut stations, &mut keyed, &mut vlan);
            }
        }

        // Install keys for any station that just completed the 4-way. With
        // per-station VIFs the PTK + GTK + authorize go on the station's AP_VLAN
        // (each gets its own group key); otherwise everything is on the main AP
        // and the BSS-wide GTK is installed once.
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
                    nl_new_key(&mut cmd, family_id, key_if, None, 1, &ap.station_gtk(sta), false);
                } else if !gtk_installed {
                    nl_new_key(&mut cmd, family_id, ifindex, None, 1, &ap.gtk(), false);
                    gtk_installed = true;
                }
                nl_authorize(&mut cmd, family_id, key_if, sta);
                keyed.insert(*sta);
                eprintln!("netlink AP: station {} keyed + authorized", crate::util::bytes_to_mac(sta));
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
fn route_outputs(sock: &mut NetlinkSocket, cmd: &mut NetlinkSocket, family: u16, ifindex: u32, freq: u32, out: &crate::ap::Outgoing, stations: &mut Vec<[u8; 6]>, keyed: &mut std::collections::HashSet<[u8; 6]>, vlan: &mut VlanState) {
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
                nl_new_station(cmd, family, ifindex, &d.addr1);
                nl_set_station_assoc(cmd, family, ifindex, &d.addr1, aid, cap);
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
