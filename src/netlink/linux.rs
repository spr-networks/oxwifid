//! Linux nl80211 socket and [`Link`] implementation.

#![cfg(target_os = "linux")]

use std::io;
use std::os::unix::io::RawFd;
use std::time::{Duration, Instant};

use super::msg::{self, Attr, GenlMessage};
use super::*;
use crate::frames as dot11;
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

/// One BSS returned by a kernel nl80211 scan.
#[derive(Clone, Debug, PartialEq)]
pub struct ScanResult {
    pub ssid: Vec<u8>,
    pub bssid: [u8; 6],
    pub frequency: u32,
    pub channel: u8,
    /// `"2.4"`, `"5"`, or `"6"`.
    pub band: &'static str,
    pub signal_dbm: Option<f32>,
    pub psk: bool,
    pub psk_sha256: bool,
    pub sae: bool,
    pub sae_h2e: bool,
    pub owe: bool,
    pub mld_addr: Option<[u8; 6]>,
    pub mlo_link_id: Option<u8>,
}

fn scan_frequency(freq: u32) -> Option<(u8, &'static str)> {
    match freq {
        2484 => Some((14, "2.4")),
        2412..=2472 if (freq - 2407).is_multiple_of(5) => Some((((freq - 2407) / 5) as u8, "2.4")),
        5005..=5895 if (freq - 5000).is_multiple_of(5) => Some((((freq - 5000) / 5) as u8, "5")),
        5955..=7115 if (freq - 5950).is_multiple_of(5) => Some((((freq - 5950) / 5) as u8, "6")),
        _ => None,
    }
}

fn read_u32(data: &[u8]) -> Option<u32> {
    Some(u32::from_ne_bytes(data.get(..4)?.try_into().ok()?))
}

fn parse_scan_bss(data: &[u8]) -> Option<ScanResult> {
    let attrs = msg::parse_attrs(data);
    let mut bssid = [0u8; 6];
    bssid.copy_from_slice(msg::find_attr(&attrs, NL80211_BSS_BSSID)?.get(..6)?);
    let frequency = read_u32(msg::find_attr(&attrs, NL80211_BSS_FREQUENCY)?)?;
    let (channel, band) = scan_frequency(frequency)?;
    let information = msg::find_attr(&attrs, NL80211_BSS_INFORMATION_ELEMENTS).unwrap_or(&[]);
    let beacon = msg::find_attr(&attrs, NL80211_BSS_BEACON_IES).unwrap_or(&[]);
    let ie = |id| {
        dot11::find_ie_strict(information, id)
            .ok()
            .flatten()
            .or_else(|| dot11::find_ie_strict(beacon, id).ok().flatten())
    };
    let ssid = ie(0).unwrap_or(&[]).to_vec();
    let rsn = ie(48);
    let rsnxe = ie(244);
    let signal_dbm = msg::find_attr(&attrs, NL80211_BSS_SIGNAL_MBM)
        .and_then(read_u32)
        .map(|raw| (raw as i32) as f32 / 100.0);
    let mld_addr = msg::find_attr(&attrs, NL80211_BSS_MLD_ADDR).and_then(|raw| {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(raw.get(..6)?);
        Some(mac)
    });
    Some(ScanResult {
        ssid,
        bssid,
        frequency,
        channel,
        band,
        signal_dbm,
        psk: rsn.is_some_and(|body| dot11::rsn_has_akm(body, 2)),
        psk_sha256: rsn.is_some_and(|body| dot11::rsn_has_akm(body, 6)),
        sae: rsn.is_some_and(|body| dot11::rsn_has_akm(body, 8)),
        sae_h2e: rsnxe.is_some_and(dot11::rsnxe_has_sae_h2e),
        owe: rsn.is_some_and(|body| dot11::rsn_has_akm(body, 18)),
        mld_addr,
        mlo_link_id: msg::find_attr(&attrs, NL80211_BSS_MLO_LINK_ID)
            .and_then(|raw| raw.first().copied()),
    })
}

fn dump_scan(
    sock: &mut NetlinkSocket,
    family_id: u16,
    ifindex: u32,
) -> io::Result<Vec<ScanResult>> {
    let seq = sock.next_seq();
    let request = GenlMessage::new(family_id, NL80211_CMD_GET_SCAN, msg::NLM_F_DUMP, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex));
    sock.send(&request.to_bytes(sock.pid))?;
    let mut results = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let Some(buf) = sock.recv(Duration::from_millis(500)) else {
            continue;
        };
        for parsed in msg::parse_messages(&buf) {
            if parsed.seq != seq {
                continue;
            }
            if parsed.typ == msg::NLMSG_DONE {
                return Ok(results);
            }
            if let Some(code) = parsed.error_code() {
                if code == 0 {
                    continue;
                }
                return Err(io::Error::from_raw_os_error(-code));
            }
            if parsed.typ != family_id || parsed.genl_cmd() != Some(NL80211_CMD_NEW_SCAN_RESULTS) {
                continue;
            }
            let attrs = msg::parse_attrs(parsed.genl_attrs());
            if let Some(bss) = msg::find_attr(&attrs, NL80211_ATTR_BSS).and_then(parse_scan_bss) {
                results.push(bss);
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "nl80211 scan dump timed out",
    ))
}

fn trigger_scan(
    sock: &mut NetlinkSocket,
    family_id: u16,
    ifindex: u32,
    ssids: &[Vec<u8>],
) -> io::Result<()> {
    let nested = if ssids.is_empty() {
        vec![Attr::bytes(1, &[])]
    } else {
        ssids
            .iter()
            .enumerate()
            .map(|(index, ssid)| Attr::bytes((index + 1) as u16, ssid))
            .collect()
    };
    let seq = sock.next_seq();
    let request = GenlMessage::new(family_id, NL80211_CMD_TRIGGER_SCAN, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::nested(NL80211_ATTR_SCAN_SSIDS, &nested));
    match sock.request_ack(request) {
        Ok(()) => {}
        // Another local scan may already be running. Since this socket joined
        // the scan group first, wait for it and consume its fresh cache.
        Err(error)
            if error.raw_os_error() == Some(libc::EBUSY)
                || error
                    .to_string()
                    .contains(&format!("os error {}", libc::EBUSY)) => {}
        Err(error) => return Err(error),
    }

    let deadline = Instant::now() + Duration::from_secs(45);
    while Instant::now() < deadline {
        let Some(buf) = sock.recv(Duration::from_millis(500)) else {
            continue;
        };
        for parsed in msg::parse_messages(&buf) {
            if parsed.typ != family_id {
                continue;
            }
            let attrs = msg::parse_attrs(parsed.genl_attrs());
            if msg::find_attr(&attrs, NL80211_ATTR_IFINDEX).and_then(read_u32) != Some(ifindex) {
                continue;
            }
            match parsed.genl_cmd() {
                Some(NL80211_CMD_NEW_SCAN_RESULTS) => return Ok(()),
                Some(NL80211_CMD_SCAN_ABORTED) => {
                    return Err(io::Error::other("nl80211 scan aborted"))
                }
                _ => {}
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "nl80211 scan did not complete",
    ))
}

/// Perform an active scan on a managed interface. Supplying SSIDs generates
/// directed probes, which is required for a manually entered hidden network.
/// The kernel/driver performs channel iteration; this function never invokes
/// `iw` and never modifies addresses or routes.
pub fn scan_interface(iface: &str, directed_ssids: &[Vec<u8>]) -> io::Result<Vec<ScanResult>> {
    // A down managed interface cannot trigger a scan. This changes link state
    // only; addresses, DHCP, policy routing, and default routes remain SPR's.
    iface_set_up(iface)?;
    let ifindex =
        unsafe { libc::if_nametoindex(format!("{iface}\0").as_ptr() as *const libc::c_char) };
    if ifindex == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut sock = NetlinkSocket::open()?;
    let (family_id, scan_group) = resolve_family(&mut sock, "nl80211", "scan")?;
    let group = scan_group
        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "nl80211 scan group missing"))?;
    sock.join_multicast(group)?;

    // Conservative batching works on radios that expose only four probe SSID
    // slots. Visible BSSes are still collected from every directed scan.
    let batches: Vec<&[Vec<u8>]> = if directed_ssids.is_empty() {
        vec![&[]]
    } else {
        directed_ssids.chunks(4).collect()
    };
    let mut all = Vec::new();
    for batch in batches {
        trigger_scan(&mut sock, family_id, ifindex, batch)?;
        for result in dump_scan(&mut sock, family_id, ifindex)? {
            if let Some(existing) = all.iter_mut().find(|old: &&mut ScanResult| {
                old.bssid == result.bssid && old.frequency == result.frequency
            }) {
                if result.signal_dbm > existing.signal_dbm {
                    *existing = result;
                }
            } else {
                all.push(result);
            }
        }
    }
    all.sort_by(|a, b| {
        b.signal_dbm
            .partial_cmp(&a.signal_dbm)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.ssid.cmp(&b.ssid))
            .then_with(|| a.bssid.cmp(&b.bssid))
    });
    Ok(all)
}

/// Tune an interface to a scan result's primary frequency. The normal client
/// arrangement calls this on the monitor VIF after scanning with its managed
/// sibling on the same wiphy.
pub fn set_interface_frequency(iface: &str, frequency: u32) -> io::Result<()> {
    let ifindex =
        unsafe { libc::if_nametoindex(format!("{iface}\0").as_ptr() as *const libc::c_char) };
    if ifindex == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut sock = NetlinkSocket::open()?;
    let (family_id, _) = resolve_family(&mut sock, "nl80211", "")?;
    let seq = sock.next_seq();
    let request = GenlMessage::new(family_id, NL80211_CMD_SET_CHANNEL, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::u32(NL80211_ATTR_WIPHY_FREQ, frequency));
    sock.request_ack(request)
}

#[cfg(test)]
mod scan_tests {
    use super::*;

    #[test]
    fn parses_sae_h2e_six_ghz_scan_result() {
        let mut ies = vec![0, 7];
        ies.extend_from_slice(b"testnet");
        ies.extend_from_slice(&dot11::RSN_WPA3);
        ies.extend_from_slice(&dot11::RSNXE_H2E);
        let signal = (-4325i32).to_ne_bytes();
        let nested = Attr::nested(
            1,
            &[
                Attr::bytes(NL80211_BSS_BSSID, &[2, 0, 0, 0, 0, 1]),
                Attr::u32(NL80211_BSS_FREQUENCY, 6135),
                Attr::bytes(NL80211_BSS_INFORMATION_ELEMENTS, &ies),
                Attr::bytes(NL80211_BSS_SIGNAL_MBM, &signal),
                Attr::u8(NL80211_BSS_MLO_LINK_ID, 1),
                Attr::bytes(NL80211_BSS_MLD_ADDR, &[2, 0, 0, 0, 0, 9]),
            ],
        );
        let result = parse_scan_bss(&nested.data).unwrap();
        assert_eq!(result.ssid, b"testnet");
        assert_eq!(result.channel, 37);
        assert_eq!(result.band, "6");
        assert_eq!(result.signal_dbm, Some(-43.25));
        assert!(result.sae);
        assert!(result.sae_h2e);
        assert!(!result.psk);
        assert_eq!(result.mlo_link_id, Some(1));
        assert_eq!(result.mld_addr, Some([2, 0, 0, 0, 0, 9]));
    }

    #[test]
    fn rejects_scan_frequencies_outside_supported_wifi_bands() {
        assert_eq!(scan_frequency(2412), Some((1, "2.4")));
        assert_eq!(scan_frequency(5180), Some((36, "5")));
        assert_eq!(scan_frequency(5955), Some((1, "6")));
        assert_eq!(scan_frequency(58320), None);
    }
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

/// Complete AP bring-up with the SET_BSS operation reference AP issues after every
/// successful START_AP/SET_BEACON. ath12k can acknowledge START_AP and expose
/// the MLD links through `iw` while transmitting no beacons until these
/// per-link BSS parameters have been installed.
fn nl_set_bss(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    link_id: Option<u8>,
    ht_enabled: bool,
    isolate: bool,
) -> io::Result<()> {
    // 6, 12 and 24 Mbps in nl80211's 500-kbps units, matching reference AP's
    // mandatory OFDM basic-rate set on 5/6 GHz.
    const AP_BASIC_RATES: [u8; 3] = [0x0c, 0x18, 0x30];
    let seq = sock.next_seq();
    let mut m = GenlMessage::new(family, NL80211_CMD_SET_BSS, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::u8(NL80211_ATTR_BSS_CTS_PROT, 0))
        .attr(Attr::u8(NL80211_ATTR_BSS_SHORT_PREAMBLE, 1))
        // Guest BSS: mac80211 stops intra-BSS station-to-station bridging
        // (reference AP `ap_isolate`).
        .attr(Attr::u8(NL80211_ATTR_AP_ISOLATE, isolate as u8))
        .attr(Attr::bytes(NL80211_ATTR_BSS_BASIC_RATES, &AP_BASIC_RATES));
    if ht_enabled {
        m = m.attr(Attr::u16v(NL80211_ATTR_BSS_HT_OPMODE, 0));
    }
    if let Some(link_id) = link_id {
        m = m.attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id));
    }
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
    // Synchronous send (NLM_F_ACK), like reference AP's send_and_recv: a fire-and-
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
/// `FULL_AP_CLIENT_STATE`, so — like reference AP's "UNASSOC_STA workaround" — the
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

fn station_ie<'a>(outer: &'a [u8], link: Option<&'a [u8]>, id: u8) -> Option<&'a [u8]> {
    link.and_then(|ies| dot11::find_ie(ies, id))
        .or_else(|| dot11::find_ie(outer, id))
}

fn station_ext_ie<'a>(outer: &'a [u8], link: Option<&'a [u8]>, ext_id: u8) -> Option<&'a [u8]> {
    link.and_then(|ies| find_ext_ie(ies, ext_id))
        .or_else(|| find_ext_ie(outer, ext_id))
}

/// Attach the same station PHY capability attributes reference AP sends. A partner
/// link's Per-STA Profile overrides the outer association IEs; anything it
/// omits is inherited from the outer request.
fn with_station_phy_capabilities(
    mut msg: GenlMessage,
    outer: &[u8],
    link: Option<&[u8]>,
) -> GenlMessage {
    if let Some(ht) = station_ie(outer, link, 45) {
        msg = msg.attr(Attr::bytes(NL80211_ATTR_HT_CAPABILITY, ht));
    }
    if let Some(vht) = station_ie(outer, link, 191) {
        msg = msg.attr(Attr::bytes(NL80211_ATTR_VHT_CAPABILITY, vht));
    }
    if std::env::var_os("RUSTAP_NO_HE_CAP").is_none() {
        if let Some(he) = station_ext_ie(outer, link, 35) {
            msg = msg.attr(Attr::bytes(NL80211_ATTR_HE_CAPABILITY, he));
        }
        if let Some(he6) = station_ext_ie(outer, link, 59) {
            msg = msg.attr(Attr::bytes(NL80211_ATTR_HE_6GHZ_CAPABILITY, he6));
        }
    }
    if let Some(eht) = station_ext_ie(outer, link, 108) {
        msg = msg.attr(Attr::bytes(NL80211_ATTR_EHT_CAPABILITY, eht));
    }
    msg
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

#[allow(clippy::too_many_arguments)]
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
    eml_capability: Option<u16>,
    force_wme: bool,
    mfp: bool,
) {
    let seq = sock.next_seq();
    // Real supported rates from the assoc request (Supported Rates id 1 + Extended
    // Rates id 50), basic-rate bits preserved, like reference AP; fall back to OFDM.
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
    if mld_mac.is_some() {
        if let Some(eml) = eml_capability.filter(|eml| *eml != 0) {
            m = m.attr(Attr::u16v(NL80211_ATTR_EML_CAPABILITY, eml));
        }
    }
    // Carry the station's HT/VHT/HE/EHT capabilities (from its Assoc Request) so the
    // driver's rate control can use MCS rates — without these it is treated as a
    // legacy station stuck on the 6 Mbps basic rate.
    if let Some(ies) = assoc_ies {
        m = with_station_phy_capabilities(m, ies, None);
        // Mark the station QoS/WMM-capable so the kernel enables A-MPDU
        // aggregation. The QoS Info byte comes from the station's WMM Information
        // element; without this nest a VHT/HE station negotiates a high MCS but
        // moves almost no data (every MPDU goes out unaggregated). reference AP sends
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
    link_ies: Option<&[u8]>,
    eml_capability: Option<u16>,
    mfp: bool,
) {
    let mut rates: Vec<u8> = Vec::new();
    if let Some(ies) = assoc_ies {
        if let Some(sr) = station_ie(ies, link_ies, 1) {
            rates.extend_from_slice(sr);
        }
        if let Some(er) = station_ie(ies, link_ies, 50) {
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
        m = with_station_phy_capabilities(m, ies, link_ies);
    }
    if let Some(eml) = eml_capability.filter(|eml| *eml != 0) {
        m = m.attr(Attr::u16v(NL80211_ATTR_EML_CAPABILITY, eml));
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

/// Install a pairwise CCMP/GCMP key or the BSS-wide CCMP-128 GTK.
#[allow(clippy::too_many_arguments)]
fn nl_new_key(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    sta: Option<&[u8; 6]>,
    idx: u8,
    key: &[u8],
    cipher: u32,
    pairwise: bool,
    link_id: Option<u8>,
) {
    let seq = sock.next_seq();
    let mut m = GenlMessage::new(family, NL80211_CMD_NEW_KEY, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_KEY_DATA, key))
        .attr(Attr::u32(NL80211_ATTR_KEY_CIPHER, cipher))
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
fn authorize_station_message(family: u16, ifindex: u32, sta: &[u8; 6], seq: u32) -> GenlMessage {
    let bit = 1u32 << NL80211_STA_FLAG_AUTHORIZED;
    let mut flags = bit.to_ne_bytes().to_vec(); // mask
    flags.extend_from_slice(&bit.to_ne_bytes()); // set
    GenlMessage::new(family, NL80211_CMD_SET_STATION, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_MAC, sta))
        .attr(Attr::bytes(NL80211_ATTR_STA_FLAGS2, &flags))
}

fn nl_authorize(sock: &mut NetlinkSocket, family: u16, ifindex: u32, sta: &[u8; 6]) {
    let seq = sock.next_seq();
    let m = authorize_station_message(family, ifindex, sta, seq);
    if let Err(e) = sock.request_ack(m) {
        eprintln!(
            "netlink AP: SET_STATION(authorize) {} failed: {e}",
            crate::util::bytes_to_mac(sta)
        );
    }
}

#[cfg(test)]
mod station_authorization_tests {
    use super::*;

    #[test]
    fn mld_authorization_uses_only_the_peer_mld_address() {
        let mld = [0x6e, 0x45, 0xbe, 0x78, 0x3b, 0xf2];
        let msg = authorize_station_message(42, 343, &mld, 7);

        assert_eq!(msg.cmd, NL80211_CMD_SET_STATION);
        assert_eq!(
            msg.attrs
                .iter()
                .find(|attr| attr.typ == NL80211_ATTR_MAC)
                .map(|attr| attr.data.as_slice()),
            Some(mld.as_slice())
        );
        assert!(
            msg.attrs
                .iter()
                .all(|attr| attr.typ != NL80211_ATTR_MLD_ADDR
                    && attr.typ != NL80211_ATTR_MLO_LINK_ID),
            "reference AP authorizes MLD state once; it does not address a link station"
        );
        let flags = msg
            .attrs
            .iter()
            .find(|attr| attr.typ == NL80211_ATTR_STA_FLAGS2)
            .expect("STA_FLAGS2");
        let bit = 1u32 << NL80211_STA_FLAG_AUTHORIZED;
        assert_eq!(&flags.data[..4], &bit.to_ne_bytes());
        assert_eq!(&flags.data[4..], &bit.to_ne_bytes());
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
/// unassoc → SET_STATION assoc, the reference AP "UNASSOC_STA workaround" for
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
/// response. reference AP builds its beacon/response capability IEs from the same
/// attributes. Keeping the driver's bytes is important: an internally
/// inconsistent synthetic HE/EHT advertisement is tolerated by some Linux
/// scanners but rejected by stricter clients (notably macOS).
#[derive(Default, Debug)]
struct WiphyCapabilities {
    ht: Option<Vec<u8>>,
    vht: Option<Vec<u8>>,
    he: Option<Vec<u8>>,
    eht: Option<Vec<u8>>,
    eml: Option<u16>,
    mld: Option<u16>,
}

impl WiphyCapabilities {
    fn phy_capabilities(&self) -> dot11::PhyCapabilities {
        dot11::PhyCapabilities {
            ht: self.ht.clone(),
            vht: self.vht.clone(),
            he: self.he.clone(),
            eht: self.eht.clone(),
        }
    }
}

// `enum nl80211_band` values from linux/nl80211.h. Keep these named: band 4
// is S1GHz, not 6 GHz, and querying it silently yields no HE/EHT capabilities.
const NL80211_BAND_2GHZ: u16 = 0;
const NL80211_BAND_5GHZ: u16 = 1;
const NL80211_BAND_6GHZ: u16 = 3;

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
    // RustAP does not currently configure SU/MU beamforming. Match reference AP's
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
        if band != NL80211_BAND_2GHZ && he_width & (0x08 | 0x10) != 0 {
            len += 3; // 160/80+80 MHz
        }
        if band == NL80211_BAND_6GHZ && phy[0] & 0x02 != 0 {
            len += 3; // 320 MHz in 6 GHz
        }
        len
    };
    if mcs.len() < mcs_len {
        return None;
    }
    // The 320 MHz bit is meaningful only in the 6 GHz band; reference AP clears it
    // in lower-band beacons even when the same radio supports 320 MHz elsewhere.
    if band != NL80211_BAND_6GHZ {
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
    fn trims_and_masks_driver_he_eht_arrays_like_reference_ap() {
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

        let eht6 =
            build_eht_capability(&attrs, &he, NL80211_BAND_6GHZ).expect("6 GHz EHT capability");
        assert_eq!(
            eht6.len(),
            20,
            "6 GHz carries <=80, 160, and 320 MHz MCS maps"
        );
        assert_ne!(eht6[2] & 0x02, 0, "6 GHz retains the 320 MHz capability");
    }

    #[test]
    fn parses_ap_mld_capabilities_from_per_iftype_wiphy_data() {
        let entry = Attr::nested(
            1,
            &[
                Attr::u32(NL80211_ATTR_IFTYPE, NL80211_IFTYPE_AP),
                Attr::bytes(169, &[0]),
                Attr::bytes(170, &[0]),
                Attr::u16v(NL80211_ATTR_EML_CAPABILITY, 0x406b),
                Attr::u16v(NL80211_ATTR_MLD_CAPA_AND_OPS, 0x0024),
            ],
        );
        let message = GenlMessage::new(30, NL80211_CMD_GET_WIPHY, 0, 1)
            .attr(Attr::nested(NL80211_ATTR_IFTYPE_EXT_CAPA, &[entry]))
            .to_bytes(1);
        let attrs = msg::parse_attrs(&message[20..]);
        assert_eq!(parse_wiphy_mld_capabilities(&attrs), Some((0x406b, 0x0024)));
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
    Some(WiphyCapabilities {
        ht,
        vht,
        he,
        eht,
        eml: None,
        mld: None,
    })
}

fn parse_wiphy_mld_capabilities(attrs: &[(u16, &[u8])]) -> Option<(u16, u16)> {
    let entries = msg::find_attr(attrs, NL80211_ATTR_IFTYPE_EXT_CAPA)?;
    for (_, entry) in msg::parse_attrs(entries) {
        let entry_attrs = msg::parse_attrs(entry);
        let iftype = msg::find_attr(&entry_attrs, NL80211_ATTR_IFTYPE)
            .and_then(|value| value.get(..4))
            .map(|value| u32::from_ne_bytes(value.try_into().unwrap()));
        if iftype != Some(NL80211_IFTYPE_AP) {
            continue;
        }
        let eml = msg::find_attr(&entry_attrs, NL80211_ATTR_EML_CAPABILITY)
            .and_then(|value| value.get(..2))
            .map(|value| u16::from_ne_bytes(value.try_into().unwrap()))?;
        let mld = msg::find_attr(&entry_attrs, NL80211_ATTR_MLD_CAPA_AND_OPS)
            .and_then(|value| value.get(..2))
            .map(|value| u16::from_ne_bytes(value.try_into().unwrap()))?;
        return Some((eml, mld));
    }
    None
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
        if src.eml.is_some() {
            dst.eml = src.eml.take();
        }
        if src.mld.is_some() {
            dst.mld = src.mld.take();
        }
    }

    fn merge_mld(dst: &mut WiphyCapabilities, attrs: &[(u16, &[u8])]) {
        if let Some((eml, mld)) = parse_wiphy_mld_capabilities(attrs) {
            dst.eml = Some(eml);
            dst.mld = Some(mld);
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
                merge_mld(&mut caps, &attrs);
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

    // Ask for the split dump reference AP/iw use and merge every response belonging
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
                merge_mld(&mut caps, &attrs);
                if let Some(found) = parse_wiphy_capabilities(&attrs, band) {
                    merge(&mut caps, found);
                }
            }
        }
    }
    Some(caps)
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
    dot11::apply_phy_capabilities(frame, ies, &caps.phy_capabilities());
}

/// reference AP's nl80211 flush operation: DEL_STATION without NL80211_ATTR_MAC
/// removes every station left by a previous AP instance. This must happen even
/// after SIGKILL/SIGTERM, where userspace destructors cannot be relied upon.
fn nl_flush_stations(sock: &mut NetlinkSocket, family: u16, ifindex: u32) -> io::Result<()> {
    let seq = sock.next_seq();
    sock.request_ack(
        GenlMessage::new(family, NL80211_CMD_DEL_STATION, 0, seq)
            .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex)),
    )
}

/// Read the same live station measurements reference AP exposes from `STA` and
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

/// The kernel's current global regulatory domain as an ISO alpha-2, via
/// `GET_REG`. `None` if it can't be read (treated as "unknown, set it anyway").
fn nl_current_reg_alpha2(sock: &mut NetlinkSocket, family: u16) -> Option<[u8; 2]> {
    let seq = sock.next_seq();
    let m = GenlMessage::new(family, NL80211_CMD_GET_REG, 0, seq);
    sock.send(&m.to_bytes(sock.pid)).ok()?;
    for _ in 0..10 {
        let buf = sock.recv(Duration::from_millis(300))?;
        for parsed in msg::parse_messages(&buf) {
            if parsed.seq != seq {
                continue;
            }
            let attrs = msg::parse_attrs(parsed.genl_attrs());
            if let Some(a) = msg::find_attr(&attrs, NL80211_ATTR_REG_ALPHA2) {
                if a.len() >= 2 {
                    return Some([a[0], a[1]]);
                }
            }
        }
    }
    None
}

/// Apply the configured regulatory domain (`iw reg set <CC>`) so the kernel
/// enables that country's channels. Without it the radio stays on the default
/// world regdomain, under which 5/6 GHz AP channels are flagged no-IR ("no
/// initiating radiation") — `START_AP` then fails with `EINVAL`, often
/// intermittently depending on whether a beacon hint has arrived. barely-ap
/// previously used `country` only for the beacon Country IE and never set the
/// kernel regdomain, so a real 5 GHz AP could not reliably start.
///
/// This subscribes to the `regulatory` multicast group and waits for the
/// `REG_CHANGE` event confirming the domain applied (like reference AP), rather
/// than sleeping a fixed interval — the no-IR flags clear only once the change
/// lands. Best-effort throughout: an unset/invalid code is skipped, a duplicate
/// request for the current domain is harmless, and a bounded timeout keeps a
/// self-managed-reg driver (which emits no global `REG_CHANGE`) from stalling
/// startup.
fn nl_set_regulatory(alpha2: &[u8; 2]) {
    if !alpha2.iter().all(u8::is_ascii_uppercase) {
        return;
    }
    let cc_str = format!("{}{}", alpha2[0] as char, alpha2[1] as char);
    let mut sock = match NetlinkSocket::open() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("netlink AP: reg socket open failed (continuing): {e}");
            return;
        }
    };
    let (family, reg_group) = match resolve_family(&mut sock, "nl80211", "regulatory") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("netlink AP: reg family resolve failed (continuing): {e}");
            return;
        }
    };
    // Already the requested domain? Then REQ_SET_REG would emit no REG_CHANGE and
    // we'd wait out the whole timeout for nothing (common: a box that boots into
    // the right country). Skip cleanly.
    if nl_current_reg_alpha2(&mut sock, family) == Some(*alpha2) {
        eprintln!("netlink AP: regulatory domain already {cc_str}");
        return;
    }
    let subscribed = reg_group.map(|g| sock.join_multicast(g).is_ok()).unwrap_or(false);

    // Send the hint. NUL-terminated alpha-2, matching iw's 3-byte attribute. We
    // don't use `request_ack` here: it would consume (and discard) the
    // REG_CHANGE broadcast while waiting for the ACK. Instead handle both the
    // ACK and the event in one recv loop below.
    let seq = sock.next_seq();
    let cc = [alpha2[0], alpha2[1], 0];
    let mut m = GenlMessage::new(family, NL80211_CMD_REQ_SET_REG, 0, seq)
        .attr(Attr::bytes(NL80211_ATTR_REG_ALPHA2, &cc));
    m.flags |= msg::NLM_F_ACK;
    if let Err(e) = sock.send(&m.to_bytes(sock.pid)) {
        eprintln!("netlink AP: REQ_SET_REG {cc_str} send failed (continuing): {e}");
        return;
    }

    // Without the multicast subscription there is no event to wait for; fall
    // back to a short settle so the async hint still lands before START_AP.
    if !subscribed {
        std::thread::sleep(Duration::from_millis(600));
        eprintln!("netlink AP: requested regulatory domain {cc_str} (no reg group; settled)");
        return;
    }

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut acked = false;
    while Instant::now() < deadline {
        let Some(buf) = sock.recv(Duration::from_millis(300)) else {
            continue;
        };
        for parsed in msg::parse_messages(&buf) {
            // ACK / error for our own request.
            if parsed.seq == seq {
                if let Some(code) = parsed.error_code() {
                    if code != 0 {
                        eprintln!(
                            "netlink AP: REQ_SET_REG {cc_str} rejected (continuing): {}",
                            io::Error::from_raw_os_error(-code)
                        );
                        return;
                    }
                    acked = true;
                }
                continue;
            }
            // REG_CHANGE broadcast — done once the domain matches the request.
            if parsed.typ == family && parsed.genl_cmd() == Some(NL80211_CMD_REG_CHANGE) {
                let attrs = msg::parse_attrs(parsed.genl_attrs());
                let matched = msg::find_attr(&attrs, NL80211_ATTR_REG_ALPHA2)
                    .map(|a| a.len() >= 2 && a[0] == alpha2[0] && a[1] == alpha2[1])
                    .unwrap_or(false);
                if matched {
                    eprintln!("netlink AP: regulatory domain {cc_str} applied");
                    return;
                }
            }
        }
    }
    if acked {
        eprintln!(
            "netlink AP: regulatory domain {cc_str} requested (no REG_CHANGE within 3s; continuing)"
        );
    } else {
        eprintln!("netlink AP: regulatory domain {cc_str} not acknowledged (continuing)");
    }
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
    use std::collections::{HashMap, HashSet};

    let mut sock = NetlinkSocket::open()?;
    let (family_id, mlme_group) = resolve_family(&mut sock, "nl80211", "mlme")?;
    let ifindex =
        unsafe { libc::if_nametoindex(format!("{iface}\0").as_ptr() as *const libc::c_char) };
    if ifindex == 0 {
        return Err(io::Error::last_os_error());
    }
    // Set the regulatory domain BEFORE touching channels/START_AP, and wait for
    // the change to land so the 5/6 GHz no-IR flags clear before beaconing.
    nl_set_regulatory(&ap.country);
    let mld_links = ap.active_mld_links();
    // Primary frequency: 6 GHz is 5950 + 5*chan, otherwise the 2.4/5 GHz table.
    let band6 = ap.band6();
    // nl80211 reports HE/EHT capability blobs per band. An MLD spanning 5 and
    // 6 GHz must not reuse the primary link's 5 GHz blob for its 6 GHz beacon
    // or Association Response: strict clients then classify that link as HE/AX.
    let mut wiphy_caps_by_link: HashMap<u8, WiphyCapabilities> = HashMap::new();
    for link in &mld_links {
        let nl_band = if link.band6 {
            NL80211_BAND_6GHZ
        } else if dot11::is_5ghz(link.channel) {
            NL80211_BAND_5GHZ
        } else {
            NL80211_BAND_2GHZ
        };
        let caps =
            nl_get_wiphy_capabilities(&mut sock, family_id, ifindex, nl_band).unwrap_or_default();
        eprintln!(
            "netlink AP: link_id={} {} GHz capabilities HT={} VHT={} HE={} EHT={} bytes",
            link.link_id,
            if link.band6 {
                "6"
            } else if dot11::is_5ghz(link.channel) {
                "5"
            } else {
                "2.4"
            },
            caps.ht.as_ref().map_or(0, Vec::len),
            caps.vht.as_ref().map_or(0, Vec::len),
            caps.he.as_ref().map_or(0, Vec::len),
            caps.eht.as_ref().map_or(0, Vec::len),
        );
        ap.set_mld_link_phy_capabilities(link.link_id, caps.phy_capabilities());
        wiphy_caps_by_link.insert(link.link_id, caps);
    }
    if ap.mld {
        if let Some((eml, mld)) = wiphy_caps_by_link
            .values()
            .find_map(|caps| caps.eml.zip(caps.mld))
        {
            ap.set_mld_driver_capabilities(eml, mld);
            eprintln!("netlink AP: AP MLD driver capabilities EML=0x{eml:04x} MLD=0x{mld:04x}");
        }
    }
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
    // Match reference AP's i802_flush(): remove every kernel station left by a
    // previous process before bringing up a new BSS. Without this, a client can
    // remain associated to the old SSID while this BSSID advertises a new one.
    match nl_flush_stations(&mut sock, family_id, ifindex) {
        Ok(()) => eprintln!("netlink AP: flushed stale kernel stations"),
        Err(e) => eprintln!("netlink AP: station flush failed (continuing): {e}"),
    }
    // Register for auth + (re)assoc BEFORE START_AP, the order reference AP uses. On
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
    // Create the complete MLD topology before installing any beacon template.
    // Every template contains the other affiliated link's profile, and ath12k
    // can accept START_AP while silently suppressing that beacon if its partner
    // link does not exist yet.
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
    for link in &mld_links {
        let link_band6 = link.band6;
        let link_freq: u32 = if link_band6 {
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
                dot11::center_channel(link.channel, link_width, link_band6),
                link_band6,
            )
        } else {
            link_freq
        };
        let link_center_chan = if link_width >= 40 {
            dot11::center_channel(link.channel, link_width, link_band6)
        } else {
            link.channel
        };
        if !link_band6 && chandef_is_dfs(link_center_chan, link_width) {
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
        let link_caps = wiphy_caps_by_link
            .get(&link.link_id)
            .expect("capabilities collected for every active link");
        apply_wiphy_capabilities(&mut beacon, link_caps);
        if ap.mld {
            eprintln!(
                "netlink AP: link_id={} beacon template MLE partner_info={} bytes",
                link.link_id,
                dot11::basic_mle_link_info_len(&beacon[36..]).unwrap_or(0)
            );
        }
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
                &ap.pairwise_cipher().suite_selector().to_ne_bytes(),
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
        nl_set_bss(
            &mut sock,
            family_id,
            ifindex,
            ap.mld.then_some(link.link_id),
            !link.band6,
            ap.guest(),
        )?;
        eprintln!(
            "netlink AP: START_AP + SET_BSS ok — kernel beaconing {:?} link_id={} on {} MHz (ifindex {ifindex})",
            String::from_utf8_lossy(&ap.ssid),
            link.link_id,
            link_freq
        );
        // reference AP follows its pre-start station flush with a broadcast Deauth
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
    // reference AP updates every affiliated link's beacon after all links have
    // reached START_AP. During the first START_AP the partner link is not yet
    // active, so mac80211/ath12k retains only the Basic MLE Common Info and
    // drops the Per-STA Profile that references that inactive link. Re-submit
    // the complete templates now that every affiliated link exists.
    if ap.mld && mld_links.len() > 1 {
        for link in &mld_links {
            let beacon_rt = ap.beacon_frame_unprotected_for_link(link);
            let mut beacon = dot11::strip_radiotap(&beacon_rt)
                .map(<[u8]>::to_vec)
                .unwrap_or(beacon_rt);
            let link_caps = wiphy_caps_by_link
                .get(&link.link_id)
                .expect("capabilities collected for every active link");
            apply_wiphy_capabilities(&mut beacon, link_caps);
            let partner_info = dot11::basic_mle_link_info_len(&beacon[36..]).unwrap_or(0);
            let (head, tail) = split_beacon_at_tim(&beacon);
            let seq = sock.next_seq();
            sock.request_ack(
                GenlMessage::new(family_id, NL80211_CMD_SET_BEACON, 0, seq)
                    .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
                    .attr(Attr::bytes(NL80211_ATTR_BEACON_HEAD, head))
                    .attr(Attr::bytes(NL80211_ATTR_BEACON_TAIL, tail))
                    .attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link.link_id)),
            )?;
            nl_set_bss(
                &mut sock,
                family_id,
                ifindex,
                Some(link.link_id),
                !link.band6,
                ap.guest(),
            )?;
            eprintln!(
                "netlink AP: SET_BEACON + SET_BSS link_id={} with MLE partner_info={} bytes",
                link.link_id, partner_info
            );
        }
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
    // reference AP does not start WPA until the successful Association Response is
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
                (
                    l.mac,
                    if l.band6 {
                        5950 + 5 * l.channel as u32
                    } else {
                        crate::netlink::msg::freq_for_channel(l.channel)
                    },
                ),
            )
        })
        .collect();
    let mut link_route: std::collections::HashMap<[u8; 6], u8> = std::collections::HashMap::new();
    // The BSS-wide GTK/IGTK installed in the kernel, tracked as (key index,
    // bytes). We install once a station is keyed, then re-install whenever the
    // AP rotates the key (group rekey toggles the GTK index 1<->2 and the IGTK
    // index 4<->5), removing the stale index — a reference AP-style two-phase rekey.
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
    // Per-STA-VIF: the GTK (key index, bytes) currently installed on every
    // negotiated link of each station's AP_VLAN. An MLD Group Key message
    // carries one KDE per link, so the kernel must have the matching key on
    // every link too; installing it only on the association link pins traffic
    // there and leaves a partner link without a usable group-key context.
    type VlanGtkMap = std::collections::HashMap<([u8; 6], Option<u8>), (u8, [u8; 16])>;
    let mut vlan_gtk: VlanGtkMap = std::collections::HashMap::new();
    let mut vlan = VlanState {
        enabled: ap.per_sta_vif(),
        base_iface: iface.to_string(),
        map: std::collections::HashMap::new(),
    };

    // reference AP uses separate netlink sockets for synchronous commands vs async
    // events. We do the same: `cmd` issues request/ACK commands (NEW_STATION,
    // NEW_KEY, AP_VLAN, …) so their ACK read-loop never swallows a frame event
    // (auth/assoc/EAPOL) that belongs to the event socket `sock`. Sharing one
    // socket dropped EAPOL frames mid-handshake and made rejoins fail.
    let mut cmd = NetlinkSocket::open()?;

    // Optional reference AP-style runtime control socket (STATUS / STA-DUMP / DEAUTH /
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
                // Multiple independently-running radios subscribe to the same
                // nl80211 multicast groups. Never let a management, TX-status,
                // control-port, or radar event for another netdev reach this
                // radio's AP state machine. Events from this radio's own
                // AP_VLAN children still belong to it: mac80211 delivers a
                // control-port EAPOL from a per-STA-VIF station (group-rekey
                // m2, rejoin) with the AP_VLAN's ifindex, not the AP's.
                if msg::find_attr(&attrs, NL80211_ATTR_IFINDEX)
                    .and_then(read_u32)
                    .is_some_and(|event_ifindex| {
                        event_ifindex != ifindex
                            && !vlan.map.values().any(|v| v.ifindex == event_ifindex)
                    })
                {
                    continue;
                }
                if std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
                    if let Some(c) = parsed.genl_cmd() {
                        if c == NL80211_CMD_FRAME || c == NL80211_CMD_CONTROL_PORT_FRAME {
                            let sub = msg::find_attr(&attrs, NL80211_ATTR_FRAME)
                                .and_then(|f| f.first().copied())
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
                            // Map an MLD or affiliated-link destination to the
                            // association-link station the core tracks.
                            let sta = ap.station_link_for_peer(&dst).unwrap_or(dst);
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
                // reference AP pre-adds the kernel station, sends the successful
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
                    if tx.subtype() == dot11::SUBTYPE_AUTH {
                        let (seq, status) = if tx.body.len() >= 6 {
                            (
                                u16::from_le_bytes([tx.body[2], tx.body[3]]),
                                u16::from_le_bytes([tx.body[4], tx.body[5]]),
                            )
                        } else {
                            (0, 0)
                        };
                        eprintln!(
                            "netlink AP: AUTH TX-STATUS dst={} seq={seq} status={status} acked={acked} link={:?}",
                            crate::util::bytes_to_mac(&tx.addr1),
                            msg::find_attr(&attrs, NL80211_ATTR_MLO_LINK_ID)
                                .and_then(|v| v.first()),
                        );
                    }
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
                    let core_sta = ap.station_link_for_peer(&sta).unwrap_or(sta);
                    if std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
                        eprintln!(
                            "netlink AP: ASSOC-RESP TX-STATUS sta={} acked={acked} sc={sc}",
                            crate::util::bytes_to_mac(&sta)
                        );
                    }
                    if acked {
                        if let Some(frame) = held_assoc_eapol.remove(&sta) {
                            ap.note_eapol_transmitted(&core_sta);
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
                                &wiphy_caps_by_link,
                                &mut assoc_tx,
                                &mut held_assoc_eapol,
                            );
                        }
                    } else if ap.is_associated(&core_sta) {
                        // A delayed negative status for a duplicate/stale
                        // Association Response must not tear down a station that
                        // has since proved connectivity by completing m4.
                        held_assoc_eapol.remove(&sta);
                    } else {
                        held_assoc_eapol.remove(&sta);
                        ap.note_assoc_response_not_acked(&core_sta);
                        let old_vlan = if vlan.enabled {
                            vlan.map.remove(&core_sta)
                        } else {
                            None
                        };
                        match old_vlan {
                            Some(assignment) => {
                                nl_del_station(
                                    &mut cmd,
                                    family_id,
                                    assignment.ifindex,
                                    &assignment.sta_addr,
                                );
                                nl_del_iface(&mut cmd, family_id, assignment.ifindex);
                            }
                            None => {
                                let kernel_addr = ap.station_mld_mac(&core_sta).unwrap_or(core_sta);
                                nl_del_station(&mut cmd, family_id, ifindex, &kernel_addr);
                            }
                        }
                        stations.retain(|s| s != &core_sta);
                        keyed.remove(&core_sta);
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
                        // and rewrite the target link-BSSID (addr1 RA + addr3
                        // BSSID) to the canonical `bssid` so the single-address
                        // `Ap` matches it. ath12k does not consistently attach
                        // MLO_LINK_ID to pre-association management frames, so
                        // fall back to the link BSSID and event frequency instead
                        // of silently dropping a valid Authentication request.
                        let mut fbytes = f.to_vec();
                        ap.set_mgmt_rx_link(None);
                        if ap.mld {
                            if fbytes.len() < 22 {
                                continue;
                            }
                            let reported_lid = msg::find_attr(&attrs, NL80211_ATTR_MLO_LINK_ID)
                                .and_then(|v| v.first())
                                .copied();
                            let event_freq = msg::find_attr(&attrs, NL80211_ATTR_WIPHY_FREQ)
                                .and_then(|v| v.get(..4))
                                .map(|v| u32::from_ne_bytes(v.try_into().unwrap()));
                            let mut ra = [0u8; 6];
                            ra.copy_from_slice(&fbytes[4..10]);
                            let mut frame_bssid = [0u8; 6];
                            frame_bssid.copy_from_slice(&fbytes[16..22]);
                            let Some(lid) = resolve_mld_rx_link(
                                &link_params,
                                reported_lid,
                                event_freq,
                                &ra,
                                &frame_bssid,
                                &ap.mld_mac,
                                fbytes[0] >> 4 == dot11::SUBTYPE_PROBE_REQ,
                            ) else {
                                eprintln!(
                                    "netlink AP: dropped MLD mgmt subtype={} reported_link={reported_lid:?} freq={event_freq:?} ra={} bssid={} (no matching configured link)",
                                    fbytes[0] >> 4,
                                    crate::util::bytes_to_mac(&ra),
                                    crate::util::bytes_to_mac(&frame_bssid),
                                );
                                continue;
                            };
                            if reported_lid.is_none() {
                                eprintln!(
                                    "netlink AP: inferred missing MLO_LINK_ID={} for mgmt subtype={} freq={event_freq:?} ra={}",
                                    lid,
                                    fbytes[0] >> 4,
                                    crate::util::bytes_to_mac(&ra),
                                );
                            }
                            // The state machine builds link-addressed responses
                            // (probe responses in particular) for the link the
                            // frame arrived on.
                            ap.set_mgmt_rx_link(Some(lid));
                            let mut client = [0u8; 6];
                            client.copy_from_slice(&fbytes[10..16]);
                            // reference AP translates every address belonging to the
                            // peer MLD back to the association station before
                            // running its MLME. Without this, an iPhone that
                            // later uses its MLD MAC (or partner-link MAC) is
                            // mistaken for a new station and the live AP_VLAN is
                            // repeatedly destroyed and recreated.
                            let core_client = ap.station_link_for_peer(&client).unwrap_or(client);
                            link_route.insert(core_client, lid);
                            fbytes[10..16].copy_from_slice(&core_client);
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
                            if let Some(link_sta) = ap.station_link_for_peer(&sta) {
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
                    &wiphy_caps_by_link,
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
                &wiphy_caps_by_link,
                &mut assoc_tx,
                &mut held_assoc_eapol,
            );
        }

        // Prune bookkeeping for stations the AP has dropped (deauth / 4-way
        // timeout), so `stations`/`keyed` don't grow unbounded over connect/
        // disconnect cycles (and the key-install loop below doesn't iterate dead
        // entries). Keep a disconnected station's AP_VLAN briefly: SPR's
        // reference AP action calls `STA <mac>` after receiving AP-STA-DISCONNECTED,
        // then uses the returned vlan_id to remove DHCP/firewall state.
        let live: HashSet<[u8; 6]> = ap.station_macs().into_iter().collect();
        stations.retain(|s| live.contains(s));
        keyed.retain(|s| live.contains(s));
        // MLO Association Responses and their first EAPOL frame are addressed
        // to the peer MLD while the core station table is keyed by the
        // association-link MAC. Preserve either representation.
        assoc_tx.retain(|s, _| live.contains(s) || ap.station_link_for_peer(s).is_some());
        held_assoc_eapol.retain(|s, _| live.contains(s) || ap.station_link_for_peer(s).is_some());
        if vlan.enabled {
            vlan_gtk.retain(|(s, _), _| live.contains(s));
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
                            nl_del_station(
                                &mut cmd,
                                family_id,
                                assignment.ifindex,
                                &assignment.sta_addr,
                            );
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
            if let Some(tk) = ap.station_pairwise_key(sta) {
                let mld_mac = ap.mld.then(|| ap.station_mld_mac(sta)).flatten();
                let key_sta = mld_mac.as_ref().unwrap_or(sta);
                // MLO pairwise keys are addressed to the peer MLD. The kernel
                // rejects MLO_LINK_ID on pairwise NEW_KEY; per-link scoping only
                // applies to group/management keys.
                nl_new_key(
                    &mut cmd,
                    family_id,
                    key_if,
                    Some(key_sta),
                    0,
                    tk,
                    ap.pairwise_cipher().suite_selector(),
                    true,
                    None,
                );
                if vlan.enabled {
                    // The GTK index is BSS-wide (the advertised key id, shared by
                    // every station); only the per-station GTK *value* differs.
                    let gidx = ap.gtk_key_id();
                    let gkey = ap.station_gtk(sta);
                    let group_links: Vec<Option<u8>> = if mld_mac.is_some() {
                        ap.station_mld_link_ids(sta).into_iter().map(Some).collect()
                    } else if ap.mld {
                        vec![Some(ap.link_id)]
                    } else {
                        vec![None]
                    };
                    for link_id in group_links {
                        nl_new_key(
                            &mut cmd,
                            family_id,
                            key_if,
                            None,
                            gidx,
                            &gkey,
                            WLAN_CIPHER_SUITE_CCMP,
                            false,
                            link_id,
                        );
                        vlan_gtk.insert((*sta, link_id), (gidx, gkey));
                    }
                }
                // Authorization is MLD-level state. Match reference AP: select an
                // MLO peer by its MLD MAC and issue one plain SET_STATION,
                // without MLO_LINK_ID/MLD_ADDR and without MODIFY_LINK_STA on
                // partner links. Applying AUTHORIZED/WME/MFP to link stations
                // can leave ath12k's data scheduler anchored to the association
                // link even though the partner station was added successfully.
                nl_authorize(&mut cmd, family_id, key_if, key_sta);
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
                        &mut cmd,
                        family_id,
                        ifindex,
                        None,
                        gtk_idx,
                        &gtk,
                        WLAN_CIPHER_SUITE_CCMP,
                        false,
                        link_id,
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
                let mld_station = ap.mld && ap.station_mld_mac(sta).is_some();
                let group_links: Vec<Option<u8>> = if mld_station {
                    ap.station_mld_link_ids(sta).into_iter().map(Some).collect()
                } else if ap.mld {
                    vec![Some(ap.link_id)]
                } else {
                    vec![None]
                };
                for link_id in group_links {
                    let state_key = (*sta, link_id);
                    if vlan_gtk.get(&state_key) != Some(&(gidx, gkey)) {
                        nl_new_key(
                            &mut cmd,
                            family_id,
                            vidx,
                            None,
                            gidx,
                            &gkey,
                            WLAN_CIPHER_SUITE_CCMP,
                            false,
                            link_id,
                        );
                        if let Some(&(old_idx, _)) = vlan_gtk.get(&state_key) {
                            if old_idx != gidx {
                                nl_del_key(&mut cmd, family_id, vidx, old_idx, link_id);
                            }
                        }
                        vlan_gtk.insert(state_key, (gidx, gkey));
                    }
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
                    vlan.assignment_for(mac).map(|assignment| {
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
                    &wiphy_caps_by_link,
                    &mut assoc_tx,
                    &mut held_assoc_eapol,
                );
            }
        }
        for ev in ap.drain_events() {
            // reference AP adds `vlanid` (no underscore) to the connect event. SPR's
            // action script ignores that extra argv today and synchronously asks
            // `STA <mac>` for `vlan_id`, which the control responder above serves.
            let line = match &ev {
                crate::ap::ApEvent::Connected { mac } => match vlan.assignment_for(mac) {
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
                    .assignment_for(mac)
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

/// Bring a network interface up (set IFF_UP) via an ioctl, like reference AP's
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
#[allow(clippy::too_many_arguments)]
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
    link_id: Option<u8>,
) -> io::Result<()> {
    let seq = sock.next_seq();
    let mut m = GenlMessage::new(family, NL80211_CMD_SET_STATION, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ap_ifindex))
        .attr(Attr::bytes(NL80211_ATTR_MAC, sta))
        .attr(Attr::u32(NL80211_ATTR_STA_VLAN, vlan_ifindex));
    if let Some(link_id) = link_id {
        m = m.attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id));
    }
    sock.request_ack(m)
}

/// Delete a dynamically-created interface (an AP_VLAN) by ifindex.
fn nl_del_iface(sock: &mut NetlinkSocket, family: u16, ifindex: u32) {
    let seq = sock.next_seq();
    let m = GenlMessage::new(family, NL80211_CMD_DEL_INTERFACE, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex));
    let _ = sock.request_ack(m);
}

/// Allow an attached reference AP control client action enough time to query `STA <mac>` and
/// remove SPR DHCP/firewall state after a disconnect event.
const VLAN_EVENT_GRACE: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
struct VlanAssignment {
    ifindex: u32,
    vlan_id: u32,
    ifname: String,
    /// nl80211 indexes an MLO peer by its MLD MAC even though RustAP's frame
    /// state remains keyed by the association-link MAC.
    sta_addr: [u8; 6],
    retire_at: Option<Instant>,
}

/// Per-station-VIF bookkeeping. IDs and names follow reference AP's wildcard VLAN
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

    fn assignment_for(&self, mac: &[u8; 6]) -> Option<&VlanAssignment> {
        self.map.get(mac).or_else(|| {
            self.map
                .values()
                .find(|assignment| &assignment.sta_addr == mac)
        })
    }
}

/// Resolve the affiliated link carrying a received MLD management frame.
///
/// nl80211 normally supplies `MLO_LINK_ID`, but ath12k can omit it for
/// pre-association Authentication frames. In that case the on-air RA/BSSID
/// identifies a unique link; an MLD-addressed frame can additionally be
/// disambiguated by the event frequency. A present-but-inconsistent link ID is
/// never overridden.
fn resolve_mld_rx_link(
    link_params: &std::collections::HashMap<u8, ([u8; 6], u32)>,
    reported_link_id: Option<u8>,
    event_freq: Option<u32>,
    ra: &[u8; 6],
    frame_bssid: &[u8; 6],
    ap_mld_mac: &[u8; 6],
    allow_broadcast: bool,
) -> Option<u8> {
    let broadcast = [0xff; 6];
    let address_matches = |link_bssid: &[u8; 6]| {
        (ra == link_bssid || ra == ap_mld_mac || (allow_broadcast && ra == &broadcast))
            && (frame_bssid == link_bssid
                || frame_bssid == ap_mld_mac
                || (allow_broadcast && frame_bssid == &broadcast))
    };

    if let Some(link_id) = reported_link_id {
        return link_params
            .get(&link_id)
            .filter(|(link_bssid, _)| address_matches(link_bssid))
            .map(|_| link_id);
    }

    let candidates: Vec<(u8, u32)> = link_params
        .iter()
        .filter(|(_, (link_bssid, _))| address_matches(link_bssid))
        .map(|(link_id, (_, freq))| (*link_id, *freq))
        .collect();
    if candidates.len() == 1 {
        return Some(candidates[0].0);
    }
    event_freq.and_then(|freq| {
        let matching: Vec<u8> = candidates
            .iter()
            .filter(|(_, link_freq)| *link_freq == freq)
            .map(|(link_id, _)| *link_id)
            .collect();
        (matching.len() == 1).then_some(matching[0])
    })
}

#[cfg(test)]
mod mld_rx_link_tests {
    use super::resolve_mld_rx_link;
    use std::collections::HashMap;

    fn links() -> HashMap<u8, ([u8; 6], u32)> {
        HashMap::from([
            (0, ([0x06, 0xf0, 0x21, 0xc9, 0x1e, 0xef], 5180)),
            (1, ([0x06, 0xf0, 0x21, 0xc9, 0x1e, 0xee], 6135)),
        ])
    }

    #[test]
    fn missing_link_id_is_inferred_from_link_bssid() {
        let links = links();
        let mld = [0x04, 0xf0, 0x21, 0xc9, 0x1e, 0xff];
        let link1 = links[&1].0;
        assert_eq!(
            resolve_mld_rx_link(&links, None, None, &link1, &link1, &mld, false),
            Some(1)
        );
    }

    #[test]
    fn mld_address_is_disambiguated_by_event_frequency() {
        let links = links();
        let mld = [0x04, 0xf0, 0x21, 0xc9, 0x1e, 0xff];
        assert_eq!(
            resolve_mld_rx_link(&links, None, Some(6135), &mld, &mld, &mld, false),
            Some(1)
        );
    }

    #[test]
    fn inconsistent_reported_link_is_rejected() {
        let links = links();
        let mld = [0x04, 0xf0, 0x21, 0xc9, 0x1e, 0xff];
        let link1 = links[&1].0;
        assert_eq!(
            resolve_mld_rx_link(&links, Some(0), Some(6135), &link1, &link1, &mld, false,),
            None
        );
    }

    #[test]
    fn broadcast_probe_uses_reported_link() {
        let links = links();
        let mld = [0x04, 0xf0, 0x21, 0xc9, 0x1e, 0xff];
        let broadcast = [0xff; 6];
        assert_eq!(
            resolve_mld_rx_link(
                &links,
                Some(0),
                Some(5180),
                &broadcast,
                &broadcast,
                &mld,
                true,
            ),
            Some(0)
        );
    }

    #[test]
    fn directed_probe_with_broadcast_ra_uses_reported_link() {
        let links = links();
        let mld = [0x04, 0xf0, 0x21, 0xc9, 0x1e, 0xff];
        let broadcast = [0xff; 6];
        let link1 = links[&1].0;
        assert_eq!(
            resolve_mld_rx_link(&links, Some(1), Some(6135), &broadcast, &link1, &mld, true,),
            Some(1)
        );
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
    wiphy_caps_by_link: &std::collections::HashMap<u8, WiphyCapabilities>,
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

            // reference AP's add_associated_sta() runs before send_assoc_resp(). It
            // deliberately puts the kernel station into associated state early:
            // otherwise cfg80211/the driver can drop EAPOL data before the
            // Association Response TX-status is processed. Our old order was the
            // reverse (send response, DEL/NEW/SET station, send m1), so ath12k
            // could apply the DEL_STATION after accepting the response for TX and
            // leave the ensuing 4-way frames queued against a torn-down peer.
            // Configure only successful responses; rejected associations must
            // never create a kernel station.
            let sta_addr = ap.station_link_for_peer(&d.addr1).unwrap_or(d.addr1);
            if assoc_succeeded && !(stations.contains(&sta_addr) && !keyed.contains(&sta_addr)) {
                let aid = u16::from_le_bytes([d.body[4], d.body[5]]) & 0x3fff;
                let mld_mac = ap.mld.then(|| ap.station_mld_mac(&sta_addr)).flatten();
                // (Re-)association: tear down any prior incarnation of this
                // station and rebuild it, and drop it from `keyed` so the fresh
                // 4-way re-installs keys (a rejoining client derives new keys).
                // A station that previously lived in an AP_VLAN must be removed
                // from *that* interface, then its VLAN torn down — deleting it on
                // the main AP leaves a stale station on the old VLAN.
                let old_vlan = if vlan.enabled {
                    vlan.map.remove(&sta_addr)
                } else {
                    None
                };
                match old_vlan {
                    Some(assignment) => {
                        nl_del_station(cmd, family, assignment.ifindex, &assignment.sta_addr);
                        nl_del_iface(cmd, family, assignment.ifindex);
                    }
                    None => {
                        let kernel_addr = mld_mac.unwrap_or(sta_addr);
                        nl_del_station(cmd, family, ifindex, &kernel_addr);
                    }
                }
                // HT/VHT caps go in SET_STATION (the only place rate control reads
                // them); NEW_STATION adds the station unassociated first so SET can
                // apply them without EINVAL. RUSTAP_NO_STA_CAPS=1 disables caps
                // entirely as a driver-compatibility escape hatch.
                let sta_caps = if std::env::var_os("RUSTAP_NO_STA_CAPS").is_some() {
                    None
                } else {
                    ap.station_assoc_ies(&sta_addr)
                };
                let listen_interval = ap.station_listen_interval(&sta_addr).unwrap_or(0);
                let capability = ap.station_capability(&sta_addr).unwrap_or(0);
                // An AP MLD must scope every station add/modify request to its
                // association link — the link the (re)assoc frame arrived on,
                // which a client may freely choose (wpa_supplicant routinely
                // picks the 5/6 GHz link, not link 0). `link_route` records that
                // per-station RX link and already drives the response/EAPOL TX,
                // so the kernel station's primary link must match it; otherwise
                // m1 is sent on the association link while the station only
                // exists on link 0, and the 4-way times out. A legacy station
                // has no MLD_ADDR, but still needs MLO_LINK_ID or cfg80211
                // rejects NEW_STATION.
                let assoc_link_id = link_route.get(&sta_addr).copied().unwrap_or(ap.link_id);
                let link_id = ap.mld.then_some(assoc_link_id);
                let eml_capability = sta_caps.and_then(dot11::parse_mld_eml_capability);
                let mld_capability = sta_caps.and_then(dot11::parse_mld_capability);
                if let Some(mld) = mld_mac {
                    eprintln!(
                        "netlink AP: MLD station link={} mld={} EML=0x{:04x} MLD=0x{:04x} max_simultaneous_links={} negotiated_links={:?}",
                        crate::util::bytes_to_mac(&sta_addr),
                        crate::util::bytes_to_mac(&mld),
                        eml_capability.unwrap_or(0),
                        mld_capability.unwrap_or(0),
                        mld_capability.map(|cap| (cap & 0x000f) + 1).unwrap_or(0),
                        ap.station_mld_link_ids(&sta_addr),
                    );
                }
                // Match reference AP's MLO state-transition order exactly:
                //
                //   1. NEW_STATION creates the association-link peer unassociated.
                //   2. ADD_LINK_STA creates every negotiated partner peer.
                //   3. SET_STATION advances the complete MLD to ASSOCIATED.
                //
                // ath12k prepares its firmware peer-association MLO partner list
                // only during step 3. Associating the primary before step 2 leaves
                // num_partner_links=0 in WMI; ADD_LINK_STA then succeeds in the
                // kernel but never enrolls that late peer in firmware scheduling.
                nl_new_station(cmd, family, ifindex, &sta_addr, mld_mac.as_ref(), link_id);
                if let Some(mld) = mld_mac {
                    let link_profiles = sta_caps
                        .map(dot11::parse_mld_link_profiles)
                        .unwrap_or_default();
                    for (peer_link_id, peer_link_mac) in ap.station_mld_link_macs(&sta_addr) {
                        // The association link is already created by NEW_STATION;
                        // only the *other* negotiated links get ADD_LINK_STA.
                        if peer_link_id == assoc_link_id {
                            continue;
                        }
                        let profile = link_profiles.iter().find(|profile| {
                            profile.link_id == peer_link_id && profile.mac == peer_link_mac
                        });
                        nl_add_link_station(
                            cmd,
                            family,
                            ifindex,
                            &mld,
                            peer_link_id,
                            &peer_link_mac,
                            aid,
                            listen_interval,
                            profile
                                .and_then(|profile| profile.capability)
                                .unwrap_or(capability),
                            sta_caps,
                            profile.map(|profile| profile.ies.as_slice()),
                            eml_capability,
                            ap.is_pmf(),
                        );
                    }
                }
                nl_set_station_assoc(
                    cmd,
                    family,
                    ifindex,
                    &sta_addr,
                    aid,
                    listen_interval,
                    capability,
                    sta_caps,
                    mld_mac.as_ref(),
                    link_id,
                    eml_capability,
                    mld_mac.is_some(),
                    ap.is_pmf(),
                );
                keyed.remove(&sta_addr);
                if !stations.contains(&sta_addr) {
                    stations.push(sta_addr);
                }
                if vlan.enabled {
                    // Per-station VIF: give this station its own AP_VLAN so its
                    // group key is isolated from other stations. Match reference AP's
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
                            // cfg80211 stores an MLO peer under its MLD MAC.
                            // reference AP translates the station identity before
                            // SET_STATION(STA_VLAN); using the link address here
                            // returns ENOENT on ath12k.
                            let kernel_addr = mld_mac.unwrap_or(sta_addr);
                            if let Err(e) =
                                nl_set_sta_vlan(cmd, family, ifindex, &kernel_addr, vidx, link_id)
                            {
                                eprintln!("netlink AP: set_sta_vlan failed: {e}");
                                nl_del_iface(cmd, family, vidx);
                            } else {
                                vlan.map.insert(
                                    sta_addr,
                                    VlanAssignment {
                                        ifindex: vidx,
                                        vlan_id,
                                        ifname: name.clone(),
                                        sta_addr: kernel_addr,
                                        retire_at: None,
                                    },
                                );
                                eprintln!(
                                    "netlink AP: station {} -> {name} (vlan_id {vlan_id}, ifindex {vidx})",
                                    crate::util::bytes_to_mac(&kernel_addr)
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
            if let Some(caps) = tlink
                .and_then(|link_id| wiphy_caps_by_link.get(&link_id))
                .or_else(|| wiphy_caps_by_link.get(&ap.link_id))
            {
                apply_wiphy_capabilities(&mut tx, caps);
            }
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
            let core_sta = ap.station_link_for_peer(&d.addr1).unwrap_or(d.addr1);
            let mld_mac = ap.mld.then(|| ap.station_mld_mac(&core_sta)).flatten();
            let dst = mld_mac.as_ref().unwrap_or(&d.addr1);
            // Send the EAPOL on the client's link (the kernel builds the MPDU
            // with that link's address from the link id). Uses the command socket:
            // the send is synchronous (NLM_F_ACK) so kernel rejections surface,
            // and waiting on the event socket would drop frame events.
            let (_f, link_id) = mld_route(ap, link_route, link_params, freq, &core_sta);
            let eapol = &d.body[8..];
            nl_send_eapol(cmd, family, ifindex, dst, eapol, link_id);
        }
    }
}
