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
                    return if code == 0 {
                        Ok(())
                    } else {
                        Err(io::Error::from_raw_os_error(-code))
                    };
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
