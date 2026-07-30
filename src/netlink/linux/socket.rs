use super::*;

/// A generic-netlink socket bound to a unique port id.
pub(super) struct NetlinkSocket {
    pub(super) fd: RawFd,
    pub(super) pid: u32,
    pub(super) seq: u32,
}

impl Drop for NetlinkSocket {
    fn drop(&mut self) {
        // Close the fd so kernel objects owned via NL80211_ATTR_SOCKET_OWNER
        // (interfaces, started APs) are torn down promptly, not only at exit.
        unsafe { libc::close(self.fd) };
    }
}

impl NetlinkSocket {
    pub(super) fn open() -> io::Result<NetlinkSocket> {
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

    pub(super) fn next_seq(&mut self) -> u32 {
        let s = self.seq;
        self.seq += 1;
        s
    }

    pub(super) fn send(&self, bytes: &[u8]) -> io::Result<()> {
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

    /// Receive one datagram into reusable caller-owned storage.
    pub(super) fn recv_into(&self, timeout: Duration, buf: &mut [u8]) -> Option<usize> {
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
            let n = libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);
            if n <= 0 {
                return None;
            }
            Some(n as usize)
        }
    }

    /// Receive one datagram into owned storage for infrequent command paths.
    pub(super) fn recv(&self, timeout: Duration) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 65536];
        let len = self.recv_into(timeout, &mut buf)?;
        buf.truncate(len);
        Some(buf)
    }

    pub(super) fn join_multicast(&self, group: u32) -> io::Result<()> {
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
    pub(super) fn request_ack(&mut self, mut m: GenlMessage) -> io::Result<()> {
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
pub(super) fn resolve_family(
    sock: &mut NetlinkSocket,
    family: &str,
    mcast_group: &str,
) -> io::Result<(u16, Option<u32>)> {
    let seq = sock.next_seq();
    let req = GenlMessage::new(msg::GENL_ID_CTRL, msg::CTRL_CMD_GETFAMILY, 0, seq)
        .with_version(1)
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
