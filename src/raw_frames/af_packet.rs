//! Monitor-mode `AF_PACKET` raw-socket transport (Linux).
//!
//! Binds a raw packet socket to a monitor interface and reads/writes
//! radiotap-prefixed 802.11 frames directly — the lowest-level frame path,
//! suitable for real radios or `mac80211_hwsim`.

#![cfg(target_os = "linux")]

use std::io;
use std::os::unix::io::RawFd;
use std::time::Duration;

use super::Link;
use crate::dot11;

pub struct IfaceLink {
    fd: RawFd,
    /// Band-aware radiotap header prepended on every injected frame.
    tx_radiotap: Vec<u8>,
}

impl IfaceLink {
    /// Open and bind a raw socket to `iface` (which must be in monitor mode) and
    /// pin injected frames to `channel`'s band (frequency / CCK-vs-OFDM / rate).
    pub fn open(iface: &str, channel: u8) -> io::Result<IfaceLink> {
        Self::open_band(iface, channel, false)
    }

    /// Open with explicit band selection (`band6` = 6 GHz channel numbering).
    pub fn open_band(iface: &str, channel: u8, band6: bool) -> io::Result<IfaceLink> {
        let tx_radiotap = if band6 {
            dot11::build_radiotap_tx_6ghz(channel)
        } else {
            dot11::build_radiotap_tx(channel)
        };
        unsafe {
            let proto = (libc::ETH_P_ALL as u16).to_be() as i32;
            let fd = libc::socket(libc::AF_PACKET, libc::SOCK_RAW, proto);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            let ifindex = libc::if_nametoindex(format!("{iface}\0").as_ptr() as *const libc::c_char);
            if ifindex == 0 {
                libc::close(fd);
                return Err(io::Error::last_os_error());
            }

            let mut sll: libc::sockaddr_ll = std::mem::zeroed();
            sll.sll_family = libc::AF_PACKET as u16;
            sll.sll_protocol = proto as u16;
            sll.sll_ifindex = ifindex as i32;
            let ret = libc::bind(
                fd,
                &sll as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            );
            if ret < 0 {
                libc::close(fd);
                return Err(io::Error::last_os_error());
            }
            Ok(IfaceLink { fd, tx_radiotap })
        }
    }
}

impl Link for IfaceLink {
    fn try_recv(&mut self, timeout: Duration) -> Option<Vec<u8>> {
        unsafe {
            let mut pfd = libc::pollfd {
                fd: self.fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
            let r = libc::poll(&mut pfd, 1, ms);
            if r <= 0 {
                return None;
            }
            let mut buf = vec![0u8; 4096];
            let n = libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);
            if n <= 0 {
                return None;
            }
            buf.truncate(n as usize);
            Some(buf)
        }
    }

    fn send(&mut self, frame: &[u8]) {
        // Replace the placeholder radiotap with the band-aware TX header so the
        // driver injects on the correct frequency/encoding.
        let dot11_frame = dot11::strip_radiotap(frame).unwrap_or(frame);
        let mut buf = Vec::with_capacity(self.tx_radiotap.len() + dot11_frame.len());
        buf.extend_from_slice(&self.tx_radiotap);
        buf.extend_from_slice(dot11_frame);
        unsafe {
            libc::send(self.fd, buf.as_ptr() as *const libc::c_void, buf.len(), 0);
        }
    }
}

impl Drop for IfaceLink {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}
