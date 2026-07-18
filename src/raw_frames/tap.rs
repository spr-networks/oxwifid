//! Linux TAP transport for the station data plane.
//!
//! The wireless side remains the barely-ap userspace supplicant. Decrypted
//! Ethernet frames are injected into a TAP netdev and frames produced by the
//! kernel (including SPR's DHCP client) are encrypted onto the Wi-Fi link.

#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::io;
use std::os::fd::RawFd;

const IFREQ_PAD: usize = 22;

#[repr(C)]
struct IfReqFlags {
    name: [libc::c_char; libc::IFNAMSIZ],
    flags: libc::c_short,
    pad: [u8; IFREQ_PAD],
}

#[repr(C)]
struct IfReqHwAddr {
    name: [libc::c_char; libc::IFNAMSIZ],
    address: libc::sockaddr,
    pad: [u8; 8],
}

fn interface_name(name: &str) -> io::Result<[libc::c_char; libc::IFNAMSIZ]> {
    if name.is_empty() || name.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TAP interface name must be 1..15 bytes",
        ));
    }
    let c_name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name contains NUL"))?;
    let mut out = [0; libc::IFNAMSIZ];
    for (dst, src) in out.iter_mut().zip(c_name.as_bytes_with_nul()) {
        *dst = *src as libc::c_char;
    }
    Ok(out)
}

pub struct TapDevice {
    fd: RawFd,
    name: String,
}

impl TapDevice {
    /// Create or attach to a TAP interface, set its Ethernet MAC to the station
    /// identity, and bring it up. IP configuration is intentionally left to
    /// SPR's DHCP/static-uplink service.
    pub fn open(name: &str, mac: [u8; 6]) -> io::Result<TapDevice> {
        let if_name = interface_name(name)?;
        let path = CString::new("/dev/net/tun").expect("constant has no NUL");
        unsafe {
            let fd = libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut request = IfReqFlags {
                name: if_name,
                flags: (libc::IFF_TAP | libc::IFF_NO_PI) as libc::c_short,
                pad: [0; IFREQ_PAD],
            };
            if libc::ioctl(fd, libc::TUNSETIFF as _, &mut request) < 0 {
                let error = io::Error::last_os_error();
                libc::close(fd);
                return Err(error);
            }
            let current = libc::fcntl(fd, libc::F_GETFL);
            if current < 0 || libc::fcntl(fd, libc::F_SETFL, current | libc::O_NONBLOCK) < 0 {
                let error = io::Error::last_os_error();
                libc::close(fd);
                return Err(error);
            }
            if let Err(error) = configure_interface(name, mac) {
                libc::close(fd);
                return Err(error);
            }
            Ok(TapDevice {
                fd,
                name: name.to_string(),
            })
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Receive one Ethernet frame without blocking.
    pub fn try_recv(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut frame = vec![0u8; 65536];
        let received = unsafe {
            libc::read(
                self.fd,
                frame.as_mut_ptr().cast::<libc::c_void>(),
                frame.len(),
            )
        };
        if received < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(error)
            };
        }
        if received == 0 {
            return Ok(None);
        }
        frame.truncate(received as usize);
        Ok(Some(frame))
    }

    pub fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        let written =
            unsafe { libc::write(self.fd, frame.as_ptr().cast::<libc::c_void>(), frame.len()) };
        if written < 0 {
            return Err(io::Error::last_os_error());
        }
        if written as usize != frame.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short TAP frame write",
            ));
        }
        Ok(())
    }
}

impl Drop for TapDevice {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

unsafe fn configure_interface(name: &str, mac: [u8; 6]) -> io::Result<()> {
    let if_name = interface_name(name)?;
    let socket = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
    if socket < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut hardware = IfReqHwAddr {
        name: if_name,
        address: std::mem::zeroed(),
        pad: [0; 8],
    };
    hardware.address.sa_family = libc::ARPHRD_ETHER as libc::sa_family_t;
    for (dst, src) in hardware.address.sa_data.iter_mut().zip(mac) {
        *dst = src as libc::c_char;
    }
    if libc::ioctl(socket, libc::SIOCSIFHWADDR as _, &hardware) < 0 {
        let error = io::Error::last_os_error();
        libc::close(socket);
        return Err(error);
    }

    let mut flags = IfReqFlags {
        name: if_name,
        flags: 0,
        pad: [0; IFREQ_PAD],
    };
    if libc::ioctl(socket, libc::SIOCGIFFLAGS as _, &mut flags) < 0 {
        let error = io::Error::last_os_error();
        libc::close(socket);
        return Err(error);
    }
    flags.flags |= libc::IFF_UP as libc::c_short;
    if libc::ioctl(socket, libc::SIOCSIFFLAGS as _, &flags) < 0 {
        let error = io::Error::last_os_error();
        libc::close(socket);
        return Err(error);
    }
    libc::close(socket);
    Ok(())
}
