//! Linux netdev operations shared by scanning and AP/VLAN setup.

use super::*;

/// Change a network interface's IFF_UP state.
pub(crate) fn iface_set_state(name: &str, up: bool) -> io::Result<()> {
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
        let mut request: IfReq = std::mem::zeroed();
        for (index, byte) in name.as_bytes().iter().take(15).enumerate() {
            request.name[index] = *byte;
        }
        let mut result = libc::ioctl(fd, libc::SIOCGIFFLAGS as _, &mut request as *mut IfReq);
        if result >= 0 {
            if up {
                request.flags |= libc::IFF_UP as libc::c_short;
            } else {
                request.flags &= !(libc::IFF_UP as libc::c_short);
            }
            result = libc::ioctl(fd, libc::SIOCSIFFLAGS as _, &request as *const IfReq);
        }
        let error = io::Error::last_os_error();
        libc::close(fd);
        if result < 0 {
            return Err(error);
        }
    }
    Ok(())
}

pub(crate) fn iface_set_up(name: &str) -> io::Result<()> {
    iface_set_state(name, true)
}

/// Set a down netdev's hardware address through SIOCSIFHWADDR.
///
/// AP_VLAN creation follows the same order as the reference backend:
/// NEW_INTERFACE, address ioctl, then IFF_UP.
pub(crate) fn iface_set_mac(name: &str, mac: &[u8; 6]) -> io::Result<()> {
    #[repr(C)]
    struct IfReq {
        name: [libc::c_char; libc::IFNAMSIZ],
        address: libc::sockaddr,
        _pad: [u8; 8],
    }

    if name.is_empty() || name.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name must be 1..15 bytes",
        ));
    }

    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut request: IfReq = std::mem::zeroed();
        for (destination, source) in request.name.iter_mut().zip(name.bytes()) {
            *destination = source as libc::c_char;
        }
        request.address.sa_family = libc::ARPHRD_ETHER as libc::sa_family_t;
        for (destination, source) in request.address.sa_data.iter_mut().zip(mac) {
            *destination = *source as libc::c_char;
        }
        let result = libc::ioctl(fd, libc::SIOCSIFHWADDR as _, &request as *const IfReq);
        let error = io::Error::last_os_error();
        libc::close(fd);
        if result < 0 {
            return Err(error);
        }
    }
    Ok(())
}
