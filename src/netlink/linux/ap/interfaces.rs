use super::*;

#[derive(Clone, Copy, Default)]
pub struct ApRuntimePaths<'a> {
    pub ctrl: Option<&'a str>,
    pub wpa_psk: Option<&'a str>,
    pub sae_psk: Option<&'a str>,
    pub spr_api: Option<&'a str>,
    pub spr_dhcp_helper: Option<&'a str>,
}

/// Remove a station from the kernel. An already-absent station is success so
/// cleanup retries remain idempotent.
pub(super) fn nl_del_station(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    sta: &[u8; 6],
) -> io::Result<()> {
    let seq = sock.next_seq();
    let m = GenlMessage::new(family, NL80211_CMD_DEL_STATION, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_MAC, sta));
    match sock.request_ack(m) {
        Err(error) if kernel_object_is_absent(&error) => Ok(()),
        result => result,
    }
}

/// Create an `AP_VLAN` interface beneath the AP (NEW_INTERFACE), bring it up,
/// and return its ifindex. Each per-station VIF gets its own such interface.
/// Delete every stranded per-station VIF belonging to this radio: netdevs named
/// `<iface>.<id>` with `id >= PER_STA_VLAN_ID_START`, matching the allocator's
/// own naming (`per_sta_vif_name`). Best-effort — a name that has already gone
/// away between the scan and the delete just no-ops.
pub(super) fn flush_stale_ap_vlans(sock: &mut NetlinkSocket, family: u16, iface: &str) {
    let prefix = format!("{iface}.");
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(id) = name
            .strip_prefix(&prefix)
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        if id < PER_STA_VLAN_ID_START {
            continue;
        }
        let cname = format!("{name}\0");
        let idx = unsafe { libc::if_nametoindex(cname.as_ptr() as *const libc::c_char) };
        if idx != 0 {
            eprintln!("netlink AP: flushing stale per-station VIF {name} (ifindex {idx})");
            if let Err(error) = nl_del_iface(sock, family, idx) {
                eprintln!("netlink AP: failed to flush stale VIF {name}: {error}");
            }
        }
    }
}

pub(super) fn nl_create_ap_vlan(
    sock: &mut NetlinkSocket,
    family: u16,
    ap_ifindex: u32,
    name: &str,
    parent_addr: &[u8; 6],
) -> io::Result<u32> {
    // A prior run (or a prior failed attempt this run) may have left a netdev of
    // this name behind — the allocator only tracks this process's own live map,
    // so it re-proposes the same id/name. Delete any stale namesake first, making
    // creation idempotent instead of failing with EEXIST.
    let cname = format!("{name}\0");
    let existing = unsafe { libc::if_nametoindex(cname.as_ptr() as *const libc::c_char) };
    if existing != 0 {
        nl_del_iface(sock, family, existing)?;
    }
    let seq = sock.next_seq();
    let m = ap_vlan_create_message(family, seq, ap_ifindex, name);
    sock.request_ack(m)?;
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr() as *const libc::c_char) };
    if idx == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "AP_VLAN ifindex lookup failed",
        ));
    }
    // NEW_INTERFACE already committed the netdev. Match the reference backend:
    // set the AP/MLD address while it is down, then bring it up. If either step
    // fails, tear it down so the next attempt does not pile onto a dead vdev.
    if let Err(e) = iface_set_mac(name, parent_addr).and_then(|()| iface_set_up(name)) {
        if let Err(cleanup_error) = nl_del_iface(sock, family, idx) {
            return Err(io::Error::other(format!(
                "{e}; cleanup of AP_VLAN {name} failed: {cleanup_error}"
            )));
        }
        return Err(e);
    }
    Ok(idx)
}

/// Create an additional standalone AP interface on the same radio as the primary
/// (NEW_INTERFACE keyed by the primary's ifindex resolves to its wiphy), assign
/// it the BSS's BSSID, bring it up, and return its ifindex. The interface is
/// created with NL80211_ATTR_SOCKET_OWNER, so the kernel deletes it when `sock`
/// closes — no leaked netdevs on shutdown, even on SIGKILL.
pub(super) fn nl_create_ap_bss(
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
    paths: ApRuntimePaths<'_>,
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
            let spr_api = paths.spr_api.map(str::to_owned);
            let spr_dhcp_helper = paths.spr_dhcp_helper.map(str::to_owned);
            let wpa_psk = paths.wpa_psk.map(str::to_owned);
            let sae_psk = paths.sae_psk.map(str::to_owned);
            let bss_ctrl = paths.ctrl.and_then(|primary| {
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
                    ApRuntimePaths {
                        ctrl: bss_ctrl.as_deref(),
                        wpa_psk: wpa_psk.as_deref(),
                        sae_psk: sae_psk.as_deref(),
                        spr_api: spr_api.as_deref(),
                        spr_dhcp_helper: spr_dhcp_helper.as_deref(),
                    },
                ) {
                    eprintln!("netlink AP: BSS {name} exited: {e}");
                }
            });
        }
        Some(setup)
    };
    run_offload_ap(primary, iface, channel, paths)
}
