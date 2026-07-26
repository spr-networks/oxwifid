//! Runtime control interface, modelled on reference AP's `ctrl_interface`.
//!
//! A Unix datagram socket carries text commands (`STATUS`, `STA-DUMP`,
//! `DEAUTH <mac>`, `FAILURES`, `PING`) and an event subscription (`ATTACH` /
//! `DETACH`). Subscribed clients receive `AP-STA-*` event lines as they happen
//! (connect / disconnect / failed-auth), the same way `reference AP control client` does.
//!
//! [`handle_command`] is portable and unit-tested; the socket server is gated to
//! Unix targets.

use crate::ap::Ap;
use crate::util::bytes_to_mac;

/// Netlink-owned metadata exposed through reference AP's `STA <mac>` control
/// command. SPR uses `vlan_id` to derive the per-station interface name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StationControlInfo {
    pub vlan_id: u32,
    pub ifname: String,
    pub telemetry: Option<StationTelemetry>,
}

/// Live per-station counters read from NL80211_CMD_GET_STATION. Rates use the
/// kernel/reference AP control-interface unit of 100 kbit/s (60 = 6 Mbit/s).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StationTelemetry {
    pub signal: Option<i8>,
    pub signal_avg: Option<i8>,
    pub tx_rate_info: Option<u32>,
    pub rx_rate_info: Option<u32>,
}

/// Execute one control command against the AP, returning the text reply and any
/// frames to transmit (e.g. the deauth produced by `DEAUTH`). `ATTACH`/`DETACH`
/// are handled by the socket server, not here.
pub fn handle_command(ap: &mut Ap, cmd: &str) -> (String, Vec<Vec<u8>>) {
    handle_command_with_context(ap, cmd, &|_| None, "")
}

/// Execute a control command with platform-owned station metadata. Keeping the
/// resolver outside [`Ap`] avoids putting Linux interface lifecycle into the
/// portable 802.11 state machine.
pub fn handle_command_with_station_info(
    ap: &mut Ap,
    cmd: &str,
    station_info: &dyn Fn(&[u8; 6]) -> Option<StationControlInfo>,
) -> (String, Vec<Vec<u8>>) {
    handle_command_with_context(ap, cmd, station_info, "")
}

fn frequency(ap: &Ap) -> u32 {
    if ap.band6() {
        5950 + 5 * ap.channel as u32
    } else if crate::frames::is_5ghz(ap.channel) {
        5000 + 5 * ap.channel as u32
    } else if ap.channel == 14 {
        2484
    } else {
        2407 + 5 * ap.channel as u32
    }
}

/// reference AP exposes a non-AP MLD as one station keyed by its stable MLD MAC,
/// regardless of which affiliated link carried the association.
fn control_station_macs(ap: &Ap) -> Vec<[u8; 6]> {
    let mut macs: Vec<[u8; 6]> = ap
        .station_macs()
        .into_iter()
        .map(|link| ap.station_mld_mac(&link).unwrap_or(link))
        .collect();
    macs.sort_unstable();
    macs.dedup();
    macs
}

fn station_reply(ap: &Ap, mac: &[u8; 6], info: Option<StationControlInfo>) -> String {
    let core_mac = ap.station_link_for_peer(mac).unwrap_or(*mac);
    let assoc_ies = ap.station_assoc_ies(&core_mac).unwrap_or(&[]);
    let flags = station_flags(ap.is_associated(&core_mac), assoc_ies);
    // reference AP's STA/STA-FIRST/STA-NEXT replies begin with the raw MAC line.
    // reference AP control client all_sta relies on that exact shape while SPR consumes vlan_id.
    let mut reply = format!("{}\nflags={flags}\n", bytes_to_mac(mac));
    if let Some(selector) = akm_suite_selector(assoc_ies) {
        reply.push_str(&format!("AKMSuiteSelector={selector}\n"));
    }
    if let Some(info) = info {
        reply.push_str(&format!(
            "vlan_id={}\nvlan_iface={}\n",
            info.vlan_id, info.ifname
        ));
        if let Some(t) = info.telemetry {
            if let Some(signal) = t.signal {
                reply.push_str(&format!("signal={signal}\n"));
            }
            if let Some(signal_avg) = t.signal_avg {
                reply.push_str(&format!("signal_avg={signal_avg}\n"));
            }
            if let Some(rate) = t.tx_rate_info {
                reply.push_str(&format!("tx_rate_info={rate}\n"));
            }
            if let Some(rate) = t.rx_rate_info {
                reply.push_str(&format!("rx_rate_info={rate}\n"));
            }
        }
    }
    reply
}

/// Reproduce reference AP's per-station PHY flags from the capabilities negotiated
/// in that station's association request. SPR uses these flags to label clients
/// as 802.11n/ac/ax/be; using the AP's configured maximum would overstate older
/// clients connected to an EHT AP.
fn station_flags(associated: bool, assoc_ies: &[u8]) -> String {
    let mut flags = String::new();
    if associated {
        flags.push_str("[AUTH][ASSOC][AUTHORIZED]");
    }
    if crate::frames::find_ie(assoc_ies, 45).is_some() {
        flags.push_str("[HT]");
    }
    if crate::frames::find_ie(assoc_ies, 191).is_some() {
        flags.push_str("[VHT]");
    }
    if find_ext_ie(assoc_ies, 35).is_some() {
        flags.push_str("[HE]");
    }
    if find_ext_ie(assoc_ies, 108).is_some() {
        flags.push_str("[EHT]");
    }
    if flags.is_empty() {
        flags.push_str("[]");
    }
    flags
}

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

/// Format the station-selected RSN AKM the same way reference AP exposes
/// `AKMSuiteSelector` (for example SAE is `00-0f-ac-8`).
fn akm_suite_selector(assoc_ies: &[u8]) -> Option<String> {
    let rsn = crate::frames::find_ie(assoc_ies, 48)?;
    let mut off = 2 + 4; // version + group cipher
    let pairwise_count = u16::from_le_bytes([*rsn.get(off)?, *rsn.get(off + 1)?]) as usize;
    off = off.checked_add(2 + 4 * pairwise_count)?;
    let akm_count = u16::from_le_bytes([*rsn.get(off)?, *rsn.get(off + 1)?]) as usize;
    if akm_count == 0 {
        return None;
    }
    off = off.checked_add(2)?;
    let suite = rsn.get(off..off + 4)?;
    Some(format!(
        "{:02x}-{:02x}-{:02x}-{}",
        suite[0], suite[1], suite[2], suite[3]
    ))
}

/// Execute the reference AP-compatible command set SPR uses, with the BSS interface
/// name included in STATUS.
pub fn handle_command_with_context(
    ap: &mut Ap,
    cmd: &str,
    station_info: &dyn Fn(&[u8; 6]) -> Option<StationControlInfo>,
    ifname: &str,
) -> (String, Vec<Vec<u8>>) {
    let mut it = cmd.split_whitespace();
    match it.next().unwrap_or("") {
        "PING" => ("PONG\n".to_string(), vec![]),
        "STATUS" => {
            let macs = control_station_macs(ap);
            let assoc = macs
                .iter()
                .filter(|m| {
                    let core = ap.station_link_for_peer(m).unwrap_or(**m);
                    ap.is_associated(&core)
                })
                .count();
            let phy = ap.phy_mode();
            (
                format!(
                    "state=ENABLED\nbackend=rustap\ndriver=rustap-netlink\nphy={}\nfreq={}\nchannel={}\nwidth={}\nieee80211n=1\nieee80211ac={}\nieee80211ax={}\nieee80211be={}\nbss[0]={}\nbssid[0]={}\nssid[0]={}\nssid={}\nnum_sta[0]={}\nstations={}\nassociated={}\n",
                    match phy {
                        crate::frames::PhyMode::Ht => "HT",
                        crate::frames::PhyMode::Vht => "VHT",
                        crate::frames::PhyMode::He => "HE",
                        crate::frames::PhyMode::Eht => "EHT",
                    },
                    frequency(ap),
                    ap.channel,
                    ap.channel_width,
                    u8::from(phy >= crate::frames::PhyMode::Vht),
                    u8::from(phy >= crate::frames::PhyMode::He),
                    u8::from(phy >= crate::frames::PhyMode::Eht),
                    ifname,
                    bytes_to_mac(&ap.mac),
                    String::from_utf8_lossy(&ap.ssid),
                    String::from_utf8_lossy(&ap.ssid),
                    assoc,
                    macs.len(),
                    assoc,
                ),
                vec![],
            )
        }
        "STA-DUMP" | "LIST-STA" => {
            let mut s = String::new();
            for m in control_station_macs(ap) {
                let core = ap.station_link_for_peer(&m).unwrap_or(m);
                let state = if ap.is_associated(&core) {
                    "ASSOCIATED"
                } else {
                    "HANDSHAKING"
                };
                s.push_str(&format!("{} {}\n", bytes_to_mac(&m), state));
            }
            if s.is_empty() {
                s.push_str("(no stations)\n");
            }
            (s, vec![])
        }
        "STA" => match it.next() {
            Some(arg) => match crate::util::try_mac_to_bytes(arg) {
                Some(mac) => {
                    let info = station_info(&mac);
                    let known = ap.station_link_for_peer(&mac).is_some() || info.is_some();
                    if !known {
                        ("FAIL unknown station\n".to_string(), vec![])
                    } else {
                        (station_reply(ap, &mac, info), vec![])
                    }
                }
                None => ("FAIL invalid MAC\n".to_string(), vec![]),
            },
            None => ("FAIL usage: STA <mac>\n".to_string(), vec![]),
        },
        "STA-FIRST" => {
            let macs = control_station_macs(ap);
            match macs.first() {
                Some(mac) => {
                    let info = station_info(mac);
                    (station_reply(ap, mac, info), vec![])
                }
                None => ("FAIL\n".to_string(), vec![]),
            }
        }
        "STA-NEXT" => match it.next().and_then(crate::util::try_mac_to_bytes) {
            Some(after) => {
                let macs = control_station_macs(ap);
                match macs.into_iter().find(|mac| *mac > after) {
                    Some(mac) => {
                        let info = station_info(&mac);
                        (station_reply(ap, &mac, info), vec![])
                    }
                    None => ("FAIL\n".to_string(), vec![]),
                }
            }
            None => ("FAIL usage: STA-NEXT <mac>\n".to_string(), vec![]),
        },
        "DEAUTH" | "DEAUTHENTICATE" | "DISASSOCIATE" => match it.next() {
            // The control socket carries untrusted input, so parse the MAC
            // without panicking (a malformed MAC must not crash the AP).
            Some(arg) => match crate::util::try_mac_to_bytes(arg) {
                // reference AP acknowledges an administratively requested removal
                // even when the station has already disappeared. SPR sends
                // DISASSOCIATE followed by DEAUTHENTICATE, so the second must
                // remain idempotent.
                Some(mac) => {
                    let core = ap.station_link_for_peer(&mac).unwrap_or(mac);
                    ("OK\n".to_string(), ap.kick(&core).into_iter().collect())
                }
                None => ("FAIL invalid MAC\n".to_string(), vec![]),
            },
            None => ("FAIL usage: DEAUTHENTICATE <mac>\n".to_string(), vec![]),
        },
        "FAILURES" => {
            let mut s = String::new();
            for r in ap.failures().records() {
                s.push_str(&format!(
                    "{} kind={} count={} traits={:#018x}\n",
                    bytes_to_mac(&r.mac),
                    r.kind.label(),
                    r.count,
                    r.traits,
                ));
            }
            if s.is_empty() {
                s.push_str("(no failures)\n");
            }
            (s, vec![])
        }
        "" => ("FAIL empty command\n".to_string(), vec![]),
        other => (format!("UNKNOWN COMMAND '{other}'\n"), vec![]),
    }
}

#[cfg(test)]
mod tests {
    use super::{handle_command, handle_command_with_station_info, StationControlInfo};
    use crate::ap::Ap;
    use crate::util::mac_to_bytes;

    fn ap() -> Ap {
        Ap::new(
            "turtlenet",
            "password1234",
            mac_to_bytes("02:00:00:00:00:00"),
            6,
        )
    }

    #[test]
    fn ping_status_and_unknown() {
        let mut ap = ap();
        assert_eq!(handle_command(&mut ap, "PING").0, "PONG\n");
        let status = handle_command(&mut ap, "STATUS").0;
        assert!(status.contains("backend=rustap"), "{status}");
        assert!(status.contains("ssid=turtlenet"), "{status}");
        assert!(status.contains("channel=6"), "{status}");
        assert!(status.contains("stations=0"), "{status}");
        assert!(handle_command(&mut ap, "BOGUS")
            .0
            .starts_with("UNKNOWN COMMAND"));
        assert!(handle_command(&mut ap, "").0.starts_with("FAIL"));
    }

    #[test]
    fn dump_and_failures_when_empty() {
        let mut ap = ap();
        assert_eq!(handle_command(&mut ap, "STA-DUMP").0, "(no stations)\n");
        assert_eq!(handle_command(&mut ap, "FAILURES").0, "(no failures)\n");
    }

    #[test]
    fn reference_ap_disconnect_commands_are_idempotent() {
        let mut ap = ap();
        let (reply, frames) = handle_command(&mut ap, "DEAUTH 02:00:00:00:ab:cd");
        assert_eq!(reply, "OK\n");
        assert!(frames.is_empty());
        assert_eq!(
            handle_command(&mut ap, "DISASSOCIATE 02:00:00:00:ab:cd").0,
            "OK\n"
        );
        assert_eq!(
            handle_command(&mut ap, "DEAUTHENTICATE 02:00:00:00:ab:cd").0,
            "OK\n"
        );
        // Missing argument is rejected, not panicked on.
        assert!(handle_command(&mut ap, "DEAUTH").0.starts_with("FAIL"));
    }

    #[test]
    fn sta_command_reports_spr_vlan_contract_even_for_disconnect_grace() {
        let mut ap = ap();
        let sta = mac_to_bytes("02:00:00:00:ab:cd");
        let calls = std::cell::Cell::new(0);
        let info = |mac: &[u8; 6]| {
            calls.set(calls.get() + 1);
            (*mac == sta).then(|| StationControlInfo {
                vlan_id: 4096,
                ifname: "wlan3.4096".to_string(),
                telemetry: Some(super::StationTelemetry {
                    signal: Some(-57),
                    signal_avg: Some(-58),
                    tx_rate_info: Some(60),
                    rx_rate_info: Some(7206),
                }),
            })
        };
        let (reply, frames) =
            handle_command_with_station_info(&mut ap, "STA 02:00:00:00:ab:cd", &info);
        assert!(frames.is_empty());
        assert!(reply.starts_with("02:00:00:00:ab:cd\n"), "{reply}");
        assert!(reply.contains("vlan_id=4096\n"), "{reply}");
        assert!(reply.contains("vlan_iface=wlan3.4096\n"), "{reply}");
        assert!(reply.contains("signal=-57\n"), "{reply}");
        assert!(reply.contains("signal_avg=-58\n"), "{reply}");
        assert!(reply.contains("tx_rate_info=60\n"), "{reply}");
        assert!(reply.contains("rx_rate_info=7206\n"), "{reply}");
        assert_eq!(calls.get(), 1, "STA metadata must be resolved once");
        assert!(
            handle_command_with_station_info(&mut ap, "STA invalid", &info)
                .0
                .starts_with("FAIL")
        );
    }

    #[test]
    fn spr_phy_and_akm_fields_are_derived_per_station() {
        let mut ies = Vec::new();
        ies.extend_from_slice(&crate::frames::ie(45, &[0; 26]));
        ies.extend_from_slice(&crate::frames::ie(191, &[0; 12]));
        ies.extend_from_slice(&crate::frames::ie(255, &[35, 0]));
        ies.extend_from_slice(&crate::frames::ie(255, &[108, 0]));
        ies.extend_from_slice(&crate::frames::RSN_WPA3);

        assert_eq!(
            super::station_flags(true, &ies),
            "[AUTH][ASSOC][AUTHORIZED][HT][VHT][HE][EHT]"
        );
        assert_eq!(
            super::akm_suite_selector(&ies).as_deref(),
            Some("00-0f-ac-8")
        );
    }

    #[test]
    fn spr_phy_flags_do_not_overstate_a_legacy_station() {
        assert_eq!(super::station_flags(true, &[]), "[AUTH][ASSOC][AUTHORIZED]");
        assert_eq!(super::station_flags(false, &[]), "[]");
    }
}

#[cfg(unix)]
pub use server::ControlServer;

#[cfg(unix)]
mod server {
    use super::{handle_command_with_context, Ap, StationControlInfo};
    use crate::ap::PreparedPskFile;
    use std::io;
    use std::os::unix::net::UnixDatagram;
    use std::path::PathBuf;

    struct CredentialReload {
        requests: std::sync::mpsc::SyncSender<Vec<u8>>,
        results: std::sync::mpsc::Receiver<Result<(usize, PreparedPskFile), String>>,
        pending: bool,
    }

    /// A bound control socket plus the set of clients subscribed to events.
    pub struct ControlServer {
        sock: UnixDatagram,
        path: PathBuf,
        ifname: String,
        psk_file: Option<PathBuf>,
        reload: Option<CredentialReload>,
        attached: Vec<PathBuf>,
    }

    impl ControlServer {
        /// Bind the control socket at `path` (replacing any stale socket file).
        pub fn bind(path: &str, ifname: &str, psk_file: Option<&str>) -> io::Result<ControlServer> {
            if let Some(parent) = std::path::Path::new(path).parent() {
                std::fs::create_dir_all(parent)?;
            }
            let _ = std::fs::remove_file(path);
            let sock = UnixDatagram::bind(path)?;
            sock.set_nonblocking(true)?;
            // Harden the socket to owner-only (0600). The control interface can
            // deauthenticate stations and trigger rekeys, so it must not be
            // writable by other local users. (reference AP guards its ctrl_interface
            // the same way, via directory ownership + mode.)
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            let psk_path = psk_file.map(PathBuf::from);
            let reload = psk_path.as_ref().and_then(|reload_path| {
                let reload_path = reload_path.clone();
                let (request_tx, request_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(1);
                let (result_tx, result_rx) = std::sync::mpsc::channel();
                std::thread::Builder::new()
                    .name("rustap-credential-reload".to_string())
                    .spawn(move || {
                        use zeroize::Zeroize;
                        while let Ok(ssid) = request_rx.recv() {
                            let result = crate::config::parse_psk_file(
                                reload_path.to_string_lossy().as_ref(),
                            )
                            .map(|mut entries| {
                                let count = entries.len();
                                let prepared = PreparedPskFile::derive(&ssid, &entries);
                                for (_, password) in &mut entries {
                                    password.zeroize();
                                }
                                (count, prepared)
                            });
                            if result_tx.send(result).is_err() {
                                break;
                            }
                        }
                    })
                    .ok()
                    .map(|_| CredentialReload {
                        requests: request_tx,
                        results: result_rx,
                        pending: false,
                    })
            });
            Ok(ControlServer {
                sock,
                path: PathBuf::from(path),
                ifname: ifname.to_string(),
                psk_file: psk_path,
                reload,
                attached: Vec::new(),
            })
        }

        fn apply_reload_results(&mut self, ap: &mut Ap) {
            let Some(reload) = self.reload.as_mut() else {
                return;
            };
            loop {
                match reload.results.try_recv() {
                    Ok(result) => {
                        reload.pending = false;
                        match result {
                            Ok((count, prepared)) => {
                                ap.install_prepared_psk_file(prepared);
                                if let Some(path) = self.psk_file.as_ref() {
                                    eprintln!(
                                        "netlink AP: reloaded {count} credential(s) from {}",
                                        path.display()
                                    );
                                }
                            }
                            Err(err) => {
                                ap.cancel_psk_reload();
                                if let Some(path) = self.psk_file.as_ref() {
                                    eprintln!(
                                        "netlink AP: credential reload from {} failed: {err}",
                                        path.display()
                                    );
                                }
                            }
                        }
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        if reload.pending {
                            reload.pending = false;
                            ap.cancel_psk_reload();
                            eprintln!(
                                "netlink AP: credential reload worker stopped before completing"
                            );
                        }
                        break;
                    }
                }
            }
        }

        /// Handle a bounded batch of pending commands, returning any frames the
        /// AP wants transmitted (e.g. an admin `DEAUTH`). Bounding the batch
        /// prevents a trusted-but-buggy local client from starving radio events.
        pub fn service(
            &mut self,
            ap: &mut Ap,
            station_info: &dyn Fn(&[u8; 6]) -> Option<StationControlInfo>,
        ) -> Vec<Vec<u8>> {
            self.apply_reload_results(ap);
            let mut frames = Vec::new();
            let mut buf = [0u8; 4096];
            const MAX_COMMANDS_PER_SERVICE: usize = 16;
            for _ in 0..MAX_COMMANDS_PER_SERVICE {
                let (n, peer) = match self.sock.recv_from(&mut buf) {
                    Ok((n, addr)) => match addr.as_pathname() {
                        Some(p) => (n, p.to_path_buf()),
                        None => continue, // unnamed peer: nowhere to reply
                    },
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                };
                let cmd = String::from_utf8_lossy(&buf[..n]);
                let cmd = cmd.trim();
                let reply = match cmd {
                    "ATTACH" => {
                        if !self.attached.contains(&peer) {
                            self.attached.push(peer.clone());
                        }
                        "OK\n".to_string()
                    }
                    "DETACH" => {
                        self.attached.retain(|p| p != &peer);
                        "OK\n".to_string()
                    }
                    // A static-credential (guest) BSS keeps its static password:
                    // reloading the device credential database must not touch it
                    // (the set_psk_file guard would ignore it anyway; answer
                    // without reading the file).
                    "RELOAD_WPA_PSK" | "RELOAD" if ap.static_credential() => "OK\n".to_string(),
                    "RELOAD_WPA_PSK" | "RELOAD" => match self.reload.as_mut() {
                        Some(reload) if reload.pending => "OK\n".to_string(),
                        Some(reload) => match reload.requests.try_send(ap.ssid.clone()) {
                            Ok(()) => {
                                reload.pending = true;
                                ap.begin_psk_reload();
                                "OK\n".to_string()
                            }
                            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                                "FAIL busy\n".to_string()
                            }
                            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                                "FAIL reload worker stopped\n".to_string()
                            }
                        },
                        None if self.psk_file.is_none() => {
                            "FAIL no psk_file configured\n".to_string()
                        }
                        None => "FAIL reload worker unavailable\n".to_string(),
                    },
                    _ => {
                        let (r, fs) =
                            handle_command_with_context(ap, cmd, station_info, &self.ifname);
                        frames.extend(fs);
                        r
                    }
                };
                let _ = self.sock.send_to(reply.as_bytes(), &peer);
            }
            frames
        }

        /// Push one event line to every attached client; drop clients whose
        /// socket has gone away. reference AP prefixes events with a `<prio>` tag.
        pub fn broadcast(&mut self, line: &str) {
            let msg = format!("<3>{line}\n");
            let sock = &self.sock;
            self.attached
                .retain(|peer| sock.send_to(msg.as_bytes(), peer).is_ok());
        }
    }

    impl Drop for ControlServer {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
