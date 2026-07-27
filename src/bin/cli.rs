//! barely-cli: a minimal WPA2/WPA3 CCMP/GCMP station.
//!
//! Connects to the first matching beacon, completes the 4-way handshake, and
//! (with --ping) sends one ICMP echo to the gateway, printing AUTHENTICATED and
//! PING_REPLY_OK to stderr on success.
//!
//! Usage:
//!   barely-cli --config FILE.json [--ssid NAME] [--mac MAC] [--ping]
//!              [--gw-mac MAC] [--src-ip IP] [--gw-ip IP]

use std::time::Duration;

use barely_ap::client::Client;
use barely_ap::config::{parse_data_cipher, parse_psk_file, Config, KeyMgmt};
use barely_ap::raw_frames::{self, ClientNode, StdioLink};
use barely_ap::uplink::{self, ScanCandidate, UplinkSecurity};
use barely_ap::util::{mac_to_bytes, try_mac_to_bytes};
use zeroize::Zeroize;

#[cfg(target_os = "linux")]
use barely_ap::raw_frames::Link;

fn parse_ip(s: &str) -> [u8; 4] {
    let mut out = [0u8; 4];
    for (i, part) in s.split('.').enumerate() {
        if i < 4 {
            out[i] = part.parse().unwrap_or(0);
        }
    }
    out
}

fn interface_mac(iface: &str) -> Result<[u8; 6], String> {
    let value = std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))
        .map_err(|error| format!("cannot read station MAC from interface {iface:?}: {error}"))?;
    let mac = try_mac_to_bytes(value.trim())
        .ok_or_else(|| format!("interface {iface:?} reported a malformed MAC address"))?;
    if mac == [0; 6] || mac[0] & 1 != 0 {
        return Err(format!(
            "interface {iface:?} has invalid station MAC {}",
            barely_ap::util::bytes_to_mac(&mac)
        ));
    }
    Ok(mac)
}

fn configured_security(key_mgmt: Option<KeyMgmt>) -> (bool, bool, bool) {
    (
        matches!(key_mgmt, Some(KeyMgmt::Sae | KeyMgmt::SaeTransition)),
        key_mgmt == Some(KeyMgmt::PskSha256),
        key_mgmt == Some(KeyMgmt::Owe),
    )
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut ssid = "turtlenet".to_string();
    let mut psk = String::new();
    let mut configured_credential_file: Option<String> = None;
    let mut configured_key_mgmt: Option<KeyMgmt> = None;
    let mut configured_iface: Option<String> = None;
    let mut configured_mode: Option<String> = None;
    let mut configured_channel: Option<u8> = None;
    let mut configured_pairwise_cipher = barely_ap::structures::DataCipher::Ccmp128;
    let mut configured_band6 = false;
    let mut configured_bssid: Option<[u8; 6]> = None;
    for i in 1..args.len() {
        if args[i] == "--config" {
            let Some(path) = args.get(i + 1) else {
                eprintln!("barely-cli: --config requires a JSON file");
                std::process::exit(2);
            };
            let mut text = std::fs::read_to_string(path).unwrap_or_else(|e| {
                eprintln!("barely-cli: cannot read config {path:?}: {e}");
                std::process::exit(1);
            });
            let mut cfg = match Config::from_json(&text) {
                Ok(cfg) => cfg,
                Err(e) => {
                    text.zeroize();
                    eprintln!("barely-cli: {path}: {e}");
                    std::process::exit(1);
                }
            };
            text.zeroize();
            ssid = cfg.ssid.clone();
            psk.zeroize();
            psk = cfg.passphrase.clone();
            let key_mgmt = cfg.effective_key_mgmt();
            configured_credential_file = match key_mgmt {
                KeyMgmt::Sae | KeyMgmt::SaeTransition => cfg.sae_psk_file.clone(),
                KeyMgmt::Psk | KeyMgmt::PskSha256 => cfg.wpa_psk_file.clone(),
                KeyMgmt::Owe => None,
            };
            configured_key_mgmt = Some(key_mgmt);
            configured_iface = Some(cfg.iface.clone());
            configured_mode = Some(cfg.mode.clone());
            configured_channel = Some(cfg.channel);
            configured_pairwise_cipher = cfg.pairwise_cipher;
            configured_band6 = cfg.band.is_6ghz();
            // In a station config, `bssid`/`mac` identifies the selected AP.
            // The all-zero default means no BSSID pin.
            if cfg.mac != [0; 6] && cfg.mac != mac_to_bytes("02:00:00:00:00:00") {
                configured_bssid = Some(cfg.mac);
            }
            cfg.passphrase.zeroize();
        }
    }
    let mut mac: Option<[u8; 6]> = None;
    let mut ping = false;
    let (mut sae, mut psk_sha256, mut owe) = configured_security(configured_key_mgmt);
    let mut hnp = false;
    let mut ocv = false;
    let mut wmm = true;
    let mut wmm_tid: Option<u8> = None; // test override for the WMM user priority
    let mut dscp: u8 = 0; // DSCP stamped on the test ping (drives WMM classification)
    let mut gw_mac = mac_to_bytes("02:00:00:00:00:00");
    let mut src_ip = [10, 10, 10, 2];
    let mut gw_ip = [10, 10, 10, 1];
    let mut mode = configured_mode.unwrap_or_else(|| "stdio".to_string());
    let mut iface = configured_iface.unwrap_or_else(|| "wlan0".to_string());
    let mut channel: u8 = configured_channel.unwrap_or(1);
    let mut target_bssid = configured_bssid;
    let mut pairwise_cipher = configured_pairwise_cipher;
    let mut mld_mac: Option<[u8; 6]> = None;
    let mut link1_mac: Option<[u8; 6]> = None;
    let mut ap_mld_mac: Option<[u8; 6]> = None;
    let mut pause_m3 = false;
    let mut tap_iface: Option<String> = None;
    let mut state_file: Option<String> = None;
    let mut spr_config_path: Option<String> = None;
    let mut spr_iface: Option<String> = None;
    let mut scan_iface: Option<String> = None;
    let mut scan_json = false;
    let mut scan_ssids: Vec<Vec<u8>> = Vec::new();
    let mut rescan_profile: Option<RescanProfile> = None;

    let mut i = 1;
    while i < args.len() {
        let next = |i: usize| args.get(i + 1).cloned().unwrap_or_default();
        match args[i].as_str() {
            "--config" => i += 1,
            "--spr-config" => spr_config_path = Some(next(i)),
            "--spr-iface" => spr_iface = Some(next(i)),
            "--scan-iface" => scan_iface = Some(next(i)),
            "--scan" => scan_json = true,
            "--scan-ssid" => {
                let value = next(i);
                if value.len() > 32 {
                    eprintln!("barely-cli: --scan-ssid exceeds 32 bytes");
                    std::process::exit(2);
                }
                scan_ssids.push(value.into_bytes());
            }
            "--ssid" => ssid = next(i),
            "--psk" => {
                psk.zeroize();
                eprintln!(
                    "barely-cli: --psk was removed because process arguments expose secrets; use --config"
                );
                std::process::exit(2);
            }
            "--mac" => mac = Some(mac_to_bytes(&next(i))),
            "--bssid" => target_bssid = Some(mac_to_bytes(&next(i))),
            "--gw-mac" => gw_mac = mac_to_bytes(&next(i)),
            "--src-ip" => src_ip = parse_ip(&next(i)),
            "--gw-ip" => gw_ip = parse_ip(&next(i)),
            "--ping" => ping = true,
            "--sae" => {
                sae = true;
                psk_sha256 = false;
                owe = false;
            }
            "--sae-hnp" => {
                sae = true;
                psk_sha256 = false;
                owe = false;
                hnp = true;
            }
            "--owe" => {
                sae = false;
                psk_sha256 = false;
                owe = true;
            }
            "--ocv" => ocv = true,
            "--no-wmm" => wmm = false,
            "--tid" | "--up" => wmm_tid = next(i).parse().ok().map(|t: u8| t & 0x07),
            "--dscp" => dscp = next(i).parse::<u8>().map(|d| d << 2).unwrap_or(0),
            "--mode" => mode = next(i),
            "--iface" => iface = next(i),
            "--channel" => channel = next(i).parse().unwrap_or(1),
            "--cipher" | "--pairwise-cipher" => {
                pairwise_cipher = parse_data_cipher(&next(i)).unwrap_or_else(|error| {
                    eprintln!("barely-cli: {error}");
                    std::process::exit(2);
                })
            }
            "--mld-mac" => mld_mac = Some(mac_to_bytes(&next(i))),
            "--link1-mac" => link1_mac = Some(mac_to_bytes(&next(i))),
            "--ap-mld-mac" => ap_mld_mac = Some(mac_to_bytes(&next(i))),
            "--pause-m3" => pause_m3 = true,
            "--tap" => tap_iface = Some(next(i)),
            "--state-file" => state_file = Some(next(i)),
            unknown if unknown.starts_with('-') => {
                eprintln!("barely-cli: unknown option {unknown:?}");
                std::process::exit(2);
            }
            _ => {}
        }
        i += 1;
    }

    if scan_json {
        let interface = scan_iface.as_deref().unwrap_or(&iface);
        let results = perform_scan(interface, &scan_ssids).unwrap_or_else(|error| {
            eprintln!("barely-cli: scan on {interface:?} failed: {error}");
            std::process::exit(1);
        });
        print_scan_json(&results);
        return;
    }

    if let Some(path) = spr_config_path.as_deref() {
        let logical_iface = spr_iface.as_deref().unwrap_or_else(|| {
            eprintln!("barely-cli: --spr-config requires --spr-iface");
            std::process::exit(2);
        });
        let physical_scan_iface = scan_iface.as_deref().unwrap_or(logical_iface);
        let mut text = std::fs::read_to_string(path).unwrap_or_else(|error| {
            eprintln!("barely-cli: cannot read SPR uplink config {path:?}: {error}");
            std::process::exit(1);
        });
        let networks = uplink::parse_spr_uplink(&text, logical_iface).unwrap_or_else(|error| {
            text.zeroize();
            eprintln!("barely-cli: {error}");
            std::process::exit(1);
        });
        text.zeroize();
        let mut directed = networks
            .iter()
            .map(|network| network.ssid.as_bytes().to_vec())
            .collect::<Vec<_>>();
        directed.sort();
        directed.dedup();
        let scanned = perform_scan(physical_scan_iface, &directed).unwrap_or_else(|error| {
            eprintln!("barely-cli: scan on {physical_scan_iface:?} failed: {error}");
            std::process::exit(1);
        });
        let candidates = scanned
            .iter()
            .map(scan_candidate)
            .collect::<Vec<ScanCandidate>>();
        let mut selected = uplink::select_uplink(networks, &candidates).unwrap_or_else(|error| {
            eprintln!("barely-cli: {error}");
            std::process::exit(1);
        });
        ssid = selected.network.ssid.clone();
        psk.zeroize();
        psk = std::mem::take(&mut selected.network.password);
        sae = selected.security == UplinkSecurity::Sae;
        psk_sha256 = selected.security == UplinkSecurity::PskSha256;
        owe = false;
        channel = selected.candidate.channel;
        configured_band6 = selected.candidate.band == "6";
        target_bssid = Some(selected.candidate.bssid);
        rescan_profile = Some(RescanProfile {
            ssid: selected.network.ssid.as_bytes().to_vec(),
            configured_bssid: selected.network.bssid,
            security: selected.security,
            scan_iface: physical_scan_iface.to_string(),
        });
        eprintln!(
            "barely-cli: selected ssid={:?} bssid={} band={} channel={} signal={:?} dBm",
            selected.network.ssid,
            barely_ap::util::bytes_to_mac(&selected.candidate.bssid),
            selected.candidate.band,
            selected.candidate.channel,
            selected.candidate.signal_dbm
        );
        #[cfg(target_os = "linux")]
        if mode == "iface" {
            barely_ap::netlink::set_interface_frequency(&iface, selected.candidate.frequency)
                .unwrap_or_else(|error| {
                    eprintln!(
                        "barely-cli: cannot tune monitor interface {iface:?} to {} MHz: {error}",
                        selected.candidate.frequency
                    );
                    std::process::exit(1);
                });
        }
    }

    let mac = match mac {
        Some(mac) => mac,
        None if mode == "iface" => interface_mac(&iface).unwrap_or_else(|error| {
            eprintln!(
                "barely-cli: {error}; pass an explicit --mac if the monitor identity differs"
            );
            std::process::exit(2);
        }),
        // stdio is a test/interop transport with no backing netdev.
        None => mac_to_bytes("02:00:00:00:ab:cd"),
    };

    if psk.is_empty() {
        if let Some(path) = configured_credential_file.as_deref() {
            let mut entries = parse_psk_file(path).unwrap_or_else(|e| {
                eprintln!("barely-cli: credential file {path:?}: {e}");
                std::process::exit(1);
            });
            let selected = entries
                .iter()
                .find(|(entry_mac, _)| *entry_mac == Some(mac))
                .or_else(|| entries.iter().find(|(entry_mac, _)| entry_mac.is_none()))
                .map(|(_, password)| password.clone());
            let Some(selected) = selected else {
                for (_, password) in &mut entries {
                    password.zeroize();
                }
                eprintln!(
                    "barely-cli: credential file {path:?} has no credential for {}",
                    barely_ap::util::bytes_to_mac(&mac)
                );
                std::process::exit(1);
            };
            psk = selected;
            for (_, password) in &mut entries {
                password.zeroize();
            }
        }
    }
    if psk.is_empty() && !owe {
        eprintln!("barely-cli: PSK/SAE requires a credential in --config");
        std::process::exit(1);
    }
    if psk_sha256 && mld_mac.is_some() {
        eprintln!(
            "barely-cli: PSK-SHA256 MLO is not enabled until its mandatory PMF/IGTK path is implemented"
        );
        std::process::exit(2);
    }
    if pairwise_cipher != barely_ap::structures::DataCipher::Ccmp128
        && (sae || owe || mld_mac.is_some())
    {
        eprintln!(
            "barely-cli: {} currently supports WPA2-Personal single-link mode only",
            pairwise_cipher.config_name()
        );
        std::process::exit(2);
    }

    eprintln!(
        "barely-cli: ssid={ssid:?} mac={} ping={ping} wmm_tid={wmm_tid:?} dscp={dscp} {} cipher={}",
        barely_ap::util::bytes_to_mac(&mac),
        if owe {
            "OWE"
        } else if sae {
            "WPA3-SAE"
        } else if psk_sha256 {
            "WPA2-PSK-SHA256"
        } else {
            "WPA2-PSK"
        },
        pairwise_cipher.config_name(),
    );

    let mut client = Client::new(&ssid, &psk, mac);
    client.set_pairwise_cipher(pairwise_cipher);
    psk.zeroize();
    if sae {
        client.enable_sae();
    }
    if psk_sha256 {
        client.enable_psk_sha256();
    }
    if hnp {
        client.use_hunting_pecking();
    }
    if owe {
        client.enable_owe();
    }
    if ocv {
        client.enable_ocv();
    }
    client.set_channel(channel);
    if let Some(bssid) = target_bssid {
        client.set_target_bssid(bssid);
    }
    client.set_wmm(wmm);
    client.set_wmm_tid(wmm_tid);
    if let (Some(m), Some(l1), Some(am)) = (mld_mac, link1_mac, ap_mld_mac) {
        client.enable_mld(m, l1, am);
        eprintln!(
            "MLD enabled: mld={} link1={} ap_mld={} pause_m3={pause_m3}",
            barely_ap::util::bytes_to_mac(&m),
            barely_ap::util::bytes_to_mac(&l1),
            barely_ap::util::bytes_to_mac(&am)
        );
    }
    if pause_m3 {
        client.set_pause_m3();
    }
    if let Some(tap) = tap_iface {
        if mode != "iface" {
            eprintln!("barely-cli: --tap requires --mode iface");
            std::process::exit(2);
        }
        run_iface_tap(
            client,
            &iface,
            channel,
            configured_band6,
            &tap,
            state_file.as_deref(),
            rescan_profile,
        );
        return;
    }

    let ping_cfg = if ping {
        Some((gw_mac, src_ip, gw_ip))
    } else {
        None
    };
    let mut node = ClientNode::new(client, Duration::from_millis(20), ping_cfg);
    node.ping_tos = dscp;
    match mode.as_str() {
        "stdio" => raw_frames::run(node, StdioLink::new()),
        "iface" => run_iface(node, &iface, channel, configured_band6),
        other => {
            eprintln!("unknown mode {other:?} (use stdio or iface)");
            std::process::exit(1);
        }
    }
}

#[derive(Clone, Debug)]
struct ObservedScan {
    ssid: Vec<u8>,
    bssid: [u8; 6],
    frequency: u32,
    channel: u8,
    band: &'static str,
    signal_dbm: Option<f32>,
    psk: bool,
    psk_sha256: bool,
    sae: bool,
    sae_h2e: bool,
    owe: bool,
    mld_addr: Option<[u8; 6]>,
    mlo_link_id: Option<u8>,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct RescanProfile {
    ssid: Vec<u8>,
    configured_bssid: Option<[u8; 6]>,
    security: UplinkSecurity,
    scan_iface: String,
}

#[cfg(target_os = "linux")]
fn perform_scan(iface: &str, directed_ssids: &[Vec<u8>]) -> std::io::Result<Vec<ObservedScan>> {
    barely_ap::netlink::scan_interface(iface, directed_ssids).map(|results| {
        results
            .into_iter()
            .map(|result| ObservedScan {
                ssid: result.ssid,
                bssid: result.bssid,
                frequency: result.frequency,
                channel: result.channel,
                band: result.band,
                signal_dbm: result.signal_dbm,
                psk: result.psk,
                psk_sha256: result.psk_sha256,
                sae: result.sae,
                sae_h2e: result.sae_h2e,
                owe: result.owe,
                mld_addr: result.mld_addr,
                mlo_link_id: result.mlo_link_id,
            })
            .collect()
    })
}

#[cfg(not(target_os = "linux"))]
fn perform_scan(_iface: &str, _directed_ssids: &[Vec<u8>]) -> std::io::Result<Vec<ObservedScan>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "nl80211 scanning is only supported on Linux",
    ))
}

fn scan_candidate(result: &ObservedScan) -> ScanCandidate {
    ScanCandidate {
        ssid: result.ssid.clone(),
        bssid: result.bssid,
        frequency: result.frequency,
        channel: result.channel,
        band: result.band,
        signal_dbm: result.signal_dbm,
        psk: result.psk,
        psk_sha256: result.psk_sha256,
        sae: result.sae,
        sae_h2e: result.sae_h2e,
    }
}

#[cfg(target_os = "linux")]
fn rescan_security_matches(profile: &RescanProfile, result: &ObservedScan) -> bool {
    match profile.security {
        UplinkSecurity::Psk => result.psk,
        UplinkSecurity::PskSha256 => result.psk_sha256,
        UplinkSecurity::Sae => result.sae && result.sae_h2e,
    }
}

fn print_scan_json(results: &[ObservedScan]) {
    let output = results
        .iter()
        .map(|result| {
            let mut security = Vec::new();
            if result.psk {
                security.push("WPA-PSK");
            }
            if result.psk_sha256 {
                security.push("WPA-PSK-SHA256");
            }
            if result.sae {
                security.push("SAE");
            }
            if result.owe {
                security.push("OWE");
            }
            serde_json::json!({
                "ssid": String::from_utf8_lossy(&result.ssid),
                "bssid": barely_ap::util::bytes_to_mac(&result.bssid),
                "frequency": result.frequency,
                "channel": result.channel,
                "band": result.band,
                "signal_dbm": result.signal_dbm,
                "key_mgmt": security,
                "sae_h2e": result.sae_h2e,
                "mld_addr": result.mld_addr.map(|mac| barely_ap::util::bytes_to_mac(&mac)),
                "mlo_link_id": result.mlo_link_id,
            })
        })
        .collect::<Vec<_>>();
    println!(
        "{}",
        serde_json::to_string(&output).expect("scan JSON serialization cannot fail")
    );
}

#[cfg(target_os = "linux")]
fn run_iface(node: ClientNode, iface: &str, channel: u8, band6: bool) {
    match raw_frames::IfaceLink::open_band(iface, channel, band6) {
        Ok(link) => raw_frames::run(node, link),
        Err(e) => {
            eprintln!("failed to open iface {iface}: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run_iface(_node: ClientNode, _iface: &str, _channel: u8, _band6: bool) {
    eprintln!("iface mode is only supported on Linux; use --mode stdio");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn run_iface_tap(
    client: Client,
    iface: &str,
    channel: u8,
    band6: bool,
    tap_iface: &str,
    state_file: Option<&str>,
    rescan_profile: Option<RescanProfile>,
) {
    let wifi = raw_frames::IfaceLink::open_band(iface, channel, band6).unwrap_or_else(|error| {
        eprintln!("failed to open wireless monitor interface {iface}: {error}");
        std::process::exit(1);
    });
    let tap = raw_frames::TapDevice::open(tap_iface, client.mac).unwrap_or_else(|error| {
        eprintln!("failed to open TAP interface {tap_iface}: {error}");
        std::process::exit(1);
    });
    let state_path = state_file.map(std::path::Path::new);
    let result = if let Some(profile) = rescan_profile {
        let monitor_iface = iface.to_string();
        raw_frames::run_client_tap_with_rescan(
            client,
            wifi,
            tap,
            state_path,
            move |client, wifi| {
                let directed = [profile.ssid.clone()];
                let scanned = perform_scan(&profile.scan_iface, &directed)?;
                let selected = scanned
                    .iter()
                    .filter(|result| {
                        let bssid_matches = profile
                            .configured_bssid
                            .is_none_or(|bssid| result.bssid == bssid);
                        let ssid_matches = result.ssid == profile.ssid
                            || (result.ssid.is_empty()
                                && profile.configured_bssid == Some(result.bssid));
                        bssid_matches && ssid_matches && rescan_security_matches(&profile, result)
                    })
                    .max_by(|a, b| {
                        a.signal_dbm
                            .partial_cmp(&b.signal_dbm)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "no compatible BSS found for selected SPR network",
                        )
                    })?;
                barely_ap::netlink::set_interface_frequency(&monitor_iface, selected.frequency)?;
                wifi.retune(selected.channel, selected.band == "6")?;
                client.set_channel(selected.channel);
                client.set_target_bssid(selected.bssid);
                eprintln!(
                    "RESCAN bssid={} band={} channel={} signal={:?} dBm",
                    barely_ap::util::bytes_to_mac(&selected.bssid),
                    selected.band,
                    selected.channel,
                    selected.signal_dbm
                );
                Ok(())
            },
        )
    } else {
        raw_frames::run_client_tap(client, wifi, tap, state_path)
    };
    if let Err(error) = result {
        eprintln!("client TAP loop failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn run_iface_tap(
    _client: Client,
    _iface: &str,
    _channel: u8,
    _band6: bool,
    _tap_iface: &str,
    _state_file: Option<&str>,
    _rescan_profile: Option<RescanProfile>,
) {
    eprintln!("TAP client mode is only supported on Linux");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_psk_sha256_selects_akm6_on_the_station() {
        assert_eq!(
            configured_security(Some(KeyMgmt::PskSha256)),
            (false, true, false)
        );
        assert_eq!(
            configured_security(Some(KeyMgmt::SaeTransition)),
            (true, false, false)
        );
    }
}
