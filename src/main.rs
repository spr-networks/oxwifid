//! barely-ap: a minimal WPA2/CCMP 802.11 access point.
//!
//! Usage:
//!   barely-ap --config FILE.json [--ssid NAME] [--mac AA:BB:CC:DD:EE:FF]
//!             [--channel N] [--ip 10.10.10.1] [--mode stdio|iface]
//!             [--iface wlanN]
//!
//! `stdio` mode (default) reads/writes length-prefixed radiotap frames on
//! stdin/stdout and is wire-compatible with the Python reference, so it can be
//! bridged to a station with socat or a pipe. `iface` mode (Linux) talks to a
//! monitor-mode interface directly.

use std::time::Duration;

#[cfg(target_os = "linux")]
use barely_ap::ap::Ap;
use barely_ap::config::{parse_ip, Config, KeyMgmt};
use barely_ap::fakenet::FakeNet;
use barely_ap::raw_frames::{self, ApNode, StdioLink};
use barely_ap::util::mac_to_bytes;
use zeroize::Zeroize;

/// Build the configuration: start from defaults, load `--config FILE` (JSON) if
/// given, then apply any CLI flags as overrides (so flags win over the file).
fn parse_args() -> Config {
    let args: Vec<String> = std::env::args().collect();
    let next = |i: usize| args.get(i + 1).cloned().unwrap_or_default();

    let mut cfg = Config::default();
    // First pass: load the config file so CLI flags can override it.
    for i in 1..args.len() {
        if args[i] == "--config" {
            let path = next(i);
            let mut text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
                eprintln!("barely-ap: cannot read config {path:?}: {e}");
                std::process::exit(1);
            });
            cfg = match Config::from_json(&text) {
                Ok(cfg) => cfg,
                Err(e) => {
                    text.zeroize();
                    eprintln!("barely-ap: {path}: {e}");
                    std::process::exit(1);
                }
            };
            text.zeroize();
        }
    }

    // Second pass: CLI overrides.
    let mut i = 1;
    while i < args.len() {
        if !cfg.radios.is_empty()
            && matches!(
                args[i].as_str(),
                "--mac" | "--channel" | "--width" | "--phy" | "--band" | "--iface" | "--ctrl"
            )
        {
            eprintln!(
                "barely-ap: {} is radio-specific; set it in the appropriate radios[] entry",
                args[i]
            );
            std::process::exit(2);
        }
        match args[i].as_str() {
            "--config" => i += 1, // already handled
            "--ssid" => cfg.ssid = next(i),
            "--psk" => {
                eprintln!(
                    "barely-ap: --psk was removed because process arguments expose secrets; put passphrase or psk_file in --config"
                );
                std::process::exit(2);
            }
            "--mac" => cfg.mac = mac_to_bytes(&next(i)),
            "--channel" => cfg.channel = next(i).parse().unwrap_or(cfg.channel),
            "--width" => cfg.width = next(i).parse().unwrap_or(cfg.width),
            "--phy" => {
                cfg.phy = barely_ap::config::parse_phy(&next(i)).unwrap_or_else(|e| {
                    eprintln!("barely-ap: {e}");
                    std::process::exit(1);
                })
            }
            "--cipher" | "--pairwise-cipher" => {
                cfg.pairwise_cipher =
                    barely_ap::config::parse_data_cipher(&next(i)).unwrap_or_else(|e| {
                        eprintln!("barely-ap: {e}");
                        std::process::exit(1);
                    })
            }
            "--band" => {
                cfg.band = barely_ap::config::parse_band_str(&next(i)).unwrap_or_else(|e| {
                    eprintln!("barely-ap: {e}");
                    std::process::exit(1);
                })
            }
            "--ip" => cfg.ip = parse_ip(&next(i)).unwrap_or(cfg.ip),
            "--country" => {
                cfg.country = barely_ap::config::parse_country(&next(i)).unwrap_or_else(|e| {
                    eprintln!("barely-ap: {e}");
                    std::process::exit(1);
                })
            }
            "--mode" => cfg.mode = next(i),
            "--iface" => cfg.iface = next(i),
            "--ctrl" => cfg.ctrl_path = Some(next(i)),
            "--spr-api-socket" => cfg.spr_api_socket = Some(next(i)),
            "--spr-dhcp-helper" => cfg.spr_dhcp_helper = Some(next(i)),
            "--no-spr-dhcp-helper" => cfg.spr_dhcp_helper = None,
            "--sae" => cfg.key_mgmt = KeyMgmt::Sae,
            "--owe" => cfg.key_mgmt = KeyMgmt::Owe,
            "--transition" => cfg.key_mgmt = KeyMgmt::SaeTransition,
            "--ocv" => cfg.ocv = true,
            "--btm" => cfg.btm = true,
            "--rnr" => cfg.rnr = true,
            "--per-sta-vif" => cfg.per_sta_vif = true,
            "--guest" => cfg.guest = true,
            "-h" | "--help" => {
                eprintln!("barely-ap --config FILE.json [--ssid NAME] [--mac MAC]");
                eprintln!(
                    "          [--channel N] [--ip IP] [--mode stdio|iface|netlink] [--iface NAME]"
                );
                eprintln!(
                    "          [--band 2.4|5|6] [--cipher ccmp-128|gcmp-128|ccmp-256|gcmp-256]"
                );
                eprintln!(
                    "          [--sae|--owe|--transition] [--ocv] [--btm] [--rnr] [--per-sta-vif]"
                );
                eprintln!(
                    "          [--guest]       (client isolation: never bridge station-to-station)"
                );
                eprintln!("          [--ctrl PATH]   (netlink: reference AP-style control socket; multi-BSS via config `bss`)");
                eprintln!("          [--spr-api-socket PATH] (direct SPR HTTP over a Unix socket; no action-script exec)");
                eprintln!("          [--spr-dhcp-helper PATH] (invoke SPR DHCP/XDP helper for AP_VLAN clients)");
                eprintln!("          [--country CC]  (2-letter regulatory code for the Country IE; default US)");
                std::process::exit(0);
            }
            other => {
                if i == 1 && !other.starts_with('-') {
                    cfg.ssid = other.to_string(); // positional ssid
                }
            }
        }
        i += 1;
    }
    cfg
}

fn main() {
    let mut cfg = parse_args();
    if let Err(e) = cfg.validate() {
        cfg.passphrase.zeroize();
        for bss in &mut cfg.bss {
            bss.passphrase.zeroize();
        }
        eprintln!("barely-ap: invalid configuration: {e}");
        std::process::exit(1);
    }

    if !cfg.radios.is_empty() {
        let definitions = std::mem::take(&mut cfg.radios);
        let radios: Vec<Config> = definitions
            .iter()
            .map(|radio| cfg.for_radio(radio))
            .collect();
        cfg.passphrase.zeroize();
        for bss in &mut cfg.bss {
            bss.passphrase.zeroize();
        }
        run_netlink_radios(radios);
        return;
    }

    log_startup(&cfg);
    if cfg.mode == "netlink" {
        if let Err(e) = run_netlink_config(cfg) {
            eprintln!("{e}");
            std::process::exit(1);
        }
        return;
    }

    let ap = cfg.build_ap();
    let net = FakeNet::new(cfg.mac, cfg.ip);
    let beacon_interval = Duration::from_millis(50);
    cfg.passphrase.zeroize();
    match cfg.mode.as_str() {
        "stdio" => {
            raw_frames::run(
                ApNode {
                    ap,
                    net,
                    beacon_interval,
                },
                StdioLink::new(),
            );
        }
        "iface" => run_iface(
            ApNode {
                ap,
                net,
                beacon_interval,
            },
            &cfg.iface,
            cfg.channel,
            cfg.band.is_6ghz(),
        ),
        other => {
            eprintln!("unknown mode {other:?} (use stdio, iface, or netlink)");
            std::process::exit(1);
        }
    }
}

fn log_startup(cfg: &Config) {
    // EHT (--phy be) mandates PMF, so a non-MFPR mode is upgraded to WPA3-SAE
    // (see Config::effective_key_mgmt); report what the AP will actually advertise.
    let security = match cfg.effective_key_mgmt() {
        KeyMgmt::Psk => "WPA2-PSK",
        KeyMgmt::Sae => "WPA3-SAE",
        KeyMgmt::SaeTransition => "WPA3-SAE/WPA2 transition",
        KeyMgmt::Owe => "OWE",
    };
    // Note: no `ip=` here. The fakenet gateway address (`cfg.ip`) only applies
    // to the stdio/iface fakenet backend; in netlink mode the kernel data plane
    // plus SPR's DHCP own addressing, so printing it there was misleading.
    eprintln!(
        "barely-ap: ssid={:?} channel={} mac={} mode={} {} cipher={}",
        cfg.ssid,
        cfg.channel,
        barely_ap::util::bytes_to_mac(&cfg.mac),
        cfg.mode,
        security,
        cfg.pairwise_cipher.config_name(),
    );
}

#[cfg(target_os = "linux")]
fn run_iface(node: ApNode, iface: &str, channel: u8, band6: bool) {
    match raw_frames::IfaceLink::open_band(iface, channel, band6) {
        Ok(link) => raw_frames::run(node, link),
        Err(e) => {
            eprintln!("failed to open iface {iface}: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run_iface(_node: ApNode, _iface: &str, _channel: u8, _band6: bool) {
    eprintln!("iface mode is only supported on Linux; use --mode stdio");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn run_netlink_config(mut cfg: Config) -> Result<(), String> {
    let ap = cfg.build_ap();
    let extra: Vec<Ap> = cfg.bss.iter().map(|bss| cfg.build_bss_ap(bss)).collect();
    if !extra.is_empty() {
        eprintln!(
            "barely-ap: {} + {} additional BSS(es)",
            cfg.iface,
            extra.len()
        );
    }
    cfg.passphrase.zeroize();
    for bss in &mut cfg.bss {
        bss.passphrase.zeroize();
    }
    barely_ap::netlink::run_offload_aps(
        ap,
        extra,
        &cfg.iface,
        cfg.channel,
        cfg.ctrl_path.as_deref(),
        cfg.psk_file.as_deref(),
        cfg.spr_api_socket.as_deref(),
        cfg.spr_dhcp_helper.as_deref(),
    )
    .map_err(|e| format!("netlink AP failed on {}: {e}", cfg.iface))
}

#[cfg(not(target_os = "linux"))]
fn run_netlink_config(_cfg: Config) -> Result<(), String> {
    Err("netlink mode is only supported on Linux; use --mode stdio".to_string())
}

fn run_netlink_radios(radios: Vec<Config>) {
    let radio_count = radios.len();
    eprintln!("barely-ap: starting {radio_count} independent DBDC/multi-radio APs");
    let (tx, rx) = std::sync::mpsc::channel();
    for radio in radios {
        let iface = radio.iface.clone();
        let tx = tx.clone();
        let spawn = std::thread::Builder::new()
            .name(format!("barely-ap-{iface}"))
            .spawn(move || {
                log_startup(&radio);
                let result = run_netlink_config(radio);
                let _ = tx.send((iface, result));
            });
        if let Err(e) = spawn {
            eprintln!("barely-ap: cannot start radio thread: {e}");
            std::process::exit(1);
        }
    }
    drop(tx);

    match rx.recv() {
        Ok((iface, Err(e))) => {
            eprintln!("barely-ap: radio {iface} exited: {e}");
            std::process::exit(1);
        }
        Ok((iface, Ok(()))) => {
            eprintln!("barely-ap: radio {iface} exited unexpectedly");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("barely-ap: all radio threads exited: {e}");
            std::process::exit(1);
        }
    }
}
