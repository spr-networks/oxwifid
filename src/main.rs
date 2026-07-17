//! barely-ap: a minimal WPA2/CCMP 802.11 access point.
//!
//! Usage:
//!   barely-ap [--ssid NAME] [--psk PASS] [--mac AA:BB:CC:DD:EE:FF]
//!             [--channel N] [--ip 10.10.10.1] [--mode stdio|iface]
//!             [--iface wlanN]
//!
//! `stdio` mode (default) reads/writes length-prefixed radiotap frames on
//! stdin/stdout and is wire-compatible with the Python reference, so it can be
//! bridged to a station with socat or a pipe. `iface` mode (Linux) talks to a
//! monitor-mode interface directly.

use std::time::Duration;

use barely_ap::ap::Ap;
use barely_ap::config::{parse_ip, Config, KeyMgmt};
use barely_ap::fakenet::FakeNet;
use barely_ap::raw_frames::{self, ApNode, StdioLink};
use barely_ap::util::mac_to_bytes;

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
            let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
                eprintln!("barely-ap: cannot read config {path:?}: {e}");
                std::process::exit(1);
            });
            cfg = Config::from_json(&text).unwrap_or_else(|e| {
                eprintln!("barely-ap: {path}: {e}");
                std::process::exit(1);
            });
        }
    }

    // Second pass: CLI overrides.
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => i += 1, // already handled
            "--ssid" => cfg.ssid = next(i),
            "--psk" => cfg.passphrase = next(i),
            "--mac" => cfg.mac = mac_to_bytes(&next(i)),
            "--channel" => cfg.channel = next(i).parse().unwrap_or(cfg.channel),
            "--width" => cfg.width = next(i).parse().unwrap_or(cfg.width),
            "--phy" => {
                cfg.phy = barely_ap::config::parse_phy(&next(i)).unwrap_or_else(|e| {
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
            "-h" | "--help" => {
                eprintln!("barely-ap [--config FILE.json] [--ssid NAME] [--psk PASS] [--mac MAC]");
                eprintln!(
                    "          [--channel N] [--ip IP] [--mode stdio|iface|netlink] [--iface NAME]"
                );
                eprintln!("          [--band 2.4|5|6] [--sae|--owe|--transition] [--ocv] [--btm] [--rnr] [--per-sta-vif]");
                eprintln!("          [--ctrl PATH]   (netlink: hostapd-style control socket; multi-BSS via config `bss`)");
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
    let cfg = parse_args();
    if let Err(e) = cfg.validate() {
        eprintln!("barely-ap: invalid configuration: {e}");
        std::process::exit(1);
    }
    let ap = cfg.build_ap();
    let net = FakeNet::new(cfg.mac, cfg.ip);
    let beacon_interval = Duration::from_millis(50);

    // EHT (--phy be) mandates PMF, so a non-MFPR mode is upgraded to WPA3-SAE
    // (see Config::effective_key_mgmt); report what the AP will actually advertise.
    let security = match cfg.effective_key_mgmt() {
        KeyMgmt::Psk => "WPA2-PSK",
        KeyMgmt::Sae => "WPA3-SAE",
        KeyMgmt::SaeTransition => "WPA3-SAE/WPA2 transition",
        KeyMgmt::Owe => "OWE",
    };
    eprintln!(
        "barely-ap: ssid={:?} channel={} mac={} ip={}.{}.{}.{} mode={} {}",
        cfg.ssid,
        cfg.channel,
        barely_ap::util::bytes_to_mac(&cfg.mac),
        cfg.ip[0],
        cfg.ip[1],
        cfg.ip[2],
        cfg.ip[3],
        cfg.mode,
        security,
    );

    let channel = cfg.channel;
    // The nl80211/"netlink" mode offloads beaconing + data-plane CCMP to the
    // kernel, so it drives the bare `Ap` (no userspace frame/event loop).
    if cfg.mode == "netlink" {
        let extra: Vec<Ap> = cfg.bss.iter().map(|b| cfg.build_bss_ap(b)).collect();
        if !extra.is_empty() {
            eprintln!(
                "barely-ap: + {} additional BSS(es) on this radio",
                extra.len()
            );
        }
        run_netlink(
            ap,
            extra,
            &cfg.iface,
            channel,
            cfg.ctrl_path.as_deref(),
            cfg.psk_file.as_deref(),
            cfg.spr_api_socket.as_deref(),
            cfg.spr_dhcp_helper.as_deref(),
        );
        return;
    }

    let node = ApNode {
        ap,
        net,
        beacon_interval,
    };
    match cfg.mode.as_str() {
        "stdio" => {
            raw_frames::run(node, StdioLink::new());
        }
        "iface" => run_iface(node, &cfg.iface, channel, cfg.band.is_6ghz()),
        other => {
            eprintln!("unknown mode {other:?} (use stdio, iface, or netlink)");
            std::process::exit(1);
        }
    }
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
fn run_netlink(
    ap: Ap,
    extra: Vec<Ap>,
    iface: &str,
    channel: u8,
    ctrl_path: Option<&str>,
    psk_file: Option<&str>,
    spr_api_socket: Option<&str>,
    spr_dhcp_helper: Option<&str>,
) {
    if let Err(e) = barely_ap::netlink::run_offload_aps(
        ap,
        extra,
        iface,
        channel,
        ctrl_path,
        psk_file,
        spr_api_socket,
        spr_dhcp_helper,
    ) {
        eprintln!("netlink AP failed on {iface}: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn run_netlink(
    _ap: Ap,
    _extra: Vec<Ap>,
    _iface: &str,
    _channel: u8,
    _ctrl_path: Option<&str>,
    _psk_file: Option<&str>,
    _spr_api_socket: Option<&str>,
    _spr_dhcp_helper: Option<&str>,
) {
    eprintln!("netlink mode is only supported on Linux; use --mode stdio");
    std::process::exit(1);
}
