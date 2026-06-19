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
use barely_ap::fakenet::FakeNet;
use barely_ap::raw_frames::{self, ApNode, StdioLink};
use barely_ap::util::mac_to_bytes;

struct Config {
    ssid: String,
    psk: String,
    mac: [u8; 6],
    channel: u8,
    ip: [u8; 4],
    mode: String,
    iface: String,
    sae: bool,
}

fn parse_ip(s: &str) -> [u8; 4] {
    let mut out = [0u8; 4];
    for (i, part) in s.split('.').enumerate() {
        if i < 4 {
            out[i] = part.parse().unwrap_or(0);
        }
    }
    out
}

fn parse_args() -> Config {
    let mut cfg = Config {
        ssid: "turtlenet".to_string(),
        psk: "password1234".to_string(),
        mac: mac_to_bytes("02:00:00:00:00:00"),
        channel: 1,
        ip: [10, 10, 10, 1],
        mode: "stdio".to_string(),
        iface: "wlan0".to_string(),
        sae: false,
    };
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        let next = |i: usize| args.get(i + 1).cloned().unwrap_or_default();
        match args[i].as_str() {
            "--ssid" => cfg.ssid = next(i),
            "--psk" => cfg.psk = next(i),
            "--mac" => cfg.mac = mac_to_bytes(&next(i)),
            "--channel" => cfg.channel = next(i).parse().unwrap_or(1),
            "--ip" => cfg.ip = parse_ip(&next(i)),
            "--mode" => cfg.mode = next(i),
            "--iface" => cfg.iface = next(i),
            "--sae" => cfg.sae = true,
            "-h" | "--help" => {
                eprintln!("barely-ap [--ssid NAME] [--psk PASS] [--mac MAC] [--channel N] [--ip IP] [--mode stdio|iface] [--iface NAME]");
                std::process::exit(0);
            }
            other => {
                if i == 1 && !other.starts_with('-') {
                    // positional ssid
                    cfg.ssid = other.to_string();
                }
            }
        }
        i += 1;
    }
    cfg
}

fn main() {
    let cfg = parse_args();
    let mut ap = Ap::new(&cfg.ssid, &cfg.psk, cfg.mac, cfg.channel);
    if cfg.sae {
        ap.enable_sae();
    }
    let net = FakeNet::new(cfg.mac, cfg.ip);
    let beacon_interval = Duration::from_millis(50);

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
        if cfg.sae { "WPA3-SAE" } else { "WPA2-PSK" },
    );

    let node = ApNode {
        ap,
        net,
        beacon_interval,
    };

    let channel = cfg.channel;
    match cfg.mode.as_str() {
        "stdio" => {
            raw_frames::run(node, StdioLink::new());
        }
        "iface" => run_iface(node, &cfg.iface, channel),
        "netlink" => run_netlink(node, &cfg.iface, channel),
        other => {
            eprintln!("unknown mode {other:?} (use stdio, iface, or netlink)");
            std::process::exit(1);
        }
    }
}

#[cfg(target_os = "linux")]
fn run_iface(node: ApNode, iface: &str, channel: u8) {
    match raw_frames::IfaceLink::open(iface, channel) {
        Ok(link) => raw_frames::run(node, link),
        Err(e) => {
            eprintln!("failed to open iface {iface}: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run_iface(_node: ApNode, _iface: &str, _channel: u8) {
    eprintln!("iface mode is only supported on Linux; use --mode stdio");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn run_netlink(node: ApNode, iface: &str, channel: u8) {
    match barely_ap::netlink::NetlinkLink::open(iface, channel) {
        Ok(link) => raw_frames::run(node, link),
        Err(e) => {
            eprintln!("failed to open nl80211 on {iface}: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run_netlink(_node: ApNode, _iface: &str, _channel: u8) {
    eprintln!("netlink mode is only supported on Linux; use --mode stdio");
    std::process::exit(1);
}
