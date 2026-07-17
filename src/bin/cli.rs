//! barely-cli: a minimal WPA2/CCMP station to drive an AP over stdio.
//!
//! Connects to the first matching beacon, completes the 4-way handshake, and
//! (with --ping) sends one ICMP echo to the gateway, printing AUTHENTICATED and
//! PING_REPLY_OK to stderr on success.
//!
//! Usage:
//!   barely-cli [--ssid NAME] [--psk PASS] [--mac MAC] [--ping]
//!              [--gw-mac MAC] [--src-ip IP] [--gw-ip IP]

use std::time::Duration;

use barely_ap::client::Client;
use barely_ap::raw_frames::{self, ClientNode, StdioLink};
use barely_ap::util::mac_to_bytes;

fn parse_ip(s: &str) -> [u8; 4] {
    let mut out = [0u8; 4];
    for (i, part) in s.split('.').enumerate() {
        if i < 4 {
            out[i] = part.parse().unwrap_or(0);
        }
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut ssid = "turtlenet".to_string();
    let mut psk = "password1234".to_string();
    let mut mac = mac_to_bytes("02:00:00:00:ab:cd");
    let mut ping = false;
    let mut sae = false;
    let mut hnp = false;
    let mut owe = false;
    let mut ocv = false;
    let mut wmm = true;
    let mut wmm_tid: Option<u8> = None; // test override for the WMM user priority
    let mut dscp: u8 = 0; // DSCP stamped on the test ping (drives WMM classification)
    let mut gw_mac = mac_to_bytes("02:00:00:00:00:00");
    let mut src_ip = [10, 10, 10, 2];
    let mut gw_ip = [10, 10, 10, 1];
    let mut mode = "stdio".to_string();
    let mut iface = "wlan0".to_string();
    let mut channel: u8 = 1;
    let mut mld_mac: Option<[u8; 6]> = None;
    let mut link1_mac: Option<[u8; 6]> = None;
    let mut ap_mld_mac: Option<[u8; 6]> = None;
    let mut pause_m3 = false;

    let mut i = 1;
    while i < args.len() {
        let next = |i: usize| args.get(i + 1).cloned().unwrap_or_default();
        match args[i].as_str() {
            "--ssid" => ssid = next(i),
            "--psk" => psk = next(i),
            "--mac" => mac = mac_to_bytes(&next(i)),
            "--gw-mac" => gw_mac = mac_to_bytes(&next(i)),
            "--src-ip" => src_ip = parse_ip(&next(i)),
            "--gw-ip" => gw_ip = parse_ip(&next(i)),
            "--ping" => ping = true,
            "--sae" => sae = true,
            "--sae-hnp" => {
                sae = true;
                hnp = true;
            }
            "--owe" => owe = true,
            "--ocv" => ocv = true,
            "--no-wmm" => wmm = false,
            "--tid" | "--up" => wmm_tid = next(i).parse().ok().map(|t: u8| t & 0x07),
            "--dscp" => dscp = next(i).parse::<u8>().map(|d| d << 2).unwrap_or(0),
            "--mode" => mode = next(i),
            "--iface" => iface = next(i),
            "--channel" => channel = next(i).parse().unwrap_or(1),
            "--mld-mac" => mld_mac = Some(mac_to_bytes(&next(i))),
            "--link1-mac" => link1_mac = Some(mac_to_bytes(&next(i))),
            "--ap-mld-mac" => ap_mld_mac = Some(mac_to_bytes(&next(i))),
            "--pause-m3" => pause_m3 = true,
            _ => {}
        }
        i += 1;
    }

    eprintln!(
        "barely-cli: ssid={ssid:?} mac={} ping={ping} wmm_tid={wmm_tid:?} dscp={dscp} {}",
        barely_ap::util::bytes_to_mac(&mac),
        if sae { "WPA3-SAE" } else { "WPA2-PSK" },
    );

    let mut client = Client::new(&ssid, &psk, mac);
    if sae {
        client.enable_sae();
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
    let ping_cfg = if ping {
        Some((gw_mac, src_ip, gw_ip))
    } else {
        None
    };
    let mut node = ClientNode::new(client, Duration::from_millis(20), ping_cfg);
    node.ping_tos = dscp;
    match mode.as_str() {
        "stdio" => raw_frames::run(node, StdioLink::new()),
        "iface" => run_iface(node, &iface, channel),
        other => {
            eprintln!("unknown mode {other:?} (use stdio or iface)");
            std::process::exit(1);
        }
    }
}

#[cfg(target_os = "linux")]
fn run_iface(node: ClientNode, iface: &str, channel: u8) {
    match raw_frames::IfaceLink::open(iface, channel) {
        Ok(link) => raw_frames::run(node, link),
        Err(e) => {
            eprintln!("failed to open iface {iface}: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run_iface(_node: ClientNode, _iface: &str, _channel: u8) {
    eprintln!("iface mode is only supported on Linux; use --mode stdio");
    std::process::exit(1);
}
