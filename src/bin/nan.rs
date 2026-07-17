//! barely-nan: run the NAN USD discovery engine on a monitor interface.
//!
//! Usage:
//!   barely-nan --iface mon0 --channel 6 --mac 02:.. [--publish NAME] [--subscribe NAME] [--ssi TEXT]
//!
//! Broadcasts the matching publish/subscribe Service Discovery Frames and prints
//! `NAN_DISCOVERED` / `NAN_SUBSCRIBE_RX` / `NAN_FOLLOWUP_RX` lines on a match, so
//! it can be interop-tested against wpa_supplicant's NAN USD. Linux-only (it
//! injects/captures raw 802.11 frames over an `AF_PACKET` monitor interface).

#[cfg(target_os = "linux")]
fn main() {
    use std::time::{Duration, Instant};

    use barely_ap::nan::{NanDe, NanEvent};
    use barely_ap::raw_frames::{IfaceLink, Link};
    use barely_ap::util::{bytes_to_mac, mac_to_bytes, to_hex};

    let args: Vec<String> = std::env::args().collect();
    let mut iface = "mon0".to_string();
    let mut channel: u8 = 6;
    let mut mac = mac_to_bytes("02:00:00:00:0e:01");
    let mut publish: Option<String> = None;
    let mut subscribe: Option<String> = None;
    let mut ssi: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        let next = |i: usize| args.get(i + 1).cloned().unwrap_or_default();
        match args[i].as_str() {
            "--iface" => iface = next(i),
            "--channel" => channel = next(i).parse().unwrap_or(6),
            "--mac" => mac = mac_to_bytes(&next(i)),
            "--publish" => publish = Some(next(i)),
            "--subscribe" => subscribe = Some(next(i)),
            "--ssi" => ssi = Some(next(i)),
            _ => {}
        }
        i += 1;
    }

    let mut link = match IfaceLink::open(&iface, channel) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed to open {iface}: {e}");
            std::process::exit(1);
        }
    };

    let mut de = NanDe::new(mac);
    if let Some(ref name) = publish {
        let id = de.publish(name, ssi.as_deref().map(|s| s.as_bytes()));
        eprintln!(
            "barely-nan: publish {name:?} instance={id} mac={}",
            bytes_to_mac(&mac)
        );
    }
    if let Some(ref name) = subscribe {
        let id = de.subscribe(name);
        eprintln!(
            "barely-nan: subscribe {name:?} instance={id} mac={}",
            bytes_to_mac(&mac)
        );
    }

    let lossy = |info: &Option<Vec<u8>>| {
        info.as_deref()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default()
    };

    let mut last_tx = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .unwrap_or_else(Instant::now);
    loop {
        if last_tx.elapsed() >= Duration::from_millis(400) {
            for f in de.periodic_frames() {
                link.send(&f);
            }
            last_tx = Instant::now();
        }
        if let Some(frame) = link.try_recv(Duration::from_millis(100)) {
            let (events, responses) = de.process_frame(&frame);
            for e in &events {
                match e {
                    NanEvent::Discovered {
                        peer,
                        service_id,
                        peer_instance,
                        service_info,
                    } => {
                        println!(
                            "NAN_DISCOVERED peer={} sid={} inst={} ssi={}",
                            bytes_to_mac(peer),
                            to_hex(service_id),
                            peer_instance,
                            lossy(service_info)
                        );
                    }
                    NanEvent::SubscribeReceived { peer, service_id } => {
                        println!(
                            "NAN_SUBSCRIBE_RX peer={} sid={}",
                            bytes_to_mac(peer),
                            to_hex(service_id)
                        );
                    }
                    NanEvent::FollowupReceived { peer, service_info } => {
                        println!(
                            "NAN_FOLLOWUP_RX peer={} ssi={}",
                            bytes_to_mac(peer),
                            lossy(service_info)
                        );
                    }
                }
            }
            for r in responses {
                link.send(&r);
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("barely-nan requires Linux (AF_PACKET monitor mode)");
    std::process::exit(1);
}
