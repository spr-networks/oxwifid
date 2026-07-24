#![no_main]

use barely_ap::{ap::Ap, client::Client, dot11, uplink};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let ap_mac = [0x02, 0, 0, 0, 0, 1];
    let sta_mac = [0x02, 0, 0, 0, 0, 2];
    let mut ap = Ap::new_without_credential("fuzz", ap_mac, 1);
    ap.enable_sae();
    ap.set_psk_file(&[]);
    ap.enable_per_sta_vif();
    let mut client = Client::new("fuzz", "fuzz-password", sta_mac);
    match data.first().copied().unwrap_or_default() % 3 {
        1 => client.enable_sae(),
        2 => client.enable_owe(),
        _ => {}
    }

    // Exercise the standalone parsers on the complete input as well as the AP
    // state machine on a sequence of length-delimited, attacker-controlled
    // operations. The target intentionally starts without credentials so fuzz
    // throughput is not dominated by PBKDF2.
    let _ = dot11::EapolKey::parse(data);
    if let Ok(json) = std::str::from_utf8(data) {
        let _ = uplink::parse_spr_uplink(json, "wlan0");
    }
    if let Some(frame) = dot11::Dot11::parse(data) {
        let _ = frame.eapol_frame();
        let _ = frame.eapol_key_body().and_then(dot11::EapolKey::parse);
        let _ = dot11::parse_auth(&frame.body);
        let _ = dot11::parse_mld_mac(&frame.body);
    }

    let mut offset = 0usize;
    while offset + 3 <= data.len() {
        let opcode = data[offset];
        let requested = u16::from_le_bytes([data[offset + 1], data[offset + 2]]) as usize;
        offset += 3;
        let length = requested.min(data.len() - offset);
        let chunk = &data[offset..offset + length];
        offset += length;

        match opcode % 6 {
            0 => {
                let _ = ap.handle_incoming(chunk);
                let _ = client.handle_incoming(chunk);
            }
            1 => {
                let mut radiotap = dot11::RADIOTAP_TX.to_vec();
                radiotap.extend_from_slice(chunk);
                let _ = ap.handle_incoming(&radiotap);
                let _ = client.handle_incoming(&radiotap);
            }
            2 => {
                let _ = ap.deliver_to_station(chunk);
                let _ = client.encrypt_uplink(chunk);
            }
            3 => {
                let _ = dot11::EapolKey::parse(chunk);
            }
            4 => {
                if let Some(frame) = dot11::Dot11::parse(chunk) {
                    let _ = frame.ccmp_pn();
                    let _ = frame.ccmp_key_id();
                    let _ = frame.eapol_key_body().and_then(dot11::EapolKey::parse);
                }
            }
            _ => {
                let _ = ap.tick();
                let _ = ap.prune_idle(std::time::Duration::ZERO);
                let _ = client.maintenance(
                    std::time::Instant::now() + std::time::Duration::from_secs(60),
                );
            }
        }
    }
});
