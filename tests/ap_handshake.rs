//! Drive the Rust AP state machine through a full WPA2 handshake using the
//! golden client frames, and assert its responses match `ap.py` exactly.

use barely_ap::ap::Ap;
use barely_ap::dot11;
use barely_ap::util::{from_hex, mac_to_bytes, to_hex};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors.json")).expect("vectors.json parses")
}

fn fixtured_ap() -> Ap {
    let v = vectors();
    let mut ap = Ap::new("turtlenet", "password1234", mac_to_bytes("02:00:00:00:00:00"), 1);
    let gtk: [u8; 16] = from_hex(v["frames"]["eapol_m3"]["gtk"].as_str().unwrap()).try_into().unwrap();
    let anonce: [u8; 32] = from_hex(v["crypto"]["anonce"].as_str().unwrap()).try_into().unwrap();
    ap.set_test_fixtures(gtk, anonce);
    ap
}

/// Send the STA's EAPOL message 4 (built with the golden KCK) so the AP can
/// verify it and complete the handshake — the AP only authorizes after m4.
fn send_m4(ap: &mut Ap, v: &Value) {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let sta = mac_to_bytes("02:00:00:00:ab:cd");
    let kck: [u8; 16] = from_hex(v["crypto"]["kck"].as_str().unwrap()).try_into().unwrap();
    let m4 = dot11::build_eapol_m4(&ap_mac, &sta, &kck, 0, dot11::KeyMic::select(false, false));
    let mut framed = dot11::RADIOTAP_TX.to_vec();
    framed.extend_from_slice(&m4);
    ap.handle_incoming(&framed);
}

#[test]
fn full_handshake_matches_reference() {
    let v = vectors();
    let sta = mac_to_bytes("02:00:00:00:ab:cd");
    let mut ap = fixtured_ap();

    // 1. Association request -> association response + EAPOL message 1
    let assoc_req = from_hex(v["incoming"]["assoc_req"]["bytes"].as_str().unwrap());
    let out = ap.handle_incoming(&assoc_req);
    assert_eq!(out.frames.len(), 2, "assoc must yield assoc-resp + m1");
    // The AP appends a BSS Max Idle Period element, so the reference assoc-resp
    // is now a prefix of what the AP emits.
    assert!(
        to_hex(&out.frames[0]).starts_with(v["frames"]["assoc_resp"]["bytes"].as_str().unwrap()),
        "assoc response must match the reference (plus the BSS Max Idle element)"
    );
    assert_eq!(to_hex(&out.frames[1]), v["frames"]["eapol_m1"]["bytes"].as_str().unwrap());

    // 2. EAPOL message 2 (valid) -> EAPOL message 3, station associated
    let m2 = from_hex(v["frames"]["eapol_m2_incoming"]["bytes"].as_str().unwrap());
    let out = ap.handle_incoming(&m2);
    assert_eq!(out.frames.len(), 1, "valid m2 must yield exactly m3");
    assert_eq!(to_hex(&out.frames[0]), v["frames"]["eapol_m3"]["bytes"].as_str().unwrap());
    assert!(!ap.is_associated(&sta), "station awaits m4, not yet associated after m3");

    // 2b. EAPOL message 4 -> station fully associated (authorized only now).
    send_m4(&mut ap, &v);
    assert!(ap.is_associated(&sta), "station must be associated after verified m4");

    // 3. Encrypted uplink data decrypts to the expected Ethernet frame
    let uplink = from_hex(v["frames"]["data_uplink"]["bytes"].as_str().unwrap());
    let out = ap.handle_incoming(&uplink);
    assert_eq!(out.to_network.len(), 1, "uplink must decrypt to one ethernet frame");
    assert_eq!(to_hex(&out.to_network[0]), v["frames"]["data_uplink"]["decrypted_eth"].as_str().unwrap());
    assert!(out.frames.is_empty());
}

#[test]
fn connect_then_disconnect_events() {
    use barely_ap::ap::ApEvent;
    let v = vectors();
    let sta = mac_to_bytes("02:00:00:00:ab:cd");
    let mut ap = fixtured_ap();

    // Drive the handshake up to (but not including) m4.
    let assoc_req = from_hex(v["incoming"]["assoc_req"]["bytes"].as_str().unwrap());
    ap.handle_incoming(&assoc_req);
    let m2 = from_hex(v["frames"]["eapol_m2_incoming"]["bytes"].as_str().unwrap());
    ap.handle_incoming(&m2);
    assert!(ap.drain_events().is_empty(), "no connect event before m4 verifies");

    // m4 authorizes the station -> AP-STA-CONNECTED.
    send_m4(&mut ap, &v);
    assert_eq!(ap.drain_events(), vec![ApEvent::Connected { mac: sta }]);
    assert!(ap.drain_events().is_empty(), "drain clears the queue");

    // Reaping the now-idle station -> AP-STA-DISCONNECTED (pairs with connect).
    std::thread::sleep(std::time::Duration::from_millis(2));
    ap.prune_idle(std::time::Duration::from_millis(1));
    assert_eq!(ap.drain_events(), vec![ApEvent::Disconnected { mac: sta, reason: 4 }]);
}

#[test]
fn wrong_psk_emits_authfail_event() {
    use barely_ap::ap::ApEvent;
    use barely_ap::failures::FailureKind;
    let v = vectors();
    let sta = mac_to_bytes("02:00:00:00:ab:cd");
    let mut ap = fixtured_ap();
    let assoc_req = from_hex(v["incoming"]["assoc_req"]["bytes"].as_str().unwrap());
    ap.handle_incoming(&assoc_req);
    // A corrupted m2 fails the MIC check (the wrong-PSK signal) -> AP-STA-AUTH-FAILED.
    let mut m2 = from_hex(v["frames"]["eapol_m2_incoming"]["bytes"].as_str().unwrap());
    *m2.last_mut().unwrap() ^= 0xff; // perturb key data; MIC no longer verifies
    ap.handle_incoming(&m2);
    let ev = ap.drain_events();
    assert_eq!(ev.len(), 1, "exactly one AuthFailed event");
    assert!(
        matches!(&ev[0], ApEvent::AuthFailed { mac, kind: FailureKind::FourWayMic, count } if *mac == sta && *count >= 1),
        "got {:?}", ev[0]
    );
}

#[test]
fn auth_request_is_answered() {
    let v = vectors();
    let mut ap = fixtured_ap();
    let auth_req = from_hex(v["incoming"]["auth_req"]["bytes"].as_str().unwrap());
    let out = ap.handle_incoming(&auth_req);
    assert_eq!(out.frames.len(), 1);
    let frame = dot11::Dot11::parse(dot11::strip_radiotap(&out.frames[0]).unwrap()).unwrap();
    assert_eq!(frame.subtype(), dot11::SUBTYPE_AUTH);
    assert_eq!(frame.addr1, mac_to_bytes("02:00:00:00:ab:cd"));
    assert_eq!(frame.addr2, mac_to_bytes("02:00:00:00:00:00"));
}

#[test]
fn probe_request_for_our_ssid_is_answered() {
    let v = vectors();
    let mut ap = fixtured_ap();
    let probe = from_hex(v["incoming"]["probe_req_named"]["bytes"].as_str().unwrap());
    let out = ap.handle_incoming(&probe);
    assert_eq!(out.frames.len(), 1);
    let frame = dot11::Dot11::parse(dot11::strip_radiotap(&out.frames[0]).unwrap()).unwrap();
    assert_eq!(frame.subtype(), dot11::SUBTYPE_PROBE_RESP);

    // An empty-SSID probe still gets our primary SSID
    let probe_empty = from_hex(v["incoming"]["probe_req_empty"]["bytes"].as_str().unwrap());
    let out = ap.handle_incoming(&probe_empty);
    assert_eq!(out.frames.len(), 1);
}

#[test]
fn bad_mic_in_message_2_triggers_deauth() {
    let v = vectors();
    let sta = mac_to_bytes("02:00:00:00:ab:cd");
    let mut ap = fixtured_ap();

    // get the station into the eapol-ready state
    let assoc_req = from_hex(v["incoming"]["assoc_req"]["bytes"].as_str().unwrap());
    ap.handle_incoming(&assoc_req);

    // corrupt the MIC of message 2
    let mut m2 = from_hex(v["frames"]["eapol_m2_incoming"]["bytes"].as_str().unwrap());
    let len = m2.len();
    m2[len - 25] ^= 0xff; // somewhere inside the key MIC region
    let out = ap.handle_incoming(&m2);

    assert_eq!(out.frames.len(), 1, "bad MIC must produce a deauth");
    let frame = dot11::Dot11::parse(dot11::strip_radiotap(&out.frames[0]).unwrap()).unwrap();
    assert_eq!(frame.frame_type(), dot11::TYPE_MGMT);
    assert!(!ap.is_associated(&sta), "station must be dropped after bad MIC");
    // the wrong-PSK attempt is recorded in the fingerprinted failure log
    let recs = ap.failures().records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].kind, barely_ap::failures::FailureKind::FourWayMic);
    assert_eq!(recs[0].count, 1);
}

#[test]
fn downlink_roundtrips_through_a_station() {
    let v = vectors();
    let sta = mac_to_bytes("02:00:00:00:ab:cd");
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let mut ap = fixtured_ap();

    // complete the handshake (m2 then m4)
    ap.handle_incoming(&from_hex(v["incoming"]["assoc_req"]["bytes"].as_str().unwrap()));
    ap.handle_incoming(&from_hex(v["frames"]["eapol_m2_incoming"]["bytes"].as_str().unwrap()));
    send_m4(&mut ap, &v);
    assert!(ap.is_associated(&sta));

    // an Ethernet frame from the AP's stack toward the station
    let tk: [u8; 16] = from_hex(v["crypto"]["tk"].as_str().unwrap()).try_into().unwrap();
    let mut eth = Vec::new();
    eth.extend_from_slice(&sta); // dst
    eth.extend_from_slice(&ap_mac); // src
    eth.extend_from_slice(&[0x08, 0x00]); // ethertype IPv4
    eth.extend_from_slice(b"hello station this is the access point");

    let frames = ap.deliver_to_station(&eth);
    assert_eq!(frames.len(), 1);

    // decrypt it back and confirm we recover the original Ethernet frame
    let f = dot11::Dot11::parse(dot11::strip_radiotap(&frames[0]).unwrap()).unwrap();
    assert!(f.from_ds() && f.protected());
    let recovered = dot11::decrypt_ccmp(&f, &tk, true).expect("downlink decrypts");
    assert_eq!(recovered, eth);
}

#[test]
fn eapol_m1_retransmits_then_times_out() {
    let v = vectors();
    let sta = mac_to_bytes("02:00:00:00:ab:cd");
    let mut ap = fixtured_ap();
    // association -> assoc-resp + m1 (cached for retransmit)
    ap.handle_incoming(&from_hex(v["incoming"]["assoc_req"]["bytes"].as_str().unwrap()));
    // a tick before the timeout does nothing
    assert!(ap.tick().frames.is_empty(), "no retransmit before timeout");
    // after the timeout, m1 is retransmitted up to MAX_EAPOL_RETRIES (4) times...
    let mut retransmits = 0;
    for _ in 0..4 {
        ap.test_expire_eapol();
        if !ap.tick().frames.is_empty() {
            retransmits += 1;
        }
    }
    assert_eq!(retransmits, 4, "m1 retransmitted 4 times");
    assert!(!ap.is_associated(&sta), "still not associated (no m2)");
    // ...then the 4-way times out: the station is deauthed and dropped.
    ap.test_expire_eapol();
    let out = ap.tick();
    assert_eq!(out.frames.len(), 1, "final tick deauths the stalled station");
    let f = dot11::Dot11::parse(dot11::strip_radiotap(&out.frames[0]).unwrap()).unwrap();
    assert_eq!(f.subtype(), dot11::SUBTYPE_DEAUTH);
    // and a subsequent tick is quiet (station gone)
    ap.test_expire_eapol();
    assert!(ap.tick().frames.is_empty(), "nothing left to retransmit");
}
