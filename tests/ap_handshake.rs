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
    let mut ap = Ap::new(
        "turtlenet",
        "password1234",
        mac_to_bytes("02:00:00:00:00:00"),
        1,
    );
    let gtk: [u8; 16] = from_hex(v["frames"]["eapol_m3"]["gtk"].as_str().unwrap())
        .try_into()
        .unwrap();
    let anonce: [u8; 32] = from_hex(v["crypto"]["anonce"].as_str().unwrap())
        .try_into()
        .unwrap();
    ap.set_test_fixtures(gtk, anonce);
    ap
}

/// Send the STA's EAPOL message 4 (built with the golden KCK) so the AP can
/// verify it and complete the handshake — the AP only authorizes after m4.
fn send_m4(ap: &mut Ap, v: &Value) {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let sta = mac_to_bytes("02:00:00:00:ab:cd");
    let kck: [u8; 16] = from_hex(v["crypto"]["kck"].as_str().unwrap())
        .try_into()
        .unwrap();
    let m4 = dot11::build_eapol_m4(
        &ap_mac,
        &sta,
        &kck,
        2,
        0,
        dot11::KeyMic::select(false, false),
    );
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
    assert_eq!(
        to_hex(&out.frames[1]),
        v["frames"]["eapol_m1"]["bytes"].as_str().unwrap()
    );

    // 2. EAPOL message 2 (valid) -> EAPOL message 3, station associated
    let m2 = from_hex(v["frames"]["eapol_m2_incoming"]["bytes"].as_str().unwrap());
    let out = ap.handle_incoming(&m2);
    assert_eq!(out.frames.len(), 1, "valid m2 must yield exactly m3");
    assert_eq!(
        to_hex(&out.frames[0]),
        v["frames"]["eapol_m3"]["bytes"].as_str().unwrap()
    );
    assert!(
        !ap.is_associated(&sta),
        "station awaits m4, not yet associated after m3"
    );

    // 2b. EAPOL message 4 -> station fully associated (authorized only now).
    send_m4(&mut ap, &v);
    assert!(
        ap.is_associated(&sta),
        "station must be associated after verified m4"
    );

    // 3. Encrypted uplink data decrypts to the expected Ethernet frame
    let uplink = from_hex(v["frames"]["data_uplink"]["bytes"].as_str().unwrap());
    let out = ap.handle_incoming(&uplink);
    assert_eq!(
        out.to_network.len(),
        1,
        "uplink must decrypt to one ethernet frame"
    );
    assert_eq!(
        to_hex(&out.to_network[0]),
        v["frames"]["data_uplink"]["decrypted_eth"]
            .as_str()
            .unwrap()
    );
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
    assert!(
        ap.drain_events().is_empty(),
        "no connect event before m4 verifies"
    );

    // m4 authorizes the station -> AP-STA-CONNECTED.
    send_m4(&mut ap, &v);
    assert_eq!(ap.drain_events(), vec![ApEvent::Connected { mac: sta }]);
    assert!(ap.drain_events().is_empty(), "drain clears the queue");

    // Reaping the now-idle station -> AP-STA-DISCONNECTED (pairs with connect).
    std::thread::sleep(std::time::Duration::from_millis(2));
    ap.prune_idle(std::time::Duration::from_millis(1));
    assert_eq!(
        ap.drain_events(),
        vec![ApEvent::Disconnected {
            mac: sta,
            reason: 4
        }]
    );
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
        "got {:?}",
        ev[0]
    );
    assert!(
        ev[0]
            .to_line()
            .starts_with("AP-STA-POSSIBLE-PSK-MISMATCH 02:00:00:00:ab:cd wpa mismatch"),
        "SPR action event was {}",
        ev[0].to_line()
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
    assert!(
        !ap.is_associated(&sta),
        "station must be dropped after bad MIC"
    );
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
    ap.handle_incoming(&from_hex(
        v["incoming"]["assoc_req"]["bytes"].as_str().unwrap(),
    ));
    ap.handle_incoming(&from_hex(
        v["frames"]["eapol_m2_incoming"]["bytes"].as_str().unwrap(),
    ));
    send_m4(&mut ap, &v);
    assert!(ap.is_associated(&sta));

    // an Ethernet frame from the AP's stack toward the station
    let tk: [u8; 16] = from_hex(v["crypto"]["tk"].as_str().unwrap())
        .try_into()
        .unwrap();
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
    ap.handle_incoming(&from_hex(
        v["incoming"]["assoc_req"]["bytes"].as_str().unwrap(),
    ));
    // a tick before the timeout does nothing
    assert!(ap.tick().frames.is_empty(), "no retransmit before timeout");
    // reference AP's default update count is four total sends: initial + 3 retries.
    let mut retransmits = 0;
    for _ in 0..3 {
        ap.test_expire_eapol();
        if !ap.tick().frames.is_empty() {
            retransmits += 1;
        }
    }
    assert_eq!(retransmits, 3, "m1 retransmitted 3 times");
    assert!(!ap.is_associated(&sta), "still not associated (no m2)");
    // ...then the 4-way times out: the station is deauthed and dropped.
    ap.test_expire_eapol();
    let out = ap.tick();
    assert_eq!(
        out.frames.len(),
        1,
        "final tick deauths the stalled station"
    );
    let f = dot11::Dot11::parse(dot11::strip_radiotap(&out.frames[0]).unwrap()).unwrap();
    assert_eq!(f.subtype(), dot11::SUBTYPE_DEAUTH);
    // and a subsequent tick is quiet (station gone)
    ap.test_expire_eapol();
    assert!(ap.tick().frames.is_empty(), "nothing left to retransmit");
}

#[test]
fn unacked_assoc_response_cancels_speculative_eapol() {
    let v = vectors();
    let sta = mac_to_bytes("02:00:00:00:ab:cd");
    let mut ap = fixtured_ap();
    let assoc_req = from_hex(v["incoming"]["assoc_req"]["bytes"].as_str().unwrap());
    let parsed = dot11::Dot11::parse(dot11::strip_radiotap(&assoc_req).unwrap()).unwrap();
    let listen_interval = u16::from_le_bytes([parsed.body[2], parsed.body[3]]);

    let out = ap.handle_incoming(&assoc_req);
    assert_eq!(
        out.frames.len(),
        2,
        "m1 is prepared with the assoc response"
    );
    assert_eq!(ap.station_listen_interval(&sta), Some(listen_interval));

    // Netlink removes the station when the successful response is not MAC-ACKed.
    // The AP core must not then leak its speculatively prepared m1 on a timer.
    ap.note_assoc_response_not_acked(&sta);
    ap.test_expire_eapol();
    assert!(ap.tick().frames.is_empty());
    assert!(
        ap.drain_events().is_empty(),
        "cancelling an unsent speculative m1 must not disconnect the station"
    );

    // Authentication/session state is retained: after the transport finishes
    // cleaning the old kernel peer and the normal 250-ms request backoff has
    // elapsed, the client's Association retry can restart the 4-way without
    // another Authentication exchange.
    ap.test_clear_auth_backoff();
    let retry = ap.handle_incoming(&assoc_req);
    assert_eq!(
        retry.frames.len(),
        2,
        "association retry must produce a fresh response and m1"
    );
}

#[test]
fn cancelling_a_suppressed_reassociation_preserves_the_established_session() {
    let v = vectors();
    let sta = mac_to_bytes("02:00:00:00:ab:cd");
    let mut ap = connected_ap(false);
    assert_eq!(ap.drain_events().len(), 1, "consume initial connect event");
    ap.test_clear_auth_backoff();

    let assoc_req = from_hex(v["incoming"]["assoc_req"]["bytes"].as_str().unwrap());
    let prepared = ap.handle_incoming(&assoc_req);
    assert_eq!(
        prepared.frames.len(),
        2,
        "reassociation prepares a response and a new m1"
    );

    ap.note_assoc_response_not_acked(&sta);
    assert!(
        ap.is_associated(&sta),
        "cancelling the new attempt must not disconnect the old association"
    );
    assert!(
        ap.drain_events().is_empty(),
        "cancellation must not emit a disconnect event"
    );

    let mut downlink = Vec::new();
    downlink.extend_from_slice(&sta);
    downlink.extend_from_slice(&mac_to_bytes("02:00:00:00:00:00"));
    downlink.extend_from_slice(&[0x08, 0x00]);
    downlink.extend_from_slice(b"old association remains usable until cleanup");
    assert_eq!(
        ap.deliver_to_station(&downlink).len(),
        1,
        "the established PTK must remain usable"
    );
}

/// Complete the golden handshake against a fresh AP, optionally in guest mode.
fn connected_ap(guest: bool) -> Ap {
    let v = vectors();
    let sta = mac_to_bytes("02:00:00:00:ab:cd");
    let mut ap = fixtured_ap();
    if guest {
        ap.enable_guest();
    }
    ap.handle_incoming(&from_hex(
        v["incoming"]["assoc_req"]["bytes"].as_str().unwrap(),
    ));
    ap.handle_incoming(&from_hex(
        v["frames"]["eapol_m2_incoming"]["bytes"].as_str().unwrap(),
    ));
    send_m4(&mut ap, &v);
    assert!(ap.is_associated(&sta));
    ap
}

/// An encrypted uplink data frame addressed to an associated station of this
/// BSS (self-addressed — the minimal station-to-station case).
fn sta_to_sta_uplink(pn: u64) -> Vec<u8> {
    let v = vectors();
    let sta = mac_to_bytes("02:00:00:00:ab:cd");
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let tk: Vec<u8> = from_hex(v["crypto"]["tk"].as_str().unwrap());
    let frame = dot11::build_protected_data_sec(
        dot11::DataCipher::Ccmp128,
        &ap_mac, // a1: BSSID
        &sta,    // a2: transmitting station
        &sta,    // a3: destination — an associated station
        &ap_mac,
        &sta,
        &sta,
        dot11::FC_TODS | dot11::FC_PROTECTED,
        0x10,
        pn,
        0,
        &tk,
        0x0800,
        b"guest isolation probe",
        None,
    );
    let mut framed = dot11::RADIOTAP_TX.to_vec();
    framed.extend_from_slice(&frame);
    framed
}

#[test]
fn guest_ap_drops_station_to_station_uplink() {
    let v = vectors();

    // Control: a non-guest AP forwards a station-addressed uplink frame.
    let mut open = connected_ap(false);
    let out = open.handle_incoming(&sta_to_sta_uplink(1));
    assert_eq!(
        out.to_network.len(),
        1,
        "non-guest AP forwards station-addressed uplink"
    );

    // Guest: upstream (gateway-bound) traffic still flows...
    let mut guest = connected_ap(true);
    let uplink = from_hex(v["frames"]["data_uplink"]["bytes"].as_str().unwrap());
    let out = guest.handle_incoming(&uplink);
    assert_eq!(
        out.to_network.len(),
        1,
        "guest AP must still forward gateway-bound uplink"
    );
    // ...but a frame addressed to another associated station is dropped.
    let out = guest.handle_incoming(&sta_to_sta_uplink(0x1000));
    assert!(
        out.to_network.is_empty(),
        "guest AP must not carry station-to-station traffic"
    );
    assert!(out.frames.is_empty(), "isolation drop must be silent");
}

#[test]
fn guest_ap_drops_hairpinned_downlink() {
    let sta = mac_to_bytes("02:00:00:00:ab:cd");
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let mut guest = connected_ap(true);

    // A frame whose source is the AP's own station: station-to-station traffic
    // reflected back by an external bridge. Must not be delivered.
    let mut hairpin = Vec::new();
    hairpin.extend_from_slice(&sta); // dst
    hairpin.extend_from_slice(&sta); // src: our own associated station
    hairpin.extend_from_slice(&[0x08, 0x00]);
    hairpin.extend_from_slice(b"reflected by an external bridge");
    assert!(
        guest.deliver_to_station(&hairpin).is_empty(),
        "guest AP must drop downlink sourced from its own station"
    );

    // Gateway-sourced downlink still delivers.
    let mut downlink = Vec::new();
    downlink.extend_from_slice(&sta); // dst
    downlink.extend_from_slice(&ap_mac); // src: the gateway
    downlink.extend_from_slice(&[0x08, 0x00]);
    downlink.extend_from_slice(b"hello station this is the access point");
    assert_eq!(
        guest.deliver_to_station(&downlink).len(),
        1,
        "guest AP still delivers gateway-sourced downlink"
    );
}
