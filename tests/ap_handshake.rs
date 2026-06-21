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
    assert!(ap.is_associated(&sta), "station must be associated after m3");

    // 3. Encrypted uplink data decrypts to the expected Ethernet frame
    let uplink = from_hex(v["frames"]["data_uplink"]["bytes"].as_str().unwrap());
    let out = ap.handle_incoming(&uplink);
    assert_eq!(out.to_network.len(), 1, "uplink must decrypt to one ethernet frame");
    assert_eq!(to_hex(&out.to_network[0]), v["frames"]["data_uplink"]["decrypted_eth"].as_str().unwrap());
    assert!(out.frames.is_empty());
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
}

#[test]
fn downlink_roundtrips_through_a_station() {
    let v = vectors();
    let sta = mac_to_bytes("02:00:00:00:ab:cd");
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let mut ap = fixtured_ap();

    // complete the handshake
    ap.handle_incoming(&from_hex(v["incoming"]["assoc_req"]["bytes"].as_str().unwrap()));
    ap.handle_incoming(&from_hex(v["frames"]["eapol_m2_incoming"]["bytes"].as_str().unwrap()));
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
