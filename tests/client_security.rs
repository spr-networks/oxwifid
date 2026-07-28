//! Station-side security regressions. These cover the clean, hook-free parts of
//! the reference implementation/wpa_supplicant adversarial model from the supplicant's side.

use barely_ap::ap::Ap;
use barely_ap::client::Client;
use barely_ap::dot11;
use barely_ap::util::mac_to_bytes;
use std::time::{Duration, Instant};

fn framed(frame: Vec<u8>) -> Vec<u8> {
    let mut out = dot11::RADIOTAP_TX.to_vec();
    out.extend_from_slice(&frame);
    out
}

fn parse_eapol_key(frame: &[u8]) -> dot11::EapolKey {
    dot11::strip_radiotap(frame)
        .and_then(dot11::Dot11::parse)
        .and_then(|parsed| parsed.eapol_key_body().and_then(dot11::EapolKey::parse))
        .expect("valid EAPOL-Key frame")
}

fn wpa2_pair() -> (Ap, Client, [u8; 6], [u8; 6]) {
    let ap_mac = mac_to_bytes("02:00:00:00:00:01");
    let sta_mac = mac_to_bytes("02:00:00:00:00:02");
    (
        Ap::new("uplink", "correct horse battery staple", ap_mac, 36),
        Client::new("uplink", "correct horse battery staple", sta_mac),
        ap_mac,
        sta_mac,
    )
}

fn associate_without_eapol(client: &mut Client, ap: &mut Ap, ap_mac: [u8; 6], sta: [u8; 6]) {
    assert_eq!(client.handle_incoming(&ap.beacon_frame()).frames.len(), 1);
    assert_eq!(
        client
            .handle_incoming(&framed(dot11::build_auth(&ap_mac, &sta, 0)))
            .frames
            .len(),
        1
    );
    let assoc = dot11::build_assoc_resp(
        &ap_mac,
        &sta,
        b"uplink",
        36,
        1,
        0,
        dot11::SUBTYPE_ASSOC_RESP,
        b"US",
        80,
        false,
        true,
        dot11::PhyMode::Vht,
        0,
    );
    assert!(
        client.handle_incoming(&framed(assoc)).frames.is_empty(),
        "association response itself has no station reply"
    );
    assert_eq!(client.connected, 2);
}

fn drive(ap: &mut Ap, client: &mut Client) {
    let mut to_client = vec![ap.beacon_frame()];
    let mut to_ap = Vec::new();
    for _ in 0..50 {
        for frame in to_client.drain(..) {
            to_ap.extend(client.handle_incoming(&frame).frames);
        }
        for frame in to_ap.drain(..) {
            to_client.extend(ap.handle_incoming(&frame).frames);
        }
        if client.connected == 4 {
            return;
        }
    }
    panic!("client did not connect");
}

#[test]
fn station_ignores_wrong_ssid_security_and_unpinned_bssid() {
    let (_ap, mut client, wanted_bssid, _sta) = wpa2_pair();
    client.set_target_bssid(wanted_bssid);

    let mut wrong_ssid = Ap::new(
        "not-uplink",
        "correct horse battery staple",
        wanted_bssid,
        36,
    );
    assert!(client
        .handle_incoming(&wrong_ssid.beacon_frame())
        .frames
        .is_empty());

    let mut wrong_security = Ap::new("uplink", "correct horse battery staple", wanted_bssid, 36);
    wrong_security.enable_sae();
    assert!(client
        .handle_incoming(&wrong_security.beacon_frame())
        .frames
        .is_empty());

    let mut other_bssid = Ap::new(
        "uplink",
        "correct horse battery staple",
        mac_to_bytes("02:00:00:00:00:99"),
        36,
    );
    assert!(client
        .handle_incoming(&other_bssid.beacon_frame())
        .frames
        .is_empty());
    assert_eq!(client.connected, 0);
}

#[test]
fn psk_sha256_client_selects_akm6_in_association() {
    let ap_mac = mac_to_bytes("02:00:00:00:00:01");
    let sta_mac = mac_to_bytes("02:00:00:00:00:02");
    let mut client = Client::new("uplink", "correct horse battery staple", sta_mac);
    client.enable_psk_sha256();
    let beacon = dot11::build_beacon(
        &ap_mac,
        b"uplink",
        36,
        0,
        &dot11::RSN_PSK_SHA256,
        b"US",
        20,
        true,
        dot11::PhyMode::Vht,
        0,
    );
    assert_eq!(client.handle_incoming(&framed(beacon)).frames.len(), 1);

    let assoc = client
        .handle_incoming(&framed(dot11::build_auth(&ap_mac, &sta_mac, 0)))
        .frames
        .pop()
        .expect("PSK-SHA256 association request");
    let frame = dot11::Dot11::parse(dot11::strip_radiotap(&assoc).unwrap()).unwrap();
    let rsn = dot11::find_ie_strict(&frame.body[4..], 48)
        .unwrap()
        .unwrap();
    assert!(dot11::rsn_has_akm(rsn, 6));
    assert!(!dot11::rsn_has_akm(rsn, 2));

    let response = dot11::build_assoc_resp(
        &ap_mac,
        &sta_mac,
        b"uplink",
        36,
        1,
        0,
        dot11::SUBTYPE_ASSOC_RESP,
        b"US",
        20,
        false,
        true,
        dot11::PhyMode::Vht,
        0,
    );
    client.handle_incoming(&framed(response));
    let m1 = dot11::build_eapol_m1(
        &ap_mac,
        &sta_mac,
        &[0x55; 32],
        1,
        0,
        dot11::KeyMic::AesCmacV3,
    );
    let m2 = client.handle_incoming(&framed(m1)).frames.remove(0);
    let m2_frame = dot11::Dot11::parse(dot11::strip_radiotap(&m2).unwrap()).unwrap();
    let key = dot11::EapolKey::parse(m2_frame.eapol_key_body().unwrap()).unwrap();
    assert_eq!(key.descriptor_version(), 3);
    let m2_rsn = dot11::find_ie_strict(&key.key_data, 48).unwrap().unwrap();
    assert!(dot11::rsn_has_akm(m2_rsn, 6));
    assert!(!dot11::rsn_has_akm(m2_rsn, 2));
}

#[test]
fn psk_sha256_mlo_stays_fail_closed_without_the_pmf_key_path() {
    let ap_mac = mac_to_bytes("02:00:00:00:00:01");
    let sta_mac = mac_to_bytes("02:00:00:00:00:02");
    let mut client = Client::new("uplink", "correct horse battery staple", sta_mac);
    client.enable_psk_sha256();
    client.enable_mld(
        mac_to_bytes("02:00:00:00:10:00"),
        mac_to_bytes("02:00:00:00:10:02"),
        mac_to_bytes("02:00:00:00:20:00"),
    );
    let beacon = dot11::build_beacon(
        &ap_mac,
        b"uplink",
        36,
        0,
        &dot11::RSN_PSK_SHA256,
        b"US",
        20,
        true,
        dot11::PhyMode::Eht,
        0,
    );
    assert!(
        client.handle_incoming(&framed(beacon)).frames.is_empty(),
        "AKM6 MLO must not fall through to the SAE-only association template"
    );
}

#[test]
fn station_pins_authentication_and_association_to_selected_ap() {
    let (mut ap, mut client, ap_mac, sta) = wpa2_pair();
    assert_eq!(client.handle_incoming(&ap.beacon_frame()).frames.len(), 1);

    let attacker = mac_to_bytes("02:00:00:00:00:99");
    assert!(client
        .handle_incoming(&framed(dot11::build_auth(&attacker, &sta, 0)))
        .frames
        .is_empty());
    assert_eq!(client.connected, 1);

    assert_eq!(
        client
            .handle_incoming(&framed(dot11::build_auth(&ap_mac, &sta, 0)))
            .frames
            .len(),
        1
    );
    assert!(client
        .handle_incoming(&framed(dot11::build_assoc_resp_reject(
            &ap_mac,
            &sta,
            dot11::STATUS_INVALID_AKMP,
            dot11::SUBTYPE_ASSOC_RESP,
            0,
        )))
        .frames
        .is_empty());
    assert_eq!(
        client.connected, 1,
        "failed association must not enter the EAPOL state"
    );
}

#[test]
fn station_ignores_robust_management_from_an_unrelated_bssid() {
    let (mut ap, mut client, ap_mac, sta) = wpa2_pair();
    associate_without_eapol(&mut client, &mut ap, ap_mac, sta);

    let attacker = mac_to_bytes("02:00:00:00:00:99");
    client.handle_incoming(&framed(dot11::build_deauth(&attacker, &sta, 7)));
    assert_eq!(
        client.connected, 2,
        "an unrelated BSSID must not tear down the selected association"
    );

    client.handle_incoming(&framed(dot11::build_deauth(&ap_mac, &sta, 7)));
    assert_eq!(
        client.connected, 0,
        "legacy WPA2 still honors deauthentication from its selected AP"
    );
}

#[test]
fn owe_requires_a_valid_group19_dh_response() {
    let ap_mac = mac_to_bytes("02:00:00:00:00:01");
    let sta = mac_to_bytes("02:00:00:00:00:02");
    let mut ap = Ap::new("uplink", "", ap_mac, 36);
    ap.enable_owe();
    let mut client = Client::new("uplink", "", sta);
    client.enable_owe();

    assert_eq!(client.handle_incoming(&ap.beacon_frame()).frames.len(), 1);
    assert_eq!(
        client
            .handle_incoming(&framed(dot11::build_auth(&ap_mac, &sta, 0)))
            .frames
            .len(),
        1
    );
    let response_without_dh = dot11::build_assoc_resp(
        &ap_mac,
        &sta,
        b"uplink",
        36,
        1,
        0,
        dot11::SUBTYPE_ASSOC_RESP,
        b"US",
        80,
        false,
        true,
        dot11::PhyMode::Vht,
        0,
    );
    client.handle_incoming(&framed(response_without_dh));
    assert_eq!(
        client.connected, 1,
        "OWE must not fall back to an empty-password PMK"
    );
}

#[test]
fn station_rejects_malformed_or_foreign_eapol_message1() {
    let (mut ap, mut client, ap_mac, sta) = wpa2_pair();
    associate_without_eapol(&mut client, &mut ap, ap_mac, sta);

    let foreign = mac_to_bytes("02:00:00:00:00:99");
    let nonce = [0x55; 32];
    let foreign_m1 = dot11::build_eapol_m1(&foreign, &sta, &nonce, 1, 0, dot11::KeyMic::HmacSha1);
    assert!(client
        .handle_incoming(&framed(foreign_m1))
        .frames
        .is_empty());

    let zero_nonce = dot11::build_eapol_m1(&ap_mac, &sta, &[0; 32], 1, 0, dot11::KeyMic::HmacSha1);
    assert!(client
        .handle_incoming(&framed(zero_nonce))
        .frames
        .is_empty());
    assert_eq!(client.connected, 2);

    let valid = dot11::build_eapol_m1(&ap_mac, &sta, &nonce, 1, 0, dot11::KeyMic::HmacSha1);
    assert_eq!(client.handle_incoming(&framed(valid)).frames.len(), 1);
}

#[test]
fn message1_retry_with_a_newer_counter_reuses_the_same_snonce() {
    let (mut ap, mut client, ap_mac, sta) = wpa2_pair();
    associate_without_eapol(&mut client, &mut ap, ap_mac, sta);
    let anonce = [0x66; 32];
    let m1 = framed(dot11::build_eapol_m1(
        &ap_mac,
        &sta,
        &anonce,
        7,
        0,
        dot11::KeyMic::HmacSha1,
    ));
    let first = client.handle_incoming(&m1).frames.remove(0);
    let retry = client.handle_incoming(&m1).frames.remove(0);
    let first_eapol = dot11::strip_radiotap(&first)
        .and_then(dot11::Dot11::parse)
        .and_then(|frame| frame.eapol_frame().map(ToOwned::to_owned))
        .expect("first M2");
    let retry_eapol = dot11::strip_radiotap(&retry)
        .and_then(dot11::Dot11::parse)
        .and_then(|frame| frame.eapol_frame().map(ToOwned::to_owned))
        .expect("retried M2");
    assert_eq!(
        first_eapol, retry_eapol,
        "an AP retry must not cause a new SNonce/PTK candidate"
    );

    let newer_m1 = framed(dot11::build_eapol_m1(
        &ap_mac,
        &sta,
        &anonce,
        8,
        0,
        dot11::KeyMic::HmacSha1,
    ));
    let newer_m2 = client.handle_incoming(&newer_m1).frames.remove(0);
    let first_key = dot11::EapolKey::parse(&first_eapol[4..]).expect("first M2");
    let newer_key = parse_eapol_key(&newer_m2);
    assert_eq!(newer_key.key_replay_counter, 8);
    assert_eq!(
        newer_key.key_nonce, first_key.key_nonce,
        "a newer replay counter with the same ANonce must preserve the SNonce"
    );
}

#[test]
fn lost_authentication_response_returns_to_scanning() {
    let (mut ap, mut client, _ap_mac, _sta) = wpa2_pair();
    assert_eq!(client.handle_incoming(&ap.beacon_frame()).frames.len(), 1);
    assert_eq!(client.connected, 1);
    assert!(client.maintenance(Instant::now() + Duration::from_secs(4)));
    assert_eq!(client.connected, 0);
    assert_eq!(
        client.handle_incoming(&ap.beacon_frame()).frames.len(),
        1,
        "the next beacon must start a fresh authentication"
    );
}

#[test]
fn wmm_is_used_only_when_the_ap_negotiates_it() {
    for (suffix, ap_wmm) in [(0x20, false), (0x21, true)] {
        let ap_mac = mac_to_bytes("02:00:00:00:00:01");
        let sta = [0x02, 0, 0, 0, 0, suffix];
        let mut ap = Ap::new("uplink", "correct horse battery staple", ap_mac, 36);
        ap.set_wmm(ap_wmm);
        let mut client = Client::new("uplink", "correct horse battery staple", sta);
        drive(&mut ap, &mut client);
        let eth = [ap_mac.as_slice(), sta.as_slice(), &[0x08, 0x00], &[0u8; 32]].concat();
        let protected = client.encrypt_uplink(&eth).expect("connected data");
        let frame = dot11::strip_radiotap(&protected)
            .and_then(dot11::Dot11::parse)
            .expect("protected frame");
        assert_eq!(
            frame.qos.is_some(),
            ap_wmm,
            "QoS framing must follow negotiated WMM"
        );
    }
}

#[test]
fn rejected_pmksa_falls_back_to_full_sae_after_ap_restart() {
    let ap_mac = mac_to_bytes("02:00:00:00:00:01");
    let sta = mac_to_bytes("02:00:00:00:00:02");
    let mut first_ap = Ap::new("uplink", "correct horse battery staple", ap_mac, 36);
    first_ap.enable_sae();
    let mut client = Client::new("uplink", "correct horse battery staple", sta);
    client.enable_sae();
    drive(&mut first_ap, &mut client);

    let deauth = first_ap.kick(&sta).expect("connected station");
    client.handle_incoming(&deauth);
    assert_eq!(client.connected, 0);

    // A fresh AP process with the same BSSID has no matching PMKSA.
    let mut restarted_ap = Ap::new("uplink", "correct horse battery staple", ap_mac, 36);
    restarted_ap.enable_sae();
    let cached_auth = client
        .handle_incoming(&restarted_ap.beacon_frame())
        .frames
        .remove(0);
    let cached_auth = dot11::strip_radiotap(&cached_auth)
        .and_then(dot11::Dot11::parse)
        .and_then(|frame| dot11::parse_auth(&frame.body).map(|auth| auth.algo))
        .expect("cached reconnect auth");
    assert_eq!(cached_auth, dot11::AUTH_ALG_OPEN);

    let mut to_ap = client
        .handle_incoming(&framed(dot11::build_auth(&ap_mac, &sta, 0)))
        .frames;
    assert_eq!(to_ap.len(), 1);
    let rejection = restarted_ap.handle_incoming(&to_ap.remove(0));
    assert_eq!(rejection.frames.len(), 1);
    client.handle_incoming(&rejection.frames[0]);
    assert_eq!(client.connected, 0, "invalid PMKID must clear the attempt");

    let full_sae = client
        .handle_incoming(&restarted_ap.beacon_frame())
        .frames
        .remove(0);
    let full_sae = dot11::strip_radiotap(&full_sae)
        .and_then(dot11::Dot11::parse)
        .and_then(|frame| dot11::parse_auth(&frame.body).map(|auth| auth.algo))
        .expect("full SAE auth");
    assert_eq!(full_sae, dot11::AUTH_ALG_SAE);
}
