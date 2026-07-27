//! Regression tests for security failures found during the reference AP comparison.

use barely_ap::ap::{Ap, MldLink};
use barely_ap::client::Client;
use barely_ap::crypto;
use barely_ap::dot11;
use barely_ap::sae::Sae;
use barely_ap::util::{from_hex, mac_to_bytes};
use serde_json::Value;

fn framed(frame: Vec<u8>) -> Vec<u8> {
    let mut out = dot11::RADIOTAP_TX.to_vec();
    out.extend_from_slice(&frame);
    out
}

fn parse(frame: &[u8]) -> dot11::Dot11 {
    dot11::strip_radiotap(frame)
        .and_then(dot11::Dot11::parse)
        .expect("frame parses")
}

fn assoc_status(frame: &[u8]) -> u16 {
    let parsed = parse(frame);
    assert_eq!(parsed.subtype(), dot11::SUBTYPE_ASSOC_RESP);
    u16::from_le_bytes([parsed.body[2], parsed.body[3]])
}

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors.json")).expect("vectors parse")
}

fn fixtured_wpa2_ap() -> Ap {
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

fn wrap_eapol(body: &[u8]) -> Vec<u8> {
    let mut frame = vec![2, 3];
    frame.extend_from_slice(&(body.len() as u16).to_be_bytes());
    frame.extend_from_slice(body);
    frame
}

fn rewrite_m3_replay(frame: &[u8], replay: u64, kck: &[u8]) -> Vec<u8> {
    let mut rewritten = frame.to_vec();
    let radiotap_len = usize::from(u16::from_le_bytes([rewritten[2], rewritten[3]]));
    let eapol_start = radiotap_len + 24 + 8;
    let body_start = eapol_start + 4;
    let body_len = usize::from(u16::from_be_bytes([
        rewritten[eapol_start + 2],
        rewritten[eapol_start + 3],
    ]));
    let eapol_end = body_start + body_len;
    let replay_offset = body_start + 5;
    let mic_offset = body_start + 77;

    rewritten[replay_offset..replay_offset + 8].copy_from_slice(&replay.to_be_bytes());
    rewritten[mic_offset..mic_offset + 16].fill(0);
    let mic = dot11::KeyMic::HmacSha1.compute(kck, &rewritten[eapol_start..eapol_end]);
    rewritten[mic_offset..mic_offset + 16].copy_from_slice(&mic);
    rewritten
}

fn drive(ap: &mut Ap, station: &mut Client, max_rounds: usize) -> Vec<Vec<u8>> {
    let mut captured_from_station = Vec::new();
    let mut to_station = vec![ap.beacon_frame()];
    let mut to_ap = Vec::new();
    for _ in 0..max_rounds {
        for frame in to_station.drain(..) {
            let frames = station.handle_incoming(&frame).frames;
            captured_from_station.extend(frames.clone());
            to_ap.extend(frames);
        }
        for frame in to_ap.drain(..) {
            to_station.extend(ap.handle_incoming(&frame).frames);
        }
        if station.connected >= 4 || (to_station.is_empty() && to_ap.is_empty()) {
            break;
        }
    }
    captured_from_station
}

fn connect_and_capture_m3(ap: &mut Ap, station: &mut Client) -> Vec<u8> {
    let mut to_station = vec![ap.beacon_frame()];
    let mut to_ap = Vec::new();
    let mut m3 = None;
    for _ in 0..50 {
        for frame in to_station.drain(..) {
            let parsed = parse(&frame);
            if parsed.is_eapol() {
                if let Some(key) = parsed.eapol_key_body().and_then(dot11::EapolKey::parse) {
                    if key.is_pairwise() && key.key_ack() && key.key_info & (1 << 6) != 0 {
                        m3 = Some(frame.clone());
                    }
                }
            }
            to_ap.extend(station.handle_incoming(&frame).frames);
        }
        for frame in to_ap.drain(..) {
            to_station.extend(ap.handle_incoming(&frame).frames);
        }
        if station.connected >= 4 {
            break;
        }
    }
    assert_eq!(station.connected, 4);
    m3.expect("captured pairwise message 3")
}

fn sae_pair(mac: [u8; 6]) -> (Ap, Client) {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let mut ap = Ap::new("secure-net", "unused-fallback", ap_mac, 1);
    ap.enable_sae();
    ap.set_psk_file(&[(Some(mac), "device-password".to_string())]);
    let mut station = Client::new("secure-net", "device-password", mac);
    station.enable_sae();
    assert!(!drive(&mut ap, &mut station, 50).is_empty());
    assert_eq!(station.connected, 4);
    assert!(ap.is_associated(&mac));
    (ap, station)
}

fn disconnect_pair(ap: &mut Ap, station: &mut Client, mac: [u8; 6]) {
    let deauth = ap.kick(&mac).expect("known station can be kicked");
    station.handle_incoming(&deauth);
    assert_eq!(station.connected, 0);
    assert!(!ap.is_associated(&mac));
}

#[test]
fn completed_handshake_frames_cannot_reinstall_a_pairwise_key() {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let sta_mac = mac_to_bytes("02:00:00:00:ab:cd");
    let mut ap = Ap::new("secure-net", "device-password", ap_mac, 1);
    let mut station = Client::new("secure-net", "device-password", sta_mac);

    let captured = drive(&mut ap, &mut station, 50);
    assert_eq!(station.connected, 4);
    let old_tk = ap.station_tk(&sta_mac).expect("first PTK installed");
    let mut old_m2 = None;
    let mut old_m4 = None;
    for frame in captured {
        let parsed = parse(&frame);
        if !parsed.is_eapol() {
            continue;
        }
        let key = dot11::EapolKey::parse(parsed.eapol_key_body().unwrap()).unwrap();
        if key.key_nonce != [0u8; 32] {
            old_m2 = Some((frame, key.key_replay_counter));
        } else if key.key_info & (1 << 9) != 0 {
            old_m4 = Some(frame);
        }
    }
    let (old_m2, old_replay) = old_m2.expect("captured message 2");
    let old_m4 = old_m4.expect("captured message 4");

    // Exercise the AP's downlink PN before starting a genuinely fresh session.
    let eth = [
        sta_mac.as_slice(),
        ap_mac.as_slice(),
        &[0x08, 0x00],
        &[0u8; 32],
    ]
    .concat();
    for _ in 0..3 {
        assert_eq!(ap.deliver_to_station(&eth).len(), 1);
    }

    ap.test_clear_auth_backoff();
    ap.handle_incoming(&framed(dot11::build_auth_req(&ap_mac, &sta_mac, 0)));
    let fresh = ap.handle_incoming(&framed(dot11::build_assoc_req(
        &ap_mac,
        &sta_mac,
        b"secure-net",
        16,
    )));
    let m1 = fresh
        .frames
        .iter()
        .map(|frame| parse(frame))
        .find(|frame| frame.is_eapol())
        .expect("fresh association emits message 1");
    let fresh_replay = dot11::EapolKey::parse(m1.eapol_key_body().unwrap())
        .unwrap()
        .key_replay_counter;
    assert_ne!(
        fresh_replay, old_replay,
        "a new session must use a new replay counter"
    );

    assert!(
        ap.handle_incoming(&old_m2).frames.is_empty(),
        "completed-session message 2 must not produce message 3"
    );
    assert!(ap.handle_incoming(&old_m4).frames.is_empty());
    assert!(!ap.is_associated(&sta_mac));
    assert_ne!(
        ap.station_tk(&sta_mac),
        Some(old_tk),
        "the completed-session TK must not be restored"
    );
}

#[test]
fn newer_message_3_retry_is_reacked_without_resetting_pairwise_pn() {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let sta_mac = mac_to_bytes("02:00:00:00:ab:cd");
    let mut ap = Ap::new("secure-net", "device-password", ap_mac, 1);
    let mut station = Client::new("secure-net", "device-password", sta_mac);
    let snonce = [0x42; 32];
    station.set_test_snonce(snonce);
    let m3 = connect_and_capture_m3(&mut ap, &mut station);
    let m3_key = parse(&m3)
        .eapol_key_body()
        .and_then(dot11::EapolKey::parse)
        .expect("captured M3");
    let pmk = crypto::pbkdf2_pmk("device-password", "secure-net");
    let ptk = crypto::custom_prf512(&pmk, &ap_mac, &sta_mac, &m3_key.key_nonce, &snonce);
    let newer_replay = m3_key.key_replay_counter + 1;
    let newer_m3 = rewrite_m3_replay(&m3, newer_replay, &ptk[..16]);

    let eth = [
        ap_mac.as_slice(),
        sta_mac.as_slice(),
        &[0x08, 0x00],
        &[0u8; 32],
    ]
    .concat();
    let first = station.encrypt_uplink(&eth).expect("first protected frame");
    let first_pn = parse(&first).ccmp_pn().expect("first packet number");

    let retry = station.handle_incoming(&newer_m3);
    assert_eq!(retry.frames.len(), 1, "newer M3 retry must be re-ACKed");
    let retry_key = parse(&retry.frames[0])
        .eapol_key_body()
        .and_then(dot11::EapolKey::parse)
        .expect("M4 retry");
    assert_eq!(retry_key.key_replay_counter, newer_replay);

    let second = station
        .encrypt_uplink(&eth)
        .expect("second protected frame");
    let second_pn = parse(&second).ccmp_pn().expect("second packet number");
    assert_eq!(
        second_pn,
        first_pn + 1,
        "M3 retry must not reinstall the PTK or reset its transmit PN"
    );

    assert!(
        station.handle_incoming(&m3).frames.is_empty(),
        "the older M3 must be rejected after authenticating the newer counter"
    );
}

#[test]
fn duplicate_group_message_1_is_reacked_without_reinstalling_gtk() {
    let sta_mac = mac_to_bytes("02:00:00:00:00:44");
    let (mut ap, mut station) = sae_pair(sta_mac);
    let group_m1 = ap.rekey_gtk().remove(0);
    let first_ack = station.handle_incoming(&group_m1);
    assert_eq!(first_ack.frames.len(), 1);

    let broadcast = [
        [0xff; 6].as_slice(),
        ap.mac.as_slice(),
        &[0x08, 0x00],
        &[0u8; 32],
    ]
    .concat();
    let group_pn1 = ap.deliver_to_station(&broadcast).remove(0);
    let group_pn2 = ap.deliver_to_station(&broadcast).remove(0);
    assert_eq!(station.handle_incoming(&group_pn1).to_network.len(), 1);
    assert_eq!(station.handle_incoming(&group_pn2).to_network.len(), 1);

    let retry_ack = station.handle_incoming(&group_m1);
    assert_eq!(
        retry_ack.frames.len(),
        1,
        "duplicate group message 1 must be re-ACKed"
    );
    assert!(
        station.handle_incoming(&group_pn1).to_network.is_empty(),
        "duplicate group message 1 must not reset the group replay window"
    );
}

#[test]
fn pmksa_is_bound_to_the_authenticated_station_identity() {
    let original = mac_to_bytes("02:00:00:00:00:11");
    let victim = mac_to_bytes("02:00:00:00:00:22");
    let (mut ap, mut station) = sae_pair(original);
    disconnect_pair(&mut ap, &mut station, original);

    // A custom supplicant can retain its PMK/PMKID while changing its on-air
    // address. That cache entry must not authorize the new identity.
    station.mac = victim;
    drive(&mut ap, &mut station, 50);
    assert_ne!(station.connected, 4);
    assert!(!ap.is_associated(&victim));
}

#[test]
fn pmksa_lookup_accepts_a_cached_pmkid_after_an_unknown_entry() {
    let mac = mac_to_bytes("02:00:00:00:00:23");
    let (mut ap, mut station) = sae_pair(mac);
    disconnect_pair(&mut ap, &mut station, mac);

    let auth_req = station.handle_incoming(&ap.beacon_frame()).frames.remove(0);
    let auth_resp = ap.handle_incoming(&auth_req).frames.remove(0);
    let mut assoc = station.handle_incoming(&auth_resp).frames.remove(0);

    let radiotap_len = assoc.len() - dot11::strip_radiotap(&assoc).unwrap().len();
    let mut ie = radiotap_len + 28; // 24-byte header + 4-byte Assoc fixed fields
    loop {
        let len = usize::from(assoc[ie + 1]);
        if assoc[ie] == 48 {
            let body = ie + 2;
            assert_eq!(&assoc[body + 20..body + 22], &1u16.to_le_bytes());
            assoc[body + 20..body + 22].copy_from_slice(&2u16.to_le_bytes());
            assoc.splice(body + 22..body + 22, [0xa5; 16]);
            assoc[ie + 1] += 16;
            break;
        }
        ie += 2 + len;
    }

    let response = ap.handle_incoming(&assoc);
    assert_eq!(assoc_status(&response.frames[0]), dot11::STATUS_SUCCESS);
    assert_eq!(
        response.frames.len(),
        2,
        "the cached second PMKID must start the four-way handshake"
    );
}

#[test]
fn credential_reload_and_pmksa_expiry_revoke_fast_reconnect() {
    let mac = mac_to_bytes("02:00:00:00:00:33");
    let (mut ap, mut station) = sae_pair(mac);
    disconnect_pair(&mut ap, &mut station, mac);
    ap.set_psk_file(&[]);
    drive(&mut ap, &mut station, 50);
    assert_ne!(station.connected, 4, "removed credential must stay revoked");
    assert!(!ap.is_associated(&mac));

    let (mut ap, mut station) = sae_pair(mac);
    disconnect_pair(&mut ap, &mut station, mac);
    ap.test_expire_pmksa();
    drive(&mut ap, &mut station, 50);
    assert_ne!(station.connected, 4, "expired PMKSA must not reconnect");
    assert!(!ap.is_associated(&mac));
}

#[test]
fn sae_anti_clogging_requires_a_valid_token_and_expires_incomplete_state() {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let mut ap = Ap::new("secure-net", "device-password", ap_mac, 1);
    ap.enable_sae();

    // Leave five exchanges incomplete to cross the anti-clogging threshold.
    for suffix in 1..=5 {
        let mac = [0x02, 0, 0, 0, 1, suffix];
        let mut station = Client::new("secure-net", "device-password", mac);
        station.enable_sae();
        let commit = station.handle_incoming(&ap.beacon_frame()).frames.remove(0);
        assert_eq!(ap.handle_incoming(&commit).frames.len(), 2);
    }
    assert_eq!(ap.station_macs().len(), 5);

    let sixth_mac = [0x02, 0, 0, 0, 1, 6];
    let mut sixth = Client::new("secure-net", "device-password", sixth_mac);
    sixth.enable_sae();
    let commit = sixth.handle_incoming(&ap.beacon_frame()).frames.remove(0);
    let token_request = ap.handle_incoming(&commit);
    assert_eq!(token_request.frames.len(), 1);
    let request = parse(&token_request.frames[0]);
    let auth = dot11::parse_auth(&request.body).expect("SAE token request");
    assert_eq!(auth.status, dot11::STATUS_ANTI_CLOGGING_TOKEN_REQ);
    assert_eq!(
        ap.station_macs().len(),
        5,
        "requesting a token must not allocate station state"
    );

    let tokenized_commit = sixth
        .handle_incoming(&token_request.frames[0])
        .frames
        .remove(0);
    assert_eq!(
        ap.handle_incoming(&tokenized_commit).frames.len(),
        2,
        "a valid round-trip token admits the exchange"
    );
    assert_eq!(ap.station_macs().len(), 6);

    // A harvested token must not remain a permanent overload bypass.
    let seventh_mac = [0x02, 0, 0, 0, 1, 7];
    let mut seventh = Client::new("secure-net", "device-password", seventh_mac);
    seventh.enable_sae();
    let seventh_commit = seventh.handle_incoming(&ap.beacon_frame()).frames.remove(0);
    let seventh_request = ap.handle_incoming(&seventh_commit);
    let seventh_tokenized = seventh
        .handle_incoming(&seventh_request.frames[0])
        .frames
        .remove(0);
    ap.test_expire_sae_tokens();
    let expired_response = ap.handle_incoming(&seventh_tokenized);
    assert_eq!(expired_response.frames.len(), 1);
    assert_eq!(
        dot11::parse_auth(&parse(&expired_response.frames[0]).body)
            .expect("replacement token request")
            .status,
        dot11::STATUS_ANTI_CLOGGING_TOKEN_REQ
    );
    assert_eq!(ap.station_macs().len(), 6);

    ap.test_expire_incomplete_sae();
    ap.tick();
    assert!(
        ap.station_macs().is_empty(),
        "incomplete SAE state must expire"
    );
}

#[test]
fn reference_ap_assoc_rsn_validation_rejects_malformed_and_wrong_akm() {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");

    for (suffix, malformed, expected_status) in [
        (1, vec![48, 0], dot11::STATUS_INVALID_IE),
        (2, vec![48, 1, 1], dot11::STATUS_INVALID_IE),
        (3, vec![48, 2, 1, 0], dot11::STATUS_INVALID_AKMP),
    ] {
        let sta = [0x02, 0, 0, 0, 2, suffix];
        let mut ap = Ap::new("turtlenet", "password1234", ap_mac, 1);
        let mut assoc = dot11::build_assoc_req(&ap_mac, &sta, b"turtlenet", 0x10);
        assoc.truncate(assoc.len() - dot11::RSN.len());
        assoc.extend_from_slice(&malformed);
        let out = ap.handle_incoming(&framed(assoc));
        assert_eq!(out.frames.len(), 1);
        assert_eq!(assoc_status(&out.frames[0]), expected_status);
    }

    let sta = mac_to_bytes("02:00:00:00:02:04");
    let mut ap = Ap::new("turtlenet", "password1234", ap_mac, 1);
    let out = ap.handle_incoming(&framed(dot11::build_assoc_req_sae(
        &ap_mac,
        &sta,
        b"turtlenet",
        0x10,
    )));
    assert_eq!(assoc_status(&out.frames[0]), dot11::STATUS_INVALID_AKMP);
}

#[test]
fn reference_ap_wpa2_assoc_without_optional_rsn_capabilities_still_works() {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let sta = mac_to_bytes("02:00:00:00:02:05");
    let mut ap = Ap::new("turtlenet", "password1234", ap_mac, 1);
    let mut assoc = dot11::build_assoc_req(&ap_mac, &sta, b"turtlenet", 0x10);
    assoc.truncate(assoc.len() - dot11::RSN.len());
    let mut rsn_without_caps = dot11::RSN[..dot11::RSN.len() - 2].to_vec();
    rsn_without_caps[1] -= 2;
    assoc.extend_from_slice(&rsn_without_caps);

    let out = ap.handle_incoming(&framed(assoc));
    assert_eq!(assoc_status(&out.frames[0]), dot11::STATUS_SUCCESS);
    assert_eq!(out.frames.len(), 2, "successful association starts M1");
}

#[test]
fn identical_rsnxe_repeats_are_unambiguous_but_conflicts_are_rejected() {
    let repeated = [0xf4, 1, 0x20, 0xf4, 1, 0x20];
    assert_eq!(
        dot11::find_ie_consistent(&repeated, 0xf4),
        Ok(Some(&[0x20][..]))
    );

    let conflicting = [0xf4, 1, 0x20, 0xf4, 1, 0x00];
    assert!(dot11::find_ie_consistent(&conflicting, 0xf4).is_err());
}

#[test]
fn reference_ap_truncated_basic_mle_is_rejected() {
    let ap_link0 = mac_to_bytes("02:00:00:00:10:01");
    let ap_link1 = mac_to_bytes("02:00:00:00:10:02");
    let ap_mld = mac_to_bytes("02:00:00:00:10:00");
    let sta = mac_to_bytes("02:11:22:33:44:00");
    let sta_mld = mac_to_bytes("02:11:22:33:44:0f");
    let mut malformed = vec![0xff, 0x0a, 0x6b, 0x00, 0x01, 0x09];
    malformed.extend_from_slice(&sta_mld);
    assert_eq!(dot11::parse_mld_mac(&malformed), None);

    let mut ap = Ap::new("turtlenet", "password1234", ap_link0, 1);
    ap.mld = true;
    ap.mld_mac = ap_mld;
    ap.link_id = 0;
    ap.set_mld_links(vec![
        MldLink {
            link_id: 0,
            mac: ap_link0,
            channel: 1,
            width: 20,
            band6: false,
        },
        MldLink {
            link_id: 1,
            mac: ap_link1,
            channel: 36,
            width: 20,
            band6: false,
        },
    ]);
    let mut assoc = dot11::build_assoc_req(&ap_link0, &sta, b"turtlenet", 0x10);
    assoc.extend_from_slice(&malformed);
    let out = ap.handle_incoming(&framed(assoc));
    assert_eq!(out.frames.len(), 1);
    assert_eq!(assoc_status(&out.frames[0]), dot11::STATUS_INVALID_IE);
    assert_eq!(ap.station_mld_mac(&sta), None);
    assert!(
        ap.station_macs().is_empty(),
        "malformed MLE must not allocate station state"
    );
}

#[test]
fn malformed_eapol_key_frames_do_not_destroy_pending_handshake() {
    let v = vectors();
    let mut ap = fixtured_wpa2_ap();
    let assoc = from_hex(v["incoming"]["assoc_req"]["bytes"].as_str().unwrap());
    ap.handle_incoming(&assoc);
    let valid_m2 = from_hex(v["frames"]["eapol_m2_incoming"]["bytes"].as_str().unwrap());

    let mut invalid_descriptor = valid_m2.clone();
    invalid_descriptor[44] = 253;
    assert!(ap.handle_incoming(&invalid_descriptor).frames.is_empty());

    let mut invalid_key_info = valid_m2.clone();
    invalid_key_info[45..47].copy_from_slice(&0u16.to_be_bytes());
    assert!(ap.handle_incoming(&invalid_key_info).frames.is_empty());

    let mut truncated_key_data = valid_m2.clone();
    let declared = u16::from_be_bytes([truncated_key_data[42], truncated_key_data[43]]);
    truncated_key_data[42..44].copy_from_slice(&(declared - 1).to_be_bytes());
    assert!(ap.handle_incoming(&truncated_key_data).frames.is_empty());

    assert_eq!(
        ap.handle_incoming(&valid_m2).frames.len(),
        1,
        "valid M2 must still produce M3 after malformed frames were dropped"
    );
}

#[test]
fn eapol_message_2_must_match_association_rsn() {
    let v = vectors();
    let mut ap = fixtured_wpa2_ap();
    let assoc = from_hex(v["incoming"]["assoc_req"]["bytes"].as_str().unwrap());
    ap.handle_incoming(&assoc);

    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let sta = mac_to_bytes("02:00:00:00:ab:cd");
    let snonce: [u8; 32] = from_hex(v["crypto"]["snonce"].as_str().unwrap())
        .try_into()
        .unwrap();
    let kck: [u8; 16] = from_hex(v["crypto"]["kck"].as_str().unwrap())
        .try_into()
        .unwrap();
    let mut mismatched_rsn = dot11::RSN.to_vec();
    *mismatched_rsn.last_mut().unwrap() ^= 0x10;
    let mismatched_m2 = dot11::build_eapol_m2(dot11::EapolM2Params {
        bssid: &ap_mac,
        sta: &sta,
        snonce: &snonce,
        kck: &kck,
        supp_rsn: &mismatched_rsn,
        replay_counter: 1,
        sc: 0,
        mic: dot11::KeyMic::select(false, false),
        oci: None,
    });
    assert!(
        ap.handle_incoming(&framed(mismatched_m2)).frames.is_empty(),
        "M2 with a different RSNE must not advance to M3"
    );

    let valid_m2 = from_hex(v["frames"]["eapol_m2_incoming"]["bytes"].as_str().unwrap());
    assert_eq!(
        ap.handle_incoming(&valid_m2).frames.len(),
        1,
        "a matching retry must still complete"
    );
}

#[test]
fn encrypted_m2_is_rejected_before_key_unwrap() {
    let v = vectors();
    let mut ap = fixtured_wpa2_ap();
    let assoc = from_hex(v["incoming"]["assoc_req"]["bytes"].as_str().unwrap());
    ap.handle_incoming(&assoc);

    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let sta = mac_to_bytes("02:00:00:00:ab:cd");
    let snonce: [u8; 32] = from_hex(v["crypto"]["snonce"].as_str().unwrap())
        .try_into()
        .unwrap();
    let kck: [u8; 16] = from_hex(v["crypto"]["kck"].as_str().unwrap())
        .try_into()
        .unwrap();
    let kek: [u8; 16] = from_hex(v["crypto"]["kek"].as_str().unwrap())
        .try_into()
        .unwrap();
    let wrapped = crypto::aes_wrap(&kek, &crypto::pad_key_data(dot11::RSN.to_vec()));
    let key_info = dot11::KeyInfo {
        encrypted_key_data: true,
        has_key_mic: true,
        key_type: true,
        key_descriptor_type_version: 2,
        ..Default::default()
    };
    let mut body = dot11::build_eapol_key_body(key_info, 0, 1, &snonce, &[0u8; 16], &wrapped);
    let raw_info = u16::from_be_bytes([body[1], body[2]]) | 0xc000;
    body[1..3].copy_from_slice(&raw_info.to_be_bytes());
    let mic = dot11::KeyMic::select(false, false).compute(&kck, &wrap_eapol(&body));
    body[77..93].copy_from_slice(&mic);

    let normal_m2 = dot11::build_eapol_m2(dot11::EapolM2Params {
        bssid: &ap_mac,
        sta: &sta,
        snonce: &snonce,
        kck: &kck,
        supp_rsn: &dot11::RSN,
        replay_counter: 1,
        sc: 0,
        mic: dot11::KeyMic::select(false, false),
        oci: None,
    });
    let mut encrypted_m2 = normal_m2[..32].to_vec();
    encrypted_m2.extend_from_slice(&wrap_eapol(&body));
    assert!(
        ap.handle_incoming(&framed(encrypted_m2)).frames.is_empty(),
        "M2 with Encrypted Key Data set must not reach AES unwrap or produce M3"
    );
}

fn sae_commit_with_status(status: u16) -> Vec<u8> {
    let ap = mac_to_bytes("02:00:00:00:00:00");
    let sta = mac_to_bytes("02:00:00:00:ab:cd");
    let mut sae = Sae::new_h2e(b"turtlenet", b"password1234", None, &ap, &sta);
    sae.prepare_commit(None);
    framed(dot11::build_sae_auth(
        &ap,
        &sta,
        &ap,
        0,
        0,
        1,
        status,
        &sae.write_commit(),
    ))
}

#[test]
fn reference_ap_sae_unknown_commit_status_is_not_legacy_sae() {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    for status in [1, 127] {
        let mut ap = Ap::new("turtlenet", "password1234", ap_mac, 1);
        ap.enable_sae();
        let out = ap.handle_incoming(&sae_commit_with_status(status));
        assert_eq!(out.frames.len(), 1);
        let parsed = parse(&out.frames[0]);
        let auth = dot11::parse_auth(&parsed.body).expect("SAE rejection");
        assert_eq!(auth.status, dot11::STATUS_UNSPECIFIED_FAILURE);
    }

    let mut ap = Ap::new("turtlenet", "password1234", ap_mac, 1);
    ap.enable_sae();
    assert_eq!(
        ap.handle_incoming(&sae_commit_with_status(dot11::STATUS_SAE_H2E))
            .frames
            .len(),
        2,
        "supported H2E commit still produces commit and confirm"
    );
}

#[test]
fn reference_ap_sae_unsupported_group_uses_status_77() {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let sta = mac_to_bytes("02:00:00:00:ab:cd");
    let mut sae = Sae::new_h2e(b"turtlenet", b"password1234", None, &ap_mac, &sta);
    sae.prepare_commit(None);
    let mut commit = sae.write_commit();
    commit[..2].copy_from_slice(&25u16.to_le_bytes());

    let frame = framed(dot11::build_sae_auth(
        &ap_mac,
        &sta,
        &ap_mac,
        0,
        0,
        1,
        dot11::STATUS_SUCCESS,
        &commit,
    ));
    let mut ap = Ap::new("turtlenet", "password1234", ap_mac, 1);
    ap.enable_sae();
    let out = ap.handle_incoming(&frame);
    assert_eq!(out.frames.len(), 1);
    let parsed = parse(&out.frames[0]);
    let auth = dot11::parse_auth(&parsed.body).expect("SAE group rejection");
    assert_eq!(auth.status, dot11::STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED);
    assert_eq!(auth.payload, 25u16.to_le_bytes());
}

fn capture_sae_assoc() -> (Ap, Vec<u8>) {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let sta_mac = mac_to_bytes("02:00:00:00:ab:cd");
    let mut ap = Ap::new("turtlenet", "password1234", ap_mac, 1);
    ap.enable_sae();
    let mut station = Client::new("turtlenet", "password1234", sta_mac);
    station.enable_sae();
    let mut to_station = vec![ap.beacon_frame()];

    for _ in 0..20 {
        let mut to_ap = Vec::new();
        let mut assoc = None;
        for frame in to_station.drain(..) {
            for reply in station.handle_incoming(&frame).frames {
                if parse(&reply).subtype() == dot11::SUBTYPE_ASSOC_REQ {
                    assoc = Some(reply);
                } else {
                    to_ap.push(reply);
                }
            }
        }
        let mut next = Vec::new();
        for frame in to_ap {
            next.extend(ap.handle_incoming(&frame).frames);
        }
        to_station = next;
        if let Some(assoc) = assoc {
            return (ap, assoc);
        }
    }
    panic!("SAE client did not reach association");
}

#[test]
fn reference_ap_sae_long_rsnxe_is_extensible() {
    let (mut ap, mut assoc) = capture_sae_assoc();
    let stripped_len = dot11::strip_radiotap(&assoc).unwrap().len();
    let radiotap_len = assoc.len() - stripped_len;
    let mut pos = radiotap_len + 28;
    let rsnxe = loop {
        let len = assoc[pos + 1] as usize;
        if assoc[pos] == 0xf4 {
            break pos;
        }
        pos += 2 + len;
    };
    let old_len = assoc[rsnxe + 1] as usize;
    let mut long = vec![0xf4, 0xff, 0x2f];
    long.extend(std::iter::repeat_n(0xee, 254));
    assoc.splice(rsnxe..rsnxe + 2 + old_len, long);

    let out = ap.handle_incoming(&assoc);
    assert_eq!(assoc_status(&out.frames[0]), dot11::STATUS_SUCCESS);
    assert_eq!(out.frames.len(), 2, "accepted association starts M1");
}

#[test]
fn reference_ap_owe_unsupported_group_uses_status_77() {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let sta = mac_to_bytes("02:00:00:00:ab:cd");
    let (_private, public) = barely_ap::sae::owe_keypair();
    let dh = dot11::build_dh_param_element(0, &public);
    let assoc = dot11::build_assoc_req_owe(&ap_mac, &sta, b"owe", &dh, 0);
    let mut ap = Ap::new_without_credential("owe", ap_mac, 1);
    ap.enable_owe();
    let out = ap.handle_incoming(&framed(assoc));
    assert_eq!(out.frames.len(), 1);
    assert_eq!(
        assoc_status(&out.frames[0]),
        dot11::STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED
    );
}

fn mld_ap_for_malformed_profile() -> Ap {
    let ap_link0 = mac_to_bytes("02:00:00:00:10:01");
    let ap_link1 = mac_to_bytes("02:00:00:00:10:02");
    let mut ap = Ap::new("turtlenet", "password1234", ap_link0, 1);
    ap.enable_sae();
    ap.mld = true;
    ap.mld_mac = mac_to_bytes("02:00:00:00:10:00");
    ap.link_id = 0;
    ap.set_mld_links(vec![
        MldLink {
            link_id: 0,
            mac: ap_link0,
            channel: 1,
            width: 20,
            band6: false,
        },
        MldLink {
            link_id: 1,
            mac: ap_link1,
            channel: 36,
            width: 80,
            band6: false,
        },
    ]);
    ap
}

#[test]
fn reference_ap_mld_truncated_nested_profile_is_rejected_before_state_install() {
    let ap_link0 = mac_to_bytes("02:00:00:00:10:01");
    let sta_link0 = mac_to_bytes("02:00:00:00:20:01");
    let sta_mld = mac_to_bytes("02:00:00:00:20:00");
    let sta_link1 = mac_to_bytes("02:00:00:00:20:11");
    let mut assoc =
        dot11::build_assoc_req_mld(&ap_link0, &sta_link0, &sta_mld, &sta_link1, b"turtlenet", 0);

    let mut pos = 28;
    let mle = loop {
        let len = assoc[pos + 1] as usize;
        if assoc[pos] == 255 && len >= 1 && assoc[pos + 2] == 107 {
            break pos;
        }
        pos += 2 + len;
    };
    let common_len = assoc[mle + 5] as usize;
    let subelement = mle + 5 + common_len;
    assert_eq!(assoc[subelement], 0);
    let sub = subelement + 2;
    let sta_info_len = assoc[sub + 2] as usize;
    let nested_ies = sub + 2 + sta_info_len + 2;
    assoc[nested_ies + 1] = 0xff;

    let mut ap = mld_ap_for_malformed_profile();
    let out = ap.handle_incoming(&framed(assoc));
    assert_eq!(out.frames.len(), 1);
    assert_ne!(assoc_status(&out.frames[0]), dot11::STATUS_SUCCESS);
    assert_eq!(ap.station_mld_mac(&sta_link0), None);
}

fn ptk_for_snonce(snonce: &[u8; 32]) -> [u8; 64] {
    let v = vectors();
    let pmk: [u8; 32] = from_hex(v["crypto"]["pmk"].as_str().unwrap())
        .try_into()
        .unwrap();
    let anonce: [u8; 32] = from_hex(v["crypto"]["anonce"].as_str().unwrap())
        .try_into()
        .unwrap();
    crypto::custom_prf512(
        &pmk,
        &mac_to_bytes("02:00:00:00:00:00"),
        &mac_to_bytes("02:00:00:00:ab:cd"),
        &anonce,
        snonce,
    )
}

fn begin_wpa2(ap: &mut Ap) {
    let assoc = from_hex(
        vectors()["incoming"]["assoc_req"]["bytes"]
            .as_str()
            .unwrap(),
    );
    assert_eq!(ap.handle_incoming(&assoc).frames.len(), 2);
}

fn send_m2(ap: &mut Ap, snonce: &[u8; 32], kck: &[u8]) -> Vec<Vec<u8>> {
    let frame = dot11::build_eapol_m2(dot11::EapolM2Params {
        bssid: &mac_to_bytes("02:00:00:00:00:00"),
        sta: &mac_to_bytes("02:00:00:00:ab:cd"),
        snonce,
        kck,
        supp_rsn: &dot11::RSN,
        replay_counter: 1,
        sc: 0,
        mic: dot11::KeyMic::select(false, false),
        oci: None,
    });
    ap.handle_incoming(&framed(frame)).frames
}

fn send_m4(ap: &mut Ap, kck: &[u8]) {
    let frame = dot11::build_eapol_m4(
        &mac_to_bytes("02:00:00:00:00:00"),
        &mac_to_bytes("02:00:00:00:ab:cd"),
        kck,
        2,
        0,
        dot11::KeyMic::select(false, false),
    );
    ap.handle_incoming(&framed(frame));
}

#[test]
fn reference_ap_changed_snonce_m2_retry_keeps_both_ptk_candidates() {
    let snonce1: [u8; 32] = from_hex(vectors()["crypto"]["snonce"].as_str().unwrap())
        .try_into()
        .unwrap();
    let snonce2 = [0x22; 32];
    let ptk1 = ptk_for_snonce(&snonce1);
    let ptk2 = ptk_for_snonce(&snonce2);

    for final_kck in [&ptk2[..16], &ptk1[..16]] {
        let mut ap = fixtured_wpa2_ap();
        begin_wpa2(&mut ap);
        assert_eq!(send_m2(&mut ap, &snonce1, &ptk1[..16]).len(), 1);
        assert_eq!(send_m2(&mut ap, &snonce2, &ptk2[..16]).len(), 1);
        send_m4(&mut ap, final_kck);
        assert!(ap.is_associated(&mac_to_bytes("02:00:00:00:ab:cd")));
    }
}

#[test]
fn encrypted_m4_is_rejected_even_when_key_data_is_validly_wrapped() {
    let snonce: [u8; 32] = from_hex(vectors()["crypto"]["snonce"].as_str().unwrap())
        .try_into()
        .unwrap();
    let ptk = ptk_for_snonce(&snonce);
    let mut ap = fixtured_wpa2_ap();
    begin_wpa2(&mut ap);
    assert_eq!(send_m2(&mut ap, &snonce, &ptk[..16]).len(), 1);

    let key_info = dot11::KeyInfo {
        encrypted_key_data: true,
        secure: true,
        has_key_mic: true,
        key_type: true,
        key_descriptor_type_version: 2,
        ..Default::default()
    };
    let build_encrypted_m4 = |key_data: &[u8]| {
        let body0 = dot11::build_eapol_key_body(key_info, 0, 2, &[0; 32], &[0; 16], key_data);
        let mic = dot11::KeyMic::select(false, false).compute(&ptk[..16], &wrap_eapol(&body0));
        let body = dot11::build_eapol_key_body(key_info, 0, 2, &[0; 32], &mic, key_data);
        let normal = dot11::build_eapol_m4(
            &mac_to_bytes("02:00:00:00:00:00"),
            &mac_to_bytes("02:00:00:00:ab:cd"),
            &ptk[..16],
            2,
            0,
            dot11::KeyMic::select(false, false),
        );
        let mut frame = normal[..32].to_vec();
        frame.extend_from_slice(&wrap_eapol(&body));
        framed(frame)
    };

    ap.handle_incoming(&build_encrypted_m4(&[0x31; 24]));
    assert!(!ap.is_associated(&mac_to_bytes("02:00:00:00:ab:cd")));

    let extra = vec![2, 5, 0x11, 0x22, 0x33, 0x44, 0x55];
    let wrapped = crypto::aes_wrap(&ptk[16..32], &crypto::pad_key_data(extra));
    ap.handle_incoming(&build_encrypted_m4(&wrapped));
    assert!(
        !ap.is_associated(&mac_to_bytes("02:00:00:00:ab:cd")),
        "Encrypted Key Data is not valid on M4"
    );
}

#[test]
fn joining_client_seeds_gtk_and_igtk_replay_windows_from_m3() {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let sta_mac = mac_to_bytes("02:00:00:00:00:77");
    let mut ap = Ap::new("secure-net", "device-password", ap_mac, 1);
    ap.enable_sae();

    let broadcast = [
        [0xff; 6].as_slice(),
        ap_mac.as_slice(),
        &[0x08, 0x00],
        b"captured before join",
    ]
    .concat();
    let captured_group_data = ap.deliver_to_station(&broadcast).remove(0);
    let captured_group_deauth = ap.group_deauth(3);

    let mut station = Client::new("secure-net", "device-password", sta_mac);
    station.enable_sae();
    drive(&mut ap, &mut station, 50);
    assert_eq!(station.connected, 4);

    assert!(
        station
            .handle_incoming(&captured_group_data)
            .to_network
            .is_empty(),
        "a GTK frame at or below M3's Key RSC must be rejected"
    );
    station.handle_incoming(&captured_group_deauth);
    assert_eq!(
        station.connected, 4,
        "a BIP frame at or below the installed IGTK IPN must be rejected"
    );

    let fresh_group_data = ap.deliver_to_station(&broadcast).remove(0);
    assert_eq!(
        station.handle_incoming(&fresh_group_data).to_network.len(),
        1,
        "the next group PN remains usable"
    );
    station.handle_incoming(&ap.group_deauth(3));
    assert_eq!(station.connected, 0, "the next IGTK IPN remains usable");
}

#[test]
fn client_drops_a_reflected_sae_commit() {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let sta_mac = mac_to_bytes("02:00:00:00:00:78");
    let mut ap = Ap::new("secure-net", "device-password", ap_mac, 1);
    ap.enable_sae();
    let mut station = Client::new("secure-net", "device-password", sta_mac);
    station.enable_sae();

    let own_commit = station.handle_incoming(&ap.beacon_frame()).frames.remove(0);
    let parsed = parse(&own_commit);
    let payload = dot11::parse_auth(&parsed.body)
        .expect("client SAE commit")
        .payload
        .to_vec();
    let reflected = framed(dot11::build_sae_auth(
        &sta_mac,
        &ap_mac,
        &ap_mac,
        0,
        0,
        1,
        dot11::STATUS_SAE_H2E,
        &payload,
    ));
    assert!(
        station.handle_incoming(&reflected).frames.is_empty(),
        "a reflected scalar/element must not produce a Confirm"
    );
}

#[test]
fn distinct_sae_commit_from_an_incomplete_mac_requires_a_token() {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let mut ap = Ap::new("turtlenet", "password1234", ap_mac, 1);
    ap.enable_sae();

    assert_eq!(
        ap.handle_incoming(&sae_commit_with_status(dot11::STATUS_SAE_H2E))
            .frames
            .len(),
        2
    );
    let response = ap.handle_incoming(&sae_commit_with_status(dot11::STATUS_SAE_H2E));
    assert_eq!(response.frames.len(), 1);
    let response = parse(&response.frames[0]);
    let auth = dot11::parse_auth(&response.body).expect("anti-clogging response");
    assert_eq!(auth.status, dot11::STATUS_ANTI_CLOGGING_TOKEN_REQ);
}

#[test]
fn auth_and_malformed_assoc_requests_are_rate_limited_per_mac() {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let sta_mac = mac_to_bytes("02:00:00:00:00:79");
    let mut ap = Ap::new("secure-net", "device-password", ap_mac, 1);
    let auth = framed(dot11::build_auth_req(&ap_mac, &sta_mac, 0));

    for _ in 0..16 {
        assert_eq!(ap.handle_incoming(&auth).frames.len(), 1);
    }
    assert!(
        ap.handle_incoming(&auth).frames.is_empty(),
        "the per-MAC authentication burst must be bounded"
    );

    let assoc_mac = mac_to_bytes("02:00:00:00:00:7a");
    let mut malformed = dot11::build_assoc_req(&ap_mac, &assoc_mac, b"secure-net", 0);
    malformed.truncate(28); // fixed association fields, no RSN element
    let malformed = framed(malformed);
    for _ in 0..8 {
        assert_eq!(
            ap.handle_incoming(&malformed).frames.len(),
            1,
            "invalid requests are still explicitly rejected inside the burst"
        );
    }
    assert!(
        ap.handle_incoming(&malformed).frames.is_empty(),
        "malformed association floods must also be bounded"
    );
}

// ---------------------------------------------------------------------------
// Key/packet-number binding, PMF enforcement, and replay-counter scoping.
// ---------------------------------------------------------------------------

fn ccmp_pn(radiotap_frame: &[u8]) -> u64 {
    parse(radiotap_frame).ccmp_pn().expect("CCMP frame")
}

/// Drive the golden WPA2 fixture through a complete 4-way and return the AP.
fn fixtured_wpa2_connected() -> (Ap, [u8; 6]) {
    let v = vectors();
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let sta = mac_to_bytes("02:00:00:00:ab:cd");
    let mut ap = fixtured_wpa2_ap();
    let kck: [u8; 16] = from_hex(v["crypto"]["kck"].as_str().unwrap())
        .try_into()
        .unwrap();
    ap.handle_incoming(&from_hex(
        v["incoming"]["assoc_req"]["bytes"].as_str().unwrap(),
    ));
    ap.handle_incoming(&from_hex(
        v["frames"]["eapol_m2_incoming"]["bytes"].as_str().unwrap(),
    ));
    ap.handle_incoming(&framed(dot11::build_eapol_m4(
        &ap_mac,
        &sta,
        &kck,
        2,
        0,
        dot11::KeyMic::select(false, false),
    )));
    assert!(ap.is_associated(&sta));
    (ap, sta)
}

#[test]
fn a_second_four_way_does_not_reset_the_packet_number_under_the_old_key() {
    let v = vectors();
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let (mut ap, sta) = fixtured_wpa2_connected();
    let kck: [u8; 16] = from_hex(v["crypto"]["kck"].as_str().unwrap())
        .try_into()
        .unwrap();
    let snonce: [u8; 32] = from_hex(v["crypto"]["snonce"].as_str().unwrap())
        .try_into()
        .unwrap();
    let old_tk = ap.station_tk(&sta).expect("installed pairwise key");

    let eth = [
        sta.as_slice(),
        ap_mac.as_slice(),
        &[0x08, 0x00],
        &[0x41; 40][..],
    ]
    .concat();
    let mut pns: Vec<u64> = (0..3)
        .map(|_| ccmp_pn(&ap.deliver_to_station(&eth)[0]))
        .collect();
    assert_eq!(pns, vec![1, 2, 3]);

    // A repeated Association Request — which anyone can forge for a non-PMF
    // station — makes the AP start a second 4-way. The associated station keeps
    // its installed PTK and keeps receiving downlink throughout.
    ap.test_clear_auth_backoff();
    let out = ap.handle_incoming(&from_hex(
        v["incoming"]["assoc_req"]["bytes"].as_str().unwrap(),
    ));
    let m1_replay = out
        .frames
        .iter()
        .filter_map(|f| {
            let p = parse(f);
            p.is_eapol()
                .then(|| p.eapol_key_body().and_then(dot11::EapolKey::parse))
                .flatten()
        })
        .map(|key| key.key_replay_counter)
        .next()
        .expect("the AP sent a fresh message 1");

    // The station answers with a valid message 2 (same ANonce fixture, so the
    // same KCK verifies). Nothing may be installed from it — and in particular
    // the transmit packet number must NOT restart while the old TK is still the
    // transmit key, which would replay CCMP nonces under a key that has already
    // used them.
    let m2 = dot11::build_eapol_m2(dot11::EapolM2Params {
        bssid: &ap_mac,
        sta: &sta,
        snonce: &snonce,
        kck: &kck,
        supp_rsn: &dot11::RSN,
        replay_counter: m1_replay,
        sc: 0,
        mic: dot11::KeyMic::select(false, false),
        oci: None,
    });
    assert_eq!(ap.handle_incoming(&framed(m2)).frames.len(), 1, "m2 -> m3");
    assert_eq!(
        ap.station_tk(&sta).expect("still keyed"),
        old_tk,
        "the old PTK is still the transmit key until message 4"
    );

    pns.push(ccmp_pn(&ap.deliver_to_station(&eth)[0]));
    assert_eq!(
        pns,
        vec![1, 2, 3, 4],
        "the packet number keeps advancing under the unchanged key"
    );
}

#[test]
fn a_group_rekey_never_resets_the_group_packet_number_under_an_unchanged_key() {
    for per_sta_vif in [false, true] {
        let mut ap = fixtured_wpa2_ap();
        if per_sta_vif {
            ap.enable_per_sta_vif();
        }
        let v = vectors();
        let ap_mac = mac_to_bytes("02:00:00:00:00:00");
        let sta = mac_to_bytes("02:00:00:00:ab:cd");
        let kck: [u8; 16] = from_hex(v["crypto"]["kck"].as_str().unwrap())
            .try_into()
            .unwrap();
        ap.handle_incoming(&from_hex(
            v["incoming"]["assoc_req"]["bytes"].as_str().unwrap(),
        ));
        ap.handle_incoming(&from_hex(
            v["frames"]["eapol_m2_incoming"]["bytes"].as_str().unwrap(),
        ));
        ap.handle_incoming(&framed(dot11::build_eapol_m4(
            &ap_mac,
            &sta,
            &kck,
            2,
            0,
            dot11::KeyMic::select(false, false),
        )));

        let eth = [
            &[0xffu8; 6][..],
            ap_mac.as_slice(),
            &[0x08, 0x00],
            &[0x42; 40][..],
        ]
        .concat();
        for expected in 1..=3u64 {
            assert_eq!(ccmp_pn(&ap.deliver_to_station(&eth)[0]), expected);
        }

        let before = ap.gtk();
        ap.rekey_gtk();
        let after = ap.gtk();
        let pn = ccmp_pn(&ap.deliver_to_station(&eth)[0]);
        // Either the group key rotated (so a restarted PN is a fresh nonce
        // space) or the PN kept climbing. Resetting the counter while the key
        // the group transmit path uses stays the same is keystream reuse.
        assert!(
            after != before || pn > 3,
            "per_sta_vif={per_sta_vif}: group PN restarted at {pn} under an unchanged GTK"
        );
    }
}

#[test]
fn an_unprotected_authentication_cannot_tear_down_a_pmf_association() {
    let sta = mac_to_bytes("02:00:00:00:ab:cd");
    let (mut ap, _station) = sae_pair(sta);
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");

    // Spoofed open-system Authentication with the victim's address: no
    // credential, no protection. It must not disturb the session — the SA Query
    // the (Re)Association path performs would be worthless otherwise.
    ap.test_clear_auth_backoff();
    let out = ap.handle_incoming(&framed(dot11::build_auth_req(&ap_mac, &sta, 0)));
    assert!(
        ap.is_associated(&sta),
        "a spoofed open-auth frame must not deauthenticate a PMF station"
    );
    assert_eq!(out.frames.len(), 1, "the AP challenges with an SA Query");
    assert_eq!(parse(&out.frames[0]).subtype(), dot11::SUBTYPE_ACTION);

    // A spoofed SAE commit is the same attack via the other algorithm: it used
    // to replace the station's PMK and clear `sae_confirmed`, after which every
    // future association was refused as "SAE confirm not complete".
    ap.test_clear_auth_backoff();
    ap.handle_incoming(&framed(dot11::build_sae_auth(
        &ap_mac,
        &sta,
        &ap_mac,
        0,
        0,
        1,
        dot11::STATUS_SAE_H2E,
        &[0x11; 2 + 3 * 32],
    )));
    assert!(
        ap.is_associated(&sta),
        "a spoofed SAE commit must not disturb a PMF association either"
    );
}

#[test]
fn an_unanswered_sa_query_eventually_retires_the_association() {
    let sta = mac_to_bytes("02:00:00:00:ab:cd");
    let (mut ap, _station) = sae_pair(sta);
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");

    ap.test_clear_auth_backoff();
    ap.handle_incoming(&framed(dot11::build_auth_req(&ap_mac, &sta, 0)));
    assert!(ap.is_associated(&sta), "session held pending the SA Query");

    // The station never answers, so it really is gone: the AP must retire it
    // rather than refuse its genuine reconnect forever.
    ap.test_expire_sa_query();
    ap.tick();
    assert!(
        !ap.is_associated(&sta),
        "an unanswered SA Query must not become a permanent lockout"
    );
}

#[test]
fn an_open_authentication_resets_the_negotiated_key_hierarchy() {
    let sta = mac_to_bytes("02:00:00:00:ab:cd");
    let (mut ap, mut station) = sae_pair(sta);
    assert!(ap.station_uses_sha256(&sta), "SAE negotiated SHA-256 + PMF");
    disconnect_pair(&mut ap, &mut station, sta);

    // A plain open-system Authentication starts a fresh session. The key
    // hierarchy belongs to the retired session, not to the MAC address: leaving
    // it set made the station's next WPA2-PSK 4-way derive with the wrong hash
    // so every message 2 MIC failed.
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    ap.test_clear_auth_backoff();
    ap.handle_incoming(&framed(dot11::build_auth_req(&ap_mac, &sta, 0)));
    assert!(
        !ap.station_uses_sha256(&sta),
        "the SHA-256 key hierarchy must not survive a new authentication"
    );
}

#[test]
fn eapol_is_only_recognised_in_an_unprotected_data_frame() {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let sta = mac_to_bytes("02:00:00:00:ab:cd");
    let anonce = [0x33; 32];
    let m1 = dot11::build_eapol_m1(&ap_mac, &sta, &anonce, 1, 0, dot11::KeyMic::HmacSha1);
    assert!(dot11::Dot11::parse(&m1).unwrap().is_eapol());

    // Same LLC/SNAP + EAPOL body, but the frame claims to be Management. Only
    // Data frames carry an LLC/SNAP payload, so this must not be parsed as a
    // key message on the uncontrolled port.
    let mut as_mgmt = m1.clone();
    as_mgmt[0] = (as_mgmt[0] & !0x0c) | (dot11::TYPE_MGMT << 2);
    let parsed = dot11::Dot11::parse(&as_mgmt).unwrap();
    assert_eq!(parsed.frame_type(), dot11::TYPE_MGMT);
    assert!(!parsed.is_eapol(), "a Management frame is never EAPOL");

    // And a frame whose Protected bit is set carries ciphertext by definition.
    let mut as_protected = m1;
    as_protected[1] |= dot11::FC_PROTECTED;
    assert!(!dot11::Dot11::parse(&as_protected).unwrap().is_eapol());
}

#[test]
fn uplink_replay_counters_are_kept_per_traffic_identifier() {
    let (mut ap, sta) = fixtured_wpa2_connected();
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let tk = ap.station_tk(&sta).expect("installed pairwise key");

    let send = |ap: &mut Ap, tid: u8, pn: u64, label: &[u8]| -> bool {
        let payload = [ap_mac.as_slice(), sta.as_slice(), &[0x08, 0x00], label].concat();
        let frame = dot11::build_ccmp_data(
            &ap_mac,
            &sta,
            &ap_mac,
            dot11::FC_TODS | dot11::FC_PROTECTED,
            0,
            pn,
            0,
            &tk,
            0x0800,
            &payload[14..],
            Some(tid),
        );
        !ap.handle_incoming(&framed(frame)).to_network.is_empty()
    };

    // A transmitter keeps one packet-number sequence per TID, so a voice frame
    // at PN 1 is perfectly valid after a best-effort frame at PN 9. Sharing one
    // counter across TIDs would silently discard it.
    assert!(send(&mut ap, 0, 9, b"best effort"));
    assert!(
        send(&mut ap, 6, 1, b"voice"),
        "a fresh TID has its own replay window"
    );
    // Replays within a TID are still rejected.
    assert!(!send(&mut ap, 6, 1, b"voice replay"));
    assert!(!send(&mut ap, 0, 9, b"best effort replay"));
    assert!(send(&mut ap, 6, 2, b"voice next"));
}
