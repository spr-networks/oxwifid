//! Assert the Rust 802.11 frame builders/parsers match the reference `ap.py`
//! (captured via scapy) byte-for-byte.

use barely_ap::dot11;
use barely_ap::util::{bytes_to_mac, from_hex, mac_to_bytes, to_hex};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors.json")).expect("vectors.json parses")
}

/// Prepend the TX radiotap header the way `sendp` does.
fn with_radiotap(frame: &[u8]) -> Vec<u8> {
    let mut v = dot11::RADIOTAP_TX.to_vec();
    v.extend_from_slice(frame);
    v
}

fn mac6(s: &str) -> [u8; 6] {
    mac_to_bytes(s)
}

const FIXED_TS: u64 = 0x0011_2233_4455_6677;

#[test]
fn beacon_matches() {
    let v = vectors();
    let f = &v["frames"]["beacon"];
    let built = dot11::build_beacon(&mac6("02:00:00:00:00:00"), b"turtlenet", 1, FIXED_TS, &dot11::RSN);
    assert_eq!(to_hex(&with_radiotap(&built)), f["bytes"].as_str().unwrap());
}

#[test]
fn beacon_5ghz_matches() {
    let v = vectors();
    let f = &v["frames"]["beacon_5ghz"];
    let built = dot11::build_beacon(&mac6("02:00:00:00:00:00"), b"turtlenet", 36, FIXED_TS, &dot11::RSN);
    assert_eq!(to_hex(&with_radiotap(&built)), f["bytes"].as_str().unwrap());
}

#[test]
fn band_aware_ies_differ_correctly() {
    // 2.4 GHz advertises a DS Parameter Set (id 3) and Extended Rates (id 50);
    // 5 GHz advertises neither and uses an OFDM-only rate set.
    let ies_24 = dot11::make_beacon_ies(b"x", 6);
    let ies_5 = dot11::make_beacon_ies(b"x", 36);
    assert!(has_ie(&ies_24, 3), "2.4 GHz must carry a DS Parameter Set");
    assert!(has_ie(&ies_24, 50), "2.4 GHz must carry Extended Supported Rates");
    assert!(!has_ie(&ies_5, 3), "5 GHz must not carry a DS Parameter Set");
    // 5 GHz supported rates must not include any CCK (DSSS) rates
    let rates_5 = ie_payload(&ies_5, 1).unwrap();
    for r in rates_5 {
        let mbps2 = r & 0x7f; // strip basic bit
        assert!(![2, 4, 11, 22].contains(&mbps2), "5 GHz must not advertise CCK rate {mbps2}");
    }
}

fn has_ie(ies: &[u8], id: u8) -> bool {
    ie_payload(ies, id).is_some()
}

fn ie_payload(ies: &[u8], id: u8) -> Option<Vec<u8>> {
    let mut i = 0;
    while i + 2 <= ies.len() {
        let eid = ies[i];
        let len = ies[i + 1] as usize;
        if i + 2 + len > ies.len() {
            break;
        }
        if eid == id {
            return Some(ies[i + 2..i + 2 + len].to_vec());
        }
        i += 2 + len;
    }
    None
}

#[test]
fn bip_cmac_protect_verify_roundtrip() {
    let igtk = from_hex("000102030405060708090a0b0c0d0e0f");
    let igtk: [u8; 16] = igtk.try_into().unwrap();
    let bssid = mac6("02:00:00:00:00:00");
    let frame = dot11::build_group_deauth_bip(&bssid, &igtk, 4, &[0, 0, 0, 0, 0, 1], 3, 0x10);
    let parsed = dot11::Dot11::parse(&frame).unwrap();
    assert_eq!(parsed.subtype(), dot11::SUBTYPE_DEAUTH);
    assert!(
        dot11::bip_verify(&igtk, parsed.fc0, parsed.fc1, &parsed.addr1, &parsed.addr2, &parsed.addr3, &parsed.body),
        "valid BIP MME must verify"
    );
    // wrong key fails
    let mut wrong = igtk;
    wrong[0] ^= 0xff;
    assert!(!dot11::bip_verify(&wrong, parsed.fc0, parsed.fc1, &parsed.addr1, &parsed.addr2, &parsed.addr3, &parsed.body));
}

#[test]
fn wpa3_security_tail_advertises_pmf_and_sae() {
    let tail = dot11::security_tail(true);
    // RSN element present with AKM = SAE (00-0F-AC:8) and group mgmt = BIP (..:6)
    assert!(has_ie(&tail, 48), "WPA3 must include an RSN element");
    assert!(has_ie(&tail, 0xf4), "WPA3 must include an RSNXE (H2E)");
    let rsn = ie_payload(&tail, 48).unwrap();
    // AKM suite (last of the suite lists before caps) must be SAE
    assert!(rsn.windows(4).any(|w| w == [0x00, 0x0f, 0xac, 0x08]), "AKM SAE present");
    assert!(rsn.windows(4).any(|w| w == [0x00, 0x0f, 0xac, 0x06]), "BIP group-mgmt cipher present");
    // RSN capabilities: MFPR | MFPC set
    // caps are the 2 bytes after the AKM list; just confirm 0xc0 byte appears
    assert!(rsn.contains(&0xc0), "MFPR|MFPC capability bits set");
    // WPA2 tail has neither RSNXE nor SAE
    let tail2 = dot11::security_tail(false);
    assert!(!has_ie(&tail2, 0xf4));
}

#[test]
fn tx_radiotap_encodes_band() {
    // 2.4 GHz channel 6 -> freq 2437, flags 2GHz|CCK, rate 1 Mbps (2 * 500k)
    let rt24 = dot11::build_radiotap_tx(6);
    let it_len = u16::from_le_bytes([rt24[2], rt24[3]]) as usize;
    assert_eq!(it_len, rt24.len());
    let present = u32::from_le_bytes([rt24[4], rt24[5], rt24[6], rt24[7]]);
    assert_eq!(present, (1 << 2) | (1 << 3), "Rate + Channel present");
    assert_eq!(rt24[8], 2, "1 Mbps in 500 kbps units");
    let freq24 = u16::from_le_bytes([rt24[10], rt24[11]]);
    let flags24 = u16::from_le_bytes([rt24[12], rt24[13]]);
    assert_eq!(freq24, 2437);
    assert_eq!(flags24, 0x0080 | 0x0020, "2GHz | CCK");

    // 5 GHz channel 36 -> freq 5180, flags 5GHz|OFDM, rate 6 Mbps (12 * 500k)
    let rt5 = dot11::build_radiotap_tx(36);
    assert_eq!(rt5[8], 12, "6 Mbps in 500 kbps units");
    let freq5 = u16::from_le_bytes([rt5[10], rt5[11]]);
    let flags5 = u16::from_le_bytes([rt5[12], rt5[13]]);
    assert_eq!(freq5, 5180);
    assert_eq!(flags5, 0x0100 | 0x0040, "5GHz | OFDM");

    // A frame carrying this radiotap must still strip back to the 802.11 body.
    let mut frame = rt5.clone();
    frame.extend_from_slice(&[0x80, 0x00, 0x00, 0x00]); // dummy 802.11 start
    let body = dot11::strip_radiotap(&frame).unwrap();
    assert_eq!(body, &[0x80, 0x00, 0x00, 0x00]);
}

#[test]
fn probe_resp_matches() {
    let v = vectors();
    let f = &v["frames"]["probe_resp"];
    let built = dot11::build_probe_resp(
        &mac6("02:00:00:00:00:00"),
        &mac6(f["sta"].as_str().unwrap()),
        b"turtlenet",
        1,
        FIXED_TS,
        16,
        &dot11::RSN,
    );
    assert_eq!(to_hex(&with_radiotap(&built)), f["bytes"].as_str().unwrap());
}

#[test]
fn auth_resp_matches() {
    let v = vectors();
    let f = &v["frames"]["auth_resp"];
    let built = dot11::build_auth(&mac6("02:00:00:00:00:00"), &mac6(f["sta"].as_str().unwrap()), 16);
    assert_eq!(to_hex(&with_radiotap(&built)), f["bytes"].as_str().unwrap());
}

#[test]
fn assoc_resp_matches() {
    let v = vectors();
    let f = &v["frames"]["assoc_resp"];
    let built = dot11::build_assoc_resp(
        &mac6("02:00:00:00:00:00"),
        &mac6(f["sta"].as_str().unwrap()),
        b"turtlenet",
        1,
        f["aid"].as_u64().unwrap() as u16,
        16,
        dot11::SUBTYPE_ASSOC_RESP,
    );
    assert_eq!(to_hex(&with_radiotap(&built)), f["bytes"].as_str().unwrap());
}

#[test]
fn eapol_m1_matches() {
    let v = vectors();
    let f = &v["frames"]["eapol_m1"];
    let anonce: [u8; 32] = from_hex(f["anonce"].as_str().unwrap()).try_into().unwrap();
    let built = dot11::build_eapol_m1(&mac6("02:00:00:00:00:00"), &mac6(f["sta"].as_str().unwrap()), &anonce, 32, false);
    assert_eq!(to_hex(&with_radiotap(&built)), f["bytes"].as_str().unwrap());
}

#[test]
fn eapol_m3_matches() {
    let v = vectors();
    let f = &v["frames"]["eapol_m3"];
    let anonce: [u8; 32] = from_hex(f["anonce"].as_str().unwrap()).try_into().unwrap();
    let kck = from_hex(f["kck"].as_str().unwrap());
    let kek = from_hex(f["kek"].as_str().unwrap());
    let gtk = from_hex(f["gtk"].as_str().unwrap());
    let built = dot11::build_eapol_m3(&mac6("02:00:00:00:00:00"), &mac6(f["sta"].as_str().unwrap()), &anonce, &kck, &kek, &gtk, None, 48, false);
    assert_eq!(to_hex(&with_radiotap(&built)), f["bytes"].as_str().unwrap());
}

#[test]
fn data_downlink_matches() {
    let v = vectors();
    let f = &v["frames"]["data_downlink"];
    let tk = from_hex(f["tk"].as_str().unwrap());
    let inner = from_hex(f["inner_payload"].as_str().unwrap());
    let sta = mac6(f["sta"].as_str().unwrap());
    let bss = mac6(f["bss_mac"].as_str().unwrap());
    let src = mac6(f["src"].as_str().unwrap());
    let built = dot11::build_ccmp_data(
        &sta,
        &bss,
        &src,
        dot11::FC_FROMDS | dot11::FC_PROTECTED,
        f["sc"].as_u64().unwrap() as u16,
        f["pn"].as_u64().unwrap(),
        f["key_id"].as_u64().unwrap() as u8,
        &tk,
        f["ethertype"].as_u64().unwrap() as u16,
        &inner,
    );
    assert_eq!(to_hex(&built), f["bytes"].as_str().unwrap());
}

#[test]
fn data_uplink_decrypts() {
    let v = vectors();
    let f = &v["frames"]["data_uplink"];
    let tk = from_hex(f["tk"].as_str().unwrap());
    let raw = from_hex(f["bytes"].as_str().unwrap());
    let frame = dot11::Dot11::parse(dot11::strip_radiotap(&raw).unwrap()).unwrap();
    assert!(frame.to_ds() && frame.protected());
    let eth = dot11::decrypt_ccmp(&frame, &tk, false).expect("uplink decrypts");
    assert_eq!(to_hex(&eth), f["decrypted_eth"].as_str().unwrap());
}

#[test]
fn data_uplink_qos_decrypts() {
    // Real stations send QoS data frames; the QoS TID changes nonce/AAD.
    let v = vectors();
    let f = &v["frames"]["data_uplink_qos"];
    let tk = from_hex(f["tk"].as_str().unwrap());
    let raw = from_hex(f["bytes"].as_str().unwrap());
    let frame = dot11::Dot11::parse(dot11::strip_radiotap(&raw).unwrap()).unwrap();
    assert!(frame.to_ds() && frame.protected());
    assert!(frame.qos.is_some(), "QoS control must be parsed");
    let eth = dot11::decrypt_ccmp(&frame, &tk, false).expect("QoS uplink decrypts");
    assert_eq!(to_hex(&eth), f["decrypted_eth"].as_str().unwrap());
}

#[test]
fn ccmp_roundtrip_rust_only() {
    // Rust encrypts, Rust decrypts — an internal consistency check.
    let tk = from_hex(vectors()["crypto"]["tk"].as_str().unwrap());
    let sta = mac6("02:00:00:00:ab:cd");
    let ap = mac6("02:00:00:00:00:00");
    let inner = b"the quick brown fox jumps over the lazy dog";
    let frame_bytes = dot11::build_ccmp_data(&sta, &ap, &ap, dot11::FC_FROMDS | dot11::FC_PROTECTED, 0x10, 0x42, 0, &tk, 0x0800, inner);
    let frame = dot11::Dot11::parse(&frame_bytes).unwrap();
    let eth = dot11::decrypt_ccmp(&frame, &tk, true).expect("roundtrip decrypts");
    // dst=addr1=sta, src=addr3=ap, ethertype 0800, then inner
    assert_eq!(&eth[0..6], &sta);
    assert_eq!(&eth[6..12], &ap);
    assert_eq!(&eth[12..14], &[0x08, 0x00]);
    assert_eq!(&eth[14..], &inner[..]);
}

// ---------------------------------------------------------------------------
// Parser checks against incoming client frames
// ---------------------------------------------------------------------------

#[test]
fn parse_probe_req_named() {
    let v = vectors();
    let f = &v["incoming"]["probe_req_named"];
    let raw = from_hex(f["bytes"].as_str().unwrap());
    let frame = dot11::Dot11::parse(dot11::strip_radiotap(&raw).unwrap()).unwrap();
    assert_eq!(frame.frame_type(), dot11::TYPE_MGMT);
    assert_eq!(frame.subtype(), dot11::SUBTYPE_PROBE_REQ);
    assert_eq!(bytes_to_mac(&frame.addr2), f["addr2"].as_str().unwrap());
    let ssid = dot11::find_ssid(&frame.body).unwrap();
    assert_eq!(String::from_utf8(ssid).unwrap(), f["ssid"].as_str().unwrap());
}

#[test]
fn parse_probe_req_empty() {
    let v = vectors();
    let f = &v["incoming"]["probe_req_empty"];
    let raw = from_hex(f["bytes"].as_str().unwrap());
    let frame = dot11::Dot11::parse(dot11::strip_radiotap(&raw).unwrap()).unwrap();
    let ssid = dot11::find_ssid(&frame.body).unwrap();
    assert_eq!(ssid.len(), 0);
}

#[test]
fn parse_auth_req() {
    let v = vectors();
    let f = &v["incoming"]["auth_req"];
    let raw = from_hex(f["bytes"].as_str().unwrap());
    let frame = dot11::Dot11::parse(dot11::strip_radiotap(&raw).unwrap()).unwrap();
    assert_eq!(frame.subtype(), dot11::SUBTYPE_AUTH);
    assert_eq!(bytes_to_mac(&frame.addr1), f["addr1"].as_str().unwrap());
    assert_eq!(bytes_to_mac(&frame.addr2), f["addr2"].as_str().unwrap());
}

#[test]
fn parse_assoc_req() {
    let v = vectors();
    let f = &v["incoming"]["assoc_req"];
    let raw = from_hex(f["bytes"].as_str().unwrap());
    let frame = dot11::Dot11::parse(dot11::strip_radiotap(&raw).unwrap()).unwrap();
    assert_eq!(frame.subtype(), dot11::SUBTYPE_ASSOC_REQ);
    assert_eq!(bytes_to_mac(&frame.addr1), f["addr1"].as_str().unwrap());
    // SSID present in the IE list after the fixed Dot11AssoReq body (cap+listen = 4 bytes)
    let ssid = dot11::find_ssid(&frame.body[4..]).unwrap();
    assert_eq!(String::from_utf8(ssid).unwrap(), "turtlenet");
}

#[test]
fn parse_eapol_m2() {
    let v = vectors();
    let f = &v["frames"]["eapol_m2_incoming"];
    let raw = from_hex(f["bytes"].as_str().unwrap());
    let frame = dot11::Dot11::parse(dot11::strip_radiotap(&raw).unwrap()).unwrap();
    assert!(frame.to_ds());
    assert!(frame.is_eapol());
    let payload = frame.eapol_key_body().unwrap();
    let ek = dot11::EapolKey::parse(payload).unwrap();
    assert_eq!(to_hex(&ek.key_nonce), f["snonce"].as_str().unwrap());
    assert_eq!(to_hex(&ek.key_mic), f["key_mic"].as_str().unwrap());
    assert_eq!(bytes_to_mac(&frame.addr1), f["addr1"].as_str().unwrap());
    assert_eq!(bytes_to_mac(&frame.addr2), f["addr2"].as_str().unwrap());
}
