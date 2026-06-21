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
    let built = dot11::build_beacon(&mac6("02:00:00:00:00:00"), b"turtlenet", 1, FIXED_TS, &dot11::RSN, b"US");
    assert_eq!(to_hex(&with_radiotap(&built)), f["bytes"].as_str().unwrap());
}

#[test]
fn beacon_5ghz_matches() {
    let v = vectors();
    let f = &v["frames"]["beacon_5ghz"];
    let built = dot11::build_beacon(&mac6("02:00:00:00:00:00"), b"turtlenet", 36, FIXED_TS, &dot11::RSN, b"US");
    assert_eq!(to_hex(&with_radiotap(&built)), f["bytes"].as_str().unwrap());
}

#[test]
fn band_aware_ies_differ_correctly() {
    // 2.4 GHz advertises a DS Parameter Set (id 3) and Extended Rates (id 50);
    // 5 GHz advertises neither and uses an OFDM-only rate set.
    let ies_24 = dot11::make_beacon_ies(b"x", 6, b"US");
    let ies_5 = dot11::make_beacon_ies(b"x", 36, b"US");
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

#[test]
fn band6_ies_are_he_only() {
    // 6 GHz: HE-only. No DSSS (3), HT (45) or VHT (191) elements; instead the HE
    // Capabilities (ext 35), HE Operation (ext 36) and HE 6 GHz Band
    // Capabilities (ext 59) elements, plus operating class 131.
    assert_eq!(dot11::channel_to_freq_6ghz(37), 6135);
    let ies = dot11::make_beacon_ies_6ghz(b"x", 37, b"US");
    assert!(!has_ie(&ies, 3), "6 GHz must not carry a DS Parameter Set");
    assert!(!has_ie(&ies, 45), "6 GHz must not carry HT Capabilities");
    assert!(!has_ie(&ies, 191), "6 GHz must not carry VHT Capabilities");
    assert!(has_ext_ie(&ies, 35), "6 GHz must carry HE Capabilities");
    assert!(has_ext_ie(&ies, 36), "6 GHz must carry HE Operation");
    assert!(has_ext_ie(&ies, 59), "6 GHz must carry HE 6 GHz Band Capabilities");
    // operating class 131 (20 MHz 6 GHz)
    assert_eq!(ie_payload(&ies, 59).unwrap()[0], 131);
}

#[test]
fn he_operation_6ghz_encodes_channel_and_present_bit() {
    let op = dot11::he_operation_6ghz(37);
    // ext_ie: [255, len, 36, params(3), bsscolor, basicmcs(2), 6ghz-info(5)]
    assert_eq!(op[0], 255);
    assert_eq!(op[2], 36, "HE Operation ext id");
    // HE Operation Parameters byte 2 bit 1 = "6 GHz Operation Information Present"
    assert_eq!(op[5] & 0x02, 0x02, "6 GHz info present bit must be set");
    // 6 GHz Operation Information primary channel = 37
    let info = &op[op.len() - 5..];
    assert_eq!(info[0], 37, "primary channel");
    assert_eq!(info[2], 37, "center freq seg0");
}

#[test]
fn multi_link_element_carries_mld_mac() {
    let mld = mac6("02:00:00:00:0a:00");
    let ml = dot11::multi_link_basic(&mld);
    // [255, len, 107(ext), control(2)=0x0000, common_len=7, mld_mac(6)]
    assert_eq!(ml[0], 255);
    assert_eq!(ml[2], 107, "Multi-Link ext id");
    assert_eq!(ml[3] & 0x07, 0, "Multi-Link Control Type = Basic");
    assert_eq!(ml[5], 7, "Common Info length");
    assert_eq!(&ml[6..12], &mld, "Common Info carries the MLD MAC");
    // EHT Capabilities present + well-formed
    let eht = dot11::eht_capabilities();
    assert_eq!(eht[0], 255);
    assert_eq!(eht[2], 108, "EHT Capabilities ext id");
}

#[test]
fn reduced_neighbor_report_advertises_6ghz_ap() {
    // A 2.4 GHz beacon advertises a co-located 6 GHz AP via RNR (id 201).
    let nb = mac6("02:00:00:00:00:06");
    let rnr = dot11::reduced_neighbor_report(&nb, 131, 37);
    assert_eq!(rnr[0], 201, "Reduced Neighbor Report element id");
    let p = ie_payload(&rnr, 201).unwrap();
    assert_eq!(p[1], 13, "TBTT Information Length");
    assert_eq!(p[2], 131, "operating class = 6 GHz (131)");
    assert_eq!(p[3], 37, "channel");
    assert_eq!(&p[5..11], &nb, "neighbour BSSID");
}

#[test]
fn btm_request_round_trips() {
    // 802.11v BSS Transition Management Request with one preferred candidate.
    let cand = dot11::neighbor_report_element(&mac6("02:00:00:00:00:09"), 115, 36);
    let body = dot11::btm_request_body(7, dot11::BTM_REQ_PREF_CAND_LIST, 0, 1, &cand);
    assert_eq!(body[0], 10, "WNM category");
    assert_eq!(body[1], 7, "BSS Transition Management Request action");
    assert_eq!(body[2], 7, "dialog token");
    assert_eq!(body[3] & 0x01, 0x01, "preferred candidate list bit");
    assert_eq!(body[6], 1, "validity interval");
    // candidate list = Neighbor Report element (id 52) carrying the BSSID
    assert_eq!(body[7], 52, "Neighbor Report element id");
    assert_eq!(&body[9..15], &mac6("02:00:00:00:00:09"));
    // a BTM Response (status 0 = accept) parses back
    let resp = [10u8, 8, 7, 0];
    assert_eq!(dot11::parse_btm_response(&resp), Some((7, 0)));
}

/// Find an Element-ID-Extension element (255) with the given extension id.
fn has_ext_ie(ies: &[u8], ext_id: u8) -> bool {
    let mut i = 0;
    while i + 2 <= ies.len() {
        let len = ies[i + 1] as usize;
        if i + 2 + len > ies.len() {
            break;
        }
        if ies[i] == 255 && len >= 1 && ies[i + 2] == ext_id {
            return true;
        }
        i += 2 + len;
    }
    false
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
    let tail = dot11::security_tail(dot11::SecurityMode::Wpa3Sae);
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
    let tail2 = dot11::security_tail(dot11::SecurityMode::Wpa2);
    assert!(!has_ie(&tail2, 0xf4));
}

#[test]
fn beacon_carries_ht_wmm_tim() {
    // 802.11n HT (45/61), WMM (221), and a beacon-only TIM (5) must be present.
    // Beacon/probe-resp IEs begin after the 24-byte MAC header + 12-byte fixed
    // fields (timestamp 8 + interval 2 + capability 2).
    let beacon = dot11::build_beacon(&mac6("02:00:00:00:00:00"), b"turtlenet", 6, 0, &dot11::RSN, b"US");
    let bies = &beacon[36..];
    assert!(has_ie(bies, 45), "HT Capabilities element");
    assert!(has_ie(bies, 61), "HT Operation element");
    assert!(has_ie(bies, 221), "WMM/WME vendor element");
    assert!(has_ie(bies, 5), "TIM element (beacon)");
    assert_eq!(ie_payload(bies, 61).unwrap()[0], 6, "HT Operation primary channel");
    assert_eq!(&ie_payload(bies, 221).unwrap()[..6], &[0x00, 0x50, 0xf2, 0x02, 0x01, 0x01]);

    // probe responses carry HT + WMM but NOT the beacon-only TIM.
    let probe = dot11::build_probe_resp(&mac6("02:00:00:00:00:00"), &mac6("02:00:00:00:ab:cd"), b"x", 6, 0, 0, &dot11::RSN, b"US");
    let pies = &probe[36..];
    assert!(has_ie(pies, 45) && has_ie(pies, 221));
    assert!(!has_ie(pies, 5), "probe response must not include a TIM");
}

#[test]
fn modern_ies_present() {
    // 5 GHz beacon advertises VHT (191/192); all advertise Extended Capabilities
    // (127, with BTM bit 19 + Beacon Protection bit 84), Supported Operating
    // Classes (59), and RRM Enabled Capabilities (70).
    let b5 = dot11::build_beacon(&mac6("02:00:00:00:00:00"), b"x", 36, 0, &dot11::RSN, b"US");
    let ies5 = &b5[36..];
    assert!(has_ie(ies5, 191) && has_ie(ies5, 192), "5 GHz must advertise VHT");
    let extcap = ie_payload(ies5, 127).unwrap();
    assert_eq!(extcap.len(), 11);
    assert!(extcap[2] & 0x08 != 0, "BSS Transition (ext cap bit 19)");
    assert!(extcap[10] & 0x10 != 0, "Beacon Protection (ext cap bit 84)");
    assert!(has_ie(ies5, 59), "Supported Operating Classes");
    assert!(has_ie(ies5, 70), "RRM Enabled Capabilities");

    // 2.4 GHz must NOT advertise VHT.
    let b24 = dot11::build_beacon(&mac6("02:00:00:00:00:00"), b"x", 6, 0, &dot11::RSN, b"US");
    assert!(!has_ie(&b24[36..], 191), "2.4 GHz must not advertise VHT");
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
        b"US",
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
        b"US",
    );
    assert_eq!(to_hex(&with_radiotap(&built)), f["bytes"].as_str().unwrap());
}

#[test]
fn eapol_m1_matches() {
    let v = vectors();
    let f = &v["frames"]["eapol_m1"];
    let anonce: [u8; 32] = from_hex(f["anonce"].as_str().unwrap()).try_into().unwrap();
    let built = dot11::build_eapol_m1(&mac6("02:00:00:00:00:00"), &mac6(f["sta"].as_str().unwrap()), &anonce, 32, dot11::KeyMic::HmacSha1);
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
    let built = dot11::build_eapol_m3(&mac6("02:00:00:00:00:00"), &mac6(f["sta"].as_str().unwrap()), &anonce, &kck, &kek, &dot11::RSN, &gtk, None, None, None, 48, dot11::KeyMic::HmacSha1);
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
