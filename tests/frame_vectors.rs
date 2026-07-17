//! Assert the Rust 802.11 frame builders/parsers match the reference `ap.py`
//! (captured via scapy) byte-for-byte.

use barely_ap::util::{bytes_to_mac, from_hex, mac_to_bytes, to_hex};
use barely_ap::{crypto, dot11};
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
    let built = dot11::build_beacon(
        &mac6("02:00:00:00:00:00"),
        b"turtlenet",
        1,
        FIXED_TS,
        &dot11::RSN,
        b"US",
        20,
        true,
        dot11::PhyMode::Vht,
        0,
    );
    assert_eq!(to_hex(&with_radiotap(&built)), f["bytes"].as_str().unwrap());
}

#[test]
fn beacon_5ghz_matches() {
    let v = vectors();
    let f = &v["frames"]["beacon_5ghz"];
    let built = dot11::build_beacon(
        &mac6("02:00:00:00:00:00"),
        b"turtlenet",
        36,
        FIXED_TS,
        &dot11::RSN,
        b"US",
        20,
        true,
        dot11::PhyMode::Vht,
        0,
    );
    assert_eq!(to_hex(&with_radiotap(&built)), f["bytes"].as_str().unwrap());
    assert_eq!(
        &built[34..36],
        &[0x11, 0x00],
        "5 GHz AP capability must match hostapd (ESS + Privacy only)"
    );
}

#[test]
fn band_aware_ies_differ_correctly() {
    // 2.4 GHz advertises a DS Parameter Set (id 3) and Extended Rates (id 50);
    // 5 GHz advertises neither and uses an OFDM-only rate set.
    let ies_24 = dot11::make_beacon_ies(
        b"x",
        6,
        b"US",
        20,
        true,
        dot11::PhyMode::Vht,
        &dot11::RSN,
        None,
        0,
    );
    let ies_5 = dot11::make_beacon_ies(
        b"x",
        36,
        b"US",
        20,
        true,
        dot11::PhyMode::Vht,
        &dot11::RSN,
        None,
        0,
    );
    assert!(has_ie(&ies_24, 3), "2.4 GHz must carry a DS Parameter Set");
    assert!(
        has_ie(&ies_24, 50),
        "2.4 GHz must carry Extended Supported Rates"
    );
    assert!(
        !has_ie(&ies_5, 3),
        "5 GHz must not carry a DS Parameter Set"
    );
    // 5 GHz supported rates must not include any CCK (DSSS) rates
    let rates_5 = ie_payload(&ies_5, 1).unwrap();
    for r in rates_5 {
        let mbps2 = r & 0x7f; // strip basic bit
        assert!(
            ![2, 4, 11, 22].contains(&mbps2),
            "5 GHz must not advertise CCK rate {mbps2}"
        );
    }
    assert_eq!(
        ie_payload(
            &dot11::make_beacon_ies(
                b"x",
                36,
                b"US",
                80,
                true,
                dot11::PhyMode::He,
                &dot11::RSN,
                None,
                0,
            ),
            59
        )
        .unwrap(),
        &[128, 0],
        "80 MHz 5 GHz BSS uses global operating class 128 like hostapd"
    );
}

#[test]
fn channel_36_80mhz_advertisements_are_consistent() {
    let ies = dot11::make_beacon_ies(
        b"rustaptest",
        36,
        b"US",
        80,
        true,
        dot11::PhyMode::Eht,
        &dot11::RSN_WPA3,
        None,
        0,
    );

    assert_eq!(
        ie_payload(&ies, 7).unwrap(),
        &[b'U', b'S', b' ', 36, 4, 23],
        "Country triplet must cover 20 MHz channels 36/40/44/48"
    );

    let ht = ie_payload(&ies, 61).unwrap();
    assert_eq!(ht[0], 36, "HT primary channel");
    assert_eq!(
        ht[1] & 0x07,
        0x05,
        "HT secondary channel is above and width is greater than 20 MHz"
    );

    let vht = ie_payload(&ies, 192).unwrap();
    assert_eq!(vht[0], 1, "VHT channel width is 80/160 MHz");
    assert_eq!(vht[1], 42, "80 MHz center-frequency segment is channel 42");
    assert_eq!(vht[2], 0, "there is no second center-frequency segment");

    assert_eq!(
        ie_payload(&ies, 59).unwrap(),
        &[128, 0],
        "global operating class 128 denotes 5 GHz 80 MHz"
    );
    assert_eq!(dot11::center_channel(36, 80, false), 42);
    assert_eq!(dot11::operating_class(36, 80, false), 128);
}

#[test]
fn band6_ies_are_he_only() {
    // 6 GHz: HE-only. No DSSS (3), HT (45) or VHT (191) elements; instead the HE
    // Capabilities (ext 35), HE Operation (ext 36) and HE 6 GHz Band
    // Capabilities (ext 59) elements, plus operating class 131.
    assert_eq!(dot11::channel_to_freq_6ghz(37), 6135);
    let ies = dot11::make_beacon_ies_6ghz(b"x", 37, b"US", 20, true, &dot11::RSN, None, 0);
    assert!(!has_ie(&ies, 3), "6 GHz must not carry a DS Parameter Set");
    assert!(!has_ie(&ies, 45), "6 GHz must not carry HT Capabilities");
    assert!(!has_ie(&ies, 191), "6 GHz must not carry VHT Capabilities");
    assert!(has_ext_ie(&ies, 35), "6 GHz must carry HE Capabilities");
    assert!(has_ext_ie(&ies, 36), "6 GHz must carry HE Operation");
    assert!(
        has_ext_ie(&ies, 59),
        "6 GHz must carry HE 6 GHz Band Capabilities"
    );
    // operating class 131 (20 MHz 6 GHz)
    assert_eq!(ie_payload(&ies, 59).unwrap()[0], 131);
}

#[test]
fn he_operation_6ghz_encodes_channel_and_present_bit() {
    let op = dot11::he_operation_6ghz(37, 20);
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
fn twt_setup_request_gets_accept_response() {
    let bssid = mac6("02:00:00:00:00:00");
    let sta = mac6("02:00:00:00:00:aa");
    // A TWT Setup Request: category 23, action 6, dialog 7, then a TWT element
    // (216) with Control=0 and a 14-octet individual TWT parameter set whose
    // Request Type has the TWT Request bit set and Setup Command = Suggest (1).
    let req_type: u16 = 0x0001 | (1 << 1); // TWT Request=1, Setup Command=Suggest
    let mut twt = vec![216u8, 15, 0x00]; // id, len, Control
    twt.extend_from_slice(&req_type.to_le_bytes()); // Request Type
    twt.extend_from_slice(&[0u8; 8]); // Target Wake Time
    twt.push(64); // Nominal Min Wake Duration
    twt.extend_from_slice(&2048u16.to_le_bytes()); // Wake Interval Mantissa
    twt.push(0); // TWT Channel
    let mut body = vec![dot11::ACTION_CATEGORY_S1G, dot11::S1G_ACT_TWT_SETUP, 7];
    body.extend_from_slice(&twt);

    let (dialog, req_twt) = dot11::parse_twt_setup(&body).expect("parses a TWT request");
    assert_eq!(dialog, 7);
    // A response (TWT Request bit clear) must NOT be treated as a request.
    let mut resp_body = body.clone();
    resp_body[6] &= !0x01; // clear TWT Request bit in Request Type low octet
    assert!(
        dot11::parse_twt_setup(&resp_body).is_none(),
        "must not answer a TWT response"
    );

    let frame = dot11::build_twt_setup_response(&bssid, &sta, dialog, &req_twt, 16);
    // Skip the 24-byte MAC header: category, action, dialog, then the TWT element.
    let b = &frame[24..];
    assert_eq!(b[0], dot11::ACTION_CATEGORY_S1G);
    assert_eq!(b[1], dot11::S1G_ACT_TWT_SETUP);
    assert_eq!(b[2], 7, "echoes dialog token");
    assert_eq!(b[3], 216, "TWT element");
    let rt = u16::from_le_bytes([b[6], b[7]]); // Request Type after id,len,control
    assert_eq!(rt & 0x0001, 0, "TWT Request bit cleared in response");
    assert_eq!(
        (rt >> 1) & 0x07,
        dot11::TWT_SETUP_CMD_ACCEPT,
        "Setup Command = Accept"
    );
    // requested wake duration echoed back
    assert_eq!(b[16], 64, "Nominal Min Wake Duration echoed");
}

#[test]
fn he_caps_advertise_twt_responder() {
    let he = dot11::he_capabilities();
    // ext_ie: [255, len, 35, HE MAC caps(6)...]; MAC caps byte0 bit2 = TWT Responder.
    assert_eq!(he[2], 35, "HE Capabilities ext id");
    assert_eq!(he[3] & 0x01, 0x01, "+HTC HE Support");
    assert_eq!(
        he[3] & 0x04,
        0x04,
        "HE MAC caps must advertise TWT Responder Support"
    );
}

#[test]
fn he_operation_disables_unconfigured_bss_color_like_hostapd() {
    let op = dot11::he_operation_5ghz();
    // [255, len, ext-id 36, params(3), BSS color, basic MCS(2)]
    assert_eq!(op[2], 36);
    assert_eq!(op[6], 0x98, "color 24 with BSS Color Disabled set");
}

#[test]
fn default_he_beacon_omits_unconfigured_mu_edca_and_spatial_reuse() {
    let ies = dot11::make_beacon_ies(
        b"x",
        36,
        b"US",
        80,
        true,
        dot11::PhyMode::He,
        &dot11::RSN_WPA3,
        None,
        0,
    );
    assert!(!has_ext_ie(&ies, 38), "MU-EDCA is not configured");
    assert!(!has_ext_ie(&ies, 39), "Spatial Reuse is not configured");
}

#[test]
fn eht_operation_preamble_puncturing() {
    // On 5 GHz without puncturing, match hostapd's short operation form: no
    // redundant Operation Information and a one-stream basic MCS requirement.
    let op0 = dot11::eht_operation(36, 80, false, 0);
    assert_eq!(op0, [0xff, 0x06, 106, 0x40, 0x11, 0x00, 0x00, 0x00]);
    // Puncturing: params bit1 set (Disabled Subchannel Bitmap Present) + the
    // 2-octet little-endian bitmap appended after CCFS1.
    let op = dot11::eht_operation(36, 80, false, 0x0004); // 3rd 20 MHz subchannel disabled
    assert_eq!(op[2], 106, "EHT Operation ext id");
    assert_eq!(
        op[3] & 0x02,
        0x02,
        "Disabled Subchannel Bitmap Present bit must be set"
    );
    assert_eq!(op[4], 0x11, "basic EHT-MCS/NSS must require only NSS1");
    let n = op.len();
    assert_eq!(
        &op[n - 2..],
        &0x0004u16.to_le_bytes(),
        "disabled-subchannel bitmap trailing"
    );
    // Puncturing requires the three-byte operation-info field plus its bitmap.
    assert_eq!(op.len(), op0.len() + 5);
    // and it appears in a be beacon
    let be = dot11::make_beacon_ies(
        b"x",
        36,
        b"US",
        80,
        true,
        dot11::PhyMode::Eht,
        &dot11::RSN,
        None,
        0x0004,
    );
    assert!(has_ext_ie(&be, 106), "be beacon carries EHT Operation");
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
    // EHT Capabilities present + well-formed; 320 MHz support bit set when wide
    let eht = dot11::eht_capabilities(320);
    assert_eq!(eht[0], 255);
    assert_eq!(eht[2], 108, "EHT Capabilities ext id");
    assert_eq!(
        eht[5] & 0x02,
        0x02,
        "EHT PHY caps must advertise 320 MHz in 6 GHz"
    );
}

#[test]
fn ap_basic_multi_link_element_carries_link_id_and_profiles() {
    let mld = mac6("02:00:00:00:0a:00");
    let link1_mac = mac6("02:00:00:00:0a:02");
    // A Per-STA Profile for the other link (link id 1), carrying a stub IE body.
    let prof = dot11::per_sta_profile(1, &link1_mac, &dot11::ie(0, b"n"));
    // subelement: [id=0, len, STA Control(2), STA Info Len(=7), MAC(6), inner...]
    assert_eq!(prof[0], 0, "Per-STA Profile subelement id");
    let sta_control = u16::from_le_bytes([prof[2], prof[3]]);
    assert_eq!(sta_control & 0x0f, 1, "Link ID in STA Control");
    assert_eq!(sta_control & 0x10, 0x10, "Complete Profile bit");
    assert_eq!(sta_control & 0x20, 0x20, "MAC Address Present bit");
    assert_eq!(prof[4], 7, "STA Info length (len + MAC)");
    assert_eq!(&prof[5..11], &link1_mac, "affiliated link MAC");

    // AP Basic ML element for link 0 with the other link's profile in Link Info.
    let ml = dot11::multi_link_ap_basic(&mld, 0, 3, &prof);
    assert_eq!(ml[0], 255);
    assert_eq!(ml[2], 107, "Multi-Link ext id");
    let control = u16::from_le_bytes([ml[3], ml[4]]);
    assert_eq!(control & 0x07, 0, "Type = Basic");
    assert_eq!(
        control, 0x0130,
        "Link ID + BSS Change Count + MLD Capabilities present"
    );
    assert_eq!(
        ml[5], 11,
        "Common Info length (len + MLD MAC + Link ID + BSS Change + MLD Caps)"
    );
    assert_eq!(&ml[6..12], &mld, "Common Info MLD MAC");
    assert_eq!(ml[12] & 0x0f, 0, "this link's Link ID = 0");
    assert_eq!(ml[13], 3, "BSS Parameters Change Count");
    assert_eq!(&ml[14..16], &[0, 0], "MLD Capabilities");
    // the Per-STA Profile for link 1 follows in Link Info
    assert_eq!(
        ml[16], 0,
        "Link Info begins with a Per-STA Profile subelement"
    );
}

#[test]
fn mld_mac_round_trips_through_ml_element() {
    let mld = mac6("02:00:00:00:0a:00");
    // A Basic ML element embedded in an IE block (e.g. an assoc request) with
    // some other IEs around it.
    let mut ies = dot11::ie(0, b"net");
    ies.extend_from_slice(&dot11::multi_link_ap_basic(&mld, 2, 0, &[]));
    ies.extend_from_slice(&dot11::ie(1, &[0x8c]));
    assert_eq!(
        dot11::parse_mld_mac(&ies),
        Some(mld),
        "extracts MLD MAC from Common Info"
    );
    // No ML element -> None.
    assert_eq!(dot11::parse_mld_mac(&dot11::ie(0, b"net")), None);
}

#[test]
fn auth_multi_link_element_matches_wpa_shape() {
    let mld = mac6("02:00:00:00:01:00");
    let ml = dot11::multi_link_auth(&mld);

    assert_eq!(&ml[..6], &[255, 10, 107, 0, 0, 7]);
    assert_eq!(&ml[6..12], &mld);
    assert_eq!(dot11::parse_mld_mac(&ml), Some(mld));
}

#[test]
fn mlo_key_kdes_match_hostap_layout() {
    let gtk: Vec<u8> = (0u8..16).collect();
    let igtk: [u8; 16] = (0u8..16).collect::<Vec<_>>().try_into().unwrap();
    let ipn = [1, 2, 3, 4, 5, 6];
    let link_mac = mac6("02:00:00:00:0a:02");
    let mut link_rsne = dot11::RSN_WPA3.to_vec();
    link_rsne.extend_from_slice(&dot11::RSNXE_H2E);

    let mut expected_gtk = vec![0xdd, 0x1b, 0x00, 0x0f, 0xac, 0x10, 0x31, 0, 0, 0, 0, 0, 0];
    expected_gtk.extend_from_slice(&gtk);
    assert_eq!(dot11::mlo_gtk_kde(3, 1, &gtk), expected_gtk);
    assert_eq!(
        dot11::parse_mlo_gtk_kde_full(&expected_gtk),
        Some((3, 1, [0; 6], gtk.clone()))
    );

    let mut expected_igtk = vec![0xdd, 0x1d, 0x00, 0x0f, 0xac, 0x11, 0x04, 0x00];
    expected_igtk.extend_from_slice(&ipn);
    expected_igtk.push(0x30);
    expected_igtk.extend_from_slice(&igtk);
    assert_eq!(dot11::mlo_igtk_kde(3, 4, &ipn, &igtk), expected_igtk);
    assert_eq!(
        dot11::parse_mlo_igtk_kde(&expected_igtk),
        Some((3, 4, ipn, igtk))
    );

    let mut expected_link = vec![
        0xdd,
        (4 + 1 + 6 + link_rsne.len()) as u8,
        0x00,
        0x0f,
        0xac,
        0x13,
        0x32,
    ];
    expected_link.extend_from_slice(&link_mac);
    expected_link.extend_from_slice(&link_rsne);
    assert_eq!(dot11::mlo_link_kde(2, &link_mac, &link_rsne), expected_link);
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
        dot11::bip_verify(
            &igtk,
            parsed.fc0,
            parsed.fc1,
            &parsed.addr1,
            &parsed.addr2,
            &parsed.addr3,
            &parsed.body
        ),
        "valid BIP MME must verify"
    );
    // wrong key fails
    let mut wrong = igtk;
    wrong[0] ^= 0xff;
    assert!(!dot11::bip_verify(
        &wrong,
        parsed.fc0,
        parsed.fc1,
        &parsed.addr1,
        &parsed.addr2,
        &parsed.addr3,
        &parsed.body
    ));
}

#[test]
fn wpa3_security_tail_advertises_pmf_and_sae() {
    let tail = dot11::security_tail(dot11::SecurityMode::Wpa3Sae);
    // RSN element present with AKM = SAE (00-0F-AC:8) and group mgmt = BIP (..:6)
    assert!(has_ie(&tail, 48), "WPA3 must include an RSN element");
    assert!(has_ie(&tail, 0xf4), "WPA3 must include an RSNXE (H2E)");
    let rsn = ie_payload(&tail, 48).unwrap();
    // AKM suite (last of the suite lists before caps) must be SAE
    assert!(
        rsn.windows(4).any(|w| w == [0x00, 0x0f, 0xac, 0x08]),
        "AKM SAE present"
    );
    assert!(
        rsn.windows(4).any(|w| w == [0x00, 0x0f, 0xac, 0x06]),
        "BIP group-mgmt cipher present"
    );
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
    let beacon = dot11::build_beacon(
        &mac6("02:00:00:00:00:00"),
        b"turtlenet",
        6,
        0,
        &dot11::RSN,
        b"US",
        20,
        true,
        dot11::PhyMode::Vht,
        0,
    );
    let bies = &beacon[36..];
    assert!(has_ie(bies, 45), "HT Capabilities element");
    assert!(has_ie(bies, 61), "HT Operation element");
    assert!(has_ie(bies, 221), "WMM/WME vendor element");
    assert!(has_ie(bies, 5), "TIM element (beacon)");
    assert_eq!(
        ie_payload(bies, 61).unwrap()[0],
        6,
        "HT Operation primary channel"
    );
    assert_eq!(
        &ie_payload(bies, 221).unwrap()[..6],
        &[0x00, 0x50, 0xf2, 0x02, 0x01, 0x01]
    );

    // probe responses carry HT + WMM but NOT the beacon-only TIM.
    let probe = dot11::build_probe_resp(
        &mac6("02:00:00:00:00:00"),
        &mac6("02:00:00:00:ab:cd"),
        b"x",
        6,
        0,
        0,
        &dot11::RSN,
        b"US",
        20,
        false,
        true,
        dot11::PhyMode::Vht,
        0,
    );
    let pies = &probe[36..];
    assert!(has_ie(pies, 45) && has_ie(pies, 221));
    assert!(!has_ie(pies, 5), "probe response must not include a TIM");
}

#[test]
fn modern_ies_present() {
    // 5 GHz beacon advertises VHT (191/192); all advertise Extended Capabilities
    // (127, with BTM bit 19), Supported Operating
    // Classes (59), and RRM Enabled Capabilities (70).
    let b5 = dot11::build_beacon(
        &mac6("02:00:00:00:00:00"),
        b"x",
        36,
        0,
        &dot11::RSN,
        b"US",
        20,
        true,
        dot11::PhyMode::Vht,
        0,
    );
    let ies5 = &b5[36..];
    assert!(
        has_ie(ies5, 191) && has_ie(ies5, 192),
        "5 GHz must advertise VHT"
    );
    let extcap = ie_payload(ies5, 127).unwrap();
    assert_eq!(extcap.len(), 11);
    assert!(extcap[2] & 0x08 != 0, "BSS Transition (ext cap bit 19)");
    assert_eq!(
        extcap[10] & 0x10,
        0,
        "default AP must not claim Beacon Protection without a BIGTK"
    );
    assert!(has_ie(ies5, 59), "Supported Operating Classes");
    assert!(has_ie(ies5, 70), "RRM Enabled Capabilities");

    // 2.4 GHz must NOT advertise VHT.
    let b24 = dot11::build_beacon(
        &mac6("02:00:00:00:00:00"),
        b"x",
        6,
        0,
        &dot11::RSN,
        b"US",
        20,
        true,
        dot11::PhyMode::Vht,
        0,
    );
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
        20,
        false,
        true,
        dot11::PhyMode::Vht,
        0,
    );
    assert_eq!(to_hex(&with_radiotap(&built)), f["bytes"].as_str().unwrap());
}

#[test]
fn auth_resp_matches() {
    let v = vectors();
    let f = &v["frames"]["auth_resp"];
    let built = dot11::build_auth(
        &mac6("02:00:00:00:00:00"),
        &mac6(f["sta"].as_str().unwrap()),
        16,
    );
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
        20,
        false,
        true,
        dot11::PhyMode::Vht,
        0,
    );
    assert_eq!(to_hex(&with_radiotap(&built)), f["bytes"].as_str().unwrap());
}

#[test]
fn eapol_m1_matches() {
    let v = vectors();
    let f = &v["frames"]["eapol_m1"];
    let anonce: [u8; 32] = from_hex(f["anonce"].as_str().unwrap()).try_into().unwrap();
    let built = dot11::build_eapol_m1(
        &mac6("02:00:00:00:00:00"),
        &mac6(f["sta"].as_str().unwrap()),
        &anonce,
        32,
        dot11::KeyMic::HmacSha1,
    );
    assert_eq!(to_hex(&with_radiotap(&built)), f["bytes"].as_str().unwrap());
}

#[test]
fn eapol_m1_mld_carries_ap_mld_mac_kde() {
    let anonce = [0x11; 32];
    let ap_mld = mac6("02:00:00:00:0a:00");
    let built = dot11::build_eapol_m1_mld(
        &mac6("02:00:00:00:00:00"),
        &mac6("02:00:00:00:ab:cd"),
        &anonce,
        32,
        dot11::KeyMic::AesCmac,
        &ap_mld,
    );
    let frame = dot11::Dot11::parse(&built).unwrap();
    let ek = dot11::EapolKey::parse(frame.eapol_key_body().unwrap()).unwrap();
    assert_eq!(dot11::parse_mac_addr_kde(&ek.key_data), Some(ap_mld));
}

#[test]
fn eapol_m3_matches() {
    let v = vectors();
    let f = &v["frames"]["eapol_m3"];
    let anonce: [u8; 32] = from_hex(f["anonce"].as_str().unwrap()).try_into().unwrap();
    let kck = from_hex(f["kck"].as_str().unwrap());
    let kek = from_hex(f["kek"].as_str().unwrap());
    let gtk = from_hex(f["gtk"].as_str().unwrap());
    let built = dot11::build_eapol_m3(
        &mac6("02:00:00:00:00:00"),
        &mac6(f["sta"].as_str().unwrap()),
        &anonce,
        &kck,
        &kek,
        &dot11::RSN,
        1,
        &gtk,
        None,
        None,
        None,
        48,
        dot11::KeyMic::HmacSha1,
    );
    assert_eq!(to_hex(&with_radiotap(&built)), f["bytes"].as_str().unwrap());
}

#[test]
fn eapol_m3_mld_uses_mlo_group_kdes() {
    let v = vectors();
    let f = &v["frames"]["eapol_m3"];
    let anonce: [u8; 32] = from_hex(f["anonce"].as_str().unwrap()).try_into().unwrap();
    let kck = from_hex(f["kck"].as_str().unwrap());
    let kek = from_hex(f["kek"].as_str().unwrap());
    let gtk = from_hex(f["gtk"].as_str().unwrap());
    let igtk: [u8; 16] = (0u8..16).collect::<Vec<_>>().try_into().unwrap();
    let ap_mld = mac6("02:00:00:00:0a:00");
    let ap_link = mac6("02:00:00:00:00:00");
    let sta = mac6(f["sta"].as_str().unwrap());
    let mut link_rsne = dot11::RSN_WPA3.to_vec();
    link_rsne.extend_from_slice(&dot11::RSNXE_H2E);

    let built = dot11::build_eapol_m3_mld(
        &ap_link,
        &sta,
        &anonce,
        &kck,
        &kek,
        &ap_mld,
        2,
        &ap_link,
        &link_rsne,
        1,
        &gtk,
        Some((4, [0; 6], igtk)),
        None,
        None,
        48,
        dot11::KeyMic::HmacSha1,
    );
    let frame = dot11::Dot11::parse(&built).unwrap();
    let ek = dot11::EapolKey::parse(frame.eapol_key_body().unwrap()).unwrap();
    let unwrapped = crypto::aes_unwrap(&kek, &ek.key_data).expect("m3 key data unwraps");

    assert_eq!(dot11::parse_mac_addr_kde(&unwrapped), Some(ap_mld));
    assert_eq!(
        dot11::parse_gtk_kde_full(&unwrapped),
        None,
        "MLD m3 must not carry the legacy GTK KDE"
    );
    assert_eq!(
        dot11::parse_igtk_kde(&unwrapped),
        None,
        "MLD m3 must not carry the legacy IGTK KDE"
    );
    let (_link_id, key_id, _pn, got_gtk) =
        dot11::parse_mlo_gtk_kde_full(&unwrapped).expect("MLO GTK KDE present");
    assert_eq!(key_id, 1);
    assert_eq!(got_gtk, gtk);
    assert_eq!(
        dot11::parse_mlo_igtk_kde(&unwrapped),
        Some((2, 4, [0; 6], igtk))
    );
    assert!(
        unwrapped
            .windows(link_rsne.len())
            .any(|w| w == link_rsne.as_slice()),
        "MLO Link KDE carries link RSNE/RSNXE"
    );
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
        None,
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
    let frame_bytes = dot11::build_ccmp_data(
        &sta,
        &ap,
        &ap,
        dot11::FC_FROMDS | dot11::FC_PROTECTED,
        0x10,
        0x42,
        0,
        &tk,
        0x0800,
        inner,
        None,
    );
    let frame = dot11::Dot11::parse(&frame_bytes).unwrap();
    let eth = dot11::decrypt_ccmp(&frame, &tk, true).expect("roundtrip decrypts");
    // dst=addr1=sta, src=addr3=ap, ethertype 0800, then inner
    assert_eq!(&eth[0..6], &sta);
    assert_eq!(&eth[6..12], &ap);
    assert_eq!(&eth[12..14], &[0x08, 0x00]);
    assert_eq!(&eth[14..], &inner[..]);
}

#[test]
fn ccmp_mld_uses_mld_addresses_for_security() {
    // 802.11be MLO: the MAC header carries the *link* addresses (so the frame
    // traverses the link) but the CCMP nonce/AAD — and thus the AP's STA lookup
    // — use the *MLD* addresses, consistent with the PTK derivation. This is the
    // exact bug behind hostapd dropping uplink data as "not associated STA
    // <link-addr>": the link-addressed CCMP context can't be mapped to the MLD STA.
    let tk = from_hex(vectors()["crypto"]["tk"].as_str().unwrap());
    let sta_link = mac6("02:00:00:00:04:00"); // STA link-0 address
    let sta_mld = mac6("02:00:00:00:04:aa"); // STA MLD address
    let ap_link = mac6("02:00:00:58:6c:d4"); // AP link-0 BSSID
    let ap_mld = mac6("02:00:00:11:22:33"); // AP MLD address
    let inner = b"mld-uplink-ccmp-payload";

    // Uplink (to-DS) frame: header = link addresses, CCMP security = MLD addresses.
    let frame_bytes = dot11::build_ccmp_data_sec(
        &ap_link,
        &sta_link,
        &ap_link, // A1/A2/A3 (MAC header, link addrs)
        &ap_mld,
        &sta_mld,
        &ap_mld, // security A1/A2/A3 (MLD addrs)
        dot11::FC_TODS | dot11::FC_PROTECTED,
        0x10,
        0x42,
        0,
        &tk,
        0x0800,
        inner,
        None,
    );
    let frame = dot11::Dot11::parse(&frame_bytes).unwrap();

    // The over-the-air header keeps the link addresses.
    assert_eq!(
        &frame.addr1, &ap_link,
        "header A1 (RA) must be the AP link BSSID"
    );
    assert_eq!(
        &frame.addr2, &sta_link,
        "header A2 (TA) must be the STA link address"
    );

    // Decrypting with the link addresses (the old, buggy single-link behaviour)
    // MUST fail — this mirrors hostapd's MLD data path rejecting the frame.
    assert!(
        dot11::decrypt_ccmp(&frame, &tk, false).is_none(),
        "link-addressed CCMP context must NOT verify (this was the bug)"
    );

    // Decrypting with the MLD security addresses succeeds, as the real AP does.
    let sec = Some((ap_mld, sta_mld, ap_mld));
    let eth = dot11::decrypt_ccmp_sec(&frame, &tk, false, sec)
        .expect("MLD-addressed CCMP context must verify");
    // Decapsulated Ethernet: dst=addr3, src=addr2 (to-DS), then the payload.
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
    assert_eq!(
        String::from_utf8(ssid).unwrap(),
        f["ssid"].as_str().unwrap()
    );
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

#[test]
fn center_channel_math() {
    use barely_ap::dot11::center_channel;
    // 5 GHz 80 MHz: 36-48 -> 42, 52-64 -> 58
    assert_eq!(center_channel(36, 80, false), 42);
    assert_eq!(center_channel(48, 80, false), 42);
    assert_eq!(center_channel(52, 80, false), 58);
    // 5 GHz 160 MHz: 36-64 -> 50, 100-128 -> 114
    assert_eq!(center_channel(36, 160, false), 50);
    assert_eq!(center_channel(100, 160, false), 114);
    // 5 GHz 40 MHz: HT40+ (36 -> 38), HT40- (40 -> 38)
    assert_eq!(center_channel(36, 40, false), 38);
    assert_eq!(center_channel(40, 40, false), 38);
    // 6 GHz 80 MHz: 1-13 -> 7; 320 MHz: 1-61 -> 31
    assert_eq!(center_channel(1, 80, true), 7);
    assert_eq!(center_channel(1, 320, true), 31);
    // 20 MHz: center == primary
    assert_eq!(center_channel(36, 20, false), 36);
}

#[test]
fn qos_data_frame_roundtrips() {
    // A QoS Data frame (TID 0) encrypts + decrypts back to the same payload, and
    // the WMM IE helpers detect/emit the WMM element.
    let tk: [u8; 16] = from_hex("000102030405060708090a0b0c0d0e0f")
        .try_into()
        .unwrap();
    let sta = mac6("02:00:00:00:00:01");
    let bss = mac6("02:00:00:00:00:00");
    let inner = b"qos payload over the air";
    // A non-trivial user priority (AC_VI) must survive build -> parse -> decrypt:
    // the TID feeds the CCMP nonce + AAD, so decryption only succeeds if the
    // parsed TID matches what was encoded.
    let frame = dot11::build_ccmp_data(
        &sta,
        &bss,
        &bss,
        dot11::FC_FROMDS | dot11::FC_PROTECTED,
        0x10,
        5,
        0,
        &tk,
        0x0800,
        inner,
        Some(5),
    );
    let parsed = dot11::Dot11::parse(&frame).unwrap();
    assert_eq!(
        parsed.subtype(),
        dot11::SUBTYPE_QOS_DATA,
        "QoS Data subtype"
    );
    assert_eq!(
        parsed.priority(),
        5,
        "user priority (TID) round-trips through parse"
    );
    let eth = dot11::decrypt_ccmp(&parsed, &tk, true).expect("QoS data decrypts at the parsed TID");
    assert_eq!(
        &eth[14..],
        inner,
        "payload survives the QoS CCMP round-trip"
    );
    // a plain Data frame stays non-QoS
    let plain = dot11::build_ccmp_data(
        &sta,
        &bss,
        &bss,
        dot11::FC_FROMDS | dot11::FC_PROTECTED,
        0x10,
        6,
        0,
        &tk,
        0x0800,
        inner,
        None,
    );
    assert!(dot11::Dot11::parse(&plain).unwrap().qos.is_none());
    // WMM IE helpers
    assert!(
        dot11::has_wmm_ie(&dot11::wmm_information()),
        "WMM info element detected"
    );
    assert!(
        !dot11::has_wmm_ie(&[221, 4, 0, 0, 0, 0]),
        "non-WMM vendor IE not matched"
    );
}

#[test]
fn wmm_element_gated_by_config() {
    // The WMM parameter element is advertised only when WMM is enabled.
    assert!(
        dot11::has_wmm_ie(&dot11::make_beacon_ies(
            b"x",
            1,
            b"US",
            20,
            true,
            dot11::PhyMode::Vht,
            &dot11::RSN,
            None,
            0
        )),
        "WMM advertised when on"
    );
    assert!(
        !dot11::has_wmm_ie(&dot11::make_beacon_ies(
            b"x",
            1,
            b"US",
            20,
            false,
            dot11::PhyMode::Vht,
            &dot11::RSN,
            None,
            0
        )),
        "no WMM element when off"
    );
    // same on 6 GHz
    assert!(dot11::has_wmm_ie(&dot11::make_beacon_ies_6ghz(
        b"x",
        37,
        b"US",
        20,
        true,
        &dot11::RSN,
        None,
        0
    )));
    assert!(!dot11::has_wmm_ie(&dot11::make_beacon_ies_6ghz(
        b"x",
        37,
        b"US",
        20,
        false,
        &dot11::RSN,
        None,
        0
    )));
}

#[test]
fn phy_mode_gates_he_and_eht() {
    use barely_ap::dot11::PhyMode;
    let ac = dot11::make_beacon_ies(
        b"x",
        36,
        b"US",
        80,
        true,
        PhyMode::Vht,
        &dot11::RSN,
        None,
        0,
    );
    let ax = dot11::make_beacon_ies(b"x", 36, b"US", 80, true, PhyMode::He, &dot11::RSN, None, 0);
    let be = dot11::make_beacon_ies(
        b"x",
        36,
        b"US",
        80,
        true,
        PhyMode::Eht,
        &dot11::RSN,
        None,
        0,
    );
    // ac (11ac/VHT): VHT Operation (id 192) but no HE / MU-EDCA / Spatial Reuse.
    assert!(has_ie(&ac, 192), "ac advertises VHT Operation");
    assert!(
        !has_ext_ie(&ac, 35),
        "ac must not advertise HE Capabilities"
    );
    assert!(!has_ext_ie(&ac, 38), "ac must not advertise MU-EDCA");
    // ax (11ax/HE): baseline HE Cap (35) + HE Op (36), no optional
    // MU-EDCA/Spatial Reuse configuration, and no EHT.
    assert!(has_ext_ie(&ax, 35), "ax advertises HE Capabilities");
    assert!(has_ext_ie(&ax, 36), "ax advertises HE Operation");
    assert!(!has_ext_ie(&ax, 38), "default ax omits MU-EDCA");
    assert!(
        !has_ext_ie(&ax, 39),
        "default ax omits Spatial Reuse Parameter Set"
    );
    assert!(!has_ext_ie(&ax, 106), "ax must not advertise EHT Operation");
    // be (11be/EHT): HE still present plus EHT Operation (ext 106).
    assert!(has_ext_ie(&be, 35), "be still advertises HE");
    assert!(has_ext_ie(&be, 106), "be advertises EHT Operation");
}

#[test]
fn wmm_tid_from_dscp() {
    // UP = ToS >> 5 (DSCP precedence). ToS = DSCP << 2.
    let mk = |ethertype: [u8; 2], tos: u8| {
        let mut e = vec![0u8; 16];
        e[12] = ethertype[0];
        e[13] = ethertype[1];
        e[14] = 0x45;
        e[15] = tos; // IPv4 ver/IHL + ToS
        e
    };
    assert_eq!(
        dot11::wmm_tid(&mk([0x08, 0x00], 0)),
        0,
        "DSCP 0 -> BE (UP 0)"
    );
    assert_eq!(
        dot11::wmm_tid(&mk([0x08, 0x00], 40 << 2)),
        5,
        "DSCP 40 (CS5) -> UP 5 (AC_VI)"
    );
    assert_eq!(
        dot11::wmm_tid(&mk([0x08, 0x00], 48 << 2)),
        6,
        "DSCP 48 (CS6) -> UP 6 (AC_VO)"
    );
    // ARP (non-IP) -> best effort
    let arp = {
        let mut e = vec![0u8; 16];
        e[12] = 0x08;
        e[13] = 0x06;
        e
    };
    assert_eq!(dot11::wmm_tid(&arp), 0, "ARP -> UP 0");
}

#[test]
fn qos_tid_written_to_frame() {
    let tk = [0u8; 16];
    let f = dot11::build_ccmp_data(
        &[1u8; 6],
        &[2u8; 6],
        &[3u8; 6],
        dot11::FC_TODS | dot11::FC_PROTECTED,
        0x10,
        1,
        0,
        &tk,
        0x0800,
        b"x",
        Some(6),
    );
    // 24-byte 3-address header, then QoS Control: byte 24 low nibble = TID.
    assert_eq!(f[0] & 0xF0, 0x80, "subtype QoS Data");
    assert_eq!(f[24] & 0x0F, 6, "QoS Control TID byte");
}
