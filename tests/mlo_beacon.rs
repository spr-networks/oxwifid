//! MLD beacon-template consistency: every affiliated link's beacon must
//! advertise its OWN Link ID in the Basic Multi-Link element and its PARTNER
//! links in the RNR MLD parameters. wpa_supplicant cross-checks these against
//! each other and against the per-STA profiles; any disagreement makes an MLO
//! client silently fall back to a single-link association.

use barely_ap::config::Config;

const L0_MAC: [u8; 6] = [0x0a, 0, 0, 0, 0xaa, 0x01];
const L1_MAC: [u8; 6] = [0x0e, 0, 0, 0, 0xaa, 0x02];

/// A parsed information element: (element id, body).
type Ie = (u8, Vec<u8>);
/// A per-STA-profile partner link: (link id, link MAC).
type MlePartner = (u8, [u8; 6]);

fn mld_ap() -> barely_ap::ap::Ap {
    let cfg = Config::from_json(
        r#"{
        "ssid": "mlo-test", "passphrase": "password1234", "key_mgmt": "sae",
        "phy": "be", "mode": "netlink", "iface": "wlan0",
        "mac": "0a:00:00:00:aa:01",
        "mld": true, "band": 2.4, "channel": 1, "width": 20, "link_id": 0,
        "mld_links": [
            { "link_id": 0, "mac": "0a:00:00:00:aa:01", "band": 2.4, "channel": 1,  "width": 20 },
            { "link_id": 1, "mac": "0e:00:00:00:aa:02", "band": 5,   "channel": 36, "width": 80 }
        ] }"#,
    )
    .expect("config parses");
    cfg.validate().expect("config valid");
    cfg.build_ap()
}

/// Walk the IE block and return (ie id, body) pairs, reassembling fragmented
/// elements (a 255-octet element followed by Fragment elements, ID 242 is for
/// subelements — the element-level Fragment ID is 254). `offset` skips the
/// beacon's fixed fields (timestamp + interval + capabilities).
fn ies(frame: &[u8], offset: usize) -> Vec<Ie> {
    let mut out: Vec<Ie> = Vec::new();
    let mut i = offset;
    while i + 2 <= frame.len() {
        let id = frame[i];
        let len = frame[i + 1] as usize;
        if i + 2 + len > frame.len() {
            break;
        }
        let body = &frame[i + 2..i + 2 + len];
        if id == 254 && !out.is_empty() {
            out.last_mut().unwrap().1.extend_from_slice(body);
        } else {
            out.push((id, body.to_vec()));
        }
        i += 2 + len;
    }
    out
}

/// The beacon's Basic Multi-Link element: (own link id, per-STA profile link ids).
fn parse_mle(ies: &[Ie]) -> Option<(u8, Vec<MlePartner>)> {
    for (id, body) in ies {
        if *id != 255 || body.first() != Some(&107) {
            continue;
        }
        let b = &body[1..];
        // Multi-Link Control (2) + Common Info Length (1) + MLD MAC (6) +
        // Link ID Info (1) ...
        let control = u16::from_le_bytes([b[0], b[1]]);
        assert_eq!(control & 0x07, 0, "Basic MLE");
        assert!(control & (1 << 4) != 0, "Link ID Info present");
        let common_len = b[2] as usize;
        let own_link = b[9] & 0x0f;
        // Link Info: subelement 0 = Per-STA Profile, reassembling sub-fragments
        // (subelement ID 254 continues the previous subelement).
        let mut subs: Vec<(u8, Vec<u8>)> = Vec::new();
        let mut i = 2 + common_len;
        while i + 2 <= b.len() {
            let sub_id = b[i];
            let sub_len = (b[i + 1] as usize).min(b.len().saturating_sub(i + 2));
            let sub_body = &b[i + 2..i + 2 + sub_len];
            if sub_id == 254 && !subs.is_empty() {
                subs.last_mut().unwrap().1.extend_from_slice(sub_body);
            } else {
                subs.push((sub_id, sub_body.to_vec()));
            }
            i += 2 + sub_len;
        }
        let mut profiles = Vec::new();
        for (sub_id, sb) in subs {
            if sub_id == 0 && sb.len() >= 2 + 1 + 6 {
                let sta_control = u16::from_le_bytes([sb[0], sb[1]]);
                let link_id = (sta_control & 0x0f) as u8;
                let mut mac = [0u8; 6];
                // STA Info: length octet then STA MAC (Complete Profile).
                mac.copy_from_slice(&sb[3..9]);
                profiles.push((link_id, mac));
            }
        }
        return Some((own_link, profiles));
    }
    None
}

/// Every RNR TBTT entry carrying MLD parameters: (link id, BSSID, channel).
fn parse_rnr_mld(ies: &[Ie]) -> Vec<(u8, [u8; 6], u8)> {
    let mut out = Vec::new();
    for (id, body) in ies {
        if *id != 201 {
            continue;
        }
        let mut i = 0;
        while i + 4 <= body.len() {
            let count = ((body[i] >> 4) & 0x0f) as usize + 1;
            let tbtt_len = body[i + 1] as usize;
            let channel = body[i + 3];
            i += 4;
            for _ in 0..count {
                if i + tbtt_len > body.len() {
                    return out;
                }
                if tbtt_len >= 16 {
                    let mut bssid = [0u8; 6];
                    bssid.copy_from_slice(&body[i + 1..i + 7]);
                    let link_id = body[i + 14] & 0x0f;
                    out.push((link_id, bssid, channel));
                }
                i += tbtt_len;
            }
        }
    }
    out
}

#[test]
fn each_link_beacon_advertises_own_id_and_partner_rnr() {
    let ap = mld_ap();
    let links = ap.active_mld_links();
    assert_eq!(links.len(), 2, "two affiliated links configured");

    for link in &links {
        let frame = ap.beacon_frame_unprotected_for_link(link);
        let body = barely_ap::dot11::strip_radiotap(&frame).unwrap_or(&frame);
        // 802.11 header (24) + beacon fixed fields (12).
        let ies = ies(body, 36);

        let (own_link, profiles) =
            parse_mle(&ies).unwrap_or_else(|| panic!("link {} beacon has an MLE", link.link_id));
        assert_eq!(
            own_link, link.link_id,
            "link {} beacon MLE must carry its own Link ID",
            link.link_id
        );

        let partner_mac = if link.link_id == 0 { L1_MAC } else { L0_MAC };
        let partner_id = 1 - link.link_id;
        assert_eq!(
            profiles.len(),
            1,
            "link {} advertises exactly its one partner profile",
            link.link_id
        );
        assert_eq!(
            profiles[0],
            (partner_id, partner_mac),
            "link {} per-STA profile must name the partner link",
            link.link_id
        );

        let rnr = parse_rnr_mld(&ies);
        assert_eq!(
            rnr.len(),
            1,
            "link {} beacon carries exactly one MLD RNR entry",
            link.link_id
        );
        let (rnr_link, rnr_bssid, rnr_channel) = rnr[0];
        assert_eq!(
            (rnr_link, rnr_bssid),
            (partner_id, partner_mac),
            "link {} RNR must advertise the PARTNER link id + BSSID",
            link.link_id
        );
        let partner_channel = if link.link_id == 0 { 36 } else { 1 };
        assert_eq!(
            rnr_channel, partner_channel,
            "link {} RNR channel must be the partner's",
            link.link_id
        );
    }
}

/// A probe request answered on a partner link must be answered with THAT
/// link's content: its own MLE Link ID and an RNR naming the partner —
/// wpa_supplicant cross-checks the probe response against the link's beacon
/// and downgrades to single-link on any contradiction.
#[test]
fn probe_response_is_built_for_the_rx_link() {
    let mut ap = mld_ap();

    let mut probe_req = barely_ap::dot11::RADIOTAP_TX.to_vec();
    probe_req.extend_from_slice(&[0x40, 0x00, 0x00, 0x00]); // FC + duration
    probe_req.extend_from_slice(&[0xff; 6]); // addr1: broadcast
    probe_req.extend_from_slice(&[0x02, 0, 0, 0, 0xab, 0xcd]); // addr2: scanner
    probe_req.extend_from_slice(&[0xff; 6]); // addr3: broadcast
    probe_req.extend_from_slice(&[0x00, 0x00]); // seq ctrl
    probe_req.extend_from_slice(&[0x00, 0x08]); // SSID IE
    probe_req.extend_from_slice(b"mlo-test");

    for (rx_link, partner) in [(0u8, 1u8), (1u8, 0u8)] {
        ap.set_mgmt_rx_link(Some(rx_link));
        let out = ap.handle_incoming(&probe_req);
        assert_eq!(out.frames.len(), 1, "probe req on link {rx_link} answered");
        let body = barely_ap::dot11::strip_radiotap(&out.frames[0]).unwrap();
        let ies = ies(body, 36);

        let (own_link, profiles) = parse_mle(&ies).expect("probe resp carries an MLE");
        assert_eq!(
            own_link, rx_link,
            "probe resp on link {rx_link} must carry its own Link ID"
        );
        assert_eq!(profiles.len(), 1);
        assert_eq!(
            profiles[0].0, partner,
            "probe resp on link {rx_link} advertises the partner profile"
        );

        let rnr = parse_rnr_mld(&ies);
        assert_eq!(rnr.len(), 1, "one MLD RNR entry");
        assert_eq!(
            rnr[0].0, partner,
            "probe resp RNR on link {rx_link} must advertise the PARTNER link"
        );
        let partner_mac = if rx_link == 0 { L1_MAC } else { L0_MAC };
        assert_eq!(rnr[0].1, partner_mac);
    }
    ap.set_mgmt_rx_link(None);
}

/// The Non-Inheritance element must list exactly the elements the reporting
/// link has but the reported partner lacks — this is what stops a 5 GHz
/// association link's VHT from being inherited onto a 2.4 GHz partner (mac80211
/// "VHT capabilities mismatch"), the bug that blocked cross-band MLO.
#[test]
fn non_inheritance_lists_reporting_only_elements() {
    use barely_ap::dot11;
    // Reporting (5 GHz assoc link) has VHT cap (191) + VHT op (192); reported
    // (2.4 GHz partner) does not.
    let reporting_base = [1u8, 48, 45, 61, 191, 192];
    let reporting_ext = [35u8, 36, 108, 106];
    let reported_base = [1u8, 3, 50, 48, 45, 61];
    let reported_ext = [35u8, 36, 108, 106];

    let el = dot11::non_inheritance_element(
        (&reporting_base, &reporting_ext),
        (&reported_base, &reported_ext),
    );
    assert_eq!(el[0], 255, "extension element");
    assert_eq!(el[2], 56, "Non-Inheritance ext id");
    let base_len = el[3] as usize;
    let base_list = &el[4..4 + base_len];
    assert_eq!(base_list, &[191, 192], "only reporting-only base elements");
    let ext_len = el[4 + base_len] as usize;
    assert_eq!(ext_len, 0, "no reporting-only extension elements");

    // When the reported partner has every element the reporting link has (a
    // superset), there is nothing to exclude.
    assert!(
        dot11::non_inheritance_element((&[1u8, 48], &[35u8]), (&[1u8, 48, 61], &[35u8, 36]),)
            .is_empty(),
        "no non-inheritance when the partner is a superset"
    );
}

/// The (Re)Assoc Response per-STA profile must carry the BSS Parameters Change
/// Count (STA Control bit 11 + one STA Info octet) that the beacon variant omits.
#[test]
fn assoc_per_sta_profile_carries_bss_param_change_count() {
    use barely_ap::dot11;
    let mac = [0x0a, 0, 0, 0, 0xaa, 0x01];
    let beacon = dot11::per_sta_profile(1, &mac, &[0x30, 0x00]);
    let assoc = dot11::per_sta_profile_assoc(1, &mac, &[0x30, 0x00], 7);

    // Subelement: id(1) + len(1) + STA Control(2) ...
    let beacon_ctrl = u16::from_le_bytes([beacon[2], beacon[3]]);
    let assoc_ctrl = u16::from_le_bytes([assoc[2], assoc[3]]);
    assert_eq!(
        beacon_ctrl & (1 << 11),
        0,
        "beacon profile omits BSS param count"
    );
    assert_ne!(
        assoc_ctrl & (1 << 11),
        0,
        "assoc profile sets BSS param count bit"
    );
    // STA Info Length is one octet larger in the assoc profile (the extra count).
    assert_eq!(
        assoc[4],
        beacon[4] + 1,
        "assoc STA Info carries the extra octet"
    );
}
