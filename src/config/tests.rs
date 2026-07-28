use super::*;
use crate::frames as dot11;
use crate::util::mac_to_bytes;

#[test]
fn defaults_are_wpa3_sae_with_ocv_opt_in() {
    let c = Config::default();
    assert_eq!(c.key_mgmt, KeyMgmt::Sae);
    assert!(!c.ocv);
    assert_eq!(c.ssid, "turtlenet");
    assert!(!c.per_sta_vif);
    assert!(c.bss.is_empty());
    assert!(c.mld_default_links.is_none());
}

#[test]
fn single_link_netlink_mld_leaves_bssid_for_runtime_derivation() {
    let cfg = Config::from_json(
        r#"{
                "ssid":"single-mld", "passphrase":"password1234",
                "key_mgmt":"sae", "phy":"be", "mode":"netlink",
                "mld":true, "mac":"02:00:00:00:00:00",
                "band":5, "channel":36, "width":80, "link_id":0
            }"#,
    )
    .expect("single-link MLD config parses");
    cfg.validate().expect("single-link MLD config validates");

    let links = cfg.resolved_mld_links();
    assert_eq!(links.len(), 1);
    assert_eq!(
        links[0].mac, [0u8; 6],
        "top-level MLD MAC must not become the affiliated-link BSSID"
    );

    let ap = cfg.build_ap();
    assert_eq!(
        ap.active_mld_links()[0].mac,
        [0u8; 6],
        "netlink bring-up resolves the sentinel from the interface MLD address"
    );
}

#[test]
fn non_netlink_mld_randomizes_omitted_link_bssid_with_configured_mld_oui() {
    let cfg = Config::from_json(
        r#"{
                "ssid":"single-mld", "passphrase":"password1234",
                "key_mgmt":"sae", "phy":"be", "mode":"stdio",
                "mld":true, "mac":"02:00:00:00:aa:00",
                "band":5, "channel":36, "width":80, "link_id":0
            }"#,
    )
    .expect("single-link MLD config parses");
    cfg.validate().expect("single-link MLD config validates");

    let ap = cfg.build_ap();
    let link = ap.active_mld_links()[0];
    assert_eq!(&link.mac[..3], &[0x02, 0, 0]);
    assert_eq!(link.mac[0] & 0x03, 0x02);
    assert_eq!(ap.mac, link.mac);
    assert_ne!(link.mac, ap.mld_mac);
}

#[test]
fn mld_default_links_are_advertised_and_mark_other_links_disabled() {
    let cfg = Config::from_json(
        r#"{
                "ssid":"mld-ttlm", "passphrase":"password1234",
                "key_mgmt":"sae", "phy":"be", "mode":"netlink",
                "mld":true, "mac":"02:00:00:00:aa:00",
                "band":5, "channel":36, "width":80, "link_id":0,
                "mld_links":[
                    {"link_id":0,"mac":"02:00:00:00:aa:01","band":5,"channel":36,"width":80},
                    {"link_id":1,"mac":"02:00:00:00:aa:02","band":6,"channel":37,"width":160}
                ],
                "mld_default_links":[1]
            }"#,
    )
    .expect("TTLM config parses");
    cfg.validate().expect("TTLM config validates");
    assert_eq!(cfg.mld_default_links, Some(vec![1]));

    let links = cfg.resolved_mld_links();
    let ap = cfg.build_ap();
    let ttlm = dot11::tid_to_link_mapping_same_set(1 << 1);
    for link in &links {
        let beacon = ap.beacon_frame_unprotected_for_link(link);
        assert!(
            beacon.windows(ttlm.len()).any(|window| window == ttlm),
            "each affiliated-link beacon carries the advertised TTLM"
        );
    }

    let link1_beacon = ap.beacon_frame_unprotected_for_link(&links[1]);
    let rnr = dot11::find_ie(&link1_beacon[36..], 201).expect("partner RNR");
    assert_eq!(rnr[18] & 0x0f, 0, "RNR describes partner link 0");
    assert_ne!(rnr[19] & 0x20, 0, "link 0 is marked disabled");
}

#[test]
fn mld_default_links_reject_invalid_link_sets() {
    let no_mld = Config::from_json(r#"{"passphrase":"password1234","mld_default_links":[0]}"#)
        .expect("config parses");
    assert_eq!(
        no_mld.validate().unwrap_err(),
        "mld_default_links requires mld=true"
    );

    let empty = Config::from_json(
        r#"{"passphrase":"password1234","mld":true,"mode":"netlink","mld_default_links":[]}"#,
    )
    .expect("config parses");
    assert_eq!(
        empty.validate().unwrap_err(),
        "mld_default_links must contain at least one Link ID"
    );

    let base = r#"{
            "ssid":"mld-ttlm", "passphrase":"password1234",
            "key_mgmt":"sae", "phy":"be", "mode":"netlink",
            "mld":true, "mac":"02:00:00:00:aa:00",
            "band":5, "channel":36, "width":80, "link_id":0,
            "mld_links":[
                {"link_id":0,"mac":"02:00:00:00:aa:01","band":5,"channel":36,"width":80},
                {"link_id":1,"mac":"02:00:00:00:aa:02","band":6,"channel":37,"width":160}
            ]
        }"#;
    let mut unknown = Config::from_json(base).expect("base config parses");
    unknown.mld_default_links = Some(vec![2]);
    assert_eq!(
        unknown.validate().unwrap_err(),
        "mld_default_links Link ID 2 is not present in mld_links"
    );

    let mut duplicate = Config::from_json(base).expect("base config parses");
    duplicate.mld_default_links = Some(vec![1, 1]);
    assert_eq!(
        duplicate.validate().unwrap_err(),
        "duplicate Link ID 1 in mld_default_links"
    );
}

#[test]
fn cross_band_mld_config_produces_band_correct_per_link_beacons() {
    // MLD across 2.4 GHz (ch 1) + 5 GHz (ch 36) — the realistic deployment,
    // not two 2.4 GHz channels. Each link's beacon must carry band-correct
    // IEs: the 5 GHz link advertises VHT (id 191); the 2.4 GHz link does not.
    let cfg = Config::from_json(include_str!("../../configs/mld.json")).expect("mld.json parses");
    let links = cfg.resolved_mld_links();
    assert_eq!(links.len(), 2);
    assert_eq!(links[0].channel, 1, "link 0 on 2.4 GHz ch 1");
    assert_eq!(links[1].channel, 36, "link 1 on 5 GHz ch 36");
    let ap = cfg.build_ap();
    let b0 = ap.beacon_frame_unprotected_for_link(&links[0]);
    let b1 = ap.beacon_frame_unprotected_for_link(&links[1]);
    // Walk the beacon IEs (after the 24-byte header + 12-byte fixed fields).
    let has_ie = |f: &[u8], id: u8| {
        let mut i = 36usize;
        while i + 2 <= f.len() {
            if f[i] == id {
                return true;
            }
            i += 2 + f[i + 1] as usize;
        }
        false
    };
    assert!(
        has_ie(&b1, 191),
        "5 GHz (ch 36) link beacon carries VHT Capabilities"
    );
    assert!(
        !has_ie(&b0, 191),
        "2.4 GHz (ch 1) link beacon omits VHT Capabilities"
    );
}

#[test]
fn six_ghz_mld_link_uses_explicit_band_despite_overlapping_channel_number() {
    let cfg = Config::from_json(
        r#"{
                "ssid":"mld-6g", "passphrase":"password1234",
                "key_mgmt":"sae", "phy":"be", "mode":"netlink",
                "mld":true, "band":5, "channel":36, "width":80, "link_id":0,
                "mld_links":[
                    {"link_id":0,"mac":"02:00:00:00:aa:01","band":5,"channel":36,"width":80},
                    {"link_id":1,"mac":"02:00:00:00:aa:02","band":6,"channel":37,"width":80}
                ]
            }"#,
    )
    .expect("mixed 5/6 GHz MLD config parses");
    cfg.validate().expect("mixed 5/6 GHz MLD config validates");
    let links = cfg.resolved_mld_links();
    assert!(!links[0].band6);
    assert!(links[1].band6);

    let ap = cfg.build_ap();
    let beacon = ap.beacon_frame_unprotected_for_link(&links[1]);
    let has_ie = |id: u8, ext_id: Option<u8>| {
        let mut i = 36usize;
        while i + 2 <= beacon.len() {
            let len = beacon[i + 1] as usize;
            if i + 2 + len > beacon.len() {
                return false;
            }
            if beacon[i] == id && ext_id.is_none_or(|ext| len > 0 && beacon[i + 2] == ext) {
                return true;
            }
            i += 2 + len;
        }
        false
    };
    assert!(
        !has_ie(191, None),
        "6 GHz link must not advertise VHT capabilities"
    );
    assert!(
        has_ie(255, Some(59)),
        "6 GHz link must advertise the HE 6 GHz capability extension"
    );
}

#[test]
fn mld_beacon_advertises_the_other_link_profile() {
    let cfg = Config::from_json(
        r#"{
                "ssid":"mld-profile", "passphrase":"password1234",
                "key_mgmt":"sae", "phy":"be", "mode":"netlink",
                "mld":true, "mac":"02:00:00:00:aa:00",
                "band":5, "channel":36, "width":80, "link_id":0,
                "mld_links":[
                    {"link_id":0,"mac":"02:00:00:00:aa:01","band":5,"channel":36,"width":80},
                    {"link_id":1,"mac":"02:00:00:00:aa:02","band":6,"channel":37,"width":80}
                ]
            }"#,
    )
    .expect("mixed-band MLD config parses");
    let links = cfg.resolved_mld_links();
    let ap = cfg.build_ap();
    let beacon = ap.beacon_frame_unprotected_for_link(&links[0]);

    // MLO RNR is emitted automatically (independent of the generic `rnr`
    // switch) and names the actual partner link, not a synthesized BSSID.
    let rnr = dot11::find_ie(&beacon[36..], 201).expect("MLO RNR");
    assert_eq!(rnr[1], 16, "MLD TBTT Information length");
    assert_eq!(rnr[2], 133, "6 GHz 80 MHz operating class");
    assert_eq!(rnr[3], 37, "partner channel");
    assert_eq!(&rnr[5..11], &links[1].mac, "partner link BSSID");
    assert_eq!(rnr[18] & 0x0f, 1, "partner Link ID");

    // The Basic MLE starts with ext-id 107. Its Common Info is followed by
    // a Per-STA Profile (subelement id 0) for link 1; a common-only MLE is
    // insufficient for a client to discover and set up the partner link.
    let mut i = 36usize;
    let mut found_profile = false;
    while i + 3 <= beacon.len() {
        let len = beacon[i + 1] as usize;
        if i + 2 + len > beacon.len() {
            break;
        }
        if beacon[i] == 255 && len >= 4 && beacon[i + 2] == 107 {
            let common_len = beacon[i + 5] as usize;
            let profile = i + 5 + common_len;
            found_profile =
                profile + 1 < i + 2 + len && beacon[profile] == 0 && beacon[profile + 1] > 0;
            break;
        }
        i += 2 + len;
    }
    assert!(found_profile, "link-0 beacon must advertise link-1 profile");
}

#[test]
fn eht_keeps_configured_akms_while_six_ghz_removes_psk() {
    use crate::frames::{PhyMode, SecurityMode};
    // Match the reference AP's EHT/MLD transition behavior: EHT on 2.4 or
    // 5 GHz does not silently replace the operator-selected AKM.
    let mut c = Config::default();
    c.phy = PhyMode::Eht;
    c.key_mgmt = KeyMgmt::Psk;
    assert_eq!(
        c.effective_key_mgmt(),
        KeyMgmt::Psk,
        "EHT + PSK remains WPA2 outside 6 GHz"
    );
    assert_eq!(c.build_ap().security_mode(), SecurityMode::Wpa2);

    c.key_mgmt = KeyMgmt::SaeTransition;
    assert_eq!(
        c.effective_key_mgmt(),
        KeyMgmt::SaeTransition,
        "EHT MLD transition must retain the WPA2 fallback"
    );
    assert_eq!(c.build_ap().security_mode(), SecurityMode::Transition);

    // OWE and SAE are unchanged as well.
    c.key_mgmt = KeyMgmt::Owe;
    assert_eq!(c.effective_key_mgmt(), KeyMgmt::Owe);
    c.key_mgmt = KeyMgmt::Sae;
    assert_eq!(c.effective_key_mgmt(), KeyMgmt::Sae);

    // The band-specific 6 GHz rule still strips the WPA2 fallback.
    c.band = Band::Ghz6;
    c.key_mgmt = KeyMgmt::SaeTransition;
    assert_eq!(c.effective_key_mgmt(), KeyMgmt::Sae);
}

#[test]
fn parses_multi_bss_config() {
    let json = r#"{
            "ssid": "main", "passphrase": "password1234", "mode": "netlink", "band": 5, "channel": 36,
            "bss": [
                { "ssid": "guest", "psk": "guestpass123", "mac": "02:00:00:00:00:10" },
                { "ssid": "iot", "key_mgmt": "sae", "passphrase": "iotpass12345", "bssid": "02:00:00:00:00:20" }
            ]
        }"#;
    let cfg = Config::from_json(json).expect("parses");
    cfg.validate().expect("valid");
    assert_eq!(cfg.bss.len(), 2);
    assert_eq!(cfg.bss[0].ssid, "guest");
    assert_eq!(
        cfg.bss[0].key_mgmt,
        KeyMgmt::Sae,
        "inherits primary default"
    );
    assert_eq!(cfg.bss[1].key_mgmt, KeyMgmt::Sae);
    assert_eq!(cfg.bss[1].mac, mac_to_bytes("02:00:00:00:00:20"));
    // build_bss_ap inherits the primary radio params, keeps the BSS identity.
    let ap = cfg.build_bss_ap(&cfg.bss[0]);
    assert_eq!(ap.channel, 36);
    assert_eq!(ap.mac, mac_to_bytes("02:00:00:00:00:10"));
    assert_eq!(ap.ssid, b"guest");
}

#[test]
fn parses_guest_flag() {
    // Per-BSS guest: isolation applies to that SSID only.
    let json = r#"{
            "ssid": "main", "passphrase": "password1234", "mode": "netlink",
            "bss": [
                { "ssid": "guests", "psk": "guestpass123", "mac": "02:00:00:00:00:10", "guest": true }
            ]
        }"#;
    let cfg = Config::from_json(json).expect("parses");
    cfg.validate().expect("valid");
    assert!(!cfg.guest, "primary stays non-guest");
    assert!(cfg.bss[0].guest);
    assert!(cfg.build_bss_ap(&cfg.bss[0]).guest());
    assert!(!cfg.build_ap().guest());

    // Top-level guest (reference AP `ap_isolate` spelling accepted).
    let cfg = Config::from_json(r#"{ "passphrase": "password1234", "ap_isolate": true }"#)
        .expect("parses");
    assert!(cfg.guest);
    assert!(cfg.build_ap().guest());

    // Type mismatches stay hard errors.
    assert!(Config::from_json(r#"{"guest": 1}"#).is_err());
    assert!(Config::from_json(
            r#"{ "passphrase": "password1234", "mode": "netlink",
                 "bss": [ { "ssid": "g", "psk": "guestpass123", "mac": "02:00:00:00:00:10", "guest": "yes" } ] }"#
        )
        .is_err());
}

#[test]
fn rejects_duplicate_bssid() {
    let json = r#"{ "ssid": "main", "passphrase": "password1234", "mac": "02:00:00:00:00:10", "mode": "netlink",
            "bss": [ { "ssid": "guest", "psk": "guestpass123", "mac": "02:00:00:00:00:10" } ] }"#;
    let cfg = Config::from_json(json).expect("parses");
    assert!(
        cfg.validate().is_err(),
        "BSSID duplicating the primary must be rejected"
    );
}

#[test]
fn bss_requires_ssid_and_mac() {
    let no_mac = r#"{ "ssid": "main", "passphrase": "password1234",
            "bss": [ { "ssid": "guest", "psk": "guestpass123" } ] }"#;
    assert!(
        Config::from_json(no_mac).is_err(),
        "a BSS without a BSSID must be rejected"
    );
    let no_ssid = r#"{ "ssid": "main", "passphrase": "password1234",
            "bss": [ { "mac": "02:00:00:00:00:10", "psk": "guestpass123" } ] }"#;
    assert!(
        Config::from_json(no_ssid).is_err(),
        "a BSS without an SSID must be rejected"
    );
}

#[test]
fn parses_a_full_json_config() {
    let json = r#"{
            "ssid": "lab",
            "passphrase": "hunter2hunter2",
            "key_mgmt": "sae",
            "band": 5,
            "channel": 36,
            "interface": "wlan3",
            "mode": "netlink",
            "mac": "02:aa:bb:cc:dd:ee",
            "ip": "192.168.5.1",
            "ocv": true,
            "per_sta_vif": true,
            "spr_api_socket": "/state/wifi/apisock",
            "spr_dhcp_helper": "/spr_dhcp_helper"
        }"#;
    let c = Config::from_json(json).unwrap();
    assert_eq!(c.ssid, "lab");
    assert_eq!(c.passphrase, "hunter2hunter2");
    assert_eq!(c.key_mgmt, KeyMgmt::Sae);
    assert_eq!(c.band, Band::Ghz5);
    assert_eq!(c.channel, 36);
    assert_eq!(c.iface, "wlan3");
    assert_eq!(c.mode, "netlink");
    assert_eq!(c.mac, [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    assert_eq!(c.ip, [192, 168, 5, 1]);
    assert!(c.ocv);
    assert!(c.per_sta_vif);
    assert_eq!(c.spr_api_socket.as_deref(), Some("/state/wifi/apisock"));
    assert_eq!(c.spr_dhcp_helper.as_deref(), Some("/spr_dhcp_helper"));
}

#[test]
fn omitted_keys_keep_defaults() {
    let c = Config::from_json(r#"{"ssid": "only-ssid"}"#).unwrap();
    assert_eq!(c.ssid, "only-ssid");
    assert_eq!(c.channel, 1); // default preserved
    assert_eq!(c.key_mgmt, KeyMgmt::Sae);
    assert_eq!(c.band, Band::Ghz2_4);
    assert!(!c.ocv, "OCV must be explicitly enabled and negotiated");
}

#[test]
fn parses_dbdc_radios_with_shared_security_and_per_radio_overrides() {
    let cfg = Config::from_json(
        r#"{
                "ssid": "s5210",
                "key_mgmt": "sae",
                "mode": "netlink",
                "sae_psk_file": "/configs/wifi/sae_passwords",
                "per_sta_vif": true,
                "ocv": false,
                "spr_api_socket": "/state/wifi/apisock",
                "spr_dhcp_helper": "/hostap_dhcp_helper",
                "radios": [
                    {
                        "iface": "wlan1",
                        "mac": "02:00:00:00:00:01",
                        "band": 2.4,
                        "channel": 1,
                        "width": 20,
                        "phy": "ax",
                        "ctrl_path": "/state/wifi/control_wlan1/wlan1"
                    },
                    {
                        "iface": "wlan2",
                        "mac": "04:f0:21:c9:1e:ff",
                        "band": 5,
                        "channel": 36,
                        "width": 80,
                        "phy": "ax",
                        "ctrl_path": "/state/wifi/control_wlan2/wlan2"
                    }
                ]
            }"#,
    )
    .expect("DBDC config parses");

    cfg.validate().expect("DBDC config validates");
    assert_eq!(cfg.radios.len(), 2);
    let low = cfg.for_radio(&cfg.radios[0]);
    let high = cfg.for_radio(&cfg.radios[1]);
    assert_eq!(low.ssid, "s5210");
    assert_eq!(
        low.sae_psk_file.as_deref(),
        Some("/configs/wifi/sae_passwords")
    );
    assert_eq!(low.spr_api_socket.as_deref(), Some("/state/wifi/apisock"));
    assert_eq!(low.iface, "wlan1");
    assert_eq!(low.band, Band::Ghz2_4);
    assert_eq!(low.channel, 1);
    assert_eq!(low.width, 20);
    assert!(low.per_sta_vif);
    assert!(!low.ocv);
    assert_eq!(high.iface, "wlan2");
    assert_eq!(high.band, Band::Ghz5);
    assert_eq!(high.channel, 36);
    assert_eq!(high.width, 80);
    assert_eq!(high.mac, mac_to_bytes("04:f0:21:c9:1e:ff"));
}

#[test]
fn radios_allow_optional_mac_and_per_radio_ssid() {
    // No `mac` on either radio (adopted from the interface), and a per-radio
    // SSID override on 2.4 GHz while 5 GHz inherits the shared SSID.
    let cfg = Config::from_json(
        r#"{
                "ssid": "shared-net",
                "key_mgmt": "sae",
                "passphrase": "password1234",
                "mode": "netlink",
                "radios": [
                    { "iface": "wlan1", "ssid": "net-2g", "band": 2.4, "channel": 6,
                      "width": 20, "phy": "ax", "ctrl_path": "/run/w1" },
                    { "iface": "wlan2", "band": 5, "channel": 36,
                      "width": 80, "phy": "ax", "ctrl_path": "/run/w2" }
                ]
            }"#,
    )
    .expect("parses without a radio mac");
    // Two macless radios must NOT collide on the placeholder default BSSID.
    cfg.validate()
        .expect("validates with adopted (implicit) BSSIDs");

    assert!(!cfg.radios[0].mac_explicit);
    assert!(!cfg.radios[1].mac_explicit);
    // Per-radio SSID override vs inherited shared SSID.
    assert_eq!(cfg.radios[0].ssid.as_deref(), Some("net-2g"));
    assert!(cfg.radios[1].ssid.is_none());
    assert_eq!(cfg.for_radio(&cfg.radios[0]).ssid, "net-2g");
    assert_eq!(cfg.for_radio(&cfg.radios[1]).ssid, "shared-net");

    // An explicit mac still parses and is dup-checked.
    assert!(Config::from_json(
        r#"{ "ssid": "s", "passphrase": "password1234", "mode": "netlink", "radios": [
                { "iface": "w1", "mac": "02:00:00:00:00:aa", "band": 5, "channel": 36,
                  "width": 20, "phy": "ax", "ctrl_path": "/run/a" },
                { "iface": "w2", "mac": "02:00:00:00:00:aa", "band": 5, "channel": 40,
                  "width": 20, "phy": "ax", "ctrl_path": "/run/b" } ] }"#
    )
    .and_then(|c| c.validate())
    .is_err());
}

#[test]
fn shipped_json_examples_parse_and_validate() {
    for (name, text) in [
        (
            "barely-ap.example.json",
            include_str!("../../barely-ap.example.json"),
        ),
        (
            "configs/rustap.json",
            include_str!("../../configs/rustap.json"),
        ),
    ] {
        let cfg =
            Config::from_json(text).unwrap_or_else(|error| panic!("{name} must parse: {error}"));
        cfg.validate()
            .unwrap_or_else(|error| panic!("{name} must validate: {error}"));
    }
}

#[test]
fn rejects_ambiguous_or_unsafe_multi_radio_configs() {
    let base = r#"{
            "passphrase": "password1234",
            "mode": "netlink",
            "radios": [
                {
                    "iface":"wlan1", "mac":"02:00:00:00:00:01",
                    "band":2.4, "channel":1, "width":20, "phy":"ax",
                    "ctrl_path":"/run/barely-ap/wlan1"
                },
                {
                    "iface":"wlan2", "mac":"02:00:00:00:00:02",
                    "band":5, "channel":36, "width":80, "phy":"ax",
                    "ctrl_path":"/run/barely-ap/wlan2"
                }
            ]
        }"#;
    let mut cfg = Config::from_json(base).unwrap();
    cfg.radios[1].iface = "wlan1".to_string();
    assert!(cfg
        .validate()
        .unwrap_err()
        .contains("duplicate radio iface"));

    let mut cfg = Config::from_json(base).unwrap();
    cfg.radios[1].mac = cfg.radios[0].mac;
    assert!(cfg.validate().unwrap_err().contains("duplicate BSSID"));

    let mut cfg = Config::from_json(base).unwrap();
    cfg.radios[1].ctrl_path = "/run/rustap".to_string();
    cfg.radios[0].ctrl_path = cfg.radios[1].ctrl_path.clone();
    assert!(cfg
        .validate()
        .unwrap_err()
        .contains("duplicate radio ctrl_path"));

    let mut cfg = Config::from_json(base).unwrap();
    cfg.mode = "iface".to_string();
    assert!(cfg
        .validate()
        .unwrap_err()
        .contains("requires top-level mode"));

    assert!(Config::from_json(r#"{"radios":[]}"#).is_err());
    assert!(Config::from_json(r#"{"radios":[{"radios":[{"iface":"wlan1"}]}]}"#).is_err());
    assert!(Config::from_json(
        r#"{
                "band": 5,
                "radios":[{
                    "iface":"wlan1", "mac":"02:00:00:00:00:01",
                    "band":2.4, "channel":1, "width":20, "phy":"ax",
                    "ctrl_path":"/run/barely-ap/wlan1"
                }]
            }"#
    )
    .unwrap_err()
    .contains("belongs inside"));
    assert!(Config::from_json(
        r#"{"radios":[{
                "iface":"wlan1", "mac":"02:00:00:00:00:01",
                "band":2.4, "channel":1, "width":20,
                "ctrl_path":"/run/barely-ap/wlan1"
            }]}"#
    )
    .unwrap_err()
    .contains("explicit phy"));
    // Genuinely-shared policy (auth/credentials/station policy) is still
    // rejected inside a radio entry. `ssid` is intentionally NOT here — it is
    // an allowed per-radio override (see radios_allow_optional_mac_and_per_radio_ssid).
    assert!(Config::from_json(
        r#"{"radios":[{
                "iface":"wlan1", "mac":"02:00:00:00:00:01",
                "band":2.4, "channel":1, "width":20, "phy":"ax",
                "ctrl_path":"/run/barely-ap/wlan1",
                "per_sta_vif": true
            }]}"#
    )
    .unwrap_err()
    .contains("shared settings belong at the top level"));
}

#[test]
fn band_is_explicit_and_replaces_band6() {
    assert_eq!(
        Config::from_json(r#"{"band": 2.4}"#).unwrap().band,
        Band::Ghz2_4
    );
    assert_eq!(
        Config::from_json(r#"{"band": 5}"#).unwrap().band,
        Band::Ghz5
    );
    assert_eq!(
        Config::from_json(r#"{"band": 6}"#).unwrap().band,
        Band::Ghz6
    );
    assert!(Config::from_json(r#"{"band": 4}"#).is_err());
    assert!(
        Config::from_json(r#"{"band6": true}"#).is_err(),
        "legacy boolean must not survive in the native JSON schema"
    );
}

#[test]
fn band_and_channel_must_match() {
    assert!(Config::from_json(r#"{"band":2.4,"channel":36}"#)
        .unwrap()
        .validate()
        .is_err());
    assert!(Config::from_json(r#"{"band":5,"channel":1}"#)
        .unwrap()
        .validate()
        .is_err());
    assert!(Config::from_json(
        r#"{"band":6,"channel":37,"key_mgmt":"sae","phy":"be","passphrase":"password1234"}"#,
    )
    .unwrap()
    .validate()
    .is_ok());
    assert!(
        Config::from_json(r#"{"band":6,"channel":36,"key_mgmt":"sae","phy":"be"}"#)
            .unwrap()
            .validate()
            .is_err()
    );
}

#[test]
fn unknown_key_is_rejected() {
    let err = Config::from_json(r#"{"ssidd": "typo"}"#).unwrap_err();
    assert!(err.contains("unknown config key"), "{err}");
}

#[test]
fn type_mismatch_is_rejected() {
    // channel as a string, not a number
    assert!(Config::from_json(r#"{"channel": "36"}"#).is_err());
    // per_sta_vif as a number, not a bool
    assert!(Config::from_json(r#"{"per_sta_vif": 1}"#).is_err());
}

#[test]
fn transition_enables_both() {
    let c = Config::from_json(r#"{"key_mgmt": "sae-transition"}"#).unwrap();
    assert_eq!(c.key_mgmt, KeyMgmt::SaeTransition);
}

#[test]
fn transition_without_a_literal_password_requires_both_credential_files() {
    let mut c = Config::default();
    c.key_mgmt = KeyMgmt::SaeTransition;
    c.passphrase.clear();

    c.wpa_psk_file = Some("/configs/wifi/wpa2pskfile".to_string());
    assert!(
        c.validate().unwrap_err().contains("sae_psk_file"),
        "the WPA2 database cannot substitute for the SAE database"
    );

    c.wpa_psk_file = None;
    c.sae_psk_file = Some("/configs/wifi/sae_passwords".to_string());
    assert!(
        c.validate().unwrap_err().contains("wpa_psk_file"),
        "the SAE database cannot substitute for the WPA2 database"
    );

    c.wpa_psk_file = Some("/configs/wifi/wpa2pskfile".to_string());
    c.validate()
        .expect("transition mode accepts independent WPA2 and SAE databases");
}

#[test]
fn malformed_json_is_an_error() {
    assert!(Config::from_json("not json").is_err());
    assert!(Config::from_json("[1,2,3]").is_err()); // not an object
}

#[test]
fn bad_ip_is_rejected() {
    assert!(Config::from_json(r#"{"ip": "999.1.1"}"#).is_err());
}

#[test]
fn validate_rejects_weak_passphrase_and_bad_transport() {
    let mut c = Config::default();
    assert!(c.validate().is_err()); // no default production credential
    c.passphrase = "password1234".to_string();
    assert!(c.validate().is_ok());
    c.passphrase = "short".to_string();
    assert!(c.validate().is_err()); // < 8
    c.passphrase = "".to_string();
    assert!(c.validate().is_err()); // empty
    c.passphrase = "password1234".to_string();
    c.mode = "netlink".to_string();
    c.key_mgmt = KeyMgmt::Sae;
    assert!(c.validate().is_ok()); // netlink now supports WPA3-SAE
    c.key_mgmt = KeyMgmt::Psk;
    assert!(c.validate().is_ok());
    // 6 GHz must not be WPA2-PSK
    c.band = Band::Ghz6;
    assert!(c.validate().is_err());
    c.key_mgmt = KeyMgmt::Sae;
    assert!(c.validate().is_ok()); // 6 GHz + SAE is fine
                                   // OWE needs no passphrase
    let mut o = Config::default();
    o.key_mgmt = KeyMgmt::Owe;
    o.passphrase = String::new();
    o.mode = "iface".to_string();
    assert!(o.validate().is_ok());
}

#[test]
fn country_defaults_and_parses() {
    assert_eq!(Config::default().country, *b"US");
    assert_eq!(
        Config::from_json(r#"{"country": "de"}"#).unwrap().country,
        *b"DE"
    );
    assert_eq!(
        Config::from_json(r#"{"country_code": "JP"}"#)
            .unwrap()
            .country,
        *b"JP"
    );
    assert!(Config::from_json(r#"{"country": "USA"}"#).is_err()); // not 2 letters
    assert!(Config::from_json(r#"{"country": "U1"}"#).is_err()); // not alphabetic
}

#[test]
fn psk_file_parses_wildcard_and_per_mac() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("barely_psk_{}.txt", std::process::id()));
    std::fs::write(
        &path,
        "# onboarding\n\
             00:00:00:00:00:00 onboardpass\n\
             \n\
             aa:bb:cc:dd:ee:ff devicepass\n\
             sae-onboard|mac=ff:ff:ff:ff:ff:ff\n\
             sae-device|mac=12:34:56:78:9a:bc\n",
    )
    .unwrap();
    let e = parse_psk_file(path.to_str().unwrap()).unwrap();
    std::fs::remove_file(&path).ok();
    assert_eq!(e.len(), 4);
    assert_eq!(e[0], (None, "onboardpass".to_string())); // wildcard
    assert_eq!(
        e[1],
        (
            Some(mac_to_bytes("aa:bb:cc:dd:ee:ff")),
            "devicepass".to_string()
        )
    );
    assert_eq!(e[2], (None, "sae-onboard".to_string()));
    assert_eq!(
        e[3],
        (
            Some(mac_to_bytes("12:34:56:78:9a:bc")),
            "sae-device".to_string()
        )
    );
    let c = Config::from_json(r#"{"wpa_psk_file":"/wpa","sae_psk_file":"/sae"}"#).unwrap();
    assert_eq!(c.wpa_psk_file.as_deref(), Some("/wpa"));
    assert_eq!(c.sae_psk_file.as_deref(), Some("/sae"));
    assert!(
        Config::from_json(r#"{"psk_file":"/old"}"#).is_err(),
        "the ambiguous shared credential path is no longer accepted"
    );
}
