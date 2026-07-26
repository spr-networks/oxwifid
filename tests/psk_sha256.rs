//! AP-side PSK-SHA256 (AKM 00-0F-AC:6): SHA-256 PTK derivation with an
//! AES-128-CMAC EAPOL-Key MIC at Key Descriptor Version 3.

use barely_ap::ap::Ap;
use barely_ap::client::Client;
use barely_ap::config::{Config, KeyMgmt};
use barely_ap::dot11;
use barely_ap::util::mac_to_bytes;

const AP_MAC: &str = "02:00:00:00:00:00";
const STA_MAC: &str = "02:00:00:00:ab:cd";

fn psk_sha256_ap() -> Ap {
    let mut ap = Ap::new("sha256-net", "password1234", mac_to_bytes(AP_MAC), 1);
    ap.enable_psk_sha256();
    ap
}

fn connect(ap: &mut Ap, sta: &mut Client) -> Vec<Vec<u8>> {
    let mut seen = Vec::new();
    let mut to_sta = vec![ap.beacon_frame()];
    let mut to_ap: Vec<Vec<u8>> = Vec::new();
    for _ in 0..30 {
        for f in to_sta.drain(..) {
            seen.push(f.clone());
            to_ap.extend(sta.handle_incoming(&f).frames);
        }
        for f in to_ap.drain(..) {
            to_sta.extend(ap.handle_incoming(&f).frames);
        }
        if sta.connected == 4 {
            break;
        }
    }
    seen
}

fn eapol_keys(frames: &[Vec<u8>]) -> Vec<dot11::EapolKey> {
    frames
        .iter()
        .filter_map(|f| dot11::strip_radiotap(f).and_then(dot11::Dot11::parse))
        .filter(|p| p.is_eapol())
        .filter_map(|p| p.eapol_key_body().and_then(dot11::EapolKey::parse))
        .collect()
}

#[test]
fn the_bss_advertises_both_psk_akms() {
    for cipher in [
        dot11::DataCipher::Ccmp128,
        dot11::DataCipher::Gcmp128,
        dot11::DataCipher::Ccmp256,
        dot11::DataCipher::Gcmp256,
    ] {
        let tail = dot11::security_tail_for_cipher(dot11::SecurityMode::Wpa2PskSha256, cipher);
        let rsn = &tail[2..2 + usize::from(tail[1])];
        assert!(
            dot11::rsn_has_akm(rsn, 2),
            "legacy WPA2-PSK stays offered for {cipher:?}"
        );
        assert!(
            dot11::rsn_has_akm(rsn, 6),
            "PSK-SHA256 is offered for {cipher:?}"
        );
        assert_eq!(
            dot11::validate_psk_sha256_rsn_for_cipher(rsn, cipher),
            Ok(())
        );
    }

    // Both AKMs must validate against this mode; SAE and OWE must not.
    for akm in [dot11::RSN, dot11::RSN_PSK_SHA256] {
        let body = &akm[2..];
        assert_eq!(
            dot11::validate_assoc_rsn_for_cipher(
                body,
                dot11::SecurityMode::Wpa2PskSha256,
                dot11::DataCipher::Ccmp128,
            ),
            Ok(())
        );
    }
    assert!(dot11::validate_assoc_rsn_for_cipher(
        &dot11::RSN_WPA3[2..],
        dot11::SecurityMode::Wpa2PskSha256,
        dot11::DataCipher::Ccmp128,
    )
    .is_err());
}

#[test]
fn psk_sha256_round_trips_every_aes_pairwise_suite() {
    for cipher in [
        dot11::DataCipher::Ccmp128,
        dot11::DataCipher::Gcmp128,
        dot11::DataCipher::Ccmp256,
        dot11::DataCipher::Gcmp256,
    ] {
        let mut ap = psk_sha256_ap();
        ap.set_pairwise_cipher(cipher);
        let sta_mac = mac_to_bytes(STA_MAC);
        let mut sta = Client::new("sha256-net", "password1234", sta_mac);
        sta.enable_psk_sha256();
        sta.set_pairwise_cipher(cipher);

        let downlink = connect(&mut ap, &mut sta);
        assert_eq!(
            sta.connected, 4,
            "PSK-SHA256 four-way completes for {cipher:?}"
        );
        assert!(
            ap.is_associated(&sta_mac),
            "AP authorizes AKM6 station for {cipher:?}"
        );
        for key in eapol_keys(&downlink) {
            assert_eq!(key.descriptor_version(), 3);
        }

        let uplink = [
            mac_to_bytes(AP_MAC).as_slice(),
            sta_mac.as_slice(),
            &[0x08, 0x00],
            b"akm6 cipher uplink",
        ]
        .concat();
        let protected = sta
            .encrypt_uplink(&uplink)
            .unwrap_or_else(|| panic!("station encrypts {cipher:?}"));
        assert_eq!(
            ap.handle_incoming(&protected).to_network,
            vec![uplink],
            "AP decrypts {cipher:?}"
        );

        let downlink = [
            sta_mac.as_slice(),
            mac_to_bytes(AP_MAC).as_slice(),
            &[0x08, 0x00],
            b"akm6 cipher downlink",
        ]
        .concat();
        let frames = ap.deliver_to_station(&downlink);
        assert_eq!(frames.len(), 1);
        assert_eq!(
            sta.handle_incoming(&frames[0]).to_network,
            vec![downlink],
            "station decrypts {cipher:?}"
        );
    }
}

#[test]
fn a_psk_sha256_station_completes_the_four_way_and_passes_data() {
    let mut ap = psk_sha256_ap();
    let sta_mac = mac_to_bytes(STA_MAC);
    let mut sta = Client::new("sha256-net", "password1234", sta_mac);
    sta.enable_psk_sha256();

    let downlink = connect(&mut ap, &mut sta);
    assert_eq!(sta.connected, 4, "PSK-SHA256 4-way completes");
    assert!(ap.is_associated(&sta_mac), "the AP authorized the station");

    // Every EAPOL-Key the AP sent must carry Key Descriptor Version 3 — the
    // AES-128-CMAC MIC that AKM 6 selects, not WPA2-PSK's HMAC-SHA1 version 2.
    let keys = eapol_keys(&downlink);
    assert!(!keys.is_empty(), "captured the AP's EAPOL-Key messages");
    for key in &keys {
        assert_eq!(
            key.descriptor_version(),
            3,
            "PSK-SHA256 uses Key Descriptor Version 3"
        );
    }

    // The key hierarchy is SHA-256, not PRF-512: both peers agreeing on the
    // PTK is what makes the data path work at all.
    let uplink = [
        mac_to_bytes(AP_MAC).as_slice(),
        sta_mac.as_slice(),
        &[0x08, 0x00],
        b"psk-sha256 uplink",
    ]
    .concat();
    let protected = sta.encrypt_uplink(&uplink).expect("station encrypts");
    assert_eq!(ap.handle_incoming(&protected).to_network, vec![uplink]);

    let dl = [
        sta_mac.as_slice(),
        mac_to_bytes(AP_MAC).as_slice(),
        &[0x08, 0x00],
        b"psk-sha256 downlink",
    ]
    .concat();
    let frames = ap.deliver_to_station(&dl);
    assert_eq!(frames.len(), 1);
    assert_eq!(sta.handle_incoming(&frames[0]).to_network, vec![dl]);
}

#[test]
fn a_plain_wpa2_station_still_associates_to_a_psk_sha256_bss() {
    let mut ap = psk_sha256_ap();
    let sta_mac = mac_to_bytes(STA_MAC);
    let mut sta = Client::new("sha256-net", "password1234", sta_mac);

    let downlink = connect(&mut ap, &mut sta);
    assert_eq!(sta.connected, 4, "the legacy PSK 4-way still completes");
    assert!(ap.is_associated(&sta_mac));
    for key in eapol_keys(&downlink) {
        assert_eq!(
            key.descriptor_version(),
            2,
            "AKM 2 keeps HMAC-SHA1 / Key Descriptor Version 2"
        );
    }
}

#[test]
fn psk_sha256_does_not_claim_management_frame_protection() {
    let mut ap = psk_sha256_ap();
    let sta_mac = mac_to_bytes(STA_MAC);
    let mut sta = Client::new("sha256-net", "password1234", sta_mac);
    sta.enable_psk_sha256();
    connect(&mut ap, &mut sta);
    assert_eq!(sta.connected, 4);

    // AKM 6 shares WPA3's SHA-256 key hierarchy but negotiates no PMF, so the
    // station must not be handed an IGTK and its robust management frames stay
    // unprotected. Keying PMF off the SHA-256 flag would get this wrong.
    assert!(
        !ap.is_pmf(),
        "a PSK-SHA256 BSS does not run management frame protection"
    );
    let mut framed = dot11::RADIOTAP_TX.to_vec();
    // Station -> AP: addr1 is the BSSID, addr2 the sender.
    framed.extend_from_slice(&dot11::build_deauth(&sta_mac, &mac_to_bytes(AP_MAC), 3));
    ap.handle_incoming(&framed);
    assert!(
        !ap.is_associated(&sta_mac),
        "without PMF an unprotected deauth still applies, as for any WPA2 station"
    );
}

#[test]
fn config_selects_psk_sha256() {
    let cfg = Config::from_json(
        r#"{"ssid":"sha256-net","passphrase":"password1234","key_mgmt":"psk-sha256"}"#,
    )
    .expect("config parses");
    assert_eq!(cfg.key_mgmt, KeyMgmt::PskSha256);
    assert!(cfg.validate().is_ok());
    assert_eq!(
        cfg.build_ap().security_mode(),
        dot11::SecurityMode::Wpa2PskSha256
    );

    // 6 GHz mandates PMF, which AKM 6 does not provide.
    let sixghz = Config::from_json(
        r#"{"ssid":"sha256-net","passphrase":"password1234","key_mgmt":"psk-sha256","band":6,"channel":37}"#,
    )
    .expect("config parses");
    assert!(sixghz.validate().is_err(), "6 GHz must reject PSK-SHA256");
}
