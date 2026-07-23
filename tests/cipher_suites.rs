//! Pairwise cipher negotiation and 128/256-bit temporal-key sizing.

use barely_ap::config::Config;
use barely_ap::structures::DataCipher;
use barely_ap::{crypto, dot11};

const CIPHERS: [DataCipher; 4] = [
    DataCipher::Ccmp128,
    DataCipher::Gcmp128,
    DataCipher::Ccmp256,
    DataCipher::Gcmp256,
];

#[test]
fn rsn_advertises_and_validates_each_pairwise_cipher() {
    for cipher in CIPHERS {
        let tail = dot11::security_tail_for_cipher(dot11::SecurityMode::Wpa2, cipher);
        assert_eq!(tail[0], 48);
        assert_eq!(tail[13], cipher.suite_type());
        let rsn_len = usize::from(tail[1]);
        assert_eq!(
            dot11::validate_assoc_rsn_for_cipher(
                &tail[2..2 + rsn_len],
                dot11::SecurityMode::Wpa2,
                cipher,
            ),
            Ok(())
        );
    }
}

#[test]
fn rsn_rejects_a_different_pairwise_suite() {
    let tail = dot11::security_tail_for_cipher(dot11::SecurityMode::Wpa2, DataCipher::Gcmp256);
    let rsn_len = usize::from(tail[1]);
    assert!(dot11::validate_assoc_rsn_for_cipher(
        &tail[2..2 + rsn_len],
        dot11::SecurityMode::Wpa2,
        DataCipher::Ccmp256,
    )
    .is_err());
}

#[test]
fn data_cipher_key_lengths_and_nl80211_selectors_are_exact() {
    assert_eq!(DataCipher::Ccmp128.key_len(), 16);
    assert_eq!(DataCipher::Gcmp128.key_len(), 16);
    assert_eq!(DataCipher::Ccmp256.key_len(), 32);
    assert_eq!(DataCipher::Gcmp256.key_len(), 32);

    assert_eq!(DataCipher::Ccmp128.suite_selector(), 0x000f_ac04);
    assert_eq!(DataCipher::Gcmp128.suite_selector(), 0x000f_ac08);
    assert_eq!(DataCipher::Gcmp256.suite_selector(), 0x000f_ac09);
    assert_eq!(DataCipher::Ccmp256.suite_selector(), 0x000f_ac0a);
}

#[test]
fn sha256_ptk_expands_for_a_256_bit_temporal_key() {
    let pmk = [0x11; 32];
    let aa = [0x20; 6];
    let spa = [0x30; 6];
    let anonce = [0x40; 32];
    let snonce = [0x50; 32];
    let ptk = crypto::derive_ptk_sha256_len(&pmk, &aa, &spa, &anonce, &snonce, 64);
    assert_eq!(ptk.len(), 16 + 16 + 32);
    assert!(ptk[32..].iter().any(|byte| *byte != 0));
}

#[test]
fn eapol_messages_carry_the_256_bit_pairwise_key_length() {
    let ap = [0x02, 0, 0, 0, 0, 0];
    let sta = [0x02, 0, 0, 0, 0xab, 0xcd];
    let anonce = [0x33; 32];
    let m1 =
        dot11::build_eapol_m1_for_key_length(&ap, &sta, &anonce, 1, 0, dot11::KeyMic::HmacSha1, 32);
    let m1 = dot11::Dot11::parse(&m1).unwrap();
    let m1 = dot11::EapolKey::parse(m1.eapol_key_body().unwrap()).unwrap();
    assert_eq!(m1.key_length, 32);

    let rsn = dot11::security_tail_for_cipher(dot11::SecurityMode::Wpa2, DataCipher::Ccmp256);
    let m3 = dot11::build_eapol_m3_for_key_length(
        &ap,
        &sta,
        &anonce,
        &[0x44; 16],
        &[0x55; 16],
        &rsn,
        1,
        &[0x66; 16],
        None,
        None,
        None,
        2,
        0,
        dot11::KeyMic::HmacSha1,
        32,
    );
    let m3 = dot11::Dot11::parse(&m3).unwrap();
    let m3 = dot11::EapolKey::parse(m3.eapol_key_body().unwrap()).unwrap();
    assert_eq!(m3.key_length, 32);
}

#[test]
fn ap_config_non_default_ciphers_are_explicitly_linux_netlink_only() {
    let netlink = Config::from_json(
        r#"{
            "ssid":"cipher-test",
            "passphrase":"password1234",
            "mode":"netlink",
            "cipher":"gcmp-256"
        }"#,
    )
    .unwrap();
    assert_eq!(netlink.pairwise_cipher, DataCipher::Gcmp256);
    assert!(netlink.validate().is_ok());

    let userspace = Config::from_json(
        r#"{
            "ssid":"cipher-test",
            "passphrase":"password1234",
            "mode":"iface",
            "cipher":"gcmp-128"
        }"#,
    )
    .unwrap();
    assert!(userspace.validate().is_err());
}

#[test]
fn userspace_data_round_trips_all_four_aes_suites() {
    let ap = [0x02, 0, 0, 0, 0, 0];
    let sta = [0x02, 0, 0, 0, 0xab, 0xcd];
    let payload = b"independent userspace CCMP/GCMP payload";

    for cipher in CIPHERS {
        let key: Vec<u8> = (0..cipher.key_len()).map(|i| i as u8).collect();
        let encoded = dot11::build_protected_data_sec(
            cipher,
            &sta,
            &ap,
            &ap,
            &sta,
            &ap,
            &ap,
            dot11::FC_FROMDS | dot11::FC_PROTECTED,
            0x20,
            7,
            0,
            &key,
            0x0800,
            payload,
            Some(0),
        );
        let frame = dot11::Dot11::parse(&encoded).unwrap();
        let ethernet = dot11::decrypt_protected_data_sec(cipher, &frame, &key, true, None).unwrap();
        assert_eq!(&ethernet[..6], &sta);
        assert_eq!(&ethernet[6..12], &ap);
        assert_eq!(&ethernet[12..14], &[0x08, 0x00]);
        assert_eq!(&ethernet[14..], payload);

        let mut tampered = encoded;
        *tampered.last_mut().unwrap() ^= 0x80;
        let tampered = dot11::Dot11::parse(&tampered).unwrap();
        assert!(dot11::decrypt_protected_data_sec(cipher, &tampered, &key, true, None).is_none());
    }
}

#[test]
fn protected_management_round_trips_all_four_aes_suites() {
    let ap = [0x02, 0, 0, 0, 0, 0];
    let sta = [0x02, 0, 0, 0, 0xab, 0xcd];
    let body = [
        dot11::ACTION_CATEGORY_SA_QUERY,
        dot11::SA_QUERY_REQUEST,
        7,
        0,
    ];

    for cipher in CIPHERS {
        let key = vec![0x5a; cipher.key_len()];
        let encoded = dot11::build_protected_mgmt_sec(
            cipher,
            dot11::SUBTYPE_ACTION,
            &sta,
            &ap,
            &ap,
            None,
            0,
            0x30,
            9,
            0,
            &key,
            &body,
        );
        let frame = dot11::Dot11::parse(&encoded).unwrap();
        assert_eq!(
            dot11::decrypt_protected_mgmt_sec(cipher, &frame, &key, None),
            Some(body.to_vec())
        );
    }
}
