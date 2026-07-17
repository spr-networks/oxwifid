//! Verify the SAE implementation against the IEEE 802.11-2020 Annex J.10 test
//! vectors (the same ones hostap's `sae_tests()` uses).
//!
//!   * H2E PWE (group 19) is checked directly against `pwe_19_x/y`.
//!   * The SAE protocol (commit, shared secret k, KCK/PMK/PMKID) is checked
//!     against the J.10 commit/key vector by recovering its PWE from the
//!     committed element and the known `mask` (so the hunting-and-pecking PWE
//!     derivation does not need to be reimplemented).

use barely_ap::sae::{self, Curve, Point, Sae};
use barely_ap::util::{from_hex, to_hex};
use num_bigint::BigUint;

// ---- Annex J.10 constants -------------------------------------------------

const ADDR1: [u8; 6] = [0x4d, 0x3f, 0x2f, 0xff, 0xe3, 0x87];
const ADDR2: [u8; 6] = [0xa5, 0xd8, 0xaa, 0x95, 0x8e, 0x3c];
const ADDR1B: [u8; 6] = [0x00, 0x09, 0x5b, 0x66, 0xec, 0x1e];
const ADDR2B: [u8; 6] = [0x00, 0x0b, 0x6b, 0xd9, 0x02, 0x46];

const LOCAL_RAND: &str = "992465fd3daa3c60aa6565b7f62a2a7f2e12dd12f198faf4fbed89d7ff1ace94";
const LOCAL_MASK: &str = "9507a90f777a044d6a0830b91ea3d5dd70bece44e1acffb86983b5e1bf9fb322";
const LOCAL_COMMIT_FULL: &str = "13002e2c0f0db52440ad146d967114ce005ce1eab0aa2c2e5c2871b774f6c2575c65d5ad9e00829707aa36ba8b859738fc961d08243505f47c035376d7ac4bc8d7b95083bf43827d0fc31ed778dd3671fd21a46d1091d64b6f9a1e1272621325dbe1";
const PEER_COMMIT: &str = "1300591b96f3397fb945100848e7b550543b6720d88337ee93fc49fd6df7e08b5223e71b9bb048d3873f20556953a96c91536fd8ee6ca9b4a68a148b056a909be03e83ae208f60f8ef5537858074db06687032399862999b511e0a1552a5fea317c2";
const KCK: &str = "1e733f6d9bd53256287304338831b09a39406d121017073a5c30db36f36cb81a";
const PMK: &str = "4e4dfab1a2dd8ac1a91790f953faaa452ae5c6873ab75b63605ba663f8a7fe59";
const PMKID: &str = "8747a600eea3f9f22475df58ca1e5498";
const PWE19_X: &str = "c93049b9e64000f848201649e999f2b5c22dea69b5632c9df4d633b8aa1f6c1e";
const PWE19_Y: &str = "73634e94b53d82e7383a8d258199d9dc1a5ee8269d060382ccbf33e614ff59a0";

#[test]
fn h2e_pwe_group19_matches_ieee_j10() {
    let c = Curve::p256();
    let pt = sae::derive_pt(&c, b"byteme", b"mekmitasdigoat", Some(b"psk4internet"));
    let pwe = sae::derive_pwe_from_pt(&c, &pt, &ADDR1B, &ADDR2B);
    let bin = c.point_to_bin(&pwe).unwrap();
    assert_eq!(to_hex(&bin[..32]), PWE19_X, "PWE.x");
    assert_eq!(to_hex(&bin[32..]), PWE19_Y, "PWE.y");
}

/// Recover the hunting-and-pecking PWE used by the J.10 commit vector from the
/// committed element and the known mask: element = -(mask * PWE), so
/// PWE = mask^-1 * (-element).
fn recover_pwe(c: &Curve, commit_full: &[u8], mask: &BigUint) -> Point {
    let elem = c.point_from_bin(&commit_full[34..98]).unwrap();
    let neg_elem = c.negate(&elem);
    let inv = sae::mod_inverse(mask, &c.n);
    c.scalar_mul(&inv, &neg_elem)
}

#[test]
fn hunting_and_pecking_matches_ieee_j10() {
    // The J.10 commit/key vector is generated with the hunting-and-pecking PWE.
    // Deriving it independently and running the protocol must reproduce the
    // standard's local commit, KCK, PMK, and PMKID.
    let c = Curve::p256();
    let pwe =
        sae::derive_pwe_hunting_pecking(&c, b"mekmitasdigoat", &ADDR1, &ADDR2).expect("H&P PWE");
    assert!(c.on_curve(&pwe));

    let rand = BigUint::from_bytes_be(&from_hex(LOCAL_RAND));
    let mask = BigUint::from_bytes_be(&from_hex(LOCAL_MASK));
    let mut sae = Sae::with_pwe(pwe);
    sae.prepare_commit(Some((rand, mask)));
    assert_eq!(
        to_hex(&sae.write_commit()),
        LOCAL_COMMIT_FULL,
        "commit (H&P PWE)"
    );

    sae.parse_peer_commit(&from_hex(PEER_COMMIT)).unwrap();
    sae.process_commit().unwrap();
    assert_eq!(to_hex(&sae.kck), KCK, "KCK");
    assert_eq!(to_hex(&sae.pmk), PMK, "PMK");
    assert_eq!(to_hex(&sae.pmkid), PMKID, "PMKID");
}

#[test]
fn sae_protocol_matches_ieee_j10() {
    let c = Curve::p256();
    let local_commit = from_hex(LOCAL_COMMIT_FULL);
    let peer_commit = from_hex(PEER_COMMIT);
    let rand = BigUint::from_bytes_be(&from_hex(LOCAL_RAND));
    let mask = BigUint::from_bytes_be(&from_hex(LOCAL_MASK));

    let pwe = recover_pwe(&c, &local_commit, &mask);
    assert!(c.on_curve(&pwe), "recovered PWE must be on curve");

    let mut sae = Sae::with_pwe(pwe);
    sae.prepare_commit(Some((rand, mask)));

    // The reconstructed commit must equal the J.10 local commit byte-for-byte.
    assert_eq!(to_hex(&sae.write_commit()), to_hex(&local_commit), "commit");

    sae.parse_peer_commit(&peer_commit)
        .expect("peer commit parses");
    sae.process_commit().expect("process commit");

    assert_eq!(to_hex(&sae.kck), KCK, "KCK");
    assert_eq!(to_hex(&sae.pmk), PMK, "PMK");
    assert_eq!(to_hex(&sae.pmkid), PMKID, "PMKID");
}

#[test]
fn full_h2e_exchange_between_two_peers_agrees() {
    // Two independent SAE instances (AP + STA) with H2E PWE must derive the same
    // PMK and verify each other's confirm.
    let ap_mac = ADDR1;
    let sta_mac = ADDR2;
    let ssid = b"byteme";
    let pw = b"mekmitasdigoat";

    let mut ap = Sae::new_h2e(ssid, pw, None, &ap_mac, &sta_mac);
    let mut sta = Sae::new_h2e(ssid, pw, None, &sta_mac, &ap_mac);
    // both sides derive the same PWE (symmetric in addresses)
    assert_eq!(
        ap.curve.point_to_bin(&ap.pwe).unwrap(),
        sta.curve.point_to_bin(&sta.pwe).unwrap()
    );

    ap.prepare_commit(None);
    sta.prepare_commit(None);

    let ap_commit = ap.write_commit();
    let sta_commit = sta.write_commit();

    ap.parse_peer_commit(&sta_commit).unwrap();
    sta.parse_peer_commit(&ap_commit).unwrap();
    ap.process_commit().unwrap();
    sta.process_commit().unwrap();

    assert_eq!(to_hex(&ap.pmk), to_hex(&sta.pmk), "PMK agreement");
    assert_eq!(to_hex(&ap.pmkid), to_hex(&sta.pmkid), "PMKID agreement");

    let ap_confirm = ap.write_confirm();
    let sta_confirm = sta.write_confirm();
    ap.check_confirm(&sta_confirm)
        .expect("AP verifies STA confirm");
    sta.check_confirm(&ap_confirm)
        .expect("STA verifies AP confirm");
}

#[test]
fn owe_two_parties_derive_the_same_pmk() {
    // OWE (RFC 8110): the STA and AP independently derive the same PMK/PMKID
    // from the ephemeral Diffie-Hellman exchange.
    let (sta_priv, sta_pub) = sae::owe_keypair();
    let (ap_priv, ap_pub) = sae::owe_keypair();
    let group = 19;
    let (sta_pmk, sta_pmkid) =
        sae::owe_derive(&sta_priv, &ap_pub, &sta_pub, &ap_pub, group).unwrap();
    let (ap_pmk, ap_pmkid) = sae::owe_derive(&ap_priv, &sta_pub, &sta_pub, &ap_pub, group).unwrap();
    assert_eq!(to_hex(&sta_pmk), to_hex(&ap_pmk), "OWE PMK agreement");
    assert_eq!(to_hex(&sta_pmkid), to_hex(&ap_pmkid), "OWE PMKID agreement");
    // distinct exchanges yield distinct keys
    let (other_priv, _) = sae::owe_keypair();
    let (other_pmk, _) = sae::owe_derive(&other_priv, &ap_pub, &sta_pub, &ap_pub, group).unwrap();
    assert_ne!(to_hex(&sta_pmk), to_hex(&other_pmk));
}

#[test]
fn rejects_off_curve_peer_element() {
    let c = Curve::p256();
    let mut sae = Sae::new_h2e(b"byteme", b"mekmitasdigoat", None, &ADDR1, &ADDR2);
    sae.prepare_commit(None);
    // group 19 + valid-looking scalar but a bogus (off-curve) element
    let mut bad = Vec::new();
    bad.extend_from_slice(&19u16.to_le_bytes());
    bad.extend_from_slice(&[0x11u8; 32]); // scalar
    bad.extend_from_slice(&[0x22u8; 64]); // element not on curve
    assert!(sae.parse_peer_commit(&bad).is_err());
    let _ = c; // silence unused in some cfgs
}
