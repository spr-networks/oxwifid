//! Opportunistic Wireless Encryption (OWE).

use super::group19::{
    point_from_p256, point_to_p256, scalar_pad, Curve, Point, SecretScalar, PRIME_LEN,
};
use crate::frames::*;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

fn hkdf_extract(salt: &[u8], input: &[&[u8]]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(salt).expect("any HKDF salt length");
    for part in input {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

fn hkdf_expand(prk: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len);
    let mut previous = Vec::new();
    let mut counter = 1u8;
    while out.len() < out_len {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(prk).expect("SHA-256 PRK length");
        mac.update(&previous);
        mac.update(info);
        mac.update(&[counter]);
        previous.zeroize();
        previous = mac.finalize().into_bytes().to_vec();
        out.extend_from_slice(&previous);
        counter += 1;
    }
    previous.zeroize();
    out.truncate(out_len);
    out
}

pub fn build_dh_param_element(group: u16, pubkey: &[u8]) -> Vec<u8> {
    let mut info = vec![32u8]; // Element ID Extension = 32 (DH Parameter)
    info.extend_from_slice(&group.to_le_bytes());
    info.extend_from_slice(pubkey);
    ie(255, &info)
}

/// Parse an OWE DH Parameter element from an IE list, returning `(group, pubkey)`.
pub fn parse_dh_param(ies: &[u8]) -> Option<(u16, Vec<u8>)> {
    let mut i = 0;
    while i + 2 <= ies.len() {
        let id = ies[i];
        let len = ies[i + 1] as usize;
        if i + 2 + len > ies.len() {
            break;
        }
        let body = &ies[i + 2..i + 2 + len];
        if id == 255 && len >= 3 && body[0] == 32 {
            let group = u16::from_le_bytes([body[1], body[2]]);
            return Some((group, body[3..].to_vec()));
        }
        i += 2 + len;
    }
    None
}

/// RSN element advertising the OWE AKM (00-0F-AC:18), CCMP, MFPR|MFPC.
pub const RSN_OWE: [u8; 22] = [
    0x30, 0x14, // id 48, len 20
    0x01, 0x00, // version
    0x00, 0x0f, 0xac, 0x04, // group: CCMP
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, // 1 pairwise: CCMP
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x12, // 1 AKM: OWE (18)
    0xc0, 0x00, // RSN caps: MFPR|MFPC
];

/// Association request for OWE: open + RSN(OWE) + the DH Parameter element.
pub fn build_assoc_req_owe(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    ssid: &[u8],
    dh_element: &[u8],
    sc: u16,
) -> Vec<u8> {
    let mut v = dot11_header(TYPE_MGMT, SUBTYPE_ASSOC_REQ, FC_TODS, bssid, sta, bssid, sc);
    v.extend_from_slice(&CAP_3101);
    v.extend_from_slice(&STA_LISTEN_INTERVAL.to_le_bytes());
    v.extend_from_slice(&ie(0, ssid));
    v.extend_from_slice(&ie(1, &[0x0c]));
    v.extend_from_slice(&RSN_OWE);
    v.extend_from_slice(dh_element);
    v
}

/// A WPA3-SAE RSN element carrying a cached PMKID, for PMKSA-caching fast
/// reconnect.
pub fn rsn_with_pmkid(pmkid: &[u8; 16]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x01, 0x00]); // version
    body.extend_from_slice(&[0x00, 0x0f, 0xac, 0x04]); // group: CCMP
    body.extend_from_slice(&[0x01, 0x00, 0x00, 0x0f, 0xac, 0x04]); // 1 pairwise: CCMP
    body.extend_from_slice(&[0x01, 0x00, 0x00, 0x0f, 0xac, 0x08]); // 1 AKM: SAE
    body.extend_from_slice(&[0xc0, 0x00]); // RSN caps: MFPR|MFPC
    body.extend_from_slice(&[0x01, 0x00]); // PMKID count = 1
    body.extend_from_slice(pmkid);
    body.extend_from_slice(&[0x00, 0x0f, 0xac, 0x06]); // group mgmt: BIP
    ie(48, &body)
}

/// Association request including a cached PMKID (PMKSA caching reconnect).
pub fn build_assoc_req_pmkid(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    ssid: &[u8],
    pmkid: &[u8; 16],
    sc: u16,
) -> Vec<u8> {
    let mut v = dot11_header(TYPE_MGMT, SUBTYPE_ASSOC_REQ, FC_TODS, bssid, sta, bssid, sc);
    v.extend_from_slice(&CAP_3101);
    v.extend_from_slice(&STA_LISTEN_INTERVAL.to_le_bytes());
    v.extend_from_slice(&ie(0, ssid));
    v.extend_from_slice(&ie(1, &[0x0c]));
    v.extend_from_slice(&rsn_with_pmkid(pmkid));
    v.extend_from_slice(&RSNXE_H2E);
    v
}

/// Generate an ephemeral group-19 OWE key pair.
pub fn owe_keypair() -> (SecretScalar, Vec<u8>) {
    let private = SecretScalar::random();
    let public = point_from_p256(
        point_to_p256(&super::group19::generator()).expect("P-256 generator") * private.scalar(),
    );
    let x = match public {
        Point::Affine(x, _) => scalar_pad(&x, PRIME_LEN),
        Point::Infinity => unreachable!("non-zero scalar times generator is finite"),
    };
    (private, x)
}

fn point_from_x(curve: &Curve, x: &[u8]) -> Option<Point> {
    let mut compressed = Vec::with_capacity(1 + x.len());
    compressed.push(0x02);
    compressed.extend_from_slice(x);
    curve.point_from_compressed(&compressed)
}

/// Derive the OWE PMK and PMKID according to RFC 8110 section 4.4.
pub fn owe_derive(
    private: &SecretScalar,
    peer_public_x: &[u8],
    station_public_x: &[u8],
    ap_public_x: &[u8],
    group: u16,
) -> Option<([u8; 32], [u8; 16])> {
    let curve = Curve::p256();
    let peer = point_from_x(&curve, peer_public_x)?;
    let shared =
        point_from_p256(point_to_p256(&peer).expect("validated P-256 point") * private.scalar());
    let mut shared_x = match shared {
        Point::Affine(x, _) => scalar_pad(&x, PRIME_LEN),
        Point::Infinity => return None,
    };

    let mut salt = Vec::with_capacity(station_public_x.len() + ap_public_x.len() + 2);
    salt.extend_from_slice(station_public_x);
    salt.extend_from_slice(ap_public_x);
    salt.extend_from_slice(&group.to_le_bytes());
    let mut prk = hkdf_extract(&salt, &[&shared_x]);
    let mut pmk_bytes = hkdf_expand(&prk, b"OWE Key Generation", 32);

    let mut digest = Sha256::new();
    digest.update(station_public_x);
    digest.update(ap_public_x);
    let digest = digest.finalize();

    let mut pmk = [0u8; 32];
    pmk.copy_from_slice(&pmk_bytes);
    let mut pmkid = [0u8; 16];
    pmkid.copy_from_slice(&digest[..16]);
    shared_x.zeroize();
    prk.zeroize();
    pmk_bytes.zeroize();
    Some((pmk, pmkid))
}
