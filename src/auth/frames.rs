//! Authentication and station association frame support.

use crate::frames::*;
use crate::structures::common::AuthBody;
use crate::structures::security::{DataCipher, SecurityMode};

pub const AUTH_ALG_OPEN: u16 = 0;
pub const AUTH_ALG_SAE: u16 = 3;
pub const STATUS_SUCCESS: u16 = 0;
/// SAE Hash-to-Element indication, used as the commit status code.
pub const STATUS_SAE_H2E: u16 = 126;

/// A parsed Authentication frame body (algorithm, transaction seq, status, rest).
pub fn parse_auth(body: &[u8]) -> Option<AuthBody<'_>> {
    if body.len() < 6 {
        return None;
    }
    Some(AuthBody {
        algo: u16::from_le_bytes([body[0], body[1]]),
        seq: u16::from_le_bytes([body[2], body[3]]),
        status: u16::from_le_bytes([body[4], body[5]]),
        payload: &body[6..],
    })
}

/// Build an SAE Authentication frame (algorithm 3) carrying `payload` (a commit
/// or confirm body).
#[allow(clippy::too_many_arguments)]
pub fn build_sae_auth(
    a1: &[u8; 6],
    a2: &[u8; 6],
    a3: &[u8; 6],
    flags: u8,
    sc: u16,
    seq: u16,
    status: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut v = dot11_header(TYPE_MGMT, SUBTYPE_AUTH, flags, a1, a2, a3, sc);
    v.extend_from_slice(&AUTH_ALG_SAE.to_le_bytes());
    v.extend_from_slice(&seq.to_le_bytes());
    v.extend_from_slice(&status.to_le_bytes());
    v.extend_from_slice(payload);
    v
}

/// Open-system authentication request (STA -> AP), seqnum 1.
pub fn build_auth_req(bssid: &[u8; 6], sta: &[u8; 6], sc: u16) -> Vec<u8> {
    // ToDS/FromDS are meaningful only for Data frames. Real drivers may
    // silently drop management injection when either DS bit is set.
    let mut v = dot11_header(TYPE_MGMT, SUBTYPE_AUTH, 0, bssid, sta, bssid, sc);
    v.extend_from_slice(&0u16.to_le_bytes()); // algo = open
    v.extend_from_slice(&1u16.to_le_bytes()); // seqnum
    v.extend_from_slice(&0u16.to_le_bytes()); // status
    v
}

/// Association request (STA -> AP) advertising the SSID and RSN/CCMP.
pub fn build_assoc_req(bssid: &[u8; 6], sta: &[u8; 6], ssid: &[u8], sc: u16) -> Vec<u8> {
    build_assoc_req_for_cipher(bssid, sta, ssid, sc, DataCipher::Ccmp128)
}

/// WPA2 association request selecting an explicit pairwise cipher.
pub fn build_assoc_req_for_cipher(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    ssid: &[u8],
    sc: u16,
    cipher: DataCipher,
) -> Vec<u8> {
    let mut v = dot11_header(TYPE_MGMT, SUBTYPE_ASSOC_REQ, 0, bssid, sta, bssid, sc);
    v.extend_from_slice(&CAP_3101);
    v.extend_from_slice(&STA_LISTEN_INTERVAL.to_le_bytes()); // listen interval
    v.extend_from_slice(&ie(0, ssid));
    v.extend_from_slice(&ie(1, &[0x0c]));
    v.extend_from_slice(&security_tail_for_cipher(SecurityMode::Wpa2, cipher));
    v
}

/// Association request selecting WPA-PSK-SHA256 rather than legacy PSK.
pub fn build_assoc_req_psk_sha256(bssid: &[u8; 6], sta: &[u8; 6], ssid: &[u8], sc: u16) -> Vec<u8> {
    build_assoc_req_psk_sha256_for_cipher(bssid, sta, ssid, sc, DataCipher::Ccmp128)
}

/// WPA-PSK-SHA256 association request selecting an explicit pairwise cipher.
pub fn build_assoc_req_psk_sha256_for_cipher(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    ssid: &[u8],
    sc: u16,
    cipher: DataCipher,
) -> Vec<u8> {
    let mut v = dot11_header(TYPE_MGMT, SUBTYPE_ASSOC_REQ, 0, bssid, sta, bssid, sc);
    v.extend_from_slice(&CAP_3101);
    v.extend_from_slice(&STA_LISTEN_INTERVAL.to_le_bytes());
    v.extend_from_slice(&ie(0, ssid));
    v.extend_from_slice(&ie(1, &[0x0c]));
    let mut rsn = RSN_PSK_SHA256;
    rsn[13] = cipher.suite_type();
    v.extend_from_slice(&rsn);
    v
}

/// Association request for WPA3-SAE: advertises the SAE AKM (00-0F-AC:8),
/// MFPR|MFPC, the BIP group-management cipher, and the RSNXE H2E capability.
/// (A WPA2-PSK RSN here would be rejected by an SAE AP with "Invalid AKMP".)
pub fn build_assoc_req_sae(bssid: &[u8; 6], sta: &[u8; 6], ssid: &[u8], sc: u16) -> Vec<u8> {
    build_assoc_req_sae_for_cipher(bssid, sta, ssid, sc, DataCipher::Ccmp128)
}

/// WPA3-SAE association request selecting an explicit pairwise cipher.
pub fn build_assoc_req_sae_for_cipher(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    ssid: &[u8],
    sc: u16,
    cipher: DataCipher,
) -> Vec<u8> {
    let mut v = dot11_header(TYPE_MGMT, SUBTYPE_ASSOC_REQ, 0, bssid, sta, bssid, sc);
    v.extend_from_slice(&CAP_3101);
    v.extend_from_slice(&STA_LISTEN_INTERVAL.to_le_bytes());
    v.extend_from_slice(&ie(0, ssid));
    v.extend_from_slice(&ie(1, &[0x0c]));
    v.extend_from_slice(&security_tail_for_cipher(SecurityMode::Wpa3Sae, cipher));
    v
}
