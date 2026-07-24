//! IGTK/BIGTK KDEs and BIP management-frame protection.

use super::kde::find_vendor_kde;
use crate::auth::crypto;

pub const EID_MME: u8 = 76;

/// Encode an IGTK KDE (00-0F-AC:9).
pub fn igtk_kde(key_id: u16, ipn: &[u8; 6], igtk: &[u8; 16]) -> Vec<u8> {
    management_key_kde(0x09, key_id, ipn, None, igtk)
}

/// Encode a BIGTK KDE (00-0F-AC:14).
pub fn bigtk_kde(key_id: u16, ipn: &[u8; 6], bigtk: &[u8; 16]) -> Vec<u8> {
    management_key_kde(0x0e, key_id, ipn, None, bigtk)
}

/// Encode an MLO IGTK KDE (00-0F-AC:17).
pub fn mlo_igtk_kde(link_id: u8, key_id: u16, ipn: &[u8; 6], igtk: &[u8; 16]) -> Vec<u8> {
    management_key_kde(0x11, key_id, ipn, Some(link_id), igtk)
}

/// Encode an MLO BIGTK KDE (00-0F-AC:18).
pub fn mlo_bigtk_kde(link_id: u8, key_id: u16, ipn: &[u8; 6], bigtk: &[u8; 16]) -> Vec<u8> {
    management_key_kde(0x12, key_id, ipn, Some(link_id), bigtk)
}

fn management_key_kde(
    kde_type: u8,
    key_id: u16,
    ipn: &[u8; 6],
    link_id: Option<u8>,
    key: &[u8; 16],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + 2 + 6 + usize::from(link_id.is_some()) + key.len());
    body.extend_from_slice(&[0x00, 0x0f, 0xac, kde_type]);
    body.extend_from_slice(&key_id.to_le_bytes());
    body.extend_from_slice(ipn);
    if let Some(link_id) = link_id {
        body.push((link_id & 0x0f) << 4);
    }
    body.extend_from_slice(key);

    let mut kde = Vec::with_capacity(body.len() + 2);
    kde.push(0xdd);
    kde.push(body.len() as u8);
    kde.extend_from_slice(&body);
    kde
}

pub fn parse_igtk_kde(key_data: &[u8]) -> Option<(u16, [u8; 6], [u8; 16])> {
    parse_management_key_kde(key_data, 0x09, false).map(|(_, key_id, ipn, key)| (key_id, ipn, key))
}

pub fn parse_bigtk_kde(key_data: &[u8]) -> Option<(u16, [u8; 6], [u8; 16])> {
    parse_management_key_kde(key_data, 0x0e, false).map(|(_, key_id, ipn, key)| (key_id, ipn, key))
}

pub fn parse_mlo_igtk_kde(key_data: &[u8]) -> Option<(u8, u16, [u8; 6], [u8; 16])> {
    parse_management_key_kde(key_data, 0x11, true)
}

pub fn parse_mlo_bigtk_kde(key_data: &[u8]) -> Option<(u8, u16, [u8; 6], [u8; 16])> {
    parse_management_key_kde(key_data, 0x12, true)
}

fn parse_management_key_kde(
    key_data: &[u8],
    kde_type: u8,
    mlo: bool,
) -> Option<(u8, u16, [u8; 6], [u8; 16])> {
    let body = find_vendor_kde(key_data, kde_type)?;
    let minimum = 4 + 2 + 6 + usize::from(mlo) + 16;
    if body.len() < minimum {
        return None;
    }
    let key_id = u16::from_le_bytes([body[4], body[5]]);
    let mut ipn = [0u8; 6];
    ipn.copy_from_slice(&body[6..12]);
    let (link_id, key_offset) = if mlo {
        ((body[12] >> 4) & 0x0f, 13)
    } else {
        (0, 12)
    };
    let mut key = [0u8; 16];
    key.copy_from_slice(&body[key_offset..key_offset + 16]);
    Some((link_id, key_id, ipn, key))
}

fn bip_aad(fc0: u8, fc1: u8, a1: &[u8; 6], a2: &[u8; 6], a3: &[u8; 6]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(20);
    aad.push(fc0);
    aad.push(fc1 & 0xc7);
    aad.extend_from_slice(a1);
    aad.extend_from_slice(a2);
    aad.extend_from_slice(a3);
    aad
}

/// Append a BIP-CMAC-128 Management MIC Element to a group management body.
#[allow(clippy::too_many_arguments)]
pub fn bip_protect(
    igtk: &[u8; 16],
    key_id: u16,
    ipn: &[u8; 6],
    fc0: u8,
    fc1: u8,
    a1: &[u8; 6],
    a2: &[u8; 6],
    a3: &[u8; 6],
    body: &[u8],
) -> Vec<u8> {
    let mme_offset = body.len();
    let mut protected = body.to_vec();
    protected.extend_from_slice(&[EID_MME, 16]);
    protected.extend_from_slice(&key_id.to_le_bytes());
    protected.extend_from_slice(ipn);
    protected.extend_from_slice(&[0; 8]);

    let mut input = bip_aad(fc0, fc1, a1, a2, a3);
    input.extend_from_slice(&protected);
    let mic = crypto::aes_cmac(igtk, &input);
    protected[mme_offset + 10..mme_offset + 18].copy_from_slice(&mic[..8]);
    protected
}

/// Verify a trailing BIP-CMAC-128 Management MIC Element.
#[allow(clippy::too_many_arguments)]
pub fn bip_verify(
    igtk: &[u8; 16],
    fc0: u8,
    fc1: u8,
    a1: &[u8; 6],
    a2: &[u8; 6],
    a3: &[u8; 6],
    body_with_mme: &[u8],
) -> bool {
    let Some(mme_offset) = body_with_mme.len().checked_sub(18) else {
        return false;
    };
    if body_with_mme[mme_offset..mme_offset + 2] != [EID_MME, 16] {
        return false;
    }
    let given = &body_with_mme[mme_offset + 10..mme_offset + 18];
    let mut protected = body_with_mme.to_vec();
    protected[mme_offset + 10..mme_offset + 18].fill(0);
    let mut input = bip_aad(fc0, fc1, a1, a2, a3);
    input.extend_from_slice(&protected);
    crypto::constant_time_eq(&crypto::aes_cmac(igtk, &input)[..8], given)
}

/// Extract a trailing Management MIC Element's 48-bit little-endian IPN.
pub fn bip_ipn(body_with_mme: &[u8]) -> Option<u64> {
    let mme_offset = body_with_mme.len().checked_sub(18)?;
    if body_with_mme[mme_offset..mme_offset + 2] != [EID_MME, 16] {
        return None;
    }
    let ipn = &body_with_mme[mme_offset + 4..mme_offset + 10];
    Some(u64::from_le_bytes([
        ipn[0], ipn[1], ipn[2], ipn[3], ipn[4], ipn[5], 0, 0,
    ]))
}

pub use crate::frames::build_group_deauth_bip;
