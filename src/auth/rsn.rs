//! RSN negotiation, validation, OCV, and security information elements.

use crate::frames::*;
use crate::structures::security::{DataCipher, SecurityMode};

pub const RSN: [u8; 22] = [
    0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
    0x00, 0x0f, 0xac, 0x02, 0x00, 0x00,
];

/// RSN information element for WPA-PSK-SHA256 (00-0F-AC:6) with CCMP.
pub const RSN_PSK_SHA256: [u8; 22] = [
    0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
    0x00, 0x0f, 0xac, 0x06, 0x00, 0x00,
];

/// RSN information element for WPA3-SAE: CCMP-128 pairwise/group, AKM = SAE
/// (00-0F-AC:8), RSN capabilities with MFPR|MFPC set, and a Group Management
/// Cipher Suite of BIP-CMAC-128 (00-0F-AC:6) for PMF.
pub const RSN_WPA3: [u8; 28] = [
    0x30, 0x1a, // id 48, len 26
    0x01, 0x00, // version
    0x00, 0x0f, 0xac, 0x04, // group data cipher: CCMP-128
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, // 1 pairwise: CCMP-128
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x08, // 1 AKM: SAE
    0xc0, 0x00, // RSN caps: MFPR (0x40) | MFPC (0x80)
    0x00, 0x00, // PMKID count = 0
    0x00, 0x0f, 0xac, 0x06, // group mgmt cipher: BIP-CMAC-128
];

/// RSN Extended Capabilities element advertising SAE Hash-to-Element support
/// (Extended RSN Capabilities bit 5).
pub const RSNXE_H2E: [u8; 3] = [0xf4, 0x01, 0x20];

/// WPA2/WPA3 transition-mode RSN element: CCMP, **both** SAE (00-0F-AC:8) and
/// PSK (00-0F-AC:2) AKMs, MFPC set but not required (so WPA2 clients can still
/// join), and a BIP group-management cipher.
pub const RSN_TRANSITION: [u8; 32] = [
    0x30, 0x1e, // id 48, len 30
    0x01, 0x00, // version
    0x00, 0x0f, 0xac, 0x04, // group data cipher: CCMP
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, // 1 pairwise: CCMP
    0x02, 0x00, 0x00, 0x0f, 0xac, 0x08, 0x00, 0x0f, 0xac, 0x02, // 2 AKMs: SAE, PSK
    0x80, 0x00, // RSN caps: MFPC (capable, not required)
    0x00, 0x00, // PMKID count
    0x00, 0x0f, 0xac, 0x06, // group mgmt cipher: BIP
];

pub fn security_tail(mode: SecurityMode) -> Vec<u8> {
    security_tail_for_cipher(mode, DataCipher::Ccmp128)
}

/// Build the advertised RSN/RSNXE tail for an explicit pairwise cipher.
///
/// Group traffic remains CCMP-128, matching reference AP's mixed-strength
/// configuration: only the pairwise suite and its TK expand to 256 bits.
pub fn security_tail_for_cipher(mode: SecurityMode, cipher: DataCipher) -> Vec<u8> {
    let mut v = Vec::new();
    match mode {
        SecurityMode::Wpa2 => v.extend_from_slice(&RSN),
        SecurityMode::Wpa3Sae => {
            v.extend_from_slice(&RSN_WPA3);
            v.extend_from_slice(&RSNXE_H2E);
        }
        SecurityMode::Transition => {
            v.extend_from_slice(&RSN_TRANSITION);
            v.extend_from_slice(&RSNXE_H2E);
        }
        SecurityMode::Owe => v.extend_from_slice(&RSN_OWE),
    }
    // Every canonical RSNE above starts at v[0] and has one pairwise selector:
    // id,len,version,group,count, OUI,type. RSNXE (if any) follows it.
    v[13] = cipher.suite_type();
    v
}

struct RsnInfo {
    group: [u8; 4],
    pairwise: Vec<[u8; 4]>,
    akms: Vec<[u8; 4]>,
    capabilities: Option<u16>,
    group_mgmt: Option<[u8; 4]>,
}

fn parse_rsn(rsn: &[u8]) -> Option<RsnInfo> {
    let mut off = 0usize;
    let take_u16 = |data: &[u8], off: &mut usize| -> Option<u16> {
        let bytes = data.get(*off..*off + 2)?;
        *off += 2;
        Some(u16::from_le_bytes([bytes[0], bytes[1]]))
    };
    let take_suite = |data: &[u8], off: &mut usize| -> Option<[u8; 4]> {
        let suite: [u8; 4] = data.get(*off..*off + 4)?.try_into().ok()?;
        *off += 4;
        Some(suite)
    };

    if take_u16(rsn, &mut off)? != 1 {
        return None;
    }
    let group = take_suite(rsn, &mut off)?;
    let pairwise_count = take_u16(rsn, &mut off)? as usize;
    if pairwise_count == 0 {
        return None;
    }
    let mut pairwise = Vec::with_capacity(pairwise_count.min(8));
    for _ in 0..pairwise_count {
        pairwise.push(take_suite(rsn, &mut off)?);
    }
    let akm_count = take_u16(rsn, &mut off)? as usize;
    if akm_count == 0 {
        return None;
    }
    let mut akms = Vec::with_capacity(akm_count.min(8));
    for _ in 0..akm_count {
        akms.push(take_suite(rsn, &mut off)?);
    }

    // RSN Capabilities and everything after it are optional. Once an optional
    // field starts, though, it must be complete and the final length exact.
    let capabilities = if off == rsn.len() {
        None
    } else {
        Some(take_u16(rsn, &mut off)?)
    };
    let mut group_mgmt = None;
    if off < rsn.len() {
        let pmkid_count = take_u16(rsn, &mut off)? as usize;
        for _ in 0..pmkid_count {
            let _: [u8; 16] = rsn.get(off..off + 16)?.try_into().ok()?;
            off += 16;
        }
        if off < rsn.len() {
            group_mgmt = Some(take_suite(rsn, &mut off)?);
        }
    }
    if off != rsn.len() {
        return None;
    }
    Some(RsnInfo {
        group,
        pairwise,
        akms,
        capabilities,
        group_mgmt,
    })
}

fn rsn_suite(suite_type: u8) -> [u8; 4] {
    [0x00, 0x0f, 0xac, suite_type]
}

/// Validate the mandatory RSN negotiation in an association request for the
/// security mode advertised by this BSS. PMKIDs remain optional and are checked
/// separately against the cache.
pub fn validate_assoc_rsn(rsn: &[u8], mode: SecurityMode) -> Result<(), u16> {
    validate_assoc_rsn_for_cipher(rsn, mode, DataCipher::Ccmp128)
}

/// Validate an association RSNE against the BSS's configured pairwise suite.
pub fn validate_assoc_rsn_for_cipher(
    rsn: &[u8],
    mode: SecurityMode,
    cipher: DataCipher,
) -> Result<(), u16> {
    // reference AP reports a syntactically complete Version-only RSNE as "invalid
    // AKMP" (43), while empty/truncated versions are invalid IEs (40).
    if rsn == [1, 0] {
        return Err(STATUS_INVALID_AKMP);
    }
    let info = parse_rsn(rsn).ok_or(STATUS_INVALID_IE)?;
    if info.group != rsn_suite(4) || !info.pairwise.contains(&rsn_suite(cipher.suite_type())) {
        return Err(STATUS_INVALID_IE);
    }
    let has_psk = info.akms.contains(&rsn_suite(2));
    let has_sae = info.akms.contains(&rsn_suite(8));
    let has_owe = info.akms.contains(&rsn_suite(18));
    let supported = match mode {
        SecurityMode::Wpa2 => has_psk,
        SecurityMode::Wpa3Sae => has_sae,
        SecurityMode::Transition => has_psk || has_sae,
        SecurityMode::Owe => has_owe,
    };
    if !supported {
        return Err(STATUS_INVALID_AKMP);
    }

    // SAE and OWE require management-frame protection. In transition mode this
    // applies when the station selects SAE; legacy PSK associations may omit
    // RSN Capabilities entirely, matching reference AP.
    if matches!(mode, SecurityMode::Wpa3Sae | SecurityMode::Owe)
        || (mode == SecurityMode::Transition && has_sae && !has_psk)
    {
        let caps = info.capabilities.ok_or(STATUS_INVALID_IE)?;
        if caps & 0x00c0 != 0x00c0 {
            return Err(STATUS_INVALID_IE);
        }
    }
    Ok(())
}

/// Validate a scanned BSS/association RSN for the WPA-PSK-SHA256 AKM.
pub fn validate_psk_sha256_rsn(rsn: &[u8]) -> Result<(), u16> {
    let info = parse_rsn(rsn).ok_or(STATUS_INVALID_IE)?;
    if info.group != rsn_suite(4)
        || !info.pairwise.contains(&rsn_suite(4))
        || !info.akms.contains(&rsn_suite(6))
    {
        return Err(STATUS_INVALID_AKMP);
    }
    Ok(())
}

/// Whether an RSN Extension element body advertises SAE Hash-to-Element.
///
/// RSNXE is extensible: capability bit 5 is meaningful even when later octets
/// are present. Requiring the exact canonical one-octet body rejects the long
/// RSNXE vectors reference AP intentionally accepts.
pub fn rsnxe_has_sae_h2e(rsnxe: &[u8]) -> bool {
    rsnxe
        .first()
        .is_some_and(|capabilities| capabilities & 0x20 != 0)
}

/// Compare the negotiated RSN parameters carried in association and EAPOL M2.
/// PMKID lists are deliberately excluded: a PMKSA association includes the
/// selected PMKID while M2 normally omits it.
pub fn rsn_negotiation_matches(association: &[u8], message_2: &[u8]) -> bool {
    let (Some(a), Some(m2)) = (parse_rsn(association), parse_rsn(message_2)) else {
        return false;
    };
    a.group == m2.group
        && a.pairwise == m2.pairwise
        && a.akms == m2.akms
        && a.capabilities == m2.capabilities
        && a.group_mgmt == m2.group_mgmt
}

/// Extract every PMKID from an RSN element body (after id/len).
pub fn parse_rsn_pmkids(rsn_body: &[u8]) -> Option<Vec<[u8; 16]>> {
    let mut off = 2 + 4; // version + group cipher
    let pw_count = u16::from_le_bytes([*rsn_body.get(off)?, *rsn_body.get(off + 1)?]) as usize;
    off = off.checked_add(2 + 4 * pw_count)?;
    let akm_count = u16::from_le_bytes([*rsn_body.get(off)?, *rsn_body.get(off + 1)?]) as usize;
    off = off.checked_add(2 + 4 * akm_count)?;
    off = off.checked_add(2)?; // RSN capabilities
    let pmkid_count = u16::from_le_bytes([*rsn_body.get(off)?, *rsn_body.get(off + 1)?]) as usize;
    off = off.checked_add(2)?;
    let end = off.checked_add(pmkid_count.checked_mul(16)?)?;
    let bytes = rsn_body.get(off..end)?;
    let mut pmkids = Vec::with_capacity(pmkid_count);
    for value in bytes.chunks_exact(16) {
        let mut pmkid = [0u8; 16];
        pmkid.copy_from_slice(value);
        pmkids.push(pmkid);
    }
    Some(pmkids)
}

/// Extract the first PMKID, retained as a convenience for callers that only
/// need to inspect whether a list is present.
pub fn parse_rsn_pmkid(rsn_body: &[u8]) -> Option<[u8; 16]> {
    parse_rsn_pmkids(rsn_body)?.into_iter().next()
}

/// Whether an RSN element body selects the requested 00-0F-AC AKM suite type.
/// This is used at association to distinguish an SAE PMKSA reconnect from the
/// PSK side of a transition-mode BSS.
pub fn rsn_has_akm(rsn_body: &[u8], suite_type: u8) -> bool {
    // version (2), group cipher (4), pairwise count + suites, AKM count + suites
    let mut off = 2 + 4;
    let Some(pairwise_count) = rsn_body
        .get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
    else {
        return false;
    };
    off += 2 + 4 * pairwise_count;
    let Some(akm_count) = rsn_body
        .get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
    else {
        return false;
    };
    off += 2;
    (0..akm_count).any(|i| {
        rsn_body.get(off + 4 * i..off + 4 * (i + 1)) == Some(&[0x00, 0x0f, 0xac, suite_type][..])
    })
}

/// Whether an RSN element advertises management-frame protection capability.
/// SAE clients may join a transition BSS whose beacon is MFPC but not MFPR;
/// the SAE association itself still requests mandatory PMF.
pub fn rsn_has_mfpc(rsn_body: &[u8]) -> bool {
    parse_rsn(rsn_body)
        .and_then(|info| info.capabilities)
        .is_some_and(|caps| caps & 0x0080 != 0)
}

/// EAPOL message 2 (STA -> AP): carries the SNONCE and the supplicant RSN, MIC'd
/// with the freshly derived KCK.
#[allow(clippy::too_many_arguments)]
pub fn oci_kde(op_class: u8, channel: u8) -> Vec<u8> {
    vec![0xDD, 4 + 3, 0x00, 0x0f, 0xac, 0x0d, op_class, channel, 0x00]
}

/// Extract `(op_class, channel)` from an OCI KDE in EAPOL key data, if present.
pub fn parse_oci_kde(key_data: &[u8]) -> Option<(u8, u8)> {
    let mut i = 0;
    while i + 2 <= key_data.len() {
        let id = key_data[i];
        let len = key_data[i + 1] as usize;
        if i + 2 + len > key_data.len() {
            break;
        }
        let body = &key_data[i + 2..i + 2 + len];
        if id == 0xDD && len >= 4 + 3 && body[..3] == [0x00, 0x0f, 0xac] && body[3] == 0x0d {
            return Some((body[4], body[5]));
        }
        i += 2 + len;
    }
    None
}

/// The operating class for a channel (81 for 2.4 GHz, 115 for 5 GHz) — used for
/// the OCI.
pub fn operating_class(channel: u8, width: u16, band6: bool) -> u8 {
    if band6 {
        // 6 GHz global classes: 131=20, 132=40, 133=80, 134=160, 137=320 MHz.
        match width {
            320 => 137,
            160 => 134,
            80 => 133,
            40 => 132,
            _ => 131,
        }
    } else if is_5ghz(channel) {
        // OCV validators check the class's bandwidth against the
        // operating width, so 115 (20 MHz) at 80 MHz fails the 4-way.
        match width {
            160 => 129,
            80 => 128,
            40 => {
                let lower = (channel as i32 - 36).rem_euclid(8) == 0;
                match (channel, lower) {
                    (36..=48, true) => 116,
                    (36..=48, false) => 117,
                    (52..=64, true) => 119,
                    (52..=64, false) => 120,
                    (100..=144, true) => 122,
                    (100..=144, false) => 123,
                    (_, true) => 126,
                    (_, false) => 127,
                }
            }
            _ => match channel {
                36..=48 => 115,
                52..=64 => 118,
                100..=144 => 121,
                _ => 124,
            },
        }
    } else {
        match width {
            40 => 83,
            _ => 81,
        } // 2.4 GHz: 81=20, 83/84=40 MHz
    }
}

/// Whether a received OCI's operating class belongs to the band we operate on —
/// the peer's class may legitimately differ in *width* from ours (e.g. a 20 MHz
/// STA on an 80 MHz BSS), so validation pins the primary channel + band rather
/// than demanding an identical class.
pub fn oci_class_matches_band(op_class: u8, channel: u8, band6: bool) -> bool {
    if band6 {
        (131..=137).contains(&op_class)
    } else if is_5ghz(channel) {
        (115..=130).contains(&op_class)
    } else {
        matches!(op_class, 81..=84)
    }
}
