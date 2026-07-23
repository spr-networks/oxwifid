//! Core management-frame constants, construction, and parsing.

use crate::frames::*;

pub const TYPE_MGMT: u8 = 0;
pub const TYPE_CTRL: u8 = 1;
pub const TYPE_DATA: u8 = 2;

pub const SUBTYPE_ASSOC_REQ: u8 = 0x00;
pub const SUBTYPE_ASSOC_RESP: u8 = 0x01;
pub const SUBTYPE_REASSOC_RESP: u8 = 0x03;
pub const SUBTYPE_REASSOC_REQ: u8 = 0x02;
pub const SUBTYPE_PROBE_REQ: u8 = 0x04;
pub const SUBTYPE_PROBE_RESP: u8 = 0x05;
pub const SUBTYPE_BEACON: u8 = 0x08;
pub const SUBTYPE_DISASSOC: u8 = 0x0A;
pub const SUBTYPE_AUTH: u8 = 0x0B;
pub const SUBTYPE_DEAUTH: u8 = 0x0C;
pub const SUBTYPE_ACTION: u8 = 0x0D;
/// Data-frame subtype: QoS Data (WMM). Carries a 2-byte QoS Control field after
/// the addresses; its TID feeds the CCMP nonce + AAD.
pub const SUBTYPE_QOS_DATA: u8 = 0x08;

/// Status code: association rejected temporarily (PMF SA Query comeback).
pub const STATUS_ASSOC_REJECTED_TEMP: u16 = 30;
/// Status code: association denied because an information element is malformed.
pub const STATUS_INVALID_IE: u16 = 40;
/// Status code: association denied because the requested AKM is unsupported.
pub const STATUS_INVALID_AKMP: u16 = 43;
/// Status code: unsupported authentication algorithm (802.11 status 13). Sent
/// when a SAE-only AP receives an open-system Authentication request.
pub const STATUS_UNSUPPORTED_AUTH_ALG: u16 = 13;
/// Status code: invalid PMKID (802.11 status 53). An SAE station using
/// Open-System authentication for PMKSA caching must receive this when the AP
/// no longer has the requested cache entry, so it falls back to a full SAE
/// exchange instead of retrying the stale PMKID indefinitely.
pub const STATUS_INVALID_PMKID: u16 = 53;
/// Status code: unspecified failure (802.11 status 1). Used to deny an
/// association that fails the WPA3-SAE / OWE anti-downgrade check (e.g. an OWE
/// request without the required Diffie-Hellman Parameter element).
pub const STATUS_UNSPECIFIED_FAILURE: u16 = 1;
/// SAE anti-clogging token required.
pub const STATUS_ANTI_CLOGGING_TOKEN_REQ: u16 = 76;
/// Requested finite cyclic group is not supported (OWE/SAE group negotiation).
pub const STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED: u16 = 77;
/// SA Query action category / actions (802.11w).
pub const FC_TODS: u8 = 0x01;
pub const FC_FROMDS: u8 = 0x02;
pub const FC_PROTECTED: u8 = 0x40;

pub const ETHERTYPE_EAPOL: u16 = 0x888E;

fn fc0(frame_type: u8, subtype: u8) -> u8 {
    (subtype << 4) | (frame_type << 2)
}

/// An information element: `[id, len, info...]`.
pub(crate) fn dot11_header(
    frame_type: u8,
    subtype: u8,
    flags: u8,
    a1: &[u8; 6],
    a2: &[u8; 6],
    a3: &[u8; 6],
    sc: u16,
) -> Vec<u8> {
    let mut v = Vec::with_capacity(24);
    v.push(fc0(frame_type, subtype));
    v.push(flags);
    v.extend_from_slice(&[0, 0]); // duration
    v.extend_from_slice(a1);
    v.extend_from_slice(a2);
    v.extend_from_slice(a3);
    v.extend_from_slice(&sc.to_le_bytes());
    v
}

pub(crate) fn llc_snap(ethertype: u16) -> [u8; 8] {
    let mut v = [0u8; 8];
    v[..3].copy_from_slice(&[0xAA, 0xAA, 0x03]); // LLC: SNAP
                                                 // OUI = 00:00:00, then 2-byte ethertype (big-endian)
    v[6..8].copy_from_slice(&ethertype.to_be_bytes());
    v
}

// ---------------------------------------------------------------------------
// Management frames
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub fn build_beacon(
    bssid: &[u8; 6],
    ssid: &[u8],
    channel: u8,
    timestamp: u64,
    tail_ies: &[u8],
    country: &[u8; 2],
    width: u16,
    wmm: bool,
    phy: PhyMode,
    punct: u16,
) -> Vec<u8> {
    let bcast = [0xffu8; 6];
    let mut v = dot11_header(TYPE_MGMT, SUBTYPE_BEACON, 0, &bcast, bssid, bssid, 0);
    v.extend_from_slice(&timestamp.to_le_bytes());
    v.extend_from_slice(&BEACON_INTERVAL_TU.to_le_bytes()); // beacon interval
    v.extend_from_slice(&ap_capability(channel, false));
    let tim = tim_element();
    v.extend_from_slice(&make_beacon_ies(
        ssid,
        channel,
        country,
        width,
        wmm,
        phy,
        tail_ies,
        Some(&tim),
        punct,
    ));
    v
}

/// Build a 6 GHz HE/EHT beacon. 6 GHz mandates WPA3, so `tail_ies` is the
/// SAE/OWE RSN(+RSNXE). The capability field omits the "Privacy" short-slot
/// bits that are 2.4/5 GHz specific.
#[allow(clippy::too_many_arguments)]
pub fn build_beacon_6ghz(
    bssid: &[u8; 6],
    ssid: &[u8],
    channel: u8,
    timestamp: u64,
    tail_ies: &[u8],
    country: &[u8; 2],
    width: u16,
    wmm: bool,
    phy: PhyMode,
    punct: u16,
) -> Vec<u8> {
    let bcast = [0xffu8; 6];
    let mut v = dot11_header(TYPE_MGMT, SUBTYPE_BEACON, 0, &bcast, bssid, bssid, 0);
    v.extend_from_slice(&timestamp.to_le_bytes());
    v.extend_from_slice(&BEACON_INTERVAL_TU.to_le_bytes());
    v.extend_from_slice(&ap_capability(channel, true));
    let tim = tim_element();
    v.extend_from_slice(&make_beacon_ies_6ghz(
        ssid,
        channel,
        country,
        width,
        wmm,
        phy,
        tail_ies,
        Some(&tim),
        punct,
    ));
    v
}

#[allow(clippy::too_many_arguments)]
pub fn build_probe_resp(
    bssid: &[u8; 6],
    dst: &[u8; 6],
    ssid: &[u8],
    channel: u8,
    timestamp: u64,
    sc: u16,
    tail_ies: &[u8],
    country: &[u8; 2],
    width: u16,
    band6: bool,
    wmm: bool,
    phy: PhyMode,
    punct: u16,
) -> Vec<u8> {
    let mut v = dot11_header(TYPE_MGMT, SUBTYPE_PROBE_RESP, 0, dst, bssid, bssid, sc);
    v.extend_from_slice(&timestamp.to_le_bytes());
    v.extend_from_slice(&BEACON_INTERVAL_TU.to_le_bytes());
    v.extend_from_slice(&ap_capability(channel, band6));
    v.extend_from_slice(&resp_ies(
        ssid, channel, country, width, band6, wmm, phy, tail_ies, punct,
    ));
    v
}

pub fn build_auth(bssid: &[u8; 6], dst: &[u8; 6], sc: u16) -> Vec<u8> {
    let mut v = dot11_header(TYPE_MGMT, SUBTYPE_AUTH, 0, dst, bssid, bssid, sc);
    // Dot11Auth: algo=0 (open), seqnum=2, status=0  (all little-endian shorts)
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&2u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v
}

/// Build an open-system Authentication *rejection* (algo 0, seqnum 2) carrying a
/// non-zero status code — e.g. status 13 (unsupported auth algorithm) when a
/// SAE-only AP refuses an open-system request.
pub fn build_auth_reject(bssid: &[u8; 6], dst: &[u8; 6], sc: u16, status: u16) -> Vec<u8> {
    let mut v = dot11_header(TYPE_MGMT, SUBTYPE_AUTH, 0, dst, bssid, bssid, sc);
    v.extend_from_slice(&AUTH_ALG_OPEN.to_le_bytes());
    v.extend_from_slice(&2u16.to_le_bytes());
    v.extend_from_slice(&status.to_le_bytes());
    v
}

#[allow(clippy::too_many_arguments)]
pub fn build_assoc_resp(
    bssid: &[u8; 6],
    dst: &[u8; 6],
    ssid: &[u8],
    channel: u8,
    aid: u16,
    sc: u16,
    resp_subtype: u8,
    country: &[u8; 2],
    width: u16,
    band6: bool,
    wmm: bool,
    phy: PhyMode,
    punct: u16,
) -> Vec<u8> {
    let mut v = dot11_header(TYPE_MGMT, resp_subtype, 0, dst, bssid, bssid, sc);
    v.extend_from_slice(&ap_capability(channel, band6));
    v.extend_from_slice(&0u16.to_le_bytes()); // status = success
    v.extend_from_slice(&aid.to_le_bytes());
    // Association responses do not carry the RSN element (no RSN tail).
    v.extend_from_slice(&resp_ies(
        ssid,
        channel,
        country,
        width,
        band6,
        wmm,
        phy,
        &[],
        punct,
    ));
    v
}

/// IE block for a probe/association response: the band-correct beacon IEs (the
/// HE-only 6 GHz set when `band6`, otherwise the 2.4/5 GHz HT/VHT set). A 6 GHz
/// channel number (e.g. 37) also exists at 5 GHz, so we must not pick by channel.
#[allow(clippy::too_many_arguments)]
pub(crate) fn resp_ies(
    ssid: &[u8],
    channel: u8,
    country: &[u8; 2],
    width: u16,
    band6: bool,
    wmm: bool,
    phy: PhyMode,
    rsn: &[u8],
    punct: u16,
) -> Vec<u8> {
    // No TIM in probe/assoc responses; RSN lands canonically (before the HT/HE
    // block), not appended after the vendor-specific WMM element.
    if band6 {
        make_beacon_ies_6ghz(ssid, channel, country, width, wmm, phy, rsn, None, punct)
    } else {
        make_beacon_ies(ssid, channel, country, width, wmm, phy, rsn, None, punct)
    }
}

pub fn build_deauth(bssid: &[u8; 6], dst: &[u8; 6], reason: u16) -> Vec<u8> {
    // Unprotected Deauthentication (subtype 12). `dst` may be a unicast STA or
    // the broadcast address.
    let mut v = dot11_header(TYPE_MGMT, SUBTYPE_DEAUTH, 0, dst, bssid, bssid, 0);
    v.extend_from_slice(&reason.to_le_bytes());
    v
}

pub fn build_assoc_resp_comeback(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    comeback_ms: u32,
    sc: u16,
) -> Vec<u8> {
    let mut v = dot11_header(TYPE_MGMT, SUBTYPE_ASSOC_RESP, 0, sta, bssid, bssid, sc);
    v.extend_from_slice(&CAP_3101);
    v.extend_from_slice(&STATUS_ASSOC_REJECTED_TEMP.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes()); // AID 0
                                              // Timeout Interval element: id 56, len 5, type 3 (Association Comeback Time), value (TUs)
    v.push(56);
    v.push(5);
    v.push(3);
    v.extend_from_slice(&comeback_ms.to_le_bytes());
    v
}

/// An Association Response carrying a non-success status code and no AID — a
/// plain rejection (e.g. status 1, unspecified failure, for the SAE/OWE
/// anti-downgrade denial).
pub fn build_assoc_resp_reject(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    status: u16,
    resp_subtype: u8,
    sc: u16,
) -> Vec<u8> {
    let mut v = dot11_header(TYPE_MGMT, resp_subtype, 0, sta, bssid, bssid, sc);
    v.extend_from_slice(&CAP_3101);
    v.extend_from_slice(&status.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes()); // AID 0
    v
}

/// Parse a management frame body as `(reason)` for Deauth/Disassoc, or an SA
/// Query `(category, action, trans_id)` for Action frames.
pub fn parse_deauth_reason(body: &[u8]) -> Option<u16> {
    if body.len() >= 2 {
        Some(u16::from_le_bytes([body[0], body[1]]))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Parsing
