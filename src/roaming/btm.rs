//! 802.11v BSS Transition Management (BTM).

pub const ACTION_CATEGORY_WNM: u8 = 10;
pub const WNM_BTM_REQUEST: u8 = 7;
pub const WNM_BTM_RESPONSE: u8 = 8;
pub const BTM_REQ_PREF_CAND_LIST: u8 = 0x01;

/// Build an 802.11v BSS Transition Management Request action body.
pub fn btm_request_body(
    dialog_token: u8,
    request_mode: u8,
    disassociation_timer: u16,
    validity: u8,
    candidates: &[u8],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(7 + candidates.len());
    body.push(ACTION_CATEGORY_WNM);
    body.push(WNM_BTM_REQUEST);
    body.push(dialog_token);
    body.push(request_mode);
    body.extend_from_slice(&disassociation_timer.to_le_bytes());
    body.push(validity);
    body.extend_from_slice(candidates);
    body
}

/// Parse a BTM Response as `(dialog_token, status_code)`.
pub fn parse_btm_response(body: &[u8]) -> Option<(u8, u8)> {
    if body.len() >= 4 && body[0] == ACTION_CATEGORY_WNM && body[1] == WNM_BTM_RESPONSE {
        Some((body[2], body[3]))
    } else {
        None
    }
}

/// Build a CCMP-protected BSS Transition Management Request.
#[allow(clippy::too_many_arguments)]
pub fn build_protected_btm_request(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    dialog: u8,
    disassoc_imminent: bool,
    disassoc_timer: u16,
    sc: u16,
    pn: u64,
    tk: &[u8],
) -> Vec<u8> {
    build_protected_btm_request_sec(
        bssid,
        sta,
        dialog,
        disassoc_imminent,
        disassoc_timer,
        sc,
        pn,
        tk,
        None,
    )
}

/// Build a protected BTM Request with optional MLO security addresses.
#[allow(clippy::too_many_arguments)]
pub fn build_protected_btm_request_sec(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    dialog: u8,
    disassoc_imminent: bool,
    disassoc_timer: u16,
    sc: u16,
    pn: u64,
    tk: &[u8],
    security_addresses: Option<([u8; 6], [u8; 6], [u8; 6])>,
) -> Vec<u8> {
    build_protected_btm_request_for_cipher_sec(
        crate::frames::DataCipher::Ccmp128,
        bssid,
        sta,
        dialog,
        disassoc_imminent,
        disassoc_timer,
        sc,
        pn,
        tk,
        security_addresses,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn build_protected_btm_request_for_cipher_sec(
    cipher: crate::frames::DataCipher,
    bssid: &[u8; 6],
    sta: &[u8; 6],
    dialog: u8,
    disassoc_imminent: bool,
    disassoc_timer: u16,
    sc: u16,
    pn: u64,
    tk: &[u8],
    security_addresses: Option<([u8; 6], [u8; 6], [u8; 6])>,
) -> Vec<u8> {
    let mode = if disassoc_imminent { 0x04 } else { 0x00 };
    let mut body = vec![ACTION_CATEGORY_WNM, WNM_BTM_REQUEST, dialog, mode];
    body.extend_from_slice(&disassoc_timer.to_le_bytes());
    body.push(0);
    crate::frames::build_protected_mgmt_sec(
        cipher,
        crate::frames::SUBTYPE_ACTION,
        sta,
        bssid,
        bssid,
        security_addresses,
        0,
        sc,
        pn,
        0,
        tk,
        &body,
    )
}
