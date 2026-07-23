//! Protected SA Query action frames.

pub const ACTION_CATEGORY_SA_QUERY: u8 = 8;
pub const SA_QUERY_REQUEST: u8 = 0;
pub const SA_QUERY_RESPONSE: u8 = 1;

/// Build a CCMP-protected SA Query request or response.
#[allow(clippy::too_many_arguments)]
pub fn build_protected_sa_query(
    bssid: &[u8; 6],
    peer: &[u8; 6],
    to_ds: bool,
    response: bool,
    transaction_id: u16,
    sc: u16,
    pn: u64,
    tk: &[u8],
) -> Vec<u8> {
    build_protected_sa_query_sec(
        bssid,
        peer,
        to_ds,
        response,
        transaction_id,
        sc,
        pn,
        tk,
        None,
    )
}

/// Build a protected SA Query with optional MLO security addresses.
#[allow(clippy::too_many_arguments)]
pub fn build_protected_sa_query_sec(
    bssid: &[u8; 6],
    peer: &[u8; 6],
    to_ds: bool,
    response: bool,
    transaction_id: u16,
    sc: u16,
    pn: u64,
    tk: &[u8],
    security_addresses: Option<([u8; 6], [u8; 6], [u8; 6])>,
) -> Vec<u8> {
    build_protected_sa_query_for_cipher_sec(
        crate::frames::DataCipher::Ccmp128,
        bssid,
        peer,
        to_ds,
        response,
        transaction_id,
        sc,
        pn,
        tk,
        security_addresses,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn build_protected_sa_query_for_cipher_sec(
    cipher: crate::frames::DataCipher,
    bssid: &[u8; 6],
    peer: &[u8; 6],
    to_ds: bool,
    response: bool,
    transaction_id: u16,
    sc: u16,
    pn: u64,
    tk: &[u8],
    security_addresses: Option<([u8; 6], [u8; 6], [u8; 6])>,
) -> Vec<u8> {
    let action = if response {
        SA_QUERY_RESPONSE
    } else {
        SA_QUERY_REQUEST
    };
    let mut body = vec![ACTION_CATEGORY_SA_QUERY, action];
    body.extend_from_slice(&transaction_id.to_le_bytes());
    let (a1, a2, a3) = if to_ds {
        (*bssid, *peer, *bssid)
    } else {
        (*peer, *bssid, *bssid)
    };
    crate::frames::build_protected_mgmt_sec(
        cipher,
        crate::frames::SUBTYPE_ACTION,
        &a1,
        &a2,
        &a3,
        security_addresses,
        if to_ds { crate::frames::FC_TODS } else { 0 },
        sc,
        pn,
        0,
        tk,
        &body,
    )
}

/// Parse an SA Query body as `(action, transaction_id)`.
pub fn parse_sa_query(body: &[u8]) -> Option<(u8, u16)> {
    if body.len() >= 4 && body[0] == ACTION_CATEGORY_SA_QUERY {
        Some((body[1], u16::from_le_bytes([body[2], body[3]])))
    } else {
        None
    }
}
