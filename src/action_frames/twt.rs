//! Wi-Fi 6 Target Wake Time (TWT) action frames.

use super::build_action_frame;

/// S1G Action category used by individual TWT.
pub const ACTION_CATEGORY_S1G: u8 = 23;
pub const S1G_ACT_TWT_SETUP: u8 = 6;
pub const S1G_ACT_TWT_TEARDOWN: u8 = 7;
pub const EID_TWT: u8 = 216;
pub const TWT_SETUP_CMD_ACCEPT: u16 = 4;

/// Parse a TWT Setup request and return its dialog token and TWT element.
pub fn parse_twt_setup(body: &[u8]) -> Option<(u8, Vec<u8>)> {
    if body.len() < 4 || body[0] != ACTION_CATEGORY_S1G || body[1] != S1G_ACT_TWT_SETUP {
        return None;
    }
    let dialog = body[2];
    let twt = &body[3..];
    if twt.len() < 2 || twt[0] != EID_TWT {
        return None;
    }
    let element_len = twt[1] as usize;
    if twt.len() < 2 + element_len || element_len < 15 {
        return None;
    }
    let request_type = u16::from_le_bytes([twt[3], twt[4]]);
    if request_type & 0x0001 == 0 {
        return None;
    }
    Some((dialog, twt[..2 + element_len].to_vec()))
}

/// Build a TWT Setup response accepting the requested TWT parameters.
pub fn build_twt_setup_response(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    dialog: u8,
    requested_twt: &[u8],
    sc: u16,
) -> Vec<u8> {
    let mut twt = requested_twt.to_vec();
    if twt.len() >= 5 {
        let mut request_type = u16::from_le_bytes([twt[3], twt[4]]);
        request_type &= !0x000F;
        request_type |= TWT_SETUP_CMD_ACCEPT << 1;
        let encoded = request_type.to_le_bytes();
        twt[3] = encoded[0];
        twt[4] = encoded[1];
    }
    let mut body = vec![ACTION_CATEGORY_S1G, S1G_ACT_TWT_SETUP, dialog];
    body.extend_from_slice(&twt);
    build_action_frame(sta, bssid, bssid, sc, &body)
}
