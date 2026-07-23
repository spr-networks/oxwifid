//! Wi-Fi 5 (802.11ac / VHT) information elements.

use crate::frames::*;

pub(crate) fn vht_capabilities(width: u16) -> Vec<u8> {
    let b0 = if width >= 160 { 0xb6 } else { 0xb2 };
    let mut info = vec![b0, 0x01, 0x80, 0x33]; // VHT Capabilities Info
                                               // Supported VHT-MCS and NSS Set (rx map, rx highest, tx map, tx highest)
    info.extend_from_slice(&[0xea, 0xff, 0x00, 0x00, 0xea, 0xff, 0x00, 0x00]);
    ie(191, &info)
}

/// 802.11ac VHT Operation element (ID 192). Encodes the 80/160 MHz width via the
/// Channel Width field and the Center Frequency Segment channels.
pub(crate) fn vht_operation(channel: u8, width: u16) -> Vec<u8> {
    // Channel Width: 0 = 20/40 MHz, 1 = 80/160/80+80 (segments disambiguate).
    let (cw, seg0, seg1) = match width {
        80 => (1u8, center_channel(channel, 80, false), 0u8),
        // 160 MHz, new encoding: width=1, seg0 = the 80 MHz center, seg1 = 160.
        160 => (
            1u8,
            center_channel(channel, 80, false),
            center_channel(channel, 160, false),
        ),
        _ => (0u8, 0u8, 0u8),
    };
    // Basic VHT-MCS and NSS Set 0xfffc: NSS1 requires MCS 0-7, NSS2-8 exempt
    // (reference AP's default, same as the HE Operation basic set). NOT 0x0000 — in
    // this 2-bits-per-NSS field 0 means "required" and 3 "not required", so
    // all-zeroes would demand 8 mandatory spatial streams from every client.
    ie(192, &[cw, seg0, seg1, 0xfc, 0xff])
}

// ---------------------------------------------------------------------------
// 802.11ax (HE) / 6 GHz
// ---------------------------------------------------------------------------
