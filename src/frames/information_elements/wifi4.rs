//! Wi-Fi 4 (802.11n / HT) information elements.

use crate::frames::*;

pub(crate) fn ht_capabilities() -> Vec<u8> {
    let mut info = vec![0x6e, 0x00]; // HT Capabilities Info
    info.push(0x17); // A-MPDU Parameters
    info.extend_from_slice(&[0xff, 0xff]); // Supported MCS Set: MCS 0-15
    info.extend_from_slice(&[0u8; 14]); // rest of MCS set
    info.extend_from_slice(&[0x00, 0x00]); // HT Extended Capabilities
    info.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Tx Beamforming
    info.push(0x00); // ASEL
    ie(45, &info)
}

/// 802.11n HT Operation element (ID 61) for `channel`. For widths >= 40 MHz it
/// sets the Secondary Channel Offset and the STA Channel Width bit.
pub(crate) fn ht_operation(channel: u8, width: u16, band6: bool) -> Vec<u8> {
    let mut info = vec![channel];
    let mut op = [0u8; 5]; // HT Operation Info
    if width >= 40 {
        let base: i32 = if band6 { 1 } else { 36 };
        // Secondary Channel Offset: 1 = above (primary is the lower 20 MHz of
        // the 40 MHz pair), 3 = below.
        op[0] = if (channel as i32 - base).rem_euclid(8) == 0 {
            0x01
        } else {
            0x03
        };
        op[0] |= 0x04; // STA Channel Width = 1 (any width above 20 MHz)
    }
    info.extend_from_slice(&op);
    info.extend_from_slice(&[0u8; 16]); // Basic HT-MCS Set
    ie(61, &info)
}
