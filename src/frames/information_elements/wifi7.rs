//! Wi-Fi 7 (802.11be / EHT) information elements.

use crate::frames::*;

pub fn eht_capabilities(width: u16) -> Vec<u8> {
    let mut data: Vec<u8> = Vec::with_capacity(20);
    data.extend_from_slice(&[0x00, 0x00]); // EHT MAC Capabilities (2)
    let mut phy = [0u8; 9]; // EHT PHY Capabilities (9)
    if width >= 320 {
        phy[0] |= 0x02; // bit 1: Support For 320 MHz In 6 GHz
    }
    data.extend_from_slice(&phy);
    // Supported EHT-MCS And NSS Set: one 3-byte map per bandwidth (Rx/Tx max NSS
    // per MCS group; 0x22 = 2 streams). A 6 GHz AP carries the BW<=80 and 160
    // maps, plus the 320 map when 320-capable — the length is derived from the
    // PHY caps, so this must match or the whole element is discarded (client
    // then falls back to the HE 160 MHz width).
    let map = [0x22u8, 0x22, 0x22];
    data.extend_from_slice(&map); // BW <= 80 MHz
    data.extend_from_slice(&map); // BW = 160 MHz
    if width >= 320 {
        data.extend_from_slice(&map); // BW = 320 MHz
    }
    ext_ie(108, &data)
}
