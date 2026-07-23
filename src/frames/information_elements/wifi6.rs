//! Wi-Fi 6/6E (802.11ax / HE) information elements.

use crate::frames::*;

pub fn he_capabilities() -> Vec<u8> {
    ext_ie(
        35,
        &[
            // HE MAC Capabilities (6): byte0 0x05 = +HTC HE (bit0) + TWT
            // Responder Support (bit2), so the AP advertises it can grant Target
            // Wake Time agreements to power-save (HE) clients.
            0x05, 0x78, 0xc8, 0x1a, 0x40, 0x00, 0x1c, 0xbf, 0xce, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, // HE PHY Capabilities (11)
            0xfa, 0xff, 0xfa, 0xff, 0xfa, 0xff, 0xfa, 0xff, 0xfa, 0xff, 0xfa,
            0xff, // HE-MCS/NSS sets
        ],
    )
}

/// HE Operation element (ext ID 36) for 5 GHz / 2.4 GHz: neither the 6 GHz
/// Operation Information (param bit 17) nor an embedded VHT Operation (bit 14) is
/// present — the operating width comes from the separate HT/VHT Operation
/// elements, while this element makes the BSS advertise 802.11ax (HE).
pub fn he_operation_5ghz() -> Vec<u8> {
    ext_ie(
        36,
        &[
            0xf0, 0x3f, 0x00, // HE Operation Parameters (no 6 GHz / VHT info)
            // BSS Color Information: color 24 with the Disabled bit set. We do
            // not configure NL80211_ATTR_HE_BSS_COLOR, so claiming an enabled
            // color would make the beacon disagree with the radio. This is the
            // baseline reference AP advertises until color is explicitly enabled.
            0x98, 0xfc, 0xff, // Basic HE-MCS And NSS Set
        ],
    )
}

/// HE Operation element (ext ID 36) carrying the **6 GHz Operation Information**
/// (the 6 GHz band has no HT/VHT Operation elements — this replaces them). The
/// "6 GHz Operation Information Present" bit (param bit 17) is set.
pub fn he_operation_6ghz(channel: u8, width: u16) -> Vec<u8> {
    // 6 GHz Operation Information "Control" channel-width field: 0=20, 1=40,
    // 2=80, 3=160 (HE caps at 160; 320 is carried by the EHT Operation element).
    let (cw, seg0, seg1) = match width {
        40 => (1u8, center_channel(channel, 40, true), 0u8),
        80 => (2u8, center_channel(channel, 80, true), 0u8),
        160 | 320 => (
            3u8,
            center_channel(channel, 80, true),
            center_channel(channel, 160, true),
        ),
        _ => (0u8, channel, 0u8),
    };
    ext_ie(
        36,
        &[
            0xf0, 0x3f, 0x02, // HE Operation Parameters (bit 17 = 6 GHz info present)
            0x98, // BSS color 24, disabled (no nl80211 color configured)
            0xfc, 0xff, // Basic HE-MCS And NSS Set
            // 6 GHz Operation Information: primary, control, seg0, seg1, min rate.
            channel, cw, seg0, seg1, 0x06,
        ],
    )
}

/// 802.11be EHT Operation element (ext ID 106), carrying the EHT Operation
/// Information needed for 320 MHz (and 160 MHz) on 6 GHz.
pub fn eht_operation(channel: u8, width: u16, band6: bool, punct: u16) -> Vec<u8> {
    // On 2.4/5 GHz without puncturing, HT/VHT Operation already carries the
    // channel geometry. reference AP therefore emits the short EHT Operation form:
    // no EHT Operation Information field, a one-stream basic MCS/NSS
    // requirement (0x11), and the default-PE-duration parameter bit. This is
    // also the form accepted by strict Apple scan parsers. The old generic form
    // set Operation Information Present and advertised an all-zero basic set,
    // which means impossible mandatory NSS requirements rather than "none".
    if !band6 && punct == 0 {
        return ext_ie(106, &[0x40, 0x11, 0x00, 0x00, 0x00]);
    }
    // Control channel-width field: 0=20,1=40,2=80,3=160,4=320. CCFS1 is the
    // center of the operating (widest) channel — the client reads center_freq1
    // from it — and CCFS0 is the narrower (next-down) segment center.
    let (cw, ccfs0, ccfs1) = match width {
        320 => (
            4u8,
            center_channel(channel, 160, band6),
            center_channel(channel, 320, band6),
        ),
        160 => (
            3u8,
            center_channel(channel, 80, band6),
            center_channel(channel, 160, band6),
        ),
        80 => (2u8, center_channel(channel, 80, band6), 0u8),
        40 => (1u8, center_channel(channel, 40, band6), 0u8),
        _ => (0u8, channel, 0u8),
    };
    // EHT Operation Parameters: bit0 = Operation Information Present; bit1 =
    // Disabled Subchannel Bitmap Present (802.11be preamble puncturing). When
    // `punct` is non-zero we set bit1 and append the 2-octet bitmap — one bit
    // per 20 MHz subchannel of the operating width, 1 = punctured/disabled — so
    // the AP can run on a channel with a hole (e.g. an 80 MHz block with a
    // DFS/incumbent 20 MHz subchannel disabled).
    let mut body = vec![
        if punct != 0 { 0x03 } else { 0x01 }, // EHT Operation Parameters
        0x11,
        0x00,
        0x00,
        0x00, // Basic EHT-MCS And NSS Set
        cw,
        ccfs0,
        ccfs1, // EHT Operation Information: Control, CCFS0, CCFS1
    ];
    if punct != 0 {
        body.extend_from_slice(&punct.to_le_bytes()); // Disabled Subchannel Bitmap
    }
    ext_ie(106, &body)
}

/// HE 6 GHz Band Capabilities element (ext ID 59): the per-STA capabilities that
/// the HT/VHT Capabilities elements carry on the lower bands.
pub fn he_6ghz_band_capabilities() -> Vec<u8> {
    ext_ie(59, &[0x00, 0x00])
}

/// MU EDCA Parameter Set element (ext ID 38): the EDCA parameters an HE AP
/// advertises for UL MU (OFDMA/MU-MIMO) operation. Byte-golden from a reference AP
/// v2.12 HE beacon: QoS Info 0x20 (queue-request set) + one 3-octet record per
/// AC (BE/BK/VI/VO): {ACI|AIFSN, ECWmin|ECWmax, MU-EDCA Timer}.
pub fn mu_edca_parameter() -> Vec<u8> {
    ext_ie(
        38,
        &[
            0x20, 0x08, 0xa9, 0xff, 0x2f, 0xa9, 0xff, 0x45, 0x75, 0xff, 0x65, 0x75, 0xff,
        ],
    )
}

/// Spatial Reuse Parameter Set element (ext ID 39): OBSS PD-based spatial reuse
/// control an HE AP advertises. Byte-golden from a reference AP v2.12 HE beacon: a
/// single SR Control octet (0x03 = SRP/Non-SRG-OBSS-PD disallowed, no extra
/// fields present).
pub fn spatial_reuse_parameter() -> Vec<u8> {
    ext_ie(39, &[0x03])
}
