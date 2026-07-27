//! Channel, operating-class, and radiotap support.

/// The 8-byte radiotap header scapy emits for a bare `RadioTap()` (no fields).
/// Used for the stdio framing path; raw-socket injection uses a band-aware
/// header built by [`build_radiotap_tx`].
pub const RADIOTAP_TX: [u8; 8] = [0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];

// radiotap "present" bits
const RT_PRESENT_RATE: u32 = 1 << 2;
const RT_PRESENT_CHANNEL: u32 = 1 << 3;
// radiotap channel flags
const CHAN_CCK: u16 = 0x0020;
const CHAN_OFDM: u16 = 0x0040;
const CHAN_2GHZ: u16 = 0x0080;
const CHAN_5GHZ: u16 = 0x0100;

/// `true` for 5 GHz channels (channel numbers above 14).
pub fn is_5ghz(channel: u8) -> bool {
    channel > 14
}

/// Centre frequency (MHz) for a channel number, across the 2.4 and 5 GHz bands.
pub fn channel_to_freq(channel: u8) -> u16 {
    match channel {
        14 => 2484,
        c if c <= 13 => 2407 + 5 * c as u16,
        c => 5000 + 5 * c as u16,
    }
}

/// The Channel Center Frequency Segment-0 channel for the wide (40/80/160/320
/// MHz) block containing the primary `channel`. The 5 GHz UNII-1/2 blocks are
/// anchored at 36/100, while UNII-3 is anchored at 149; treating all of 5 GHz
/// as one channel-number grid produces invalid centers such as 154 instead of
/// 155 for an 80 MHz channel 149 AP. The 6 GHz grid is anchored at channel 1.
/// For 20 MHz this is the primary channel itself.
pub fn center_channel(channel: u8, width_mhz: u16, band6: bool) -> u8 {
    let p = channel as i32;
    let base: i32 = if band6 {
        1
    } else if channel >= 149 {
        149
    } else if channel >= 100 {
        100
    } else {
        36
    };
    let c = match width_mhz {
        // HT40+: primary is the lower 20 MHz of the pair; HT40-: the upper.
        40 => {
            if (p - base).rem_euclid(8) == 0 {
                p + 2
            } else {
                p - 2
            }
        }
        80 => base + (p - base).div_euclid(16) * 16 + 6,
        160 => base + (p - base).div_euclid(32) * 32 + 14,
        320 => base + (p - base).div_euclid(64) * 64 + 30,
        _ => p,
    };
    c as u8
}

/// Frequency (MHz) of a 5 GHz / 6 GHz center channel.
pub fn channel_to_center_freq(center_chan: u8, band6: bool) -> u32 {
    if band6 {
        5950 + 5 * center_chan as u32
    } else {
        5000 + 5 * center_chan as u32
    }
}

/// Build a radiotap header for monitor-mode TX that pins the frame to the right
/// band: it carries a Rate field and a Channel field (frequency + 2 GHz/CCK or
/// 5 GHz/OFDM flags) so the driver injects on the correct band/encoding.
pub fn build_radiotap_tx(channel: u8) -> Vec<u8> {
    // lowest basic rate for the band, in 500 kbps units: 2.4 GHz -> 1 Mbps CCK,
    // 5 GHz -> 6 Mbps OFDM.
    let (chan_flags, rate_500k) = if is_5ghz(channel) {
        (CHAN_5GHZ | CHAN_OFDM, 12u8)
    } else {
        (CHAN_2GHZ | CHAN_CCK, 2u8)
    };
    radiotap_tx(channel_to_freq(channel), chan_flags, rate_500k)
}

/// Radiotap TX header for a 6 GHz channel (OFDM, 6 Mbps basic rate).
pub fn build_radiotap_tx_6ghz(channel: u8) -> Vec<u8> {
    radiotap_tx(channel_to_freq_6ghz(channel), CHAN_OFDM, 12)
}

fn radiotap_tx(freq: u16, chan_flags: u16, rate_500k: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(14);
    v.push(0); // version
    v.push(0); // pad
    v.extend_from_slice(&[0, 0]); // it_len placeholder
    v.extend_from_slice(&(RT_PRESENT_RATE | RT_PRESENT_CHANNEL).to_le_bytes());
    v.push(rate_500k); // Rate (offset 8, 1-byte aligned)
    v.push(0); // pad so the Channel field is 2-byte aligned (offset 10)
    v.extend_from_slice(&freq.to_le_bytes()); // Channel: frequency
    v.extend_from_slice(&chan_flags.to_le_bytes()); // Channel: flags
    let len = v.len() as u16;
    v[2..4].copy_from_slice(&len.to_le_bytes());
    v
}

// Band-appropriate supported-rate sets. Rate octets are in 500 kbps units; the
// high bit (0x80) marks a Basic (mandatory) rate.
//   2.4 GHz (802.11b/g): 1*, 2*, 5.5*, 11*, 6, 9, 12, 18 + ext 24, 36, 48, 54
/// Centre frequency (MHz) for a 6 GHz channel number (operating class 131+):
/// the 6 GHz band starts at 5950 MHz with 5 MHz channel spacing.
pub fn channel_to_freq_6ghz(channel: u8) -> u16 {
    5950 + 5 * channel as u16
}

/// Strip a radiotap header, returning the 802.11 frame slice. Reads `it_len`
/// (bytes 2..4, little-endian) and skips that many bytes.
pub fn strip_radiotap(buf: &[u8]) -> Option<&[u8]> {
    if buf.len() < 4 {
        return None;
    }
    let it_len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
    if buf.len() < it_len {
        return None;
    }
    Some(&buf[it_len..])
}

/// Whether the radiotap header reports a bad FCS (RX Flags BAD_FCS bit), the
/// check `recv_pkt` performs before processing a frame.
///
/// This properly parses the radiotap `present` bitmap and the (bit 1) Flags
/// field, so it never confuses 802.11 frame bytes for radiotap content the way
/// a naive fixed-offset read would. A minimal radiotap header (no Flags field)
/// is reported as good.
pub fn radiotap_bad_fcs(buf: &[u8]) -> bool {
    if buf.len() < 8 || buf[0] != 0 {
        return false;
    }
    let it_len = u16::from_le_bytes([buf[2], buf[3]]) as usize;

    // Walk the (possibly extended) present bitmap words.
    let mut off = 4;
    let mut first_present = 0u32;
    let mut idx = 0;
    loop {
        if off + 4 > buf.len() {
            return false;
        }
        let w = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
        if idx == 0 {
            first_present = w;
        }
        off += 4;
        idx += 1;
        if w & 0x8000_0000 == 0 {
            break;
        }
        if idx > 8 {
            return false;
        }
    }

    // Flags is present bit 1.
    if first_present & (1 << 1) == 0 {
        return false;
    }
    // TSFT (bit 0, 8 bytes, 8-byte aligned) precedes Flags if present.
    let mut p = off;
    if first_present & (1 << 0) != 0 {
        let rem = p % 8;
        if rem != 0 {
            p += 8 - rem;
        }
        p += 8;
    }
    if p >= it_len || p >= buf.len() {
        return false;
    }
    buf[p] & 0x40 != 0
}
