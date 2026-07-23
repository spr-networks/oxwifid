//! Information elements shared across Wi-Fi generations.

use crate::frames::*;
use crate::structures::common::IeParseError;

pub(crate) const RATES_2GHZ: [u8; 8] = [0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24];
pub(crate) const EXT_RATES_2GHZ: [u8; 4] = [0x30, 0x48, 0x60, 0x6c];
//   5 GHz (802.11a): 6*, 9, 12*, 18, 24*, 36, 48, 54 (OFDM only, no CCK)
pub(crate) const RATES_5GHZ: [u8; 8] = [0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c];
/// Country Information element (ID 7): the 2-letter `country` code + the
/// all-environments indicator, then a band-appropriate (first-channel,
/// num-channels, max-tx-power dBm) triplet.
pub(crate) fn country_ie(country: &[u8; 2], channel: u8, width: u16, band6: bool) -> Vec<u8> {
    // The triplet must cover the channels the BSS actually operates on (a
    // strict 802.11d client treats uncovered channels as unusable): on 5/6 GHz
    // span the full operating width from the block's lowest 20 MHz channel
    // (channels step by 4 per 20 MHz); 2.4 GHz keeps the fixed 1-11 span.
    let triplet: [u8; 3] = if band6 || is_5ghz(channel) {
        let n = (width / 20).max(1) as u8;
        let first = if width > 20 {
            center_channel(channel, width, band6) - 2 * (n - 1)
        } else {
            channel
        };
        [first, n, 23]
    } else {
        [1, 11, 30]
    };
    let mut data = vec![country[0], country[1], 0x20];
    data.extend_from_slice(&triplet);
    ie(7, &data)
}

/// Legacy 2.4 GHz capability info used by the frame-vector client helpers.
/// Little-endian `0x0131` is ESS + Privacy + Short Preamble + Spectrum Mgmt.
pub const CAP_3101: [u8; 2] = [0x31, 0x01];

/// Capability Information for AP-originated management frames.
///
/// Short Preamble is a 2.4 GHz-only capability. Advertising the old `0x0131`
/// value on 5/6 GHz also claimed Spectrum Management without the matching
/// 802.11h elements; strict clients (notably macOS) discard that BSS. Match
/// reference AP's baseline ESS + Privacy value on the OFDM-only bands.
pub(crate) fn ap_capability(channel: u8, band6: bool) -> [u8; 2] {
    if band6 || is_5ghz(channel) {
        0x0011u16.to_le_bytes()
    } else {
        CAP_3101
    }
}

/// Beacon interval advertised by beacons/probe responses, in TUs (100 TU ≈ 102 ms).
pub const BEACON_INTERVAL_TU: u16 = 0x0064;

/// Listen interval a station advertises in its (re)association requests, in
/// beacon intervals.
pub const STA_LISTEN_INTERVAL: u16 = 0x00c8;

/// RSN information element (WPA2-PSK / CCMP-128), == `eRSN.build()`.
pub fn ie(id: u8, info: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + info.len());
    v.push(id);
    v.push(info.len() as u8);
    v.extend_from_slice(info);
    v
}

/// 802.11n HT Capabilities element (ID 45): 1 spatial stream, MCS 0-15.
fn wmm_parameter() -> Vec<u8> {
    ie(
        221,
        &[
            0x00, 0x50, 0xf2, 0x02, 0x01,
            0x01, // OUI 00:50:f2, type 2 (WMM), subtype 1, version 1
            0x00, 0x00, // QoS Info, reserved
            0x03, 0xa4, 0x00, 0x00, // AC_BE
            0x27, 0xa4, 0x00, 0x00, // AC_BK
            0x42, 0x43, 0x5e, 0x00, // AC_VI
            0x62, 0x32, 0x2f, 0x00, // AC_VO
        ],
    )
}

/// WMM/WME Information element (subtype 0) for a station's (Re)Assoc Request,
/// advertising that it is WMM-capable so the AP enables QoS for it.
pub fn wmm_information() -> Vec<u8> {
    // OUI 00:50:f2, type 2 (WMM), subtype 0 (Information), version 1, QoS Info 0.
    ie(221, &[0x00, 0x50, 0xf2, 0x02, 0x00, 0x01, 0x00])
}

/// Map an Ethernet frame to its 802.11e/WMM user priority (TID 0-7) from the IP
/// DSCP / IPv6 Traffic Class precedence — the kernel's `cfg80211_classify8021d`
/// default, `UP = ToS >> 5`. The MAC's EDCA then selects the access category
/// (UP 1,2→BK, 0,3→BE, 4,5→VI, 6,7→VO). Non-IP frames (ARP, etc.) are best-effort
/// (TID 0).
pub fn wmm_tid(eth: &[u8]) -> u8 {
    if eth.len() < 16 {
        return 0;
    }
    match u16::from_be_bytes([eth[12], eth[13]]) {
        0x0800 => eth[15] >> 5,                                    // IPv4 ToS byte
        0x86DD => (((eth[14] & 0x0f) << 4) | (eth[15] >> 4)) >> 5, // IPv6 Traffic Class
        _ => 0,
    }
}

/// Whether an IE block carries a WMM/WME element (vendor OUI 00:50:F2, type 2).
/// A station that includes this in its (Re)Association Request is negotiating
/// WMM. Pass the IE portion of the frame (after the fixed fields).
pub fn has_wmm_ie(ies: &[u8]) -> bool {
    let mut i = 0;
    while i + 2 <= ies.len() {
        let len = ies[i + 1] as usize;
        if i + 2 + len > ies.len() {
            break;
        }
        if ies[i] == 221 && len >= 4 && ies[i + 2..i + 6] == [0x00, 0x50, 0xf2, 0x02] {
            return true;
        }
        i += 2 + len;
    }
    false
}

/// TIM (Traffic Indication Map) element (ID 5), beacon-only. DTIM period 1.
pub fn tim_element() -> Vec<u8> {
    ie(5, &[0x00, 0x01, 0x00, 0x00]) // DTIM count, DTIM period, bitmap control, partial bitmap
}

/// Channel Switch Announcement element (ID 37): switch mode, new channel, count.
pub fn csa_element(new_channel: u8, count: u8) -> Vec<u8> {
    ie(37, &[0x01, new_channel, count]) // mode 1 = STA should stop TX until switch
}

/// Multiple BSSID element (ID 71): advertises co-located BSSes (max indicator =
/// log2 of the maximum number of BSSIDs).
pub fn multiple_bssid_element(max_bssid_indicator: u8) -> Vec<u8> {
    ie(71, &[max_bssid_indicator])
}

/// BSS Max Idle Period element (ID 90): the period (in 1000-TU units) after
/// which the AP may disassociate an idle STA, plus idle options.
pub fn bss_max_idle_element(period_1000tu: u16) -> Vec<u8> {
    let mut info = period_1000tu.to_le_bytes().to_vec();
    info.push(0x00); // Idle Options (no protected keep-alive required)
    ie(90, &info)
}

/// 802.11ac VHT Capabilities element (ID 191), 5 GHz. MCS 0-9, 2 SS. Bits 2-3 of
/// the first Capabilities-Info byte are the Supported Channel Width Set: 0 = up
/// to 80 MHz, 1 = also 160 MHz. A station caps its width to this regardless of
/// the VHT Operation, so a 160 MHz BSS must advertise it here too.
pub(crate) fn ext_ie(ext_id: u8, data: &[u8]) -> Vec<u8> {
    // An extension element's body is [ext_id || data]. When that exceeds 255
    // octets it must be split with 802.11 element fragmentation (a leading
    // element of length 255 followed by Fragment elements, id 254) — e.g. a
    // Multi-Link element carrying a full per-STA profile. Small elements take
    // the fast path (a single element), byte-identical to before.
    let mut body = Vec::with_capacity(1 + data.len());
    body.push(ext_id);
    body.extend_from_slice(data);
    fragmented_element(255, &body)
}

/// Advertised TID-to-Link Mapping element (extension ID 109) with the same
/// active-link set for every TID and both traffic directions.
///
/// This is the AP-advertised form implemented by reference AP and accepted by
/// mac80211 during association: control=2 (both directions), presence=0xff
/// (all eight TIDs), followed by eight little-endian 16-bit link bitmaps.
pub fn replace_ie_payload(
    bytes: &mut Vec<u8>,
    mut start: usize,
    id: u8,
    ext_id: Option<u8>,
    body: &[u8],
) -> bool {
    while start + 2 <= bytes.len() {
        let len = bytes[start + 1] as usize;
        let end = start + 2 + len;
        if end > bytes.len() {
            return false;
        }
        let matches = bytes[start] == id
            && match ext_id {
                Some(ext) => len >= 1 && bytes[start + 2] == ext,
                None => true,
            };
        if matches {
            let extra = usize::from(ext_id.is_some());
            if body.len() + extra > u8::MAX as usize {
                return false;
            }
            let mut replacement = Vec::with_capacity(2 + extra + body.len());
            replacement.push(id);
            replacement.push((extra + body.len()) as u8);
            if let Some(ext) = ext_id {
                replacement.push(ext);
            }
            replacement.extend_from_slice(body);
            bytes.splice(start..end, replacement);
            return true;
        }
        start = end;
    }
    false
}

/// Apply the radio's band-specific HT/VHT/HE/EHT payloads to an IE block.
pub fn apply_phy_capabilities(bytes: &mut Vec<u8>, start: usize, caps: &PhyCapabilities) {
    if let Some(ht) = &caps.ht {
        replace_ie_payload(bytes, start, 45, None, ht);
    }
    if let Some(vht) = &caps.vht {
        replace_ie_payload(bytes, start, 191, None, vht);
    }
    if let Some(he) = &caps.he {
        replace_ie_payload(bytes, start, 255, Some(35), he);
    }
    if let Some(eht) = &caps.eht {
        replace_ie_payload(bytes, start, 255, Some(108), eht);
    }
}

fn supported_operating_classes_6ghz(channel: u8, width: u16) -> Vec<u8> {
    ie(59, &[operating_class(channel, width, true), 0])
}

/// Beacon/probe/assoc IE block for a 6 GHz channel. 6 GHz has no legacy
/// DSSS/HT/VHT elements: HE is mandatory, and EHT is added when `phy` selects
/// 802.11be. Channel width does not determine the PHY generation.
#[allow(clippy::too_many_arguments)]
pub fn make_beacon_ies_6ghz(
    ssid: &[u8],
    channel: u8,
    country: &[u8; 2],
    width: u16,
    wmm: bool,
    phy: PhyMode,
    rsn: &[u8],
    tim: Option<&[u8]>,
    punct: u16,
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&ie(0, ssid)); // SSID
    v.extend_from_slice(&ie(1, &RATES_5GHZ)); // Supported Rates (OFDM)
    v.extend_from_slice(&country_ie(country, channel, width, true)); // Country
    if let Some(t) = tim {
        v.extend_from_slice(t); // TIM (beacon only)
    }
    v.extend_from_slice(rsn); // RSN, before HE
    v.extend_from_slice(&he_capabilities());
    v.extend_from_slice(&he_operation_6ghz(channel, width));
    v.extend_from_slice(&mu_edca_parameter());
    v.extend_from_slice(&spatial_reuse_parameter());
    v.extend_from_slice(&he_6ghz_band_capabilities());
    // 802.11be: EHT is valid at every supported channel width. Width controls
    // the EHT MCS/NSS maps and operation geometry, not whether EHT is present.
    if phy >= PhyMode::Eht {
        v.extend_from_slice(&eht_capabilities(width));
        v.extend_from_slice(&eht_operation(channel, width, true, punct));
    }
    v.extend_from_slice(&extended_capabilities());
    v.extend_from_slice(&supported_operating_classes_6ghz(channel, width));
    v.extend_from_slice(&rrm_enabled_capabilities());
    if wmm {
        v.extend_from_slice(&wmm_parameter());
    }
    v
}

/// Extended Capabilities element (ID 127): advertises BSS Transition (bit 19).
/// Beacon Protection (bit 84) must only be set when a BIGTK is installed and
/// the AP is actually protecting beacons; the default AP does neither.
fn extended_capabilities() -> Vec<u8> {
    let mut bits = [0u8; 11];
    bits[2] |= 0x08; // bit 19: BSS Transition Management
    ie(127, &bits)
}

/// Mark an existing Extended Capabilities IE as Beacon Protection enabled.
/// The caller supplies only the IE block (not the management-frame header).
pub fn enable_beacon_protection_capability(ies: &mut [u8]) -> bool {
    let mut pos = 0;
    while pos + 2 <= ies.len() {
        let len = ies[pos + 1] as usize;
        let end = pos + 2 + len;
        if end > ies.len() {
            return false;
        }
        if ies[pos] == 127 && len >= 11 {
            ies[pos + 2 + 10] |= 0x10; // Extended Capability bit 84
            return true;
        }
        pos = end;
    }
    false
}

/// Supported Operating Classes element (ID 59): the current operating class.
fn supported_operating_classes(channel: u8, width: u16) -> Vec<u8> {
    ie(59, &[operating_class(channel, width, false), 0])
}

/// 802.11k RRM Enabled Capabilities element (ID 70): Neighbor Report capable.
fn rrm_enabled_capabilities() -> Vec<u8> {
    ie(70, &[0x02, 0x00, 0x00, 0x00, 0x00])
}

/// The IE block shared by beacons, probe & association responses, tailored to
/// the band of `channel`:
///   * 2.4 GHz: DSSS/CCK + OFDM rates, a DS Parameter Set, and an Extended
///     Supported Rates element.
///   * 5 GHz: OFDM-only rates and no DSSS Parameter Set (DSSS is 2.4 GHz only).
#[allow(clippy::too_many_arguments)]
pub fn make_beacon_ies(
    ssid: &[u8],
    channel: u8,
    country: &[u8; 2],
    width: u16,
    wmm: bool,
    phy: PhyMode,
    rsn: &[u8],
    tim: Option<&[u8]>,
    punct: u16,
) -> Vec<u8> {
    // Canonical 802.11 beacon/response element order (matches reference AP): SSID +
    // rates, then TIM (beacon only), then RSN — all BEFORE the HT/VHT/HE/EHT
    // block — with the vendor-specific WMM element LAST. A strict conformance
    // parser may stop at the first out-of-order element, so keeping this order
    // is what lets the rate/security IEs survive such a parser.
    let mut v = Vec::new();
    v.extend_from_slice(&ie(0, ssid)); // SSID
    if is_5ghz(channel) {
        v.extend_from_slice(&ie(1, &RATES_5GHZ)); // Supported Rates (OFDM)
        v.extend_from_slice(&country_ie(country, channel, width, false)); // Country
    } else {
        v.extend_from_slice(&ie(1, &RATES_2GHZ)); // Supported Rates
        v.extend_from_slice(&ie(3, &[channel])); // DS Parameter Set
        v.extend_from_slice(&country_ie(country, channel, width, false)); // Country
        v.extend_from_slice(&ie(50, &EXT_RATES_2GHZ)); // Extended Supported Rates
    }
    if let Some(t) = tim {
        v.extend_from_slice(t); // TIM (beacon only)
    }
    v.extend_from_slice(rsn); // RSN (+ RSNXE), before the HT block
                              // 802.11n HT
    v.extend_from_slice(&ht_capabilities());
    v.extend_from_slice(&ht_operation(channel, width, false));
    // 802.11ac VHT (5 GHz only)
    if is_5ghz(channel) && phy >= PhyMode::Vht {
        v.extend_from_slice(&vht_capabilities(width));
        v.extend_from_slice(&vht_operation(channel, width));
    }
    // 802.11ax HE
    if phy >= PhyMode::He {
        v.extend_from_slice(&he_capabilities());
        v.extend_from_slice(&he_operation_5ghz());
        // MU-EDCA and Spatial Reuse are optional configuration, not baseline
        // HE capabilities. Do not advertise static parameters when neither is
        // configured in nl80211; reference AP likewise omits them by default.
    }
    // 802.11be EHT
    if phy >= PhyMode::Eht {
        v.extend_from_slice(&eht_capabilities(width));
        v.extend_from_slice(&eht_operation(channel, width, false, punct));
    }
    // Extended Capabilities (BTM, Beacon Protection), Operating Classes, RRM
    v.extend_from_slice(&extended_capabilities());
    v.extend_from_slice(&supported_operating_classes(channel, width));
    v.extend_from_slice(&rrm_enabled_capabilities());
    // WMM/QoS — vendor-specific, emitted last per the canonical ordering.
    if wmm {
        v.extend_from_slice(&wmm_parameter());
    }
    v
}

pub fn find_ie(ies: &[u8], id: u8) -> Option<&[u8]> {
    let mut i = 0;
    while i + 2 <= ies.len() {
        let eid = ies[i];
        let len = ies[i + 1] as usize;
        if i + 2 + len > ies.len() {
            break;
        }
        if eid == id {
            return Some(&ies[i + 2..i + 2 + len]);
        }
        i += 2 + len;
    }
    None
}

/// Strictly find one information element. Unlike [`find_ie`], this rejects a
/// truncated IE stream and duplicate instances of the requested element.
pub fn find_ie_strict(ies: &[u8], id: u8) -> Result<Option<&[u8]>, IeParseError> {
    let mut found = None;
    let mut i = 0;
    while i < ies.len() {
        if i + 2 > ies.len() {
            return Err(IeParseError);
        }
        let len = ies[i + 1] as usize;
        let end = i.checked_add(2 + len).ok_or(IeParseError)?;
        if end > ies.len() {
            return Err(IeParseError);
        }
        if ies[i] == id {
            if found.is_some() {
                return Err(IeParseError);
            }
            found = Some(&ies[i + 2..end]);
        }
        i = end;
    }
    Ok(found)
}

/// Find an information element while tolerating byte-identical repeats.
///
/// Some Linux SME paths append the same driver-supplied RSNXE twice to an
/// association request. Identical values are unambiguous, while conflicting
/// duplicates and malformed IE streams remain errors.
pub fn find_ie_consistent(ies: &[u8], id: u8) -> Result<Option<&[u8]>, IeParseError> {
    let mut found = None;
    let mut i = 0;
    while i < ies.len() {
        if i + 2 > ies.len() {
            return Err(IeParseError);
        }
        let len = ies[i + 1] as usize;
        let end = i.checked_add(2 + len).ok_or(IeParseError)?;
        if end > ies.len() {
            return Err(IeParseError);
        }
        if ies[i] == id {
            let value = &ies[i + 2..end];
            if found.is_some_and(|previous| previous != value) {
                return Err(IeParseError);
            }
            found = Some(value);
        }
        i = end;
    }
    Ok(found)
}

/// Remove the `0xdd 00...` padding added before AES Key Wrap. A real
/// zero-length vendor IE is not useful in EAPOL Key Data, while this exact
/// suffix is the padding form required by 802.11.
pub fn trim_key_data_padding(data: &[u8]) -> &[u8] {
    let mut i = 0;
    while i + 2 <= data.len() {
        let len = data[i + 1] as usize;
        let Some(end) = i.checked_add(2 + len) else {
            return data;
        };
        if end > data.len() {
            return data;
        }
        if data[i] == 0xdd
            && len == 0
            && data
                .get(i + 2..)
                .is_some_and(|tail| tail.iter().all(|b| *b == 0))
        {
            return &data[..i];
        }
        i = end;
    }
    data
}

pub fn find_ssid(ies: &[u8]) -> Option<Vec<u8>> {
    let mut i = 0;
    while i + 2 <= ies.len() {
        let id = ies[i];
        let len = ies[i + 1] as usize;
        if i + 2 + len > ies.len() {
            break;
        }
        if id == 0 {
            return Some(ies[i + 2..i + 2 + len].to_vec());
        }
        i += 2 + len;
    }
    None
}
