//! IEEE 802.11 frame building & parsing, reproducing the scapy layouts used by
//! the reference `ap.py` byte-for-byte.
//!
//! Frame Control octet 0 = `(subtype << 4) | (type << 2) | proto`.
//! Octet 1 flags: to-DS=0x01, from-DS=0x02, more-frag=0x04, retry=0x08,
//! pwr=0x10, more-data=0x20, protected=0x40, order=0x80.

use crate::crypto;

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
const RATES_2GHZ: [u8; 8] = [0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24];
const EXT_RATES_2GHZ: [u8; 4] = [0x30, 0x48, 0x60, 0x6c];
//   5 GHz (802.11a): 6*, 9, 12*, 18, 24*, 36, 48, 54 (OFDM only, no CCK)
const RATES_5GHZ: [u8; 8] = [0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c];
/// Country Information element (ID 7): the 2-letter `country` code + the
/// all-environments indicator, then a band-appropriate (first-channel,
/// num-channels, max-tx-power dBm) triplet.
fn country_ie(country: &[u8; 2], channel: u8) -> Vec<u8> {
    let triplet: [u8; 3] = if is_5ghz(channel) { [36, 4, 23] } else { [1, 11, 30] };
    let mut data = vec![country[0], country[1], 0x20];
    data.extend_from_slice(&triplet);
    ie(7, &data)
}

/// Capability info as it appears on the wire for `cap=0x3101` (ESS + Privacy +
/// short-slot/short-preamble), used by every management body in `ap.py`.
pub const CAP_3101: [u8; 2] = [0x31, 0x01];

/// Beacon interval advertised by beacons/probe responses, in TUs (100 TU ≈ 102 ms).
pub const BEACON_INTERVAL_TU: u16 = 0x0064;

/// Listen interval a station advertises in its (re)association requests, in
/// beacon intervals.
pub const STA_LISTEN_INTERVAL: u16 = 0x00c8;

/// RSN information element (WPA2-PSK / CCMP-128), == `eRSN.build()`.
pub const RSN: [u8; 22] = [
    0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
    0x00, 0x0f, 0xac, 0x02, 0x00, 0x00,
];

/// RSN information element for WPA3-SAE: CCMP-128 pairwise/group, AKM = SAE
/// (00-0F-AC:8), RSN capabilities with MFPR|MFPC set, and a Group Management
/// Cipher Suite of BIP-CMAC-128 (00-0F-AC:6) for PMF.
pub const RSN_WPA3: [u8; 28] = [
    0x30, 0x1a, // id 48, len 26
    0x01, 0x00, // version
    0x00, 0x0f, 0xac, 0x04, // group data cipher: CCMP-128
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, // 1 pairwise: CCMP-128
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x08, // 1 AKM: SAE
    0xc0, 0x00, // RSN caps: MFPR (0x40) | MFPC (0x80)
    0x00, 0x00, // PMKID count = 0
    0x00, 0x0f, 0xac, 0x06, // group mgmt cipher: BIP-CMAC-128
];

/// RSN Extended Capabilities element advertising SAE Hash-to-Element support
/// (Extended RSN Capabilities bit 5).
pub const RSNXE_H2E: [u8; 3] = [0xf4, 0x01, 0x20];

/// WPA2/WPA3 transition-mode RSN element: CCMP, **both** SAE (00-0F-AC:8) and
/// PSK (00-0F-AC:2) AKMs, MFPC set but not required (so WPA2 clients can still
/// join), and a BIP group-management cipher.
pub const RSN_TRANSITION: [u8; 32] = [
    0x30, 0x1e, // id 48, len 30
    0x01, 0x00, // version
    0x00, 0x0f, 0xac, 0x04, // group data cipher: CCMP
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, // 1 pairwise: CCMP
    0x02, 0x00, 0x00, 0x0f, 0xac, 0x08, 0x00, 0x0f, 0xac, 0x02, // 2 AKMs: SAE, PSK
    0x80, 0x00, // RSN caps: MFPC (capable, not required)
    0x00, 0x00, // PMKID count
    0x00, 0x0f, 0xac, 0x06, // group mgmt cipher: BIP
];

pub const TYPE_MGMT: u8 = 0;
pub const TYPE_CTRL: u8 = 1;
pub const TYPE_DATA: u8 = 2;

pub const SUBTYPE_ASSOC_REQ: u8 = 0x00;
pub const SUBTYPE_ASSOC_RESP: u8 = 0x01;
pub const SUBTYPE_REASSOC_REQ: u8 = 0x02;
pub const SUBTYPE_PROBE_REQ: u8 = 0x04;
pub const SUBTYPE_PROBE_RESP: u8 = 0x05;
pub const SUBTYPE_BEACON: u8 = 0x08;
pub const SUBTYPE_DISASSOC: u8 = 0x0A;
pub const SUBTYPE_AUTH: u8 = 0x0B;
pub const SUBTYPE_DEAUTH: u8 = 0x0C;
pub const SUBTYPE_ACTION: u8 = 0x0D;

/// Status code: association rejected temporarily (PMF SA Query comeback).
pub const STATUS_ASSOC_REJECTED_TEMP: u16 = 30;
/// SA Query action category / actions (802.11w).
pub const ACTION_CATEGORY_SA_QUERY: u8 = 8;
pub const SA_QUERY_REQUEST: u8 = 0;
pub const SA_QUERY_RESPONSE: u8 = 1;

pub const FC_TODS: u8 = 0x01;
pub const FC_FROMDS: u8 = 0x02;
pub const FC_PROTECTED: u8 = 0x40;

const ETHERTYPE_EAPOL: u16 = 0x888E;

fn fc0(frame_type: u8, subtype: u8) -> u8 {
    (subtype << 4) | (frame_type << 2)
}

/// An information element: `[id, len, info...]`.
pub fn ie(id: u8, info: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + info.len());
    v.push(id);
    v.push(info.len() as u8);
    v.extend_from_slice(info);
    v
}

/// 802.11n HT Capabilities element (ID 45): 1 spatial stream, MCS 0-15.
fn ht_capabilities() -> Vec<u8> {
    let mut info = vec![0x6e, 0x00]; // HT Capabilities Info
    info.push(0x17); // A-MPDU Parameters
    info.extend_from_slice(&[0xff, 0xff]); // Supported MCS Set: MCS 0-15
    info.extend_from_slice(&[0u8; 14]); // rest of MCS set
    info.extend_from_slice(&[0x00, 0x00]); // HT Extended Capabilities
    info.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Tx Beamforming
    info.push(0x00); // ASEL
    ie(45, &info)
}

/// 802.11n HT Operation element (ID 61) for `channel` (20 MHz, no secondary).
fn ht_operation(channel: u8) -> Vec<u8> {
    let mut info = vec![channel];
    info.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00]); // HT Operation Info
    info.extend_from_slice(&[0u8; 16]); // Basic HT-MCS Set
    ie(61, &info)
}

/// WMM/WME Parameter element (vendor-specific, Microsoft OUI) with the default
/// EDCA parameters — advertises QoS support.
fn wmm_parameter() -> Vec<u8> {
    ie(
        221,
        &[
            0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, // OUI 00:50:f2, type 2 (WMM), subtype 1, version 1
            0x00, 0x00, // QoS Info, reserved
            0x03, 0xa4, 0x00, 0x00, // AC_BE
            0x27, 0xa4, 0x00, 0x00, // AC_BK
            0x42, 0x43, 0x5e, 0x00, // AC_VI
            0x62, 0x32, 0x2f, 0x00, // AC_VO
        ],
    )
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

/// 802.11ac VHT Capabilities element (ID 191), 5 GHz. 1 SS, MCS 0-9.
fn vht_capabilities() -> Vec<u8> {
    let mut info = vec![0xb2, 0x01, 0x80, 0x33]; // VHT Capabilities Info
    // Supported VHT-MCS and NSS Set (rx map, rx highest, tx map, tx highest)
    info.extend_from_slice(&[0xea, 0xff, 0x00, 0x00, 0xea, 0xff, 0x00, 0x00]);
    ie(191, &info)
}

/// 802.11ac VHT Operation element (ID 192): 20/40 MHz, no center segment.
fn vht_operation() -> Vec<u8> {
    ie(192, &[0x00, 0x00, 0x00, 0x00, 0x00])
}

// ---------------------------------------------------------------------------
// 802.11ax (HE) / 6 GHz
// ---------------------------------------------------------------------------

/// Centre frequency (MHz) for a 6 GHz channel number (operating class 131+):
/// the 6 GHz band starts at 5950 MHz with 5 MHz channel spacing.
pub fn channel_to_freq_6ghz(channel: u8) -> u16 {
    5950 + 5 * channel as u16
}

/// An "Element ID Extension" element (ID 255): `255, len, ext_id, data...`.
fn ext_ie(ext_id: u8, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(3 + data.len());
    v.push(255);
    v.push((1 + data.len()) as u8);
    v.push(ext_id);
    v.extend_from_slice(data);
    v
}

/// HE Capabilities element (ext ID 35): 6 MAC + 11 PHY capability octets and the
/// supported HE-MCS/NSS set. Byte-golden from a `mac80211_hwsim` HE AP beacon.
pub fn he_capabilities() -> Vec<u8> {
    ext_ie(
        35,
        &[
            0x01, 0x78, 0xc8, 0x1a, 0x40, 0x00, // HE MAC Capabilities (6)
            0x1c, 0xbf, 0xce, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // HE PHY Capabilities (11)
            0xfa, 0xff, 0xfa, 0xff, 0xfa, 0xff, 0xfa, 0xff, 0xfa, 0xff, 0xfa, 0xff, // HE-MCS/NSS sets
        ],
    )
}

/// HE Operation element (ext ID 36) carrying the **6 GHz Operation Information**
/// (the 6 GHz band has no HT/VHT Operation elements — this replaces them). The
/// "6 GHz Operation Information Present" bit (param bit 17) is set.
pub fn he_operation_6ghz(channel: u8) -> Vec<u8> {
    ext_ie(
        36,
        &[
            0xf0, 0x3f, 0x02, // HE Operation Parameters (bit 17 = 6 GHz info present)
            0x86, // BSS Color Information
            0xfc, 0xff, // Basic HE-MCS And NSS Set
            // 6 GHz Operation Information: primary, control(20 MHz, LPI),
            // center seg0, center seg1, minimum rate.
            channel, 0x00, channel, 0x00, 0x06,
        ],
    )
}

/// HE 6 GHz Band Capabilities element (ext ID 59): the per-STA capabilities that
/// the HT/VHT Capabilities elements carry on the lower bands.
pub fn he_6ghz_band_capabilities() -> Vec<u8> {
    ext_ie(59, &[0x00, 0x00])
}

// ---------------------------------------------------------------------------
// 802.11be (EHT) / Multi-Link Device (MLD)
// ---------------------------------------------------------------------------

/// Basic Multi-Link element (ext ID 107) — the element that advertises an AP as
/// part of a Multi-Link Device. Carries the Multi-Link Control (type = Basic)
/// and a Common Info field with the MLD MAC Address. Optional per-link profiles
/// (full multi-link operation) are a larger effort layered on top of this.
pub fn multi_link_basic(mld_mac: &[u8; 6]) -> Vec<u8> {
    let mut data = Vec::new();
    // Multi-Link Control (2 octets, little-endian): bits 0-2 Type = 0 (Basic),
    // bits 4-15 Presence Bitmap = 0 (only the always-present MLD MAC).
    data.extend_from_slice(&[0x00, 0x00]);
    // Common Info: length (incl. itself) + MLD MAC Address.
    data.push(7);
    data.extend_from_slice(mld_mac);
    ext_ie(107, &data)
}

/// EHT Capabilities element (ext ID 108) — minimal MAC/PHY capabilities so a
/// Wi-Fi 7 client recognizes the BSS as EHT-capable.
pub fn eht_capabilities() -> Vec<u8> {
    // EHT MAC Capabilities (2) + EHT PHY Capabilities (9) + supported EHT-MCS/NSS.
    ext_ie(108, &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22])
}

/// Reduced Neighbor Report element (ID 201): how a lower-band (2.4/5 GHz) AP
/// advertises a co-located AP on another band — the standard out-of-band
/// discovery path for a 6 GHz / MLD affiliated AP (6 GHz is passive-scan, so
/// clients learn of it from the lower-band beacon's RNR). One Neighbor AP
/// Information field with a single TBTT Information field (length 13: TBTT
/// offset, BSSID, short SSID, BSS parameters, 20 MHz PSD).
pub fn reduced_neighbor_report(neighbor_bssid: &[u8; 6], op_class: u8, channel: u8) -> Vec<u8> {
    // TBTT Information Header: field type 0, count 0 (1 TBTT info), length 13;
    // then operating class, channel, and the TBTT Information field's offset.
    let mut d = vec![0x00, 13, op_class, channel, 0xff];
    d.extend_from_slice(neighbor_bssid); // BSSID
    d.extend_from_slice(&[0, 0, 0, 0]); // Short SSID
    d.push(0x00); // BSS Parameters
    d.push(0x00); // 20 MHz PSD
    ie(201, &d)
}

/// Supported Operating Classes for a 6 GHz channel: global class 131 (20 MHz).
fn supported_operating_classes_6ghz() -> Vec<u8> {
    ie(59, &[131, 131])
}

/// Beacon/probe/assoc IE block for a 6 GHz channel. 6 GHz is HE-only: no
/// DSSS/HT/VHT, OFDM rates only, plus the HE Capabilities, HE Operation (with
/// the 6 GHz Operation Information) and HE 6 GHz Band Capabilities elements.
pub fn make_beacon_ies_6ghz(ssid: &[u8], channel: u8, country: &[u8; 2]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&ie(0, ssid)); // SSID
    v.extend_from_slice(&ie(1, &RATES_5GHZ)); // Supported Rates (OFDM)
    v.extend_from_slice(&country_ie(country, channel)); // Country
    v.extend_from_slice(&he_capabilities());
    v.extend_from_slice(&he_operation_6ghz(channel));
    v.extend_from_slice(&he_6ghz_band_capabilities());
    v.extend_from_slice(&extended_capabilities());
    v.extend_from_slice(&supported_operating_classes_6ghz());
    v.extend_from_slice(&rrm_enabled_capabilities());
    v.extend_from_slice(&wmm_parameter());
    v
}

/// Extended Capabilities element (ID 127): advertises BSS Transition (bit 19)
/// and Beacon Protection (bit 84).
fn extended_capabilities() -> Vec<u8> {
    let mut bits = [0u8; 11];
    bits[2] |= 0x08; // bit 19: BSS Transition Management
    bits[10] |= 0x10; // bit 84: Beacon Protection Enabled
    ie(127, &bits)
}

/// Supported Operating Classes element (ID 59): the current operating class.
fn supported_operating_classes(channel: u8) -> Vec<u8> {
    let class = if is_5ghz(channel) { 115 } else { 81 };
    ie(59, &[class, class])
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
pub fn make_beacon_ies(ssid: &[u8], channel: u8, country: &[u8; 2]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&ie(0, ssid)); // SSID
    if is_5ghz(channel) {
        v.extend_from_slice(&ie(1, &RATES_5GHZ)); // Supported Rates (OFDM)
        v.extend_from_slice(&country_ie(country, channel)); // Country
    } else {
        v.extend_from_slice(&ie(1, &RATES_2GHZ)); // Supported Rates
        v.extend_from_slice(&ie(3, &[channel])); // DS Parameter Set
        v.extend_from_slice(&country_ie(country, channel)); // Country
        v.extend_from_slice(&ie(50, &EXT_RATES_2GHZ)); // Extended Supported Rates
    }
    // 802.11n HT
    v.extend_from_slice(&ht_capabilities());
    v.extend_from_slice(&ht_operation(channel));
    // 802.11ac VHT (5 GHz only)
    if is_5ghz(channel) {
        v.extend_from_slice(&vht_capabilities());
        v.extend_from_slice(&vht_operation());
    }
    // Extended Capabilities (BTM, Beacon Protection), Operating Classes, RRM
    v.extend_from_slice(&extended_capabilities());
    v.extend_from_slice(&supported_operating_classes(channel));
    v.extend_from_slice(&rrm_enabled_capabilities());
    // WMM/QoS
    v.extend_from_slice(&wmm_parameter());
    v
}

fn dot11_header(frame_type: u8, subtype: u8, flags: u8, a1: &[u8; 6], a2: &[u8; 6], a3: &[u8; 6], sc: u16) -> Vec<u8> {
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

fn llc_snap(ethertype: u16) -> [u8; 8] {
    let mut v = [0u8; 8];
    v[..3].copy_from_slice(&[0xAA, 0xAA, 0x03]); // LLC: SNAP
    // OUI = 00:00:00, then 2-byte ethertype (big-endian)
    v[6..8].copy_from_slice(&ethertype.to_be_bytes());
    v
}

// ---------------------------------------------------------------------------
// Management frames
// ---------------------------------------------------------------------------

pub fn build_beacon(bssid: &[u8; 6], ssid: &[u8], channel: u8, timestamp: u64, tail_ies: &[u8], country: &[u8; 2]) -> Vec<u8> {
    let bcast = [0xffu8; 6];
    let mut v = dot11_header(TYPE_MGMT, SUBTYPE_BEACON, 0, &bcast, bssid, bssid, 0);
    v.extend_from_slice(&timestamp.to_le_bytes());
    v.extend_from_slice(&BEACON_INTERVAL_TU.to_le_bytes()); // beacon interval
    v.extend_from_slice(&CAP_3101);
    v.extend_from_slice(&make_beacon_ies(ssid, channel, country));
    v.extend_from_slice(&tim_element()); // TIM (beacon-only)
    v.extend_from_slice(tail_ies); // RSN (+ RSNXE for WPA3)
    v
}

/// Build a 6 GHz (HE-only) beacon. 6 GHz mandates WPA3, so `tail_ies` is the
/// SAE/OWE RSN(+RSNXE). The capability field omits the "Privacy" short-slot
/// bits that are 2.4/5 GHz specific.
pub fn build_beacon_6ghz(bssid: &[u8; 6], ssid: &[u8], channel: u8, timestamp: u64, tail_ies: &[u8], country: &[u8; 2]) -> Vec<u8> {
    let bcast = [0xffu8; 6];
    let mut v = dot11_header(TYPE_MGMT, SUBTYPE_BEACON, 0, &bcast, bssid, bssid, 0);
    v.extend_from_slice(&timestamp.to_le_bytes());
    v.extend_from_slice(&BEACON_INTERVAL_TU.to_le_bytes());
    v.extend_from_slice(&CAP_3101);
    v.extend_from_slice(&make_beacon_ies_6ghz(ssid, channel, country));
    v.extend_from_slice(&tim_element());
    v.extend_from_slice(tail_ies);
    v
}

#[allow(clippy::too_many_arguments)]
pub fn build_probe_resp(bssid: &[u8; 6], dst: &[u8; 6], ssid: &[u8], channel: u8, timestamp: u64, sc: u16, tail_ies: &[u8], country: &[u8; 2]) -> Vec<u8> {
    let mut v = dot11_header(TYPE_MGMT, SUBTYPE_PROBE_RESP, 0, dst, bssid, bssid, sc);
    v.extend_from_slice(&timestamp.to_le_bytes());
    v.extend_from_slice(&BEACON_INTERVAL_TU.to_le_bytes());
    v.extend_from_slice(&CAP_3101);
    v.extend_from_slice(&make_beacon_ies(ssid, channel, country));
    v.extend_from_slice(tail_ies);
    v
}

/// The security mode an AP advertises.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SecurityMode {
    Wpa2,
    Wpa3Sae,
    /// WPA2/WPA3 transition (mixed PSK + SAE).
    Transition,
    /// OWE (Opportunistic Wireless Encryption).
    Owe,
}

/// The trailing security IEs (RSN, plus RSNXE for SAE modes) advertised in
/// beacons and probe responses.
pub fn security_tail(mode: SecurityMode) -> Vec<u8> {
    let mut v = Vec::new();
    match mode {
        SecurityMode::Wpa2 => v.extend_from_slice(&RSN),
        SecurityMode::Wpa3Sae => {
            v.extend_from_slice(&RSN_WPA3);
            v.extend_from_slice(&RSNXE_H2E);
        }
        SecurityMode::Transition => {
            v.extend_from_slice(&RSN_TRANSITION);
            v.extend_from_slice(&RSNXE_H2E);
        }
        SecurityMode::Owe => v.extend_from_slice(&RSN_OWE),
    }
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

#[allow(clippy::too_many_arguments)]
pub fn build_assoc_resp(bssid: &[u8; 6], dst: &[u8; 6], ssid: &[u8], channel: u8, aid: u16, sc: u16, resp_subtype: u8, country: &[u8; 2]) -> Vec<u8> {
    let mut v = dot11_header(TYPE_MGMT, resp_subtype, 0, dst, bssid, bssid, sc);
    v.extend_from_slice(&CAP_3101);
    v.extend_from_slice(&0u16.to_le_bytes()); // status = success
    v.extend_from_slice(&aid.to_le_bytes());
    v.extend_from_slice(&make_beacon_ies(ssid, channel, country));
    v
}

pub fn build_deauth(bssid: &[u8; 6], dst: &[u8; 6], reason: u16) -> Vec<u8> {
    // Unprotected Deauthentication (subtype 12). `dst` may be a unicast STA or
    // the broadcast address.
    let mut v = dot11_header(TYPE_MGMT, SUBTYPE_DEAUTH, 0, dst, bssid, bssid, 0);
    v.extend_from_slice(&reason.to_le_bytes());
    v
}

// ---------------------------------------------------------------------------
// EAPOL key frames
// ---------------------------------------------------------------------------

/// Key Information bit flags for the EAPOL-Key frame.
#[derive(Default, Clone, Copy)]
pub struct KeyInfo {
    pub encrypted_key_data: bool,
    pub secure: bool,
    pub has_key_mic: bool,
    pub key_ack: bool,
    pub install: bool,
    pub key_type: bool, // true => pairwise
    pub key_descriptor_type_version: u8,
}

impl KeyInfo {
    fn to_u16(self) -> u16 {
        let mut ki: u16 = 0;
        ki |= (self.encrypted_key_data as u16) << 12;
        ki |= (self.secure as u16) << 9;
        ki |= (self.has_key_mic as u16) << 8;
        ki |= (self.key_ack as u16) << 7;
        ki |= (self.install as u16) << 6;
        ki |= (self.key_type as u16) << 3;
        ki |= (self.key_descriptor_type_version as u16) & 0x7;
        ki
    }
}

/// Build the bare EAPOL-Key body (the part scapy calls `EAPOL_KEY`).
#[allow(clippy::too_many_arguments)]
pub fn build_eapol_key_body(
    key_info: KeyInfo,
    key_length: u16,
    key_replay_counter: u64,
    key_nonce: &[u8; 32],
    key_mic: &[u8; 16],
    key_data: &[u8],
) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(0x02); // key_descriptor_type = RSN
    v.extend_from_slice(&key_info.to_u16().to_be_bytes());
    v.extend_from_slice(&key_length.to_be_bytes());
    v.extend_from_slice(&key_replay_counter.to_be_bytes());
    v.extend_from_slice(key_nonce);
    v.extend_from_slice(&[0u8; 16]); // key_iv
    v.extend_from_slice(&[0u8; 8]); // key_rsc
    v.extend_from_slice(&[0u8; 8]); // key_id
    v.extend_from_slice(key_mic);
    v.extend_from_slice(&(key_data.len() as u16).to_be_bytes());
    v.extend_from_slice(key_data);
    v
}

/// Wrap an EAPOL-Key body in the EAPOL header (version 802.1X-2004, type Key).
fn eapol_wrap(body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + body.len());
    v.push(0x02); // version 802.1X-2004
    v.push(0x03); // type EAPOL-Key
    v.extend_from_slice(&(body.len() as u16).to_be_bytes());
    v.extend_from_slice(body);
    v
}

fn eapol_data_header(bssid: &[u8; 6], sta: &[u8; 6], sc: u16) -> Vec<u8> {
    // Data frame, subtype 0, from-DS, addr1=sta addr2=bssid addr3=bssid
    let mut v = dot11_header(TYPE_DATA, 0, FC_FROMDS, sta, bssid, bssid, sc);
    v.extend_from_slice(&llc_snap(ETHERTYPE_EAPOL));
    v
}

fn eapol_data_header_tods(bssid: &[u8; 6], sta: &[u8; 6], sc: u16) -> Vec<u8> {
    // Data frame, subtype 0, to-DS, addr1=bssid addr2=sta addr3=bssid
    let mut v = dot11_header(TYPE_DATA, 0, FC_TODS, bssid, sta, bssid, sc);
    v.extend_from_slice(&llc_snap(ETHERTYPE_EAPOL));
    v
}

// ---------------------------------------------------------------------------
// Station-side management & EAPOL frames (uplink / to-DS)
// ---------------------------------------------------------------------------

pub const AUTH_ALG_OPEN: u16 = 0;
pub const AUTH_ALG_SAE: u16 = 3;
pub const STATUS_SUCCESS: u16 = 0;
/// SAE Hash-to-Element indication, used as the commit status code.
pub const STATUS_SAE_H2E: u16 = 126;

/// A parsed Authentication frame body (algorithm, transaction seq, status, rest).
pub struct AuthBody<'a> {
    pub algo: u16,
    pub seq: u16,
    pub status: u16,
    pub payload: &'a [u8],
}

/// Parse the fixed 6-byte Authentication header and return the trailing payload.
pub fn parse_auth(body: &[u8]) -> Option<AuthBody<'_>> {
    if body.len() < 6 {
        return None;
    }
    Some(AuthBody {
        algo: u16::from_le_bytes([body[0], body[1]]),
        seq: u16::from_le_bytes([body[2], body[3]]),
        status: u16::from_le_bytes([body[4], body[5]]),
        payload: &body[6..],
    })
}

/// Build an SAE Authentication frame (algorithm 3) carrying `payload` (a commit
/// or confirm body).
#[allow(clippy::too_many_arguments)]
pub fn build_sae_auth(a1: &[u8; 6], a2: &[u8; 6], a3: &[u8; 6], flags: u8, sc: u16, seq: u16, status: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = dot11_header(TYPE_MGMT, SUBTYPE_AUTH, flags, a1, a2, a3, sc);
    v.extend_from_slice(&AUTH_ALG_SAE.to_le_bytes());
    v.extend_from_slice(&seq.to_le_bytes());
    v.extend_from_slice(&status.to_le_bytes());
    v.extend_from_slice(payload);
    v
}

/// Open-system authentication request (STA -> AP), seqnum 1.
pub fn build_auth_req(bssid: &[u8; 6], sta: &[u8; 6], sc: u16) -> Vec<u8> {
    let mut v = dot11_header(TYPE_MGMT, SUBTYPE_AUTH, FC_TODS, bssid, sta, bssid, sc);
    v.extend_from_slice(&0u16.to_le_bytes()); // algo = open
    v.extend_from_slice(&1u16.to_le_bytes()); // seqnum
    v.extend_from_slice(&0u16.to_le_bytes()); // status
    v
}

/// Association request (STA -> AP) advertising the SSID and RSN/CCMP.
pub fn build_assoc_req(bssid: &[u8; 6], sta: &[u8; 6], ssid: &[u8], sc: u16) -> Vec<u8> {
    let mut v = dot11_header(TYPE_MGMT, SUBTYPE_ASSOC_REQ, FC_TODS, bssid, sta, bssid, sc);
    v.extend_from_slice(&CAP_3101);
    v.extend_from_slice(&STA_LISTEN_INTERVAL.to_le_bytes()); // listen interval
    v.extend_from_slice(&ie(0, ssid));
    v.extend_from_slice(&ie(1, &[0x0c]));
    v.extend_from_slice(&RSN);
    v
}

/// Association request for WPA3-SAE: advertises the SAE AKM (00-0F-AC:8),
/// MFPR|MFPC, the BIP group-management cipher, and the RSNXE H2E capability.
/// (A WPA2-PSK RSN here would be rejected by an SAE AP with "Invalid AKMP".)
pub fn build_assoc_req_sae(bssid: &[u8; 6], sta: &[u8; 6], ssid: &[u8], sc: u16) -> Vec<u8> {
    let mut v = dot11_header(TYPE_MGMT, SUBTYPE_ASSOC_REQ, FC_TODS, bssid, sta, bssid, sc);
    v.extend_from_slice(&CAP_3101);
    v.extend_from_slice(&STA_LISTEN_INTERVAL.to_le_bytes());
    v.extend_from_slice(&ie(0, ssid));
    v.extend_from_slice(&ie(1, &[0x0c]));
    v.extend_from_slice(&RSN_WPA3);
    v.extend_from_slice(&RSNXE_H2E);
    v
}

/// OWE Diffie-Hellman Parameter element (ID 255, extension 32): group + public
/// key (RFC 8110).
pub fn build_dh_param_element(group: u16, pubkey: &[u8]) -> Vec<u8> {
    let mut info = vec![32u8]; // Element ID Extension = 32 (DH Parameter)
    info.extend_from_slice(&group.to_le_bytes());
    info.extend_from_slice(pubkey);
    ie(255, &info)
}

/// Parse an OWE DH Parameter element from an IE list, returning `(group, pubkey)`.
pub fn parse_dh_param(ies: &[u8]) -> Option<(u16, Vec<u8>)> {
    let mut i = 0;
    while i + 2 <= ies.len() {
        let id = ies[i];
        let len = ies[i + 1] as usize;
        if i + 2 + len > ies.len() {
            break;
        }
        let body = &ies[i + 2..i + 2 + len];
        if id == 255 && len >= 3 && body[0] == 32 {
            let group = u16::from_le_bytes([body[1], body[2]]);
            return Some((group, body[3..].to_vec()));
        }
        i += 2 + len;
    }
    None
}

/// RSN element advertising the OWE AKM (00-0F-AC:18), CCMP, MFPR|MFPC.
pub const RSN_OWE: [u8; 22] = [
    0x30, 0x14, // id 48, len 20
    0x01, 0x00, // version
    0x00, 0x0f, 0xac, 0x04, // group: CCMP
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, // 1 pairwise: CCMP
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x12, // 1 AKM: OWE (18)
    0xc0, 0x00, // RSN caps: MFPR|MFPC
];

/// Association request for OWE: open + RSN(OWE) + the DH Parameter element.
pub fn build_assoc_req_owe(bssid: &[u8; 6], sta: &[u8; 6], ssid: &[u8], dh_element: &[u8], sc: u16) -> Vec<u8> {
    let mut v = dot11_header(TYPE_MGMT, SUBTYPE_ASSOC_REQ, FC_TODS, bssid, sta, bssid, sc);
    v.extend_from_slice(&CAP_3101);
    v.extend_from_slice(&STA_LISTEN_INTERVAL.to_le_bytes());
    v.extend_from_slice(&ie(0, ssid));
    v.extend_from_slice(&ie(1, &[0x0c]));
    v.extend_from_slice(&RSN_OWE);
    v.extend_from_slice(dh_element);
    v
}

/// A WPA3-SAE RSN element carrying a cached PMKID, for PMKSA-caching fast
/// reconnect.
pub fn rsn_with_pmkid(pmkid: &[u8; 16]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x01, 0x00]); // version
    body.extend_from_slice(&[0x00, 0x0f, 0xac, 0x04]); // group: CCMP
    body.extend_from_slice(&[0x01, 0x00, 0x00, 0x0f, 0xac, 0x04]); // 1 pairwise: CCMP
    body.extend_from_slice(&[0x01, 0x00, 0x00, 0x0f, 0xac, 0x08]); // 1 AKM: SAE
    body.extend_from_slice(&[0xc0, 0x00]); // RSN caps: MFPR|MFPC
    body.extend_from_slice(&[0x01, 0x00]); // PMKID count = 1
    body.extend_from_slice(pmkid);
    body.extend_from_slice(&[0x00, 0x0f, 0xac, 0x06]); // group mgmt: BIP
    ie(48, &body)
}

/// Association request including a cached PMKID (PMKSA caching reconnect).
pub fn build_assoc_req_pmkid(bssid: &[u8; 6], sta: &[u8; 6], ssid: &[u8], pmkid: &[u8; 16], sc: u16) -> Vec<u8> {
    let mut v = dot11_header(TYPE_MGMT, SUBTYPE_ASSOC_REQ, FC_TODS, bssid, sta, bssid, sc);
    v.extend_from_slice(&CAP_3101);
    v.extend_from_slice(&STA_LISTEN_INTERVAL.to_le_bytes());
    v.extend_from_slice(&ie(0, ssid));
    v.extend_from_slice(&ie(1, &[0x0c]));
    v.extend_from_slice(&rsn_with_pmkid(pmkid));
    v
}

/// Find an information element by id in an IE list, returning its payload.
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

/// Extract a PMKID from an RSN element body (after id/len), if present.
pub fn parse_rsn_pmkid(rsn_body: &[u8]) -> Option<[u8; 16]> {
    let mut off = 2 + 4; // version + group cipher
    let pw_count = u16::from_le_bytes([*rsn_body.get(off)?, *rsn_body.get(off + 1)?]) as usize;
    off += 2 + 4 * pw_count;
    let akm_count = u16::from_le_bytes([*rsn_body.get(off)?, *rsn_body.get(off + 1)?]) as usize;
    off += 2 + 4 * akm_count;
    off += 2; // RSN capabilities
    let pmkid_count = u16::from_le_bytes([*rsn_body.get(off)?, *rsn_body.get(off + 1)?]) as usize;
    off += 2;
    if pmkid_count >= 1 && off + 16 <= rsn_body.len() {
        let mut pmkid = [0u8; 16];
        pmkid.copy_from_slice(&rsn_body[off..off + 16]);
        Some(pmkid)
    } else {
        None
    }
}

/// EAPOL message 2 (STA -> AP): carries the SNONCE and the supplicant RSN, MIC'd
/// with the freshly derived KCK.
#[allow(clippy::too_many_arguments)]
pub fn build_eapol_m2(bssid: &[u8; 6], sta: &[u8; 6], snonce: &[u8; 32], kck: &[u8], supp_rsn: &[u8], sc: u16, mic: KeyMic, oci: Option<(u8, u8)>) -> Vec<u8> {
    let ki = KeyInfo {
        has_key_mic: true,
        key_type: true,
        key_descriptor_type_version: mic.version(),
        ..Default::default()
    };
    // m2's key data echoes the exact RSN(E + RSNXE) the STA sent in its
    // (re)association request; an AP rejects a mismatch (e.g. SAE expects the
    // SAE RSN, not WPA2-PSK).
    let mut key_data = supp_rsn.to_vec();
    if let Some((oc, ch)) = oci {
        key_data.extend_from_slice(&oci_kde(oc, ch)); // OCV
    }
    let body0 = build_eapol_key_body(ki, 0, 1, snonce, &[0u8; 16], &key_data);
    let mic = mic.compute(kck, &eapol_wrap(&body0));
    let body = build_eapol_key_body(ki, 0, 1, snonce, &mic, &key_data);
    let mut frame = eapol_data_header_tods(bssid, sta, sc);
    frame.extend_from_slice(&eapol_wrap(&body));
    frame
}

/// EAPOL message 4 (STA -> AP): the handshake ack, MIC'd with the KCK.
pub fn build_eapol_m4(bssid: &[u8; 6], sta: &[u8; 6], kck: &[u8], sc: u16, mic: KeyMic) -> Vec<u8> {
    let ki = KeyInfo {
        has_key_mic: true,
        key_type: true,
        key_descriptor_type_version: mic.version(),
        ..Default::default()
    };
    let zero_nonce = [0u8; 32];
    let body0 = build_eapol_key_body(ki, 0, 2, &zero_nonce, &[0u8; 16], &[]);
    let mic = mic.compute(kck, &eapol_wrap(&body0));
    let body = build_eapol_key_body(ki, 0, 2, &zero_nonce, &mic, &[]);
    let mut frame = eapol_data_header_tods(bssid, sta, sc);
    frame.extend_from_slice(&eapol_wrap(&body));
    frame
}

/// Key Descriptor Version: 0 for AKM-defined (SAE/SHA-256), 2 for WPA2 (SHA-1).
/// The EAPOL-Key MIC algorithm + Key Descriptor Version, selected by the AKM.
/// (Real APs reject the wrong one: SAE wants AES-CMAC, OWE wants HMAC-SHA-256.)
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KeyMic {
    /// WPA2-PSK (AKM 00-0F-AC:2): HMAC-SHA1-128, Key Descriptor Version 2.
    HmacSha1,
    /// WPA3-SAE (AKM 00-0F-AC:8): AES-128-CMAC, Key Descriptor Version 0.
    AesCmac,
    /// OWE (AKM 00-0F-AC:18): HMAC-SHA256-128, Key Descriptor Version 0.
    HmacSha256,
}

impl KeyMic {
    /// Select by `sha256` (SHA-256 key hierarchy: SAE or OWE) and `owe`.
    pub fn select(sha256: bool, owe: bool) -> KeyMic {
        if !sha256 {
            KeyMic::HmacSha1
        } else if owe {
            KeyMic::HmacSha256
        } else {
            KeyMic::AesCmac
        }
    }

    fn version(self) -> u8 {
        match self {
            KeyMic::HmacSha1 => 2,
            _ => 0,
        }
    }

    /// Compute the EAPOL-Key MIC over `data` (with the MIC field zeroed).
    pub fn compute(self, kck: &[u8], data: &[u8]) -> [u8; 16] {
        let mut mic = [0u8; 16];
        match self {
            KeyMic::HmacSha1 => mic.copy_from_slice(&crypto::hmac_sha1(kck, data)[..16]),
            KeyMic::AesCmac => mic.copy_from_slice(&crypto::aes_cmac(kck, data)),
            KeyMic::HmacSha256 => mic.copy_from_slice(&crypto::hmac_sha256(kck, data)[..16]),
        }
        mic
    }
}

/// EAPOL message 1 of the 4-way handshake (AP -> STA, carries the ANONCE).
pub fn build_eapol_m1(bssid: &[u8; 6], sta: &[u8; 6], anonce: &[u8; 32], sc: u16, mic: KeyMic) -> Vec<u8> {
    let ki = KeyInfo {
        key_ack: true,
        key_type: true,
        key_descriptor_type_version: mic.version(),
        ..Default::default()
    };
    let body = build_eapol_key_body(ki, 16, 1, anonce, &[0u8; 16], &[]);
    let mut frame = eapol_data_header(bssid, sta, sc);
    frame.extend_from_slice(&eapol_wrap(&body));
    frame
}

/// The GTK key-data encapsulation (KDE) wrapped inside message 3:
/// `DD len 00-0F-AC 01 <KeyID/Tx byte> <reserved> <GTK>` (IEEE 802.11 Fig 12-45).
///
/// Note: the reference `ap.py` appends a stray zero-length `DD 00` vendor
/// element after the GTK; that is non-standard cruft and is intentionally not
/// reproduced here.
pub fn gtk_kde(gtk: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(0xDD);
    v.push((gtk.len() + 6) as u8);
    v.extend_from_slice(&[0x00, 0x0f, 0xac]);
    v.extend_from_slice(&[0x01, 0x00, 0x00]);
    v.extend_from_slice(gtk);
    v
}

/// Operating Channel Information (OCI) KDE (00-0F-AC type 13) for Operating
/// Channel Validation: Operating Class, Primary Channel, Frequency Segment 1.
pub fn oci_kde(op_class: u8, channel: u8) -> Vec<u8> {
    vec![0xDD, 4 + 3, 0x00, 0x0f, 0xac, 0x0d, op_class, channel, 0x00]
}

/// Extract `(op_class, channel)` from an OCI KDE in EAPOL key data, if present.
pub fn parse_oci_kde(key_data: &[u8]) -> Option<(u8, u8)> {
    let mut i = 0;
    while i + 2 <= key_data.len() {
        let id = key_data[i];
        let len = key_data[i + 1] as usize;
        if i + 2 + len > key_data.len() {
            break;
        }
        let body = &key_data[i + 2..i + 2 + len];
        if id == 0xDD && len >= 4 + 3 && body[..3] == [0x00, 0x0f, 0xac] && body[3] == 0x0d {
            return Some((body[4], body[5]));
        }
        i += 2 + len;
    }
    None
}

/// The operating class for a channel (81 for 2.4 GHz, 115 for 5 GHz) — used for
/// the OCI.
pub fn operating_class(channel: u8) -> u8 {
    if is_5ghz(channel) {
        115
    } else {
        81
    }
}

/// The IGTK key-data encapsulation (KDE) for PMF (802.11w): delivers the
/// Integrity GTK used to BIP-protect group-addressed robust management frames.
/// `DD len 00-0F-AC 09 KeyID(2 LE) IPN(6) IGTK(16)`.
pub fn igtk_kde(key_id: u16, ipn: &[u8; 6], igtk: &[u8; 16]) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(0xDD);
    v.push((4 + 2 + 6 + 16) as u8); // OUI(3)+type(1)+data
    v.extend_from_slice(&[0x00, 0x0f, 0xac, 0x09]);
    v.extend_from_slice(&key_id.to_le_bytes());
    v.extend_from_slice(ipn);
    v.extend_from_slice(igtk);
    v
}

/// Build an (unprotected) management Action frame carrying `body`.
pub fn build_action_frame(a1: &[u8; 6], a2: &[u8; 6], a3: &[u8; 6], sc: u16, body: &[u8]) -> Vec<u8> {
    let mut v = dot11_header(TYPE_MGMT, SUBTYPE_ACTION, 0, a1, a2, a3, sc);
    v.extend_from_slice(body);
    v
}

// ---------------------------------------------------------------------------
// 802.11v BSS Transition Management — unprotected (WPA2) request + response
// (the CCMP-protected/PMF path is `build_protected_btm_request`).
// ---------------------------------------------------------------------------

/// BSS Transition Management Response action.
pub const WNM_BTM_RESPONSE: u8 = 8;
/// BTM Request Mode: "Preferred Candidate List Included" bit.
pub const BTM_REQ_PREF_CAND_LIST: u8 = 0x01;

/// 802.11v BSS Transition Management Request action-frame body, optionally
/// carrying a preferred candidate list (Neighbor Report elements). Steers a
/// client toward a better BSS (band/AP steering, load balancing).
pub fn btm_request_body(dialog_token: u8, req_mode: u8, disassoc_timer: u16, validity: u8, candidates: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(7 + candidates.len());
    v.push(ACTION_CATEGORY_WNM);
    v.push(WNM_BTM_REQUEST);
    v.push(dialog_token);
    v.push(req_mode);
    v.extend_from_slice(&disassoc_timer.to_le_bytes());
    v.push(validity);
    v.extend_from_slice(candidates);
    v
}

/// Parse a BTM Response: returns `(dialog_token, status_code)`. Status 0 =
/// "Accept". `body` is the action-frame body (starting at the WNM category).
pub fn parse_btm_response(body: &[u8]) -> Option<(u8, u8)> {
    if body.len() >= 4 && body[0] == ACTION_CATEGORY_WNM && body[1] == WNM_BTM_RESPONSE {
        Some((body[2], body[3])) // dialog token, status code
    } else {
        None
    }
}

/// Management MIC Element id (802.11w / BIP).
pub const EID_MME: u8 = 76;

/// BIP-CMAC-128 AAD: FC (Retry/PwrMgmt/MoreData masked) || A1 || A2 || A3.
fn bip_aad(fc0: u8, fc1: u8, a1: &[u8; 6], a2: &[u8; 6], a3: &[u8; 6]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(20);
    aad.push(fc0);
    aad.push(fc1 & 0xC7); // mask Retry (0x08), PwrMgmt (0x10), MoreData (0x20)
    aad.extend_from_slice(a1);
    aad.extend_from_slice(a2);
    aad.extend_from_slice(a3);
    aad
}

/// Protect a group-addressed robust management frame with BIP-CMAC-128 by
/// appending a Management MIC Element (MME) computed over the frame body.
/// Returns the body with the MME appended.
#[allow(clippy::too_many_arguments)]
pub fn bip_protect(igtk: &[u8; 16], key_id: u16, ipn: &[u8; 6], fc0: u8, fc1: u8, a1: &[u8; 6], a2: &[u8; 6], a3: &[u8; 6], body: &[u8]) -> Vec<u8> {
    let mme_off = body.len();
    let mut full = body.to_vec();
    full.push(EID_MME);
    full.push(16); // KeyID(2) + IPN(6) + MIC(8)
    full.extend_from_slice(&key_id.to_le_bytes());
    full.extend_from_slice(ipn);
    full.extend_from_slice(&[0u8; 8]); // MIC placeholder

    let mut input = bip_aad(fc0, fc1, a1, a2, a3);
    input.extend_from_slice(&full);
    let mic = crypto::aes_cmac(igtk, &input);

    let mic_off = mme_off + 10; // EID(1)+len(1)+KeyID(2)+IPN(6)
    full[mic_off..mic_off + 8].copy_from_slice(&mic[..8]);
    full
}

/// Verify a BIP-protected group management frame (the MME must be the trailing
/// 18 bytes of `body_with_mme`).
pub fn bip_verify(igtk: &[u8; 16], fc0: u8, fc1: u8, a1: &[u8; 6], a2: &[u8; 6], a3: &[u8; 6], body_with_mme: &[u8]) -> bool {
    if body_with_mme.len() < 18 {
        return false;
    }
    let mme_off = body_with_mme.len() - 18;
    if body_with_mme[mme_off] != EID_MME || body_with_mme[mme_off + 1] != 16 {
        return false;
    }
    let given = &body_with_mme[mme_off + 10..mme_off + 18];

    let mut full = body_with_mme.to_vec();
    for b in full[mme_off + 10..mme_off + 18].iter_mut() {
        *b = 0;
    }
    let mut input = bip_aad(fc0, fc1, a1, a2, a3);
    input.extend_from_slice(&full);
    let mic = crypto::aes_cmac(igtk, &input);
    crypto::constant_time_eq(&mic[..8], given)
}

/// The BIGTK key-data encapsulation (KDE) for Beacon Protection: delivers the
/// Beacon Integrity GTK. `DD len 00-0F-AC 14 KeyID(2 LE) IPN(6) BIGTK(16)`.
pub fn bigtk_kde(key_id: u16, ipn: &[u8; 6], bigtk: &[u8; 16]) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(0xDD);
    v.push((4 + 2 + 6 + 16) as u8);
    v.extend_from_slice(&[0x00, 0x0f, 0xac, 0x0e]); // type 14 = BIGTK
    v.extend_from_slice(&key_id.to_le_bytes());
    v.extend_from_slice(ipn);
    v.extend_from_slice(bigtk);
    v
}

/// Scan EAPOL key data for the BIGTK KDE (00-0F-AC type 14).
pub fn parse_bigtk_kde(key_data: &[u8]) -> Option<(u16, [u8; 6], [u8; 16])> {
    let mut i = 0;
    while i + 2 <= key_data.len() {
        let id = key_data[i];
        let len = key_data[i + 1] as usize;
        if i + 2 + len > key_data.len() {
            break;
        }
        let body = &key_data[i + 2..i + 2 + len];
        if id == 0xDD && len >= 4 + 2 + 6 + 16 && body[..3] == [0x00, 0x0f, 0xac] && body[3] == 0x0e {
            let key_id = u16::from_le_bytes([body[4], body[5]]);
            let mut ipn = [0u8; 6];
            ipn.copy_from_slice(&body[6..12]);
            let mut bigtk = [0u8; 16];
            bigtk.copy_from_slice(&body[12..28]);
            return Some((key_id, ipn, bigtk));
        }
        i += 2 + len;
    }
    None
}

/// EAPOL message 3 (AP -> STA): installs the PTK and delivers the wrapped GTK
/// (and IGTK for PMF, BIGTK for Beacon Protection). `sha256` selects the
/// SHA-256 key descriptor (SAE/WPA3) vs SHA-1 (WPA2).
#[allow(clippy::too_many_arguments)]
pub fn build_eapol_m3(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    anonce: &[u8; 32],
    kck: &[u8],
    kek: &[u8],
    ap_rsn: &[u8],
    gtk: &[u8],
    igtk: Option<(u16, [u8; 6], [u8; 16])>,
    bigtk: Option<(u16, [u8; 6], [u8; 16])>,
    oci: Option<(u8, u8)>,
    sc: u16,
    mic: KeyMic,
) -> Vec<u8> {
    let mut plain = Vec::new();
    plain.extend_from_slice(ap_rsn);
    plain.extend_from_slice(&gtk_kde(gtk));
    if let Some((key_id, ipn, ik)) = igtk {
        plain.extend_from_slice(&igtk_kde(key_id, &ipn, &ik));
    }
    if let Some((key_id, ipn, bk)) = bigtk {
        plain.extend_from_slice(&bigtk_kde(key_id, &ipn, &bk));
    }
    if let Some((oc, ch)) = oci {
        plain.extend_from_slice(&oci_kde(oc, ch)); // OCV
    }
    let keydata = crypto::aes_wrap(kek, &crypto::pad_key_data(plain));

    let ki = KeyInfo {
        encrypted_key_data: true,
        secure: true,
        has_key_mic: true,
        key_ack: true,
        install: true,
        key_type: true,
        key_descriptor_type_version: mic.version(),
    };

    // Build once with a zero MIC, compute the MIC over the EAPOL frame, rebuild.
    let body0 = build_eapol_key_body(ki, 16, 2, anonce, &[0u8; 16], &keydata);
    let mic = mic.compute(kck, &eapol_wrap(&body0));

    let body = build_eapol_key_body(ki, 16, 2, anonce, &mic, &keydata);
    let mut frame = eapol_data_header(bssid, sta, sc);
    frame.extend_from_slice(&eapol_wrap(&body));
    frame
}

// ---------------------------------------------------------------------------
// CCMP data frames
// ---------------------------------------------------------------------------

/// 6-byte big-endian packed packet number, for the CCM nonce (`pn2bin`).
pub fn pn2bin(pn: u64) -> [u8; 6] {
    let b = pn.to_be_bytes(); // 8 bytes
    let mut out = [0u8; 6];
    out.copy_from_slice(&b[2..]);
    out
}

/// Little-endian per-octet PN, as stored in the CCMP header (`pn2bytes`).
pub fn pn2bytes(pn: u64) -> [u8; 6] {
    let mut out = [0u8; 6];
    let mut v = pn;
    for o in out.iter_mut() {
        *o = (v & 0xFF) as u8;
        v >>= 8;
    }
    out
}

/// CCM nonce = priority(1) || addr(6) || PN(6, big-endian).
pub fn ccmp_get_nonce(priority: u8, addr: &[u8; 6], pn: u64) -> [u8; 13] {
    let mut nonce = [0u8; 13];
    nonce[0] = priority;
    nonce[1..7].copy_from_slice(addr);
    nonce[7..13].copy_from_slice(&pn2bin(pn));
    nonce
}

/// CCM additional authenticated data, mirroring `ccmp_get_aad`.
pub fn ccmp_get_aad(fc0: u8, fc1: u8, a1: &[u8; 6], a2: &[u8; 6], a3: &[u8; 6], sc: u16, qos_tid: Option<u16>) -> Vec<u8> {
    let mut aad = Vec::with_capacity(22);
    // FC octet 0: per IEEE 802.11 / mac80211, the Subtype bits (b4-b6) are masked
    // to 0 for Data frames only; for Management frames the full octet (incl.
    // subtype) is covered, so Deauth vs Disassoc vs Action can't be swapped.
    let is_data = (fc0 >> 2) & 0x03 == TYPE_DATA;
    aad.push(if is_data { fc0 & 0x8F } else { fc0 });
    aad.push(fc1 & 0xC7);
    aad.extend_from_slice(a1);
    aad.extend_from_slice(a2);
    aad.extend_from_slice(a3);
    aad.extend_from_slice(&(sc & 0xF).to_le_bytes());
    if let Some(tid) = qos_tid {
        aad.extend_from_slice(&tid.to_le_bytes());
    }
    aad
}

/// CCMP header: PN0 PN1 rsvd keyflags PN2 PN3 PN4 PN5.
fn ccmp_header(pn: u64, key_id: u8) -> [u8; 8] {
    let p = pn2bytes(pn);
    let mut h = [0u8; 8];
    h[0] = p[0];
    h[1] = p[1];
    h[2] = 0x00; // reserved
    h[3] = (key_id << 6) | 0x20; // ext_iv = 1
    h[4] = p[2];
    h[5] = p[3];
    h[6] = p[4];
    h[7] = p[5];
    h
}

/// Build an encrypted CCMP data frame carrying an L3 payload.
///
/// `flags` selects direction (`FC_FROMDS|FC_PROTECTED` downlink, etc.). The
/// inner payload is the bytes *after* the Ethernet header; `ethertype` is the
/// SNAP code. Mirrors `encrypt_ccmp`.
#[allow(clippy::too_many_arguments)]
pub fn build_ccmp_data(
    a1: &[u8; 6],
    a2: &[u8; 6],
    a3: &[u8; 6],
    flags: u8,
    sc: u16,
    pn: u64,
    key_id: u8,
    tk: &[u8],
    ethertype: u16,
    inner_payload: &[u8],
) -> Vec<u8> {
    let mut frame = dot11_header(TYPE_DATA, 0, flags, a1, a2, a3, sc);

    let fc_bytes = (frame[0], frame[1]);
    let nonce = ccmp_get_nonce(0, a2, pn);
    let aad = ccmp_get_aad(fc_bytes.0, fc_bytes.1, a1, a2, a3, sc, None);

    let mut plaintext = Vec::with_capacity(8 + inner_payload.len());
    plaintext.extend_from_slice(&llc_snap(ethertype));
    plaintext.extend_from_slice(inner_payload);

    let (cipher, tag) = crypto::run_ccmp_encrypt(tk, &nonce, &aad, &plaintext);

    frame.extend_from_slice(&ccmp_header(pn, key_id));
    frame.extend_from_slice(&cipher);
    frame.extend_from_slice(&tag);
    frame
}

/// Scan EAPOL key data for the IGTK KDE (00-0F-AC type 9) and extract
/// `(key_id, IPN, IGTK)`.
pub fn parse_igtk_kde(key_data: &[u8]) -> Option<(u16, [u8; 6], [u8; 16])> {
    let mut i = 0;
    while i + 2 <= key_data.len() {
        let id = key_data[i];
        let len = key_data[i + 1] as usize;
        if i + 2 + len > key_data.len() {
            break;
        }
        // an empty element (e.g. the GTK KDE's trailing `dd 00` pad) is skipped
        let body = &key_data[i + 2..i + 2 + len];
        if id == 0xDD && len >= 4 + 2 + 6 + 16 && body[..3] == [0x00, 0x0f, 0xac] && body[3] == 0x09 {
            let key_id = u16::from_le_bytes([body[4], body[5]]);
            let mut ipn = [0u8; 6];
            ipn.copy_from_slice(&body[6..12]);
            let mut igtk = [0u8; 16];
            igtk.copy_from_slice(&body[12..28]);
            return Some((key_id, ipn, igtk));
        }
        i += 2 + len;
    }
    None
}

/// Scan EAPOL key data for the GTK KDE (00-0F-AC type 1) and extract the GTK.
pub fn parse_gtk_kde(key_data: &[u8]) -> Option<Vec<u8>> {
    let mut i = 0;
    while i + 2 <= key_data.len() {
        let id = key_data[i];
        let len = key_data[i + 1] as usize;
        if i + 2 + len > key_data.len() {
            break;
        }
        let body = &key_data[i + 2..i + 2 + len];
        if id == 0xDD && len >= 6 + 16 && body[..3] == [0x00, 0x0f, 0xac] && body[3] == 0x01 {
            // OUI(3) + type(1) + keyinfo(1) + reserved(1), then GTK
            return Some(body[6..len].to_vec());
        }
        i += 2 + len;
    }
    None
}

/// Group Key Handshake message 1 (AP -> STA): delivers a fresh GTK (and IGTK)
/// for rekeying, encrypted under the KEK and MIC'd with the KCK.
#[allow(clippy::too_many_arguments)]
pub fn build_group_key_msg1(bssid: &[u8; 6], sta: &[u8; 6], kck: &[u8], kek: &[u8], gtk: &[u8], igtk: Option<(u16, [u8; 6], [u8; 16])>, replay: u64, sc: u16, mic: KeyMic) -> Vec<u8> {
    let mut plain = gtk_kde(gtk);
    if let Some((kid, ipn, ik)) = igtk {
        plain.extend_from_slice(&igtk_kde(kid, &ipn, &ik));
    }
    let keydata = crypto::aes_wrap(kek, &crypto::pad_key_data(plain));
    let ki = KeyInfo {
        encrypted_key_data: true,
        secure: true,
        has_key_mic: true,
        key_ack: true,
        install: false,
        key_type: false, // group key
        key_descriptor_type_version: mic.version(),
    };
    let zero_nonce = [0u8; 32];
    let body0 = build_eapol_key_body(ki, 16, replay, &zero_nonce, &[0u8; 16], &keydata);
    let mic = mic.compute(kck, &eapol_wrap(&body0));
    let body = build_eapol_key_body(ki, 16, replay, &zero_nonce, &mic, &keydata);
    let mut frame = eapol_data_header(bssid, sta, sc);
    frame.extend_from_slice(&eapol_wrap(&body));
    frame
}

/// Group Key Handshake message 2 (STA -> AP): acknowledges the new GTK.
pub fn build_group_key_msg2(bssid: &[u8; 6], sta: &[u8; 6], kck: &[u8], replay: u64, sc: u16, mic: KeyMic) -> Vec<u8> {
    let ki = KeyInfo {
        secure: true,
        has_key_mic: true,
        key_type: false, // group key
        key_descriptor_type_version: mic.version(),
        ..Default::default()
    };
    let zero_nonce = [0u8; 32];
    let body0 = build_eapol_key_body(ki, 0, replay, &zero_nonce, &[0u8; 16], &[]);
    let mic = mic.compute(kck, &eapol_wrap(&body0));
    let body = build_eapol_key_body(ki, 0, replay, &zero_nonce, &mic, &[]);
    let mut frame = eapol_data_header_tods(bssid, sta, sc);
    frame.extend_from_slice(&eapol_wrap(&body));
    frame
}

/// Build a BIP-protected, group-addressed Deauthentication frame (PMF). The
/// management body is `reason`, with a trailing Management MIC Element.
pub fn build_group_deauth_bip(bssid: &[u8; 6], igtk: &[u8; 16], key_id: u16, ipn: &[u8; 6], reason: u16, sc: u16) -> Vec<u8> {
    let bcast = [0xffu8; 6];
    let hdr = dot11_header(TYPE_MGMT, SUBTYPE_DEAUTH, 0, &bcast, bssid, bssid, sc);
    let (fc0, fc1) = (hdr[0], hdr[1]);
    let body = bip_protect(igtk, key_id, ipn, fc0, fc1, &bcast, bssid, bssid, &reason.to_le_bytes());
    let mut frame = hdr;
    frame.extend_from_slice(&body);
    frame
}

/// Decrypt a CCMP-protected data frame back into an Ethernet frame.
///
/// `from_ap` chooses the address mapping: downlink (from-DS) frames take
/// DA=addr1/SA=addr3, uplink (to-DS) frames take DA=addr3/SA=addr2. Returns the
/// reconstructed Ethernet bytes, or `None` if the tag does not verify.
pub fn decrypt_ccmp(frame: &Dot11, tk: &[u8], from_ap: bool) -> Option<Vec<u8>> {
    let pn = frame.ccmp_pn()?;
    let qos_tid = frame.qos.map(|_| frame.priority());
    let nonce = ccmp_get_nonce(frame.priority() as u8, &frame.addr2, pn);
    let aad = ccmp_get_aad(frame.fc0, frame.fc1, &frame.addr1, &frame.addr2, &frame.addr3, frame.sc, qos_tid);

    let data = frame.ccmp_data()?;
    if data.len() < 8 {
        return None;
    }
    let (payload, tag) = data.split_at(data.len() - 8);
    let (plaintext, valid) = crypto::run_ccmp_decrypt(tk, &nonce, &aad, payload, tag);
    if !valid {
        return None;
    }
    if plaintext.len() < 8 {
        return None;
    }
    // LLC/SNAP: skip 6 bytes, ethertype at [6..8], L3 follows
    let ethertype = [plaintext[6], plaintext[7]];
    let l3 = &plaintext[8..];

    let (da, sa) = if from_ap {
        (frame.addr1, frame.addr3)
    } else {
        (frame.addr3, frame.addr2)
    };

    let mut eth = Vec::with_capacity(14 + l3.len());
    eth.extend_from_slice(&da);
    eth.extend_from_slice(&sa);
    eth.extend_from_slice(&ethertype);
    eth.extend_from_slice(l3);
    Some(eth)
}

// ---------------------------------------------------------------------------
// Protected (CCMP) management frames — robust unicast mgmt under PMF
// ---------------------------------------------------------------------------

/// CCMP-encrypt a management frame body (no LLC/SNAP — management frames carry
/// their fixed fields directly). Used to protect robust unicast management
/// frames (Deauth/Disassoc/Action) under PMF.
#[allow(clippy::too_many_arguments)]
pub fn build_ccmp_mgmt(subtype: u8, a1: &[u8; 6], a2: &[u8; 6], a3: &[u8; 6], sc: u16, pn: u64, key_id: u8, tk: &[u8], body: &[u8]) -> Vec<u8> {
    let mut frame = dot11_header(TYPE_MGMT, subtype, FC_PROTECTED, a1, a2, a3, sc);
    let (fc0, fc1) = (frame[0], frame[1]);
    let nonce = ccmp_get_nonce(0, a2, pn);
    let aad = ccmp_get_aad(fc0, fc1, a1, a2, a3, sc, None);
    let (cipher, tag) = crypto::run_ccmp_encrypt(tk, &nonce, &aad, body);
    frame.extend_from_slice(&ccmp_header(pn, key_id));
    frame.extend_from_slice(&cipher);
    frame.extend_from_slice(&tag);
    frame
}

/// Decrypt a CCMP-protected management frame, returning the plaintext body, or
/// `None` if the MIC does not verify.
pub fn decrypt_ccmp_mgmt(frame: &Dot11, tk: &[u8]) -> Option<Vec<u8>> {
    let pn = frame.ccmp_pn()?;
    let nonce = ccmp_get_nonce(frame.priority() as u8, &frame.addr2, pn);
    let aad = ccmp_get_aad(frame.fc0, frame.fc1, &frame.addr1, &frame.addr2, &frame.addr3, frame.sc, frame.qos.map(|_| frame.priority()));
    let data = frame.ccmp_data()?;
    if data.len() < 8 {
        return None;
    }
    let (payload, tag) = data.split_at(data.len() - 8);
    let (plaintext, valid) = crypto::run_ccmp_decrypt(tk, &nonce, &aad, payload, tag);
    if valid {
        Some(plaintext)
    } else {
        None
    }
}

/// Build a CCMP-protected unicast Deauthentication frame (AP -> STA under PMF).
pub fn build_protected_deauth(bssid: &[u8; 6], sta: &[u8; 6], reason: u16, sc: u16, pn: u64, tk: &[u8]) -> Vec<u8> {
    build_ccmp_mgmt(SUBTYPE_DEAUTH, sta, bssid, bssid, sc, pn, 0, tk, &reason.to_le_bytes())
}

// 802.11v WNM and 802.11k Radio Measurement action categories.
pub const ACTION_CATEGORY_RADIO_MEAS: u8 = 5;
pub const RADIO_MEAS_NEIGHBOR_REPORT_RESP: u8 = 5;
pub const ACTION_CATEGORY_WNM: u8 = 10;
pub const WNM_BTM_REQUEST: u8 = 7;

/// 802.11v BSS Transition Management Request (CCMP-protected). `disassoc_imminent`
/// sets the WNM disassociation-imminent bit (steer / kick a STA).
#[allow(clippy::too_many_arguments)]
pub fn build_protected_btm_request(bssid: &[u8; 6], sta: &[u8; 6], dialog: u8, disassoc_imminent: bool, disassoc_timer: u16, sc: u16, pn: u64, tk: &[u8]) -> Vec<u8> {
    let mode = if disassoc_imminent { 0x04 } else { 0x00 };
    let mut body = vec![ACTION_CATEGORY_WNM, WNM_BTM_REQUEST, dialog, mode];
    body.extend_from_slice(&disassoc_timer.to_le_bytes());
    body.push(0x00); // Validity Interval
    build_ccmp_mgmt(SUBTYPE_ACTION, sta, bssid, bssid, sc, pn, 0, tk, &body)
}

/// An 802.11k Neighbor Report element (ID 52).
pub fn neighbor_report_element(bssid: &[u8; 6], op_class: u8, channel: u8) -> Vec<u8> {
    let mut info = bssid.to_vec();
    info.extend_from_slice(&0u32.to_le_bytes()); // BSSID Info
    info.push(op_class);
    info.push(channel);
    info.push(0x09); // PHY type: HT
    ie(52, &info)
}

/// 802.11k Neighbor Report Response action frame (CCMP-protected).
#[allow(clippy::too_many_arguments)]
pub fn build_protected_neighbor_report(bssid: &[u8; 6], sta: &[u8; 6], dialog: u8, neighbors: &[u8], sc: u16, pn: u64, tk: &[u8]) -> Vec<u8> {
    let mut body = vec![ACTION_CATEGORY_RADIO_MEAS, RADIO_MEAS_NEIGHBOR_REPORT_RESP, dialog];
    body.extend_from_slice(neighbors);
    build_ccmp_mgmt(SUBTYPE_ACTION, sta, bssid, bssid, sc, pn, 0, tk, &body)
}

/// Build a CCMP-protected SA Query Action frame (request or response).
#[allow(clippy::too_many_arguments)]
pub fn build_protected_sa_query(bssid: &[u8; 6], peer: &[u8; 6], to_ds: bool, response: bool, trans_id: u16, sc: u16, pn: u64, tk: &[u8]) -> Vec<u8> {
    let action = if response { SA_QUERY_RESPONSE } else { SA_QUERY_REQUEST };
    let mut body = vec![ACTION_CATEGORY_SA_QUERY, action];
    body.extend_from_slice(&trans_id.to_le_bytes());
    let (a1, a2, a3) = if to_ds { (*bssid, *peer, *bssid) } else { (*peer, *bssid, *bssid) };
    // protected bit + (for STA->AP) to-DS
    let mut frame = build_ccmp_mgmt(SUBTYPE_ACTION, &a1, &a2, &a3, sc, pn, 0, tk, &body);
    if to_ds {
        frame[1] |= FC_TODS;
    }
    frame
}

/// An Association Response carrying status 30 (rejected temporarily) plus an
/// Association Comeback Time (Timeout Interval element, type 3) — the PMF
/// response to a (re)association request from an already-associated STA.
pub fn build_assoc_resp_comeback(bssid: &[u8; 6], sta: &[u8; 6], comeback_ms: u32, sc: u16) -> Vec<u8> {
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

/// Parse a management frame body as `(reason)` for Deauth/Disassoc, or an SA
/// Query `(category, action, trans_id)` for Action frames.
pub fn parse_deauth_reason(body: &[u8]) -> Option<u16> {
    if body.len() >= 2 {
        Some(u16::from_le_bytes([body[0], body[1]]))
    } else {
        None
    }
}

pub fn parse_sa_query(body: &[u8]) -> Option<(u8, u16)> {
    if body.len() >= 4 && body[0] == ACTION_CATEGORY_SA_QUERY {
        Some((body[1], u16::from_le_bytes([body[2], body[3]])))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

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

/// A parsed 802.11 frame: header fields plus the body (everything after the
/// MAC header, QoS control consumed if present).
#[derive(Debug, Clone)]
pub struct Dot11 {
    pub fc0: u8,
    pub fc1: u8,
    pub addr1: [u8; 6],
    pub addr2: [u8; 6],
    pub addr3: [u8; 6],
    pub sc: u16,
    pub qos: Option<u16>,
    pub body: Vec<u8>,
}

impl Dot11 {
    pub fn frame_type(&self) -> u8 {
        (self.fc0 >> 2) & 0x3
    }
    pub fn subtype(&self) -> u8 {
        (self.fc0 >> 4) & 0xF
    }
    pub fn to_ds(&self) -> bool {
        self.fc1 & FC_TODS != 0
    }
    pub fn from_ds(&self) -> bool {
        self.fc1 & FC_FROMDS != 0
    }
    pub fn protected(&self) -> bool {
        self.fc1 & FC_PROTECTED != 0
    }

    /// Parse an 802.11 frame (no radiotap).
    pub fn parse(buf: &[u8]) -> Option<Dot11> {
        if buf.len() < 24 {
            return None;
        }
        let fc0 = buf[0];
        let fc1 = buf[1];
        let frame_type = (fc0 >> 2) & 0x3;
        let subtype = (fc0 >> 4) & 0xF;
        let mut a1 = [0u8; 6];
        let mut a2 = [0u8; 6];
        let mut a3 = [0u8; 6];
        a1.copy_from_slice(&buf[4..10]);
        a2.copy_from_slice(&buf[10..16]);
        a3.copy_from_slice(&buf[16..22]);
        let sc = u16::from_le_bytes([buf[22], buf[23]]);

        let mut off = 24;
        // 4th address only present for WDS (to-DS and from-DS both set)
        if fc1 & FC_TODS != 0 && fc1 & FC_FROMDS != 0 {
            off += 6;
        }
        // QoS control for QoS data subtypes (subtype bit 0x08 of a data frame)
        let mut qos = None;
        if frame_type == TYPE_DATA && subtype & 0x08 != 0 {
            if buf.len() < off + 2 {
                return None;
            }
            qos = Some(u16::from_le_bytes([buf[off], buf[off + 1]]));
            off += 2;
        }
        if buf.len() < off {
            return None;
        }
        Some(Dot11 {
            fc0,
            fc1,
            addr1: a1,
            addr2: a2,
            addr3: a3,
            sc,
            qos,
            body: buf[off..].to_vec(),
        })
    }

    /// QoS priority/TID (`dot11_get_priority`): 0 when not a QoS frame.
    pub fn priority(&self) -> u16 {
        self.qos.map(|q| q & 0x000F).unwrap_or(0)
    }

    /// `true` if this is an EAPOL frame (LLC/SNAP with ethertype 0x888E).
    pub fn is_eapol(&self) -> bool {
        self.body.len() >= 8 && self.body[0] == 0xAA && self.body[1] == 0xAA && self.body[6..8] == ETHERTYPE_EAPOL.to_be_bytes()
    }

    /// The whole EAPOL frame (4-byte EAPOL header + body, after LLC/SNAP). This
    /// is what the MIC is computed over.
    pub fn eapol_frame(&self) -> Option<&[u8]> {
        if self.is_eapol() {
            Some(&self.body[8..])
        } else {
            None
        }
    }

    /// The EAPOL-Key body, after the 4-byte EAPOL header (== `EAPOL.payload.load`).
    pub fn eapol_key_body(&self) -> Option<&[u8]> {
        if self.is_eapol() && self.body.len() >= 12 {
            Some(&self.body[12..])
        } else {
            None
        }
    }

    /// Reconstruct the integer PN from a CCMP-protected data frame body.
    pub fn ccmp_pn(&self) -> Option<u64> {
        if self.body.len() < 8 {
            return None;
        }
        let b = &self.body;
        // PN0 PN1 _ _ PN2 PN3 PN4 PN5
        let pn = (b[0] as u64)
            | ((b[1] as u64) << 8)
            | ((b[7] as u64) << 16)
            | ((b[6] as u64) << 24)
            | ((b[5] as u64) << 32)
            | ((b[4] as u64) << 40);
        Some(pn)
    }

    /// CCMP key id (bits 6-7 of the flags byte).
    pub fn ccmp_key_id(&self) -> u8 {
        if self.body.len() < 4 {
            0
        } else {
            (self.body[3] >> 6) & 0x3
        }
    }

    /// The CCMP data (ciphertext + 8-byte tag), after the 8-byte CCMP header.
    pub fn ccmp_data(&self) -> Option<&[u8]> {
        if self.body.len() < 8 {
            None
        } else {
            Some(&self.body[8..])
        }
    }
}

/// Find the SSID (element id 0) in a management-frame IE list.
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

/// A minimal parsed EAPOL-Key body (the fields the AP needs from message 2).
#[derive(Debug, Clone)]
pub struct EapolKey {
    pub key_info: u16,
    pub key_replay_counter: u64,
    pub key_nonce: [u8; 32],
    pub key_mic: [u8; 16],
    pub key_data: Vec<u8>,
    /// Offset of the 16-byte MIC field within the raw body (for MIC re-check).
    pub mic_offset: usize,
}

impl EapolKey {
    /// Key Information flag accessors (see `KeyInfo::to_u16`).
    pub fn is_pairwise(&self) -> bool {
        (self.key_info >> 3) & 1 != 0
    }
    pub fn key_ack(&self) -> bool {
        (self.key_info >> 7) & 1 != 0
    }
    pub fn encrypted_key_data(&self) -> bool {
        (self.key_info >> 12) & 1 != 0
    }

    /// Parse an EAPOL-Key body (everything after the 4-byte EAPOL header).
    pub fn parse(body: &[u8]) -> Option<EapolKey> {
        // 1 + 2 + 2 + 8 + 32 + 16 + 8 + 8 + 16 + 2 = 95 bytes minimum
        if body.len() < 95 {
            return None;
        }
        let key_info = u16::from_be_bytes([body[1], body[2]]);
        let key_replay_counter = u64::from_be_bytes(body[5..13].try_into().ok()?);
        let mut key_nonce = [0u8; 32];
        key_nonce.copy_from_slice(&body[13..45]);
        let mic_offset = 77;
        let mut key_mic = [0u8; 16];
        key_mic.copy_from_slice(&body[mic_offset..mic_offset + 16]);
        let key_data_len = u16::from_be_bytes([body[93], body[94]]) as usize;
        let key_data = if body.len() >= 95 + key_data_len {
            body[95..95 + key_data_len].to_vec()
        } else {
            body[95..].to_vec()
        };
        Some(EapolKey {
            key_info,
            key_replay_counter,
            key_nonce,
            key_mic,
            key_data,
            mic_offset,
        })
    }
}
