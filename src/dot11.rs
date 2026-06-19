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
    let five = is_5ghz(channel);
    let freq = channel_to_freq(channel);
    // lowest basic rate for the band, in 500 kbps units: 2.4 GHz -> 1 Mbps CCK,
    // 5 GHz -> 6 Mbps OFDM.
    let (chan_flags, rate_500k) = if five {
        (CHAN_5GHZ | CHAN_OFDM, 12u8)
    } else {
        (CHAN_2GHZ | CHAN_CCK, 2u8)
    };

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
// Country triplets (US): first-channel, num-channels, max-tx-power(dBm)
const COUNTRY_2GHZ: [u8; 6] = [b'U', b'S', 0x20, 1, 11, 30];
const COUNTRY_5GHZ: [u8; 6] = [b'U', b'S', 0x20, 36, 4, 23];

/// Capability info as it appears on the wire for `cap=0x3101` (ESS + Privacy +
/// short-slot/short-preamble), used by every management body in `ap.py`.
pub const CAP_3101: [u8; 2] = [0x31, 0x01];

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

/// The IE block shared by beacons, probe & association responses, tailored to
/// the band of `channel`:
///   * 2.4 GHz: DSSS/CCK + OFDM rates, a DS Parameter Set, and an Extended
///     Supported Rates element.
///   * 5 GHz: OFDM-only rates and no DSSS Parameter Set (DSSS is 2.4 GHz only).
pub fn make_beacon_ies(ssid: &[u8], channel: u8) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&ie(0, ssid)); // SSID
    if is_5ghz(channel) {
        v.extend_from_slice(&ie(1, &RATES_5GHZ)); // Supported Rates (OFDM)
        v.extend_from_slice(&ie(7, &COUNTRY_5GHZ)); // Country
    } else {
        v.extend_from_slice(&ie(1, &RATES_2GHZ)); // Supported Rates
        v.extend_from_slice(&ie(3, &[channel])); // DS Parameter Set
        v.extend_from_slice(&ie(7, &COUNTRY_2GHZ)); // Country
        v.extend_from_slice(&ie(50, &EXT_RATES_2GHZ)); // Extended Supported Rates
    }
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

pub fn build_beacon(bssid: &[u8; 6], ssid: &[u8], channel: u8, timestamp: u64, tail_ies: &[u8]) -> Vec<u8> {
    let bcast = [0xffu8; 6];
    let mut v = dot11_header(TYPE_MGMT, SUBTYPE_BEACON, 0, &bcast, bssid, bssid, 0);
    v.extend_from_slice(&timestamp.to_le_bytes());
    v.extend_from_slice(&0x0064u16.to_le_bytes()); // beacon interval
    v.extend_from_slice(&CAP_3101);
    v.extend_from_slice(&make_beacon_ies(ssid, channel));
    v.extend_from_slice(tail_ies); // RSN (+ RSNXE for WPA3)
    v
}

pub fn build_probe_resp(bssid: &[u8; 6], dst: &[u8; 6], ssid: &[u8], channel: u8, timestamp: u64, sc: u16, tail_ies: &[u8]) -> Vec<u8> {
    let mut v = dot11_header(TYPE_MGMT, SUBTYPE_PROBE_RESP, 0, dst, bssid, bssid, sc);
    v.extend_from_slice(&timestamp.to_le_bytes());
    v.extend_from_slice(&0x0064u16.to_le_bytes());
    v.extend_from_slice(&CAP_3101);
    v.extend_from_slice(&make_beacon_ies(ssid, channel));
    v.extend_from_slice(tail_ies);
    v
}

/// The trailing security IEs (RSN, plus RSNXE for WPA3) advertised in beacons
/// and probe responses.
pub fn security_tail(sae: bool) -> Vec<u8> {
    let mut v = Vec::new();
    if sae {
        v.extend_from_slice(&RSN_WPA3);
        v.extend_from_slice(&RSNXE_H2E);
    } else {
        v.extend_from_slice(&RSN);
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

pub fn build_assoc_resp(bssid: &[u8; 6], dst: &[u8; 6], ssid: &[u8], channel: u8, aid: u16, sc: u16, resp_subtype: u8) -> Vec<u8> {
    let mut v = dot11_header(TYPE_MGMT, resp_subtype, 0, dst, bssid, bssid, sc);
    v.extend_from_slice(&CAP_3101);
    v.extend_from_slice(&0u16.to_le_bytes()); // status = success
    v.extend_from_slice(&aid.to_le_bytes());
    v.extend_from_slice(&make_beacon_ies(ssid, channel));
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
    v.extend_from_slice(&0x00c8u16.to_le_bytes()); // listen interval
    v.extend_from_slice(&ie(0, ssid));
    v.extend_from_slice(&ie(1, &[0x0c]));
    v.extend_from_slice(&RSN);
    v
}

/// EAPOL message 2 (STA -> AP): carries the SNONCE and the supplicant RSN, MIC'd
/// with the freshly derived KCK.
pub fn build_eapol_m2(bssid: &[u8; 6], sta: &[u8; 6], snonce: &[u8; 32], kck: &[u8], sc: u16, sha256: bool) -> Vec<u8> {
    let ki = KeyInfo {
        has_key_mic: true,
        key_type: true,
        key_descriptor_type_version: desc_version(sha256),
        ..Default::default()
    };
    let body0 = build_eapol_key_body(ki, 0, 1, snonce, &[0u8; 16], &RSN);
    let mic = eapol_mic(kck, &eapol_wrap(&body0), sha256);
    let body = build_eapol_key_body(ki, 0, 1, snonce, &mic, &RSN);
    let mut frame = eapol_data_header_tods(bssid, sta, sc);
    frame.extend_from_slice(&eapol_wrap(&body));
    frame
}

/// EAPOL message 4 (STA -> AP): the handshake ack, MIC'd with the KCK.
pub fn build_eapol_m4(bssid: &[u8; 6], sta: &[u8; 6], kck: &[u8], sc: u16, sha256: bool) -> Vec<u8> {
    let ki = KeyInfo {
        has_key_mic: true,
        key_type: true,
        key_descriptor_type_version: desc_version(sha256),
        ..Default::default()
    };
    let zero_nonce = [0u8; 32];
    let body0 = build_eapol_key_body(ki, 0, 2, &zero_nonce, &[0u8; 16], &[]);
    let mic = eapol_mic(kck, &eapol_wrap(&body0), sha256);
    let body = build_eapol_key_body(ki, 0, 2, &zero_nonce, &mic, &[]);
    let mut frame = eapol_data_header_tods(bssid, sta, sc);
    frame.extend_from_slice(&eapol_wrap(&body));
    frame
}

/// Key Descriptor Version: 0 for AKM-defined (SAE/SHA-256), 2 for WPA2 (SHA-1).
fn desc_version(sha256: bool) -> u8 {
    if sha256 {
        0
    } else {
        2
    }
}

/// Compute the EAPOL-Key MIC: HMAC-SHA256-128 for SHA-256 AKMs, HMAC-SHA1-128
/// for WPA2.
fn eapol_mic(kck: &[u8], data: &[u8], sha256: bool) -> [u8; 16] {
    let mut mic = [0u8; 16];
    if sha256 {
        mic.copy_from_slice(&crypto::hmac_sha256(kck, data)[..16]);
    } else {
        mic.copy_from_slice(&crypto::hmac_sha1(kck, data)[..16]);
    }
    mic
}

/// EAPOL message 1 of the 4-way handshake (AP -> STA, carries the ANONCE).
pub fn build_eapol_m1(bssid: &[u8; 6], sta: &[u8; 6], anonce: &[u8; 32], sc: u16, sha256: bool) -> Vec<u8> {
    let ki = KeyInfo {
        key_ack: true,
        key_type: true,
        key_descriptor_type_version: desc_version(sha256),
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

/// EAPOL message 3 (AP -> STA): installs the PTK and delivers the wrapped GTK
/// (and IGTK, when PMF is in use). `sha256` selects the SHA-256 key descriptor
/// (SAE/WPA3) vs SHA-1 (WPA2).
#[allow(clippy::too_many_arguments)]
pub fn build_eapol_m3(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    anonce: &[u8; 32],
    kck: &[u8],
    kek: &[u8],
    gtk: &[u8],
    igtk: Option<(u16, [u8; 6], [u8; 16])>,
    sc: u16,
    sha256: bool,
) -> Vec<u8> {
    let mut plain = Vec::new();
    plain.extend_from_slice(&RSN);
    plain.extend_from_slice(&gtk_kde(gtk));
    if let Some((key_id, ipn, ik)) = igtk {
        plain.extend_from_slice(&igtk_kde(key_id, &ipn, &ik));
    }
    let keydata = crypto::aes_wrap(kek, &crypto::pad_key_data(plain));

    let ki = KeyInfo {
        encrypted_key_data: true,
        secure: true,
        has_key_mic: true,
        key_ack: true,
        install: true,
        key_type: true,
        key_descriptor_type_version: desc_version(sha256),
    };

    // Build once with a zero MIC, compute the MIC over the EAPOL frame, rebuild.
    let body0 = build_eapol_key_body(ki, 16, 2, anonce, &[0u8; 16], &keydata);
    let mic = eapol_mic(kck, &eapol_wrap(&body0), sha256);

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
    aad.push(fc0 & 0x8F);
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
