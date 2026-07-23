//! Authentication and key-handshake structures.

use crate::auth::crypto;

/// RSN pairwise data-protection suite.
///
/// The 128/256 suffix is the AES temporal-key size, not the PMK size (the PMK
/// remains 256 bits for WPA2-Personal and WPA3-Personal). Non-CCMP-128 suites
/// are currently used by the Linux nl80211 offload path, where mac80211 performs
/// the actual CCMP/GCMP authenticated encryption.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum DataCipher {
    #[default]
    Ccmp128,
    Gcmp128,
    Ccmp256,
    Gcmp256,
}

impl DataCipher {
    /// IEEE 802.11 RSN suite type under OUI 00-0F-AC.
    pub const fn suite_type(self) -> u8 {
        match self {
            DataCipher::Ccmp128 => 4,
            DataCipher::Gcmp128 => 8,
            DataCipher::Gcmp256 => 9,
            DataCipher::Ccmp256 => 10,
        }
    }

    /// Full nl80211 suite selector (00-0F-AC:type).
    pub const fn suite_selector(self) -> u32 {
        0x000f_ac00 | self.suite_type() as u32
    }

    /// Pairwise temporal-key length in octets.
    pub const fn key_len(self) -> usize {
        match self {
            DataCipher::Ccmp128 | DataCipher::Gcmp128 => 16,
            DataCipher::Ccmp256 | DataCipher::Gcmp256 => 32,
        }
    }

    pub const fn config_name(self) -> &'static str {
        match self {
            DataCipher::Ccmp128 => "ccmp-128",
            DataCipher::Gcmp128 => "gcmp-128",
            DataCipher::Ccmp256 => "ccmp-256",
            DataCipher::Gcmp256 => "gcmp-256",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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
    pub(crate) fn to_u16(self) -> u16 {
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

/// The EAPOL-Key MIC algorithm and descriptor version selected by the AKM.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyMic {
    /// WPA2-PSK (AKM 00-0F-AC:2): HMAC-SHA1-128, Key Descriptor Version 2.
    HmacSha1,
    /// WPA3-SAE (AKM 00-0F-AC:8): AES-128-CMAC, Key Descriptor Version 0.
    AesCmac,
    /// OWE (AKM 00-0F-AC:18): HMAC-SHA256-128, Key Descriptor Version 0.
    HmacSha256,
    /// PSK-SHA256 (AKM 00-0F-AC:6): AES-128-CMAC, Key Descriptor Version 3.
    AesCmacV3,
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

    pub(crate) fn version(self) -> u8 {
        match self {
            KeyMic::HmacSha1 => 2,
            KeyMic::AesCmacV3 => 3,
            _ => 0,
        }
    }

    /// Compute the EAPOL-Key MIC over `data` (with the MIC field zeroed).
    pub fn compute(self, kck: &[u8], data: &[u8]) -> [u8; 16] {
        let mut mic = [0u8; 16];
        match self {
            KeyMic::HmacSha1 => mic.copy_from_slice(&crypto::hmac_sha1(kck, data)[..16]),
            KeyMic::AesCmac | KeyMic::AesCmacV3 => {
                mic.copy_from_slice(&crypto::aes_cmac(kck, data))
            }
            KeyMic::HmacSha256 => mic.copy_from_slice(&crypto::hmac_sha256(kck, data)[..16]),
        }
        mic
    }
}

/// Parsed fields from an EAPOL-Key body.
#[derive(Debug, Clone)]
pub struct EapolKey {
    pub key_info: u16,
    pub key_length: u16,
    pub key_replay_counter: u64,
    pub key_nonce: [u8; 32],
    pub key_mic: [u8; 16],
    pub key_data: Vec<u8>,
    /// Offset of the 16-byte MIC field within the raw body (for MIC re-check).
    pub mic_offset: usize,
}

impl EapolKey {
    /// Key Information flag accessors (see `KeyInfo::to_u16`).
    pub fn descriptor_version(&self) -> u8 {
        (self.key_info & 0x0007) as u8
    }
    pub fn is_pairwise(&self) -> bool {
        (self.key_info >> 3) & 1 != 0
    }
    pub fn install(&self) -> bool {
        (self.key_info >> 6) & 1 != 0
    }
    pub fn key_ack(&self) -> bool {
        (self.key_info >> 7) & 1 != 0
    }
    pub fn has_key_mic(&self) -> bool {
        (self.key_info >> 8) & 1 != 0
    }
    pub fn secure(&self) -> bool {
        (self.key_info >> 9) & 1 != 0
    }
    pub fn error(&self) -> bool {
        (self.key_info >> 10) & 1 != 0
    }
    pub fn request(&self) -> bool {
        (self.key_info >> 11) & 1 != 0
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
        // RSN Key Descriptor, plus the legacy 254 workaround accepted by
        // reference AP. Other descriptor types must be dropped before they can be
        // misclassified as a wrong-password M2.
        if body[0] != 2 && body[0] != 254 {
            return None;
        }
        let key_info = u16::from_be_bytes([body[1], body[2]]);
        let key_length = u16::from_be_bytes([body[3], body[4]]);
        let key_replay_counter = u64::from_be_bytes(body[5..13].try_into().ok()?);
        let mut key_nonce = [0u8; 32];
        key_nonce.copy_from_slice(&body[13..45]);
        let mic_offset = 77;
        let mut key_mic = [0u8; 16];
        key_mic.copy_from_slice(&body[mic_offset..mic_offset + 16]);
        let key_data_len = u16::from_be_bytes([body[93], body[94]]) as usize;
        let end = 95usize.checked_add(key_data_len)?;
        if end != body.len() {
            return None;
        }
        let key_data = body[95..end].to_vec();
        Some(EapolKey {
            key_info,
            key_length,
            key_replay_counter,
            key_nonce,
            key_mic,
            key_data,
            mic_offset,
        })
    }
}
