use super::model::{Band, KeyMgmt};
use crate::structures::DataCipher;
use serde_json::Value;

pub fn parse_country(s: &str) -> Result<[u8; 2], String> {
    let b = s.as_bytes();
    if b.len() != 2 || !b[0].is_ascii_alphabetic() || !b[1].is_ascii_alphabetic() {
        return Err(format!("country must be a 2-letter code, got {s:?}"));
    }
    Ok([b[0].to_ascii_uppercase(), b[1].to_ascii_uppercase()])
}

pub(super) fn parse_band(key: &str, val: &Value) -> Result<Band, String> {
    if let Some(n) = val.as_f64() {
        if (n - 2.4).abs() < f64::EPSILON {
            return Ok(Band::Ghz2_4);
        }
        if n == 5.0 {
            return Ok(Band::Ghz5);
        }
        if n == 6.0 {
            return Ok(Band::Ghz6);
        }
    }
    if let Some(s) = val.as_str() {
        return parse_band_str(s).map_err(|_| format!("{key} must be 2.4, 5, or 6"));
    }
    Err(format!("{key} must be 2.4, 5, or 6"))
}

pub(super) fn validate_band_channel(band: Band, channel: u8, label: &str) -> Result<(), String> {
    match band {
        Band::Ghz2_4 if !(1..=14).contains(&channel) => Err(format!(
            "{label}: channel {channel} is not in the 2.4 GHz band"
        )),
        Band::Ghz5 if channel <= 14 => Err(format!(
            "{label}: channel {channel} is not in the 5 GHz band"
        )),
        Band::Ghz6 if channel == 0 || channel > 233 || channel % 4 != 1 => Err(format!(
            "{label}: channel {channel} is not a 6 GHz primary channel"
        )),
        _ => Ok(()),
    }
}

pub fn parse_band_str(s: &str) -> Result<Band, String> {
    match s.to_ascii_lowercase().replace(' ', "").as_str() {
        "2.4" | "2.4g" | "2.4ghz" => Ok(Band::Ghz2_4),
        "5" | "5g" | "5ghz" => Ok(Band::Ghz5),
        "6" | "6g" | "6ghz" => Ok(Band::Ghz6),
        _ => Err(format!("band must be 2.4, 5, or 6 (got {s:?})")),
    }
}

pub fn parse_phy(s: &str) -> Result<crate::frames::PhyMode, String> {
    use crate::frames::PhyMode;
    match s.to_ascii_lowercase().as_str() {
        "n" | "ht" => Ok(PhyMode::Ht),
        "ac" | "vht" => Ok(PhyMode::Vht),
        "ax" | "he" => Ok(PhyMode::He),
        "be" | "eht" => Ok(PhyMode::Eht),
        other => Err(format!("phy must be one of n/ac/ax/be (got {other:?})")),
    }
}

pub(super) fn parse_key_mgmt(s: &str) -> Result<KeyMgmt, String> {
    match s.to_ascii_lowercase().replace(['_', ' '], "-").as_str() {
        "psk" | "wpa-psk" | "wpa2" | "wpa2-psk" => Ok(KeyMgmt::Psk),
        "psk-sha256" | "wpa-psk-sha256" | "wpa2-psk-sha256" => Ok(KeyMgmt::PskSha256),
        "sae" | "wpa3" | "wpa3-sae" => Ok(KeyMgmt::Sae),
        "sae-transition" | "transition" | "wpa2-wpa3" | "wpa2+wpa3" => Ok(KeyMgmt::SaeTransition),
        "owe" => Ok(KeyMgmt::Owe),
        _ => Err(format!(
            "unknown key_mgmt {s:?} (psk|psk-sha256|sae|sae-transition|owe)"
        )),
    }
}

pub fn parse_data_cipher(s: &str) -> Result<DataCipher, String> {
    match s.to_ascii_lowercase().replace('_', "-").as_str() {
        "ccmp" | "ccmp-128" | "aes-ccmp" | "aes-ccmp-128" => Ok(DataCipher::Ccmp128),
        "gcmp" | "gcmp-128" | "aes-gcmp" | "aes-gcmp-128" => Ok(DataCipher::Gcmp128),
        "ccmp-256" | "aes-ccmp-256" | "aes256-ccmp" => Ok(DataCipher::Ccmp256),
        "gcmp-256" | "aes-gcmp-256" | "aes256-gcmp" => Ok(DataCipher::Gcmp256),
        _ => Err(format!(
            "unknown pairwise cipher {s:?} (ccmp-128|gcmp-128|ccmp-256|gcmp-256)"
        )),
    }
}

/// Parse a dotted-quad IPv4 address.
pub fn parse_ip(s: &str) -> Result<[u8; 4], String> {
    let mut out = [0u8; 4];
    let mut n = 0;
    for part in s.split('.') {
        if n >= 4 {
            return Err(format!("invalid IPv4 address {s:?}"));
        }
        out[n] = part
            .parse()
            .map_err(|_| format!("invalid IPv4 octet {part:?} in {s:?}"))?;
        n += 1;
    }
    if n != 4 {
        return Err(format!("invalid IPv4 address {s:?}"));
    }
    Ok(out)
}

pub(super) fn as_str<'a>(key: &str, val: &'a Value) -> Result<&'a str, String> {
    val.as_str()
        .ok_or_else(|| format!("{key} must be a string"))
}

pub(super) fn as_bool(key: &str, val: &Value) -> Result<bool, String> {
    val.as_bool()
        .ok_or_else(|| format!("{key} must be a boolean"))
}

pub(super) fn as_u8(key: &str, val: &Value) -> Result<u8, String> {
    let n = val
        .as_u64()
        .ok_or_else(|| format!("{key} must be a non-negative integer"))?;
    u8::try_from(n).map_err(|_| format!("{key} must be 0..=255"))
}
