//! Declarative AP configuration.
//!
//! Settings (SSID, passphrase, key management, channel, feature toggles such as
//! `per_sta_vif`, …) come from a JSON config file rather than being scattered
//! across ad-hoc CLI flags. [`Config::from_json`] parses a file; [`Config::build_ap`]
//! turns the configuration into a fully wired [`Ap`].
//!
//! Example config:
//! ```json
//! {
//!   "ssid": "turtlenet",
//!   "passphrase": "password1234",
//!   "key_mgmt": "sae",
//!   "channel": 36,
//!   "interface": "wlan0",
//!   "mode": "netlink",
//!   "per_sta_vif": true
//! }
//! ```

use crate::ap::Ap;
use crate::util::mac_to_bytes;
use serde_json::Value;

/// How stations authenticate to the AP.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyMgmt {
    /// WPA2-Personal (PSK).
    Psk,
    /// WPA3-Personal (SAE).
    Sae,
    /// WPA3-SAE with a WPA2-PSK fallback (transition mode).
    SaeTransition,
    /// Opportunistic Wireless Encryption (OWE).
    Owe,
}

/// Fully-resolved AP configuration.
#[derive(Clone, Debug)]
pub struct Config {
    pub ssid: String,
    pub passphrase: String,
    pub key_mgmt: KeyMgmt,
    /// 2-letter regulatory country code for the beacon Country IE. The actual
    /// channel regulatory domain is left to the system (e.g. `iw reg set`).
    pub country: [u8; 2],
    pub mac: [u8; 6],
    pub channel: u8,
    pub ip: [u8; 4],
    /// Transport: `stdio`, `iface` (raw monitor) or `netlink` (kernel offload).
    pub mode: String,
    pub iface: String,
    /// Operating Channel Validation (OCV) in the 4-way handshake.
    pub ocv: bool,
    /// 802.11v BSS Transition Management.
    pub btm: bool,
    /// Advertise a co-located 6 GHz AP via a Reduced Neighbor Report.
    pub rnr: bool,
    /// Operate on 6 GHz (HE-only; forces WPA3).
    pub band6: bool,
    /// Per-station VIF: each station gets its own AP_VLAN + GTK (netlink mode).
    pub per_sta_vif: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            ssid: "turtlenet".to_string(),
            passphrase: "password1234".to_string(),
            key_mgmt: KeyMgmt::Psk,
            country: *b"US",
            mac: mac_to_bytes("02:00:00:00:00:00"),
            channel: 1,
            ip: [10, 10, 10, 1],
            mode: "stdio".to_string(),
            iface: "wlan0".to_string(),
            ocv: false,
            btm: false,
            rnr: false,
            band6: false,
            per_sta_vif: false,
        }
    }
}

impl Config {
    /// Parse a JSON config document, starting from the defaults and overriding
    /// each present key. Unknown keys and type mismatches are hard errors so a
    /// typo never silently leaves the AP misconfigured.
    pub fn from_json(text: &str) -> Result<Config, String> {
        let value: Value = serde_json::from_str(text).map_err(|e| format!("invalid JSON: {e}"))?;
        let obj = value.as_object().ok_or("config must be a JSON object")?;
        let mut cfg = Config::default();
        for (key, val) in obj {
            cfg.set(key, val)?;
        }
        Ok(cfg)
    }

    /// Apply a single `key`/`value` setting. Used by the file parser and by the
    /// CLI-override path.
    pub fn set(&mut self, key: &str, val: &Value) -> Result<(), String> {
        match key {
            "ssid" => self.ssid = as_str(key, val)?.to_string(),
            "passphrase" | "wpa_passphrase" | "sae_password" | "psk" => {
                self.passphrase = as_str(key, val)?.to_string()
            }
            "key_mgmt" | "security" => self.key_mgmt = parse_key_mgmt(as_str(key, val)?)?,
            "country" | "country_code" => self.country = parse_country(as_str(key, val)?)?,
            "channel" => self.channel = as_u8(key, val)?,
            "interface" | "iface" => self.iface = as_str(key, val)?.to_string(),
            "mode" => self.mode = as_str(key, val)?.to_string(),
            "mac" | "bssid" => self.mac = mac_to_bytes(as_str(key, val)?),
            "ip" => self.ip = parse_ip(as_str(key, val)?)?,
            "ocv" => self.ocv = as_bool(key, val)?,
            "btm" => self.btm = as_bool(key, val)?,
            "rnr" => self.rnr = as_bool(key, val)?,
            "band6" => self.band6 = as_bool(key, val)?,
            "per_sta_vif" => self.per_sta_vif = as_bool(key, val)?,
            _ => return Err(format!("unknown config key {key:?}")),
        }
        Ok(())
    }

    /// Construct and fully configure an [`Ap`] from this configuration.
    pub fn build_ap(&self) -> Ap {
        let mut ap = Ap::new(&self.ssid, &self.passphrase, self.mac, self.channel);
        ap.set_country(self.country);
        match self.key_mgmt {
            KeyMgmt::Psk => {}
            KeyMgmt::Sae => ap.enable_sae(),
            KeyMgmt::SaeTransition => {
                ap.enable_sae();
                ap.enable_transition();
            }
            KeyMgmt::Owe => ap.enable_owe(),
        }
        if self.ocv {
            ap.enable_ocv();
        }
        if self.btm {
            ap.enable_btm();
        }
        if self.rnr {
            ap.enable_rnr_6ghz(37);
        }
        if self.band6 {
            ap.enable_band6();
            ap.enable_sae(); // 6 GHz mandates WPA3
        }
        if self.per_sta_vif {
            ap.enable_per_sta_vif();
        }
        ap
    }
}

fn parse_country(s: &str) -> Result<[u8; 2], String> {
    let b = s.as_bytes();
    if b.len() != 2 || !b[0].is_ascii_alphabetic() || !b[1].is_ascii_alphabetic() {
        return Err(format!("country must be a 2-letter code, got {s:?}"));
    }
    Ok([b[0].to_ascii_uppercase(), b[1].to_ascii_uppercase()])
}

fn parse_key_mgmt(s: &str) -> Result<KeyMgmt, String> {
    match s.to_ascii_lowercase().replace(['_', ' '], "-").as_str() {
        "psk" | "wpa-psk" | "wpa2" | "wpa2-psk" => Ok(KeyMgmt::Psk),
        "sae" | "wpa3" | "wpa3-sae" => Ok(KeyMgmt::Sae),
        "sae-transition" | "transition" | "wpa2-wpa3" | "wpa2+wpa3" => Ok(KeyMgmt::SaeTransition),
        "owe" => Ok(KeyMgmt::Owe),
        _ => Err(format!("unknown key_mgmt {s:?} (psk|sae|sae-transition|owe)")),
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
        out[n] = part.parse().map_err(|_| format!("invalid IPv4 octet {part:?} in {s:?}"))?;
        n += 1;
    }
    if n != 4 {
        return Err(format!("invalid IPv4 address {s:?}"));
    }
    Ok(out)
}

fn as_str<'a>(key: &str, val: &'a Value) -> Result<&'a str, String> {
    val.as_str().ok_or_else(|| format!("{key} must be a string"))
}

fn as_bool(key: &str, val: &Value) -> Result<bool, String> {
    val.as_bool().ok_or_else(|| format!("{key} must be a boolean"))
}

fn as_u8(key: &str, val: &Value) -> Result<u8, String> {
    let n = val.as_u64().ok_or_else(|| format!("{key} must be a non-negative integer"))?;
    u8::try_from(n).map_err(|_| format!("{key} must be 0..=255"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_wpa2_psk() {
        let c = Config::default();
        assert_eq!(c.key_mgmt, KeyMgmt::Psk);
        assert_eq!(c.ssid, "turtlenet");
        assert!(!c.per_sta_vif);
    }

    #[test]
    fn parses_a_full_json_config() {
        let json = r#"{
            "ssid": "lab",
            "passphrase": "hunter2hunter2",
            "key_mgmt": "sae",
            "channel": 36,
            "interface": "wlan3",
            "mode": "netlink",
            "mac": "02:aa:bb:cc:dd:ee",
            "ip": "192.168.5.1",
            "ocv": true,
            "per_sta_vif": true
        }"#;
        let c = Config::from_json(json).unwrap();
        assert_eq!(c.ssid, "lab");
        assert_eq!(c.passphrase, "hunter2hunter2");
        assert_eq!(c.key_mgmt, KeyMgmt::Sae);
        assert_eq!(c.channel, 36);
        assert_eq!(c.iface, "wlan3");
        assert_eq!(c.mode, "netlink");
        assert_eq!(c.mac, [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
        assert_eq!(c.ip, [192, 168, 5, 1]);
        assert!(c.ocv);
        assert!(c.per_sta_vif);
    }

    #[test]
    fn omitted_keys_keep_defaults() {
        let c = Config::from_json(r#"{"ssid": "only-ssid"}"#).unwrap();
        assert_eq!(c.ssid, "only-ssid");
        assert_eq!(c.channel, 1); // default preserved
        assert_eq!(c.key_mgmt, KeyMgmt::Psk);
    }

    #[test]
    fn unknown_key_is_rejected() {
        let err = Config::from_json(r#"{"ssidd": "typo"}"#).unwrap_err();
        assert!(err.contains("unknown config key"), "{err}");
    }

    #[test]
    fn type_mismatch_is_rejected() {
        // channel as a string, not a number
        assert!(Config::from_json(r#"{"channel": "36"}"#).is_err());
        // per_sta_vif as a number, not a bool
        assert!(Config::from_json(r#"{"per_sta_vif": 1}"#).is_err());
    }

    #[test]
    fn transition_enables_both() {
        let c = Config::from_json(r#"{"key_mgmt": "sae-transition"}"#).unwrap();
        assert_eq!(c.key_mgmt, KeyMgmt::SaeTransition);
    }

    #[test]
    fn malformed_json_is_an_error() {
        assert!(Config::from_json("not json").is_err());
        assert!(Config::from_json("[1,2,3]").is_err()); // not an object
    }

    #[test]
    fn bad_ip_is_rejected() {
        assert!(Config::from_json(r#"{"ip": "999.1.1"}"#).is_err());
    }

    #[test]
    fn country_defaults_and_parses() {
        assert_eq!(Config::default().country, *b"US");
        assert_eq!(Config::from_json(r#"{"country": "de"}"#).unwrap().country, *b"DE");
        assert_eq!(Config::from_json(r#"{"country_code": "JP"}"#).unwrap().country, *b"JP");
        assert!(Config::from_json(r#"{"country": "USA"}"#).is_err()); // not 2 letters
        assert!(Config::from_json(r#"{"country": "U1"}"#).is_err()); // not alphabetic
    }
}
