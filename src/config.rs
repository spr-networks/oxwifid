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
    /// Channel width in MHz: 20, 40, 80, 160 (5/6 GHz) or 320 (6 GHz / 11be).
    pub width: u16,
    /// PHY generation advertised on 2.4/5 GHz: `Vht` (ac), `He` (ax), `Eht` (be).
    /// 6 GHz is always HE+. Default `Vht`.
    pub phy: crate::dot11::PhyMode,
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
    /// WMM (Wi-Fi Multimedia / WME QoS): advertise the WMM parameter element and
    /// exchange QoS Data frames with stations that negotiate it. Default on.
    pub wmm: bool,
    /// Path for the runtime control socket (hostapd-style `ctrl_interface`).
    /// `None` disables it. netlink mode only.
    pub ctrl_path: Option<String>,
    /// Additional co-hosted BSSes (extra SSIDs) on the same radio. Each gets its
    /// own netdev/BSSID and 4-way. netlink mode only.
    pub bss: Vec<BssConfig>,
    /// GTK rekey period in seconds (hostapd `wpa_group_rekey`, default 600; 0
    /// disables periodic group rekeying).
    pub group_rekey: u64,
    /// Rekey the GTK when an authorized station leaves (hostapd
    /// `wpa_strict_rekey`, default on).
    pub strict_rekey: bool,
}

/// One additional BSS sharing the radio with the primary: its own SSID, BSSID,
/// and security, but the primary's channel/width/country/band.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BssConfig {
    pub ssid: String,
    pub passphrase: String,
    pub key_mgmt: KeyMgmt,
    pub mac: [u8; 6],
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
            width: 20,
            phy: crate::dot11::PhyMode::Vht,
            ip: [10, 10, 10, 1],
            mode: "stdio".to_string(),
            iface: "wlan0".to_string(),
            ocv: false,
            btm: false,
            rnr: false,
            band6: false,
            per_sta_vif: false,
            wmm: true,
            ctrl_path: None,
            bss: Vec::new(),
            group_rekey: 600,
            strict_rekey: true,
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
            "width" | "channel_width" => {
                let n = val.as_u64().ok_or_else(|| format!("{key} must be an integer"))?;
                self.width = u16::try_from(n).map_err(|_| format!("{key} out of range"))?;
            }
            "phy" | "phy_mode" | "ieee80211_mode" => self.phy = parse_phy(as_str(key, val)?)?,
            "interface" | "iface" => self.iface = as_str(key, val)?.to_string(),
            "mode" => self.mode = as_str(key, val)?.to_string(),
            "mac" | "bssid" => self.mac = mac_to_bytes(as_str(key, val)?),
            "ip" => self.ip = parse_ip(as_str(key, val)?)?,
            "ocv" => self.ocv = as_bool(key, val)?,
            "btm" => self.btm = as_bool(key, val)?,
            "rnr" => self.rnr = as_bool(key, val)?,
            "band6" => self.band6 = as_bool(key, val)?,
            "per_sta_vif" => self.per_sta_vif = as_bool(key, val)?,
            "wmm" | "wme" => self.wmm = as_bool(key, val)?,
            "ctrl_path" | "ctrl_interface" => self.ctrl_path = Some(as_str(key, val)?.to_string()),
            "wpa_group_rekey" | "group_rekey" => {
                self.group_rekey = val.as_u64().ok_or_else(|| format!("{key} must be an integer"))?;
            }
            "wpa_strict_rekey" | "strict_rekey" => self.strict_rekey = as_bool(key, val)?,
            "bss" => {
                let arr = val.as_array().ok_or_else(|| format!("{key} must be an array"))?;
                let (default_pass, default_km) = (self.passphrase.clone(), self.key_mgmt);
                for item in arr {
                    self.bss.push(parse_bss(item, &default_pass, default_km)?);
                }
            }
            _ => return Err(format!("unknown config key {key:?}")),
        }
        Ok(())
    }

    /// Validate the configuration for consistency before use. Catches the
    /// silent-misconfiguration footguns: a too-short/empty passphrase that would
    /// still derive a (weak) PMK, and security modes the chosen transport can't
    /// actually deliver.
    pub fn validate(&self) -> Result<(), String> {
        // WPA2-PSK / WPA3-SAE passphrases are 8..=63 characters; OWE has none.
        if self.key_mgmt != KeyMgmt::Owe {
            let n = self.passphrase.len();
            if !(8..=63).contains(&n) {
                return Err(format!("passphrase must be 8..=63 characters (got {n})"));
            }
        }
        // 6 GHz is Wi-Fi 6E/7 only and mandates WPA3 (SAE) or OWE — WPA2-PSK is
        // not permitted on 6 GHz in any mode.
        if self.band6 && self.key_mgmt == KeyMgmt::Psk {
            return Err("6 GHz mandates WPA3/SAE or OWE, not WPA2-PSK".to_string());
        }
        // Channel width.
        if !matches!(self.width, 20 | 40 | 80 | 160 | 320) {
            return Err(format!("width must be one of 20/40/80/160/320 MHz (got {})", self.width));
        }
        if self.width == 320 && !self.band6 {
            return Err("320 MHz is 6 GHz / 802.11be only (set band6)".to_string());
        }
        if self.width >= 80 && !self.band6 && !crate::dot11::is_5ghz(self.channel) {
            return Err("80/160 MHz require a 5 or 6 GHz channel".to_string());
        }
        // Additional BSSes need per-BSS netdevs, which only the netlink transport
        // creates.
        if !self.bss.is_empty() && self.mode != "netlink" {
            return Err("multiple BSSes (bss) require netlink mode".to_string());
        }
        // Additional BSSes: same passphrase rules, and each must have a BSSID
        // distinct from the primary and every other BSS (one radio, many MACs).
        let mut macs = vec![self.mac];
        for b in &self.bss {
            if b.key_mgmt != KeyMgmt::Owe && !(8..=63).contains(&b.passphrase.len()) {
                return Err(format!("bss {:?} passphrase must be 8..=63 characters", b.ssid));
            }
            if self.band6 && b.key_mgmt == KeyMgmt::Psk {
                return Err(format!("bss {:?}: 6 GHz mandates WPA3/SAE or OWE, not WPA2-PSK", b.ssid));
            }
            if macs.contains(&b.mac) {
                return Err(format!(
                    "bss {:?} BSSID {} duplicates another BSS on this radio",
                    b.ssid,
                    crate::util::bytes_to_mac(&b.mac)
                ));
            }
            macs.push(b.mac);
        }
        Ok(())
    }

    /// Construct and fully configure an [`Ap`] from this configuration.
    pub fn build_ap(&self) -> Ap {
        let mut ap = Ap::new(&self.ssid, &self.passphrase, self.mac, self.channel);
        ap.set_country(self.country);
        ap.set_width(self.width);
        ap.set_phy(self.phy);
        ap.set_wmm(self.wmm);
        ap.set_group_rekey(self.group_rekey);
        ap.set_strict_rekey(self.strict_rekey);
        apply_security(&mut ap, self.key_mgmt);
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

    /// Build an [`Ap`] for an additional BSS: the primary's radio parameters
    /// (channel, width, country, band) with the BSS's own SSID/BSSID/security.
    pub fn build_bss_ap(&self, bss: &BssConfig) -> Ap {
        let mut ap = Ap::new(&bss.ssid, &bss.passphrase, bss.mac, self.channel);
        ap.set_country(self.country);
        ap.set_width(self.width);
        ap.set_phy(self.phy);
        ap.set_wmm(self.wmm);
        ap.set_group_rekey(self.group_rekey);
        ap.set_strict_rekey(self.strict_rekey);
        apply_security(&mut ap, bss.key_mgmt);
        if self.band6 {
            ap.enable_band6();
            ap.enable_sae();
        }
        ap
    }
}

/// Apply a key-management mode to an AP (shared by the primary + extra BSSes).
fn apply_security(ap: &mut Ap, km: KeyMgmt) {
    match km {
        KeyMgmt::Psk => {}
        KeyMgmt::Sae => ap.enable_sae(),
        KeyMgmt::SaeTransition => {
            ap.enable_sae();
            ap.enable_transition();
        }
        KeyMgmt::Owe => ap.enable_owe(),
    }
}

/// Parse one `bss` array entry, inheriting the primary's passphrase + key_mgmt
/// when the entry omits them. SSID and a distinct BSSID are required.
fn parse_bss(item: &Value, default_pass: &str, default_km: KeyMgmt) -> Result<BssConfig, String> {
    let o = item.as_object().ok_or("each bss must be a JSON object")?;
    let mut b = BssConfig {
        ssid: String::new(),
        passphrase: default_pass.to_string(),
        key_mgmt: default_km,
        mac: [0u8; 6],
    };
    let mut have_mac = false;
    for (k, v) in o {
        match k.as_str() {
            "ssid" => b.ssid = as_str(k, v)?.to_string(),
            "passphrase" | "wpa_passphrase" | "sae_password" | "psk" => {
                b.passphrase = as_str(k, v)?.to_string()
            }
            "key_mgmt" | "security" => b.key_mgmt = parse_key_mgmt(as_str(k, v)?)?,
            "mac" | "bssid" => {
                b.mac = mac_to_bytes(as_str(k, v)?);
                have_mac = true;
            }
            _ => return Err(format!("unknown bss key {k:?}")),
        }
    }
    if b.ssid.is_empty() {
        return Err("each bss requires an ssid".to_string());
    }
    if !have_mac {
        return Err(format!("bss {:?} requires a mac/bssid", b.ssid));
    }
    Ok(b)
}

fn parse_country(s: &str) -> Result<[u8; 2], String> {
    let b = s.as_bytes();
    if b.len() != 2 || !b[0].is_ascii_alphabetic() || !b[1].is_ascii_alphabetic() {
        return Err(format!("country must be a 2-letter code, got {s:?}"));
    }
    Ok([b[0].to_ascii_uppercase(), b[1].to_ascii_uppercase()])
}

pub fn parse_phy(s: &str) -> Result<crate::dot11::PhyMode, String> {
    use crate::dot11::PhyMode;
    match s.to_ascii_lowercase().as_str() {
        "n" | "ht" => Ok(PhyMode::Ht),
        "ac" | "vht" => Ok(PhyMode::Vht),
        "ax" | "he" => Ok(PhyMode::He),
        "be" | "eht" => Ok(PhyMode::Eht),
        other => Err(format!("phy must be one of n/ac/ax/be (got {other:?})")),
    }
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
        assert!(c.bss.is_empty());
    }

    #[test]
    fn parses_multi_bss_config() {
        let json = r#"{
            "ssid": "main", "passphrase": "password1234", "mode": "netlink", "channel": 36,
            "bss": [
                { "ssid": "guest", "psk": "guestpass123", "mac": "02:00:00:00:00:10" },
                { "ssid": "iot", "key_mgmt": "sae", "passphrase": "iotpass12345", "bssid": "02:00:00:00:00:20" }
            ]
        }"#;
        let cfg = Config::from_json(json).expect("parses");
        cfg.validate().expect("valid");
        assert_eq!(cfg.bss.len(), 2);
        assert_eq!(cfg.bss[0].ssid, "guest");
        assert_eq!(cfg.bss[0].key_mgmt, KeyMgmt::Psk, "inherits primary default");
        assert_eq!(cfg.bss[1].key_mgmt, KeyMgmt::Sae);
        assert_eq!(cfg.bss[1].mac, mac_to_bytes("02:00:00:00:00:20"));
        // build_bss_ap inherits the primary radio params, keeps the BSS identity.
        let ap = cfg.build_bss_ap(&cfg.bss[0]);
        assert_eq!(ap.channel, 36);
        assert_eq!(ap.mac, mac_to_bytes("02:00:00:00:00:10"));
        assert_eq!(ap.ssid, b"guest");
    }

    #[test]
    fn rejects_duplicate_bssid() {
        let json = r#"{ "ssid": "main", "passphrase": "password1234", "mac": "02:00:00:00:00:10", "mode": "netlink",
            "bss": [ { "ssid": "guest", "psk": "guestpass123", "mac": "02:00:00:00:00:10" } ] }"#;
        let cfg = Config::from_json(json).expect("parses");
        assert!(cfg.validate().is_err(), "BSSID duplicating the primary must be rejected");
    }

    #[test]
    fn bss_requires_ssid_and_mac() {
        let no_mac = r#"{ "ssid": "main", "passphrase": "password1234",
            "bss": [ { "ssid": "guest", "psk": "guestpass123" } ] }"#;
        assert!(Config::from_json(no_mac).is_err(), "a BSS without a BSSID must be rejected");
        let no_ssid = r#"{ "ssid": "main", "passphrase": "password1234",
            "bss": [ { "mac": "02:00:00:00:00:10", "psk": "guestpass123" } ] }"#;
        assert!(Config::from_json(no_ssid).is_err(), "a BSS without an SSID must be rejected");
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
    fn validate_rejects_weak_passphrase_and_bad_transport() {
        let mut c = Config::default();
        assert!(c.validate().is_ok()); // default "password1234"
        c.passphrase = "short".to_string();
        assert!(c.validate().is_err()); // < 8
        c.passphrase = "".to_string();
        assert!(c.validate().is_err()); // empty
        c.passphrase = "password1234".to_string();
        c.mode = "netlink".to_string();
        c.key_mgmt = KeyMgmt::Sae;
        assert!(c.validate().is_ok()); // netlink now supports WPA3-SAE
        c.key_mgmt = KeyMgmt::Psk;
        assert!(c.validate().is_ok());
        // 6 GHz must not be WPA2-PSK
        c.band6 = true;
        assert!(c.validate().is_err());
        c.key_mgmt = KeyMgmt::Sae;
        assert!(c.validate().is_ok()); // 6 GHz + SAE is fine
        // OWE needs no passphrase
        let o = Config {
            key_mgmt: KeyMgmt::Owe,
            passphrase: String::new(),
            mode: "iface".to_string(),
            ..Config::default()
        };
        assert!(o.validate().is_ok());
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
