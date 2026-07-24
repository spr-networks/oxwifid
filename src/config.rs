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
//!   "psk_file": "/run/secrets/wifi-credentials",
//!   "key_mgmt": "sae",
//!   "band": 5,
//!   "channel": 36,
//!   "interface": "wlan0",
//!   "mode": "netlink",
//!   "per_sta_vif": true
//! }
//! ```

use crate::ap::{Ap, MldLink};
use crate::structures::DataCipher;
use crate::util::{mac_to_bytes, try_mac_to_bytes};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

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

/// Explicit RF band used by the JSON configuration. Keeping this separate from
/// the channel number is required because 6 GHz reuses channel numbers that
/// also exist on lower bands.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Band {
    Ghz2_4,
    Ghz5,
    Ghz6,
}

impl Band {
    pub fn is_6ghz(self) -> bool {
        self == Band::Ghz6
    }

    pub fn as_f64(self) -> f64 {
        match self {
            Band::Ghz2_4 => 2.4,
            Band::Ghz5 => 5.0,
            Band::Ghz6 => 6.0,
        }
    }
}

/// Fully-resolved AP configuration.
#[derive(Clone, Debug)]
pub struct Config {
    pub ssid: String,
    pub passphrase: String,
    pub key_mgmt: KeyMgmt,
    /// RSN pairwise cipher. Group traffic remains CCMP-128.
    pub pairwise_cipher: DataCipher,
    /// 2-letter regulatory country code for the beacon Country IE. The actual
    /// channel regulatory domain is left to the system (e.g. `iw reg set`).
    pub country: [u8; 2],
    pub mac: [u8; 6],
    pub channel: u8,
    /// Channel width in MHz: 20, 40, 80, 160 (5/6 GHz) or 320 (6 GHz / 11be).
    pub width: u16,
    /// PHY generation advertised on 2.4/5 GHz: `Vht` (ac), `He` (ax), `Eht` (be).
    /// 6 GHz is always HE+. Default `Vht`.
    pub phy: crate::frames::PhyMode,
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
    /// RF band: 2.4, 5, or 6 GHz. 6 GHz forces WPA3.
    pub band: Band,
    /// Per-station VIF: each station gets its own AP_VLAN + GTK (netlink mode).
    pub per_sta_vif: bool,
    /// 802.11be preamble-puncturing bitmap (EHT Operation Disabled Subchannel
    /// Bitmap): one bit per 20 MHz subchannel, 1 = punctured. 0 = none.
    pub punct_bitmap: u16,
    /// 802.11be AP MLD: advertise a Basic Multi-Link element and run association
    /// + 4-way at the MLD level. Off by default.
    pub mld: bool,
    /// This affiliated link's Link ID (0-15).
    pub link_id: u8,
    /// Affiliated AP links for an MLD AP. Empty means the top-level
    /// mac/channel/link_id describes the only link.
    pub mld_links: Vec<MldLinkConfig>,
    /// Advertised TID-to-link mapping shared by all eight QoS TIDs, expressed
    /// as the configured MLD Link IDs that may carry traffic. This is the
    /// interoperable advertised-TTLM form supported by current mac80211 and
    /// reference AP; `None` leaves link selection to the peer/driver.
    pub mld_default_links: Option<Vec<u8>>,
    /// One authoritative credential file. RustAP accepts SPR's WPA form
    /// (`MAC passphrase`, all-zero wildcard) and SAE form
    /// (`passphrase|mac=MAC`, all-ones wildcard) so the same pending-device flow
    /// works without a JSON passphrase fallback.
    pub psk_file: Option<String>,
    /// WMM (Wi-Fi Multimedia / WME QoS): advertise the WMM parameter element and
    /// exchange QoS Data frames with stations that negotiate it. Default on.
    pub wmm: bool,
    /// Path for the runtime control socket (reference AP-style `ctrl_interface`).
    /// `None` disables it. netlink mode only.
    pub ctrl_path: Option<String>,
    /// SPR API Unix socket. When set, station events are delivered directly as
    /// HTTP PUT requests without spawning reference AP control client, an action script, or curl.
    pub spr_api_socket: Option<String>,
    /// SPR's reference implementation DHCP/XDP helper. When set alongside `spr_api_socket`, the
    /// event worker invokes `add|remove <AP_VLAN iface> <station MAC>` before
    /// reporting the corresponding event to the SPR API.
    pub spr_dhcp_helper: Option<String>,
    /// Additional co-hosted BSSes (extra SSIDs) on the same radio. Each gets its
    /// own netdev/BSSID and 4-way. netlink mode only.
    pub bss: Vec<BssConfig>,
    /// GTK rekey period in seconds (reference AP `wpa_group_rekey`, default 600; 0
    /// disables periodic group rekeying).
    pub group_rekey: u64,
    /// Rekey the GTK when an authorized station leaves (reference AP
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MldLinkConfig {
    pub link_id: u8,
    pub mac: [u8; 6],
    pub channel: u8,
    pub width: Option<u16>,
    /// Explicit RF band for this link. Channel numbers overlap between bands,
    /// so this cannot be inferred reliably from `channel` alone.
    pub band: Option<Band>,
}

impl Drop for Config {
    fn drop(&mut self) {
        self.passphrase.zeroize();
    }
}

impl Drop for BssConfig {
    fn drop(&mut self) {
        self.passphrase.zeroize();
    }
}

impl Default for Config {
    fn default() -> Config {
        Config {
            ssid: "turtlenet".to_string(),
            // No production credential default: PSK/SAE configurations must
            // supply `passphrase` or an authoritative `psk_file`.
            passphrase: String::new(),
            // Secure-by-default: WPA3-SAE implies mandatory PMF. Operators must
            // still supply a credential or authoritative psk_file.
            key_mgmt: KeyMgmt::Sae,
            pairwise_cipher: DataCipher::Ccmp128,
            country: *b"US",
            mac: mac_to_bytes("02:00:00:00:00:00"),
            channel: 1,
            width: 20,
            phy: crate::frames::PhyMode::Vht,
            ip: [10, 10, 10, 1],
            mode: "stdio".to_string(),
            iface: "wlan0".to_string(),
            ocv: true,
            btm: false,
            rnr: false,
            band: Band::Ghz2_4,
            per_sta_vif: false,
            punct_bitmap: 0,
            mld: false,
            link_id: 0,
            mld_links: Vec::new(),
            mld_default_links: None,
            psk_file: None,
            wmm: true,
            ctrl_path: None,
            spr_api_socket: None,
            // wifid installs this helper at the container root. It is only used
            // when `spr_api_socket` enables the SPR event worker.
            spr_dhcp_helper: Some("/spr_dhcp_helper".to_string()),
            bss: Vec::new(),
            group_rekey: 600,
            strict_rekey: true,
        }
    }
}

fn zeroize_json_credentials(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if matches!(
                    key.as_str(),
                    "passphrase" | "wpa_passphrase" | "sae_password" | "psk"
                ) {
                    if let Value::String(secret) = value {
                        secret.zeroize();
                    }
                }
                zeroize_json_credentials(value);
            }
        }
        Value::Array(values) => {
            for value in values {
                zeroize_json_credentials(value);
            }
        }
        _ => {}
    }
}

impl Config {
    /// Parse a JSON config document, starting from the defaults and overriding
    /// each present key. Unknown keys and type mismatches are hard errors so a
    /// typo never silently leaves the AP misconfigured.
    pub fn from_json(text: &str) -> Result<Config, String> {
        let mut value: Value =
            serde_json::from_str(text).map_err(|e| format!("invalid JSON: {e}"))?;
        let result = (|| {
            let obj = value.as_object().ok_or("config must be a JSON object")?;
            let mut cfg = Config::default();
            for (key, val) in obj {
                cfg.set(key, val)?;
            }
            Ok(cfg)
        })();
        zeroize_json_credentials(&mut value);
        result
    }

    /// Apply a single `key`/`value` setting. Used by the file parser and by the
    /// CLI-override path.
    pub fn set(&mut self, key: &str, val: &Value) -> Result<(), String> {
        match key {
            "ssid" => self.ssid = as_str(key, val)?.to_string(),
            "passphrase" | "wpa_passphrase" | "sae_password" | "psk" => {
                self.passphrase.zeroize();
                self.passphrase = as_str(key, val)?.to_string()
            }
            "key_mgmt" | "security" => self.key_mgmt = parse_key_mgmt(as_str(key, val)?)?,
            "pairwise_cipher" | "cipher" | "rsn_pairwise" => {
                self.pairwise_cipher = parse_data_cipher(as_str(key, val)?)?
            }
            "country" | "country_code" => self.country = parse_country(as_str(key, val)?)?,
            "channel" => self.channel = as_u8(key, val)?,
            "width" | "channel_width" => {
                let n = val
                    .as_u64()
                    .ok_or_else(|| format!("{key} must be an integer"))?;
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
            "band" => self.band = parse_band(key, val)?,
            "per_sta_vif" => self.per_sta_vif = as_bool(key, val)?,
            "punct_bitmap" | "ru_puncturing_bitmap" => {
                let n = val
                    .as_u64()
                    .ok_or_else(|| format!("{key} must be an integer"))?;
                self.punct_bitmap = u16::try_from(n).map_err(|_| format!("{key} out of range"))?;
            }
            "mld" | "mld_ap" => self.mld = as_bool(key, val)?,
            "mld_mac" | "mld_addr" => {
                // The AP MLD address must equal the interface's own MAC (the
                // kernel keys MLO on it); it is not independently configurable, so
                // reject it rather than silently ignoring the admin's value. Set
                // the interface address via `mac` instead.
                return Err("mld_mac is not separately configurable; the AP MLD address is the interface's own MAC (set it via `mac`)".to_string());
            }
            "link_id" | "mld_link_id" => self.link_id = as_u8(key, val)?,
            "mld_links" | "links" => {
                let arr = val
                    .as_array()
                    .ok_or_else(|| format!("{key} must be an array"))?;
                self.mld_links.clear();
                for item in arr {
                    self.mld_links.push(parse_mld_link(item, self.width)?);
                }
            }
            "mld_default_links" | "mld_tid_to_link" => {
                let arr = val
                    .as_array()
                    .ok_or_else(|| format!("{key} must be an array of MLD Link IDs"))?;
                let mut links = Vec::with_capacity(arr.len());
                for item in arr {
                    links.push(as_u8(key, item)?);
                }
                self.mld_default_links = Some(links);
            }
            "psk_file" => self.psk_file = Some(as_str(key, val)?.to_string()),
            "wmm" | "wme" => self.wmm = as_bool(key, val)?,
            "ctrl_path" | "ctrl_interface" => self.ctrl_path = Some(as_str(key, val)?.to_string()),
            "spr_api_socket" | "spr_socket" => {
                self.spr_api_socket = Some(as_str(key, val)?.to_string())
            }
            "spr_dhcp_helper" | "spr_helper" => {
                self.spr_dhcp_helper = if val.is_null() {
                    None
                } else {
                    Some(as_str(key, val)?.to_string())
                }
            }
            "wpa_group_rekey" | "group_rekey" => {
                self.group_rekey = val
                    .as_u64()
                    .ok_or_else(|| format!("{key} must be an integer"))?;
            }
            "wpa_strict_rekey" | "strict_rekey" => self.strict_rekey = as_bool(key, val)?,
            "bss" => {
                let arr = val
                    .as_array()
                    .ok_or_else(|| format!("{key} must be an array"))?;
                let default_pass = Zeroizing::new(self.passphrase.clone());
                let default_km = self.key_mgmt;
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
        if self.key_mgmt != KeyMgmt::Owe && !(self.passphrase.is_empty() && self.psk_file.is_some())
        {
            let n = self.passphrase.len();
            if !(8..=63).contains(&n) {
                return Err(format!(
                    "PSK/SAE requires passphrase (8..=63 characters) or psk_file (got {n})"
                ));
            }
        }
        // 6 GHz is Wi-Fi 6E/7 only and mandates WPA3 (SAE) or OWE — WPA2-PSK is
        // not permitted on 6 GHz in any mode.
        if self.band.is_6ghz() && self.key_mgmt == KeyMgmt::Psk {
            return Err("6 GHz mandates WPA3/SAE or OWE, not WPA2-PSK".to_string());
        }
        if self.pairwise_cipher != DataCipher::Ccmp128 && self.mld {
            return Err("non-default pairwise ciphers are not yet supported with MLO".to_string());
        }
        // Channel width.
        if !matches!(self.width, 20 | 40 | 80 | 160 | 320) {
            return Err(format!(
                "width must be one of 20/40/80/160/320 MHz (got {})",
                self.width
            ));
        }
        if self.width == 320 && !self.band.is_6ghz() {
            return Err("320 MHz is 6 GHz / 802.11be only (set band to 6)".to_string());
        }
        if self.width >= 80 && self.band == Band::Ghz2_4 {
            return Err("80/160 MHz require a 5 or 6 GHz channel".to_string());
        }
        validate_band_channel(self.band, self.channel, "primary")?;
        if !self.mld_links.is_empty() {
            if !self.mld {
                return Err("mld_links requires mld=true".to_string());
            }
            if self.mode != "netlink" {
                return Err("multi-link MLD AP requires netlink mode".to_string());
            }
            let mut ids = Vec::new();
            let mut macs = Vec::new();
            for link in &self.mld_links {
                if link.link_id > 15 {
                    return Err(format!("mld link_id {} out of range", link.link_id));
                }
                if ids.contains(&link.link_id) {
                    return Err(format!("duplicate mld link_id {}", link.link_id));
                }
                if macs.contains(&link.mac) {
                    return Err(format!(
                        "duplicate mld link MAC {}",
                        crate::util::bytes_to_mac(&link.mac)
                    ));
                }
                let width = link.width.unwrap_or(self.width);
                let band = link.band.unwrap_or(self.band);
                let band6 = band.is_6ghz();
                if !matches!(width, 20 | 40 | 80 | 160 | 320) {
                    return Err(format!(
                        "mld link {} width must be one of 20/40/80/160/320 MHz",
                        link.link_id
                    ));
                }
                if width == 320 && !band6 {
                    return Err(format!(
                        "mld link {}: 320 MHz is 6 GHz / 802.11be only (set band to 6)",
                        link.link_id
                    ));
                }
                if width >= 80 && band == Band::Ghz2_4 {
                    return Err(format!(
                        "mld link {}: 80/160 MHz require a 5 or 6 GHz channel",
                        link.link_id
                    ));
                }
                validate_band_channel(band, link.channel, &format!("mld link {}", link.link_id))?;
                ids.push(link.link_id);
                macs.push(link.mac);
            }
            if !ids.contains(&self.link_id) {
                return Err(format!(
                    "mld_links must include the association link_id {}",
                    self.link_id
                ));
            }
        }
        if let Some(default_links) = &self.mld_default_links {
            if !self.mld {
                return Err("mld_default_links requires mld=true".to_string());
            }
            if default_links.is_empty() {
                return Err("mld_default_links must contain at least one Link ID".to_string());
            }
            let configured_links: Vec<u8> = if self.mld_links.is_empty() {
                vec![self.link_id]
            } else {
                self.mld_links.iter().map(|link| link.link_id).collect()
            };
            let mut seen = Vec::new();
            for link_id in default_links {
                if *link_id > 15 {
                    return Err(format!("mld_default_links Link ID {link_id} out of range"));
                }
                if seen.contains(link_id) {
                    return Err(format!("duplicate Link ID {link_id} in mld_default_links"));
                }
                if !configured_links.contains(link_id) {
                    return Err(format!(
                        "mld_default_links Link ID {link_id} is not present in mld_links"
                    ));
                }
                seen.push(*link_id);
            }
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
                return Err(format!(
                    "bss {:?} passphrase must be 8..=63 characters",
                    b.ssid
                ));
            }
            if self.band.is_6ghz() && b.key_mgmt == KeyMgmt::Psk {
                return Err(format!(
                    "bss {:?}: 6 GHz mandates WPA3/SAE or OWE, not WPA2-PSK",
                    b.ssid
                ));
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

    /// The key-management mode the AP will actually advertise, after applying the
    /// PMF mandates of the chosen band/PHY.
    ///
    /// 802.11be (EHT, `--phy be`) **requires** Management Frame Protection: a
    /// spec-compliant client rejects an EHT BSS whose RSN element is not PMF-capable
    /// (`MFPC`)/required (`MFPR`) — it logs "skip RSN IE - no mgmt frame protection"
    /// and never associates. WPA2-PSK and SAE-transition advertise a non-MFPR RSN,
    /// so under EHT they are upgraded to WPA3-SAE (which advertises MFPR|MFPC + the
    /// BIP group-management cipher). This mirrors the existing 6 GHz rule, where
    /// `band: 6` likewise forces SAE because 6 GHz mandates WPA3. OWE is already
    /// PMF-protected and is left as-is.
    pub fn effective_key_mgmt(&self) -> KeyMgmt {
        if self.phy == crate::frames::PhyMode::Eht
            && matches!(self.key_mgmt, KeyMgmt::Psk | KeyMgmt::SaeTransition)
        {
            KeyMgmt::Sae
        } else {
            self.key_mgmt
        }
    }

    /// Construct and fully configure an [`Ap`] from this configuration.
    pub fn build_ap(&self) -> Ap {
        let mut ap = if self.passphrase.is_empty() {
            Ap::new_without_credential(&self.ssid, self.mac, self.channel)
        } else {
            Ap::new(&self.ssid, &self.passphrase, self.mac, self.channel)
        };
        ap.set_country(self.country);
        ap.set_width(self.width);
        ap.punct = self.punct_bitmap;
        if self.mld {
            ap.mld = true;
            // The kernel's AP-MLD address is the interface's own address (the
            // links get their own addresses via ADD_LINK). It must equal the MLD
            // MAC barely-ap advertises + uses for SAE/4-way crypto, otherwise the
            // kernel does not recognize (and silently drops) EAPOL the client
            // sends to the advertised MLD address. So the MLD MAC IS the primary
            // interface `mac`; the affiliated links use the `mld_links` BSSIDs.
            ap.mld_mac = self.mac;
            ap.link_id = self.link_id;
            let links = self.resolved_mld_links();
            // Anchor the management plane (auth/assoc/EAPOL) on the association
            // link's BSSID: the client authenticates to that link address, so the
            // AP's responses must originate from it (not the default `mac`). The
            // per-link beacons already use their own `link.mac`.
            if let Some(assoc) = links.iter().find(|l| l.link_id == self.link_id) {
                ap.mac = assoc.mac;
            }
            ap.set_mld_links(links);
            if let Some(default_links) = &self.mld_default_links {
                let mask = default_links
                    .iter()
                    .fold(0u16, |mask, link_id| mask | (1u16 << link_id));
                ap.set_mld_default_link_mask(mask);
            }
        }
        ap.set_phy(self.phy);
        ap.set_pairwise_cipher(self.pairwise_cipher);
        ap.set_wmm(self.wmm);
        ap.set_group_rekey(self.group_rekey);
        ap.set_strict_rekey(self.strict_rekey);
        apply_security(&mut ap, self.effective_key_mgmt());
        if self.ocv {
            ap.enable_ocv();
        }
        if self.btm {
            ap.enable_btm();
        }
        if self.rnr {
            ap.enable_rnr_6ghz(37);
        }
        if self.band.is_6ghz() {
            ap.enable_band6();
            ap.enable_sae(); // 6 GHz mandates WPA3
        }
        if self.per_sta_vif {
            ap.enable_per_sta_vif();
        }
        if let Some(path) = &self.psk_file {
            // A configured credential file is authoritative even when startup
            // cannot read it. Mark it active with an empty set first so an I/O
            // or parse error fails closed instead of enabling the test/default
            // JSON passphrase.
            ap.set_psk_file(&[]);
            match parse_psk_file(path) {
                Ok(mut entries) => {
                    ap.set_psk_file(&entries);
                    for (_, password) in &mut entries {
                        password.zeroize();
                    }
                }
                Err(e) => eprintln!("barely-ap: psk_file {path:?}: {e}"),
            }
        }
        ap
    }

    pub fn resolved_mld_links(&self) -> Vec<MldLink> {
        if self.mld_links.is_empty() {
            vec![MldLink {
                link_id: self.link_id,
                mac: self.mac,
                channel: self.channel,
                width: self.width,
                band6: self.band.is_6ghz(),
            }]
        } else {
            self.mld_links
                .iter()
                .map(|l| MldLink {
                    link_id: l.link_id,
                    mac: l.mac,
                    channel: l.channel,
                    width: l.width.unwrap_or(self.width),
                    band6: l.band.unwrap_or(self.band).is_6ghz(),
                })
                .collect()
        }
    }

    /// Build an [`Ap`] for an additional BSS: the primary's radio parameters
    /// (channel, width, country, band) with the BSS's own SSID/BSSID/security.
    pub fn build_bss_ap(&self, bss: &BssConfig) -> Ap {
        let mut ap = if bss.passphrase.is_empty() {
            Ap::new_without_credential(&bss.ssid, bss.mac, self.channel)
        } else {
            Ap::new(&bss.ssid, &bss.passphrase, bss.mac, self.channel)
        };
        ap.set_country(self.country);
        ap.set_width(self.width);
        ap.set_phy(self.phy);
        ap.set_pairwise_cipher(self.pairwise_cipher);
        ap.set_wmm(self.wmm);
        ap.set_group_rekey(self.group_rekey);
        ap.set_strict_rekey(self.strict_rekey);
        // EHT mandates PMF for every BSS on the radio, the same way `band: 6` does
        // below — upgrade a non-MFPR mode to SAE (see `effective_key_mgmt`).
        let km = if self.phy == crate::frames::PhyMode::Eht
            && matches!(bss.key_mgmt, KeyMgmt::Psk | KeyMgmt::SaeTransition)
        {
            KeyMgmt::Sae
        } else {
            bss.key_mgmt
        };
        apply_security(&mut ap, km);
        if self.ocv {
            ap.enable_ocv();
        }
        if self.band.is_6ghz() {
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
                b.passphrase.zeroize();
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

fn parse_mld_link(item: &Value, _default_width: u16) -> Result<MldLinkConfig, String> {
    let o = item
        .as_object()
        .ok_or("each mld link must be a JSON object")?;
    let mut link_id: Option<u8> = None;
    let mut mac: Option<[u8; 6]> = None;
    let mut channel: Option<u8> = None;
    let mut width: Option<u16> = None;
    let mut band: Option<Band> = None;
    for (k, v) in o {
        match k.as_str() {
            "link_id" | "mld_link_id" => link_id = Some(as_u8(k, v)?),
            "mac" | "bssid" | "link_mac" => mac = Some(mac_to_bytes(as_str(k, v)?)),
            "channel" => channel = Some(as_u8(k, v)?),
            "width" | "channel_width" => {
                let n = v
                    .as_u64()
                    .ok_or_else(|| format!("{k} must be an integer"))?;
                width = Some(u16::try_from(n).map_err(|_| format!("{k} out of range"))?);
            }
            "band" => band = Some(parse_band(k, v)?),
            _ => return Err(format!("unknown mld link key {k:?}")),
        }
    }
    Ok(MldLinkConfig {
        link_id: link_id.ok_or("mld link missing link_id")?,
        mac: mac.ok_or("mld link missing mac")?,
        channel: channel.ok_or("mld link missing channel")?,
        width,
        band,
    })
}

/// One credential-file entry: `(MAC filter, passphrase)`, `None` MAC = wildcard.
pub type PskEntry = (Option<[u8; 6]>, String);

struct PskEntryGuard(Vec<PskEntry>);

impl Drop for PskEntryGuard {
    fn drop(&mut self) {
        for (_, password) in &mut self.0 {
            password.zeroize();
        }
    }
}

/// Parse either credential format generated by SPR:
///
/// - WPA: `MAC passphrase` (`00:00:00:00:00:00` is wildcard)
/// - SAE: `passphrase|mac=MAC` (`ff:ff:ff:ff:ff:ff` is wildcard)
///
/// Both wildcard spellings are accepted in either form and returned as `None`.
pub fn parse_psk_file(path: &str) -> Result<Vec<PskEntry>, String> {
    let text = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| e.to_string())?);
    let mut out = PskEntryGuard(Vec::new());
    for (line_no, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (mac_tok, pass) = if line.contains("|mac=") {
            let mut fields = line.split('|');
            let pass = fields.next().unwrap_or("").trim();
            let mac = fields
                .find_map(|field| field.trim().strip_prefix("mac="))
                .ok_or_else(|| format!("line {}: SAE entry missing mac=", line_no + 1))?;
            (mac, pass)
        } else {
            match line.split_once(char::is_whitespace) {
                Some((mac, pass)) => (mac, pass.trim()),
                None => {
                    return Err(format!(
                        "line {}: expected 'MAC passphrase' or 'passphrase|mac=MAC'",
                        line_no + 1
                    ));
                }
            }
        };
        if pass.is_empty() {
            return Err(format!("line {}: empty passphrase", line_no + 1));
        }
        let mac = if mac_tok.eq_ignore_ascii_case("00:00:00:00:00:00")
            || mac_tok.eq_ignore_ascii_case("ff:ff:ff:ff:ff:ff")
        {
            None
        } else {
            Some(
                try_mac_to_bytes(mac_tok)
                    .ok_or_else(|| format!("line {}: invalid MAC {mac_tok:?}", line_no + 1))?,
            )
        };
        out.0.push((mac, pass.to_string()));
    }
    Ok(std::mem::take(&mut out.0))
}

pub fn parse_country(s: &str) -> Result<[u8; 2], String> {
    let b = s.as_bytes();
    if b.len() != 2 || !b[0].is_ascii_alphabetic() || !b[1].is_ascii_alphabetic() {
        return Err(format!("country must be a 2-letter code, got {s:?}"));
    }
    Ok([b[0].to_ascii_uppercase(), b[1].to_ascii_uppercase()])
}

fn parse_band(key: &str, val: &Value) -> Result<Band, String> {
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

fn validate_band_channel(band: Band, channel: u8, label: &str) -> Result<(), String> {
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

fn parse_key_mgmt(s: &str) -> Result<KeyMgmt, String> {
    match s.to_ascii_lowercase().replace(['_', ' '], "-").as_str() {
        "psk" | "wpa-psk" | "wpa2" | "wpa2-psk" => Ok(KeyMgmt::Psk),
        "sae" | "wpa3" | "wpa3-sae" => Ok(KeyMgmt::Sae),
        "sae-transition" | "transition" | "wpa2-wpa3" | "wpa2+wpa3" => Ok(KeyMgmt::SaeTransition),
        "owe" => Ok(KeyMgmt::Owe),
        _ => Err(format!(
            "unknown key_mgmt {s:?} (psk|sae|sae-transition|owe)"
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

fn as_str<'a>(key: &str, val: &'a Value) -> Result<&'a str, String> {
    val.as_str()
        .ok_or_else(|| format!("{key} must be a string"))
}

fn as_bool(key: &str, val: &Value) -> Result<bool, String> {
    val.as_bool()
        .ok_or_else(|| format!("{key} must be a boolean"))
}

fn as_u8(key: &str, val: &Value) -> Result<u8, String> {
    let n = val
        .as_u64()
        .ok_or_else(|| format!("{key} must be a non-negative integer"))?;
    u8::try_from(n).map_err(|_| format!("{key} must be 0..=255"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frames as dot11;

    #[test]
    fn defaults_are_wpa3_sae_with_ocv() {
        let c = Config::default();
        assert_eq!(c.key_mgmt, KeyMgmt::Sae);
        assert!(c.ocv);
        assert_eq!(c.ssid, "turtlenet");
        assert!(!c.per_sta_vif);
        assert!(c.bss.is_empty());
        assert!(c.mld_default_links.is_none());
    }

    #[test]
    fn mld_default_links_are_advertised_and_mark_other_links_disabled() {
        let cfg = Config::from_json(
            r#"{
                "ssid":"mld-ttlm", "passphrase":"password1234",
                "key_mgmt":"sae", "phy":"be", "mode":"netlink",
                "mld":true, "mac":"02:00:00:00:aa:00",
                "band":5, "channel":36, "width":80, "link_id":0,
                "mld_links":[
                    {"link_id":0,"mac":"02:00:00:00:aa:01","band":5,"channel":36,"width":80},
                    {"link_id":1,"mac":"02:00:00:00:aa:02","band":6,"channel":37,"width":160}
                ],
                "mld_default_links":[1]
            }"#,
        )
        .expect("TTLM config parses");
        cfg.validate().expect("TTLM config validates");
        assert_eq!(cfg.mld_default_links, Some(vec![1]));

        let links = cfg.resolved_mld_links();
        let ap = cfg.build_ap();
        let ttlm = dot11::tid_to_link_mapping_same_set(1 << 1);
        for link in &links {
            let beacon = ap.beacon_frame_unprotected_for_link(link);
            assert!(
                beacon.windows(ttlm.len()).any(|window| window == ttlm),
                "each affiliated-link beacon carries the advertised TTLM"
            );
        }

        let link1_beacon = ap.beacon_frame_unprotected_for_link(&links[1]);
        let rnr = dot11::find_ie(&link1_beacon[36..], 201).expect("partner RNR");
        assert_eq!(rnr[18] & 0x0f, 0, "RNR describes partner link 0");
        assert_ne!(rnr[19] & 0x20, 0, "link 0 is marked disabled");
    }

    #[test]
    fn mld_default_links_reject_invalid_link_sets() {
        let no_mld = Config::from_json(r#"{"passphrase":"password1234","mld_default_links":[0]}"#)
            .expect("config parses");
        assert_eq!(
            no_mld.validate().unwrap_err(),
            "mld_default_links requires mld=true"
        );

        let empty = Config::from_json(
            r#"{"passphrase":"password1234","mld":true,"mode":"netlink","mld_default_links":[]}"#,
        )
        .expect("config parses");
        assert_eq!(
            empty.validate().unwrap_err(),
            "mld_default_links must contain at least one Link ID"
        );

        let base = r#"{
            "ssid":"mld-ttlm", "passphrase":"password1234",
            "key_mgmt":"sae", "phy":"be", "mode":"netlink",
            "mld":true, "mac":"02:00:00:00:aa:00",
            "band":5, "channel":36, "width":80, "link_id":0,
            "mld_links":[
                {"link_id":0,"mac":"02:00:00:00:aa:01","band":5,"channel":36,"width":80},
                {"link_id":1,"mac":"02:00:00:00:aa:02","band":6,"channel":37,"width":160}
            ]
        }"#;
        let mut unknown = Config::from_json(base).expect("base config parses");
        unknown.mld_default_links = Some(vec![2]);
        assert_eq!(
            unknown.validate().unwrap_err(),
            "mld_default_links Link ID 2 is not present in mld_links"
        );

        let mut duplicate = Config::from_json(base).expect("base config parses");
        duplicate.mld_default_links = Some(vec![1, 1]);
        assert_eq!(
            duplicate.validate().unwrap_err(),
            "duplicate Link ID 1 in mld_default_links"
        );
    }

    #[test]
    fn cross_band_mld_config_produces_band_correct_per_link_beacons() {
        // MLD across 2.4 GHz (ch 1) + 5 GHz (ch 36) — the realistic deployment,
        // not two 2.4 GHz channels. Each link's beacon must carry band-correct
        // IEs: the 5 GHz link advertises VHT (id 191); the 2.4 GHz link does not.
        let cfg = Config::from_json(include_str!("../configs/mld.json")).expect("mld.json parses");
        let links = cfg.resolved_mld_links();
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].channel, 1, "link 0 on 2.4 GHz ch 1");
        assert_eq!(links[1].channel, 36, "link 1 on 5 GHz ch 36");
        let ap = cfg.build_ap();
        let b0 = ap.beacon_frame_unprotected_for_link(&links[0]);
        let b1 = ap.beacon_frame_unprotected_for_link(&links[1]);
        // Walk the beacon IEs (after the 24-byte header + 12-byte fixed fields).
        let has_ie = |f: &[u8], id: u8| {
            let mut i = 36usize;
            while i + 2 <= f.len() {
                if f[i] == id {
                    return true;
                }
                i += 2 + f[i + 1] as usize;
            }
            false
        };
        assert!(
            has_ie(&b1, 191),
            "5 GHz (ch 36) link beacon carries VHT Capabilities"
        );
        assert!(
            !has_ie(&b0, 191),
            "2.4 GHz (ch 1) link beacon omits VHT Capabilities"
        );
    }

    #[test]
    fn six_ghz_mld_link_uses_explicit_band_despite_overlapping_channel_number() {
        let cfg = Config::from_json(
            r#"{
                "ssid":"mld-6g", "passphrase":"password1234",
                "key_mgmt":"sae", "phy":"be", "mode":"netlink",
                "mld":true, "band":5, "channel":36, "width":80, "link_id":0,
                "mld_links":[
                    {"link_id":0,"mac":"02:00:00:00:aa:01","band":5,"channel":36,"width":80},
                    {"link_id":1,"mac":"02:00:00:00:aa:02","band":6,"channel":37,"width":80}
                ]
            }"#,
        )
        .expect("mixed 5/6 GHz MLD config parses");
        cfg.validate().expect("mixed 5/6 GHz MLD config validates");
        let links = cfg.resolved_mld_links();
        assert!(!links[0].band6);
        assert!(links[1].band6);

        let ap = cfg.build_ap();
        let beacon = ap.beacon_frame_unprotected_for_link(&links[1]);
        let has_ie = |id: u8, ext_id: Option<u8>| {
            let mut i = 36usize;
            while i + 2 <= beacon.len() {
                let len = beacon[i + 1] as usize;
                if i + 2 + len > beacon.len() {
                    return false;
                }
                if beacon[i] == id && ext_id.is_none_or(|ext| len > 0 && beacon[i + 2] == ext) {
                    return true;
                }
                i += 2 + len;
            }
            false
        };
        assert!(
            !has_ie(191, None),
            "6 GHz link must not advertise VHT capabilities"
        );
        assert!(
            has_ie(255, Some(59)),
            "6 GHz link must advertise the HE 6 GHz capability extension"
        );
    }

    #[test]
    fn mld_beacon_advertises_the_other_link_profile() {
        let cfg = Config::from_json(
            r#"{
                "ssid":"mld-profile", "passphrase":"password1234",
                "key_mgmt":"sae", "phy":"be", "mode":"netlink",
                "mld":true, "mac":"02:00:00:00:aa:00",
                "band":5, "channel":36, "width":80, "link_id":0,
                "mld_links":[
                    {"link_id":0,"mac":"02:00:00:00:aa:01","band":5,"channel":36,"width":80},
                    {"link_id":1,"mac":"02:00:00:00:aa:02","band":6,"channel":37,"width":80}
                ]
            }"#,
        )
        .expect("mixed-band MLD config parses");
        let links = cfg.resolved_mld_links();
        let ap = cfg.build_ap();
        let beacon = ap.beacon_frame_unprotected_for_link(&links[0]);

        // MLO RNR is emitted automatically (independent of the generic `rnr`
        // switch) and names the actual partner link, not a synthesized BSSID.
        let rnr = dot11::find_ie(&beacon[36..], 201).expect("MLO RNR");
        assert_eq!(rnr[1], 16, "MLD TBTT Information length");
        assert_eq!(rnr[2], 133, "6 GHz 80 MHz operating class");
        assert_eq!(rnr[3], 37, "partner channel");
        assert_eq!(&rnr[5..11], &links[1].mac, "partner link BSSID");
        assert_eq!(rnr[18] & 0x0f, 1, "partner Link ID");

        // The Basic MLE starts with ext-id 107. Its Common Info is followed by
        // a Per-STA Profile (subelement id 0) for link 1; a common-only MLE is
        // insufficient for a client to discover and set up the partner link.
        let mut i = 36usize;
        let mut found_profile = false;
        while i + 3 <= beacon.len() {
            let len = beacon[i + 1] as usize;
            if i + 2 + len > beacon.len() {
                break;
            }
            if beacon[i] == 255 && len >= 4 && beacon[i + 2] == 107 {
                let common_len = beacon[i + 5] as usize;
                let profile = i + 5 + common_len;
                found_profile =
                    profile + 1 < i + 2 + len && beacon[profile] == 0 && beacon[profile + 1] > 0;
                break;
            }
            i += 2 + len;
        }
        assert!(found_profile, "link-0 beacon must advertise link-1 profile");
    }

    #[test]
    fn eht_mandates_pmf_upgrading_non_mfpr_modes_to_sae() {
        use crate::frames::{PhyMode, SecurityMode};
        // 802.11be (EHT) requires PMF: a non-MFPR mode (WPA2-PSK / SAE-transition)
        // is upgraded to WPA3-SAE, so the AP advertises an MFPR|MFPC RSN that a
        // spec-compliant Wi-Fi 7 client will accept.
        let mut c = Config::default();
        c.phy = PhyMode::Eht;
        c.key_mgmt = KeyMgmt::Psk;
        assert_eq!(
            c.effective_key_mgmt(),
            KeyMgmt::Sae,
            "EHT + PSK must advertise SAE/PMF"
        );
        assert_eq!(c.build_ap().security_mode(), SecurityMode::Wpa3Sae);

        c.key_mgmt = KeyMgmt::SaeTransition; // transition is only MFPC, not MFPR
        assert_eq!(
            c.effective_key_mgmt(),
            KeyMgmt::Sae,
            "EHT + transition must advertise SAE/PMF"
        );

        // OWE is already PMF-protected; SAE is already correct — both unchanged.
        c.key_mgmt = KeyMgmt::Owe;
        assert_eq!(c.effective_key_mgmt(), KeyMgmt::Owe);
        c.key_mgmt = KeyMgmt::Sae;
        assert_eq!(c.effective_key_mgmt(), KeyMgmt::Sae);

        // An explicitly selected WPA2-PSK mode remains available on non-EHT
        // PHYs even though the default is SAE.
        for phy in [PhyMode::Ht, PhyMode::Vht, PhyMode::He] {
            let mut c = Config::default();
            c.phy = phy;
            c.key_mgmt = KeyMgmt::Psk;
            assert_eq!(
                c.effective_key_mgmt(),
                KeyMgmt::Psk,
                "{phy:?} must stay WPA2-PSK"
            );
            assert_eq!(c.build_ap().security_mode(), SecurityMode::Wpa2);
        }
    }

    #[test]
    fn parses_multi_bss_config() {
        let json = r#"{
            "ssid": "main", "passphrase": "password1234", "mode": "netlink", "band": 5, "channel": 36,
            "bss": [
                { "ssid": "guest", "psk": "guestpass123", "mac": "02:00:00:00:00:10" },
                { "ssid": "iot", "key_mgmt": "sae", "passphrase": "iotpass12345", "bssid": "02:00:00:00:00:20" }
            ]
        }"#;
        let cfg = Config::from_json(json).expect("parses");
        cfg.validate().expect("valid");
        assert_eq!(cfg.bss.len(), 2);
        assert_eq!(cfg.bss[0].ssid, "guest");
        assert_eq!(
            cfg.bss[0].key_mgmt,
            KeyMgmt::Sae,
            "inherits primary default"
        );
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
        assert!(
            cfg.validate().is_err(),
            "BSSID duplicating the primary must be rejected"
        );
    }

    #[test]
    fn bss_requires_ssid_and_mac() {
        let no_mac = r#"{ "ssid": "main", "passphrase": "password1234",
            "bss": [ { "ssid": "guest", "psk": "guestpass123" } ] }"#;
        assert!(
            Config::from_json(no_mac).is_err(),
            "a BSS without a BSSID must be rejected"
        );
        let no_ssid = r#"{ "ssid": "main", "passphrase": "password1234",
            "bss": [ { "mac": "02:00:00:00:00:10", "psk": "guestpass123" } ] }"#;
        assert!(
            Config::from_json(no_ssid).is_err(),
            "a BSS without an SSID must be rejected"
        );
    }

    #[test]
    fn parses_a_full_json_config() {
        let json = r#"{
            "ssid": "lab",
            "passphrase": "hunter2hunter2",
            "key_mgmt": "sae",
            "band": 5,
            "channel": 36,
            "interface": "wlan3",
            "mode": "netlink",
            "mac": "02:aa:bb:cc:dd:ee",
            "ip": "192.168.5.1",
            "ocv": true,
            "per_sta_vif": true,
            "spr_api_socket": "/state/wifi/apisock",
            "spr_dhcp_helper": "/spr_dhcp_helper"
        }"#;
        let c = Config::from_json(json).unwrap();
        assert_eq!(c.ssid, "lab");
        assert_eq!(c.passphrase, "hunter2hunter2");
        assert_eq!(c.key_mgmt, KeyMgmt::Sae);
        assert_eq!(c.band, Band::Ghz5);
        assert_eq!(c.channel, 36);
        assert_eq!(c.iface, "wlan3");
        assert_eq!(c.mode, "netlink");
        assert_eq!(c.mac, [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
        assert_eq!(c.ip, [192, 168, 5, 1]);
        assert!(c.ocv);
        assert!(c.per_sta_vif);
        assert_eq!(c.spr_api_socket.as_deref(), Some("/state/wifi/apisock"));
        assert_eq!(c.spr_dhcp_helper.as_deref(), Some("/spr_dhcp_helper"));
    }

    #[test]
    fn omitted_keys_keep_defaults() {
        let c = Config::from_json(r#"{"ssid": "only-ssid"}"#).unwrap();
        assert_eq!(c.ssid, "only-ssid");
        assert_eq!(c.channel, 1); // default preserved
        assert_eq!(c.key_mgmt, KeyMgmt::Sae);
        assert_eq!(c.band, Band::Ghz2_4);
    }

    #[test]
    fn band_is_explicit_and_replaces_band6() {
        assert_eq!(
            Config::from_json(r#"{"band": 2.4}"#).unwrap().band,
            Band::Ghz2_4
        );
        assert_eq!(
            Config::from_json(r#"{"band": 5}"#).unwrap().band,
            Band::Ghz5
        );
        assert_eq!(
            Config::from_json(r#"{"band": 6}"#).unwrap().band,
            Band::Ghz6
        );
        assert!(Config::from_json(r#"{"band": 4}"#).is_err());
        assert!(
            Config::from_json(r#"{"band6": true}"#).is_err(),
            "legacy boolean must not survive in the native JSON schema"
        );
    }

    #[test]
    fn band_and_channel_must_match() {
        assert!(Config::from_json(r#"{"band":2.4,"channel":36}"#)
            .unwrap()
            .validate()
            .is_err());
        assert!(Config::from_json(r#"{"band":5,"channel":1}"#)
            .unwrap()
            .validate()
            .is_err());
        assert!(Config::from_json(
            r#"{"band":6,"channel":37,"key_mgmt":"sae","phy":"be","passphrase":"password1234"}"#,
        )
        .unwrap()
        .validate()
        .is_ok());
        assert!(
            Config::from_json(r#"{"band":6,"channel":36,"key_mgmt":"sae","phy":"be"}"#)
                .unwrap()
                .validate()
                .is_err()
        );
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
        assert!(c.validate().is_err()); // no default production credential
        c.passphrase = "password1234".to_string();
        assert!(c.validate().is_ok());
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
        c.band = Band::Ghz6;
        assert!(c.validate().is_err());
        c.key_mgmt = KeyMgmt::Sae;
        assert!(c.validate().is_ok()); // 6 GHz + SAE is fine
                                       // OWE needs no passphrase
        let mut o = Config::default();
        o.key_mgmt = KeyMgmt::Owe;
        o.passphrase = String::new();
        o.mode = "iface".to_string();
        assert!(o.validate().is_ok());
    }

    #[test]
    fn country_defaults_and_parses() {
        assert_eq!(Config::default().country, *b"US");
        assert_eq!(
            Config::from_json(r#"{"country": "de"}"#).unwrap().country,
            *b"DE"
        );
        assert_eq!(
            Config::from_json(r#"{"country_code": "JP"}"#)
                .unwrap()
                .country,
            *b"JP"
        );
        assert!(Config::from_json(r#"{"country": "USA"}"#).is_err()); // not 2 letters
        assert!(Config::from_json(r#"{"country": "U1"}"#).is_err()); // not alphabetic
    }

    #[test]
    fn psk_file_parses_wildcard_and_per_mac() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("barely_psk_{}.txt", std::process::id()));
        std::fs::write(
            &path,
            "# onboarding\n\
             00:00:00:00:00:00 onboardpass\n\
             \n\
             aa:bb:cc:dd:ee:ff devicepass\n\
             sae-onboard|mac=ff:ff:ff:ff:ff:ff\n\
             sae-device|mac=12:34:56:78:9a:bc\n",
        )
        .unwrap();
        let e = parse_psk_file(path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(e.len(), 4);
        assert_eq!(e[0], (None, "onboardpass".to_string())); // wildcard
        assert_eq!(
            e[1],
            (
                Some(mac_to_bytes("aa:bb:cc:dd:ee:ff")),
                "devicepass".to_string()
            )
        );
        assert_eq!(e[2], (None, "sae-onboard".to_string()));
        assert_eq!(
            e[3],
            (
                Some(mac_to_bytes("12:34:56:78:9a:bc")),
                "sae-device".to_string()
            )
        );
        let c = Config::from_json(r#"{"psk_file": "/x"}"#).unwrap();
        assert_eq!(c.psk_file.as_deref(), Some("/x"));
    }
}
