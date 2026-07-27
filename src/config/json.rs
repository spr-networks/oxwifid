use super::model::{Band, BssConfig, Config, KeyMgmt, MldLinkConfig, RadioConfig};
use super::values::{
    as_bool, as_str, as_u8, parse_band, parse_country, parse_data_cipher, parse_ip, parse_key_mgmt,
    parse_phy,
};
use crate::util::{mac_to_bytes, try_mac_to_bytes};
use serde_json::{Map, Value};
use zeroize::{Zeroize, Zeroizing};

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

/// Apply scalar settings before parsing BSS entries so BSS inheritance is
/// independent of JSON object key order. `radios` itself is parsed separately.
fn apply_config_object(cfg: &mut Config, object: &Map<String, Value>) -> Result<(), String> {
    for (key, value) in object {
        if key == "bss" || key == "radios" {
            continue;
        }
        cfg.set(key, value)?;
    }
    if let Some(bss) = object.get("bss") {
        cfg.set("bss", bss)?;
    }
    Ok(())
}

fn radio_field<'a>(
    object: &'a Map<String, Value>,
    aliases: &[&str],
    label: &str,
    required: bool,
) -> Result<Option<&'a Value>, String> {
    let present: Vec<&&str> = aliases
        .iter()
        .filter(|key| object.contains_key(**key))
        .collect();
    if present.len() > 1 {
        return Err(format!(
            "{label} was supplied more than once ({})",
            present
                .iter()
                .map(|key| format!("{key:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if let Some(key) = present.first() {
        return Ok(object.get(**key));
    }
    if required {
        return Err(format!("requires an explicit {label}"));
    }
    Ok(None)
}

fn parse_radio(
    object: &Map<String, Value>,
    default_passphrase: &str,
    default_key_mgmt: KeyMgmt,
) -> Result<RadioConfig, String> {
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "iface"
                | "interface"
                | "ssid"
                | "mac"
                | "bssid"
                | "band"
                | "channel"
                | "width"
                | "channel_width"
                | "phy"
                | "phy_mode"
                | "ieee80211_mode"
                | "ctrl_path"
                | "ctrl_interface"
                | "punct_bitmap"
                | "ru_puncturing_bitmap"
                | "mld"
                | "mld_ap"
                | "link_id"
                | "mld_link_id"
                | "mld_links"
                | "links"
                | "mld_default_links"
                | "mld_tid_to_link"
                | "bss"
        ) {
            return Err(format!(
                "unknown radio key {key:?}; shared settings belong at the top level"
            ));
        }
    }

    let iface_value = radio_field(object, &["iface", "interface"], "iface", true)?.unwrap();
    let band_value = radio_field(object, &["band"], "band", true)?.unwrap();
    let channel_value = radio_field(object, &["channel"], "channel", true)?.unwrap();
    let width_value = radio_field(object, &["width", "channel_width"], "width", true)?.unwrap();
    let phy_value =
        radio_field(object, &["phy", "phy_mode", "ieee80211_mode"], "phy", true)?.unwrap();
    let ctrl_value =
        radio_field(object, &["ctrl_path", "ctrl_interface"], "ctrl_path", true)?.unwrap();

    // MAC is optional: a non-MLD netlink AP adopts the interface's own MAC as
    // the BSSID regardless, so a config need not repeat it. When omitted, use
    // the placeholder default (it will be adopted at bring-up).
    let (mac, mac_explicit) = match radio_field(object, &["mac", "bssid"], "mac", false)? {
        Some(value) => {
            let text = as_str("mac", value)?;
            let m = try_mac_to_bytes(text).ok_or_else(|| format!("invalid radio mac {text:?}"))?;
            (m, true)
        }
        None => (mac_to_bytes("02:00:00:00:00:00"), false),
    };
    let ssid = radio_field(object, &["ssid"], "ssid", false)?
        .map(|value| as_str("ssid", value).map(str::to_string))
        .transpose()?;
    let width_number = width_value
        .as_u64()
        .ok_or("radio width must be an integer")?;
    let width = u16::try_from(width_number).map_err(|_| "radio width out of range".to_string())?;

    let punct_bitmap = match radio_field(
        object,
        &["punct_bitmap", "ru_puncturing_bitmap"],
        "punct_bitmap",
        false,
    )? {
        Some(value) => {
            let number = value
                .as_u64()
                .ok_or("radio punct_bitmap must be an integer")?;
            u16::try_from(number).map_err(|_| "radio punct_bitmap out of range".to_string())?
        }
        None => 0,
    };
    let mld = radio_field(object, &["mld", "mld_ap"], "mld", false)?
        .map(|value| as_bool("mld", value))
        .transpose()?
        .unwrap_or(false);
    let link_id = radio_field(object, &["link_id", "mld_link_id"], "link_id", false)?
        .map(|value| as_u8("link_id", value))
        .transpose()?
        .unwrap_or(0);

    let mut mld_links = Vec::new();
    if let Some(value) = radio_field(object, &["mld_links", "links"], "mld_links", false)? {
        for item in value.as_array().ok_or("radio mld_links must be an array")? {
            mld_links.push(parse_mld_link(item, width)?);
        }
    }
    let mld_default_links = if let Some(value) = radio_field(
        object,
        &["mld_default_links", "mld_tid_to_link"],
        "mld_default_links",
        false,
    )? {
        let mut links = Vec::new();
        for item in value
            .as_array()
            .ok_or("radio mld_default_links must be an array")?
        {
            links.push(as_u8("mld_default_links", item)?);
        }
        Some(links)
    } else {
        None
    };

    let mut bss = Vec::new();
    if let Some(value) = object.get("bss") {
        for item in value.as_array().ok_or("radio bss must be an array")? {
            bss.push(parse_bss(item, default_passphrase, default_key_mgmt)?);
        }
    }

    Ok(RadioConfig {
        iface: as_str("iface", iface_value)?.to_string(),
        mac,
        mac_explicit,
        ssid,
        band: parse_band("band", band_value)?,
        channel: as_u8("channel", channel_value)?,
        width,
        phy: parse_phy(as_str("phy", phy_value)?)?,
        ctrl_path: as_str("ctrl_path", ctrl_value)?.to_string(),
        punct_bitmap,
        mld,
        link_id,
        mld_links,
        mld_default_links,
        bss,
    })
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
            if obj.contains_key("radios") {
                for key in [
                    "band",
                    "channel",
                    "width",
                    "channel_width",
                    "phy",
                    "phy_mode",
                    "ieee80211_mode",
                    "interface",
                    "iface",
                    "mac",
                    "bssid",
                    "ctrl_path",
                    "ctrl_interface",
                    "bss",
                    "punct_bitmap",
                    "ru_puncturing_bitmap",
                    "mld",
                    "mld_ap",
                    "link_id",
                    "mld_link_id",
                    "mld_links",
                    "links",
                    "mld_default_links",
                    "mld_tid_to_link",
                ] {
                    if obj.contains_key(key) {
                        return Err(format!("{key:?} belongs inside each radios[] entry"));
                    }
                }
            }
            apply_config_object(&mut cfg, obj)?;

            if let Some(radios) = obj.get("radios") {
                let entries = radios
                    .as_array()
                    .ok_or("radios must be a non-empty array")?;
                if entries.is_empty() {
                    return Err("radios must be a non-empty array".to_string());
                }
                cfg.radios.clear();
                for (index, entry) in entries.iter().enumerate() {
                    let radio_obj = entry
                        .as_object()
                        .ok_or_else(|| format!("radios[{index}] must be an object"))?;
                    cfg.radios.push(
                        parse_radio(radio_obj, &cfg.passphrase, cfg.key_mgmt)
                            .map_err(|e| format!("radios[{index}]: {e}"))?,
                    );
                }
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
            "guest" | "ap_isolate" => self.guest = as_bool(key, val)?,
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
                self.bss.clear();
                for item in arr {
                    self.bss.push(parse_bss(item, &default_pass, default_km)?);
                }
            }
            "radios" => {
                return Err("radios is only valid at the top level".to_string());
            }
            _ => return Err(format!("unknown config key {key:?}")),
        }
        Ok(())
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
        own_passphrase: false,
        disable_isolation: false,
        guest: true,
    };
    let mut have_mac = false;
    for (k, v) in o {
        match k.as_str() {
            "ssid" => b.ssid = as_str(k, v)?.to_string(),
            "passphrase" | "wpa_passphrase" | "sae_password" | "psk" | "guest_password" => {
                b.passphrase.zeroize();
                b.passphrase = as_str(k, v)?.to_string();
                b.own_passphrase = true;
            }
            "key_mgmt" | "security" => b.key_mgmt = parse_key_mgmt(as_str(k, v)?)?,
            "mac" | "bssid" => {
                b.mac = mac_to_bytes(as_str(k, v)?);
                have_mac = true;
            }
            "disable_isolation" => b.disable_isolation = as_bool(k, v)?,
            "guest" | "ap_isolate" => b.guest = as_bool(k, v)?,
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
        mac,
        channel: channel.ok_or("mld link missing channel")?,
        width,
        band,
    })
}
