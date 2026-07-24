//! SPR Wi-Fi uplink configuration and scan-result selection.
//!
//! SPR stores the networks selected (or manually entered) by the wireless UI in
//! `/configs/wifi_uplink/wpa.json`. The client consumes that file directly:
//! there is no generated wpa_supplicant configuration or password-bearing
//! command line between SPR and barely-ap.

use crate::util::try_mac_to_bytes;
use serde_json::Value;
use zeroize::Zeroize;

struct SecretJson(Value);

fn zeroize_json_strings(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => {
            for value in values {
                zeroize_json_strings(value);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                zeroize_json_strings(value);
            }
        }
        _ => {}
    }
}

impl Drop for SecretJson {
    fn drop(&mut self) {
        zeroize_json_strings(&mut self.0);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UplinkSecurity {
    Psk,
    PskSha256,
    Sae,
}

pub struct UplinkNetwork {
    pub ssid: String,
    pub password: String,
    pub key_mgmt: String,
    pub priority: i32,
    pub bssid: Option<[u8; 6]>,
}

impl Drop for UplinkNetwork {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ScanCandidate {
    pub ssid: Vec<u8>,
    pub bssid: [u8; 6],
    pub frequency: u32,
    pub channel: u8,
    pub band: &'static str,
    pub signal_dbm: Option<f32>,
    pub psk: bool,
    pub psk_sha256: bool,
    pub sae: bool,
    pub sae_h2e: bool,
}

pub struct SelectedUplink {
    pub network: UplinkNetwork,
    pub candidate: ScanCandidate,
    pub security: UplinkSecurity,
}

fn json_string<'a>(object: &'a serde_json::Map<String, Value>, key: &str) -> &'a str {
    object.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// Parse the enabled networks for one SPR WPA interface.
pub fn parse_spr_uplink(text: &str, iface: &str) -> Result<Vec<UplinkNetwork>, String> {
    let root = SecretJson(
        serde_json::from_str(text).map_err(|error| format!("invalid SPR uplink JSON: {error}"))?,
    );
    let interfaces = root
        .0
        .get("WPAs")
        .and_then(Value::as_array)
        .ok_or_else(|| "SPR uplink config has no WPAs array".to_string())?;
    let selected = interfaces
        .iter()
        .filter_map(Value::as_object)
        .find(|entry| json_string(entry, "Iface") == iface)
        .ok_or_else(|| format!("SPR uplink config has no interface {iface:?}"))?;
    if !selected
        .get("Enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err(format!("SPR Wi-Fi uplink {iface:?} is disabled"));
    }
    let entries = selected
        .get("Networks")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("SPR Wi-Fi uplink {iface:?} has no Networks array"))?;
    let mut networks = Vec::new();
    for (index, value) in entries.iter().enumerate() {
        let object = value
            .as_object()
            .ok_or_else(|| format!("network {index} is not an object"))?;
        if object
            .get("Disabled")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            continue;
        }
        let ssid = json_string(object, "SSID");
        if ssid.is_empty() || ssid.len() > 32 {
            return Err(format!(
                "network {index} SSID must contain between 1 and 32 bytes"
            ));
        }
        let key_mgmt = json_string(object, "KeyMgmt");
        if key_mgmt.is_empty() {
            return Err(format!("network {index} has no KeyMgmt"));
        }
        for akm in key_mgmt.split_whitespace() {
            if !matches!(akm, "NONE" | "WPA-PSK" | "WPA-PSK-SHA256" | "SAE") {
                return Err(format!("network {index} has unsupported KeyMgmt {akm:?}"));
            }
        }
        let password = json_string(object, "Password");
        if !key_mgmt.split_whitespace().all(|akm| akm == "NONE")
            && !(8..=63).contains(&password.len())
        {
            return Err(format!(
                "network {index} password must contain between 8 and 63 bytes"
            ));
        }
        let priority_text = json_string(object, "Priority");
        let priority = if priority_text.is_empty() {
            0
        } else {
            priority_text
                .parse::<i32>()
                .map_err(|_| format!("network {index} has invalid Priority"))?
        };
        let bssid_text = json_string(object, "BSSID");
        let bssid = if bssid_text.is_empty() {
            None
        } else {
            Some(
                try_mac_to_bytes(bssid_text)
                    .ok_or_else(|| format!("network {index} has invalid BSSID"))?,
            )
        };
        networks.push(UplinkNetwork {
            ssid: ssid.to_string(),
            password: password.to_string(),
            key_mgmt: key_mgmt.to_string(),
            priority,
            bssid,
        });
    }
    if networks.is_empty() {
        return Err(format!(
            "SPR Wi-Fi uplink {iface:?} has no enabled networks"
        ));
    }
    Ok(networks)
}

fn candidate_security(
    network: &UplinkNetwork,
    candidate: &ScanCandidate,
) -> Option<UplinkSecurity> {
    let has = |name| network.key_mgmt.split_whitespace().any(|akm| akm == name);
    // The current SAE client uses H2E. A mixed WPA2/WPA3 network without an
    // H2E RSNXE therefore safely falls back to PSK instead of repeatedly
    // attempting an incompatible SAE exchange.
    if has("SAE") && candidate.sae && candidate.sae_h2e {
        return Some(UplinkSecurity::Sae);
    }
    if has("WPA-PSK-SHA256") && candidate.psk_sha256 {
        return Some(UplinkSecurity::PskSha256);
    }
    if has("WPA-PSK") && candidate.psk {
        return Some(UplinkSecurity::Psk);
    }
    None
}

/// Select like wpa_supplicant: highest configured priority first, strongest
/// matching BSS second. An explicitly saved BSSID is always enforced. A hidden
/// result with an empty SSID can match only through that explicit BSSID.
pub fn select_uplink(
    mut networks: Vec<UplinkNetwork>,
    candidates: &[ScanCandidate],
) -> Result<SelectedUplink, String> {
    let mut best: Option<(usize, usize, UplinkSecurity)> = None;
    for (network_index, network) in networks.iter().enumerate() {
        for (candidate_index, candidate) in candidates.iter().enumerate() {
            if network
                .bssid
                .is_some_and(|configured| configured != candidate.bssid)
            {
                continue;
            }
            let ssid_matches = candidate.ssid == network.ssid.as_bytes()
                || (candidate.ssid.is_empty() && network.bssid == Some(candidate.bssid));
            if !ssid_matches {
                continue;
            }
            let Some(security) = candidate_security(network, candidate) else {
                continue;
            };
            let replace = best.is_none_or(|(old_network, old_candidate, _)| {
                let old = &networks[old_network];
                network.priority > old.priority
                    || (network.priority == old.priority
                        && candidate.signal_dbm.unwrap_or(f32::NEG_INFINITY)
                            > candidates[old_candidate]
                                .signal_dbm
                                .unwrap_or(f32::NEG_INFINITY))
            });
            if replace {
                best = Some((network_index, candidate_index, security));
            }
        }
    }
    let Some((network_index, candidate_index, security)) = best else {
        return Err(
            "no scanned BSS matches an enabled SPR uplink network and security mode".into(),
        );
    };
    let network = networks.swap_remove(network_index);
    Ok(SelectedUplink {
        network,
        candidate: candidates[candidate_index].clone(),
        security,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(ssid: &[u8], bssid: [u8; 6], signal: f32) -> ScanCandidate {
        ScanCandidate {
            ssid: ssid.to_vec(),
            bssid,
            frequency: 5180,
            channel: 36,
            band: "5",
            signal_dbm: Some(signal),
            psk: true,
            psk_sha256: false,
            sae: true,
            sae_h2e: true,
        }
    }

    #[test]
    fn parses_enabled_spr_networks_without_logging_passwords() {
        let json = r#"{
          "WPAs": [{
            "Iface": "wlan0", "Enabled": true,
            "Networks": [
              {"Disabled": true, "SSID": "old", "Password": "password1",
               "KeyMgmt": "WPA-PSK", "Priority": "1"},
              {"SSID": "chosen", "Password": "password2",
               "KeyMgmt": "WPA-PSK WPA-PSK-SHA256 SAE", "Priority": "7",
               "BSSID": "02:00:00:00:00:07"}
            ]
          }]
        }"#;
        let parsed = parse_spr_uplink(json, "wlan0").unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].ssid, "chosen");
        assert_eq!(parsed[0].priority, 7);
        assert_eq!(parsed[0].bssid, Some([2, 0, 0, 0, 0, 7]));
    }

    #[test]
    fn selection_honors_priority_bssid_and_hidden_ssid() {
        let networks = vec![
            UplinkNetwork {
                ssid: "low".into(),
                password: "password1".into(),
                key_mgmt: "WPA-PSK".into(),
                priority: 1,
                bssid: None,
            },
            UplinkNetwork {
                ssid: "hidden".into(),
                password: "password2".into(),
                key_mgmt: "WPA-PSK SAE".into(),
                priority: 9,
                bssid: Some([2, 0, 0, 0, 0, 9]),
            },
        ];
        let candidates = vec![
            candidate(b"low", [2, 0, 0, 0, 0, 1], -20.0),
            candidate(b"", [2, 0, 0, 0, 0, 9], -70.0),
        ];
        let selected = select_uplink(networks, &candidates).unwrap();
        assert_eq!(selected.network.ssid, "hidden");
        assert_eq!(selected.security, UplinkSecurity::Sae);
    }

    #[test]
    fn mixed_mode_falls_back_when_sae_h2e_is_absent() {
        let networks = vec![UplinkNetwork {
            ssid: "mixed".into(),
            password: "password1".into(),
            key_mgmt: "WPA-PSK SAE".into(),
            priority: 0,
            bssid: None,
        }];
        let mut scan = candidate(b"mixed", [2, 0, 0, 0, 0, 1], -40.0);
        scan.sae_h2e = false;
        let selected = select_uplink(networks, &[scan]).unwrap();
        assert_eq!(selected.security, UplinkSecurity::Psk);
    }
}
