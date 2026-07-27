//! Declarative AP configuration.
//!
//! Settings (SSID, passphrase, key management, channel, feature toggles such as
//! `per_sta_vif`, …) come from a JSON config file rather than being scattered
//! across ad-hoc CLI flags. [`Config::from_json`] parses a file; [`Config::build_ap`]
//! turns the configuration into a fully wired [`Ap`].
//!
//! A DBDC device puts policy shared by all radios at the top level and the
//! physical configuration of each independently operating radio in `radios`:
//! ```json
//! {
//!   "ssid": "turtlenet",
//!   "psk_file": "/run/secrets/wifi-credentials",
//!   "key_mgmt": "sae",
//!   "mode": "netlink",
//!   "radios": [
//!     { "iface": "wlan1", "mac": "02:00:00:00:00:01",
//!       "band": 2.4, "channel": 1, "width": 20, "phy": "ax",
//!       "ctrl_path": "/run/barely-ap/wlan1" },
//!     { "iface": "wlan2", "mac": "02:00:00:00:00:02",
//!       "band": 5, "channel": 36, "width": 80, "phy": "ax",
//!       "ctrl_path": "/run/barely-ap/wlan2" }
//!   ]
//! }
//! ```

mod build;
mod credentials;
mod json;
mod model;
mod validation;
mod values;

pub use credentials::{parse_psk_file, PskEntry};
pub use model::{Band, BssConfig, Config, KeyMgmt, MldLinkConfig, RadioConfig};
pub use values::{parse_band_str, parse_country, parse_data_cipher, parse_ip, parse_phy};

#[cfg(test)]
mod tests;
