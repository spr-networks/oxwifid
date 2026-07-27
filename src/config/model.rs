use crate::structures::DataCipher;
use crate::util::mac_to_bytes;
use zeroize::Zeroize;

/// How stations authenticate to the AP.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyMgmt {
    /// WPA2-Personal (PSK).
    Psk,
    /// WPA2-Personal offering the SHA-256 PSK AKM (00-0F-AC:6) alongside the
    /// SHA-1 one, so a SHA-256-capable station can select the stronger key
    /// hierarchy while legacy WPA2 stations keep associating.
    PskSha256,
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
    /// Guest network: client isolation (reference AP `ap_isolate`). The AP never
    /// carries traffic between its own stations, in any mode.
    pub guest: bool,
    /// 802.11be preamble-puncturing bitmap (EHT Operation Disabled Subchannel
    /// Bitmap): one bit per 20 MHz subchannel, 1 = punctured. 0 = none.
    pub punct_bitmap: u16,
    /// 802.11be AP MLD: advertise a Basic Multi-Link element and run association
    /// + 4-way at the MLD level. Off by default.
    pub mld: bool,
    /// This affiliated link's Link ID (0-15).
    pub link_id: u8,
    /// Affiliated AP links for an MLD AP. Empty means the top-level
    /// channel/link_id describes the only link; its BSSID is derived from the
    /// runtime interface MLD address in netlink mode.
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
    /// When omitted for an SPR-integrated AP, the runtime derives the standard
    /// `control_<iface>/<iface>` path beside `spr_api_socket`. netlink mode only.
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
    /// Independent physical radios. Security, SSID, credentials, and policy are
    /// shared from this top-level configuration.
    pub radios: Vec<RadioConfig>,
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
    /// The entry supplied its own passphrase — a static guest password (SPR
    /// `GuestPassword`). The device credential database (`psk_file`) then never
    /// applies to this BSS. When false, the BSS authenticates against the
    /// primary's `psk_file` (or its inherited passphrase if none is set).
    pub own_passphrase: bool,
    /// Opt out of the default guest isolation (SPR `DisableIsolation`):
    /// extra BSSes otherwise get `ap_isolate` + `per_sta_vif`.
    pub disable_isolation: bool,
    /// Whether this extra BSS applies guest/client isolation. Extra BSSes
    /// default to isolated; `guest: false` or `disable_isolation: true` opts out.
    pub guest: bool,
}

/// Physical and radio-local settings for one independently operating radio.
///
/// Keeping this separate from [`Config`] prevents a radio entry from silently
/// overriding shared authentication, credentials, or station policy.
#[derive(Clone, Debug)]
pub struct RadioConfig {
    pub iface: String,
    /// Radio BSSID. Optional: when not given (`mac_explicit == false`) the
    /// netlink AP adopts the interface's own MAC, which is what a kernel-offload
    /// BSSID must be anyway, so most configs can omit it.
    pub mac: [u8; 6],
    pub mac_explicit: bool,
    /// Per-radio SSID override. `None` inherits the shared top-level `ssid`, so
    /// a DBDC config can give 2.4 and 5 GHz the same or different network names.
    pub ssid: Option<String>,
    pub band: Band,
    pub channel: u8,
    pub width: u16,
    pub phy: crate::frames::PhyMode,
    pub ctrl_path: String,
    pub punct_bitmap: u16,
    pub mld: bool,
    pub link_id: u8,
    pub mld_links: Vec<MldLinkConfig>,
    pub mld_default_links: Option<Vec<u8>>,
    pub bss: Vec<BssConfig>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MldLinkConfig {
    pub link_id: u8,
    pub mac: Option<[u8; 6]>,
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
            ocv: false,
            btm: false,
            rnr: false,
            band: Band::Ghz2_4,
            per_sta_vif: false,
            guest: false,
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
            radios: Vec::new(),
            group_rekey: 600,
            strict_rekey: true,
        }
    }
}
