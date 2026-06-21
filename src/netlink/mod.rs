//! WPA3-capable nl80211 (generic netlink) transport.
//!
//! This is an alternative to the [`crate::raw_frames::af_packet`] monitor-mode
//! socket: instead of a raw `AF_PACKET` socket it talks to the kernel's
//! `cfg80211`/`mac80211` over generic netlink (the same interface hostapd uses).
//! It configures the radio (interface type + channel) and injects/receives
//! management frames via `NL80211_CMD_FRAME`.
//!
//! The message-encoding layer ([`msg`]) is platform independent and unit
//! tested; the socket/[`Link`] layer is Linux-only.
//!
//! Scope: management-frame TX/RX + radio setup. Because `NL80211_CMD_FRAME`
//! only carries management frames, userspace-encrypted CCMP **data** frames
//! still require the monitor (`af_packet`) path — this transport is intended for
//! the management/handshake plane. It is Linux-only and not exercised on
//! non-Linux hosts.

pub mod msg;

// nl80211 generic-netlink commands (resolved from the kernel header).
pub const NL80211_CMD_NEW_KEY: u8 = 11;
pub const NL80211_CMD_START_AP: u8 = 15;
pub const NL80211_CMD_NEW_INTERFACE: u8 = 7;
pub const NL80211_CMD_DEL_INTERFACE: u8 = 8;
pub const NL80211_CMD_SET_INTERFACE: u8 = 6;
pub const NL80211_CMD_SET_STATION: u8 = 18;
pub const NL80211_CMD_NEW_STATION: u8 = 19;
pub const NL80211_CMD_DEL_STATION: u8 = 20;
pub const NL80211_CMD_REGISTER_FRAME: u8 = 58;
pub const NL80211_CMD_FRAME: u8 = 59;
pub const NL80211_CMD_SET_CHANNEL: u8 = 65;
pub const NL80211_CMD_CONTROL_PORT_FRAME: u8 = 129;

// nl80211 attributes.
pub const NL80211_ATTR_WIPHY: u16 = 1;
pub const NL80211_ATTR_IFINDEX: u16 = 3;
pub const NL80211_ATTR_IFNAME: u16 = 4;
pub const NL80211_ATTR_IFTYPE: u16 = 5;
/// ifindex of the VLAN interface to move a station into (per-STA VIF).
pub const NL80211_ATTR_STA_VLAN: u16 = 20;
pub const NL80211_ATTR_MAC: u16 = 6;
pub const NL80211_ATTR_KEY_DATA: u16 = 7;
pub const NL80211_ATTR_KEY_IDX: u16 = 8;
pub const NL80211_ATTR_KEY_CIPHER: u16 = 9;
pub const NL80211_ATTR_KEY_SEQ: u16 = 10;
pub const NL80211_ATTR_KEY_DEFAULT: u16 = 11;
pub const NL80211_ATTR_BEACON_INTERVAL: u16 = 12;
pub const NL80211_ATTR_DTIM_PERIOD: u16 = 13;
pub const NL80211_ATTR_BEACON_HEAD: u16 = 14;
pub const NL80211_ATTR_BEACON_TAIL: u16 = 15;
pub const NL80211_ATTR_STA_AID: u16 = 16;
pub const NL80211_ATTR_STA_FLAGS: u16 = 17;
pub const NL80211_ATTR_STA_LISTEN_INTERVAL: u16 = 18;
pub const NL80211_ATTR_STA_SUPPORTED_RATES: u16 = 19;
pub const NL80211_ATTR_WIPHY_FREQ: u16 = 38;
pub const NL80211_ATTR_FRAME: u16 = 51;
pub const NL80211_ATTR_SSID: u16 = 52;
pub const NL80211_ATTR_AUTH_TYPE: u16 = 53;
pub const NL80211_ATTR_STA_FLAGS2: u16 = 67;
pub const NL80211_ATTR_PRIVACY: u16 = 70;
pub const NL80211_ATTR_CONTROL_PORT: u16 = 68;
pub const NL80211_ATTR_CIPHER_SUITES_PAIRWISE: u16 = 73;
pub const NL80211_ATTR_CIPHER_SUITE_GROUP: u16 = 74;
pub const NL80211_ATTR_WPA_VERSIONS: u16 = 75;
pub const NL80211_ATTR_AKM_SUITES: u16 = 76;
pub const NL80211_ATTR_FRAME_MATCH: u16 = 91;
pub const NL80211_ATTR_FRAME_TYPE: u16 = 101;
pub const NL80211_ATTR_HIDDEN_SSID: u16 = 126;
pub const NL80211_ATTR_KEY_TYPE: u16 = 55;
pub const NL80211_ATTR_STA_CAPABILITY: u16 = 171;
pub const NL80211_ATTR_CONTROL_PORT_ETHERTYPE: u16 = 102;
pub const NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT: u16 = 103;
pub const NL80211_ATTR_CHANNEL_WIDTH: u16 = 159;
pub const NL80211_ATTR_CENTER_FREQ1: u16 = 160;
pub const NL80211_ATTR_SOCKET_OWNER: u16 = 204;
pub const NL80211_ATTR_CONTROL_PORT_OVER_NL80211: u16 = 264;
pub const NL80211_CHAN_WIDTH_20: u32 = 1;
pub const NL80211_KEYTYPE_GROUP: u32 = 0;
pub const NL80211_KEYTYPE_PAIRWISE: u32 = 1;
pub const ETH_P_PAE: u16 = 0x888e; // 802.1X / EAPOL ethertype

// interface types.
pub const NL80211_IFTYPE_AP: u32 = 3;
pub const NL80211_IFTYPE_AP_VLAN: u32 = 4;
pub const NL80211_IFTYPE_MONITOR: u32 = 6;

// auth type + WPA versions + cipher/AKM suite selectors.
pub const NL80211_AUTHTYPE_OPEN_SYSTEM: u32 = 0;
pub const NL80211_WPA_VERSION_2: u32 = 2;
pub const WLAN_CIPHER_SUITE_CCMP: u32 = 0x000f_ac04;
pub const WLAN_AKM_SUITE_PSK: u32 = 0x000f_ac02;
// per-STA flag bits (NL80211_STA_FLAG_*).
pub const NL80211_STA_FLAG_AUTHORIZED: u32 = 1;
pub const NL80211_STA_FLAG_AUTHENTICATED: u32 = 5;
pub const NL80211_STA_FLAG_ASSOCIATED: u32 = 7;

/// Management frame-control type+subtype values to register for, matching the
/// frames the AP handles (probe req, auth, (re)assoc req).
pub const REGISTER_SUBTYPES: [u16; 4] = [
    0x0040, // probe request  (subtype 4)
    0x00b0, // authentication (subtype 11)
    0x0000, // association request
    0x0020, // reassociation request
];

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{run_offload_ap, NetlinkLink};
