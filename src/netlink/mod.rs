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
pub const NL80211_CMD_SET_INTERFACE: u8 = 6;
pub const NL80211_CMD_REGISTER_FRAME: u8 = 58;
pub const NL80211_CMD_FRAME: u8 = 59;
pub const NL80211_CMD_SET_CHANNEL: u8 = 65;

// nl80211 attributes.
pub const NL80211_ATTR_WIPHY: u16 = 1;
pub const NL80211_ATTR_IFINDEX: u16 = 3;
pub const NL80211_ATTR_IFTYPE: u16 = 5;
pub const NL80211_ATTR_MAC: u16 = 6;
pub const NL80211_ATTR_WIPHY_FREQ: u16 = 38;
pub const NL80211_ATTR_FRAME: u16 = 51;
pub const NL80211_ATTR_FRAME_MATCH: u16 = 91;
pub const NL80211_ATTR_FRAME_TYPE: u16 = 101;

// interface types.
pub const NL80211_IFTYPE_AP: u32 = 3;
pub const NL80211_IFTYPE_MONITOR: u32 = 6;

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
pub use linux::NetlinkLink;
