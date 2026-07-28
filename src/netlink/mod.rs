//! WPA3-capable nl80211 (generic netlink) transport.
//!
//! This is an alternative to the `raw_frames::af_packet` monitor-mode
//! socket: instead of a raw `AF_PACKET` socket it talks to the kernel's
//! `cfg80211`/`mac80211` over generic netlink (the same interface reference AP uses).
//! It configures the radio (interface type + channel) and injects/receives
//! management frames via `NL80211_CMD_FRAME`.
//!
//! The message-encoding layer ([`msg`]) is platform independent and unit
//! tested; the socket/[`crate::raw_frames::Link`] layer is Linux-only.
//!
//! Scope: management-frame TX/RX + radio setup. Because `NL80211_CMD_FRAME`
//! only carries management frames, userspace-encrypted CCMP **data** frames
//! still require the monitor (`af_packet`) path — this transport is intended for
//! the management/handshake plane. It is Linux-only and not exercised on
//! non-Linux hosts.

pub mod msg;

mod abi;
mod helpers;

pub use abi::*;
#[cfg(target_os = "linux")]
pub(crate) use helpers::{
    ap_vlan_create_message, ap_vlan_parent_addr, default_multicast_key_attr,
    first_free_per_sta_vlan_id, per_sta_vif_name, resolve_mld_addresses,
};
pub use helpers::{chandef_is_dfs, fallback_channel};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{
    run_offload_ap, run_offload_aps, scan_interface, set_interface_frequency, ApRuntimePaths,
    NetlinkLink, ScanResult,
};
