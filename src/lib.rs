//! barely-ap: a minimal WPA2/CCMP 802.11 access point, ported from the
//! Python/Scapy reference implementation.

pub mod config;
pub mod crypto;
pub mod dot11;
pub mod fakenet;
pub mod ap;
pub mod client;
pub mod nan;
pub mod netlink;
pub mod raw_frames;
pub mod sae;
pub mod util;

/// Backwards-compatible alias for the transport/event-loop layer, which moved
/// into [`raw_frames`].
pub use raw_frames as netio;
