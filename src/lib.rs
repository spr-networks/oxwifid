//! barely-ap: a minimal 802.11 access point.
//!
//! The crate is organized by protocol domain for review and audit. [`frames`]
//! owns low-level wire encoding, [`auth`] owns authentication and key
//! establishment, and the remaining top-level modules expose focused MLO,
//! group-key, roaming, and action-frame surfaces.

pub mod action_frames;
pub mod ap;
pub mod auth;
pub mod client;
pub mod config;
pub mod control;
pub mod failures;
pub mod fakenet;
pub mod frames;
pub mod group_keys;
pub mod mlo;
pub mod nan;
pub mod netlink;
pub mod raw_frames;
pub mod roaming;
#[cfg(unix)]
pub mod spr;
pub mod structures;
pub mod uplink;
pub mod util;

/// Backwards-compatible name for the low-level 802.11 frame API.
pub use frames as dot11;

/// Backwards-compatible name for shared authentication cryptography.
pub use auth::crypto;

/// Backwards-compatible name for the WPA3 SAE implementation.
pub use auth::wpa3::sae;

/// Backwards-compatible alias for the transport/event-loop layer, which moved
/// into [`raw_frames`].
pub use raw_frames as netio;
