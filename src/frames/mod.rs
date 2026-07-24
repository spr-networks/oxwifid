//! Low-level IEEE 802.11 wire-format support.
//!
//! Most callers should prefer the crate-level protocol domains (`auth`,
//! `mlo`, `group_keys`, `roaming`, and `action_frames`). The root exports are
//! retained because `barely_ap::dot11` is a compatibility alias for this
//! module.

pub mod channels;
pub mod data;
pub mod information_elements;
pub mod management;

pub use channels::*;
pub use data::*;
pub use information_elements::*;
pub use management::*;

// Compatibility surface for callers of the historic `dot11` module. Protocol
// implementations live in their owning domains; this module only re-exports
// their public wire helpers.
pub use crate::action_frames::build_action_frame;
pub use crate::action_frames::sa_query::*;
pub use crate::action_frames::twt::*;
pub use crate::auth::eapol::*;
pub use crate::auth::frames::*;
pub use crate::auth::rsn::*;
pub use crate::auth::wpa3::owe::*;
pub use crate::group_keys::handshake::*;
pub use crate::group_keys::kde::*;
pub use crate::group_keys::management::*;
pub use crate::mlo::elements::*;
pub use crate::mlo::handshake::*;
pub use crate::mlo::keys::*;
pub use crate::roaming::btm::*;
pub use crate::roaming::neighbor_report::*;
pub use crate::structures::common::{AuthBody, Dot11, IeParseError};
pub use crate::structures::common::{PhyCapabilities, PhyMode};
pub use crate::structures::security::{DataCipher, EapolKey, KeyInfo, KeyMic, SecurityMode};
pub use crate::structures::wifi7::MldLinkProfile;
