//! Wi-Fi 7 / 802.11be structures.

pub use super::common::{PhyCapabilities, PhyMode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MldLinkProfile {
    pub link_id: u8,
    pub mac: [u8; 6],
    /// Link-specific Capability Information field. It follows STA Info in an
    /// association-request Per-STA Profile.
    pub capability: Option<u16>,
    /// Link-specific IEs after Capability Information. Missing IEs inherit from
    /// the outer association request.
    pub ies: Vec<u8>,
}
