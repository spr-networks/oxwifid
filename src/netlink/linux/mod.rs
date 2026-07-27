//! Linux nl80211 socket and [`Link`] implementation.

#![cfg(target_os = "linux")]

pub(super) use std::io;
pub(super) use std::os::unix::io::RawFd;
pub(super) use std::time::{Duration, Instant};

pub(super) use super::msg::{self, Attr, GenlMessage};
pub(super) use super::*;
pub(super) use crate::frames as dot11;
pub(super) use crate::raw_frames::Link;

mod ap;
mod interface;
mod link;
mod scan;
mod socket;

pub use ap::{run_offload_ap, run_offload_aps};
pub(super) use interface::{iface_set_mac, iface_set_state, iface_set_up};
pub use link::NetlinkLink;
pub use scan::{scan_interface, set_interface_frequency, ScanResult};
use socket::{resolve_family, NetlinkSocket};
