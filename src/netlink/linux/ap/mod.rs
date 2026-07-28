//! Kernel-offloaded access-point backend.
//!
//! The protocol engine owns 802.11 authentication and association semantics.
//! This module owns the Linux projection of that state: radio setup, nl80211
//! I/O, station publication, keys, AP_VLANs, and teardown.

use super::*;

mod capabilities;
mod cleanup;
mod commands;
mod events;
mod integration;
mod interfaces;
mod keys;
mod management_io;
mod publication;
mod radio;
mod regulatory;
mod routing;
mod setup;
mod state;
mod vlan;
mod workers;

use capabilities::*;
use commands::*;
use interfaces::*;
use keys::*;
use management_io::*;
use radio::native_u32;
use regulatory::*;
use routing::*;
use setup::*;
use state::*;
use vlan::*;
use workers::*;

pub use interfaces::{run_offload_aps, ApRuntimePaths};
pub use radio::run_offload_ap;
