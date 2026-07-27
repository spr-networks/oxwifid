//! Access-point state and orchestration.
//!
//! Incoming 802.11 frames are fed to [`Ap::handle_incoming`], which mutates
//! state and returns frames to transmit plus decrypted Ethernet packets for the
//! AP network stack. Protocol-specific behavior lives in the focused child
//! modules; this facade owns shared state and the stable public API.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

use crate::auth::{crypto, wpa3::sae};
use crate::frames as dot11;

mod output;
mod runtime;
mod state;
mod station;

pub use output::{ApEvent, MldLink, Outgoing};
pub use state::Ap;
pub(crate) use station::PreparedCredentials;
pub use station::{CredentialEntry, Station};

use runtime::{
    AsyncSae, PendingHandshake, PendingSaeCommit, PmksaEntry, RequestRate, SaeCommitJob,
    SaeCommitOutcome, SaeCommitResult,
};
use station::PtkCandidate;

/// Per-station auth/assoc backoff (matches `BACKOFF = 0.25`).
const BACKOFF: Duration = Duration::from_millis(250);
const REQUEST_RATE_WINDOW: Duration = Duration::from_secs(1);
const AUTH_REQUEST_BURST: u16 = 16;
const ASSOC_REQUEST_BURST: u16 = 8;
const REQUEST_RATE_ENTRY_MAX: usize = 1024;

/// Retransmit a pending EAPOL m1/m3 if its m2/m4 hasn't arrived within this long
/// (reference AP's `eapol_key_timeout_subseq`), up to [`MAX_EAPOL_RETRIES`] times
/// before giving up and deauthenticating.
const EAPOL_TIMEOUT: Duration = Duration::from_millis(1000);
/// The *first* retransmit fires much sooner, mirroring reference AP's
/// `eapol_key_timeout_first = 100 ms`. This matters on real hardware: an m1 sent
/// the instant the STA associates can be dropped before the driver has the
/// station fully set up for downlink control-port TX. Waiting a full second to
/// resend lets the client's own post-association 4-way timer fire first — it then
/// deauthenticates and reconnects, and because each reconnect mints a fresh
/// ANonce, the client's Message 2 ends up keyed to a stale m1's ANonce and the
/// MIC never verifies (a self-sustaining livelock seen on ath12k). Resending
/// within ~100 ms lands a second m1 (identical ANonce) inside the *same*
/// association, exactly as reference AP does, so the handshake completes.
const EAPOL_FIRST_TIMEOUT: Duration = Duration::from_millis(100);
/// Match the normal authenticator retry budget. In particular, do not use a
/// large retry count to compensate for a slow hardware TX-status event: every
/// retry is another real frame queued in the driver, and flooding that queue can
/// put message 3 behind dozens of stale message-1 copies.
/// reference AP's default dot11RSNAConfigPairwiseUpdateCount is four total sends:
/// the initial message plus three retransmissions.
const MAX_EAPOL_RETRIES: u8 = 3;

/// How long an associated PMF station has to answer the SA Query provoked by an
/// unprotected Authentication or (Re)Association Request bearing its address
/// (IEEE 802.11 `dot11AssociationSAQueryMaximumTimeout`, 1000 TU). If it stays
/// silent the association really is stale and is torn down, so a genuine
/// reconnect is delayed by ~1 s rather than blocked; if it answers, the spoofed
/// frame is discarded without disturbing the session.
const SA_QUERY_TIMEOUT: Duration = Duration::from_millis(1024);

/// How long an unconsumed message-1 ANonce/replay pair is held for a reconnecting
/// station. The pair is destroyed as soon as message 2 verifies, before either
/// peer can install the PTK.
const ANONCE_HOLD: Duration = Duration::from_secs(10);

/// Cap on the PMKSA (fast-reconnect PMK) cache. reference AP bounds + expires these;
/// we cap the size so the cache can't grow without bound over a long uptime with
/// many distinct clients. An evicted client simply re-runs the full SAE/auth.
const PMKSA_CACHE_MAX: usize = 256;
/// IEEE 802.11's default PMKSA lifetime (12 hours).
const PMKSA_LIFETIME: Duration = Duration::from_secs(12 * 60 * 60);
/// Require an SAE anti-clogging token once this many exchanges are incomplete.
const SAE_ANTI_CLOGGING_THRESHOLD: usize = 5;
/// Absolute cap even for peers that returned a valid anti-clogging token.
const SAE_INCOMPLETE_MAX: usize = 64;
const MAX_PACKET_NUMBER: u64 = 0x0000_ffff_ffff_ffff;
/// Incomplete SAE state is short-lived and must not accumulate indefinitely.
const SAE_AUTH_TIMEOUT: Duration = Duration::from_secs(5);
/// Stateless anti-clogging tokens are intentionally short-lived so an attacker
/// cannot harvest them ahead of time and bypass overload protection later.
const SAE_TOKEN_LIFETIME: Duration = Duration::from_secs(10);

fn is_broadcast(a: &[u8; 6]) -> bool {
    a == &[0xff; 6]
}

fn is_multicast(a: &[u8; 6]) -> bool {
    a[0] & 0x01 != 0
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("OS RNG available");
    b
}

fn random_nonzero_u64() -> u64 {
    loop {
        let value = u64::from_be_bytes(random_bytes());
        if value != 0 && value != u64::MAX {
            return value;
        }
    }
}

/// Increment a 6-octet BIP IPN, which is a LITTLE-endian counter in the MME
/// (octet 0 is least significant). Carries upward from octet 0, matching how
/// `dot11::bip_ipn` decodes it.
fn inc_ipn_le(ipn: &mut [u8; 6]) {
    for b in ipn.iter_mut() {
        *b = b.wrapping_add(1);
        if *b != 0 {
            break;
        }
    }
}

fn prepend_radiotap(frame: Vec<u8>) -> Vec<u8> {
    let mut f = dot11::RADIOTAP_TX.to_vec();
    f.extend_from_slice(&frame);
    f
}

/// The Key Descriptor Version an EAPOL-Key from this station must carry. It is
/// exactly the version of the MIC algorithm its AKM selects (2 for HMAC-SHA1,
/// 0 for SAE/OWE, 3 for PSK-SHA256).
fn expected_key_descriptor_version(mic: dot11::KeyMic) -> u16 {
    u16::from(mic.version())
}

fn key_info_matches(key_info: u16, expected: u16) -> bool {
    // The two top bits are reserved. Every defined state bit, including
    // Encrypted Key Data, must match the expected handshake message.
    key_info & !0xc000 == expected
}

fn message_2_security_matches(assoc_ies: &[u8], key_data: &[u8]) -> bool {
    let Ok(Some(assoc_rsn)) = dot11::find_ie_strict(assoc_ies, 48) else {
        return false;
    };
    let Ok(Some(m2_rsn)) = dot11::find_ie_strict(key_data, 48) else {
        return false;
    };
    if !dot11::rsn_negotiation_matches(assoc_rsn, m2_rsn) {
        return false;
    }
    let Ok(assoc_rsnxe) = dot11::find_ie_consistent(assoc_ies, 0xf4) else {
        return false;
    };
    let Ok(m2_rsnxe) = dot11::find_ie_consistent(key_data, 0xf4) else {
        return false;
    };
    assoc_rsnxe == m2_rsnxe
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transmit_packet_numbers_stop_at_48_bits() {
        let mac = [0x02, 0, 0, 0, 0, 1];
        let mut station = Station::new(mac);
        station.client_pn = MAX_PACKET_NUMBER;
        assert_eq!(station.next_client_pn(), Some(MAX_PACKET_NUMBER));
        assert_eq!(station.next_client_pn(), None);

        let mut ap = Ap::new("pn-test", "device-password", [0x02, 0, 0, 0, 0, 0], 1);
        ap.group_pn = MAX_PACKET_NUMBER;
        assert_eq!(ap.next_group_pn(), Some(MAX_PACKET_NUMBER));
        assert_eq!(ap.next_group_pn(), None);
    }
}

mod association;
mod beacon;
mod configuration;
mod data;
mod group_keys;
mod handshake;
mod lifecycle;
mod management;
mod mlo;
mod receive;
mod roaming;
mod sae_auth;
