use super::{
    Ap, ASSOC_REQUEST_BURST, AUTH_REQUEST_BURST, REQUEST_RATE_ENTRY_MAX, REQUEST_RATE_WINDOW,
};
use crate::auth::wpa3::sae;
use std::collections::HashMap;
use std::sync::mpsc;
use std::time::Instant;
use zeroize::Zeroize;

pub(super) struct PmksaEntry {
    pub(super) identity: [u8; 6],
    pub(super) pmk: [u8; 32],
    pub(super) sha256: bool,
    pub(super) expires_at: Instant,
}

pub(super) struct RequestRate {
    pub(super) auth_window: Instant,
    pub(super) auth_count: u16,
    pub(super) assoc_window: Instant,
    pub(super) assoc_count: u16,
    pub(super) last_seen: Instant,
}

impl RequestRate {
    fn new(now: Instant) -> RequestRate {
        RequestRate {
            auth_window: now,
            auth_count: 0,
            assoc_window: now,
            assoc_count: 0,
            last_seen: now,
        }
    }
}

impl Drop for PmksaEntry {
    fn drop(&mut self) {
        self.pmk.zeroize();
    }
}

#[derive(Clone, Copy)]
pub(super) struct PendingHandshake {
    pub(super) anonce: [u8; 32],
    pub(super) replay_counter: u64,
    pub(super) created_at: Instant,
}

pub(super) struct SaeCommitJob {
    pub(super) id: u64,
    pub(super) sta: [u8; 6],
    pub(super) h2e: bool,
    pub(super) ssid: Vec<u8>,
    pub(super) password: Vec<u8>,
    pub(super) sae_ap: [u8; 6],
    pub(super) sae_sta: [u8; 6],
    pub(super) peer_mld: Option<[u8; 6]>,
    pub(super) commit_payload: Vec<u8>,
}

impl Drop for SaeCommitJob {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

pub(super) enum SaeCommitOutcome {
    Complete {
        sae: Box<sae::Sae>,
        commit_body: Vec<u8>,
        confirm_body: Vec<u8>,
        rejected_groups: Vec<u16>,
    },
    Reflection,
    Failed(String),
}

pub(super) struct SaeCommitResult {
    pub(super) id: u64,
    pub(super) sta: [u8; 6],
    pub(super) h2e: bool,
    pub(super) peer_mld: Option<[u8; 6]>,
    pub(super) commit_payload: Vec<u8>,
    pub(super) outcome: SaeCommitOutcome,
}

pub(super) struct PendingSaeCommit {
    pub(super) id: u64,
    pub(super) commit_payload: Vec<u8>,
    pub(super) queued_at: Instant,
    pub(super) pending_confirm: Option<Vec<u8>>,
}

pub(super) struct AsyncSae {
    pub(super) jobs: mpsc::SyncSender<SaeCommitJob>,
    pub(super) results: mpsc::Receiver<SaeCommitResult>,
    pub(super) pending: HashMap<[u8; 6], PendingSaeCommit>,
    pub(super) next_id: u64,
}

fn allow_request(window: &mut Instant, count: &mut u16, burst: u16, now: Instant) -> bool {
    if now.duration_since(*window) >= REQUEST_RATE_WINDOW {
        *window = now;
        *count = 0;
    }
    if *count >= burst {
        return false;
    }
    *count += 1;
    true
}

impl Ap {
    fn request_rate_entry(&mut self, sta: [u8; 6], now: Instant) -> Option<&mut RequestRate> {
        if !self.request_rates.contains_key(&sta)
            && self.request_rates.len() >= REQUEST_RATE_ENTRY_MAX
        {
            self.request_rates
                .retain(|_, rate| now.duration_since(rate.last_seen) < REQUEST_RATE_WINDOW);
            if self.request_rates.len() >= REQUEST_RATE_ENTRY_MAX {
                return None;
            }
        }
        let rate = self
            .request_rates
            .entry(sta)
            .or_insert_with(|| RequestRate::new(now));
        rate.last_seen = now;
        Some(rate)
    }

    pub(super) fn allow_auth_request(&mut self, sta: [u8; 6], now: Instant) -> bool {
        let Some(rate) = self.request_rate_entry(sta, now) else {
            return false;
        };
        allow_request(
            &mut rate.auth_window,
            &mut rate.auth_count,
            AUTH_REQUEST_BURST,
            now,
        )
    }

    pub(super) fn allow_assoc_request(&mut self, sta: [u8; 6], now: Instant) -> bool {
        let Some(rate) = self.request_rate_entry(sta, now) else {
            return false;
        };
        allow_request(
            &mut rate.assoc_window,
            &mut rate.assoc_count,
            ASSOC_REQUEST_BURST,
            now,
        )
    }
}
