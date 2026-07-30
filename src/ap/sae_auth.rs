//! AP-side SAE authentication state-machine handling.

use super::*;

impl Ap {
    pub(super) fn sae_commit_token(
        payload: &[u8],
        h2e: bool,
    ) -> Option<(Vec<u8>, Option<[u8; 32]>)> {
        const COMMIT_LEN: usize = 2 + 3 * 32;
        if payload.len() < COMMIT_LEN {
            return None;
        }
        if !h2e {
            // Legacy SAE inserts the fixed-size token after the group ID and
            // before scalar/element. With no token, the core commit is 98 bytes.
            if payload.len() >= COMMIT_LEN + 32 {
                let mut token = [0u8; 32];
                token.copy_from_slice(&payload[2..34]);
                let mut commit = Vec::with_capacity(payload.len() - 32);
                commit.extend_from_slice(&payload[..2]);
                commit.extend_from_slice(&payload[34..]);
                return Some((commit, Some(token)));
            }
            return Some((payload.to_vec(), None));
        }

        // H2E carries the token in Extension IE 93 after scalar/element. Strip
        // exactly one well-formed token container while retaining other IEs
        // (Rejected Groups and MLO identity) in the canonical commit.
        let mut commit = payload[..COMMIT_LEN].to_vec();
        let mut token = None;
        let mut pos = COMMIT_LEN;
        while pos < payload.len() {
            if payload.len() - pos < 2 {
                return None;
            }
            let len = payload[pos + 1] as usize;
            let end = pos
                .checked_add(2 + len)
                .filter(|end| *end <= payload.len())?;
            if payload[pos] == 255 && len == 33 && payload[pos + 2] == 93 {
                if token.is_some() {
                    return None;
                }
                let mut value = [0u8; 32];
                value.copy_from_slice(&payload[pos + 3..end]);
                token = Some(value);
            } else {
                commit.extend_from_slice(&payload[pos..end]);
            }
            pos = end;
        }
        Some((commit, token))
    }

    pub(super) fn sae_token_at(
        &self,
        sta: &[u8; 6],
        h2e: bool,
        commit: &[u8],
        issued_at_secs: u64,
    ) -> [u8; 32] {
        let method = [u8::from(h2e)];
        let issued = issued_at_secs.to_be_bytes();
        let mut input =
            Vec::with_capacity(19 + issued.len() + sta.len() + method.len() + commit.len());
        input.extend_from_slice(b"rustap-sae-token-v1");
        input.extend_from_slice(&issued);
        input.extend_from_slice(sta);
        input.extend_from_slice(&method);
        input.extend_from_slice(commit);
        let mut mac = crypto::hmac_sha256(&self.sae_token_key, &input);
        let mut token = [0u8; 32];
        token[..8].copy_from_slice(&issued);
        token[8..].copy_from_slice(&mac[..24]);
        mac.zeroize();
        token
    }

    pub(super) fn sae_token(&self, sta: &[u8; 6], h2e: bool, commit: &[u8]) -> [u8; 32] {
        self.sae_token_at(sta, h2e, commit, self.boottime.elapsed().as_secs())
    }

    pub(super) fn valid_sae_token(
        &self,
        sta: &[u8; 6],
        h2e: bool,
        commit: &[u8],
        token: &[u8; 32],
    ) -> bool {
        let issued_at_secs = u64::from_be_bytes(token[..8].try_into().expect("token timestamp"));
        let now = self.boottime.elapsed().as_secs();
        let Some(age) = now.checked_sub(issued_at_secs) else {
            return false;
        };
        if age > SAE_TOKEN_LIFETIME.as_secs() {
            return false;
        }
        let mut expected = self.sae_token_at(sta, h2e, commit, issued_at_secs);
        let valid = crypto::constant_time_eq(&token[8..], &expected[8..]);
        expected.zeroize();
        valid
    }

    pub(super) fn request_sae_token(
        &mut self,
        sta: &[u8; 6],
        h2e: bool,
        commit: &[u8],
        out: &mut Outgoing,
    ) {
        let Some(group) = commit.get(..2) else {
            return;
        };
        let token = self.sae_token(sta, h2e, commit);
        let mut body = group.to_vec();
        if h2e {
            body.extend_from_slice(&[255, 33, 93]);
        }
        body.extend_from_slice(&token);
        let sc = self.next_sc();
        out.tx(dot11::build_sae_auth(
            sta,
            &self.mac,
            &self.mac,
            0,
            sc,
            1,
            dot11::STATUS_ANTI_CLOGGING_TOKEN_REQ,
            &body,
        ));
    }

    pub(super) fn incomplete_sae_count(&self) -> usize {
        let established = self
            .stations
            .values()
            .filter(|s| s.sae.is_some() && !s.sae_confirmed)
            .count();
        established
            + self
                .async_sae
                .as_ref()
                .map_or(0, |worker| worker.pending.len())
    }

    /// Drive the SAE (Dragonfly) exchange. Commit (seq 1) yields our commit +
    /// confirm; the peer's confirm (seq 2) completes authentication.
    pub(super) fn handle_sae_auth(
        &mut self,
        sta: &[u8; 6],
        seq: u16,
        status: u16,
        payload: &[u8],
        out: &mut Outgoing,
    ) {
        if crate::util::netlink_debug_enabled() {
            let grp = if seq == 1 && payload.len() >= 2 {
                u16::from_le_bytes([payload[0], payload[1]])
            } else {
                0
            };
            eprintln!(
                "AP: SAE seq={seq} status={status} group={grp} payload_len={} from {}",
                payload.len(),
                crate::util::bytes_to_mac(sta)
            );
        }
        if seq == 1 && !matches!(status, dot11::STATUS_SUCCESS | dot11::STATUS_SAE_H2E) {
            // SAE-PK (127) and other non-success commit status values are not
            // legacy SAE. reference AP answers these unsupported commit methods with
            // status 1 instead of feeding their payload into hunting-and-pecking.
            let sc = self.next_sc();
            out.tx(dot11::build_sae_auth(
                sta,
                &self.mac,
                &self.mac,
                0,
                sc,
                1,
                dot11::STATUS_UNSPECIFIED_FAILURE,
                &[],
            ));
            return;
        }
        if seq == 1 {
            let Some(group_bytes) = payload.get(..2) else {
                self.record_failure(sta, crate::failures::FailureKind::Sae);
                return;
            };
            let group = u16::from_le_bytes([group_bytes[0], group_bytes[1]]);
            if group != sae::SAE_GROUP_19 {
                // SAE group negotiation depends on an explicit status 77:
                // Silently dropping an unsupported commit leaves it retrying
                // the same group until authentication times out.
                let sc = self.next_sc();
                out.tx(dot11::build_sae_auth(
                    sta,
                    &self.mac,
                    &self.mac,
                    0,
                    sc,
                    1,
                    dot11::STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED,
                    group_bytes,
                ));
                return;
            }
            let h2e = status == dot11::STATUS_SAE_H2E;
            let Some((commit_payload, supplied_token)) = Self::sae_commit_token(payload, h2e)
            else {
                self.record_failure(sta, crate::failures::FailureKind::Sae);
                return;
            };
            // A duplicate can arrive while the worker is still deriving the
            // PWE. It is already represented by the queued job, so coalesce it
            // instead of consuming another queue slot/CPU pass.
            if self
                .async_sae
                .as_ref()
                .and_then(|worker| worker.pending.get(sta))
                .is_some_and(|pending| pending.commit_payload == commit_payload)
            {
                return;
            }
            // Idempotent retry: if the STA re-sends the identical commit while
            // SAE is still in progress, resend the cached commit+confirm instead
            // of resetting our scalar. A lost response on a flaky medium then
            // recovers rather than desyncing into an authentication loop.
            if let Some(s) = self.stations.get(sta) {
                if s.sae.is_some()
                    && !s.sae_confirmed
                    && !s.sae_resp.is_empty()
                    && s.sae_commit == commit_payload
                {
                    for f in s.sae_resp.clone() {
                        out.tx(f);
                    }
                    return;
                }
            }
            let incomplete = self.incomplete_sae_count();
            let existing_exchange = self
                .stations
                .get(sta)
                .map(|s| s.sae.is_some() && !s.sae_confirmed)
                .unwrap_or(false)
                || self
                    .async_sae
                    .as_ref()
                    .is_some_and(|worker| worker.pending.contains_key(sta));
            if !existing_exchange && incomplete >= SAE_INCOMPLETE_MAX {
                // Do no ECC work and allocate no state while the hard cap is
                // full. Expiration in tick/prune_idle makes this self-healing.
                self.request_sae_token(sta, h2e, &commit_payload, out);
                return;
            }
            // A new, distinct commit from a MAC that already has an incomplete
            // exchange must prove reachability before it can replace that
            // exchange and trigger another PWE/scalar-multiplication pass.
            if existing_exchange || incomplete >= SAE_ANTI_CLOGGING_THRESHOLD {
                let valid = supplied_token
                    .as_ref()
                    .map(|token| self.valid_sae_token(sta, h2e, &commit_payload, token))
                    .unwrap_or(false);
                if !valid {
                    self.request_sae_token(sta, h2e, &commit_payload, out);
                    return;
                }
            }
            // A worker may already be inside an uncancellable scalar
            // multiplication for this MAC. Even a valid token must not let one
            // peer enqueue a train of replacement jobs behind it; the peer will
            // retry after the bounded in-flight job completes.
            if self
                .async_sae
                .as_ref()
                .is_some_and(|worker| worker.pending.contains_key(sta))
            {
                return;
            }
            // Pick the PWE method the STA advertised: status 126 = Hash-to-Element
            // (the preferred, side-channel-free derivation), otherwise legacy
            // hunting-and-pecking (whose derivation is made constant-time in
            // `derive_pwe_hunting_pecking` so it has no Dragonblood timing leak).
            let auth_mld = self
                .mld
                .then(|| Self::sae_auth_mld_mac(seq, &commit_payload))
                .flatten();
            // Apple can first try a cached-PMKSA MLO association and only then
            // fall back to full SAE. That association has already supplied and
            // validated the non-AP MLD identity. Some drivers deliver the
            // subsequent SAE commit link-addressed or without exposing its
            // Authentication MLE to userspace; in that case retain the stable
            // identity instead of attempting credential lookup by the rotating
            // link MAC. The later association-to-SAE identity check still
            // rejects any conflicting MLD address.
            let known_mld = self
                .mld
                .then(|| self.stations.get(sta).and_then(|s| s.client_mld_mac))
                .flatten();
            let peer_mld = auth_mld.or(known_mld);
            // Match reference AP's ap_sta_is_mld() split: an MLD AP still uses its
            // link address for a legacy station. The MLD address is an SAE
            // identity only when the peer's Authentication frame identifies
            // that peer as an MLD.
            let sae_ap = if peer_mld.is_some() {
                self.mld_mac
            } else {
                self.mac
            };
            let sae_sta = peer_mld.unwrap_or(*sta);
            // A reference AP-style credential file may bind a different SAE
            // password to each link-addressed station. Select and own it before
            // mutably borrowing the SAE/station state below.
            let Some(password) = self
                .sae_password_for(&sae_sta, peer_mld.as_ref().map(|_| sta))
                .map(<[u8]>::to_vec)
            else {
                eprintln!(
                    "AP: SAE credential lookup failed link={} auth_mld={} known_mld={} identity={}",
                    crate::util::bytes_to_mac(sta),
                    auth_mld
                        .as_ref()
                        .map(crate::util::bytes_to_mac)
                        .unwrap_or_else(|| "-".to_string()),
                    known_mld
                        .as_ref()
                        .map(crate::util::bytes_to_mac)
                        .unwrap_or_else(|| "-".to_string()),
                    crate::util::bytes_to_mac(&sae_sta)
                );
                self.record_failure(sta, crate::failures::FailureKind::Sae);
                return;
            };
            eprintln!(
                "AP: SAE commit link={} auth_mld={} known_mld={} identity={} ap_identity={} h2e={h2e}",
                crate::util::bytes_to_mac(sta),
                auth_mld
                    .as_ref()
                    .map(crate::util::bytes_to_mac)
                    .unwrap_or_else(|| "-".to_string()),
                known_mld
                    .as_ref()
                    .map(crate::util::bytes_to_mac)
                    .unwrap_or_else(|| "-".to_string()),
                crate::util::bytes_to_mac(&sae_sta),
                crate::util::bytes_to_mac(&sae_ap),
            );
            let job = SaeCommitJob {
                id: 0,
                sta: *sta,
                h2e,
                ssid: self.ssid.clone(),
                password,
                sae_ap,
                sae_sta,
                peer_mld,
                commit_payload,
            };
            if self.async_sae.is_some() {
                self.queue_sae_commit(job, out);
            } else {
                let result = Self::compute_sae_commit(job);
                self.finish_sae_commit(result, None, out);
            }
        } else if seq == 2 {
            if let Some(pending) = self
                .async_sae
                .as_mut()
                .and_then(|worker| worker.pending.get_mut(sta))
            {
                // Worker completion and the peer's confirm are two independent
                // inputs. Hold the confirm so completion is applied first even
                // on very fast clients / slow CPUs.
                pending.pending_confirm = Some(payload.to_vec());
                return;
            }
            self.finish_sae_confirm(sta, payload);
        }
    }

    /// Move SAE's PWE/ECC work off the caller's frame-receive thread. The queue
    /// is deliberately bounded like the reference implementation's commit
    /// queue; duplicate commits are coalesced in `handle_sae_auth`.
    pub fn enable_async_sae(&mut self) {
        if self.async_sae.is_some() {
            return;
        }
        const SAE_WORK_QUEUE_MAX: usize = 15;
        let (job_tx, job_rx) = std::sync::mpsc::sync_channel(SAE_WORK_QUEUE_MAX);
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let spawn = std::thread::Builder::new()
            .name("rustap-sae".to_string())
            .spawn(move || {
                while let Ok(job) = job_rx.recv() {
                    let result = Self::compute_sae_commit(job);
                    if result_tx.send(result).is_err() {
                        break;
                    }
                }
            });
        match spawn {
            Ok(_) => {
                self.async_sae = Some(AsyncSae {
                    jobs: job_tx,
                    results: result_rx,
                    pending: HashMap::new(),
                    next_id: 1,
                });
            }
            Err(err) => {
                eprintln!("AP: cannot start SAE worker; using synchronous SAE: {err}");
            }
        }
    }

    fn queue_sae_commit(&mut self, mut job: SaeCommitJob, out: &mut Outgoing) {
        let queued_at = Instant::now();
        let (id, sta, commit_payload, send) = {
            let worker = self.async_sae.as_mut().expect("worker enabled");
            job.id = worker.next_id;
            worker.next_id = worker.next_id.wrapping_add(1).max(1);
            let id = job.id;
            let sta = job.sta;
            let commit_payload = job.commit_payload.clone();
            (id, sta, commit_payload, worker.jobs.try_send(job))
        };
        match send {
            Ok(()) => {
                let worker = self.async_sae.as_mut().expect("worker enabled");
                worker.pending.insert(
                    sta,
                    PendingSaeCommit {
                        id,
                        commit_payload,
                        queued_at,
                        pending_confirm: None,
                    },
                );
                self.schedule_maintenance(queued_at + SAE_AUTH_TIMEOUT);
            }
            Err(std::sync::mpsc::TrySendError::Full(job)) => {
                self.request_sae_token(&job.sta, job.h2e, &job.commit_payload, out);
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(job)) => {
                eprintln!("AP: SAE worker stopped; rejecting commit");
                self.record_failure(&job.sta, crate::failures::FailureKind::Sae);
                self.async_sae = None;
            }
        }
    }

    fn compute_sae_commit(job: SaeCommitJob) -> SaeCommitResult {
        let mut sae = if job.h2e {
            sae::Sae::new_h2e(&job.ssid, &job.password, None, &job.sae_ap, &job.sae_sta)
        } else {
            let Some(sae) = sae::Sae::new_hunting_pecking(&job.password, &job.sae_ap, &job.sae_sta)
            else {
                return SaeCommitResult {
                    id: job.id,
                    sta: job.sta,
                    h2e: job.h2e,
                    peer_mld: job.peer_mld,
                    commit_payload: job.commit_payload.clone(),
                    outcome: SaeCommitOutcome::Failed(
                        "hunting-and-pecking found no password element".to_string(),
                    ),
                };
            };
            sae
        };
        if let Err(err) = sae.parse_peer_commit(&job.commit_payload) {
            return SaeCommitResult {
                id: job.id,
                sta: job.sta,
                h2e: job.h2e,
                peer_mld: job.peer_mld,
                commit_payload: job.commit_payload.clone(),
                outcome: SaeCommitOutcome::Failed(format!("commit parse failed: {err:?}")),
            };
        }
        let rejected_groups = sae.peer_rejected_groups();
        sae.prepare_commit(None);
        if sae.is_reflection() {
            return SaeCommitResult {
                id: job.id,
                sta: job.sta,
                h2e: job.h2e,
                peer_mld: job.peer_mld,
                commit_payload: job.commit_payload.clone(),
                outcome: SaeCommitOutcome::Reflection,
            };
        }
        if let Err(err) = sae.process_commit() {
            return SaeCommitResult {
                id: job.id,
                sta: job.sta,
                h2e: job.h2e,
                peer_mld: job.peer_mld,
                commit_payload: job.commit_payload.clone(),
                outcome: SaeCommitOutcome::Failed(format!("commit processing failed: {err:?}")),
            };
        }
        let commit_body = sae.write_commit();
        let confirm_body = match sae.write_confirm() {
            Ok(body) => body,
            Err(err) => {
                return SaeCommitResult {
                    id: job.id,
                    sta: job.sta,
                    h2e: job.h2e,
                    peer_mld: job.peer_mld,
                    commit_payload: job.commit_payload.clone(),
                    outcome: SaeCommitOutcome::Failed(format!(
                        "confirm generation failed: {err:?}"
                    )),
                };
            }
        };
        SaeCommitResult {
            id: job.id,
            sta: job.sta,
            h2e: job.h2e,
            peer_mld: job.peer_mld,
            commit_payload: job.commit_payload.clone(),
            outcome: SaeCommitOutcome::Complete {
                sae: Box::new(sae),
                commit_body,
                confirm_body,
                rejected_groups,
            },
        }
    }

    pub(super) fn poll_sae_work(&mut self, out: &mut Outgoing) {
        while let Some(worker) = self.async_sae.as_ref() {
            let result = match worker.results.try_recv() {
                Ok(result) => result,
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    eprintln!("AP: SAE worker result channel closed");
                    self.async_sae = None;
                    break;
                }
            };
            let pending_confirm = {
                let worker = self.async_sae.as_mut().expect("worker present");
                let matches = worker.pending.get(&result.sta).is_some_and(|pending| {
                    pending.id == result.id && pending.commit_payload == result.commit_payload
                });
                if !matches {
                    continue;
                }
                worker
                    .pending
                    .remove(&result.sta)
                    .and_then(|pending| pending.pending_confirm)
            };
            self.finish_sae_commit(result, pending_confirm, out);
        }
    }

    fn finish_sae_commit(
        &mut self,
        result: SaeCommitResult,
        pending_confirm: Option<Vec<u8>>,
        out: &mut Outgoing,
    ) {
        let SaeCommitResult {
            sta,
            h2e,
            peer_mld,
            commit_payload,
            outcome,
            ..
        } = result;
        let SaeCommitOutcome::Complete {
            sae,
            mut commit_body,
            mut confirm_body,
            rejected_groups,
        } = outcome
        else {
            match outcome {
                SaeCommitOutcome::Reflection => {
                    eprintln!(
                        "AP: SAE reflected commit from {}",
                        crate::util::bytes_to_mac(&sta)
                    );
                }
                SaeCommitOutcome::Failed(err) => {
                    eprintln!(
                        "AP: SAE commit failed from {}: {err}",
                        crate::util::bytes_to_mac(&sta)
                    );
                }
                SaeCommitOutcome::Complete { .. } => unreachable!(),
            }
            self.record_failure(&sta, crate::failures::FailureKind::Sae);
            return;
        };
        if !rejected_groups.is_empty() {
            eprintln!(
                "AP: SAE H2E peer {} rejected groups {}; applying negotiated key salt",
                crate::util::bytes_to_mac(&peer_mld.unwrap_or(sta)),
                rejected_groups
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }
        if peer_mld.is_some() {
            let ml = dot11::multi_link_auth(&self.mld_mac);
            commit_body.extend_from_slice(&ml);
            confirm_body.extend_from_slice(&ml);
        }
        let resp_status = if h2e {
            dot11::STATUS_SAE_H2E
        } else {
            dot11::STATUS_SUCCESS
        };
        self.sc = -1;
        let sc1 = self.next_sc();
        let commit = dot11::build_sae_auth(
            &sta,
            &self.mac,
            &self.mac,
            0,
            sc1,
            1,
            resp_status,
            &commit_body,
        );
        let sc2 = self.next_sc();
        let confirm = dot11::build_sae_auth(
            &sta,
            &self.mac,
            &self.mac,
            0,
            sc2,
            2,
            dot11::STATUS_SUCCESS,
            &confirm_body,
        );

        let mut pmk = [0u8; 32];
        pmk.copy_from_slice(&sae.pmk);
        let now = Instant::now();
        let entry = self
            .stations
            .entry(sta)
            .or_insert_with(|| Station::new(sta));
        entry.sae = Some(*sae);
        entry.set_pmk(Some(pmk));
        pmk.zeroize();
        entry.sae_confirmed = false;
        entry.sae_h2e = h2e;
        entry.sha256 = true;
        entry.psk_sha256 = false;
        entry.pmf = true;
        if let Some(mld) = peer_mld {
            entry.client_mld_mac = Some(mld);
        }
        entry.sae_resp = vec![commit.clone(), confirm.clone()];
        entry.sae_commit = commit_payload;
        entry.last_activity = now;
        self.schedule_maintenance(now + SAE_AUTH_TIMEOUT);
        out.tx(commit);
        out.tx(confirm);
        if let Some(payload) = pending_confirm {
            self.finish_sae_confirm(&sta, &payload);
        }
    }

    fn finish_sae_confirm(&mut self, sta: &[u8; 6], payload: &[u8]) {
        eprintln!(
            "AP: SAE confirm received from {} payload_len={}",
            crate::util::bytes_to_mac(sta),
            payload.len(),
        );
        let confirm_result = self
            .stations
            .get_mut(sta)
            .and_then(|s| s.sae.as_mut())
            .map(|sae| sae.check_confirm(payload));
        match confirm_result {
            Some(Ok(())) => {}
            Some(Err(sae::SaeError::ReplayedConfirm)) => return,
            Some(Err(err)) => {
                eprintln!(
                    "AP: SAE confirm verification failed from {}: {err:?}",
                    crate::util::bytes_to_mac(sta)
                );
                self.record_failure(sta, crate::failures::FailureKind::Sae);
                return;
            }
            None => {
                eprintln!(
                    "AP: SAE confirm from {} has no matching commit state",
                    crate::util::bytes_to_mac(sta)
                );
                return;
            }
        }
        let confirmed = self
            .stations
            .get(sta)
            .and_then(|s| s.sae.as_ref())
            .map(|sae| (sae.pmkid.clone(), sae.pmk.clone()));
        let identity = self
            .stations
            .get(sta)
            .and_then(|s| s.client_mld_mac)
            .unwrap_or(*sta);
        if let Some(s) = self.stations.get_mut(sta) {
            s.sae_confirmed = true;
        }
        eprintln!(
            "AP: SAE confirm verified for {}",
            crate::util::bytes_to_mac(sta),
        );
        if let Some((pmkid, mut pmk)) = confirmed {
            if crate::util::netlink_debug_enabled() {
                let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
                eprintln!("AP: SAE confirmed pmkid={} pmk={}", hex(&pmkid), hex(&pmk));
            }
            if pmkid.len() == 16 && pmk.len() == 32 {
                let mut id = [0u8; 16];
                id.copy_from_slice(&pmkid);
                let mut k = [0u8; 32];
                k.copy_from_slice(&pmk);
                self.cache_pmksa(id, identity, k, true);
                k.zeroize();
            }
            pmk.zeroize();
        }
    }

    pub(super) fn sae_auth_mld_mac(seq: u16, payload: &[u8]) -> Option<[u8; 6]> {
        const SAE_GROUP19_COMMIT_LEN: usize = 2 + 3 * 32;
        const SAE_CONFIRM_LEN: usize = 2 + 32;
        let ies = match seq {
            1 => payload.get(SAE_GROUP19_COMMIT_LEN..)?,
            2 => payload.get(SAE_CONFIRM_LEN..)?,
            _ => return None,
        };
        dot11::parse_mld_mac(ies)
    }
}
