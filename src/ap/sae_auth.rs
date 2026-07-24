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
        self.stations
            .values()
            .filter(|s| s.sae.is_some() && !s.sae_confirmed)
            .count()
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
        if std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
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
                // wpa_supplicant then advances to its next configured group.
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
                .unwrap_or(false);
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
            let Some(mut password) = self
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
            let mut sae = if h2e {
                sae::Sae::new_h2e(&self.ssid, &password, None, &sae_ap, &sae_sta)
            } else {
                match sae::Sae::new_hunting_pecking(&password, &sae_ap, &sae_sta) {
                    Some(s) => s,
                    None => {
                        password.zeroize();
                        return;
                    }
                }
            };
            password.zeroize();
            if let Err(err) = sae.parse_peer_commit(&commit_payload) {
                eprintln!(
                    "AP: SAE commit parse failed from {}: {err:?}",
                    crate::util::bytes_to_mac(sta)
                );
                self.record_failure(sta, crate::failures::FailureKind::Sae);
                return;
            }
            let rejected_groups = sae.peer_rejected_groups();
            if !rejected_groups.is_empty() {
                eprintln!(
                    "AP: SAE H2E peer {} rejected groups {}; applying negotiated key salt",
                    crate::util::bytes_to_mac(&sae_sta),
                    rejected_groups
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
            sae.prepare_commit(None);
            // Reject a reflected commit (peer echoing our own scalar + element).
            if sae.is_reflection() {
                eprintln!(
                    "AP: SAE reflected commit from {}",
                    crate::util::bytes_to_mac(sta)
                );
                self.record_failure(sta, crate::failures::FailureKind::Sae);
                return;
            }
            if let Err(err) = sae.process_commit() {
                eprintln!(
                    "AP: SAE commit processing failed from {}: {err:?}",
                    crate::util::bytes_to_mac(sta)
                );
                self.record_failure(sta, crate::failures::FailureKind::Sae);
                return;
            }

            let mut commit_body = sae.write_commit();
            let Ok(mut confirm_body) = sae.write_confirm() else {
                return;
            };
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
                sta,
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
                sta,
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
            let entry = self
                .stations
                .entry(*sta)
                .or_insert_with(|| Station::new(*sta));
            entry.sae = Some(sae);
            entry.set_pmk(Some(pmk));
            pmk.zeroize();
            entry.sae_confirmed = false;
            entry.sae_h2e = h2e;
            entry.sha256 = true; // WPA3-SAE uses SHA-256 key descriptors + PMF
            if let Some(mld) = peer_mld {
                entry.client_mld_mac = Some(mld);
            }
            // Cache this response so an identical retried commit is answered
            // idempotently (see the guard above).
            entry.sae_resp = vec![commit.clone(), confirm.clone()];
            entry.sae_commit = commit_payload;
            entry.last_activity = Instant::now();

            out.tx(commit);
            out.tx(confirm);
        } else if seq == 2 {
            eprintln!(
                "AP: SAE confirm received from {} payload_len={}",
                crate::util::bytes_to_mac(sta),
                payload.len(),
            );
            // Verify the peer's confirm. Only a verified confirm completes SAE:
            // it gates association (see `handle_assoc_req`) and is the point at
            // which the PMK becomes mutually authenticated, so the PMKSA is
            // cached *here*, not on the unconfirmed commit.
            let confirm_result = self
                .stations
                .get_mut(sta)
                .and_then(|s| s.sae.as_mut())
                .map(|sae| sae.check_confirm(payload));
            match confirm_result {
                Some(Ok(())) => {}
                // An authenticated duplicate/lower counter is a replay, not a
                // password failure. Drop it without advancing state or logging
                // a false credential alert.
                Some(Err(sae::SaeError::ReplayedConfirm)) => return,
                // Confirm present but invalid -> wrong password / forged confirm.
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
                if std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
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
