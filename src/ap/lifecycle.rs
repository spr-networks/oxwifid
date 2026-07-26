//! Retry timers, PMKSA maintenance, station lifecycle, and event reporting.

use super::*;

impl Ap {
    /// The kernel reported an 802.11 ACK (`CONTROL_PORT_FRAME_TX_STATUS`) for
    /// EAPOL message 1. Like reference AP, stretch the short initial timeout to the
    /// normal interval from the ACK time. Message 3 keeps its short first timeout.
    pub fn note_eapol_acked(&mut self, sta: &[u8; 6]) {
        if let Some(s) = self.stations.get_mut(sta) {
            if !s.awaiting_m4 && !s.group_rekeying {
                s.eapol_acked = true;
                s.eapol_tx = Instant::now();
            }
        }
        self.arm_eapol_timer(sta);
    }

    /// The transport held the first EAPOL-Key frame until the successful
    /// Association Response was acknowledged and is releasing it now. Start the
    /// retry clock at the real transmission time instead of when the AP state
    /// machine originally produced the frame.
    pub fn note_eapol_transmitted(&mut self, sta: &[u8; 6]) {
        if let Some(s) = self.stations.get_mut(sta) {
            s.eapol_tx = Instant::now();
            s.eapol_retries = 0;
            s.eapol_acked = false;
        }
        self.arm_eapol_timer(sta);
    }

    /// The successful Association Response was not acknowledged. The netlink
    /// transport removes the kernel station in this case, so cancel the 4-way
    /// work that was prepared speculatively before the response was sent. Keep
    /// the authentication/ANonce state so a retransmitted association request
    /// can restart cleanly without racing an obsolete EAPOL retry.
    pub fn note_assoc_response_not_acked(&mut self, sta: &[u8; 6]) {
        if let Some(s) = self.stations.get_mut(sta) {
            s.pending_eapol = None;
            s.eapol_ready = false;
            s.awaiting_m4 = false;
            s.ptk_candidates.clear();
            // An initial association has no installed PTK to preserve. A
            // suppressed reassociation can, however, belong to a station whose
            // old association is still authorized until transport cleanup
            // completes. Cancelling the unsent *new* M1 must not erase that
            // established session's data key or turn cancellation into a
            // premature disconnect.
            if !s.associated {
                s.kck.zeroize();
                s.kek.zeroize();
                s.tk.zeroize();
                s.pairwise_tk.zeroize();
            }
            s.eapol_retries = 0;
            s.eapol_acked = false;
        }
        self.cancel_eapol_timer(sta);
    }

    /// Whether a station has completed the handshake.
    pub fn is_associated(&self, sta: &[u8; 6]) -> bool {
        self.stations
            .get(sta)
            .map(|s| s.associated)
            .unwrap_or(false)
    }

    /// Periodic maintenance for handshake reliability: retransmit any pending
    /// EAPOL m1/m3 whose m2/m4 hasn't arrived within the EAPOL timeout, and
    /// deauthenticate (and drop) a station whose 4-way still hasn't completed
    /// after the configured retry limit. The transport calls this on its tick so a
    /// single dropped handshake frame self-heals instead of stalling forever.
    pub fn tick(&mut self) -> Outgoing {
        let mut out = Outgoing::default();
        let now = Instant::now();
        self.poll_sae_work(&mut out);
        if self
            .maintenance_deadline
            .is_some_and(|deadline| now >= deadline)
        {
            self.run_deadline_maintenance(now);
        }

        // Key lifecycle: a queued strict rekey (a station left) or the periodic
        // `wpa_group_rekey` interval triggers a Group Key Handshake. rekey_gtk()
        // coalesces if one is already in flight, and arms each msg 1 for
        // retransmit through the loop below.
        // Keep the group-key timer running while the BSS is idle too, matching
        // reference AP. Otherwise an AP left idle past the interval starts a
        // Group Key Handshake immediately after its first station completes the
        // 4-way. Apart from being needless (M3 already delivered the current
        // keys), that exposed clients to a second key transition before their
        // data path had settled.
        let periodic = self.group_rekey_secs > 0
            && now.duration_since(self.last_group_rekey)
                >= Duration::from_secs(self.group_rekey_secs);
        if self.group_rekey_due || periodic {
            self.group_rekey_due = false;
            out.frames.extend(self.rekey_gtk());
        }

        while self
            .eapol_deadlines
            .peek()
            .is_some_and(|Reverse((deadline, _, _))| *deadline <= now)
        {
            let Reverse((_deadline, generation, mac)) =
                self.eapol_deadlines.pop().expect("peeked deadline");
            let action = {
                let Some(s) = self.stations.get_mut(&mac) else {
                    continue;
                };
                if s.eapol_timer_generation != generation || s.pending_eapol.is_none() {
                    continue;
                }
                if s.eapol_retries >= MAX_EAPOL_RETRIES {
                    Some(Err((s.group_rekeying, s.awaiting_m4, s.eapol_retries)))
                } else {
                    let frame = s.pending_eapol.clone().expect("checked above");
                    s.eapol_tx = now;
                    s.eapol_retries += 1;
                    s.eapol_acked = false;
                    s.eapol_timer_generation = s.eapol_timer_generation.wrapping_add(1);
                    let next_generation = s.eapol_timer_generation;
                    Some(Ok((frame, next_generation)))
                }
            };
            match action {
                Some(Ok((frame, next_generation))) => {
                    out.frames.push(frame);
                    self.eapol_deadlines
                        .push(Reverse((now + EAPOL_TIMEOUT, next_generation, mac)));
                }
                Some(Err((group_rekeying, awaiting_m4, retries))) => {
                    eprintln!(
                        "AP: {} timeout for {} after {} retries",
                        if group_rekeying {
                            "group-key handshake"
                        } else if awaiting_m4 {
                            "4-way message 3"
                        } else {
                            "4-way message 1"
                        },
                        crate::util::bytes_to_mac(&mac),
                        retries,
                    );
                    self.disconnect(&mac, 15);
                    let deauth = dot11::build_deauth(&self.mac, &mac, 15);
                    out.tx(deauth);
                }
                None => {}
            }
        }
        out
    }

    pub(super) fn schedule_maintenance(&mut self, deadline: Instant) {
        if self
            .maintenance_deadline
            .is_none_or(|current| deadline < current)
        {
            self.maintenance_deadline = Some(deadline);
        }
    }

    pub(super) fn arm_eapol_timer(&mut self, sta: &[u8; 6]) {
        let Some(s) = self.stations.get_mut(sta) else {
            return;
        };
        s.eapol_timer_generation = s.eapol_timer_generation.wrapping_add(1);
        let generation = s.eapol_timer_generation;
        let Some(_) = s.pending_eapol else {
            return;
        };
        let timeout = if s.eapol_retries == 0 && !s.eapol_acked {
            EAPOL_FIRST_TIMEOUT
        } else {
            EAPOL_TIMEOUT
        };
        self.eapol_deadlines
            .push(Reverse((s.eapol_tx + timeout, generation, *sta)));
    }

    pub(super) fn cancel_eapol_timer(&mut self, sta: &[u8; 6]) {
        if let Some(s) = self.stations.get_mut(sta) {
            s.eapol_timer_generation = s.eapol_timer_generation.wrapping_add(1);
        }
    }

    fn run_deadline_maintenance(&mut self, now: Instant) {
        self.pending_anonce
            .retain(|_, pending| now.duration_since(pending.created_at) < ANONCE_HOLD);
        if let Some(worker) = self.async_sae.as_mut() {
            worker
                .pending
                .retain(|_, pending| now.duration_since(pending.queued_at) < SAE_AUTH_TIMEOUT);
        }
        let stale_sae: Vec<[u8; 6]> = self
            .stations
            .iter()
            .filter(|(_, s)| {
                !s.associated
                    && s.sae.is_some()
                    && now.duration_since(s.last_activity) >= SAE_AUTH_TIMEOUT
            })
            .map(|(mac, _)| *mac)
            .collect();
        for mac in stale_sae {
            self.disconnect(&mac, 15);
        }
        let unresponsive: Vec<[u8; 6]> = self
            .stations
            .iter()
            .filter(|(_, s)| {
                s.sa_query
                    .is_some_and(|(_, started)| now.duration_since(started) >= SA_QUERY_TIMEOUT)
            })
            .map(|(mac, _)| *mac)
            .collect();
        for mac in unresponsive {
            eprintln!(
                "AP: SA Query unanswered by {}; retiring the association",
                crate::util::bytes_to_mac(&mac)
            );
            self.disconnect(&mac, 15);
        }
        self.expire_pmksa();

        let mut next = None;
        let mut consider = |deadline: Instant| {
            if deadline > now && next.is_none_or(|current| deadline < current) {
                next = Some(deadline);
            }
        };
        for pending in self.pending_anonce.values() {
            consider(pending.created_at + ANONCE_HOLD);
        }
        for station in self.stations.values() {
            if !station.associated && station.sae.is_some() && !station.sae_confirmed {
                consider(station.last_activity + SAE_AUTH_TIMEOUT);
            }
            if let Some((_, started)) = station.sa_query {
                consider(started + SA_QUERY_TIMEOUT);
            }
        }
        for entry in self.pmksa_cache.values() {
            consider(entry.expires_at);
        }
        if let Some(worker) = self.async_sae.as_ref() {
            for pending in worker.pending.values() {
                consider(pending.queued_at + SAE_AUTH_TIMEOUT);
            }
        }
        self.maintenance_deadline = next;
    }

    /// Test hook: age the group-rekey clock past `wpa_group_rekey` so the next
    /// [`Ap::tick`] performs a periodic Group Key Handshake. Set a small
    /// `wpa_group_rekey` first so the back-dated instant stays valid.
    #[doc(hidden)]
    pub fn test_expire_group_rekey(&mut self) {
        let ago = Duration::from_secs(self.group_rekey_secs.saturating_add(1));
        self.last_group_rekey = Instant::now()
            .checked_sub(ago)
            .unwrap_or(self.last_group_rekey);
    }

    /// Test hook: clear the per-station auth/assoc backoff so an immediate
    /// re-authentication is treated as a genuine new session (not a retransmit),
    /// as a real reconnect seconds/minutes later would be.
    #[doc(hidden)]
    pub fn test_clear_auth_backoff(&mut self) {
        for s in self.stations.values_mut() {
            s.last_auth = None;
            s.last_assoc = None;
        }
        self.request_rates.clear();
    }

    /// Test hook: age every pending EAPOL frame past the retransmit timeout so a
    /// subsequent [`Ap::tick`] retransmits (or times out) deterministically.
    #[doc(hidden)]
    pub fn test_expire_eapol(&mut self) {
        let past = Instant::now() - EAPOL_TIMEOUT - Duration::from_millis(1);
        let mut armed = Vec::new();
        for (mac, s) in self.stations.iter_mut() {
            if s.pending_eapol.is_some() {
                s.eapol_tx = past;
                armed.push(*mac);
            }
        }
        for mac in armed {
            self.arm_eapol_timer(&mac);
        }
    }

    /// Whether a station negotiated the SHA-256 key hierarchy (SAE, OWE, or
    /// PSK-SHA256). Distinct from PMF — see [`Ap::station_uses_pmf`].
    pub fn station_uses_sha256(&self, sta: &[u8; 6]) -> bool {
        self.stations.get(sta).map(|s| s.sha256).unwrap_or(false)
    }

    /// Whether management frame protection is in force for a station.
    pub fn station_uses_pmf(&self, sta: &[u8; 6]) -> bool {
        self.stations.get(sta).map(|s| s.pmf).unwrap_or(false)
    }

    /// Test hook: age every outstanding SA Query past its timeout so the next
    /// [`Ap::tick`] retires the unresponsive station.
    #[doc(hidden)]
    pub fn test_expire_sa_query(&mut self) {
        let past = Instant::now() - SA_QUERY_TIMEOUT - Duration::from_millis(1);
        for station in self.stations.values_mut() {
            if let Some((trans, _)) = station.sa_query {
                station.sa_query = Some((trans, past));
            }
        }
        self.maintenance_deadline = Some(Instant::now());
    }

    /// Test hook: age every incomplete SAE exchange past its authentication
    /// timeout so the next maintenance tick removes it.
    #[doc(hidden)]
    pub fn test_expire_incomplete_sae(&mut self) {
        let past = Instant::now() - SAE_AUTH_TIMEOUT - Duration::from_millis(1);
        for station in self.stations.values_mut() {
            if station.sae.is_some() && !station.sae_confirmed {
                station.last_activity = past;
            }
        }
        self.maintenance_deadline = Some(Instant::now());
    }

    /// Test hook: advance the token epoch beyond its accepted lifetime.
    #[doc(hidden)]
    pub fn test_expire_sae_tokens(&mut self) {
        self.boottime -= SAE_TOKEN_LIFETIME + Duration::from_secs(1);
    }

    /// Insert a PMK into the PMKSA cache, evicting one entry when at capacity so
    /// the cache stays bounded ([`PMKSA_CACHE_MAX`]) instead of growing forever.
    pub(super) fn cache_pmksa(
        &mut self,
        id: [u8; 16],
        identity: [u8; 6],
        pmk: [u8; 32],
        sha256: bool,
    ) {
        self.expire_pmksa();
        let key = (id, identity);
        if self.pmksa_cache.len() >= PMKSA_CACHE_MAX && !self.pmksa_cache.contains_key(&key) {
            if let Some(victim) = self.pmksa_cache.keys().next().copied() {
                self.pmksa_cache.remove(&victim);
            }
        }
        let expires_at = Instant::now() + PMKSA_LIFETIME;
        self.pmksa_cache.insert(
            key,
            PmksaEntry {
                identity,
                pmk,
                sha256,
                expires_at,
            },
        );
        self.schedule_maintenance(expires_at);
    }

    pub(super) fn expire_pmksa(&mut self) {
        let now = Instant::now();
        self.pmksa_cache
            .retain(|(_, identity), entry| *identity == entry.identity && entry.expires_at > now);
    }

    /// Test hook: insert a dummy PMKSA entry (exercises the cache bound).
    #[doc(hidden)]
    pub fn test_cache_pmksa(&mut self, id: [u8; 16]) {
        let mut identity = [0u8; 6];
        identity.copy_from_slice(&id[..6]);
        self.cache_pmksa(id, identity, [0u8; 32], true);
    }

    /// Test hook: expire every cached PMKSA entry.
    #[doc(hidden)]
    pub fn test_expire_pmksa(&mut self) {
        let expired = Instant::now() - Duration::from_millis(1);
        for entry in self.pmksa_cache.values_mut() {
            entry.expires_at = expired;
        }
        self.expire_pmksa();
    }

    /// Number of cached PMKSA entries (for tests).
    #[doc(hidden)]
    pub fn pmksa_len(&self) -> usize {
        self.pmksa_cache.len()
    }

    pub(super) fn record_failure(&mut self, sta: &[u8; 6], kind: crate::failures::FailureKind) {
        let traits = self.stations.get(sta).map(|s| s.traits).unwrap_or(0);
        let count = self.failures.record(*sta, traits, kind);
        self.events.push(ApEvent::AuthFailed {
            mac: *sta,
            kind,
            count,
        });
        eprintln!(
            "AP: {} failure from {} (attempt #{count}, traits {:#018x})",
            kind.label(),
            crate::util::bytes_to_mac(sta),
            traits
        );
    }

    /// Remove a station, emitting a `Disconnected` event if it had completed the
    /// 4-way — so connect/disconnect events pair up like reference AP's. A station
    /// torn down mid-handshake never connected, so it produces no event.
    pub(super) fn disconnect(&mut self, sta: &[u8; 6], reason: u16) {
        if let Some(s) = self.stations.remove(sta) {
            self.removed_stations.push(*sta);
            if s.associated {
                self.events.push(ApEvent::Disconnected {
                    mac: s.client_mld_mac.unwrap_or(*sta),
                    reason,
                });
                // reference AP `wpa_strict_rekey`: an authorized station that held the
                // GTK is leaving — rotate the GTK so it can't read future group
                // traffic. Only worthwhile if other stations remain to receive
                // the new key; the next tick performs the rekey.
                if self.strict_rekey && self.stations.values().any(|o| o.associated) {
                    self.group_rekey_due = true;
                }
            }
        }
    }

    /// Drain station removals for change-driven transport reconciliation.
    pub fn drain_removed_stations(&mut self) -> Vec<[u8; 6]> {
        std::mem::take(&mut self.removed_stations)
    }

    /// Drain stations whose PTK became installable after a verified message 4.
    pub fn drain_key_ready_stations(&mut self) -> Vec<[u8; 6]> {
        std::mem::take(&mut self.key_ready_stations)
    }

    pub fn group_key_epoch(&self) -> u64 {
        self.group_key_epoch
    }

    /// Drain the control events (connect/disconnect/auth-fail) queued since the
    /// last call — consumed by the control interface and event logging.
    pub fn drain_events(&mut self) -> Vec<ApEvent> {
        std::mem::take(&mut self.events)
    }

    /// The MAC addresses of every known station (for the control interface).
    pub fn station_macs(&self) -> Vec<[u8; 6]> {
        self.stations.keys().copied().collect()
    }

    /// The capability IE block from a station's (Re)Assoc Request (HT/VHT/HE/
    /// rates), for handing to the kernel on association so rate control works.
    pub fn station_assoc_ies(&self, sta: &[u8; 6]) -> Option<&[u8]> {
        self.stations.get(sta).map(|s| s.assoc_ies.as_slice())
    }

    /// Listen interval advertised in the station's latest association request.
    pub fn station_listen_interval(&self, sta: &[u8; 6]) -> Option<u16> {
        self.stations.get(sta).map(|s| s.listen_interval)
    }

    pub fn station_capability(&self, sta: &[u8; 6]) -> Option<u16> {
        self.stations.get(sta).map(|s| s.capability)
    }

    /// The station's MLD MAC, when this link-addressed station authenticated as
    /// a non-AP MLD.
    pub fn station_mld_mac(&self, sta: &[u8; 6]) -> Option<[u8; 6]> {
        self.stations.get(sta).and_then(|s| s.client_mld_mac)
    }

    pub fn station_mld_link_macs(&self, sta: &[u8; 6]) -> Vec<(u8, [u8; 6])> {
        self.stations
            .get(sta)
            .map(|s| s.client_mld_links.clone())
            .unwrap_or_default()
    }

    /// MLD links negotiated by this station, including the association link.
    /// Group keys are installed and delivered per link even though the compact
    /// userspace key model currently uses one per-station GTK value.
    pub fn station_mld_link_ids(&self, sta: &[u8; 6]) -> Vec<u8> {
        let Some(s) = self.stations.get(sta) else {
            return Vec::new();
        };
        if !self.mld || s.client_mld_mac.is_none() {
            return Vec::new();
        }
        // The anchor configured on the AP is not necessarily the link this
        // station used. In particular, an iPhone can associate on link 1 and
        // advertise link 0 as its partner. Seeding this list with `self.link_id`
        // then collapses the negotiated set to [0], so the kernel never receives
        // the GTK for the active association link and DHCP/group downlink dies.
        let association_link = s.assoc_link_id.unwrap_or(self.link_id);
        let mut ids = vec![association_link];
        for (link_id, _) in &s.client_mld_links {
            if !ids.contains(link_id)
                && self
                    .mld_links
                    .iter()
                    .any(|configured| configured.link_id == *link_id)
            {
                ids.push(*link_id);
            }
        }
        ids.sort_unstable();
        ids
    }

    /// Find the link-addressed station entry that corresponds to a STA MLD MAC.
    pub fn station_link_for_mld(&self, mld: &[u8; 6]) -> Option<[u8; 6]> {
        self.stations
            .iter()
            .find_map(|(link, s)| (s.client_mld_mac.as_ref() == Some(mld)).then_some(*link))
    }

    /// Resolve any address belonging to a non-AP MLD (its MLD MAC, association
    /// link MAC, or an affiliated partner-link MAC) to the single association-
    /// link station record used by the userspace MLME. This mirrors reference AP's
    /// MLO address translation and prevents one client from being treated as
    /// several independent stations as it sends frames on different links.
    pub fn station_link_for_peer(&self, peer: &[u8; 6]) -> Option<[u8; 6]> {
        if self.stations.contains_key(peer) {
            return Some(*peer);
        }
        self.stations.iter().find_map(|(link, s)| {
            (s.client_mld_mac.as_ref() == Some(peer)
                || s.client_mld_links.iter().any(|(_, mac)| mac == peer))
            .then_some(*link)
        })
    }

    /// Administratively deauthenticate a station: tears it down (emitting a
    /// `Disconnected` event) and returns the radiotap-prefixed deauth to send,
    /// or `None` if the station is unknown. PMF stations get a protected deauth.
    pub fn kick(&mut self, mac: &[u8; 6]) -> Option<Vec<u8>> {
        if !self.stations.contains_key(mac) {
            return None;
        }
        let frame = self
            .protected_deauth(mac, 3)
            .unwrap_or_else(|| prepend_radiotap(dot11::build_deauth(&self.mac, mac, 3)));
        self.disconnect(mac, 3);
        Some(frame)
    }

    /// The deduplicated, fingerprinted log of failed auth / decryption attempts.
    pub fn failures(&self) -> &crate::failures::FailureLog {
        &self.failures
    }
}
