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
            s.kck.zeroize();
            s.kek.zeroize();
            s.tk.zeroize();
            s.pairwise_tk.zeroize();
            s.eapol_retries = 0;
            s.eapol_acked = false;
        }
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
        self.pending_anonce
            .retain(|_, pending| now.duration_since(pending.created_at) < ANONCE_HOLD);
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
        self.expire_pmksa();

        // Key lifecycle: a queued strict rekey (a station left) or the periodic
        // `wpa_group_rekey` interval triggers a Group Key Handshake. rekey_gtk()
        // coalesces if one is already in flight, and arms each msg 1 for
        // retransmit through the loop below.
        let periodic = self.group_rekey_secs > 0
            && now.duration_since(self.last_group_rekey)
                >= Duration::from_secs(self.group_rekey_secs)
            && self.stations.values().any(|s| s.associated);
        if self.group_rekey_due || periodic {
            self.group_rekey_due = false;
            out.frames.extend(self.rekey_gtk());
        }

        let mut timed_out: Vec<[u8; 6]> = Vec::new();
        for (mac, s) in self.stations.iter_mut() {
            let Some(frame) = s.pending_eapol.as_ref() else {
                continue;
            };
            // The first message-1 attempt gets the authenticator's short retry
            // timeout. An ACK stretches that first timeout to the normal interval,
            // and every later attempt also waits the normal interval. Do not
            // aggressively enqueue a new copy merely because TX status is still
            // pending: ath12k can report status late, and the old 40-ms loop filled
            // its queue with 31 stale m1/m3 copies before the first status arrived.
            let timeout = if s.eapol_retries == 0 && !s.eapol_acked {
                EAPOL_FIRST_TIMEOUT
            } else {
                EAPOL_TIMEOUT
            };
            if now.duration_since(s.eapol_tx) < timeout {
                continue;
            }
            if s.eapol_retries >= MAX_EAPOL_RETRIES {
                eprintln!(
                    "AP: {} timeout for {} after {} retries",
                    if s.group_rekeying {
                        "group-key handshake"
                    } else if s.awaiting_m4 {
                        "4-way message 3"
                    } else {
                        "4-way message 1"
                    },
                    crate::util::bytes_to_mac(mac),
                    s.eapol_retries,
                );
                timed_out.push(*mac);
            } else {
                out.frames.push(frame.clone()); // already radiotap-prefixed
                s.eapol_tx = now;
                s.eapol_retries += 1;
                s.eapol_acked = false; // awaiting the ACK for this resend
            }
        }
        for mac in timed_out {
            self.disconnect(&mac, 15);
            let deauth = dot11::build_deauth(&self.mac, &mac, 15); // 4-way timeout
            out.tx(deauth);
        }
        out
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
        for s in self.stations.values_mut() {
            if s.pending_eapol.is_some() {
                s.eapol_tx = past;
            }
        }
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
        self.pmksa_cache.insert(
            key,
            PmksaEntry {
                identity,
                pmk,
                sha256,
                expires_at: Instant::now() + PMKSA_LIFETIME,
            },
        );
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
        let mut ids = vec![self.link_id];
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
