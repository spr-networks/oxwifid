//! Top-level receive dispatch plus probe and open-authentication handling.

use super::*;

impl Ap {
    /// Process one received frame (radiotap-prefixed) and return what to do.
    pub fn handle_incoming(&mut self, radiotap_frame: &[u8]) -> Outgoing {
        let mut out = Outgoing::default();
        if dot11::radiotap_bad_fcs(radiotap_frame) {
            return out;
        }
        let Some(body) = dot11::strip_radiotap(radiotap_frame) else {
            return out;
        };
        let Some(frame) = dot11::Dot11::parse(body) else {
            return out;
        };

        // Address filter (recv_pkt): only accept frames addressed to us, or
        // group-addressed frames from someone else.
        let a1 = frame.addr1;
        if a1 != self.mac {
            if is_multicast(&a1) || is_broadcast(&a1) {
                if frame.addr2 == self.mac {
                    return out;
                }
            } else {
                return out;
            }
        }

        // Inactivity timer: any frame from a known station counts as activity.
        if let Some(s) = self.stations.get_mut(&frame.addr2) {
            s.last_activity = Instant::now();
        }

        // Encrypted uplink data (to-DS + protected) goes through the decrypt +
        // replay path FIRST: a protected frame must never be treated as a
        // plaintext EAPOL by `is_eapol()` (whose LLC/SNAP match an attacker
        // could otherwise force with a crafted CCMP packet number).
        if frame.frame_type() == dot11::TYPE_DATA && frame.protected() {
            if frame.to_ds() {
                self.handle_data_uplink(&frame, &mut out);
            }
            return out;
        }

        // EAPOL is only accepted unprotected here — the 4-way handshake (msg 2/4)
        // runs before the PTK is installed.
        if frame.is_eapol() {
            self.handle_eapol(&frame, &mut out);
            return out;
        }

        // Management frames
        if frame.frame_type() == dot11::TYPE_MGMT {
            match frame.subtype() {
                dot11::SUBTYPE_PROBE_REQ => self.handle_probe_req(&frame, &mut out),
                dot11::SUBTYPE_AUTH => self.handle_auth_req(&frame, &mut out),
                dot11::SUBTYPE_ASSOC_REQ | dot11::SUBTYPE_REASSOC_REQ => {
                    self.handle_assoc_req(&frame, &mut out)
                }
                dot11::SUBTYPE_DEAUTH | dot11::SUBTYPE_DISASSOC => self.handle_robust_mgmt(&frame),
                dot11::SUBTYPE_ACTION => self.handle_action(&frame, &mut out),
                _ => {}
            }
        }
        out
    }

    pub(super) fn handle_probe_req(&mut self, frame: &dot11::Dot11, out: &mut Outgoing) {
        let ssid = dot11::find_ssid(&frame.body);
        match ssid {
            Some(s) if s.is_empty() => {
                // empty SSID -> respond with our primary SSID
                self.send_probe_resp(&frame.addr2, out);
            }
            Some(s) if s == self.ssid => {
                self.send_probe_resp(&frame.addr2, out);
            }
            _ => {}
        }
    }

    pub(super) fn send_probe_resp(&mut self, dst: &[u8; 6], out: &mut Outgoing) {
        // The response must describe the link the probe request arrived on: its
        // channel/band IEs, its own MLE Link ID, and an RNR naming its
        // PARTNERS. Answering a partner link's probe with the association
        // link's content contradicts that link's beacon, and an MLO client
        // (wpa_supplicant "Neighbor has unexpected link ID") then falls back
        // to a single-link association.
        let (link_id, link_mac, channel, width, band6) =
            match self.mgmt_rx_link.filter(|_| self.mld).and_then(|lid| {
                self.active_mld_links()
                    .into_iter()
                    .find(|link| link.link_id == lid)
            }) {
                Some(link) => (link.link_id, link.mac, link.channel, link.width, link.band6),
                None => (
                    self.link_id,
                    self.mac,
                    self.channel,
                    self.channel_width,
                    self.band6,
                ),
            };
        let sc = self.next_sc();
        let ts = self.current_timestamp();
        let mut frame = dot11::build_probe_resp(
            &link_mac,
            dst,
            &self.ssid,
            channel,
            ts,
            sc,
            &dot11::security_tail_for_cipher(self.security_mode(), self.pairwise_cipher),
            &self.country,
            width,
            band6,
            self.wmm,
            self.phy_mode,
            self.punct,
        );
        if self.beacon_prot {
            dot11::enable_beacon_protection_capability(&mut frame[36..]);
        }
        if self.mld {
            frame.extend_from_slice(&self.mld_rnr_for(link_id));
            let info = self.mld_link_info_for(link_id);
            frame.extend_from_slice(&self.mld_basic_element(link_id, &info));
            frame.extend_from_slice(&self.mld_tid_to_link_element());
        }
        out.tx(frame);
    }

    pub(super) fn handle_auth_req(&mut self, frame: &dot11::Dot11, out: &mut Outgoing) {
        if frame.addr1 != self.mac {
            return;
        }
        let sta = frame.addr2;
        let Some(auth) = dot11::parse_auth(&frame.body) else {
            return;
        };
        let now = Instant::now();
        if !self.allow_auth_request(sta, now) {
            return;
        }

        // WPA3-SAE authentication (algorithm 3)
        if auth.algo == dot11::AUTH_ALG_SAE {
            if self.sae_enabled {
                self.handle_sae_auth(&sta, auth.seq, auth.status, auth.payload, out);
            }
            return;
        }

        // A SAE AP still accepts open-system Authentication, because WPA3-SAE
        // *PMKSA caching* (fast reconnect) skips a fresh SAE exchange and does
        // open-auth followed by (Re)Association carrying the cached PMKID — a
        // client that already ran SAE once (e.g. reconnecting after a link
        // glitch) uses exactly this path. Rejecting open-auth here (status 13)
        // breaks that reconnect and loops the STA in AUTHENTICATING. The
        // anti-downgrade guarantee is preserved at *association*: a SAE/OWE-only
        // AP rejects an assoc with no SAE/OWE/cached PMK (see `handle_assoc_req`),
        // so an open-auth station that has no valid PMKID never reaches a 4-way
        // and can never fall back to the bare PSK path.

        // Open-system authentication (algorithm 0) -- WPA2/PSK, or SAE PMKSA reconnect
        let mut restarted_association = None;
        {
            let entry = self
                .stations
                .entry(sta)
                .or_insert_with(|| Station::new(sta));
            // A duplicate auth within the backoff window is a retransmission (the
            // STA didn't get our response and retried). Re-answer it idempotently
            // — dropping it would stall a client over a lossy link — but do NOT
            // restart the session (that's only for a genuinely new auth).
            let retransmit = entry
                .last_auth
                .map(|t| now.duration_since(t) < BACKOFF)
                .unwrap_or(false);
            // A (re-)Authentication restarts the station's session, as in
            // reference AP: drop any prior 4-way / association state so a reconnecting
            // client derives a fresh PTK against a fresh ANonce. Without this, a
            // station that left without a (seen) deauth keeps its stale ANonce and
            // keys, and the reconnect's 4-way fails with a MIC/"wrong key".
            //
            // BUT: a re-Auth that interrupts an *in-flight initial 4-way* must NOT
            // regenerate the ANonce. Real clients fall back to a PMKSA-cached
            // reconnect (a second Auth+Assoc) mid-handshake; if each Association
            // mints a fresh ANonce, the client's in-flight Message 2 — keyed to the
            // ANonce we already sent it — never verifies, and every retry advances
            // us one ANonce ahead of the client: a permanent off-by-one livelock
            // (observed on ath12k, where the client always PMKSA-reconnects). While
            // mid-handshake (we sent m1 but have not accepted m2) reuse the
            // existing ANonce/replay pair. Once m2 verifies, `eapol_ready` is
            // cleared and the pending pair is consumed before m3 can install a
            // PTK, so any later authentication gets a full reset.
            let mid_handshake = entry.anonce.is_some() && entry.eapol_ready && !entry.awaiting_m4;
            if std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
                eprintln!(
                    "AP: AUTH-REQ sta={} retransmit={retransmit} mid_handshake={mid_handshake} anonce_set={} associated={} eapol_ready={}",
                    crate::util::bytes_to_mac(&sta),
                    entry.anonce.is_some(),
                    entry.associated,
                    entry.eapol_ready,
                );
            }
            if !retransmit && !mid_handshake {
                if entry.associated {
                    restarted_association = Some(entry.client_mld_mac.unwrap_or(sta));
                }
                entry.last_auth = Some(now);
                entry.anonce = None;
                entry.eapol_ready = false;
                entry.awaiting_m4 = false;
                entry.associated = false;
                entry.eapol_replay = 0;
                entry.m1_replay = 0;
                entry.ptk_candidates.clear();
                entry.kck.zeroize();
                entry.kek.zeroize();
                entry.tk.zeroize();
                entry.pairwise_tk.zeroize();
                entry.gtk.zeroize();
                entry.gtk = random_bytes::<16>();
                entry.pending_eapol = None; // no stale m1/m3 to retransmit
                                            // Drop any psk_file PMK pinned by a previous 4-way so the
                                            // candidate trial (per-MAC -> wildcard -> default) re-runs — a
                                            // re-onboarded device may use a different password now. (SAE uses
                                            // algorithm-3 auth and never reaches this open-auth reset; PMKSA
                                            // fast-reconnect re-sets `pmk` from the cache at association.)
                entry.set_pmk(None);
            } else if !retransmit {
                // Mid-message-1 re-auth: keep the ANonce/replay state, just
                // note the auth time so the backoff window tracks the latest attempt.
                entry.last_auth = Some(now);
            }
        }
        if let Some(mac) = restarted_association {
            eprintln!(
                "AP: station {} started a fresh authentication while associated; retiring old session",
                crate::util::bytes_to_mac(&mac)
            );
            self.events.push(ApEvent::Disconnected { mac, reason: 0 });
            if self.strict_rekey && self.stations.values().any(|s| s.associated) {
                self.group_rekey_due = true;
            }
        }

        // recv_pkt resets the sequence counter on auth
        self.sc = -1;
        let sc = self.next_sc();
        let auth = dot11::build_auth(&self.mac, &sta, sc);
        out.tx(auth);
    }
}
