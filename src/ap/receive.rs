//! Top-level receive dispatch plus probe and open-authentication handling.

use super::*;

/// Which component verified/decrypted a protected management frame.
#[derive(Clone, Copy)]
pub(crate) enum ManagementRx {
    /// Monitor/raw-frame mode: the protocol engine verifies the MIC and PN.
    Userspace,
    /// nl80211 mode: mac80211 already verified, replay-checked, and decrypted
    /// the body while retaining the Protected bit in the 802.11 header.
    #[cfg(target_os = "linux")]
    Kernel,
}

impl Ap {
    /// Process one received frame (radiotap-prefixed) and return what to do.
    pub fn handle_incoming(&mut self, radiotap_frame: &[u8]) -> Outgoing {
        self.handle_incoming_from(radiotap_frame, ManagementRx::Userspace)
    }

    /// Process an nl80211-delivered frame.
    ///
    /// This is deliberately a separate transport boundary: treating a
    /// kernel-decrypted robust frame as raw CCMP would parse its plaintext
    /// action/reason bytes as a CCMP header and drop every PMF exchange.
    #[cfg(target_os = "linux")]
    pub(crate) fn handle_kernel_incoming(&mut self, radiotap_frame: &[u8]) -> Outgoing {
        self.handle_incoming_from(radiotap_frame, ManagementRx::Kernel)
    }

    fn handle_incoming_from(
        &mut self,
        radiotap_frame: &[u8],
        management_rx: ManagementRx,
    ) -> Outgoing {
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
                dot11::SUBTYPE_DEAUTH | dot11::SUBTYPE_DISASSOC => {
                    self.handle_robust_mgmt(&frame, management_rx)
                }
                dot11::SUBTYPE_ACTION => self.handle_action(&frame, management_rx, &mut out),
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

        // An Authentication frame is never integrity-protected — it predates the
        // keys — so anyone can forge one carrying an associated station's
        // address. If that station already holds a PMF association, this frame
        // must not be allowed to disturb it: the open-system path below zeroizes
        // its PTK and clears `associated`, and the SAE path replaces its PMK and
        // clears `sae_confirmed` (after which `handle_assoc_req` refuses every
        // future association). Either one is the deauthentication primitive PMF
        // is meant to eliminate, and the SA Query the (Re)Association path
        // already performs is worthless if the same teardown is reachable one
        // frame type over. Keep the session and challenge the peer instead.
        if self.pmf_session_protected(&sta) {
            self.sa_query_challenge(&sta, out);
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
            if crate::util::netlink_debug_enabled() {
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
                entry.last_rx_pn = [0; 17];
                entry.last_rx_mgmt_pn = 0;
                entry.sa_query = None;
                // The key hierarchy this station negotiated is part of the
                // session being retired, not a property of the MAC address.
                // Leaving `sha256`/`owe` set made a station that once ran SAE
                // keep SHA-256 + AES-CMAC key descriptors forever: on a
                // transition-mode BSS its next plain WPA2-PSK reconnect derived
                // the PTK with the wrong hash and every message 2 MIC failed.
                // PMKSA fast-reconnect re-establishes both flags from the cache
                // at association, which happens after this reset.
                entry.sha256 = false;
                entry.owe = false;
                entry.psk_sha256 = false;
                entry.pmf = false;
                entry.sae_h2e = false;
                entry.kck.zeroize();
                entry.kek.zeroize();
                entry.tk.zeroize();
                entry.pairwise_tk.zeroize();
                entry.gtk.zeroize();
                entry.gtk = random_bytes::<16>();
                // A strict GTK rekey may have been queued immediately before
                // this fresh Authentication arrived. Its Message 1 belongs to
                // the retired PTK/session; leaving this flag set makes the new
                // four-way Message 2 enter the group-key parser and get dropped.
                entry.group_rekeying = false;
                entry.pending_eapol = None; // no stale m1/m3 to retransmit
                                            // Drop any credential-file PMK pinned by a previous 4-way so the
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
