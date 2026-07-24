//! Authenticator-side four-way and group-key EAPOL processing.

use super::*;

impl Ap {
    pub(super) fn handle_eapol(&mut self, frame: &dot11::Dot11, out: &mut Outgoing) {
        let sta = frame.addr2;
        if frame.addr1 != self.mac {
            return;
        }
        let (
            anonce,
            ready,
            awaiting_m4,
            kck,
            sha256_m4,
            owe_m4,
            group_rekeying,
            eapol_replay,
            m1_replay,
        ) = match self.stations.get(&sta) {
            Some(s) => (
                s.anonce,
                s.eapol_ready,
                s.awaiting_m4,
                s.kck,
                s.sha256,
                s.owe,
                s.group_rekeying,
                s.eapol_replay,
                s.m1_replay,
            ),
            None => return,
        };

        let Some(eapol_frame) = frame.eapol_frame() else {
            return;
        };
        let Some(key_body) = frame.eapol_key_body() else {
            return;
        };
        let Some(ek) = dot11::EapolKey::parse(key_body) else {
            return;
        };

        if std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
            eprintln!(
                "AP: EAPOL rx from {} replay={} key_info=0x{:04x} ready={} anonce_set={} awaiting_m4={} rekey={}",
                crate::util::bytes_to_mac(&sta),
                ek.key_replay_counter,
                ek.key_info,
                ready,
                anonce.is_some(),
                awaiting_m4,
                group_rekeying,
            );
        }

        // Group Key Handshake message 2: an associated station's ACK of a GTK
        // rekey (its replay counter echoes the message 1 we sent). Verify the MIC,
        // then clear its rekey state; once every station has ACKed, the BSS is
        // fully on the new GTK (reference AP's GKeyDoneStations reaching 0).
        if group_rekeying && ek.key_replay_counter == eapol_replay {
            let version = expected_key_descriptor_version(sha256_m4, owe_m4);
            if !key_info_matches(ek.key_info, 0x0300 | version)
                || ek.key_length != 0
                || ek.key_nonce != [0u8; 32]
                || !ek.key_data.is_empty()
            {
                return;
            }
            let mic_off = 4 + ek.mic_offset;
            if eapol_frame.len() < mic_off + 16 {
                return;
            }
            let mut to_check = eapol_frame.to_vec();
            for b in to_check[mic_off..mic_off + 16].iter_mut() {
                *b = 0;
            }
            let computed = dot11::KeyMic::select(sha256_m4, owe_m4).compute(&kck, &to_check);
            if crypto::constant_time_eq(&computed[..16], &ek.key_mic) {
                if let Some(s) = self.stations.get_mut(&sta) {
                    s.group_rekeying = false;
                    s.pending_eapol = None;
                    s.last_activity = Instant::now();
                }
                eprintln!(
                    "AP: group-key handshake completed for {} replay={}",
                    crate::util::bytes_to_mac(&sta),
                    ek.key_replay_counter,
                );
            } else {
                eprintln!(
                    "AP: group-key message 2 MIC failed for {} replay={}",
                    crate::util::bytes_to_mac(&sta),
                    ek.key_replay_counter,
                );
            }
            return;
        }

        // Message 4: accept the PTK candidate whose MIC verifies. reference AP keeps
        // both the old and new PTK when a station retries M2 with a changed
        // SNonce, so either subsequent M4 can finish the same 4-way.
        let version = expected_key_descriptor_version(sha256_m4, owe_m4);
        let is_m4 = key_info_matches(ek.key_info, 0x0308 | version)
            && ek.key_length == 0
            && ek.key_nonce == [0u8; 32];
        if awaiting_m4 && is_m4 {
            let mic_off = 4 + ek.mic_offset;
            if eapol_frame.len() < mic_off + 16 {
                return;
            }
            let mut to_check = eapol_frame.to_vec();
            for b in to_check[mic_off..mic_off + 16].iter_mut() {
                *b = 0;
            }
            let candidates: Vec<PtkCandidate> = self
                .stations
                .get(&sta)
                .map(|s| {
                    s.ptk_candidates
                        .iter()
                        .filter(|candidate| candidate.m3_replay_counter == ek.key_replay_counter)
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            let expected_mld = self
                .mld
                .then(|| self.stations.get(&sta).and_then(|s| s.client_mld_mac))
                .flatten();
            let mut selected = None;
            for candidate in candidates {
                let mut computed =
                    dot11::KeyMic::select(sha256_m4, owe_m4).compute(&candidate.kck, &to_check);
                let mic_valid = crypto::constant_time_eq(&computed[..16], &ek.key_mic);
                computed.zeroize();
                if !mic_valid {
                    continue;
                }

                // M4 must not set Encrypted Key Data (enforced by
                // `key_info_matches`). MLD M4 carries its MAC KDE in plaintext.
                let key_data = ek.key_data.as_slice();
                let key_data_valid = expected_mld
                    .map(|expected| dot11::parse_mac_addr_kde(key_data) == Some(expected))
                    .unwrap_or(true);
                if key_data_valid {
                    selected = Some(candidate);
                    break;
                }
            }

            if let Some(candidate) = selected {
                let mut event_mac = None;
                if let Some(s) = self.stations.get_mut(&sta) {
                    s.kck.zeroize();
                    s.kek.zeroize();
                    s.tk.zeroize();
                    s.pairwise_tk.zeroize();
                    s.kck = candidate.kck;
                    s.kek = candidate.kek;
                    s.tk.copy_from_slice(&candidate.tk[..16]);
                    s.pairwise_tk = candidate.tk;
                    s.ptk_candidates.clear();
                    s.associated = true;
                    s.awaiting_m4 = false;
                    s.pending_eapol = None; // 4-way complete, nothing to retransmit
                    event_mac = Some(s.client_mld_mac.unwrap_or(sta));
                }
                if let Some(mac) = event_mac {
                    self.events.push(ApEvent::Connected { mac });
                }
                // 4-way complete: release the held ANonce so any *future*
                // reassociation derives a fresh one (KRACK-safe rekey).
                self.pending_anonce.remove(&sta);
            }
            return;
        }

        // Message 2 must be expected and echo the replay counter from message 1.
        // While awaiting M4, keep accepting valid M2 retries for this same M1;
        // this is the reference AP retry1b/1c/1d behavior.
        if !ready && !awaiting_m4 {
            return;
        }
        let Some(anonce) = anonce else { return };
        if ek.key_replay_counter != m1_replay {
            return;
        }
        if !key_info_matches(ek.key_info, 0x0108 | version) || ek.key_length != 0 {
            return;
        }

        let snonce = ek.key_nonce;
        // 802.11be MLD: the PTK is derived from the MLD MAC addresses (AA = AP
        // MLD MAC, SPA = STA MLD MAC), not the per-link addresses — both peers
        // key the link off the MLD identity. Falls back to the link addresses
        // for a non-MLD station.
        let client_mld = self.stations.get(&sta).and_then(|s| s.client_mld_mac);
        let (amac, smac) = match client_mld {
            Some(cmld) if self.mld => (self.mld_mac, cmld),
            _ => (self.mac, sta),
        };

        // Use the SAE-derived PMK + SHA-256 key descriptors when the station
        // authenticated via WPA3-SAE; otherwise the PSK (PBKDF2) PMK + SHA-1.
        // Anti-downgrade backstop: on a WPA3-SAE-only or OWE-only AP, a station
        // with no SAE/OWE-derived or cached PMK must not be silently keyed via
        // the PSK 4-way fallback.
        if matches!(
            self.security_mode(),
            dot11::SecurityMode::Wpa3Sae | dot11::SecurityMode::Owe
        ) && self
            .stations
            .get(&sta)
            .map(|s| s.pmk.is_none())
            .unwrap_or(true)
        {
            return;
        }
        let (sta_pmk, sha256, owe) = self
            .stations
            .get(&sta)
            .map(|s| (s.pmk, s.sha256, s.owe))
            .unwrap_or((None, false, false));

        // reference AP `wpa_psk_file` order: a PMK already fixed for this station
        // (SAE / OWE / PMKSA) is used outright; otherwise try the PSK-file entries
        // whose MAC matches this station, then the wildcard onboarding entries.
        // The single BSS passphrase is considered only when no authoritative
        // credential file is configured. The candidate whose PTK verifies
        // message 2's MIC is this station's password.
        let mut candidates: Vec<[u8; 32]> = if let Some(p) = sta_pmk {
            vec![p]
        } else {
            let mut v: Vec<[u8; 32]> = Vec::new();
            v.extend(
                self.psk_candidates
                    .iter()
                    .filter(|(m, _)| *m == Some(sta))
                    .map(|(_, p)| *p),
            );
            v.extend(
                self.psk_candidates
                    .iter()
                    .filter(|(m, _)| m.is_none())
                    .map(|(_, p)| *p),
            );
            if !self.credential_file_authoritative {
                v.push(self.pmk);
            }
            v
        };

        let mic_off_in_eapol = 4 + ek.mic_offset; // EAPOL header (4) + body offset
        if std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
            eprintln!(
                "AP: m2 PTK amac={} smac={} client_mld={:?} sta={} sha256={sha256} cands={} pmk[..8]={}",
                crate::util::bytes_to_mac(&amac),
                crate::util::bytes_to_mac(&smac),
                client_mld.map(|m| crate::util::bytes_to_mac(&m)),
                crate::util::bytes_to_mac(&sta),
                candidates.len(),
                candidates.first().map(|p| p[..8].iter().map(|x| format!("{x:02x}")).collect::<String>()).unwrap_or_default(),
            );
        }
        if std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
            let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
            eprintln!("AP: m2 anonce={}", hex(&anonce));
            eprintln!("AP: m2 snonce={}", hex(&snonce));
            eprintln!(
                "AP: m2 mic_off_in_eapol={mic_off_in_eapol} eapol_len={}",
                eapol_frame.len()
            );
            eprintln!("AP: m2 eapol_frame={}", hex(eapol_frame));
            eprintln!("AP: m2 recv_mic={}", hex(&ek.key_mic));
        }
        let mut kck = [0u8; 16];
        let mut kek = [0u8; 16];
        let mut tk = [0u8; 32];
        let tk_len = self.pairwise_cipher.key_len();
        let mut matched_pmk: Option<[u8; 32]> = None;
        for pmk in &candidates {
            if sha256 {
                let mut ptk =
                    crypto::derive_ptk_sha256_len(pmk, &amac, &smac, &anonce, &snonce, 32 + tk_len);
                kck.copy_from_slice(&ptk[..16]);
                kek.copy_from_slice(&ptk[16..32]);
                tk[..tk_len].copy_from_slice(&ptk[32..32 + tk_len]);
                ptk.zeroize();
            } else {
                let mut ptk = crypto::custom_prf512(pmk, &amac, &smac, &anonce, &snonce);
                kck.copy_from_slice(&ptk[..16]);
                kek.copy_from_slice(&ptk[16..32]);
                tk[..tk_len].copy_from_slice(&ptk[32..32 + tk_len]);
                ptk.zeroize();
            }
            let mut to_check = eapol_frame.to_vec();
            for b in to_check[mic_off_in_eapol..mic_off_in_eapol + 16].iter_mut() {
                *b = 0;
            }
            let mut computed = dot11::KeyMic::select(sha256, owe).compute(&kck, &to_check);
            if std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
                let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
                eprintln!(
                    "AP: m2 try kck={} computed_mic={}",
                    hex(&kck),
                    hex(&computed[..16])
                );
            }
            let mic_valid = crypto::constant_time_eq(&computed, &ek.key_mic);
            computed.zeroize();
            if mic_valid {
                matched_pmk = Some(*pmk);
                break;
            }
        }
        if matched_pmk.is_none() && std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
            eprintln!("AP: m2 MIC did not match the pending handshake");
        }
        let mut matched_pmk = match matched_pmk {
            None => {
                candidates.zeroize();
                kck.zeroize();
                kek.zeroize();
                tk.zeroize();
                // A bad first M2 means the configured password did not verify.
                // Once at least one M2 has already verified, however, a bad
                // retry must not destroy the valid pending candidate.
                if awaiting_m4 {
                    return;
                }
                self.record_failure(&sta, crate::failures::FailureKind::FourWayMic);
                let deauth = dot11::build_deauth(&self.mac, &sta, 1);
                out.tx(deauth);
                self.disconnect(&sta, 1);
                return;
            }
            Some(p) => p,
        };
        candidates.zeroize();

        // M2 must carry unencrypted Key Data; the key-info validation above
        // rejects an attacker-controlled encrypted-data bit before any unwrap.
        let mut m2_key_data = ek.key_data.clone();
        let unpadded_len = dot11::trim_key_data_padding(&m2_key_data).len();
        m2_key_data.truncate(unpadded_len);
        let assoc_ies = self
            .stations
            .get(&sta)
            .map(|s| s.assoc_ies.as_slice())
            .unwrap_or(&[]);
        if !message_2_security_matches(assoc_ies, &m2_key_data) {
            m2_key_data.zeroize();
            matched_pmk.zeroize();
            kck.zeroize();
            kek.zeroize();
            tk.zeroize();
            return;
        }

        // Pin the matched password to this station so m3 retransmits and GTK
        // rekeys reuse the same PMK.
        if let Some(s) = self.stations.get_mut(&sta) {
            s.set_pmk(Some(matched_pmk));
        }
        matched_pmk.zeroize();

        // Operating Channel Validation: message 2's OCI must match our channel.
        if self.ocv {
            match dot11::parse_oci_kde(&m2_key_data) {
                Some((oc, ch))
                    if ch == self.channel
                        && dot11::oci_class_matches_band(oc, self.channel, self.band6) => {}
                _ => {
                    m2_key_data.zeroize();
                    kck.zeroize();
                    kek.zeroize();
                    tk.zeroize();
                    return;
                } // missing or mismatched OCI -> possible MITM, drop
            }
        }
        m2_key_data.zeroize();

        // The first valid M2 consumes the cross-reassociation M1 hold and gets a
        // fresh M3 replay counter. Changed-SNonce retries remain inside this same
        // 4-way and reuse that M3 counter, matching reference AP retry1c/1d.
        if !awaiting_m4 {
            self.pending_anonce.remove(&sta);
        }
        let m3_replay = if awaiting_m4 {
            eapol_replay
        } else {
            self.next_eapol_replay()
        };

        // Retain a bounded set of valid PTK candidates until M4 selects one.
        // Nothing is exposed to the driver until `associated` becomes true.
        {
            let s = self.stations.get_mut(&sta).unwrap();
            if !s
                .ptk_candidates
                .iter()
                .any(|candidate| candidate.m3_replay_counter == m3_replay && candidate.kck == kck)
            {
                if s.ptk_candidates.len() >= 8 {
                    s.ptk_candidates.remove(0);
                }
                s.ptk_candidates.push(PtkCandidate {
                    m3_replay_counter: m3_replay,
                    kck,
                    kek,
                    tk,
                });
            }
            s.eapol_ready = false;
            s.client_pn = 1;
            s.eapol_replay = m3_replay;
        }
        // Deliver the IGTK KDE to PMF (WPA3-SAE) stations so they can validate
        // BIP-protected group-addressed management frames, and the BIGTK KDE when
        // Beacon Protection is enabled.
        let igtk = if sha256 {
            Some((self.igtk_key_id, self.igtk_ipn, self.igtk))
        } else {
            None
        };
        let bigtk = if sha256 && self.beacon_prot {
            Some((self.bigtk_key_id, self.bigtk_ipn, self.bigtk))
        } else {
            None
        };
        let oci = if self.ocv {
            Some((
                dot11::operating_class(self.channel, self.channel_width, self.band6),
                self.channel,
            ))
        } else {
            None
        };
        let sc = self.next_sc();
        // m3's key data must echo the exact RSNE (+ RSNXE) the AP advertises in
        // its beacon, or the supplicant rejects it as a Beacon/EAPOL IE mismatch.
        let mut ap_rsn: Vec<u8> = if owe {
            dot11::RSN_OWE.to_vec()
        } else if sha256 {
            let mut r = dot11::RSN_WPA3.to_vec();
            r.extend_from_slice(&dot11::RSNXE_H2E);
            r
        } else {
            dot11::RSN.to_vec()
        };
        ap_rsn[13] = self.pairwise_cipher.suite_type();
        // In per-station-VIF mode each station gets its own GTK *value* (broadcast
        // isolation); otherwise all stations share the BSS-wide GTK. Either way the
        // GTK *index* is the single BSS-wide `gtk_key_id` (what the RSNE advertises
        // and every client installs under), following the rekey toggle.
        let gtk = self.station_gtk(&sta);
        let gtk_key_id = self.gtk_key_id;
        let group_rsc = self.current_group_rsc();
        let mld_station = self.mld && client_mld.is_some();
        let m3 = if mld_station {
            // Every link the station holds needs its group keys: the partner
            // links from its association request PLUS the association link
            // itself (which is not in `client_mld_links`). Missing the
            // association link's MLO GTK/IGTK leaves the client unable to key
            // that link, so it never sends m4.
            let mut negotiated = self.station_mld_link_ids(&sta);
            if let Some(assoc_link) = self.stations.get(&sta).and_then(|s| s.assoc_link_id) {
                if !negotiated.contains(&assoc_link) {
                    negotiated.push(assoc_link);
                }
            }
            let configured = self.active_mld_links();
            let link_kdes: Vec<(u8, [u8; 6], &[u8])> = configured
                .iter()
                .filter(|link| negotiated.contains(&link.link_id))
                .map(|link| (link.link_id, link.mac, ap_rsn.as_slice()))
                .collect();
            dot11::build_eapol_m3_mld_links_with_rsc(
                &self.mac,
                &sta,
                &anonce,
                &kck,
                &kek,
                &self.mld_mac,
                &link_kdes,
                gtk_key_id,
                &gtk,
                igtk,
                bigtk,
                oci,
                group_rsc,
                m3_replay,
                sc,
                dot11::KeyMic::select(sha256, owe),
            )
        } else {
            dot11::build_eapol_m3_for_key_length_with_rsc(
                &self.mac,
                &sta,
                &anonce,
                &kck,
                &kek,
                &ap_rsn,
                gtk_key_id,
                &gtk,
                igtk,
                bigtk,
                oci,
                group_rsc,
                m3_replay,
                sc,
                dot11::KeyMic::select(sha256, owe),
                self.pairwise_cipher.key_len() as u16,
            )
        };
        // Keys are derived and m3 is sent, but the station is not authorized
        // until its m4 ACK verifies (see the top of `handle_eapol`). Cache m3 so
        // it can be retransmitted if m4 is lost (m2 arrived, so the m1 cache is
        // replaced by m3).
        if let Some(s) = self.stations.get_mut(&sta) {
            s.awaiting_m4 = true;
            s.pending_eapol = Some(prepend_radiotap(m3.clone()));
            s.eapol_tx = Instant::now();
            s.eapol_retries = 0;
            s.eapol_acked = false;
        }
        kck.zeroize();
        kek.zeroize();
        tk.zeroize();
        out.tx(m3);
        // 802.11v auto-steer: send an (unprotected, WPA2) BSS Transition
        // Management Request once associated. For PMF (WPA3/OWE) the request must
        // be CCMP-protected and is sent via `btm_request()` after the STA has
        // installed the PTK.
        if self.btm {
            let pmf = self.stations.get(&sta).map(|s| s.sha256).unwrap_or(false);
            if !pmf {
                let f = self.btm_request_frame(&sta);
                out.tx(f);
            }
        }
    }
}
