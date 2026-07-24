//! Association validation, station negotiation, and initial EAPOL dispatch.

use super::*;

impl Ap {
    pub(super) fn handle_assoc_req(&mut self, frame: &dot11::Dot11, out: &mut Outgoing) {
        if frame.addr1 != self.mac {
            return;
        }
        let sta = frame.addr2;
        let reassoc = frame.subtype() == dot11::SUBTYPE_REASSOC_REQ;
        let request_time = Instant::now();
        if !self.allow_assoc_request(sta, request_time) {
            return;
        }

        // PMF SA Query takes precedence over parsing a repeated association
        // request: the frame may be spoofed and intentionally malformed. Do not
        // let it overwrite station state or turn the required status-30 comeback
        // into a negotiation error.
        let (pmf_assoc, tk) = self
            .stations
            .get(&sta)
            .map(|s| (s.associated && s.sha256, s.pairwise_tk))
            .unwrap_or((false, [0u8; 32]));
        if pmf_assoc {
            let sc = self.next_sc();
            out.tx(dot11::build_assoc_resp_comeback(&self.mac, &sta, 1000, sc));
            self.sa_query_id = self.sa_query_id.wrapping_add(1);
            let trans = self.sa_query_id;
            let Some(pn) = self.stations.get_mut(&sta).unwrap().next_client_pn() else {
                return;
            };
            let sc = self.next_sc();
            let sec = self.mld_mgmt_tx_sec_addrs(&sta);
            out.tx(dot11::build_protected_sa_query_for_cipher_sec(
                self.pairwise_cipher,
                &self.mac,
                &sta,
                false,
                false,
                trans,
                sc,
                pn,
                &tk[..self.pairwise_cipher.key_len()],
                sec,
            ));
            return;
        }

        let ie_off = if reassoc { 10 } else { 4 };
        let Some(assoc_ies) = frame.body.get(ie_off..) else {
            self.reject_assoc_status(&sta, reassoc, dot11::STATUS_INVALID_IE, out);
            return;
        };
        let assoc_rsn = match dot11::find_ie_strict(assoc_ies, 48) {
            Ok(Some(rsn)) => rsn,
            _ => {
                self.reject_assoc_status(&sta, reassoc, dot11::STATUS_INVALID_IE, out);
                return;
            }
        };
        if let Err(status) = dot11::validate_assoc_rsn_for_cipher(
            assoc_rsn,
            self.security_mode(),
            self.pairwise_cipher,
        ) {
            self.reject_assoc_status(&sta, reassoc, status, out);
            return;
        }
        let requests_sae = dot11::rsn_has_akm(assoc_rsn, 8);
        if requests_sae {
            let sae_h2e = self
                .stations
                .get(&sta)
                .is_some_and(|station| station.sae_h2e);
            match (sae_h2e, dot11::find_ie_consistent(assoc_ies, 0xf4)) {
                (true, Ok(Some(rsnxe))) if dot11::rsnxe_has_sae_h2e(rsnxe) => {}
                (false, Ok(_)) => {}
                _ => {
                    self.reject_assoc_status(&sta, reassoc, dot11::STATUS_INVALID_IE, out);
                    return;
                }
            }
        }
        let mld_assoc = if self.mld {
            let client_mld = dot11::parse_mld_mac(assoc_ies);
            if dot11::has_basic_multi_link_element(assoc_ies) && client_mld.is_none() {
                self.reject_assoc_status(&sta, reassoc, dot11::STATUS_INVALID_IE, out);
                return;
            }
            if let Some(client_mld) = client_mld {
                let sae_mld = self.stations.get(&sta).and_then(|s| s.client_mld_mac);
                if sae_mld.map(|prev| prev != client_mld).unwrap_or(false) {
                    self.reject_assoc(&sta, reassoc, out);
                    return;
                }
                let Some(links) = self.validate_mld_assoc_links(&sta, &client_mld, assoc_ies)
                else {
                    self.reject_assoc(&sta, reassoc, out);
                    return;
                };
                Some((client_mld, links))
            } else {
                None
            }
        } else {
            None
        };

        // Fingerprint the client from its association characteristics (for the
        // failure log), and note whether it negotiated WMM (the IE block starts
        // after the fixed fields: 4 bytes for Assoc, 10 for Reassoc).
        let ap_wmm = self.wmm;
        let client_wmm = frame.body.len() > ie_off && dot11::has_wmm_ie(&frame.body[ie_off..]);
        {
            let s = self
                .stations
                .entry(sta)
                .or_insert_with(|| Station::new(sta));
            s.traits = crate::failures::client_traits(&frame.body);
            s.wmm = ap_wmm && client_wmm;
            if frame.body.len() >= 4 {
                s.capability = u16::from_le_bytes([frame.body[0], frame.body[1]]);
                s.listen_interval = u16::from_le_bytes([frame.body[2], frame.body[3]]);
            }
            // Remember the station's capability IEs (HT/VHT/HE/rates) so the
            // netlink station setup can hand them to the driver for rate control.
            s.assoc_ies = frame.body.get(ie_off..).unwrap_or(&[]).to_vec();
            if let Some((client_mld, links)) = mld_assoc.as_ref() {
                s.client_mld_mac = Some(*client_mld);
                s.client_mld_links = links.clone();
            }
        }
        if std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
            let ies = frame.body.get(ie_off..).unwrap_or(&[]);
            let ml = dot11::parse_mld_mac(ies);
            let rsn_hex: String = dot11::find_ie(ies, 48)
                .map(|r| r.iter().map(|b| format!("{b:02x}")).collect())
                .unwrap_or_default();
            eprintln!(
                "AP: DBG-ASSOC sta={} has_ml_element={} client_mld={:?} rsn={}",
                crate::util::bytes_to_mac(&sta),
                ml.is_some(),
                ml.map(|m| crate::util::bytes_to_mac(&m)),
                rsn_hex
            );
        }
        if let Some((client_mld, links)) = mld_assoc {
            eprintln!(
                "AP: MLD association sta={} mld={} requested_links={}",
                crate::util::bytes_to_mac(&sta),
                crate::util::bytes_to_mac(&client_mld),
                links
                    .iter()
                    .map(|(link_id, mac)| format!("{}:{}", link_id, crate::util::bytes_to_mac(mac)))
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }

        // A station that began SAE must have a *verified* confirm before it may
        // associate — otherwise the mutual authentication is incomplete and we'd
        // derive a PTK from an unconfirmed PMK. (The anti-downgrade check that a
        // WPA3-only AP doesn't fall back to the PSK 4-way lives in `handle_eapol`,
        // so PMKSA fast-reconnect — which skips SAE with a cached PMK — still works.)
        if let Some(s) = self.stations.get(&sta) {
            if s.sae.is_some() && !s.sae_confirmed {
                eprintln!(
                    "AP: association from {} deferred because SAE confirm is not complete",
                    crate::util::bytes_to_mac(&sta),
                );
                return;
            }
        }

        let now = request_time;
        {
            let entry = self
                .stations
                .entry(sta)
                .or_insert_with(|| Station::new(sta));
            if let Some(t) = entry.last_assoc {
                if now.duration_since(t) < BACKOFF {
                    return;
                }
            }
            entry.last_assoc = Some(now);
        }

        // PMKSA caching: if the (re)assoc request carries a PMKID we have cached,
        // skip a fresh SAE exchange and run the 4-way with the cached PMK.
        let requested_pmkids = dot11::parse_rsn_pmkids(assoc_rsn).unwrap_or_default();
        let requested_pmksa = !requested_pmkids.is_empty();
        let pmksa_identity = self
            .stations
            .get(&sta)
            .and_then(|s| s.client_mld_mac)
            .unwrap_or(sta);
        self.expire_pmksa();
        for pmkid in requested_pmkids {
            if let Some(entry) = self.pmksa_cache.get(&(pmkid, pmksa_identity)) {
                let pmk = entry.pmk;
                let sha256 = entry.sha256;
                if let Some(s) = self.stations.get_mut(&sta) {
                    s.set_pmk(Some(pmk));
                    s.sha256 = sha256;
                }
                break;
            }
        }

        // Match reference AP/802.11 PMKSA fallback: an SAE station that open-auths
        // with a PMKID the AP no longer knows must receive status 53. A generic
        // failure leaves Apple clients retrying that stale PMKID indefinitely;
        // INVALID_PMKID tells them to discard it and perform full SAE again.
        // A PMK already established by a fresh SAE exchange remains valid even
        // if that association happens to include an unknown PMKID.
        if requests_sae
            && requested_pmksa
            && self
                .stations
                .get(&sta)
                .map(|s| s.pmk.is_none())
                .unwrap_or(true)
        {
            let sc = self.next_sc();
            out.tx(dot11::build_assoc_resp_reject(
                &self.mac,
                &sta,
                dot11::STATUS_INVALID_PMKID,
                if reassoc {
                    dot11::SUBTYPE_REASSOC_RESP
                } else {
                    dot11::SUBTYPE_ASSOC_RESP
                },
                sc,
            ));
            return;
        }

        // OWE: if the (re)assoc request carries a DH Parameter element, run the
        // Diffie-Hellman exchange and key the 4-way with the resulting PMK.
        let mut owe_dh_resp: Option<Vec<u8>> = None;
        if self.owe && frame.body.len() > 4 {
            if let Some((group, sta_pub)) = dot11::parse_dh_param(&frame.body[4..]) {
                if group != 19 {
                    self.reject_assoc_status(
                        &sta,
                        reassoc,
                        dot11::STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED,
                        out,
                    );
                    return;
                }
                let (ap_priv, ap_pub) = sae::owe_keypair();
                if let Some((pmk, _pmkid)) =
                    sae::owe_derive(&ap_priv, &sta_pub, &sta_pub, &ap_pub, group)
                {
                    if let Some(s) = self.stations.get_mut(&sta) {
                        s.set_pmk(Some(pmk));
                        s.sha256 = true;
                        s.owe = true; // OWE uses the HMAC-SHA256 EAPOL MIC
                    }
                    owe_dh_resp = Some(dot11::build_dh_param_element(group, &ap_pub));
                }
            }
        }

        let resp_subtype = if reassoc {
            0x03
        } else {
            dot11::SUBTYPE_ASSOC_RESP
        };

        // Anti-downgrade: a WPA3-SAE-only or OWE-only AP must not associate a
        // station that has no SAE/OWE/cached PMK — otherwise it would fall back
        // to the bare PSK 4-way (`self.pmk`), defeating WPA3/OWE and exposing the
        // password to offline attack. SAE sets `pmk` at auth; OWE sets it from the
        // DH element above (so an OWE assoc that *omits* the DH Parameter element
        // leaves `pmk` unset and is rejected here, never falling back to the PSK
        // 4-way); PMKSA fast-reconnect sets it from the cache. A station that did
        // none of those is denied with status 1. Transition/WPA2 modes intentionally
        // still allow the PSK path.
        if matches!(
            self.security_mode(),
            dot11::SecurityMode::Wpa3Sae | dot11::SecurityMode::Owe
        ) && self
            .stations
            .get(&sta)
            .map(|s| s.pmk.is_none())
            .unwrap_or(true)
        {
            let sc = self.next_sc();
            out.tx(dot11::build_assoc_resp_reject(
                &self.mac,
                &sta,
                dot11::STATUS_UNSPECIFIED_FAILURE,
                resp_subtype,
                sc,
            ));
            return;
        }

        let aid = self.next_aid();
        let sc = self.next_sc();
        let mut assoc = dot11::build_assoc_resp(
            &self.mac,
            &sta,
            &self.ssid,
            self.channel,
            aid,
            sc,
            resp_subtype,
            &self.country,
            self.channel_width,
            self.band6,
            self.wmm,
            self.phy_mode,
            self.punct,
        );
        if self.beacon_prot {
            // Association Response fixed fields are Capability, Status and AID.
            dot11::enable_beacon_protection_capability(&mut assoc[30..]);
        }
        // Advertise a BSS Max Idle Period (~300 s) so the STA sends keep-alives.
        assoc.extend_from_slice(&dot11::bss_max_idle_element(300));
        // 802.11be MLD: echo our Basic Multi-Link element to an MLD station so it
        // completes the MLD (re)association.
        if self.mld
            && self
                .stations
                .get(&sta)
                .map(|s| s.client_mld_mac.is_some())
                .unwrap_or(false)
        {
            let requested = self
                .stations
                .get(&sta)
                .map(|s| s.client_mld_links.as_slice())
                .unwrap_or(&[]);
            let info = self.mld_assoc_link_info_for(requested);
            assoc.extend_from_slice(&self.mld_basic_element(self.link_id, &info));
            assoc.extend_from_slice(&self.mld_tid_to_link_element());
        }
        if let Some(dh) = owe_dh_resp {
            assoc.extend_from_slice(&dh); // OWE DH Parameter element
        }

        // If the 4-way has already advanced to Message 3 (we verified this STA's
        // m2 and are awaiting m4), a repeated Association Request must NOT regress
        // the handshake back to m1: rebuilding m1 here would replace the cached m3
        // and derive a fresh PTK, so the STA — which already has the PTK from m3 —
        // could never finish. Re-send the Assoc Response and let the pending m3
        // keep retransmitting. (Seen with iPhones, which re-associate aggressively
        // via PMKSA between m2 and m3.)
        let awaiting_m4 = self
            .stations
            .get(&sta)
            .map(|s| s.awaiting_m4 && s.pending_eapol.is_some())
            .unwrap_or(false);
        if awaiting_m4 {
            out.tx(assoc);
            if let Some(m3) = self
                .stations
                .get(&sta)
                .and_then(|s| s.pending_eapol.clone())
            {
                if let Some(s) = self.stations.get_mut(&sta) {
                    s.eapol_tx = Instant::now();
                    s.eapol_retries = 0;
                    s.eapol_acked = false;
                }
                out.frames.push(m3); // already radiotap-prefixed
            }
            return;
        }

        // Prepare EAPOL message 1. The ANonce must stay STABLE for the whole of a
        // station's *initial* 4-way — including across a deauthenticate+reconnect
        // — so the client's Message 2 (keyed to whichever m1 it received) always
        // verifies. A fresh ANonce per Association Request instead leaves us one
        // ANonce ahead of a client that is still answering an earlier m1, which
        // never converges (the ath12k livelock). Priority: (1) the ANonce already
        // on a still-in-progress station, (2) the ANonce held for this MAC from a
        // torn-down-but-incomplete handshake (`pending_anonce`), else a fresh one.
        //
        // Reuse is KRACK-safe because this ANonce/replay pair is consumed as soon
        // as m2 verifies, before m3 can install a PTK at either peer.
        let now = Instant::now();
        self.pending_anonce
            .retain(|_, pending| now.duration_since(pending.created_at) < ANONCE_HOLD);
        let existing_station = self
            .stations
            .get(&sta)
            .filter(|s| s.eapol_ready)
            .and_then(|s| s.anonce.map(|anonce| (anonce, s.eapol_replay)));
        let existing_pending = self
            .pending_anonce
            .get(&sta)
            .map(|pending| (pending.anonce, pending.replay_counter));
        let (anonce, m1_replay) = match existing_station.or(existing_pending) {
            Some(pending) => pending,
            None => (
                self.test_anonce.unwrap_or_else(random_bytes::<32>),
                self.next_eapol_replay(),
            ),
        };
        self.pending_anonce.insert(
            sta,
            PendingHandshake {
                anonce,
                replay_counter: m1_replay,
                created_at: now,
            },
        );
        {
            let entry = self.stations.get_mut(&sta).unwrap();
            entry.anonce = Some(anonce);
            entry.eapol_ready = true;
            entry.eapol_replay = m1_replay;
            entry.m1_replay = m1_replay;
            entry.ptk_candidates.clear();
        }
        let (sha256, owe) = self
            .stations
            .get(&sta)
            .map(|s| (s.sha256, s.owe))
            .unwrap_or((false, false));
        let m1_sc = self.next_sc();
        let mld_station = self.mld
            && self
                .stations
                .get(&sta)
                .and_then(|s| s.client_mld_mac)
                .is_some();
        let m1 = if mld_station {
            dot11::build_eapol_m1_mld(
                &self.mac,
                &sta,
                &anonce,
                m1_replay,
                m1_sc,
                dot11::KeyMic::select(sha256, owe),
                &self.mld_mac,
            )
        } else {
            dot11::build_eapol_m1_for_key_length(
                &self.mac,
                &sta,
                &anonce,
                m1_replay,
                m1_sc,
                dot11::KeyMic::select(sha256, owe),
                self.pairwise_cipher.key_len() as u16,
            )
        };

        // Cache m1 (radiotap-prefixed) so it can be retransmitted if m2 is lost.
        if let Some(entry) = self.stations.get_mut(&sta) {
            entry.pending_eapol = Some(prepend_radiotap(m1.clone()));
            entry.eapol_tx = Instant::now();
            entry.eapol_retries = 0;
            entry.eapol_acked = false;
        }

        if std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
            eprintln!(
                "AP: TX m1 anonce={} sc={m1_sc}",
                anonce
                    .iter()
                    .map(|x| format!("{x:02x}"))
                    .collect::<String>()
            );
        }
        out.tx(assoc);
        out.tx(m1);
    }
}
