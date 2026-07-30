//! Top-level receive dispatch for management, EAPOL, and protected data.

use super::*;

impl Client {
    /// Dispatch one EAPOL-Key message from the AP, from either transport:
    /// `protected` distinguishes a bare 802.11 data frame on the uncontrolled
    /// port from one that arrived CCMP-encapsulated on the controlled port.
    /// Replies go back the same way.
    pub(super) fn handle_eapol_key(
        &mut self,
        eapol: &[u8],
        ek: &dot11::EapolKey,
        protected: bool,
        out: &mut ClientOut,
    ) {
        // Message 1 is the only key message with no MIC, which is what lets a
        // forged one be injected at all. Once a pairwise key is installed the AP
        // carries EAPOL inside protected data, so an unprotected, MIC-less
        // pairwise key message at that point cannot have come from the AP —
        // drop it rather than let it churn the handshake state of a working
        // session. Gated on PMF: without PMF an attacker can
        // simply deauthenticate instead, so refusing costs interoperability for
        // no gain.
        if !protected
            && self.ptk_installed
            && self.sae_pmk.is_some()
            && ek.is_pairwise()
            && !ek.has_key_mic()
        {
            return;
        }

        let before = out.frames.len();
        if self.connected >= 4 {
            // Group Key Handshake message 1 (GTK rekey).
            if !ek.is_pairwise() {
                if self.valid_group_m1(ek) {
                    self.handle_group_rekey(eapol, ek, protected, out);
                    if out.frames.len() != before {
                        self.note_ap_activity();
                    }
                }
                return;
            }
            // The AP retransmits message 3 if our message 4 was lost.
            // Verify and re-ACK it, but never reinstall its keys.
            if self.eapol_state == 2 {
                if self.valid_m3(ek) {
                    self.send_eapol4(eapol, ek, protected, out);
                } else if self.valid_m1(ek) && self.is_m1_fresh(ek) {
                    // Authenticator-initiated PTK rekey: the AP may start a new
                    // 4-way at any time on an established link. Answer it, but
                    // keep the installed PTK carrying traffic — the candidate
                    // derived here replaces it only once its message 3 verifies,
                    // so a forged message 1 cannot drop the session or advance
                    // the replay counter.
                    self.send_eapol2(ek, protected, out);
                }
                if out.frames.len() != before {
                    self.note_ap_activity();
                }
                return;
            }
        }
        if self.eapol_state == 0 {
            if self.valid_m1(ek) {
                self.send_eapol2(ek, protected, out);
            }
        } else if self.eapol_state == 1 {
            if self.valid_m3(ek) {
                self.send_eapol4(eapol, ek, protected, out);
            } else if self.valid_m1(ek) && self.is_m1_retry(ek) {
                // Lost M2: reproduce it with the same SNonce/PTK.
                self.send_eapol2_retry(ek, protected, out);
            } else if self.valid_m1(ek) && self.is_m1_fresh(ek) {
                // The AP restarted the 4-way (or a rekey superseded an
                // unfinished one) with a newer replay counter.
                self.send_eapol2(ek, protected, out);
            }
        }
        if out.frames.len() != before {
            self.note_ap_activity();
        }
    }

    pub fn handle_incoming(&mut self, radiotap_frame: &[u8]) -> ClientOut {
        let mut out = ClientOut::default();
        let bad_fcs = dot11::radiotap_bad_fcs(radiotap_frame);
        let stripped = dot11::strip_radiotap(radiotap_frame);
        if std::env::var_os("RUSTAP_CLIENT_RX_DEBUG").is_some() {
            if let Some(raw) = stripped {
                let is_raw_beacon = raw.len() >= 24 && raw[0] & 0xfc == 0x80;
                let is_target = self
                    .target_bssid
                    .is_none_or(|target| raw.get(16..22) == Some(target.as_slice()));
                if is_raw_beacon && is_target {
                    eprintln!(
                        "client raw RX target beacon radiotap_len={} dot11_len={} bad_fcs={bad_fcs} radiotap={}",
                        radiotap_frame.len().saturating_sub(raw.len()),
                        raw.len(),
                        crate::util::to_hex(
                            &radiotap_frame[..radiotap_frame.len().saturating_sub(raw.len())]
                        )
                    );
                }
            }
        }
        // Some FullMAC monitor paths (observed on ath12k) mark every otherwise
        // parseable frame BAD_FCS. Keep the secure default, but allow a
        // deliberately scoped interoperability diagnostic; protected data and
        // EAPOL still have their own CCMP/MIC integrity checks.
        if bad_fcs && std::env::var_os("RUSTAP_CLIENT_IGNORE_BAD_FCS").is_none() {
            return out;
        }
        let Some(body) = stripped else {
            return out;
        };
        let Some(frame) = dot11::Dot11::parse(body) else {
            return out;
        };
        if frame.addr2 == self.mac {
            return out; // ignore our own frames
        }

        let is_mgmt = frame.frame_type() == dot11::TYPE_MGMT;
        let is_beacon = is_mgmt && frame.subtype() == dot11::SUBTYPE_BEACON;
        let beacon_matches = is_beacon && self.beacon_matches(&frame);
        if is_beacon
            && std::env::var_os("RUSTAP_CLIENT_RX_DEBUG").is_some()
            && self.target_bssid.is_none_or(|target| frame.addr3 == target)
        {
            let ssid = frame
                .body
                .get(12..)
                .and_then(|ies| dot11::find_ie_strict(ies, 0).ok().flatten())
                .map(String::from_utf8_lossy)
                .map(|ssid| ssid.into_owned())
                .unwrap_or_else(|| "<invalid>".to_string());
            eprintln!(
                "client RX beacon bssid={} ssid={ssid:?} len={} matches={beacon_matches}",
                crate::util::bytes_to_mac(&frame.addr3),
                body.len()
            );
        }

        // PMF enforcement: robust management frames (Deauth/Disassoc/Action).
        if is_mgmt
            && self.connected >= 2
            && (frame.subtype() == dot11::SUBTYPE_DEAUTH
                || frame.subtype() == dot11::SUBTYPE_DISASSOC
                || frame.subtype() == dot11::SUBTYPE_ACTION)
        {
            if !self.is_from_selected_ap(&frame) {
                return out;
            }
            self.handle_robust_mgmt(&frame, &mut out);
            return out;
        }

        // Beacon -> authenticate (SAE commit or open-system auth)
        if self.connected == 0 && beacon_matches {
            let bssid = frame.addr2;
            self.expire_cached_pmksa();
            self.reset_session_keys();
            self.bssid = Some(bssid);
            self.ap_wmm = Self::has_wmm(&frame.body[12..]);
            self.set_connected_state(1);
            self.note_ap_activity();
            // Learn the operating channel from the DS Parameter Set (for OCV).
            if frame.body.len() > 12 {
                if let Some(ds) = dot11::find_ie(&frame.body[12..], 3) {
                    if !ds.is_empty() {
                        self.channel = ds[0];
                    }
                }
            }
            // PMKSA caching fast reconnect: if we have a cached PMKSA for this
            // BSS, do open-system auth and restore the cached PMK (no SAE).
            if let Some((cbssid, _pmkid, pmk)) = self.cached_pmksa {
                if cbssid == bssid {
                    self.set_sae_pmk(Some(pmk));
                    self.pmksa_reconnect = true;
                    let sc = self.next_sc();
                    out.tx(dot11::build_auth_req(&bssid, &self.mac, sc));
                    return out;
                }
            }
            if self.sae_enabled {
                self.start_sae(&bssid, &mut out);
            } else {
                let sc = self.next_sc();
                out.tx(dot11::build_auth_req(&bssid, &self.mac, sc));
            }
            return out;
        }

        // Authentication frame from the AP
        if self.connected == 1 && is_mgmt && frame.subtype() == dot11::SUBTYPE_AUTH {
            if frame.addr1 != self.mac || !self.is_from_selected_ap(&frame) {
                return out;
            }
            if let Some(auth) = dot11::parse_auth(&frame.body) {
                if auth.algo == dot11::AUTH_ALG_SAE {
                    if !self.sae_enabled {
                        return out;
                    }
                    self.handle_sae_auth(auth.seq, auth.status, auth.payload, &mut out);
                    if !out.frames.is_empty() {
                        self.note_ap_activity();
                    }
                    return out;
                }
                if auth.algo != dot11::AUTH_ALG_OPEN
                    || auth.seq != 2
                    || auth.status != dot11::STATUS_SUCCESS
                    || (self.sae_enabled && !self.pmksa_reconnect)
                {
                    return out;
                }
            } else {
                return out;
            }
            self.note_ap_activity();
            // open-system auth response -> associate
            let bssid = frame.addr2;
            self.bssid = Some(bssid);
            let sc = self.next_sc();
            let ssid = self.ssid.clone();
            if self.pmksa_reconnect {
                if let Some((_, pmkid, _)) = self.cached_pmksa {
                    out.tx(self.with_wmm(dot11::build_assoc_req_pmkid(
                        &bssid, &self.mac, &ssid, &pmkid, sc,
                    )));
                    return out;
                }
            }
            if self.owe {
                // OWE: generate an ephemeral DH key and send it in the assoc req.
                let (priv_k, pub_b) = sae::owe_keypair();
                let dh = dot11::build_dh_param_element(19, &pub_b);
                self.owe_priv = Some(priv_k);
                self.owe_pub = Some(pub_b);
                out.tx(self.with_wmm(dot11::build_assoc_req_owe(
                    &bssid, &self.mac, &ssid, &dh, sc,
                )));
                return out;
            }
            if let (Some(mld), Some(l1)) = (self.mld_mac, self.link1_mac) {
                out.tx(dot11::build_assoc_req_mld(
                    &bssid, &self.mac, &mld, &l1, &ssid, sc,
                ));
            } else if self.psk_sha256 {
                out.tx(self.with_wmm(dot11::build_assoc_req_psk_sha256_for_cipher(
                    &bssid,
                    &self.mac,
                    &ssid,
                    sc,
                    self.pairwise_cipher,
                )));
            } else {
                out.tx(self.with_wmm(dot11::build_assoc_req_for_cipher(
                    &bssid,
                    &self.mac,
                    &ssid,
                    sc,
                    self.pairwise_cipher,
                )));
            }
            return out;
        }

        // Association response
        if self.connected == 1 && is_mgmt && frame.subtype() == dot11::SUBTYPE_ASSOC_RESP {
            if frame.addr1 != self.mac || !self.is_from_selected_ap(&frame) || frame.body.len() < 6
            {
                return out;
            }
            let status = u16::from_le_bytes([frame.body[2], frame.body[3]]);
            if status != dot11::STATUS_SUCCESS {
                // The AP may have restarted or expired its cache while this
                // process retained a PMKSA. Status 53 means the offered PMKID
                // is invalid; discard it and let the next beacon run full SAE.
                if status == dot11::STATUS_INVALID_PMKID && self.pmksa_reconnect {
                    self.set_cached_pmksa(None);
                    self.disconnect();
                }
                return out;
            }
            // OWE: derive the PMK from the AP's DH Parameter element.
            if self.owe {
                let mut derived = None;
                if let (Some(priv_k), Some(own_pub)) =
                    (self.owe_priv.as_ref(), self.owe_pub.as_ref())
                {
                    if let Some((group, ap_pub)) = dot11::parse_dh_param(&frame.body[6..]) {
                        derived = sae::owe_derive(priv_k, &ap_pub, own_pub, &ap_pub, group)
                            .map(|(pmk, _)| pmk);
                    }
                }
                let Some(pmk) = derived else {
                    return out;
                };
                self.set_sae_pmk(Some(pmk));
            }
            if self.sae_enabled && self.sae_pmk.is_none() {
                return out;
            }
            self.wmm_negotiated =
                self.wmm && (self.mld_mac.is_some() || Self::has_wmm(&frame.body[6..]));
            self.set_connected_state(2);
            self.note_ap_activity();
            return out;
        }

        // A valid beacon from the selected AP keeps the link-liveness timer
        // alive after association. It never restarts authentication by itself.
        if self.connected > 0
            && is_mgmt
            && frame.subtype() == dot11::SUBTYPE_BEACON
            && self.bssid == Some(frame.addr3)
            && self.beacon_matches(&frame)
        {
            self.note_ap_activity();
            return out;
        }

        // EAPOL key frames from the AP
        if self.connected > 1 && frame.is_eapol() {
            if !frame.from_ds() || frame.addr1 != self.mac || !self.is_from_selected_ap(&frame) {
                return out;
            }
            let (Some(eapol), Some(ek)) = (
                frame.eapol_frame().map(ToOwned::to_owned),
                frame.eapol_key_body().and_then(dot11::EapolKey::parse),
            ) else {
                return out;
            };
            self.handle_eapol_key(&eapol, &ek, false, &mut out);
            return out;
        }

        // Encrypted downlink data
        if self.connected > 3
            && frame.frame_type() == dot11::TYPE_DATA
            && frame.protected()
            && frame.from_ds()
        {
            if frame.is_fragment() || frame.is_amsdu() {
                return out;
            }
            let key_id = frame.ccmp_key_id();
            let group_ra = frame.addr1[0] & 0x01 != 0; // multicast/broadcast RA
            if !group_ra && frame.addr1 != self.mac {
                return out;
            }
            // The GTK (a group key, key id 1/2) may only decrypt group-addressed
            // frames. A unicast frame addressed to us must use the pairwise key
            // (key id 0); a unicast frame arriving under a group key id is forged
            // (any peer that knows the GTK could otherwise inject AP-sourced
            // unicast), so drop it.
            let use_group = key_id == self.gtk_key_id && key_id != 0;
            if use_group && !group_ra {
                return out; // unicast under a group key id — reject
            }
            if !use_group && (group_ra || key_id != 0) {
                return out; // group-addressed under a non-group key, or unknown key id
            }
            let Some(pn) = frame.ccmp_pn() else {
                return out;
            };
            // CCMP replay protection (separate counters for pairwise and group).
            let replay_index = frame.qos.map_or(16, |q| usize::from(q & 0x000f));
            let last = if use_group {
                self.last_rx_gpn[replay_index]
            } else {
                self.last_rx_pn[replay_index]
            };
            if pn <= last {
                return out; // replayed frame
            }
            // 802.11be (MLO) pairwise downlink: the AP CCMP-protects with the
            // MLD addresses while the header carries link addresses, so decrypt
            // with the MLD security context (mirroring the uplink translation).
            // Group (GTK) frames keep their as-sent addresses.
            let sec = match (use_group, self.mld_mac, self.ap_mld_mac, self.bssid) {
                (false, Some(mld), Some(ap_mld), Some(bssid)) => {
                    let sec_a1 = mld; // RA: our link addr -> our MLD
                    let sec_a2 = ap_mld; // TA: AP link0 BSSID -> AP MLD
                    let sec_a3 = if frame.addr3 == bssid {
                        ap_mld
                    } else {
                        frame.addr3
                    };
                    Some((sec_a1, sec_a2, sec_a3))
                }
                _ => None,
            };
            let decrypted = if use_group {
                dot11::decrypt_protected_data_sec(
                    dot11::DataCipher::Ccmp128,
                    &frame,
                    &self.gtk,
                    true,
                    sec,
                )
            } else {
                dot11::decrypt_protected_data_sec(
                    self.pairwise_cipher,
                    &frame,
                    &self.pairwise_tk[..self.pairwise_cipher.key_len()],
                    true,
                    sec,
                )
            };
            if let Some(eth) = decrypted {
                if use_group {
                    self.last_rx_gpn[replay_index] = pn;
                } else {
                    self.last_rx_pn[replay_index] = pn;
                }
                self.note_ap_activity();
                // Once a pairwise key is installed, reference AP carries Group-Key
                // EAPOL frames inside CCMP-protected data. Consume those on the
                // controlled port and return Message 2 under the PTK; never
                // leak them into the SPR-facing TAP as ordinary Ethernet.
                if eth.get(12..14) == Some(&dot11::ETHERTYPE_EAPOL.to_be_bytes()) {
                    if !use_group {
                        if let Some((eapol, ek)) = Self::ethernet_eapol_key(&eth) {
                            let eapol = eapol.to_vec();
                            self.handle_eapol_key(&eapol, &ek, true, &mut out);
                        }
                    }
                    return out;
                }
                out.to_network.push(eth);
            }
        }

        out
    }
}
