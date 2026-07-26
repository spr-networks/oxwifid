//! Supplicant-side four-way EAPOL processing.

use super::*;

impl Client {
    pub(super) fn send_eapol2(
        &mut self,
        ek: &dot11::EapolKey,
        protected: bool,
        out: &mut ClientOut,
    ) {
        let Some(bssid) = self.bssid else { return };

        // Derive into a PENDING candidate. Message 1 has no MIC, so nothing it
        // produces may touch the live session until message 3 authenticates it:
        // that is what lets an already-connected station answer an
        // authenticator-initiated rekey without dropping its current key, and
        // what stops a forged message 1 from destroying a working link or
        // poisoning the replay counter.
        let anonce = ek.key_nonce;
        let snonce = self.test_snonce.unwrap_or_else(random_bytes::<32>);

        // SAE/OWE/PSK-SHA256 use the SHA-256 key hierarchy; plain WPA2-PSK SHA-1.
        // For MLD the 4-way derives the PTK from the MLD MAC addresses.
        let sha256 = self.sae_pmk.is_some() || self.psk_sha256;
        let mut pmk = self.sae_pmk.unwrap_or(self.pmk);
        let aa = self.ap_mld_mac.unwrap_or(bssid);
        let spa = self.mld_mac.unwrap_or(self.mac);
        let tk_len = self.pairwise_cipher.key_len();
        let mut pending = PendingPtk {
            anonce,
            snonce,
            replay: ek.key_replay_counter,
            kck: [0; 16],
            kek: [0; 16],
            tk: [0; 16],
            pairwise_tk: [0; 32],
        };
        if sha256 {
            let mut ptk =
                crypto::derive_ptk_sha256_len(&pmk, &aa, &spa, &anonce, &snonce, 32 + tk_len);
            pending.kck.copy_from_slice(&ptk[..16]);
            pending.kek.copy_from_slice(&ptk[16..32]);
            pending.tk.copy_from_slice(&ptk[32..48]);
            pending.pairwise_tk[..tk_len].copy_from_slice(&ptk[32..32 + tk_len]);
            ptk.zeroize();
        } else {
            let mut ptk = crypto::custom_prf512(&pmk, &aa, &spa, &anonce, &snonce);
            pending.kck.copy_from_slice(&ptk[..16]);
            pending.kek.copy_from_slice(&ptk[16..32]);
            pending.tk.copy_from_slice(&ptk[32..48]);
            pending.pairwise_tk[..tk_len].copy_from_slice(&ptk[32..32 + tk_len]);
            ptk.zeroize();
        }
        pmk.zeroize();

        let sc = self.next_sc();
        let kck = pending.kck;
        let replay = pending.replay;
        self.pending_ptk = Some(pending);
        let oci = if self.ocv {
            Some((
                dot11::operating_class(self.channel, 20, false),
                self.channel,
            )) // 20 MHz STA data plane
        } else {
            None
        };
        // m2 must echo the RSN this STA advertised in its assoc request.
        let mut supp_rsn: Vec<u8> = if self.mld_mac.is_some() {
            let mut r = dot11::AMLD_RSN_SAE.to_vec();
            r.extend_from_slice(&dot11::RSNXE_H2E);
            r
        } else if self.psk_sha256 {
            dot11::RSN_PSK_SHA256.to_vec()
        } else if self.owe {
            dot11::RSN_OWE.to_vec()
        } else if sha256 {
            let mut r = dot11::RSN_WPA3.to_vec();
            r.extend_from_slice(&dot11::RSNXE_H2E);
            r
        } else {
            dot11::RSN.to_vec()
        };
        if self.mld_mac.is_none() {
            supp_rsn[13] = self.pairwise_cipher.suite_type();
        }
        // MLD: m2 must carry the STA's MLD MAC in a MAC Address KDE (00-0F-AC:3)
        // plus one MLO Link KDE (00-0F-AC:19) per affiliated link (link 1 here),
        // else the AP rejects ("Invalid MLD address" / "Expecting N MLD links").
        if let Some(mld) = self.mld_mac {
            supp_rsn.extend_from_slice(&[0xdd, 0x0a, 0x00, 0x0f, 0xac, 0x03]);
            supp_rsn.extend_from_slice(&mld);
            if let Some(l1) = self.link1_mac {
                // link info = link_id 1, no RSNE; then the link-1 STA MAC.
                supp_rsn.extend_from_slice(&[0xdd, 0x0b, 0x00, 0x0f, 0xac, 0x13, 0x01]);
                supp_rsn.extend_from_slice(&l1);
            }
        }
        let mic = self.key_mic();
        let message_2 = dot11::build_eapol_m2(dot11::EapolM2Params {
            bssid: &bssid,
            sta: &self.mac,
            snonce: &snonce,
            kck: &kck,
            supp_rsn: &supp_rsn,
            replay_counter: replay,
            sc,
            mic,
            oci,
        });
        self.tx_eapol(message_2, protected, out);
        self.eapol_state = 1;
    }

    /// Re-send M2 after a duplicate M1 without changing the SNonce or derived
    /// PTK. A supplicant that generates a new SNonce on every AP retry creates
    /// ambiguous PTK candidates and unnecessary interoperability risk.
    pub(super) fn send_eapol2_retry(
        &mut self,
        ek: &dot11::EapolKey,
        protected: bool,
        out: &mut ClientOut,
    ) {
        let original_override = self.test_snonce;
        self.test_snonce = self.pending_ptk.as_ref().map(|p| p.snonce);
        self.send_eapol2(ek, protected, out);
        self.test_snonce = original_override;
    }

    /// Send an EAPOL-Key frame over the transport the peer's message arrived on.
    ///
    /// Once a pairwise key is installed the controlled port is protected, so the
    /// reply must be CCMP-encapsulated rather than sent as bare 802.11 data.
    pub(super) fn tx_eapol(&mut self, frame: Vec<u8>, protected: bool, out: &mut ClientOut) {
        if !protected {
            out.tx(frame);
            return;
        }
        let Some(bssid) = self.bssid else { return };
        let Some(eapol) = dot11::Dot11::parse(&frame)
            .and_then(|parsed| parsed.eapol_frame().map(ToOwned::to_owned))
        else {
            return;
        };
        let mut ethernet = Vec::with_capacity(14 + eapol.len());
        ethernet.extend_from_slice(&bssid);
        ethernet.extend_from_slice(&self.mac);
        ethernet.extend_from_slice(&dot11::ETHERTYPE_EAPOL.to_be_bytes());
        ethernet.extend_from_slice(&eapol);
        if let Some(encrypted) = self.encrypt_uplink(&ethernet) {
            out.frames.push(encrypted);
        }
    }

    pub(super) fn send_eapol4(
        &mut self,
        eapol_frame: &[u8],
        ek: &dot11::EapolKey,
        protected: bool,
        out: &mut ClientOut,
    ) {
        let Some(bssid) = self.bssid else { return };

        // A lower counter is stale. A counter equal to the already-installed M3
        // is a retry after M4 loss: it must be re-ACKed without reinstalling any
        // key or resetting a packet number. The explicit debug pause retains its
        // diagnostic behavior.
        let duplicate_m3 = !self.pause_m3
            && self.eapol_state == 2
            && self.ptk_installed
            && ek.key_replay_counter == self.eapol_replay;
        // A fresh M3 needs a candidate to verify it against, and its counter must
        // be at least the M1 that candidate answers (the authenticator advances
        // the counter between M1 and M3) and newer than anything we have already
        // authenticated. The binding to *our* handshake is the MIC under the
        // candidate's KCK, checked below; these bounds only reject replays.
        let fresh_m3 = self
            .pending_ptk
            .as_ref()
            .is_some_and(|p| ek.key_replay_counter >= p.replay)
            && (self.pause_m3 || ek.key_replay_counter > self.eapol_replay);
        if !self.pause_m3 && !duplicate_m3 && !fresh_m3 {
            return;
        }

        // Verify the AP's MIC over message 3. A duplicate is checked with the
        // installed KCK; a fresh M3 with the pending candidate's KCK, which is
        // precisely what proves the candidate came from the real AP.
        let kck = if duplicate_m3 {
            self.kck
        } else {
            match self.pending_ptk.as_ref() {
                Some(p) => p.kck,
                None => return,
            }
        };
        let mic_off = 4 + ek.mic_offset;
        let mut to_check = eapol_frame.to_vec();
        if to_check.len() < mic_off + 16 {
            return;
        }
        for b in to_check[mic_off..mic_off + 16].iter_mut() {
            *b = 0;
        }
        let mut computed = self.key_mic().compute(&kck, &to_check);
        let mic_valid = crypto::constant_time_eq(&computed, &ek.key_mic);
        computed.zeroize();
        if !mic_valid {
            return; // bad MIC, drop
        }

        // A duplicate M3 is authenticated above, then goes straight to the M4
        // response below. In particular, it never unwraps or reinstalls the GTK.
        if !duplicate_m3 {
            let kek = match self.pending_ptk.as_ref() {
                Some(p) => p.kek,
                None => return,
            };
            let Some(mut unwrapped) = crypto::aes_unwrap(&kek, &ek.key_data) else {
                if self.pause_m3 {
                    eprintln!("M3_UNWRAP_FAIL kd_len={}", ek.key_data.len());
                }
                return;
            };
            if self.pause_m3 {
                // The UAF-leaked IGTK (back-indexed heap bytes) rides in here.
                eprintln!("M3_KEYDATA {}", hex_str(&unwrapped));
            }
            if self.ocv {
                // The AP's OCI carries ITS operating class (e.g. 128 at 80 MHz)
                // — pin the primary channel + band, not an identical class.
                match dot11::parse_oci_kde(&unwrapped) {
                    Some((oc, ch))
                        if ch == self.channel
                            && dot11::oci_class_matches_band(oc, self.channel, false) => {}
                    _ => {
                        unwrapped.zeroize();
                        return;
                    } // missing or mismatched OCI -> possible MITM, drop
                }
            }
            if !self.install_group_keys(&unwrapped, ek.key_rsc) {
                unwrapped.zeroize();
                return;
            }
            unwrapped.zeroize();
            self.eapol_replay = ek.key_replay_counter;
            self.commit_pending_ptk();
        }

        if self.pause_m3 {
            // Never ack m3: stay at eapol_state=1 so the AP keeps retransmitting it.
            return;
        }

        let sc = self.next_sc();
        let kck = self.kck;
        let mic = self.key_mic();
        // MLD: m4 must carry the STA's MLD MAC (MAC Address KDE), like m2, or the
        // AP rejects msg 4/4 and never authorizes the port (uplink data dropped).
        let message_4 = dot11::build_eapol_m4_mld(
            &bssid,
            &self.mac,
            &kck,
            self.eapol_replay,
            sc,
            mic,
            self.mld_mac.as_ref(),
        );
        self.tx_eapol(message_4, protected, out);
        self.set_connected_state(4);
        self.note_ap_activity();
        // The pairwise key is now installed (m3 verified, m4 sent); only from
        // here may protected unicast management frames be validated with `tk`.
        self.ptk_installed = true;
        self.eapol_state = 2;
    }

    /// Promote the authenticated PTK candidate to the live session key.
    ///
    /// Called only once the matching message 3 has verified under the
    /// candidate's own KCK. The packet number and both receive replay windows
    /// are reset here and nowhere else: they are properties of the key, and
    /// restarting them against a key that had already used those nonces is the
    /// keystream-reuse bug at the heart of a key-reinstallation attack.
    fn commit_pending_ptk(&mut self) {
        let Some(pending) = self.pending_ptk.take() else {
            return;
        };
        let tk_len = self.pairwise_cipher.key_len();
        // Replay counters and transmit packet numbers belong to the temporal
        // key, not to the handshake instance. A fresh, MIC-valid handshake will
        // normally derive a different PTK because both nonces change, but do
        // not rely on RNG uniqueness for the KRACK invariant: if identical TK
        // material is delivered under a newer EAPOL replay counter, update the
        // authenticated KCK/KEK/nonce state without reinstalling the TK or
        // resetting any data/management replay window.
        let same_temporal_key = self.ptk_installed
            && crypto::constant_time_eq(
                &self.pairwise_tk[..tk_len],
                &pending.pairwise_tk[..tk_len],
            );
        self.anonce.zeroize();
        self.snonce.zeroize();
        self.kck.zeroize();
        self.kek.zeroize();
        self.tk.zeroize();
        self.pairwise_tk.zeroize();
        self.anonce = pending.anonce;
        self.snonce = pending.snonce;
        self.kck = pending.kck;
        self.kek = pending.kek;
        self.tk = pending.tk;
        self.pairwise_tk = pending.pairwise_tk;
        if !same_temporal_key {
            self.client_pn = 1;
            self.last_rx_pn = [0; 17];
            self.last_rx_mgmt_pn = 0;
        }
    }
}
