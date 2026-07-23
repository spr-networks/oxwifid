//! Supplicant-side four-way EAPOL processing.

use super::*;

impl Client {
    pub(super) fn send_eapol2(&mut self, m1: &dot11::Dot11, out: &mut ClientOut) {
        let Some(bssid) = self.bssid else { return };
        let Some(key_body) = m1.eapol_key_body() else {
            return;
        };
        let Some(ek) = dot11::EapolKey::parse(key_body) else {
            return;
        };

        self.eapol_replay = ek.key_replay_counter; // remember m1's replay counter
        self.anonce = ek.key_nonce;
        self.snonce = self.test_snonce.unwrap_or_else(random_bytes::<32>);

        // SAE/OWE/PSK-SHA256 use the SHA-256 key hierarchy; plain WPA2-PSK SHA-1.
        // For MLD the 4-way derives the PTK from the MLD MAC addresses.
        let sha256 = self.sae_pmk.is_some() || self.psk_sha256;
        let mut pmk = self.sae_pmk.unwrap_or(self.pmk);
        let aa = self.ap_mld_mac.unwrap_or(bssid);
        let spa = self.mld_mac.unwrap_or(self.mac);
        let tk_len = self.pairwise_cipher.key_len();
        self.pairwise_tk.zeroize();
        if sha256 {
            let mut ptk = crypto::derive_ptk_sha256_len(
                &pmk,
                &aa,
                &spa,
                &self.anonce,
                &self.snonce,
                32 + tk_len,
            );
            self.kck.copy_from_slice(&ptk[..16]);
            self.kek.copy_from_slice(&ptk[16..32]);
            self.tk.copy_from_slice(&ptk[32..48]);
            self.pairwise_tk[..tk_len].copy_from_slice(&ptk[32..32 + tk_len]);
            ptk.zeroize();
        } else {
            let mut ptk = crypto::custom_prf512(&pmk, &aa, &spa, &self.anonce, &self.snonce);
            self.kck.copy_from_slice(&ptk[..16]);
            self.kek.copy_from_slice(&ptk[16..32]);
            self.tk.copy_from_slice(&ptk[32..48]);
            self.pairwise_tk[..tk_len].copy_from_slice(&ptk[32..32 + tk_len]);
            ptk.zeroize();
        }
        pmk.zeroize();
        self.client_pn = 1;

        let sc = self.next_sc();
        let kck = self.kck;
        let snonce = self.snonce;
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
        out.tx(dot11::build_eapol_m2(
            &bssid,
            &self.mac,
            &snonce,
            &kck,
            &supp_rsn,
            self.eapol_replay,
            sc,
            mic,
            oci,
        ));
        self.eapol_state = 1;
    }

    /// Re-send M2 after a duplicate M1 without changing the SNonce or derived
    /// PTK. A supplicant that generates a new SNonce on every AP retry creates
    /// ambiguous PTK candidates and unnecessary interoperability risk.
    pub(super) fn send_eapol2_retry(&mut self, m1: &dot11::Dot11, out: &mut ClientOut) {
        let original_override = self.test_snonce;
        self.test_snonce = Some(self.snonce);
        self.send_eapol2(m1, out);
        self.test_snonce = original_override;
    }

    pub(super) fn send_eapol4(&mut self, m3: &dot11::Dot11, out: &mut ClientOut) {
        let Some(bssid) = self.bssid else { return };
        let Some(eapol_frame) = m3.eapol_frame() else {
            return;
        };
        let Some(key_body) = m3.eapol_key_body() else {
            return;
        };
        let Some(ek) = dot11::EapolKey::parse(key_body) else {
            return;
        };

        // A lower counter is stale. A counter equal to the already-installed M3
        // is a retry after M4 loss: it must be re-ACKed without reinstalling any
        // key or resetting a packet number. The explicit debug pause retains its
        // diagnostic behavior.
        let duplicate_m3 = !self.pause_m3
            && self.eapol_state == 2
            && self.ptk_installed
            && ek.key_replay_counter == self.eapol_replay;
        if !self.pause_m3
            && (ek.key_replay_counter < self.eapol_replay
                || (!duplicate_m3 && ek.key_replay_counter == self.eapol_replay))
        {
            return;
        }

        // verify the AP's MIC over message 3
        let mic_off = 4 + ek.mic_offset;
        let mut to_check = eapol_frame.to_vec();
        if to_check.len() < mic_off + 16 {
            return;
        }
        for b in to_check[mic_off..mic_off + 16].iter_mut() {
            *b = 0;
        }
        let mut computed = self.key_mic().compute(&self.kck, &to_check);
        let mic_valid = crypto::constant_time_eq(&computed, &ek.key_mic);
        computed.zeroize();
        if !mic_valid {
            return; // bad MIC, drop
        }

        // A duplicate M3 is authenticated above, then goes straight to the M4
        // response below. In particular, it never unwraps or reinstalls the GTK.
        if !duplicate_m3 {
            let Some(mut unwrapped) = crypto::aes_unwrap(&self.kek, &ek.key_data) else {
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
            if !self.install_group_keys(&unwrapped, false) {
                unwrapped.zeroize();
                return;
            }
            unwrapped.zeroize();
            self.eapol_replay = ek.key_replay_counter;
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
        out.tx(dot11::build_eapol_m4_mld(
            &bssid,
            &self.mac,
            &kck,
            self.eapol_replay,
            sc,
            mic,
            self.mld_mac.as_ref(),
        ));
        self.set_connected_state(4);
        self.note_ap_activity();
        // The pairwise key is now installed (m3 verified, m4 sent); only from
        // here may protected unicast management frames be validated with `tk`.
        self.ptk_installed = true;
        self.eapol_state = 2;
    }
}
