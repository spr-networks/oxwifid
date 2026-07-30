//! Client-side SAE authentication state-machine handling.

use super::*;

impl Client {
    pub(super) fn disconnect(&mut self) {
        self.connected = 0;
        self.reset_session_keys();
        self.bssid = None;
        self.gtk_key_id = 1;
        self.sae = None;
        self.set_sae_pmk(None);
    }

    /// Send our SAE commit to start the exchange (status 126 for H2E, 0 for
    /// hunting-and-pecking).
    pub(super) fn start_sae(&mut self, bssid: &[u8; 6], out: &mut ClientOut) {
        // MLD SAE: because the auth frames carry the STA's MLD MAC (multi_link_auth),
        // the AP derives the SAE PWE/keys from the MLD MAC addresses — so we must too.
        // The auth frames themselves stay link-addressed.
        let sae_sta = self.mld_mac.unwrap_or(self.mac);
        let sae_ap = self.ap_mld_mac.unwrap_or(*bssid);
        let sae = if self.sae_h2e {
            Some(sae::Sae::new_h2e(
                &self.ssid,
                &self.password,
                None,
                &sae_sta,
                &sae_ap,
            ))
        } else {
            sae::Sae::new_hunting_pecking(&self.password, &sae_sta, &sae_ap)
        };
        let Some(mut sae) = sae else { return };
        sae.prepare_commit(None);
        let mut commit = sae.write_commit();
        // MLD: carry the STA's MLD MAC in the SAE commit so the AP records it
        // (the assoc's MLD MAC must match the auth's).
        if let Some(mld) = self.mld_mac {
            commit.extend_from_slice(&dot11::multi_link_auth(&mld));
        }
        let status = if self.sae_h2e {
            dot11::STATUS_SAE_H2E
        } else {
            dot11::STATUS_SUCCESS
        };
        let sc = self.next_sc();
        out.tx(dot11::build_sae_auth(
            bssid, &self.mac, bssid, 0, sc, 1, status, &commit,
        ));
        self.sae = Some(sae);
    }

    /// Handle an SAE authentication frame from the AP (commit then confirm).
    pub(super) fn handle_sae_auth(
        &mut self,
        seq: u16,
        status: u16,
        payload: &[u8],
        out: &mut ClientOut,
    ) {
        if seq == 1 && status == dot11::STATUS_ANTI_CLOGGING_TOKEN_REQ {
            let token = if self.sae_h2e {
                if payload.len() != 2 + 3 + 32
                    || payload[2] != 255
                    || payload[3] != 33
                    || payload[4] != 93
                {
                    return;
                }
                &payload[5..]
            } else {
                if payload.len() != 2 + 32 {
                    return;
                }
                &payload[2..]
            };
            let Some(sae) = self.sae.as_ref() else {
                return;
            };
            let mut commit = sae.write_commit();
            if self.sae_h2e {
                commit.extend_from_slice(&[255, 33, 93]);
                commit.extend_from_slice(token);
            } else {
                commit.splice(2..2, token.iter().copied());
            }
            if let Some(mld) = self.mld_mac {
                commit.extend_from_slice(&dot11::multi_link_auth(&mld));
            }
            let Some(bssid) = self.bssid else { return };
            let sc = self.next_sc();
            out.tx(dot11::build_sae_auth(
                &bssid,
                &self.mac,
                &bssid,
                0,
                sc,
                1,
                if self.sae_h2e {
                    dot11::STATUS_SAE_H2E
                } else {
                    dot11::STATUS_SUCCESS
                },
                &commit,
            ));
            return;
        }
        match seq {
            1 => {
                let expected = if self.sae_h2e {
                    dot11::STATUS_SAE_H2E
                } else {
                    dot11::STATUS_SUCCESS
                };
                if status != expected {
                    return;
                }
                // AP commit -> derive keys, send our confirm
                let confirm = {
                    let Some(sae) = self.sae.as_mut() else { return };
                    if sae.parse_peer_commit(payload).is_err() || sae.is_reflection() {
                        return;
                    }
                    if sae.process_commit().is_err() {
                        return;
                    }
                    sae.write_confirm().ok()
                };
                let Some(mut confirm) = confirm else {
                    // Exhausting send-confirm requires a fresh SAE exchange;
                    // never reuse the final counter under the old KCK.
                    self.sae = None;
                    if let Some(bssid) = self.bssid {
                        self.start_sae(&bssid, out);
                    }
                    return;
                };
                if let Some(mld) = self.mld_mac {
                    confirm.extend_from_slice(&dot11::multi_link_auth(&mld));
                }
                let Some(bssid) = self.bssid else { return };
                let sc = self.next_sc();
                out.tx(dot11::build_sae_auth(
                    &bssid,
                    &self.mac,
                    &bssid,
                    0,
                    sc,
                    2,
                    dot11::STATUS_SUCCESS,
                    &confirm,
                ));
            }
            2 => {
                if status != dot11::STATUS_SUCCESS {
                    return;
                }
                // AP confirm -> verify, store PMK, associate
                let verified = self
                    .sae
                    .as_mut()
                    .map(|s| s.check_confirm(payload).is_ok())
                    .unwrap_or(false);
                if !verified {
                    return;
                }
                let pmk_pmkid = self.sae.as_ref().map(|s| {
                    let mut p = [0u8; 32];
                    p.copy_from_slice(&s.pmk);
                    let mut id = [0u8; 16];
                    id.copy_from_slice(&s.pmkid);
                    (p, id)
                });
                self.set_sae_pmk(pmk_pmkid.map(|(p, _)| p));
                let Some(bssid) = self.bssid else { return };
                // Cache the PMKSA for fast reconnect.
                if let Some((pmk, pmkid)) = pmk_pmkid {
                    self.set_cached_pmksa(Some((bssid, pmkid, pmk)));
                }
                let sc = self.next_sc();
                let ssid = self.ssid.clone();
                // SAE associations must advertise the SAE AKM, not WPA2-PSK,
                // otherwise the AP rejects with "Invalid AKMP". For MLD, send the
                // 2-link assoc carrying the per-STA profile.
                if let (Some(mld), Some(l1)) = (self.mld_mac, self.link1_mac) {
                    out.tx(dot11::build_assoc_req_mld(
                        &bssid, &self.mac, &mld, &l1, &ssid, sc,
                    ));
                } else {
                    out.tx(self.with_wmm(dot11::build_assoc_req_sae_for_cipher(
                        &bssid,
                        &self.mac,
                        &ssid,
                        sc,
                        self.pairwise_cipher,
                    )));
                }
            }
            _ => {}
        }
    }
}
