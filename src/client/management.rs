//! Protected management validation, replay defense, and disconnect handling.

use super::*;

impl Client {
    /// PMF enforcement for received robust management frames. Under PMF,
    /// unprotected Deauth/Disassoc/Action frames are dropped; only BIP-valid
    /// group frames or pairwise-cipher-valid unicast frames are acted upon.
    /// Without PMF (WPA2), deauth/disassoc are honoured as before.
    pub(super) fn handle_robust_mgmt(&mut self, frame: &dot11::Dot11, out: &mut ClientOut) {
        let pmf = self.sae_pmk.is_some();
        let group = frame.addr1[0] & 0x01 != 0;

        if frame.subtype() == dot11::SUBTYPE_ACTION {
            // Only SA Query is handled, and only when PMF-protected. Require the
            // PTK to be installed (never validate with the all-zero placeholder
            // key) and reject replays (PN must strictly increase).
            if !pmf || !frame.protected() || !self.ptk_installed {
                return;
            }
            let Some(plain) = dot11::decrypt_protected_mgmt_sec(
                self.pairwise_cipher,
                frame,
                &self.pairwise_tk[..self.pairwise_cipher.key_len()],
                self.mld_mgmt_rx_sec_addrs(),
            ) else {
                return;
            };
            match frame.ccmp_pn() {
                Some(pn) if pn > self.last_rx_mgmt_pn => self.last_rx_mgmt_pn = pn,
                _ => return, // replay or missing PN
            }
            // 802.11v BTM request: disassociate on disassoc-imminent.
            if plain.len() >= 4
                && plain[0] == dot11::ACTION_CATEGORY_WNM
                && plain[1] == dot11::WNM_BTM_REQUEST
            {
                if plain[3] & 0x04 != 0 {
                    self.disconnect();
                }
                return;
            }
            if let Some((action, trans_id)) = dot11::parse_sa_query(&plain) {
                if action == dot11::SA_QUERY_REQUEST {
                    if let Some(bssid) = self.bssid {
                        let Some(pn) = self.next_client_pn() else {
                            return;
                        };
                        let sc = self.next_sc();
                        let sec = self.mld_mgmt_tx_sec_addrs();
                        out.tx(dot11::build_protected_sa_query_for_cipher_sec(
                            self.pairwise_cipher,
                            &bssid,
                            &self.mac,
                            true,
                            true,
                            trans_id,
                            sc,
                            pn,
                            &self.pairwise_tk[..self.pairwise_cipher.key_len()],
                            sec,
                        ));
                    }
                }
            }
            return;
        }

        // Deauthentication / Disassociation
        let accept = if !pmf {
            true // legacy WPA2: no PMF, honour the frame
        } else if group {
            // Group-addressed: BIP-protected; verify the MIC, then require a
            // strictly increasing IPN (reject a replayed protected deauth).
            match self.igtk {
                Some(igtk)
                    if dot11::bip_verify(
                        &igtk,
                        frame.fc0,
                        frame.fc1,
                        &frame.addr1,
                        &frame.addr2,
                        &frame.addr3,
                        &frame.body,
                    ) =>
                {
                    match dot11::bip_ipn(&frame.body) {
                        Some(ipn) if ipn > self.last_rx_igtk_ipn => {
                            self.last_rx_igtk_ipn = ipn;
                            true
                        }
                        _ => false,
                    }
                }
                _ => false,
            }
        } else {
            // Unicast: only with an installed PTK, a valid negotiated-cipher
            // MIC, and a strictly increasing PN (anti replay).
            if self.ptk_installed
                && frame.protected()
                && dot11::decrypt_protected_mgmt_sec(
                    self.pairwise_cipher,
                    frame,
                    &self.pairwise_tk[..self.pairwise_cipher.key_len()],
                    self.mld_mgmt_rx_sec_addrs(),
                )
                .is_some()
            {
                match frame.ccmp_pn() {
                    Some(pn) if pn > self.last_rx_mgmt_pn => {
                        self.last_rx_mgmt_pn = pn;
                        true
                    }
                    _ => false,
                }
            } else {
                false
            }
        };
        if accept {
            self.disconnect();
        }
    }
}
