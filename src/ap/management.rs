//! Protected management enforcement and action-frame handling.

use super::*;

impl Ap {
    /// PMF enforcement for received Deauth/Disassoc: under PMF only a valid
    /// CCMP-protected frame tears the station down; unprotected ones are dropped.
    pub(super) fn handle_robust_mgmt(&mut self, frame: &dot11::Dot11) {
        let sta = frame.addr2;
        let pmf = match self.stations.get(&sta) {
            Some(s) => s.sha256,
            None => return,
        };
        if !pmf {
            // WPA2 (no PMF): Deauth/Disassoc are unprotected, so tear down.
            let reason = frame
                .body
                .get(..2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .unwrap_or(0);
            self.disconnect(&sta, reason);
            return;
        }
        // PMF: only a CCMP-valid frame from a station that has *completed the
        // 4-way* (real PTK installed) tears it down. `installed_tk` returns None
        // before the handshake finishes, so we never attempt CCMP with the
        // all-zero placeholder key — which would let a spoofed "NULL-key"
        // frame decrypt and kill a station mid-handshake.
        if frame.protected() {
            if let Some(tk) = self.installed_pairwise_key(&sta) {
                // Reject a replayed protected frame (PN must strictly increase)
                // before acting on it.
                let Some(pn) = frame.ccmp_pn() else { return };
                if self
                    .stations
                    .get(&sta)
                    .map(|s| pn <= s.last_rx_mgmt_pn)
                    .unwrap_or(true)
                {
                    return;
                }
                if let Some(plain) = dot11::decrypt_protected_mgmt_sec(
                    self.pairwise_cipher,
                    frame,
                    &tk[..self.pairwise_cipher.key_len()],
                    self.mld_mgmt_rx_sec_addrs(&sta),
                ) {
                    let reason = plain
                        .get(..2)
                        .map(|b| u16::from_le_bytes([b[0], b[1]]))
                        .unwrap_or(0);
                    eprintln!(
                        "AP: protected {} from {} reason={reason}",
                        if frame.subtype() == dot11::SUBTYPE_DEAUTH {
                            "deauth"
                        } else {
                            "disassoc"
                        },
                        crate::util::bytes_to_mac(&sta),
                    );
                    self.disconnect(&sta, reason);
                } else {
                    self.record_failure(&sta, crate::failures::FailureKind::ProtectedMgmt);
                }
            }
        }
    }

    /// Handle a (PMF-protected) SA Query Action frame: respond to a Request, and
    /// accept a Response as proof the station is alive.
    pub(super) fn handle_action(&mut self, frame: &dot11::Dot11, out: &mut Outgoing) {
        let sta = frame.addr2;
        // 802.11v BTM Response (unprotected, e.g. WPA2): the client's reply to
        // our steering request.
        if !frame.protected() {
            // TWT Setup Request (non-robust S1G Action): grant the requested TWT
            // to an associated HE station by echoing its TWT element back with
            // Setup Command = Accept. barely-ap advertises TWT Responder Support.
            if let Some((dialog, req_twt)) = dot11::parse_twt_setup(&frame.body) {
                if self
                    .stations
                    .get(&sta)
                    .map(|s| s.associated)
                    .unwrap_or(false)
                {
                    let sc = self.next_sc();
                    out.tx(dot11::build_twt_setup_response(
                        &self.mac, &sta, dialog, &req_twt, sc,
                    ));
                    eprintln!(
                        "AP: TWT Setup accepted for {}",
                        crate::util::bytes_to_mac(&sta)
                    );
                }
                return;
            }
            if let Some((token, status)) = dot11::parse_btm_response(&frame.body) {
                eprintln!(
                    "AP: BTM Response from {} token={token} status={status}",
                    crate::util::bytes_to_mac(&sta)
                );
            }
            return;
        }
        if !frame.protected() {
            return; // robust action frames must be protected under PMF
        }
        // Only attempt CCMP with a fully-installed PTK (never the all-zero
        // placeholder of a station that skipped ahead before keying).
        let Some(tk) = self.installed_pairwise_key(&sta) else {
            return;
        };
        // Reject a replayed protected action frame (PN must strictly increase).
        let Some(rx_pn) = frame.ccmp_pn() else { return };
        if self
            .stations
            .get(&sta)
            .map(|s| rx_pn <= s.last_rx_mgmt_pn)
            .unwrap_or(true)
        {
            return;
        }
        let Some(plain) = dot11::decrypt_protected_mgmt_sec(
            self.pairwise_cipher,
            frame,
            &tk[..self.pairwise_cipher.key_len()],
            self.mld_mgmt_rx_sec_addrs(&sta),
        ) else {
            self.record_failure(&sta, crate::failures::FailureKind::ProtectedMgmt);
            return;
        };
        if let Some(s) = self.stations.get_mut(&sta) {
            s.last_rx_mgmt_pn = rx_pn;
        }
        if let Some((action, trans)) = dot11::parse_sa_query(&plain) {
            if action == dot11::SA_QUERY_REQUEST {
                let pn = self.stations.get_mut(&sta).unwrap().next_client_pn();
                let sc = self.next_sc();
                let sec = self.mld_mgmt_tx_sec_addrs(&sta);
                out.tx(dot11::build_protected_sa_query_for_cipher_sec(
                    self.pairwise_cipher,
                    &self.mac,
                    &sta,
                    false,
                    true,
                    trans,
                    sc,
                    pn,
                    &tk[..self.pairwise_cipher.key_len()],
                    sec,
                ));
            }
        }
    }
}
