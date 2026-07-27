//! Protected management enforcement and action-frame handling.

use super::receive::ManagementRx;
use super::*;

impl Ap {
    /// Whether an unprotected Authentication or (Re)Association Request bearing
    /// `sta`'s address must be refused because that station already holds a
    /// management-frame-protected association.
    ///
    /// These frames carry no integrity protection at all, so anyone can forge
    /// one with a victim's source address. Acting on it — tearing down the
    /// session, zeroizing its keys, or replacing its PMK — hands an off-path
    /// attacker exactly the deauthentication primitive PMF exists to remove.
    /// IEEE 802.11 instead requires the AP to keep the existing SA and prove the
    /// peer's liveness with an SA Query.
    pub(super) fn pmf_session_protected(&self, sta: &[u8; 6]) -> bool {
        self.stations
            .get(sta)
            .map(|s| s.associated && s.pmf)
            .unwrap_or(false)
    }

    /// Challenge a PMF station whose association was just contested by an
    /// unprotected frame: send a protected SA Query Request and arm the timeout.
    /// A station that answers keeps its session; one that stays silent for
    /// [`SA_QUERY_TIMEOUT`] is torn down by `tick`, so a genuine reconnect is
    /// delayed rather than denied.
    pub(super) fn sa_query_challenge(&mut self, sta: &[u8; 6], out: &mut Outgoing) {
        let Some(tk) = self.installed_pairwise_key(sta) else {
            return;
        };
        // Reuse an outstanding query's transaction identifier instead of minting
        // a new one. The station answers with the identifier it was given, so
        // letting a later spoofed frame move the target would make the genuine
        // response fail to match and turn the defence into the lockout it is
        // meant to avoid.
        let trans = match self.stations.get(sta).and_then(|s| s.sa_query) {
            Some((trans, _)) => trans,
            None => {
                self.sa_query_id = self.sa_query_id.wrapping_add(1);
                self.sa_query_id
            }
        };
        let Some(pn) = self.stations.get_mut(sta).and_then(|s| s.next_client_pn()) else {
            return;
        };
        let sc = self.next_sc();
        let sec = self.mld_mgmt_tx_sec_addrs(sta);
        out.tx(dot11::build_protected_sa_query_for_cipher_sec(
            self.pairwise_cipher,
            &self.mac,
            sta,
            false,
            false,
            trans,
            sc,
            pn,
            &tk[..self.pairwise_cipher.key_len()],
            sec,
        ));
        let mut started = None;
        if let Some(s) = self.stations.get_mut(sta) {
            // Keep the FIRST outstanding query's deadline: re-arming it on every
            // spoofed frame would let a flood postpone the timeout indefinitely.
            let now = Instant::now();
            let query = s.sa_query.get_or_insert((trans, now));
            started = Some(query.1);
        }
        if let Some(started) = started {
            self.schedule_maintenance(started + SA_QUERY_TIMEOUT);
        }
    }

    /// PMF enforcement for received Deauth/Disassoc: under PMF only a valid
    /// CCMP-protected frame tears the station down; unprotected ones are dropped.
    pub(super) fn handle_robust_mgmt(&mut self, frame: &dot11::Dot11, management_rx: ManagementRx) {
        let sta = frame.addr2;
        let pmf = match self.stations.get(&sta) {
            Some(s) => s.pmf,
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
        // PMF: only a protected frame from a station that completed the 4-way
        // may tear down the association. `protected_mgmt_body` gives exactly
        // one component ownership of MIC/replay validation: this protocol
        // engine in raw mode, mac80211 in nl80211 mode.
        let Some(plain) = self.protected_mgmt_body(frame, management_rx) else {
            return;
        };
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
    }

    /// Handle a (PMF-protected) SA Query Action frame: respond to a Request, and
    /// accept a Response as proof the station is alive.
    pub(super) fn handle_action(
        &mut self,
        frame: &dot11::Dot11,
        management_rx: ManagementRx,
        out: &mut Outgoing,
    ) {
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
            if self.stations.get(&sta).is_some_and(|station| station.pmf)
                && dot11::parse_btm_response(&frame.body).is_some()
            {
                // WNM/BTM is a robust action category. A PMF station's
                // unprotected response is unauthenticated and must be ignored.
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
        // Everything below is robust. In raw mode this verifies CCMP/GCMP and
        // advances the replay window; in nl80211 mode mac80211 already did so.
        let Some(plain) = self.protected_mgmt_body(frame, management_rx) else {
            return;
        };
        if let Some((action, trans)) = dot11::parse_sa_query(&plain) {
            if action == dot11::SA_QUERY_RESPONSE {
                // The station proved it still holds the PTK, so whatever
                // unprotected frame contested its association was forged. Cancel
                // the teardown timer and leave the session alone. The identifier
                // must be the one we asked with: the CCMP MIC is what actually
                // authenticates this, but answering a query we never sent is not
                // evidence of anything, and IEEE 802.11 specifies the match.
                if let Some(s) = self.stations.get_mut(&sta) {
                    if s.sa_query.is_some_and(|(pending, _)| pending == trans) {
                        s.sa_query = None;
                    }
                }
                return;
            }
            if action == dot11::SA_QUERY_REQUEST {
                let Some(tk) = self.installed_pairwise_key(&sta) else {
                    return;
                };
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

    /// Return an authenticated robust-management body.
    ///
    /// Keeping this decision in one function prevents the former split where
    /// Action and Deauth each implemented subtly different PN/MIC handling
    /// (including a Deauth path that verified a PN but never advanced it).
    fn protected_mgmt_body(
        &mut self,
        frame: &dot11::Dot11,
        management_rx: ManagementRx,
    ) -> Option<Vec<u8>> {
        #[cfg(not(target_os = "linux"))]
        let _ = management_rx;
        if !frame.protected() {
            return None;
        }
        let sta = frame.addr2;
        // Even on the kernel path, require a completed userspace association.
        // This prevents a protected-looking event for an unknown/half-keyed
        // peer from changing protocol state.
        self.installed_pairwise_key(&sta)?;

        #[cfg(target_os = "linux")]
        if matches!(management_rx, ManagementRx::Kernel) {
            return Some(frame.body.clone());
        }

        let pn = frame.ccmp_pn()?;
        if self
            .stations
            .get(&sta)
            .is_none_or(|station| pn <= station.last_rx_mgmt_pn)
        {
            return None;
        }
        let tk = self.installed_pairwise_key(&sta)?;
        let Some(plain) = dot11::decrypt_protected_mgmt_sec(
            self.pairwise_cipher,
            frame,
            &tk[..self.pairwise_cipher.key_len()],
            self.mld_mgmt_rx_sec_addrs(&sta),
        ) else {
            self.record_failure(&sta, crate::failures::FailureKind::ProtectedMgmt);
            return None;
        };
        if let Some(station) = self.stations.get_mut(&sta) {
            station.last_rx_mgmt_pn = pn;
        }
        Some(plain)
    }
}
