//! BSS selection, session reset, liveness, and EAPOL frame classification.

use super::*;

impl Client {
    /// Select only a structurally valid beacon for this configured network.
    /// SSID, BSSID, CCMP cipher, AKM, and PMF requirements are checked before
    /// sending any authentication frame.
    pub(super) fn beacon_matches(&self, frame: &dot11::Dot11) -> bool {
        if frame.addr1 != [0xff; 6] || frame.addr2 != frame.addr3 || frame.body.len() < 12 {
            return false;
        }
        if self
            .target_bssid
            .is_some_and(|target| frame.addr3 != target)
        {
            return false;
        }
        let ies = &frame.body[12..];
        let Ok(Some(ssid)) = dot11::find_ie_strict(ies, 0) else {
            return false;
        };
        if ssid != self.ssid {
            return false;
        }
        let Ok(Some(rsn)) = dot11::find_ie_strict(ies, 48) else {
            return false;
        };
        let security_valid = if self.sae_enabled {
            // A transition BSS advertises both PSK and SAE with MFPC but cannot
            // set MFPR globally because legacy WPA2 stations remain allowed.
            // The SAE association request below still selects SAE + MFPR.
            dot11::validate_assoc_rsn_for_cipher(
                rsn,
                dot11::SecurityMode::Transition,
                self.pairwise_cipher,
            )
            .is_ok()
                && dot11::rsn_has_akm(rsn, 8)
                && dot11::rsn_has_mfpc(rsn)
        } else if self.psk_sha256 {
            dot11::validate_psk_sha256_rsn(rsn).is_ok()
        } else {
            dot11::validate_assoc_rsn_for_cipher(rsn, self.security_mode(), self.pairwise_cipher)
                .is_ok()
        };
        if !security_valid {
            return false;
        }
        if self.sae_enabled && self.sae_h2e {
            let Ok(Some(rsnxe)) = dot11::find_ie_strict(ies, 244) else {
                return false;
            };
            if !dot11::rsnxe_has_sae_h2e(rsnxe) {
                return false;
            }
        }
        true
    }

    pub(super) fn is_from_selected_ap(&self, frame: &dot11::Dot11) -> bool {
        self.bssid
            .is_some_and(|bssid| frame.addr2 == bssid && frame.addr3 == bssid)
    }

    pub(super) fn reset_session_keys(&mut self) {
        self.anonce.zeroize();
        self.snonce.zeroize();
        self.kck.zeroize();
        self.kek.zeroize();
        self.tk.zeroize();
        self.pairwise_tk.zeroize();
        self.gtk.zeroize();
        self.ptk_installed = false;
        self.client_pn = 1;
        self.last_rx_pn = [0; 17];
        self.last_rx_gpn = [0; 17];
        self.last_rx_mgmt_pn = 0;
        self.last_rx_igtk_ipn = 0;
        self.igtk_key_id = None;
        self.eapol_replay = 0;
        self.eapol_state = 0;
        if let Some(key) = self.igtk.as_mut() {
            key.zeroize();
        }
        self.igtk = None;
        if let Some(key) = self.bigtk.as_mut() {
            key.zeroize();
        }
        self.bigtk = None;
        self.owe_priv = None;
        if let Some(public) = self.owe_pub.as_mut() {
            public.zeroize();
        }
        self.owe_pub = None;
        self.pmksa_reconnect = false;
        self.ap_wmm = false;
        self.wmm_negotiated = false;
    }

    pub(super) fn set_connected_state(&mut self, state: u8) {
        self.connected = state;
        self.state_since = Instant::now();
    }

    pub(super) fn note_ap_activity(&mut self) {
        self.last_ap_seen = Instant::now();
    }

    /// Run timeout/liveness maintenance. Returns `true` when a stale session was
    /// cleared and the caller should reset its network-facing connected state.
    pub fn maintenance(&mut self, now: Instant) -> bool {
        let timed_out = match self.connected {
            1 => now.saturating_duration_since(self.state_since) >= AUTH_ASSOC_TIMEOUT,
            2 | 3 => now.saturating_duration_since(self.state_since) >= FOUR_WAY_TIMEOUT,
            4 => now.saturating_duration_since(self.last_ap_seen) >= LINK_SILENCE_TIMEOUT,
            _ => false,
        };
        if timed_out {
            self.disconnect();
        }
        timed_out
    }

    pub(super) fn valid_m1(&self, ek: &dot11::EapolKey) -> bool {
        ek.is_pairwise()
            && ek.key_ack()
            && !ek.install()
            && !ek.has_key_mic()
            && !ek.secure()
            && !ek.error()
            && !ek.request()
            && !ek.encrypted_key_data()
            && ek.descriptor_version() == self.key_mic().version()
            && usize::from(ek.key_length) == self.pairwise_cipher.key_len()
            && ek.key_nonce != [0; 32]
    }

    pub(super) fn valid_m3(&self, ek: &dot11::EapolKey) -> bool {
        ek.is_pairwise()
            && ek.key_ack()
            && ek.install()
            && ek.has_key_mic()
            && ek.secure()
            && !ek.error()
            && !ek.request()
            && ek.encrypted_key_data()
            && ek.descriptor_version() == self.key_mic().version()
            && usize::from(ek.key_length) == self.pairwise_cipher.key_len()
            && ek.key_nonce == self.anonce
            && !ek.key_data.is_empty()
    }

    pub(super) fn valid_group_m1(&self, ek: &dot11::EapolKey) -> bool {
        !ek.is_pairwise()
            && ek.key_ack()
            && !ek.install()
            && ek.has_key_mic()
            && ek.secure()
            && !ek.error()
            && !ek.request()
            && ek.encrypted_key_data()
            && ek.descriptor_version() == self.key_mic().version()
            && ek.key_nonce == [0; 32]
            && !ek.key_data.is_empty()
    }

    pub(super) fn ethernet_eapol_key(ethernet: &[u8]) -> Option<(&[u8], dot11::EapolKey)> {
        if ethernet.len() < 18 || ethernet[12..14] != dot11::ETHERTYPE_EAPOL.to_be_bytes() {
            return None;
        }
        let eapol = &ethernet[14..];
        if eapol.get(1) != Some(&3) {
            return None;
        }
        let body_len = u16::from_be_bytes([*eapol.get(2)?, *eapol.get(3)?]) as usize;
        let end = 4usize.checked_add(body_len)?;
        if end > eapol.len() {
            return None;
        }
        let eapol = &eapol[..end];
        let key = dot11::EapolKey::parse(&eapol[4..])?;
        Some((eapol, key))
    }
}
