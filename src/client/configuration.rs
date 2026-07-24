//! Client construction, feature selection, counters, and local capabilities.

use super::*;

impl Client {
    pub(super) fn set_sae_pmk(&mut self, pmk: Option<[u8; 32]>) {
        if let Some(old) = self.sae_pmk.as_mut() {
            old.zeroize();
        }
        self.sae_pmk = pmk;
    }

    pub(super) fn set_cached_pmksa(&mut self, pmksa: Option<([u8; 6], [u8; 16], [u8; 32])>) {
        if let Some((_, _, old_pmk)) = self.cached_pmksa.as_mut() {
            old_pmk.zeroize();
        }
        self.cached_pmksa_at = pmksa.as_ref().map(|_| Instant::now());
        self.cached_pmksa = pmksa;
    }

    pub(super) fn expire_cached_pmksa(&mut self) {
        if self
            .cached_pmksa_at
            .is_some_and(|cached_at| cached_at.elapsed() >= PMKSA_CACHE_LIFETIME)
        {
            self.set_cached_pmksa(None);
        }
    }

    pub fn new(ssid: &str, psk: &str, mac: [u8; 6]) -> Client {
        Client {
            mac,
            ssid: ssid.as_bytes().to_vec(),
            pmk: crypto::pbkdf2_pmk(psk, ssid),
            bssid: None,
            target_bssid: None,
            connected: 0,
            eapol_state: 0,
            anonce: [0; 32],
            snonce: [0; 32],
            kck: [0; 16],
            kek: [0; 16],
            tk: [0; 16],
            pairwise_tk: [0; 32],
            pairwise_cipher: dot11::DataCipher::Ccmp128,
            ptk_installed: false,
            gtk: [0; 16],
            gtk_key_id: 1,
            sc: 0,
            client_pn: 1,
            last_rx_pn: [0; 17],
            last_rx_gpn: [0; 17],
            last_rx_mgmt_pn: 0,
            last_rx_igtk_ipn: 0,
            igtk_key_id: None,
            eapol_replay: 0,
            test_snonce: None,
            password: psk.as_bytes().to_vec(),
            sae_enabled: false,
            sae_h2e: true,
            sae: None,
            sae_pmk: None,
            igtk: None,
            bigtk: None,
            cached_pmksa: None,
            cached_pmksa_at: None,
            pmksa_reconnect: false,
            ocv: false,
            channel: 1,
            owe: false,
            owe_priv: None,
            owe_pub: None,
            wmm: true,
            ap_wmm: false,
            wmm_negotiated: false,
            wmm_tid_override: None,
            mld_mac: None,
            link1_mac: None,
            ap_mld_mac: None,
            psk_sha256: false,
            pause_m3: false,
            state_since: Instant::now(),
            last_ap_seen: Instant::now(),
        }
    }

    /// Enable 2-link MLD: the (re)assoc carries a per-STA profile for link 1, and
    /// the SAE auth + 4-way derive keys from the MLD MAC addresses. Combine with
    /// `enable_sae()` (the MLD AP on hwsim is SAE).
    pub fn enable_mld(&mut self, mld_mac: [u8; 6], link1_mac: [u8; 6], ap_mld_mac: [u8; 6]) {
        self.mld_mac = Some(mld_mac);
        self.link1_mac = Some(link1_mac);
        self.ap_mld_mac = Some(ap_mld_mac);
    }

    /// Restrict association to one BSSID. A configured uplink must not silently
    /// roam to an arbitrary same-SSID BSS without an explicit selection policy.
    pub fn set_target_bssid(&mut self, bssid: [u8; 6]) {
        self.target_bssid = Some(bssid);
    }

    /// Set the configured operating channel. This is authoritative for OCV on
    /// bands whose beacons do not carry a legacy DS Parameter Set element.
    pub fn set_channel(&mut self, channel: u8) {
        self.channel = channel;
    }

    pub fn set_pairwise_cipher(&mut self, cipher: dot11::DataCipher) {
        self.pairwise_cipher = cipher;
    }

    /// Pause at EAPOL message 3 (decrypt + log, never ack) for the m3-retransmit leak.
    pub fn set_pause_m3(&mut self) {
        self.pause_m3 = true;
    }

    /// The EAPOL-Key MIC algorithm for this association's AKM.
    pub(super) fn key_mic(&self) -> dot11::KeyMic {
        if self.psk_sha256 {
            dot11::KeyMic::AesCmacV3
        } else {
            dot11::KeyMic::select(self.sae_pmk.is_some(), self.owe)
        }
    }

    pub(super) fn mld_mgmt_rx_sec_addrs(&self) -> Option<([u8; 6], [u8; 6], [u8; 6])> {
        let sta_mld = self.mld_mac?;
        let ap_mld = self.ap_mld_mac?;
        Some((sta_mld, ap_mld, ap_mld))
    }

    pub(super) fn mld_mgmt_tx_sec_addrs(&self) -> Option<([u8; 6], [u8; 6], [u8; 6])> {
        let sta_mld = self.mld_mac?;
        let ap_mld = self.ap_mld_mac?;
        Some((ap_mld, sta_mld, ap_mld))
    }

    /// Enable/disable WMM (advertise the WMM element + send QoS Data uplink).
    pub fn set_wmm(&mut self, wmm: bool) {
        self.wmm = wmm;
    }

    /// Test override: force a fixed WMM user priority (TID 0-7) on uplink data,
    /// regardless of the packet's DSCP. `None` restores per-packet classification.
    pub fn set_wmm_tid(&mut self, tid: Option<u8>) {
        self.wmm_tid_override = tid.map(|t| t & 0x07);
    }

    /// Append the WMM Information element to a (Re)Assoc Request when WMM is on.
    pub(super) fn with_wmm(&self, mut frame: Vec<u8>) -> Vec<u8> {
        if self.wmm && self.ap_wmm {
            frame.extend_from_slice(&dot11::wmm_information());
        }
        frame
    }

    /// Enable Operating Channel Validation (anti-MITM).
    pub fn enable_ocv(&mut self) {
        self.ocv = true;
    }

    /// Enable OWE (Opportunistic Wireless Encryption): connect to an open BSS
    /// with a Diffie-Hellman exchange that keys the 4-way handshake.
    pub fn enable_owe(&mut self) {
        self.owe = true;
    }

    /// Use WPA3-SAE (H2E by default) instead of open-system auth + PSK.
    pub fn enable_sae(&mut self) {
        self.sae_enabled = true;
    }

    /// Select the WPA-PSK-SHA256 AKM advertised by a mixed WPA2 BSS.
    pub fn enable_psk_sha256(&mut self) {
        self.psk_sha256 = true;
    }

    /// Use the legacy hunting-and-pecking PWE instead of Hash-to-Element.
    pub fn use_hunting_pecking(&mut self) {
        self.sae_h2e = false;
    }

    pub fn set_test_snonce(&mut self, snonce: [u8; 32]) {
        self.test_snonce = Some(snonce);
    }

    pub(super) fn next_sc(&mut self) -> u16 {
        self.sc = (self.sc + 1).rem_euclid(4096);
        (self.sc * 16) as u16
    }

    pub(super) fn next_client_pn(&mut self) -> Option<u64> {
        // CCMP encodes a 48-bit packet number. Never wrap/truncate it and reuse
        // a nonce under the same temporal key; the liveness timeout will force
        // a fresh association/key if this practically unreachable limit is hit.
        if self.client_pn > 0x0000_ffff_ffff_ffff {
            return None;
        }
        let pn = self.client_pn;
        self.client_pn += 1;
        Some(pn)
    }

    pub(super) fn security_mode(&self) -> dot11::SecurityMode {
        if self.owe {
            dot11::SecurityMode::Owe
        } else if self.sae_enabled {
            dot11::SecurityMode::Wpa3Sae
        } else {
            dot11::SecurityMode::Wpa2
        }
    }

    pub(super) fn has_wmm(ies: &[u8]) -> bool {
        let mut offset = 0usize;
        while offset + 2 <= ies.len() {
            let len = usize::from(ies[offset + 1]);
            let Some(end) = offset.checked_add(2 + len) else {
                return false;
            };
            if end > ies.len() {
                return false;
            }
            let body = &ies[offset + 2..end];
            if ies[offset] == 221
                && body.len() >= 6
                && body[..4] == [0x00, 0x50, 0xf2, 0x02]
                && matches!(body[4], 0 | 1)
            {
                return true;
            }
            offset = end;
        }
        false
    }
}
