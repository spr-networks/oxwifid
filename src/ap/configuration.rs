//! AP construction, feature configuration, and public capability accessors.

use super::*;

impl Ap {
    pub fn new(ssid: &str, psk: &str, mac: [u8; 6], channel: u8) -> Ap {
        let mut ap = Self::new_without_credential(ssid, mac, channel);
        ap.pmk = crypto::pbkdf2_pmk(psk, ssid);
        ap.password = psk.as_bytes().to_vec();
        ap
    }

    /// Construct an AP with no fallback credential. Configuration-file callers
    /// use this when credentials come exclusively from `psk_file` or the BSS is
    /// OWE; authentication remains fail-closed until credentials are installed.
    pub fn new_without_credential(ssid: &str, mac: [u8; 6], channel: u8) -> Ap {
        let mut gtk_full = random_bytes::<32>();
        let mut gtk = [0u8; 16];
        gtk.copy_from_slice(&gtk_full[..16]);
        gtk_full.zeroize();
        Ap {
            mac,
            ssid: ssid.as_bytes().to_vec(),
            country: *b"US",
            channel,
            channel_width: 20,
            punct: 0,
            mld: false,
            mld_mac: [0u8; 6],
            link_id: 0,
            bss_change_count: 0,
            mld_links: Vec::new(),
            mld_default_link_mask: None,
            mld_eml_capability: 0,
            mld_driver_capability: None,
            mld_link_phy_capabilities: HashMap::new(),
            phy_mode: dot11::PhyMode::Vht,
            pairwise_cipher: dot11::DataCipher::Ccmp128,
            pmk: [0u8; 32],
            psk_candidates_by_mac: HashMap::new(),
            wildcard_psk_candidates: Vec::new(),
            credential_passwords_by_mac: HashMap::new(),
            wildcard_credential_password: None,
            credential_file_authoritative: false,
            credential_reload_pending: false,
            password: Vec::new(),
            sae_enabled: false,
            psk_sha256: false,
            transition: false,
            boottime: Instant::now(),
            sc: 0,
            aid: 0,
            group_pn: 1,
            gtk,
            gtk_key_id: 1, // GTK key ids are 1/2
            igtk: random_bytes::<16>(),
            igtk_key_id: 4, // IGTK key ids are 4/5
            igtk_ipn: [0; 6],
            bigtk: random_bytes::<16>(),
            bigtk_key_id: 6, // BIGTK key ids are 6/7
            bigtk_ipn: [0; 6],
            beacon_prot: false,
            pending_csa: None,
            multi_bssid: false,
            btm: false,
            rnr_6ghz: None,
            band6: false,
            per_sta_vif: false,
            guest: false,
            static_credential: false,
            mgmt_rx_link: None,
            wmm: true,
            ocv: false,
            owe: false,
            sa_query_id: 0,
            pmksa_cache: HashMap::new(),
            pending_anonce: HashMap::new(),
            maintenance_deadline: None,
            eapol_deadlines: BinaryHeap::new(),
            removed_stations: Vec::new(),
            key_ready_stations: Vec::new(),
            group_key_epoch: 0,
            async_sae: None,
            eapol_replay_counter: random_nonzero_u64(),
            sae_token_key: random_bytes(),
            request_rates: HashMap::new(),
            failures: crate::failures::FailureLog::default(),
            events: Vec::new(),
            group_rekey_secs: 600,
            strict_rekey: true,
            last_group_rekey: Instant::now(),
            group_rekey_due: false,
            stations: HashMap::new(),
            test_anonce: None,
        }
    }

    /// Configure the periodic GTK rekey interval in seconds (reference AP
    /// `wpa_group_rekey`); 0 disables periodic group rekeying.
    pub fn set_group_rekey(&mut self, secs: u64) {
        self.group_rekey_secs = secs;
    }

    pub fn set_pairwise_cipher(&mut self, cipher: dot11::DataCipher) {
        self.pairwise_cipher = cipher;
    }

    pub fn pairwise_cipher(&self) -> dot11::DataCipher {
        self.pairwise_cipher
    }

    /// Enable/disable rekeying the GTK when an authorized station leaves
    /// (reference AP `wpa_strict_rekey`).
    pub fn set_strict_rekey(&mut self, on: bool) {
        self.strict_rekey = on;
    }

    /// Enable WPA3-SAE (H2E) authentication on this AP.
    pub fn enable_sae(&mut self) {
        self.sae_enabled = true;
    }

    /// Advertise and accept the PSK-SHA256 AKM (00-0F-AC:6) alongside plain
    /// WPA2-PSK. A station selecting AKM 6 gets a SHA-256-derived PTK and an
    /// AES-128-CMAC EAPOL-Key MIC at Key Descriptor Version 3; stations
    /// selecting AKM 2 are unaffected. Mutually exclusive with SAE/OWE, which
    /// bring their own key hierarchies.
    pub fn enable_psk_sha256(&mut self) {
        self.psk_sha256 = true;
    }

    /// Enable WPA2/WPA3 transition mode (accept both PSK and SAE clients).
    pub fn enable_transition(&mut self) {
        self.sae_enabled = true;
        self.transition = true;
    }

    /// Enable Beacon Protection (BIGTK): protect beacons with a BIP MME and
    /// deliver the BIGTK in EAPOL message 3.
    pub fn enable_beacon_protection(&mut self) {
        self.sae_enabled = true;
        self.beacon_prot = true;
    }

    /// The current BIGTK (test/inspection helper).
    pub fn bigtk(&self) -> [u8; 16] {
        self.bigtk
    }

    pub fn security_mode(&self) -> dot11::SecurityMode {
        if self.owe {
            dot11::SecurityMode::Owe
        } else if self.transition {
            dot11::SecurityMode::Transition
        } else if self.sae_enabled {
            dot11::SecurityMode::Wpa3Sae
        } else if self.psk_sha256 {
            dot11::SecurityMode::Wpa2PskSha256
        } else {
            dot11::SecurityMode::Wpa2
        }
    }

    /// Force a fixed GTK / ANONCE for deterministic tests.
    pub fn set_test_fixtures(&mut self, gtk: [u8; 16], anonce: [u8; 32]) {
        self.gtk = gtk;
        self.test_anonce = Some(anonce);
        // Golden frame vectors use replay counters 1 and 2.
        self.eapol_replay_counter = 0;
    }

    pub(super) fn next_sc(&mut self) -> u16 {
        self.sc = (self.sc + 1).rem_euclid(4096);
        (self.sc * 16) as u16
    }

    pub(super) fn next_aid(&mut self) -> u16 {
        self.aid = (self.aid + 1) % 2008;
        self.aid
    }

    pub(super) fn next_eapol_replay(&mut self) -> u64 {
        self.eapol_replay_counter = self.eapol_replay_counter.wrapping_add(1);
        if self.eapol_replay_counter == 0 {
            self.eapol_replay_counter = 1;
        }
        self.eapol_replay_counter
    }

    pub(super) fn next_group_pn(&mut self) -> Option<u64> {
        if self.group_pn > MAX_PACKET_NUMBER {
            return None;
        }
        let pn = self.group_pn;
        self.group_pn += 1;
        Some(pn)
    }

    /// Highest group PN already transmitted under the current GTK.
    pub(super) fn current_group_rsc(&self) -> u64 {
        self.group_pn.saturating_sub(1)
    }

    pub fn current_timestamp(&self) -> u64 {
        self.boottime.elapsed().as_micros() as u64
    }

    // -- beacons ------------------------------------------------------------

    /// Announce a Channel Switch (802.11h CSA): beacons advertise the switch and
    /// the AP moves to `new_channel` after `count` beacons.
    pub fn announce_channel_switch(&mut self, new_channel: u8, count: u8) {
        self.pending_csa = Some((new_channel, count));
    }

    /// Advertise the Multiple BSSID element (co-located BSS support).
    pub fn enable_multi_bssid(&mut self) {
        self.multi_bssid = true;
    }

    pub fn enable_btm(&mut self) {
        self.btm = true;
    }

    /// Advertise a co-located 6 GHz affiliated AP on `channel` via the Reduced
    /// Neighbor Report (out-of-band 6 GHz / MLD discovery).
    pub fn enable_rnr_6ghz(&mut self, channel: u8) {
        self.rnr_6ghz = Some(channel);
    }

    pub fn set_mld_links(&mut self, links: Vec<MldLink>) {
        self.mld_links = links;
    }

    /// Fill in affiliated-link BSSIDs that were left unspecified in the config
    /// (sentinel `00:00:00:00:00:00`) using the reference AP's
    /// `random_mac_addr_keep_oui()` rule: retain the MLD address's first three
    /// octets, randomize the final three, and force locally-administered unicast.
    ///
    /// Generate each missing address once during AP bring-up. Explicit link
    /// BSSIDs are preserved. The uniqueness check makes the reference behavior
    /// fail-safe against the extremely unlikely random collision.
    pub fn derive_missing_mld_link_macs(&mut self) {
        let base = self.mld_mac;
        let mut used = self
            .mld_links
            .iter()
            .filter_map(|link| (link.mac != [0u8; 6]).then_some(link.mac))
            .collect::<HashSet<_>>();
        used.insert(base);

        for link in &mut self.mld_links {
            if link.mac == [0u8; 6] {
                loop {
                    let mut mac = base;
                    mac[3..].copy_from_slice(&random_bytes::<3>());
                    mac[0] = (mac[0] & 0xfe) | 0x02;
                    if used.insert(mac) {
                        link.mac = mac;
                        break;
                    }
                }
            }
        }
    }

    /// BSSID of the affiliated link with the given Link ID, if present.
    pub fn mld_link_mac(&self, link_id: u8) -> Option<[u8; 6]> {
        self.mld_links
            .iter()
            .find(|l| l.link_id == link_id)
            .map(|l| l.mac)
    }

    /// Advertise one active-link set for every QoS TID in both directions.
    pub fn set_mld_default_link_mask(&mut self, link_mask: u16) {
        self.mld_default_link_mask = Some(link_mask);
    }

    pub fn active_mld_links(&self) -> Vec<MldLink> {
        if self.mld && !self.mld_links.is_empty() {
            self.mld_links.clone()
        } else {
            vec![MldLink {
                link_id: self.link_id,
                mac: self.mac,
                channel: self.channel,
                width: self.channel_width,
                band6: self.band6,
            }]
        }
    }

    /// Operate the AP on the 6 GHz band (HE-only beacon; WPA3 mandatory).
    pub fn enable_band6(&mut self) {
        self.band6 = true;
    }

    /// Set the 2-letter regulatory country code advertised in the Country IE.
    pub fn set_country(&mut self, country: [u8; 2]) {
        self.country = country;
    }

    /// Set the operating channel width in MHz (20/40/80/160/320).
    pub fn set_width(&mut self, width: u16) {
        self.channel_width = width;
    }

    /// Set the PHY generation advertised on 2.4/5 GHz (ac/ax/be).
    pub fn set_phy(&mut self, phy: dot11::PhyMode) {
        self.phy_mode = phy;
    }

    /// PHY generation advertised by this BSS (used by the reference AP-compatible
    /// runtime status interface).
    pub fn phy_mode(&self) -> dot11::PhyMode {
        self.phy_mode
    }

    /// Enable/disable WMM (advertise the WMM element + exchange QoS Data).
    pub fn set_wmm(&mut self, wmm: bool) {
        self.wmm = wmm;
    }

    /// Whether WMM/QoS is enabled.
    pub fn wmm(&self) -> bool {
        self.wmm
    }

    /// The operating channel width in MHz.
    pub fn width(&self) -> u16 {
        self.channel_width
    }

    /// Whether the AP operates on the 6 GHz band (`channel` is a 6 GHz channel).
    pub fn band6(&self) -> bool {
        self.band6
    }

    /// Give each station its own GTK (per-station VIF / nl80211 AP_VLAN), so a
    /// station cannot read broadcast/multicast addressed to another's VLAN.
    pub fn enable_per_sta_vif(&mut self) {
        self.per_sta_vif = true;
    }

    /// Install the reference AP-style credential-file candidates: `(mac, passphrase)`
    /// pairs (`None` mac = wildcard onboarding entry). Each passphrase is turned
    /// into a PMK against this AP's SSID. Once called, this file is authoritative:
    /// the BSS passphrase is no longer an authentication fallback.
    pub fn set_psk_file(&mut self, entries: &[(Option<[u8; 6]>, String)]) {
        // A static-credential (guest) BSS never adopts the device credential
        // database — not at startup and not via a control-socket RELOAD.
        if self.static_credential {
            return;
        }
        let prepared = PreparedPskFile::derive(&self.ssid, entries);
        self.install_prepared_psk_file(prepared);
    }

    /// Atomically adopt a credential database whose PBKDF2 work was completed
    /// off the radio thread.
    pub(crate) fn install_prepared_psk_file(&mut self, mut prepared: PreparedPskFile) {
        if self.static_credential {
            return;
        }
        self.pmksa_cache.clear();
        for candidates in self.psk_candidates_by_mac.values_mut() {
            candidates.zeroize();
        }
        self.wildcard_psk_candidates.zeroize();
        for password in self.credential_passwords_by_mac.values_mut() {
            password.zeroize();
        }
        if let Some(password) = self.wildcard_credential_password.as_mut() {
            password.zeroize();
        }
        self.psk_candidates_by_mac.clear();
        self.wildcard_psk_candidates.clear();
        self.credential_passwords_by_mac.clear();
        self.wildcard_credential_password = None;
        self.credential_file_authoritative = true;
        self.credential_reload_pending = false;
        self.psk_candidates_by_mac = std::mem::take(&mut prepared.candidates_by_mac);
        self.wildcard_psk_candidates = std::mem::take(&mut prepared.wildcard_candidates);
        self.credential_passwords_by_mac = std::mem::take(&mut prepared.passwords_by_mac);
        self.wildcard_credential_password = std::mem::take(&mut prepared.wildcard_password);
        // The file is authoritative, so the JSON passphrase is no longer a
        // fallback and should not remain resident.
        self.pmk.zeroize();
        self.password.zeroize();
    }

    pub(crate) fn begin_psk_reload(&mut self) {
        if !self.static_credential {
            self.credential_reload_pending = true;
        }
    }

    pub(crate) fn cancel_psk_reload(&mut self) {
        self.credential_reload_pending = false;
    }

    /// Select an SAE credential using reference AP's non-AP MLD identity rules. An
    /// exact MLD-MAC entry wins over an exact per-link entry, then the pending
    /// wildcard is considered. This matters for Apple MLO clients whose SAE
    /// frame source address can change between affiliated links while the MLD
    /// address remains the stable SPR device identity.
    pub(super) fn sae_password_for(
        &self,
        identity: &[u8; 6],
        link_identity: Option<&[u8; 6]>,
    ) -> Option<&[u8]> {
        if self.credential_reload_pending {
            return None;
        }
        self.credential_passwords_by_mac
            .get(identity)
            .or_else(|| link_identity.and_then(|link| self.credential_passwords_by_mac.get(link)))
            .or(self.wildcard_credential_password.as_ref())
            .map(Vec::as_slice)
            .or_else(|| (!self.credential_file_authoritative).then_some(self.password.as_slice()))
    }

    /// Whether per-station-VIF mode is enabled.
    pub fn per_sta_vif(&self) -> bool {
        self.per_sta_vif
    }

    /// Guest BSS: block all station-to-station traffic (client isolation).
    /// In netlink mode this also sets `NL80211_ATTR_AP_ISOLATE` so the kernel
    /// data path stops intra-BSS bridging.
    pub fn enable_guest(&mut self) {
        self.guest = true;
    }

    /// Whether this BSS is a guest network (client isolation on).
    pub fn guest(&self) -> bool {
        self.guest
    }

    /// Pin this BSS to its static (guest) passphrase: the device credential
    /// database no longer applies, so `set_psk_file` becomes a no-op.
    pub fn set_static_credential(&mut self) {
        self.static_credential = true;
    }

    /// Whether this BSS authenticates only its static (guest) passphrase.
    pub fn static_credential(&self) -> bool {
        self.static_credential
    }

    /// Record which affiliated link the management frame about to be handled
    /// arrived on (netlink MLD path). `None` outside an MLD frame context.
    pub fn set_mgmt_rx_link(&mut self, link_id: Option<u8>) {
        self.mgmt_rx_link = link_id;
    }

    /// The group key handed to `sta` in its 4-way handshake — the station's own
    /// GTK in `per_sta_vif` mode, otherwise the BSS-wide GTK.
    pub fn station_gtk(&self, sta: &[u8; 6]) -> [u8; 16] {
        if self.per_sta_vif {
            if let Some(s) = self.stations.get(sta) {
                return s.gtk;
            }
        }
        self.gtk
    }

    /// The CCMP key index of the group key handed to `sta`. The GTK key index is
    /// a BSS-wide concept — it is what the RSNE/beacon advertises and the index
    /// every client installs its GTK under — so it is the single global
    /// `gtk_key_id` for every station, in both modes. In `per_sta_vif` mode only
    /// the GTK *value* differs per station (see [`Ap::station_gtk`]); the shared
    /// index toggles 1<->2 together on each rekey. Used by the netlink path to
    /// (re)install the GTK at the same index the station was told.
    pub fn station_gtk_key_id(&self, _sta: &[u8; 6]) -> u8 {
        self.gtk_key_id
    }

    /// Build an 802.11v BSS Transition Management Request steering `sta` toward a
    /// preferred candidate BSS (a Neighbor Report on the same operating class).
    pub(super) fn btm_request_frame(&mut self, sta: &[u8; 6]) -> Vec<u8> {
        let op_class = if dot11::is_5ghz(self.channel) {
            115
        } else {
            81
        };
        let mut cand = [0u8; 6];
        cand.copy_from_slice(&self.mac);
        cand[5] ^= 0x01; // a neighbour BSSID
        let candidates = dot11::neighbor_report_element(&cand, op_class, self.channel);
        let body = dot11::btm_request_body(1, dot11::BTM_REQ_PREF_CAND_LIST, 0, 255, &candidates);
        let sc = self.next_sc();
        dot11::build_action_frame(sta, &self.mac, &self.mac, sc, &body)
    }

    /// Enable Operating Channel Validation (anti-MITM): require a matching OCI
    /// in the 4-way handshake.
    pub fn enable_ocv(&mut self) {
        self.ocv = true;
    }

    /// Enable OWE (Opportunistic Wireless Encryption): an open BSS that performs
    /// a Diffie-Hellman exchange in (re)association to key the 4-way handshake.
    pub fn enable_owe(&mut self) {
        self.owe = true;
    }
}
