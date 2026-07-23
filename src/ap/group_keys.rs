//! GTK/IGTK/BIGTK inspection, rotation, rekeying, and group deauthentication.

use super::*;

impl Ap {
    /// Disassociate stations idle longer than `max_idle` (reference AP
    /// `ap_max_inactivity`). Returns Deauthentication frames (CCMP-protected for
    /// PMF stations), reason 4 (disassociated due to inactivity).
    pub fn prune_idle(&mut self, max_idle: Duration) -> Vec<Vec<u8>> {
        let now = Instant::now();
        let stale_sae: Vec<[u8; 6]> = self
            .stations
            .iter()
            .filter(|(_, s)| {
                !s.associated
                    && s.sae.is_some()
                    && now.duration_since(s.last_activity) >= SAE_AUTH_TIMEOUT
            })
            .map(|(m, _)| *m)
            .collect();
        for sta in stale_sae {
            self.disconnect(&sta, 15);
        }
        let idle: Vec<[u8; 6]> = self
            .stations
            .iter()
            .filter(|(_, s)| s.associated && now.duration_since(s.last_activity) > max_idle)
            .map(|(m, _)| *m)
            .collect();

        let mut frames = Vec::new();
        for sta in idle {
            let frame = self.protected_deauth(&sta, 4).unwrap_or_else(|| {
                let mut f = dot11::RADIOTAP_TX.to_vec();
                f.extend_from_slice(&dot11::build_deauth(&self.mac, &sta, 4));
                f
            });
            frames.push(frame);
            self.disconnect(&sta, 4);
        }
        frames
    }

    /// The current IGTK (for PMF / BIP).
    pub fn igtk(&self) -> [u8; 16] {
        self.igtk
    }

    /// The current GTK (test/inspection helper).
    pub fn gtk(&self) -> [u8; 16] {
        self.gtk
    }

    /// The CCMP key index the current BSS-wide GTK is installed at (toggles
    /// 1<->2 on each group rekey). Used by the netlink path to install the GTK
    /// at the same index the stations were told.
    pub fn gtk_key_id(&self) -> u8 {
        self.gtk_key_id
    }

    /// The current IGTK key index (toggles 4<->5 on rekey) and IPN, so the
    /// netlink path can install the IGTK in the kernel for BIP.
    pub fn igtk_key_id(&self) -> u16 {
        self.igtk_key_id
    }

    pub fn igtk_ipn(&self) -> [u8; 6] {
        self.igtk_ipn
    }

    /// Whether Beacon Protection (BIGTK) is enabled.
    pub fn beacon_prot(&self) -> bool {
        self.beacon_prot
    }

    /// The current BIGTK key index (6/7) and IPN, so the netlink path can install
    /// the BIGTK in the kernel and let mac80211 generate the per-beacon MME.
    pub fn bigtk_key_id(&self) -> u16 {
        self.bigtk_key_id
    }

    pub fn bigtk_ipn(&self) -> [u8; 6] {
        self.bigtk_ipn
    }

    /// Whether this AP uses Management Frame Protection (PMF/802.11w): true for
    /// SAE, OWE, and transition mode, where the kernel must be given the IGTK to
    /// send/validate BIP-protected robust management frames.
    pub fn is_pmf(&self) -> bool {
        matches!(
            self.security_mode(),
            dot11::SecurityMode::Wpa3Sae
                | dot11::SecurityMode::Owe
                | dot11::SecurityMode::Transition
        )
    }

    /// Rotate the GTK (and IGTK) and run the Group Key Handshake: send Group Key
    /// message 1 to every associated station. Returns the frames to transmit.
    /// Mirrors reference AP's `wpa_group_rekey`. Each message 1 is armed for retransmit
    /// (`pending_eapol`) and the station is marked `group_rekeying` until it ACKs
    /// with message 2, so a dropped rekey frame doesn't strand a station on the
    /// old GTK. If a rekey is already in flight (any station still awaiting its
    /// message 2) this is a no-op, matching reference AP's coalescing.
    pub fn rekey_gtk(&mut self) -> Vec<Vec<u8>> {
        if self.stations.values().any(|s| s.group_rekeying) {
            return Vec::new();
        }
        // Per-STA-VIF mode: each station has its OWN group key *value* (broadcast
        // isolation). A shared GTK value would collapse that isolation, so rotate
        // each station's per-station GTK value and drive its msg 1 with that value.
        // The key *index* is a fixed constant (1) — each station's value is the
        // isolation; the index never moves in this mode.
        if self.per_sta_vif {
            return self.rekey_gtk_per_sta();
        }
        let mut gtk_full = random_bytes::<32>();
        self.gtk.zeroize();
        self.gtk.copy_from_slice(&gtk_full[..16]);
        gtk_full.zeroize();
        self.group_pn = 1;
        // Two-phase group rekey (reference AP): the rotated GTK/IGTK go in at the
        // OTHER key index (toggle 1<->2 for the GTK, 4<->5 for the IGTK), so the
        // new key is advertised + installed at a fresh index and the IPN may be
        // reset (a fresh key id gets a fresh IPN).
        self.gtk_key_id = if self.gtk_key_id == 1 { 2 } else { 1 };
        self.igtk.zeroize();
        self.igtk = random_bytes::<16>();
        self.igtk_key_id = if self.igtk_key_id == 4 { 5 } else { 4 };
        self.igtk_ipn = [0; 6]; // fresh IGTK (new key id) gets a fresh IPN
        self.last_group_rekey = Instant::now();

        let stations: Vec<[u8; 6]> = self
            .stations
            .iter()
            .filter(|(_, s)| s.associated)
            .map(|(m, _)| *m)
            .collect();

        let gtk = self.gtk;
        let gtk_key_id = self.gtk_key_id;
        let igtk = self.igtk;
        let igtk_key_id = self.igtk_key_id;
        let igtk_ipn = self.igtk_ipn;

        let mut frames = Vec::new();
        for sta in stations {
            let mld_link_ids = self.station_mld_link_ids(&sta);
            let replay = self.next_eapol_replay();
            let (kck, kek, sha256, owe, replay) = {
                let s = self.stations.get_mut(&sta).unwrap();
                s.eapol_replay = replay;
                (s.kck, s.kek, s.sha256, s.owe, s.eapol_replay)
            };
            let igtk_kde = if sha256 {
                Some((igtk_key_id, igtk_ipn, igtk))
            } else {
                None
            };
            let sc = self.next_sc();
            let frame = if mld_link_ids.is_empty() {
                dot11::build_group_key_msg1(
                    &self.mac,
                    &sta,
                    &kck,
                    &kek,
                    gtk_key_id,
                    &gtk,
                    igtk_kde,
                    replay,
                    sc,
                    dot11::KeyMic::select(sha256, owe),
                )
            } else {
                dot11::build_group_key_msg1_mld(
                    &self.mac,
                    &sta,
                    &kck,
                    &kek,
                    &mld_link_ids,
                    gtk_key_id,
                    &gtk,
                    igtk_kde,
                    None,
                    replay,
                    sc,
                    dot11::KeyMic::select(sha256, owe),
                )
            };
            let mut f = dot11::RADIOTAP_TX.to_vec();
            f.extend_from_slice(&frame);
            if let Some(s) = self.stations.get_mut(&sta) {
                s.pending_eapol = Some(f.clone());
                s.eapol_tx = Instant::now();
                s.eapol_retries = 0;
                s.group_rekeying = true;
            }
            frames.push(f);
        }
        frames
    }

    /// Per-STA-VIF group rekey: rotate EACH associated station's OWN per-station
    /// GTK *value* and send that station a Group Key message 1 carrying its own
    /// new value — preserving the per-station broadcast isolation. The GTK *index*
    /// is a fixed constant (1): each station's own value (isolated in its own
    /// AP_VLAN) is what separates them, so the index never moves and is not a
    /// per-station or a shared toggling counter — the new value overwrites the old
    /// at the same index 1. The IGTK is genuinely BSS-wide (one BIP key for the
    /// radio's robust management frames), so it IS rotated once with its own 4<->5
    /// index toggle and delivered to every PMF station. Called only from
    /// `rekey_gtk` when `per_sta_vif` is set; the caller already guarantees no
    /// rekey is in flight.
    pub(super) fn rekey_gtk_per_sta(&mut self) -> Vec<Vec<u8>> {
        // The per-station GTK index is a fixed constant (1): each station's own
        // GTK *value* (its own key, isolated in its own AP_VLAN) is what separates
        // them, so the index never moves and is not a shared, toggling counter —
        // only the value rotates per station (below), overwriting the old one at
        // the same index 1. The BSS-wide IGTK (management-frame BIP, genuinely one
        // key per radio) still rotates with its own 4<->5 index toggle.
        self.igtk.zeroize();
        self.igtk = random_bytes::<16>();
        self.igtk_key_id = if self.igtk_key_id == 4 { 5 } else { 4 };
        self.igtk_ipn = [0; 6]; // fresh IGTK (new key id) gets a fresh IPN
        self.last_group_rekey = Instant::now();
        let gtk_key_id: u8 = 1;
        let igtk = self.igtk;
        let igtk_key_id = self.igtk_key_id;
        let igtk_ipn = self.igtk_ipn;

        let stations: Vec<[u8; 6]> = self
            .stations
            .iter()
            .filter(|(_, s)| s.associated)
            .map(|(m, _)| *m)
            .collect();

        let mut frames = Vec::new();
        for sta in stations {
            let mld_link_ids = self.station_mld_link_ids(&sta);
            let replay = self.next_eapol_replay();
            let (kck, kek, sha256, owe, replay, gtk) = {
                let s = self.stations.get_mut(&sta).unwrap();
                // Rotate this station's own GTK *value*; it goes in at the shared
                // (already-toggled) BSS-wide index.
                let mut gtk_full = random_bytes::<32>();
                s.gtk.zeroize();
                s.gtk.copy_from_slice(&gtk_full[..16]);
                gtk_full.zeroize();
                s.eapol_replay = replay;
                (s.kck, s.kek, s.sha256, s.owe, s.eapol_replay, s.gtk)
            };
            let igtk_kde = if sha256 {
                Some((igtk_key_id, igtk_ipn, igtk))
            } else {
                None
            };
            let sc = self.next_sc();
            let frame = if mld_link_ids.is_empty() {
                dot11::build_group_key_msg1(
                    &self.mac,
                    &sta,
                    &kck,
                    &kek,
                    gtk_key_id,
                    &gtk,
                    igtk_kde,
                    replay,
                    sc,
                    dot11::KeyMic::select(sha256, owe),
                )
            } else {
                dot11::build_group_key_msg1_mld(
                    &self.mac,
                    &sta,
                    &kck,
                    &kek,
                    &mld_link_ids,
                    gtk_key_id,
                    &gtk,
                    igtk_kde,
                    None,
                    replay,
                    sc,
                    dot11::KeyMic::select(sha256, owe),
                )
            };
            let mut f = dot11::RADIOTAP_TX.to_vec();
            f.extend_from_slice(&frame);
            if let Some(s) = self.stations.get_mut(&sta) {
                s.pending_eapol = Some(f.clone());
                s.eapol_tx = Instant::now();
                s.eapol_retries = 0;
                s.group_rekeying = true;
            }
            frames.push(f);
        }
        frames
    }

    /// Emit a BIP-protected, group-addressed Deauthentication frame (PMF). PMF
    /// stations validate it with the IGTK delivered in EAPOL message 3.
    pub fn group_deauth(&mut self, reason: u16) -> Vec<u8> {
        // advance the 48-bit IPN (little-endian, to match bip_ipn / the spec)
        inc_ipn_le(&mut self.igtk_ipn);
        let sc = self.next_sc();
        let frame = dot11::build_group_deauth_bip(
            &self.mac,
            &self.igtk,
            self.igtk_key_id,
            &self.igtk_ipn,
            reason,
            sc,
        );
        let mut f = dot11::RADIOTAP_TX.to_vec();
        f.extend_from_slice(&frame);
        f
    }
}
