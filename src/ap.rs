//! The access-point state machine, ported from `ap.py`'s `AP`/`BSS`/`Station`.
//!
//! Unlike the threaded Python original, this is a single-threaded state machine:
//! incoming 802.11 frames are fed to [`Ap::handle_incoming`], which mutates
//! state and returns the frames to transmit plus any decrypted Ethernet packets
//! destined for the AP's network stack. The driver wires those to real I/O.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::crypto;
use crate::dot11;

/// Per-station auth/assoc backoff (matches `BACKOFF = 0.25`).
const BACKOFF: Duration = Duration::from_millis(250);

pub struct Station {
    pub mac: [u8; 6],
    pub associated: bool,
    pub eapol_ready: bool,
    pub anonce: Option<[u8; 32]>,
    pub kck: [u8; 16],
    pub kek: [u8; 16],
    pub tk: [u8; 16],
    pub client_pn: u64,
    /// Highest received CCMP packet number (replay protection).
    pub last_rx_pn: u64,
    /// Highest received CCMP PN for protected management frames (separate replay
    /// counter, so a captured protected Deauth/Disassoc/Action can't be replayed).
    pub last_rx_mgmt_pn: u64,
    /// EAPOL-Key replay counter for downlink key messages (m1=1, m3=2, rekeys 3+).
    pub eapol_replay: u64,
    pub last_auth: Option<Instant>,
    pub last_assoc: Option<Instant>,
    /// In-progress SAE exchange (WPA3); `None` for WPA2/PSK stations.
    pub sae: Option<crate::sae::Sae>,
    /// PMK established by SAE; when set it overrides the AP's PSK-derived PMK.
    pub pmk: Option<[u8; 32]>,
    pub sae_confirmed: bool,
    /// SHA-256 key descriptors + PMF (true for WPA3-SAE and OWE stations).
    pub sha256: bool,
    /// OWE station: the EAPOL-Key MIC is HMAC-SHA256 (not SAE's AES-CMAC).
    pub owe: bool,
    /// Last time a frame was received from this station (inactivity timer).
    pub last_activity: Instant,
    /// Per-station GTK, used only in `per_sta_vif` mode so each station's VLAN
    /// has its own group key (broadcast isolation). Ignored otherwise.
    pub gtk: [u8; 16],
}

impl Station {
    fn new(mac: [u8; 6]) -> Station {
        Station {
            mac,
            associated: false,
            eapol_ready: false,
            anonce: None,
            kck: [0; 16],
            kek: [0; 16],
            tk: [0; 16],
            client_pn: 1, // CCMP PN starts at 1
            last_rx_pn: 0,
            last_rx_mgmt_pn: 0,
            eapol_replay: 0,
            last_auth: None,
            last_assoc: None,
            sae: None,
            pmk: None,
            sae_confirmed: false,
            sha256: false,
            owe: false,
            last_activity: Instant::now(),
            gtk: random_bytes::<16>(),
        }
    }

    fn next_client_pn(&mut self) -> u64 {
        let pn = self.client_pn;
        self.client_pn += 1;
        pn
    }
}

/// What [`Ap::handle_incoming`] produced for one inbound frame.
#[derive(Default)]
pub struct Outgoing {
    /// 802.11 frames to transmit (already radiotap-prefixed).
    pub frames: Vec<Vec<u8>>,
    /// Decrypted Ethernet frames for the AP's network backend (TUN / fakenet).
    pub to_network: Vec<Vec<u8>>,
}

impl Outgoing {
    fn tx(&mut self, frame: Vec<u8>) {
        // sendp prepends the TX radiotap header
        let mut f = dot11::RADIOTAP_TX.to_vec();
        f.extend_from_slice(&frame);
        self.frames.push(f);
    }
}

pub struct Ap {
    pub mac: [u8; 6],
    pub ssid: Vec<u8>,
    /// 2-letter regulatory country code advertised in the beacon Country IE.
    pub country: [u8; 2],
    pub channel: u8,
    pub pmk: [u8; 32],
    /// Passphrase, retained for WPA3-SAE PWE derivation.
    password: Vec<u8>,
    /// When true, accept WPA3-SAE (H2E) authentication.
    sae_enabled: bool,
    /// When true, advertise WPA2/WPA3 transition mode (mixed PSK + SAE).
    transition: bool,
    boottime: Instant,
    sc: i32,
    aid: u16,
    group_pn: u64,
    gtk: [u8; 16],
    /// Integrity GTK + key id + IPN, delivered to PMF stations for BIP.
    igtk: [u8; 16],
    igtk_key_id: u16,
    igtk_ipn: [u8; 6],
    /// Beacon Integrity GTK (Beacon Protection / 802.11 BIGTK).
    bigtk: [u8; 16],
    bigtk_key_id: u16,
    bigtk_ipn: [u8; 6],
    beacon_prot: bool,
    /// Pending Channel Switch Announcement (new channel, remaining count).
    pending_csa: Option<(u8, u8)>,
    /// Advertise the Multiple BSSID element.
    multi_bssid: bool,
    /// 802.11v: send a BSS Transition Management Request after each handshake.
    btm: bool,
    /// Advertise a co-located 6 GHz AP via a Reduced Neighbor Report.
    rnr_6ghz: Option<u8>,
    /// Operate on 6 GHz (HE-only beacon; `channel` is a 6 GHz channel number).
    band6: bool,
    /// Per-station VIF: each station gets its own GTK (for an nl80211 AP_VLAN),
    /// isolating broadcast/multicast traffic between stations.
    per_sta_vif: bool,
    /// Operating Channel Validation (OCV): include + validate the OCI KDE.
    ocv: bool,
    /// OWE (Opportunistic Wireless Encryption): open + DH key exchange.
    owe: bool,
    sa_query_id: u16,
    /// PMKSA cache: PMKID -> (PMK, sha256) for fast reconnect (hostapd `okc`).
    pmksa_cache: HashMap<[u8; 16], ([u8; 32], bool)>,
    stations: HashMap<[u8; 6], Station>,
    /// Deterministic randomness hook for tests; `None` uses the OS RNG.
    test_anonce: Option<[u8; 32]>,
}

fn is_broadcast(a: &[u8; 6]) -> bool {
    a == &[0xff; 6]
}

fn is_multicast(a: &[u8; 6]) -> bool {
    a[0] & 0x01 != 0
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("OS RNG available");
    b
}

fn prepend_radiotap(frame: Vec<u8>) -> Vec<u8> {
    let mut f = dot11::RADIOTAP_TX.to_vec();
    f.extend_from_slice(&frame);
    f
}

impl Ap {
    pub fn new(ssid: &str, psk: &str, mac: [u8; 6], channel: u8) -> Ap {
        let pmk = crypto::pbkdf2_pmk(psk, ssid);
        let gtk_full = random_bytes::<32>();
        let mut gtk = [0u8; 16];
        gtk.copy_from_slice(&gtk_full[..16]);
        Ap {
            mac,
            ssid: ssid.as_bytes().to_vec(),
            country: *b"US",
            channel,
            pmk,
            password: psk.as_bytes().to_vec(),
            sae_enabled: false,
            transition: false,
            boottime: Instant::now(),
            sc: 0,
            aid: 0,
            group_pn: 1,
            gtk,
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
            ocv: false,
            owe: false,
            sa_query_id: 0,
            pmksa_cache: HashMap::new(),
            stations: HashMap::new(),
            test_anonce: None,
        }
    }

    /// Enable WPA3-SAE (H2E) authentication on this AP.
    pub fn enable_sae(&mut self) {
        self.sae_enabled = true;
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

    fn security_mode(&self) -> dot11::SecurityMode {
        if self.owe {
            dot11::SecurityMode::Owe
        } else if self.transition {
            dot11::SecurityMode::Transition
        } else if self.sae_enabled {
            dot11::SecurityMode::Wpa3Sae
        } else {
            dot11::SecurityMode::Wpa2
        }
    }

    /// Force a fixed GTK / ANONCE for deterministic tests.
    pub fn set_test_fixtures(&mut self, gtk: [u8; 16], anonce: [u8; 32]) {
        self.gtk = gtk;
        self.test_anonce = Some(anonce);
    }

    fn next_sc(&mut self) -> u16 {
        self.sc = (self.sc + 1).rem_euclid(4096);
        (self.sc * 16) as u16
    }

    fn next_aid(&mut self) -> u16 {
        self.aid = (self.aid + 1) % 2008;
        self.aid
    }

    fn next_group_pn(&mut self) -> u64 {
        let pn = self.group_pn;
        self.group_pn += 1;
        pn
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

    /// Operate the AP on the 6 GHz band (HE-only beacon; WPA3 mandatory).
    pub fn enable_band6(&mut self) {
        self.band6 = true;
    }

    /// Set the 2-letter regulatory country code advertised in the Country IE.
    pub fn set_country(&mut self, country: [u8; 2]) {
        self.country = country;
    }

    /// Give each station its own GTK (per-station VIF / nl80211 AP_VLAN), so a
    /// station cannot read broadcast/multicast addressed to another's VLAN.
    pub fn enable_per_sta_vif(&mut self) {
        self.per_sta_vif = true;
    }

    /// Whether per-station-VIF mode is enabled.
    pub fn per_sta_vif(&self) -> bool {
        self.per_sta_vif
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

    /// Build an 802.11v BSS Transition Management Request steering `sta` toward a
    /// preferred candidate BSS (a Neighbor Report on the same operating class).
    fn btm_request_frame(&mut self, sta: &[u8; 6]) -> Vec<u8> {
        let op_class = if dot11::is_5ghz(self.channel) { 115 } else { 81 };
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
        self.sae_enabled = true;
        self.ocv = true;
    }

    /// Enable OWE (Opportunistic Wireless Encryption): an open BSS that performs
    /// a Diffie-Hellman exchange in (re)association to key the 4-way handshake.
    pub fn enable_owe(&mut self) {
        self.owe = true;
    }

    /// One beacon frame for the beacon ticker.
    pub fn beacon_frame(&mut self) -> Vec<u8> {
        let ts = self.current_timestamp();
        let tail = dot11::security_tail(self.security_mode());
        let mut frame = if self.band6 {
            dot11::build_beacon_6ghz(&self.mac, &self.ssid, self.channel, ts, &tail, &self.country)
        } else {
            dot11::build_beacon(&self.mac, &self.ssid, self.channel, ts, &tail, &self.country)
        };
        // Channel Switch Announcement (802.11h)
        if let Some((nch, count)) = self.pending_csa {
            frame.extend_from_slice(&dot11::csa_element(nch, count));
            if count == 0 {
                self.channel = nch;
                self.pending_csa = None;
            } else {
                self.pending_csa = Some((nch, count - 1));
            }
        }
        // Multiple BSSID element
        if self.multi_bssid {
            frame.extend_from_slice(&dot11::multiple_bssid_element(0));
        }
        // Reduced Neighbor Report: advertise a co-located 6 GHz affiliated AP.
        if let Some(ch6) = self.rnr_6ghz {
            let mut nb = self.mac;
            nb[5] ^= 0x10;
            frame.extend_from_slice(&dot11::reduced_neighbor_report(&nb, 131, ch6));
        }
        if self.beacon_prot {
            // Protect the beacon body with a BIP Management MIC Element (BIGTK).
            for b in self.bigtk_ipn.iter_mut().rev() {
                *b = b.wrapping_add(1);
                if *b != 0 {
                    break;
                }
            }
            let (fc0, fc1) = (frame[0], frame[1]);
            let bcast = [0xffu8; 6];
            let body = dot11::bip_protect(&self.bigtk, self.bigtk_key_id, &self.bigtk_ipn, fc0, fc1, &bcast, &self.mac, &self.mac, &frame[24..]);
            frame.truncate(24);
            frame.extend_from_slice(&body);
        }
        let mut f = dot11::RADIOTAP_TX.to_vec();
        f.extend_from_slice(&frame);
        f
    }

    // -- inbound frame handling --------------------------------------------

    /// Process one received frame (radiotap-prefixed) and return what to do.
    pub fn handle_incoming(&mut self, radiotap_frame: &[u8]) -> Outgoing {
        let mut out = Outgoing::default();
        if dot11::radiotap_bad_fcs(radiotap_frame) {
            return out;
        }
        let Some(body) = dot11::strip_radiotap(radiotap_frame) else {
            return out;
        };
        let Some(frame) = dot11::Dot11::parse(body) else {
            return out;
        };

        // Address filter (recv_pkt): only accept frames addressed to us, or
        // group-addressed frames from someone else.
        let a1 = frame.addr1;
        if a1 != self.mac {
            if is_multicast(&a1) || is_broadcast(&a1) {
                if frame.addr2 == self.mac {
                    return out;
                }
            } else {
                return out;
            }
        }

        // Inactivity timer: any frame from a known station counts as activity.
        if let Some(s) = self.stations.get_mut(&frame.addr2) {
            s.last_activity = Instant::now();
        }

        // Encrypted uplink data (to-DS + protected) goes through the decrypt +
        // replay path FIRST: a protected frame must never be treated as a
        // plaintext EAPOL by `is_eapol()` (whose LLC/SNAP match an attacker
        // could otherwise force with a crafted CCMP packet number).
        if frame.frame_type() == dot11::TYPE_DATA && frame.protected() {
            if frame.to_ds() {
                self.handle_data_uplink(&frame, &mut out);
            }
            return out;
        }

        // EAPOL is only accepted unprotected here — the 4-way handshake (msg 2/4)
        // runs before the PTK is installed.
        if frame.is_eapol() {
            self.handle_eapol(&frame, &mut out);
            return out;
        }

        // Management frames
        if frame.frame_type() == dot11::TYPE_MGMT {
            match frame.subtype() {
                dot11::SUBTYPE_PROBE_REQ => self.handle_probe_req(&frame, &mut out),
                dot11::SUBTYPE_AUTH => self.handle_auth_req(&frame, &mut out),
                dot11::SUBTYPE_ASSOC_REQ | dot11::SUBTYPE_REASSOC_REQ => self.handle_assoc_req(&frame, &mut out),
                dot11::SUBTYPE_DEAUTH | dot11::SUBTYPE_DISASSOC => self.handle_robust_mgmt(&frame),
                dot11::SUBTYPE_ACTION => self.handle_action(&frame, &mut out),
                _ => {}
            }
        }
        out
    }

    fn handle_probe_req(&mut self, frame: &dot11::Dot11, out: &mut Outgoing) {
        let ssid = dot11::find_ssid(&frame.body);
        match ssid {
            Some(s) if s.is_empty() => {
                // empty SSID -> respond with our primary SSID
                self.send_probe_resp(&frame.addr2, out);
            }
            Some(s) if s == self.ssid => {
                self.send_probe_resp(&frame.addr2, out);
            }
            _ => {}
        }
    }

    fn send_probe_resp(&mut self, dst: &[u8; 6], out: &mut Outgoing) {
        let sc = self.next_sc();
        let ts = self.current_timestamp();
        let frame = dot11::build_probe_resp(&self.mac, dst, &self.ssid, self.channel, ts, sc, &dot11::security_tail(self.security_mode()), &self.country);
        out.tx(frame);
    }

    fn handle_auth_req(&mut self, frame: &dot11::Dot11, out: &mut Outgoing) {
        if frame.addr1 != self.mac {
            return;
        }
        let sta = frame.addr2;
        let Some(auth) = dot11::parse_auth(&frame.body) else {
            return;
        };

        // WPA3-SAE authentication (algorithm 3)
        if auth.algo == dot11::AUTH_ALG_SAE {
            if self.sae_enabled {
                self.handle_sae_auth(&sta, auth.seq, auth.status, auth.payload, out);
            }
            return;
        }

        // Open-system authentication (algorithm 0) -- WPA2/PSK
        let now = Instant::now();
        {
            let entry = self.stations.entry(sta).or_insert_with(|| Station::new(sta));
            if let Some(t) = entry.last_auth {
                if now.duration_since(t) < BACKOFF {
                    return;
                }
            }
            entry.last_auth = Some(now);
            // A (re-)Authentication restarts the station's session, as in
            // hostapd: drop any prior 4-way / association state so a reconnecting
            // client derives a fresh PTK against a fresh ANonce. Without this, a
            // station that left without a (seen) deauth keeps its stale ANonce
            // and keys, and the reconnect's 4-way fails with a MIC/"wrong key".
            entry.anonce = None;
            entry.eapol_ready = false;
            entry.associated = false;
            entry.eapol_replay = 0;
            entry.kck = [0; 16];
            entry.kek = [0; 16];
            entry.tk = [0; 16];
            entry.gtk = random_bytes::<16>();
        }

        // recv_pkt resets the sequence counter on auth
        self.sc = -1;
        let sc = self.next_sc();
        let auth = dot11::build_auth(&self.mac, &sta, sc);
        out.tx(auth);
    }

    /// Drive the SAE (Dragonfly) exchange. Commit (seq 1) yields our commit +
    /// confirm; the peer's confirm (seq 2) completes authentication.
    fn handle_sae_auth(&mut self, sta: &[u8; 6], seq: u16, status: u16, payload: &[u8], out: &mut Outgoing) {
        if seq == 1 {
            // Pick the PWE method the STA advertised: status 126 = Hash-to-Element
            // (the preferred, side-channel-free derivation), otherwise legacy
            // hunting-and-pecking (whose derivation is made constant-time in
            // `derive_pwe_hunting_pecking` so it has no Dragonblood timing leak).
            let h2e = status == dot11::STATUS_SAE_H2E;
            let mut sae = if h2e {
                crate::sae::Sae::new_h2e(&self.ssid, &self.password, None, &self.mac, sta)
            } else {
                match crate::sae::Sae::new_hunting_pecking(&self.password, &self.mac, sta) {
                    Some(s) => s,
                    None => return,
                }
            };
            if sae.parse_peer_commit(payload).is_err() {
                return;
            }
            sae.prepare_commit(None);
            // Reject a reflected commit (peer echoing our own scalar + element).
            if sae.is_reflection() {
                return;
            }
            if sae.process_commit().is_err() {
                return;
            }

            let commit_body = sae.write_commit();
            let confirm_body = sae.write_confirm();
            let resp_status = if h2e { dot11::STATUS_SAE_H2E } else { dot11::STATUS_SUCCESS };

            self.sc = -1;
            let sc1 = self.next_sc();
            let commit = dot11::build_sae_auth(sta, &self.mac, &self.mac, 0, sc1, 1, resp_status, &commit_body);
            let sc2 = self.next_sc();
            let confirm = dot11::build_sae_auth(sta, &self.mac, &self.mac, 0, sc2, 2, dot11::STATUS_SUCCESS, &confirm_body);

            let mut pmk = [0u8; 32];
            pmk.copy_from_slice(&sae.pmk);
            let entry = self.stations.entry(*sta).or_insert_with(|| Station::new(*sta));
            entry.sae = Some(sae);
            entry.pmk = Some(pmk);
            entry.sae_confirmed = false;
            entry.sha256 = true; // WPA3-SAE uses SHA-256 key descriptors + PMF

            out.tx(commit);
            out.tx(confirm);
        } else if seq == 2 {
            // Verify the peer's confirm. Only a verified confirm completes SAE:
            // it gates association (see `handle_assoc_req`) and is the point at
            // which the PMK becomes mutually authenticated, so the PMKSA is
            // cached *here*, not on the unconfirmed commit.
            let confirmed = match self.stations.get(sta).and_then(|s| s.sae.as_ref()) {
                Some(sae) if sae.check_confirm(payload).is_ok() => Some((sae.pmkid.clone(), sae.pmk.clone())),
                _ => return,
            };
            if let Some(s) = self.stations.get_mut(sta) {
                s.sae_confirmed = true;
            }
            if let Some((pmkid, pmk)) = confirmed {
                if pmkid.len() == 16 && pmk.len() == 32 {
                    let mut id = [0u8; 16];
                    id.copy_from_slice(&pmkid);
                    let mut k = [0u8; 32];
                    k.copy_from_slice(&pmk);
                    self.pmksa_cache.insert(id, (k, true));
                }
            }
        }
    }

    fn handle_assoc_req(&mut self, frame: &dot11::Dot11, out: &mut Outgoing) {
        if frame.addr1 != self.mac {
            return;
        }
        let sta = frame.addr2;
        let reassoc = frame.subtype() == dot11::SUBTYPE_REASSOC_REQ;

        // An SAE station must have completed a *verified* SAE confirm before it
        // may associate. Otherwise the mutual authentication is incomplete and
        // we would derive a PTK from an unconfirmed PMK — the SAE confirm is the
        // step that proves the peer actually holds the password.
        if let Some(s) = self.stations.get(&sta) {
            if s.sae.is_some() && !s.sae_confirmed {
                return;
            }
        }

        // PMF SA Query: a (re)association request from a STA we already have a
        // PMF association with must NOT tear down the existing session (it may be
        // spoofed). Reject with status 30 and SA-Query the existing STA instead.
        let (pmf_assoc, tk) = self
            .stations
            .get(&sta)
            .map(|s| (s.associated && s.sha256, s.tk))
            .unwrap_or((false, [0u8; 16]));
        if pmf_assoc {
            let sc = self.next_sc();
            out.tx(dot11::build_assoc_resp_comeback(&self.mac, &sta, 1000, sc));
            self.sa_query_id = self.sa_query_id.wrapping_add(1);
            let trans = self.sa_query_id;
            let pn = self.stations.get_mut(&sta).unwrap().next_client_pn();
            let sc = self.next_sc();
            out.tx(dot11::build_protected_sa_query(&self.mac, &sta, false, false, trans, sc, pn, &tk));
            return;
        }

        let now = Instant::now();
        {
            let entry = self.stations.entry(sta).or_insert_with(|| Station::new(sta));
            if let Some(t) = entry.last_assoc {
                if now.duration_since(t) < BACKOFF {
                    return;
                }
            }
            entry.last_assoc = Some(now);
        }

        // PMKSA caching: if the (re)assoc request carries a PMKID we have cached,
        // skip a fresh SAE exchange and run the 4-way with the cached PMK.
        if frame.body.len() > 4 {
            if let Some(rsn) = dot11::find_ie(&frame.body[4..], 48) {
                if let Some(pmkid) = dot11::parse_rsn_pmkid(rsn) {
                    if let Some((pmk, sha256)) = self.pmksa_cache.get(&pmkid).copied() {
                        if let Some(s) = self.stations.get_mut(&sta) {
                            s.pmk = Some(pmk);
                            s.sha256 = sha256;
                        }
                    }
                }
            }
        }

        // OWE: if the (re)assoc request carries a DH Parameter element, run the
        // Diffie-Hellman exchange and key the 4-way with the resulting PMK.
        let mut owe_dh_resp: Option<Vec<u8>> = None;
        if self.owe && frame.body.len() > 4 {
            if let Some((group, sta_pub)) = dot11::parse_dh_param(&frame.body[4..]) {
                if group == 19 {
                    let (ap_priv, ap_pub) = crate::sae::owe_keypair();
                    if let Some((pmk, _pmkid)) = crate::sae::owe_derive(&ap_priv, &sta_pub, &sta_pub, &ap_pub, group) {
                        if let Some(s) = self.stations.get_mut(&sta) {
                            s.pmk = Some(pmk);
                            s.sha256 = true;
                            s.owe = true; // OWE uses the HMAC-SHA256 EAPOL MIC
                        }
                        owe_dh_resp = Some(dot11::build_dh_param_element(group, &ap_pub));
                    }
                }
            }
        }

        let resp_subtype = if reassoc { 0x03 } else { dot11::SUBTYPE_ASSOC_RESP };
        let aid = self.next_aid();
        let sc = self.next_sc();
        let mut assoc = dot11::build_assoc_resp(&self.mac, &sta, &self.ssid, self.channel, aid, sc, resp_subtype, &self.country);
        // Advertise a BSS Max Idle Period (~300 s) so the STA sends keep-alives.
        assoc.extend_from_slice(&dot11::bss_max_idle_element(300));
        if let Some(dh) = owe_dh_resp {
            assoc.extend_from_slice(&dh); // OWE DH Parameter element
        }

        // Prepare EAPOL message 1 with a FRESH ANonce for every 4-way (every
        // (re)association). Reusing the ANonce would let an attacker who forces
        // a reassociation replay the station's earlier Message 2 — it still
        // verifies under the unchanged PTK — and make the AP reinstall that PTK
        // with its packet number reset to 1, a KRACK-style keystream/nonce
        // reuse. A fresh ANonce changes the PTK, so a replayed old m2 fails its
        // MIC and is rejected.
        let anonce = self.test_anonce.unwrap_or_else(random_bytes::<32>);
        {
            let entry = self.stations.get_mut(&sta).unwrap();
            entry.anonce = Some(anonce);
            entry.eapol_ready = true;
        }
        let (sha256, owe) = self.stations.get(&sta).map(|s| (s.sha256, s.owe)).unwrap_or((false, false));
        let m1_sc = self.next_sc();
        let m1 = dot11::build_eapol_m1(&self.mac, &sta, &anonce, m1_sc, dot11::KeyMic::select(sha256, owe));

        out.tx(assoc);
        out.tx(m1);
    }

    fn handle_eapol(&mut self, frame: &dot11::Dot11, out: &mut Outgoing) {
        let sta = frame.addr2;
        if frame.addr1 != self.mac {
            return;
        }
        // station must exist and be expecting message 2
        let (anonce, ready) = match self.stations.get(&sta) {
            Some(s) => (s.anonce, s.eapol_ready),
            None => return,
        };
        if !ready {
            return;
        }
        let Some(anonce) = anonce else { return };

        let Some(eapol_frame) = frame.eapol_frame() else { return };
        let Some(key_body) = frame.eapol_key_body() else { return };
        let Some(ek) = dot11::EapolKey::parse(key_body) else { return };

        // EAPOL-Key replay-counter enforcement: message 2 must echo the replay
        // counter the AP used in message 1 (1). This rejects replayed/forged m2.
        if ek.key_replay_counter != 1 {
            return;
        }

        let snonce = ek.key_nonce;
        let amac = self.mac;
        let smac = sta;

        // Use the SAE-derived PMK + SHA-256 key descriptors when the station
        // authenticated via WPA3-SAE; otherwise the PSK (PBKDF2) PMK + SHA-1.
        let (pmk, sha256, owe) = self
            .stations
            .get(&sta)
            .map(|s| (s.pmk.unwrap_or(self.pmk), s.sha256, s.owe))
            .unwrap_or((self.pmk, false, false));
        let mut kck = [0u8; 16];
        let mut kek = [0u8; 16];
        let mut tk = [0u8; 16];
        if sha256 {
            let ptk = crypto::derive_ptk_sha256(&pmk, &amac, &smac, &anonce, &snonce);
            kck.copy_from_slice(&ptk[..16]);
            kek.copy_from_slice(&ptk[16..32]);
            tk.copy_from_slice(&ptk[32..48]);
        } else {
            let ptk = crypto::custom_prf512(&pmk, &amac, &smac, &anonce, &snonce);
            kck.copy_from_slice(&ptk[..16]);
            kek.copy_from_slice(&ptk[16..32]);
            tk.copy_from_slice(&ptk[32..48]);
        }

        // Verify the MIC on message 2: recompute over the EAPOL frame with the
        // MIC field zeroed (AES-CMAC for SAE, HMAC-SHA256 for OWE, HMAC-SHA1 for WPA2).
        let mic_off_in_eapol = 4 + ek.mic_offset; // EAPOL header (4) + body offset
        let mut to_check = eapol_frame.to_vec();
        for b in to_check[mic_off_in_eapol..mic_off_in_eapol + 16].iter_mut() {
            *b = 0;
        }
        let computed = dot11::KeyMic::select(sha256, owe).compute(&kck, &to_check).to_vec();
        if !crypto::constant_time_eq(&computed[..16], &ek.key_mic) {
            // bad MIC -> deauth and drop the station
            let deauth = dot11::build_deauth(&self.mac, &sta, 1);
            out.tx(deauth);
            self.stations.remove(&sta);
            return;
        }

        // Operating Channel Validation: message 2's OCI must match our channel.
        if self.ocv {
            let want = (dot11::operating_class(self.channel), self.channel);
            match dot11::parse_oci_kde(&ek.key_data) {
                Some(oci) if oci == want => {}
                _ => return, // missing or mismatched OCI -> possible MITM, drop
            }
        }

        // good: install keys, send message 3
        {
            let s = self.stations.get_mut(&sta).unwrap();
            s.kck = kck;
            s.kek = kek;
            s.tk = tk;
            s.eapol_ready = false;
            s.client_pn = 1;
            s.eapol_replay = 2; // m1=1, m3=2; rekeys continue from here
        }
        // Deliver the IGTK KDE to PMF (WPA3-SAE) stations so they can validate
        // BIP-protected group-addressed management frames, and the BIGTK KDE when
        // Beacon Protection is enabled.
        let igtk = if sha256 {
            Some((self.igtk_key_id, self.igtk_ipn, self.igtk))
        } else {
            None
        };
        let bigtk = if sha256 && self.beacon_prot {
            Some((self.bigtk_key_id, self.bigtk_ipn, self.bigtk))
        } else {
            None
        };
        let oci = if self.ocv {
            Some((dot11::operating_class(self.channel), self.channel))
        } else {
            None
        };
        let sc = self.next_sc();
        // m3's key data must echo the exact RSNE (+ RSNXE) the AP advertises in
        // its beacon, or the supplicant rejects it as a Beacon/EAPOL IE mismatch.
        let ap_rsn: Vec<u8> = if owe {
            dot11::RSN_OWE.to_vec()
        } else if sha256 {
            let mut r = dot11::RSN_WPA3.to_vec();
            r.extend_from_slice(&dot11::RSNXE_H2E);
            r
        } else {
            dot11::RSN.to_vec()
        };
        // In per-station-VIF mode each station gets its own GTK (broadcast
        // isolation); otherwise all stations share the BSS-wide GTK.
        let gtk = self.station_gtk(&sta);
        let m3 = dot11::build_eapol_m3(&self.mac, &sta, &anonce, &kck, &kek, &ap_rsn, &gtk, igtk, bigtk, oci, sc, dot11::KeyMic::select(sha256, owe));
        out.tx(m3);
        if let Some(s) = self.stations.get_mut(&sta) {
            s.associated = true;
        }
        // 802.11v auto-steer: send an (unprotected, WPA2) BSS Transition
        // Management Request once associated. For PMF (WPA3/OWE) the request must
        // be CCMP-protected and is sent via `btm_request()` after the STA has
        // installed the PTK.
        if self.btm {
            let pmf = self.stations.get(&sta).map(|s| s.sha256).unwrap_or(false);
            if !pmf {
                let f = self.btm_request_frame(&sta);
                out.tx(f);
            }
        }
    }

    fn handle_data_uplink(&mut self, frame: &dot11::Dot11, out: &mut Outgoing) {
        let sta = frame.addr2;
        let bssid = frame.addr1;
        if bssid != self.mac {
            return;
        }
        let key_id = frame.ccmp_key_id();
        let tk = match key_id {
            0 => match self.stations.get(&sta) {
                Some(s) if s.associated => s.tk,
                _ => {
                    // unknown station -> deauth
                    let deauth = dot11::build_deauth(&self.mac, &sta, 9);
                    out.tx(deauth);
                    return;
                }
            },
            1 => self.gtk,
            _ => return,
        };

        // CCMP replay protection: the packet number must strictly increase.
        let pn = match frame.ccmp_pn() {
            Some(p) => p,
            None => return,
        };
        if key_id == 0 {
            if let Some(s) = self.stations.get(&sta) {
                if pn <= s.last_rx_pn {
                    return; // replayed / out-of-order frame
                }
            }
        }

        if let Some(eth) = dot11::decrypt_ccmp(frame, &tk, false) {
            // sanity: source MAC in the Ethernet frame must match the station
            if eth.len() >= 12 && eth[6..12] == sta {
                if key_id == 0 {
                    if let Some(s) = self.stations.get_mut(&sta) {
                        s.last_rx_pn = pn;
                    }
                }
                out.to_network.push(eth);
            }
        }
    }

    // -- downlink (network -> station) -------------------------------------

    /// Encrypt an Ethernet frame from the network backend toward its
    /// destination station (or the group for broadcast/multicast). Mirrors
    /// `enc_send`.
    pub fn deliver_to_station(&mut self, eth: &[u8]) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        if eth.len() < 14 {
            return frames;
        }
        let mut dst = [0u8; 6];
        let mut src = [0u8; 6];
        dst.copy_from_slice(&eth[0..6]);
        src.copy_from_slice(&eth[6..12]);
        let ethertype = u16::from_be_bytes([eth[12], eth[13]]);
        let inner = &eth[14..];

        let (key_id, pn, tk, a1) = if is_multicast(&dst) || is_broadcast(&dst) {
            let pn = self.next_group_pn();
            (1u8, pn, self.gtk, dst)
        } else {
            match self.stations.get(&dst) {
                Some(s) if s.associated => {}
                _ => return frames,
            }
            let s = self.stations.get_mut(&dst).unwrap();
            let pn = s.next_client_pn();
            (0u8, pn, s.tk, dst)
        };

        let sc = self.next_sc();
        let frame = dot11::build_ccmp_data(
            &a1,
            &self.mac,
            &src,
            dot11::FC_FROMDS | dot11::FC_PROTECTED,
            sc,
            pn,
            key_id,
            &tk,
            ethertype,
            inner,
        );
        let mut f = dot11::RADIOTAP_TX.to_vec();
        f.extend_from_slice(&frame);
        frames.push(f);
        frames
    }

    /// PMF enforcement for received Deauth/Disassoc: under PMF only a valid
    /// CCMP-protected frame tears the station down; unprotected ones are dropped.
    fn handle_robust_mgmt(&mut self, frame: &dot11::Dot11) {
        let sta = frame.addr2;
        let pmf = match self.stations.get(&sta) {
            Some(s) => s.sha256,
            None => return,
        };
        if !pmf {
            // WPA2 (no PMF): Deauth/Disassoc are unprotected, so tear down.
            self.stations.remove(&sta);
            return;
        }
        // PMF: only a CCMP-valid frame from a station that has *completed the
        // 4-way* (real PTK installed) tears it down. `installed_tk` returns None
        // before the handshake finishes, so we never attempt CCMP with the
        // all-zero placeholder key — which would let a spoofed "NULL-key"
        // frame decrypt and kill a station mid-handshake.
        if frame.protected() {
            if let Some(tk) = self.installed_tk(&sta) {
                // Reject a replayed protected frame (PN must strictly increase)
                // before acting on it.
                let Some(pn) = frame.ccmp_pn() else { return };
                if self.stations.get(&sta).map(|s| pn <= s.last_rx_mgmt_pn).unwrap_or(true) {
                    return;
                }
                if dot11::decrypt_ccmp_mgmt(frame, &tk).is_some() {
                    self.stations.remove(&sta);
                }
            }
        }
    }

    /// Handle a (PMF-protected) SA Query Action frame: respond to a Request, and
    /// accept a Response as proof the station is alive.
    fn handle_action(&mut self, frame: &dot11::Dot11, out: &mut Outgoing) {
        let sta = frame.addr2;
        // 802.11v BTM Response (unprotected, e.g. WPA2): the client's reply to
        // our steering request.
        if !frame.protected() {
            if let Some((token, status)) = dot11::parse_btm_response(&frame.body) {
                eprintln!("AP: BTM Response from {} token={token} status={status}", crate::util::bytes_to_mac(&sta));
            }
            return;
        }
        if !frame.protected() {
            return; // robust action frames must be protected under PMF
        }
        // Only attempt CCMP with a fully-installed PTK (never the all-zero
        // placeholder of a station that skipped ahead before keying).
        let Some(tk) = self.installed_tk(&sta) else {
            return;
        };
        // Reject a replayed protected action frame (PN must strictly increase).
        let Some(rx_pn) = frame.ccmp_pn() else { return };
        if self.stations.get(&sta).map(|s| rx_pn <= s.last_rx_mgmt_pn).unwrap_or(true) {
            return;
        }
        let Some(plain) = dot11::decrypt_ccmp_mgmt(frame, &tk) else {
            return;
        };
        if let Some(s) = self.stations.get_mut(&sta) {
            s.last_rx_mgmt_pn = rx_pn;
        }
        if let Some((action, trans)) = dot11::parse_sa_query(&plain) {
            if action == dot11::SA_QUERY_REQUEST {
                let pn = self.stations.get_mut(&sta).unwrap().next_client_pn();
                let sc = self.next_sc();
                out.tx(dot11::build_protected_sa_query(&self.mac, &sta, false, true, trans, sc, pn, &tk));
            }
        }
    }

    /// Whether a station has completed the handshake.
    pub fn is_associated(&self, sta: &[u8; 6]) -> bool {
        self.stations.get(sta).map(|s| s.associated).unwrap_or(false)
    }

    /// The *installed* pairwise key for a station: the TK only once the 4-way is
    /// complete (`associated`). Returns `None` beforehand so no code path ever
    /// performs CCMP with the all-zero placeholder key — i.e. a station that
    /// skipped ahead in the auth sequence cannot trigger crypto with a NULL key.
    fn installed_tk(&self, sta: &[u8; 6]) -> Option<[u8; 16]> {
        self.stations.get(sta).filter(|s| s.associated).map(|s| s.tk)
    }

    /// The session TK for a station (test/inspection helper).
    pub fn station_tk(&self, sta: &[u8; 6]) -> Option<[u8; 16]> {
        self.stations.get(sta).map(|s| s.tk)
    }

    /// 802.11v: send a (CCMP-protected) BSS Transition Management request, e.g.
    /// to steer or kick a station (`disassoc_imminent`).
    pub fn btm_request(&mut self, sta: &[u8; 6], disassoc_imminent: bool, disassoc_timer: u16) -> Option<Vec<u8>> {
        let tk = self.installed_tk(sta)?;
        let pn = self.stations.get_mut(sta)?.next_client_pn();
        let sc = self.next_sc();
        let frame = dot11::build_protected_btm_request(&self.mac, sta, 1, disassoc_imminent, disassoc_timer, sc, pn, &tk);
        Some(prepend_radiotap(frame))
    }

    /// 802.11k: send a (CCMP-protected) Neighbor Report Response listing this AP.
    pub fn neighbor_report(&mut self, sta: &[u8; 6]) -> Option<Vec<u8>> {
        let tk = self.installed_tk(sta)?;
        let pn = self.stations.get_mut(sta)?.next_client_pn();
        let sc = self.next_sc();
        let op_class = if dot11::is_5ghz(self.channel) { 115 } else { 81 };
        let neighbor = dot11::neighbor_report_element(&self.mac, op_class, self.channel);
        let frame = dot11::build_protected_neighbor_report(&self.mac, sta, 1, &neighbor, sc, pn, &tk);
        Some(prepend_radiotap(frame))
    }

    /// Build a CCMP-protected unicast Deauthentication toward a PMF station.
    pub fn protected_deauth(&mut self, sta: &[u8; 6], reason: u16) -> Option<Vec<u8>> {
        let tk = self.installed_tk(sta)?;
        let pn = self.stations.get_mut(sta)?.next_client_pn();
        let sc = self.next_sc();
        let frame = dot11::build_protected_deauth(&self.mac, sta, reason, sc, pn, &tk);
        let mut f = dot11::RADIOTAP_TX.to_vec();
        f.extend_from_slice(&frame);
        Some(f)
    }

    /// Disassociate stations idle longer than `max_idle` (hostapd
    /// `ap_max_inactivity`). Returns Deauthentication frames (CCMP-protected for
    /// PMF stations), reason 4 (disassociated due to inactivity).
    pub fn prune_idle(&mut self, max_idle: Duration) -> Vec<Vec<u8>> {
        let now = Instant::now();
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
            self.stations.remove(&sta);
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

    /// Rotate the GTK (and IGTK) and run the Group Key Handshake: send Group Key
    /// message 1 to every associated station. Returns the frames to transmit.
    /// Mirrors hostapd's `wpa_group_rekey`.
    pub fn rekey_gtk(&mut self) -> Vec<Vec<u8>> {
        let gtk_full = random_bytes::<32>();
        self.gtk.copy_from_slice(&gtk_full[..16]);
        self.group_pn = 1;
        self.igtk = random_bytes::<16>();

        let stations: Vec<[u8; 6]> = self
            .stations
            .iter()
            .filter(|(_, s)| s.associated)
            .map(|(m, _)| *m)
            .collect();

        let gtk = self.gtk;
        let igtk = self.igtk;
        let igtk_key_id = self.igtk_key_id;
        let igtk_ipn = self.igtk_ipn;

        let mut frames = Vec::new();
        for sta in stations {
            let (kck, kek, sha256, owe, replay) = {
                let s = self.stations.get_mut(&sta).unwrap();
                s.eapol_replay += 1;
                (s.kck, s.kek, s.sha256, s.owe, s.eapol_replay)
            };
            let igtk_kde = if sha256 { Some((igtk_key_id, igtk_ipn, igtk)) } else { None };
            let sc = self.next_sc();
            let frame = dot11::build_group_key_msg1(&self.mac, &sta, &kck, &kek, &gtk, igtk_kde, replay, sc, dot11::KeyMic::select(sha256, owe));
            let mut f = dot11::RADIOTAP_TX.to_vec();
            f.extend_from_slice(&frame);
            frames.push(f);
        }
        frames
    }

    /// Emit a BIP-protected, group-addressed Deauthentication frame (PMF). PMF
    /// stations validate it with the IGTK delivered in EAPOL message 3.
    pub fn group_deauth(&mut self, reason: u16) -> Vec<u8> {
        // advance the 48-bit IPN
        for b in self.igtk_ipn.iter_mut().rev() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
        let sc = self.next_sc();
        let frame = dot11::build_group_deauth_bip(&self.mac, &self.igtk, self.igtk_key_id, &self.igtk_ipn, reason, sc);
        let mut f = dot11::RADIOTAP_TX.to_vec();
        f.extend_from_slice(&frame);
        f
    }
}
