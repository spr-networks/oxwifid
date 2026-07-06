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

/// Retransmit a pending EAPOL m1/m3 if its m2/m4 hasn't arrived within this long
/// (hostapd's `wpa_group_update_count`/`eapol_key_timeout`), up to
/// [`MAX_EAPOL_RETRIES`] times before giving up and deauthenticating.
const EAPOL_TIMEOUT: Duration = Duration::from_millis(1000);
const MAX_EAPOL_RETRIES: u8 = 4;

/// Cap on the PMKSA (fast-reconnect PMK) cache. hostapd bounds + expires these;
/// we cap the size so the cache can't grow without bound over a long uptime with
/// many distinct clients. An evicted client simply re-runs the full SAE/auth.
const PMKSA_CACHE_MAX: usize = 256;

pub struct Station {
    pub mac: [u8; 6],
    pub associated: bool,
    pub eapol_ready: bool,
    /// Keys derived from a valid m2 and m3 sent; awaiting the STA's m4 ACK.
    /// `associated` is only set once m4's MIC verifies, so the AP (and the
    /// kernel, in netlink mode) authorizes the station only after the full 4-way.
    pub awaiting_m4: bool,
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
    /// Per-station GTK *value*, used only in `per_sta_vif` mode so each station's
    /// VLAN has its own group key (broadcast isolation). Ignored otherwise. The
    /// key *index* is BSS-wide (`Ap::gtk_key_id`) and shared by every station —
    /// only the value differs per station; that difference is what isolates them.
    pub gtk: [u8; 16],
    /// Fingerprint of the client's association characteristics, for the failure
    /// log (set at association; 0 before then).
    pub traits: u64,
    /// Whether this station negotiated WMM (its (Re)Assoc Request carried the
    /// WMM Information element); gates QoS Data frames on the downlink to it.
    pub wmm: bool,
    /// The IE block from the station's (Re)Assoc Request, so the netlink station
    /// setup can hand the driver the station's HT/VHT/HE capabilities for rate
    /// control. Empty until associated.
    pub assoc_ies: Vec<u8>,
    /// The last EAPOL m1/m3 (radiotap-prefixed) sent to this station that is
    /// still awaiting its m2/m4. Retransmitted on a timer if no reply arrives,
    /// so a single dropped handshake frame doesn't stall the 4-way forever.
    pub pending_eapol: Option<Vec<u8>>,
    /// When `pending_eapol` was last (re)transmitted, and how many times.
    pub eapol_tx: Instant,
    pub eapol_retries: u8,
    /// Awaiting this station's Group Key Handshake message 2 (its ACK of a GTK
    /// rekey). Cleared on msg 2; while any station has it set, a fresh rekey is
    /// not started (hostapd coalesces — `GKeyDoneStations`).
    pub group_rekeying: bool,
}

impl Station {
    fn new(mac: [u8; 6]) -> Station {
        Station {
            mac,
            associated: false,
            awaiting_m4: false,
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
            traits: 0,
            wmm: false,
            assoc_ies: Vec::new(),
            pending_eapol: None,
            eapol_tx: Instant::now(),
            eapol_retries: 0,
            group_rekeying: false,
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

/// A notable AP state change, surfaced to the control interface and the log —
/// mirrors hostapd's `AP-STA-*` control events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApEvent {
    /// A station completed the 4-way handshake and is authorized to pass data.
    Connected { mac: [u8; 6] },
    /// A previously-connected station was torn down (it left, was reaped for
    /// inactivity, or was kicked).
    Disconnected { mac: [u8; 6], reason: u16 },
    /// A fingerprinted failed-auth / decryption attempt — the `count` is how many
    /// times this identical (station, fingerprint, kind) tuple has been seen.
    AuthFailed { mac: [u8; 6], kind: crate::failures::FailureKind, count: u64 },
}

impl ApEvent {
    /// Render as a hostapd-style control line, e.g. `AP-STA-CONNECTED 02:..:01`.
    pub fn to_line(&self) -> String {
        use crate::util::bytes_to_mac;
        match self {
            ApEvent::Connected { mac } => format!("AP-STA-CONNECTED {}", bytes_to_mac(mac)),
            ApEvent::Disconnected { mac, reason } => {
                format!("AP-STA-DISCONNECTED {} reason={reason}", bytes_to_mac(mac))
            }
            ApEvent::AuthFailed { mac, kind, count } => {
                format!("AP-STA-AUTH-FAILED {} kind={} count={count}", bytes_to_mac(mac), kind.label())
            }
        }
    }
}

pub struct Ap {
    pub mac: [u8; 6],
    pub ssid: Vec<u8>,
    /// 2-letter regulatory country code advertised in the beacon Country IE.
    pub country: [u8; 2],
    pub channel: u8,
    /// Channel width in MHz (20/40/80/160/320); 20 unless widened.
    pub channel_width: u16,
    /// PHY generation advertised on 2.4/5 GHz: ac (VHT), ax (HE), or be (EHT).
    /// 6 GHz is always HE+. Defaults to VHT to match prior behaviour.
    phy_mode: dot11::PhyMode,
    pub pmk: [u8; 32],
    /// hostapd `wpa_psk_file` model: candidate PMKs, each optionally bound to a
    /// station MAC. `None` MAC = wildcard (00:00:00:00:00:00) onboarding entry.
    /// On the 4-way, MAC-specific entries are tried before wildcards; the one
    /// whose PTK verifies message 2's MIC is that station's password. Empty =>
    /// the single `pmk` above is used (classic single-passphrase AP).
    psk_candidates: Vec<(Option<[u8; 6]>, [u8; 32])>,
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
    /// GTK key id (CCMP key index). Toggles 1<->2 on each group rekey so a fresh
    /// GTK gets a fresh index (hostapd's two-phase group rekey); stations and the
    /// kernel are told which index the current GTK lives at.
    gtk_key_id: u8,
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
    /// WMM/WME QoS: advertise the WMM parameter element and send QoS Data frames
    /// to stations that negotiated WMM.
    wmm: bool,
    /// Operating Channel Validation (OCV): include + validate the OCI KDE.
    ocv: bool,
    /// OWE (Opportunistic Wireless Encryption): open + DH key exchange.
    owe: bool,
    sa_query_id: u16,
    /// PMKSA cache: PMKID -> (PMK, sha256) for fast reconnect (hostapd `okc`).
    pmksa_cache: HashMap<[u8; 16], ([u8; 32], bool)>,
    stations: HashMap<[u8; 6], Station>,
    /// Deduplicated log of failed auth / decryption attempts, fingerprinted by
    /// client (intrusion detection).
    failures: crate::failures::FailureLog,
    /// Queued control events (connect/disconnect/auth-fail) drained by the run
    /// loop / control interface.
    events: Vec<ApEvent>,
    /// GTK rekey period (hostapd `wpa_group_rekey`, default 600 s; 0 disables).
    group_rekey_secs: u64,
    /// Rekey the GTK when an authorized station leaves so it can no longer read
    /// group traffic (hostapd `wpa_strict_rekey`, default on).
    strict_rekey: bool,
    /// When the GTK was last rotated (drives the periodic group rekey).
    last_group_rekey: Instant,
    /// A strict rekey is queued (a station left); the next `tick` performs it.
    group_rekey_due: bool,
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

/// Increment a 6-octet BIP IPN, which is a LITTLE-endian counter in the MME
/// (octet 0 is least significant). Carries upward from octet 0, matching how
/// `dot11::bip_ipn` decodes it.
fn inc_ipn_le(ipn: &mut [u8; 6]) {
    for b in ipn.iter_mut() {
        *b = b.wrapping_add(1);
        if *b != 0 {
            break;
        }
    }
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
            channel_width: 20,
            phy_mode: dot11::PhyMode::Vht,
            pmk,
            psk_candidates: Vec::new(),
            password: psk.as_bytes().to_vec(),
            sae_enabled: false,
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
            wmm: true,
            ocv: false,
            owe: false,
            sa_query_id: 0,
            pmksa_cache: HashMap::new(),
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

    /// Configure the periodic GTK rekey interval in seconds (hostapd
    /// `wpa_group_rekey`); 0 disables periodic group rekeying.
    pub fn set_group_rekey(&mut self, secs: u64) {
        self.group_rekey_secs = secs;
    }

    /// Enable/disable rekeying the GTK when an authorized station leaves
    /// (hostapd `wpa_strict_rekey`).
    pub fn set_strict_rekey(&mut self, on: bool) {
        self.strict_rekey = on;
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

    pub fn security_mode(&self) -> dot11::SecurityMode {
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

    /// Set the operating channel width in MHz (20/40/80/160/320).
    pub fn set_width(&mut self, width: u16) {
        self.channel_width = width;
    }

    /// Set the PHY generation advertised on 2.4/5 GHz (ac/ax/be).
    pub fn set_phy(&mut self, phy: dot11::PhyMode) {
        self.phy_mode = phy;
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

    /// Install the hostapd-style `wpa_psk_file` candidates: `(mac, passphrase)`
    /// pairs (`None` mac = wildcard onboarding entry). Each passphrase is turned
    /// into a PMK against this AP's SSID. Tried MAC-specific-first on the 4-way.
    pub fn set_psk_file(&mut self, entries: &[(Option<[u8; 6]>, String)]) {
        let ssid = String::from_utf8_lossy(&self.ssid).to_string();
        self.psk_candidates = entries
            .iter()
            .map(|(m, pass)| (*m, crypto::pbkdf2_pmk(pass, &ssid)))
            .collect();
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

    /// One beacon frame for the beacon ticker. Adds a per-beacon BIP MME when
    /// Beacon Protection is enabled (userspace TX path).
    pub fn beacon_frame(&mut self) -> Vec<u8> {
        self.beacon_frame_inner(true)
    }

    /// A beacon frame WITHOUT a BIP MME, even when Beacon Protection is enabled.
    /// The netlink (kernel-beacon) path uses this for the static START_AP beacon:
    /// a single fixed-IPN MME baked into a kernel-repeated beacon would be
    /// replayable, so instead the BIGTK is installed in the kernel and mac80211
    /// generates + increments the per-beacon MME itself.
    pub fn beacon_frame_unprotected(&mut self) -> Vec<u8> {
        self.beacon_frame_inner(false)
    }

    fn beacon_frame_inner(&mut self, protect: bool) -> Vec<u8> {
        let ts = self.current_timestamp();
        let tail = dot11::security_tail(self.security_mode());
        let mut frame = if self.band6 {
            dot11::build_beacon_6ghz(&self.mac, &self.ssid, self.channel, ts, &tail, &self.country, self.channel_width, self.wmm)
        } else {
            dot11::build_beacon(&self.mac, &self.ssid, self.channel, ts, &tail, &self.country, self.channel_width, self.wmm, self.phy_mode)
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
        if self.beacon_prot && protect {
            // Protect the beacon body with a BIP Management MIC Element (BIGTK).
            // The BIGTK IPN is the same little-endian counter as the IGTK's.
            inc_ipn_le(&mut self.bigtk_ipn);
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
        let frame = dot11::build_probe_resp(&self.mac, dst, &self.ssid, self.channel, ts, sc, &dot11::security_tail(self.security_mode()), &self.country, self.channel_width, self.band6, self.wmm, self.phy_mode);
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

        // Anti-downgrade: a SAE-*only* AP must reject open-system Authentication
        // outright (status 13, unsupported auth algorithm). Without this a station
        // that never starts SAE could open-auth + associate and reach the WPA2 PSK
        // 4-way (`self.pmk`), defeating WPA3. Transition mode still accepts open
        // (it offers a PSK fallback); OWE and PSK use open-system auth and have
        // `sae_enabled == false`, so they are unaffected by this gate.
        if self.sae_enabled && !self.transition {
            let sc = self.next_sc();
            out.tx(dot11::build_auth_reject(&self.mac, &sta, sc, dot11::STATUS_UNSUPPORTED_AUTH_ALG));
            return;
        }

        // Open-system authentication (algorithm 0) -- WPA2/PSK
        let now = Instant::now();
        {
            let entry = self.stations.entry(sta).or_insert_with(|| Station::new(sta));
            // A duplicate auth within the backoff window is a retransmission (the
            // STA didn't get our response and retried). Re-answer it idempotently
            // — dropping it would stall a client over a lossy link — but do NOT
            // restart the session (that's only for a genuinely new auth).
            let retransmit = entry.last_auth.map(|t| now.duration_since(t) < BACKOFF).unwrap_or(false);
            if !retransmit {
                entry.last_auth = Some(now);
                // A (re-)Authentication restarts the station's session, as in
                // hostapd: drop any prior 4-way / association state so a
                // reconnecting client derives a fresh PTK against a fresh ANonce.
                // Without this, a station that left without a (seen) deauth keeps
                // its stale ANonce and keys, and the reconnect's 4-way fails with
                // a MIC/"wrong key".
                entry.anonce = None;
                entry.eapol_ready = false;
                entry.awaiting_m4 = false;
                entry.associated = false;
                entry.eapol_replay = 0;
                entry.kck = [0; 16];
                entry.kek = [0; 16];
                entry.tk = [0; 16];
                entry.gtk = random_bytes::<16>();
                entry.pending_eapol = None; // no stale m1/m3 to retransmit
                // Drop any psk_file PMK pinned by a previous 4-way so the
                // candidate trial (per-MAC -> wildcard -> default) re-runs — a
                // re-onboarded device may use a different password now. (SAE uses
                // algorithm-3 auth and never reaches this open-auth reset; PMKSA
                // fast-reconnect re-sets `pmk` from the cache at association.)
                entry.pmk = None;
            }
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
                self.record_failure(sta, crate::failures::FailureKind::Sae);
                return;
            }
            sae.prepare_commit(None);
            // Reject a reflected commit (peer echoing our own scalar + element).
            if sae.is_reflection() {
                self.record_failure(sta, crate::failures::FailureKind::Sae);
                return;
            }
            if sae.process_commit().is_err() {
                self.record_failure(sta, crate::failures::FailureKind::Sae);
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
            let confirm_ok = self
                .stations
                .get(sta)
                .and_then(|s| s.sae.as_ref())
                .map(|sae| sae.check_confirm(payload).is_ok());
            match confirm_ok {
                Some(true) => {}
                // Confirm present but invalid -> wrong password / forged confirm.
                Some(false) => {
                    self.record_failure(sta, crate::failures::FailureKind::Sae);
                    return;
                }
                None => return,
            }
            let confirmed = self
                .stations
                .get(sta)
                .and_then(|s| s.sae.as_ref())
                .map(|sae| (sae.pmkid.clone(), sae.pmk.clone()));
            if let Some(s) = self.stations.get_mut(sta) {
                s.sae_confirmed = true;
            }
            if let Some((pmkid, pmk)) = confirmed {
                if pmkid.len() == 16 && pmk.len() == 32 {
                    let mut id = [0u8; 16];
                    id.copy_from_slice(&pmkid);
                    let mut k = [0u8; 32];
                    k.copy_from_slice(&pmk);
                    self.cache_pmksa(id, k, true);
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

        // Fingerprint the client from its association characteristics (for the
        // failure log), and note whether it negotiated WMM (the IE block starts
        // after the fixed fields: 4 bytes for Assoc, 10 for Reassoc).
        let ap_wmm = self.wmm;
        let ie_off = if reassoc { 10 } else { 4 };
        let client_wmm = frame.body.len() > ie_off && dot11::has_wmm_ie(&frame.body[ie_off..]);
        if let Some(s) = self.stations.get_mut(&sta) {
            s.traits = crate::failures::client_traits(&frame.body);
            s.wmm = ap_wmm && client_wmm;
            // Remember the station's capability IEs (HT/VHT/HE/rates) so the
            // netlink station setup can hand them to the driver for rate control.
            s.assoc_ies = frame.body.get(ie_off..).unwrap_or(&[]).to_vec();
        }

        // A station that began SAE must have a *verified* confirm before it may
        // associate — otherwise the mutual authentication is incomplete and we'd
        // derive a PTK from an unconfirmed PMK. (The anti-downgrade check that a
        // WPA3-only AP doesn't fall back to the PSK 4-way lives in `handle_eapol`,
        // so PMKSA fast-reconnect — which skips SAE with a cached PMK — still works.)
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

        // Anti-downgrade: a WPA3-SAE-only or OWE-only AP must not associate a
        // station that has no SAE/OWE/cached PMK — otherwise it would fall back
        // to the bare PSK 4-way (`self.pmk`), defeating WPA3/OWE and exposing the
        // password to offline attack. SAE sets `pmk` at auth; OWE sets it from the
        // DH element above (so an OWE assoc that *omits* the DH Parameter element
        // leaves `pmk` unset and is rejected here, never falling back to the PSK
        // 4-way); PMKSA fast-reconnect sets it from the cache. A station that did
        // none of those is denied with status 1. Transition/WPA2 modes intentionally
        // still allow the PSK path.
        if matches!(self.security_mode(), dot11::SecurityMode::Wpa3Sae | dot11::SecurityMode::Owe)
            && self.stations.get(&sta).map(|s| s.pmk.is_none()).unwrap_or(true)
        {
            let sc = self.next_sc();
            out.tx(dot11::build_assoc_resp_reject(&self.mac, &sta, dot11::STATUS_UNSPECIFIED_FAILURE, resp_subtype, sc));
            return;
        }

        let aid = self.next_aid();
        let sc = self.next_sc();
        let mut assoc = dot11::build_assoc_resp(&self.mac, &sta, &self.ssid, self.channel, aid, sc, resp_subtype, &self.country, self.channel_width, self.band6, self.wmm, self.phy_mode);
        // Advertise a BSS Max Idle Period (~300 s) so the STA sends keep-alives.
        assoc.extend_from_slice(&dot11::bss_max_idle_element(300));
        if let Some(dh) = owe_dh_resp {
            assoc.extend_from_slice(&dh); // OWE DH Parameter element
        }

        // Prepare EAPOL message 1. Use a FRESH ANonce for every *new* 4-way:
        // reusing it across a *re*association would let an attacker replay the
        // station's earlier Message 2 (still valid under the unchanged PTK) and
        // force a PTK reinstall with a reset packet number — KRACK-style nonce
        // reuse. BUT a *duplicate* Association Request for a handshake already in
        // progress (the STA didn't get our assoc-resp/m1 and retried) must reuse
        // the same ANonce, or the STA's m2 — computed against the first m1 — no
        // longer matches. So: reuse only while still awaiting this station's m2.
        let in_progress = self
            .stations
            .get(&sta)
            .map(|s| s.eapol_ready && s.anonce.is_some())
            .unwrap_or(false);
        let anonce = if in_progress {
            self.stations.get(&sta).and_then(|s| s.anonce).unwrap()
        } else {
            self.test_anonce.unwrap_or_else(random_bytes::<32>)
        };
        {
            let entry = self.stations.get_mut(&sta).unwrap();
            entry.anonce = Some(anonce);
            entry.eapol_ready = true;
        }
        let (sha256, owe) = self.stations.get(&sta).map(|s| (s.sha256, s.owe)).unwrap_or((false, false));
        let m1_sc = self.next_sc();
        let m1 = dot11::build_eapol_m1(&self.mac, &sta, &anonce, m1_sc, dot11::KeyMic::select(sha256, owe));

        // Cache m1 (radiotap-prefixed) so it can be retransmitted if m2 is lost.
        if let Some(entry) = self.stations.get_mut(&sta) {
            entry.pending_eapol = Some(prepend_radiotap(m1.clone()));
            entry.eapol_tx = Instant::now();
            entry.eapol_retries = 0;
        }

        out.tx(assoc);
        out.tx(m1);
    }

    fn handle_eapol(&mut self, frame: &dot11::Dot11, out: &mut Outgoing) {
        let sta = frame.addr2;
        if frame.addr1 != self.mac {
            return;
        }
        let (anonce, ready, awaiting_m4, kck, sha256_m4, owe_m4, group_rekeying, eapol_replay) = match self.stations.get(&sta) {
            Some(s) => (s.anonce, s.eapol_ready, s.awaiting_m4, s.kck, s.sha256, s.owe, s.group_rekeying, s.eapol_replay),
            None => return,
        };

        let Some(eapol_frame) = frame.eapol_frame() else { return };
        let Some(key_body) = frame.eapol_key_body() else { return };
        let Some(ek) = dot11::EapolKey::parse(key_body) else { return };

        // Group Key Handshake message 2: an associated station's ACK of a GTK
        // rekey (its replay counter echoes the message 1 we sent). Verify the MIC,
        // then clear its rekey state; once every station has ACKed, the BSS is
        // fully on the new GTK (hostapd's GKeyDoneStations reaching 0).
        if group_rekeying && ek.key_replay_counter == eapol_replay {
            let mic_off = 4 + ek.mic_offset;
            if eapol_frame.len() < mic_off + 16 {
                return;
            }
            let mut to_check = eapol_frame.to_vec();
            for b in to_check[mic_off..mic_off + 16].iter_mut() {
                *b = 0;
            }
            let computed = dot11::KeyMic::select(sha256_m4, owe_m4).compute(&kck, &to_check);
            if crypto::constant_time_eq(&computed[..16], &ek.key_mic) {
                if let Some(s) = self.stations.get_mut(&sta) {
                    s.group_rekeying = false;
                    s.pending_eapol = None;
                    s.last_activity = Instant::now();
                }
            }
            return;
        }

        // Message 4 (replay counter 2): the STA's final ACK. Verify its MIC with
        // the installed KCK, then mark the station associated — only here is the
        // 4-way actually complete, so the AP (and the kernel, in netlink mode)
        // authorizes the station only after a verified m4.
        if awaiting_m4 && ek.key_replay_counter == 2 {
            let mic_off = 4 + ek.mic_offset;
            if eapol_frame.len() < mic_off + 16 {
                return;
            }
            let mut to_check = eapol_frame.to_vec();
            for b in to_check[mic_off..mic_off + 16].iter_mut() {
                *b = 0;
            }
            let computed = dot11::KeyMic::select(sha256_m4, owe_m4).compute(&kck, &to_check);
            if crypto::constant_time_eq(&computed[..16], &ek.key_mic) {
                if let Some(s) = self.stations.get_mut(&sta) {
                    s.associated = true;
                    s.awaiting_m4 = false;
                    s.pending_eapol = None; // 4-way complete, nothing to retransmit
                    self.events.push(ApEvent::Connected { mac: sta });
                }
            }
            return;
        }

        // Message 2 must be expected and echo the replay counter from message 1.
        if !ready {
            return;
        }
        let Some(anonce) = anonce else { return };
        if ek.key_replay_counter != 1 {
            return;
        }

        let snonce = ek.key_nonce;
        let amac = self.mac;
        let smac = sta;

        // Use the SAE-derived PMK + SHA-256 key descriptors when the station
        // authenticated via WPA3-SAE; otherwise the PSK (PBKDF2) PMK + SHA-1.
        // Anti-downgrade backstop: on a WPA3-SAE-only or OWE-only AP, a station
        // with no SAE/OWE-derived or cached PMK must not be silently keyed via
        // the PSK 4-way fallback.
        if matches!(self.security_mode(), dot11::SecurityMode::Wpa3Sae | dot11::SecurityMode::Owe)
            && self.stations.get(&sta).map(|s| s.pmk.is_none()).unwrap_or(true)
        {
            return;
        }
        let (sta_pmk, sha256, owe) = self
            .stations
            .get(&sta)
            .map(|s| (s.pmk, s.sha256, s.owe))
            .unwrap_or((None, false, false));

        // hostapd `wpa_psk_file` order: a PMK already fixed for this station
        // (SAE / OWE / PMKSA) is used outright; otherwise try the PSK-file entries
        // whose MAC matches this station, then the wildcard onboarding entries,
        // then the single default passphrase. The candidate whose PTK verifies
        // message 2's MIC is this station's password.
        let candidates: Vec<[u8; 32]> = if let Some(p) = sta_pmk {
            vec![p]
        } else {
            let mut v: Vec<[u8; 32]> = Vec::new();
            v.extend(self.psk_candidates.iter().filter(|(m, _)| *m == Some(sta)).map(|(_, p)| *p));
            v.extend(self.psk_candidates.iter().filter(|(m, _)| m.is_none()).map(|(_, p)| *p));
            v.push(self.pmk);
            v
        };

        let mic_off_in_eapol = 4 + ek.mic_offset; // EAPOL header (4) + body offset
        let mut kck = [0u8; 16];
        let mut kek = [0u8; 16];
        let mut tk = [0u8; 16];
        let mut matched_pmk: Option<[u8; 32]> = None;
        for pmk in &candidates {
            if sha256 {
                let ptk = crypto::derive_ptk_sha256(pmk, &amac, &smac, &anonce, &snonce);
                kck.copy_from_slice(&ptk[..16]);
                kek.copy_from_slice(&ptk[16..32]);
                tk.copy_from_slice(&ptk[32..48]);
            } else {
                let ptk = crypto::custom_prf512(pmk, &amac, &smac, &anonce, &snonce);
                kck.copy_from_slice(&ptk[..16]);
                kek.copy_from_slice(&ptk[16..32]);
                tk.copy_from_slice(&ptk[32..48]);
            }
            // Recompute the MIC over the EAPOL frame with the MIC field zeroed
            // (AES-CMAC for SAE, HMAC-SHA256 for OWE, HMAC-SHA1 for WPA2).
            let mut to_check = eapol_frame.to_vec();
            for b in to_check[mic_off_in_eapol..mic_off_in_eapol + 16].iter_mut() {
                *b = 0;
            }
            let computed = dot11::KeyMic::select(sha256, owe).compute(&kck, &to_check);
            if crypto::constant_time_eq(&computed[..16], &ek.key_mic) {
                matched_pmk = Some(*pmk);
                break;
            }
        }
        let matched_pmk = match matched_pmk {
            None => {
                // no candidate verified -> wrong password: log, deauth, drop.
                self.record_failure(&sta, crate::failures::FailureKind::FourWayMic);
                let deauth = dot11::build_deauth(&self.mac, &sta, 1);
                out.tx(deauth);
                self.disconnect(&sta, 1);
                return;
            }
            Some(p) => p,
        };
        // Pin the matched password to this station so m3 retransmits and GTK
        // rekeys reuse the same PMK.
        if let Some(s) = self.stations.get_mut(&sta) {
            s.pmk = Some(matched_pmk);
        }

        // Operating Channel Validation: message 2's OCI must match our channel.
        if self.ocv {
            match dot11::parse_oci_kde(&ek.key_data) {
                Some((oc, ch))
                    if ch == self.channel
                        && dot11::oci_class_matches_band(oc, self.channel, self.band6) => {}
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
            Some((dot11::operating_class(self.channel, self.channel_width, self.band6), self.channel))
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
        // In per-station-VIF mode each station gets its own GTK *value* (broadcast
        // isolation); otherwise all stations share the BSS-wide GTK. Either way the
        // GTK *index* is the single BSS-wide `gtk_key_id` (what the RSNE advertises
        // and every client installs under), following the rekey toggle.
        let gtk = self.station_gtk(&sta);
        let gtk_key_id = self.gtk_key_id;
        let m3 = dot11::build_eapol_m3(&self.mac, &sta, &anonce, &kck, &kek, &ap_rsn, gtk_key_id, &gtk, igtk, bigtk, oci, sc, dot11::KeyMic::select(sha256, owe));
        // Keys are derived and m3 is sent, but the station is not authorized
        // until its m4 ACK verifies (see the top of `handle_eapol`). Cache m3 so
        // it can be retransmitted if m4 is lost (m2 arrived, so the m1 cache is
        // replaced by m3).
        if let Some(s) = self.stations.get_mut(&sta) {
            s.awaiting_m4 = true;
            s.pending_eapol = Some(prepend_radiotap(m3.clone()));
            s.eapol_tx = Instant::now();
            s.eapol_retries = 0;
        }
        out.tx(m3);
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
        // Drop aggregated (A-MSDU) and fragmented frames: the AP neither
        // de-aggregates nor reassembles, and silently mis-parsing either is the
        // A-MSDU-injection / fragmentation (FragAttacks) primitive.
        if frame.is_amsdu() || frame.is_fragment() {
            return;
        }
        // Uplink unicast data must be pairwise-encrypted (key id 0). A station
        // must never send to-DS data under the group key (no per-frame group
        // replay counter exists, and it would let any STA forge group traffic).
        if frame.ccmp_key_id() != 0 {
            return;
        }
        let tk = match self.stations.get(&sta) {
            Some(s) if s.associated => s.tk,
            // Known but mid-handshake: drop the (premature) data without
            // deauthing, so a data frame that races ahead of m4 on a reordering
            // link doesn't tear down a handshake that's about to complete.
            Some(_) => return,
            // Truly unknown station: the client thinks it's associated but the AP
            // has no state for it (the AP restarted, or pruned it). Deauth (reason
            // 7: class-3 frame from a non-associated STA) so the client tears down
            // and re-handshakes instead of sending into a black hole.
            None => {
                out.tx(dot11::build_deauth(&self.mac, &sta, 7));
                return;
            }
        };

        // CCMP replay protection: the packet number must strictly increase.
        let pn = match frame.ccmp_pn() {
            Some(p) => p,
            None => return,
        };
        if let Some(s) = self.stations.get(&sta) {
            if pn <= s.last_rx_pn {
                return; // replayed / out-of-order frame
            }
        }

        match dot11::decrypt_ccmp(frame, &tk, false) {
            // sanity: source MAC in the Ethernet frame must match the station
            Some(eth) if eth.len() >= 12 && eth[6..12] == sta => {
                if let Some(s) = self.stations.get_mut(&sta) {
                    s.last_rx_pn = pn;
                }
                out.to_network.push(eth);
            }
            Some(_) => {} // decrypted, but spoofed source MAC — drop quietly
            None => self.record_failure(&sta, crate::failures::FailureKind::CcmpData),
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

        let (key_id, pn, tk, a1, qos_tid) = if is_multicast(&dst) || is_broadcast(&dst) {
            let pn = self.next_group_pn();
            // Group-addressed: encrypt at the current GTK key index (toggles
            // 1<->2 on rekey), the same index advertised in the GTK KDE and
            // installed in the kernel, so receivers select the matching key.
            (self.gtk_key_id, pn, self.gtk, dst, None)
        } else {
            match self.stations.get(&dst) {
                Some(s) if s.associated => {}
                _ => return frames,
            }
            let s = self.stations.get_mut(&dst).unwrap();
            let pn = s.next_client_pn();
            // QoS Data to a WMM station, with the user priority derived from the
            // packet's DSCP (so voice/video/etc. land in the right access category).
            let qos = if s.wmm { Some(dot11::wmm_tid(eth)) } else { None };
            (0u8, pn, s.tk, dst, qos)
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
            qos_tid,
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
            let reason = frame.body.get(..2).map(|b| u16::from_le_bytes([b[0], b[1]])).unwrap_or(0);
            self.disconnect(&sta, reason);
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
                    self.disconnect(&sta, 0);
                } else {
                    self.record_failure(&sta, crate::failures::FailureKind::ProtectedMgmt);
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
                out.tx(dot11::build_protected_sa_query(&self.mac, &sta, false, true, trans, sc, pn, &tk));
            }
        }
    }

    /// Whether a station has completed the handshake.
    pub fn is_associated(&self, sta: &[u8; 6]) -> bool {
        self.stations.get(sta).map(|s| s.associated).unwrap_or(false)
    }

    /// Periodic maintenance for handshake reliability: retransmit any pending
    /// EAPOL m1/m3 whose m2/m4 hasn't arrived within [`EAPOL_TIMEOUT`], and
    /// deauthenticate (and drop) a station whose 4-way still hasn't completed
    /// after [`MAX_EAPOL_RETRIES`]. The transport calls this on its tick so a
    /// single dropped handshake frame self-heals instead of stalling forever.
    pub fn tick(&mut self) -> Outgoing {
        let mut out = Outgoing::default();
        let now = Instant::now();

        // Key lifecycle: a queued strict rekey (a station left) or the periodic
        // `wpa_group_rekey` interval triggers a Group Key Handshake. rekey_gtk()
        // coalesces if one is already in flight, and arms each msg 1 for
        // retransmit through the loop below.
        let periodic = self.group_rekey_secs > 0
            && now.duration_since(self.last_group_rekey) >= Duration::from_secs(self.group_rekey_secs)
            && self.stations.values().any(|s| s.associated);
        if self.group_rekey_due || periodic {
            self.group_rekey_due = false;
            out.frames.extend(self.rekey_gtk());
        }

        let mut timed_out: Vec<[u8; 6]> = Vec::new();
        for (mac, s) in self.stations.iter_mut() {
            let Some(frame) = s.pending_eapol.as_ref() else { continue };
            if now.duration_since(s.eapol_tx) < EAPOL_TIMEOUT {
                continue;
            }
            if s.eapol_retries >= MAX_EAPOL_RETRIES {
                timed_out.push(*mac);
            } else {
                out.frames.push(frame.clone()); // already radiotap-prefixed
                s.eapol_tx = now;
                s.eapol_retries += 1;
            }
        }
        for mac in timed_out {
            self.disconnect(&mac, 15);
            let deauth = dot11::build_deauth(&self.mac, &mac, 15); // 4-way timeout
            out.tx(deauth);
        }
        out
    }

    /// Test hook: age the group-rekey clock past `wpa_group_rekey` so the next
    /// [`Ap::tick`] performs a periodic Group Key Handshake. Set a small
    /// `wpa_group_rekey` first so the back-dated instant stays valid.
    #[doc(hidden)]
    pub fn test_expire_group_rekey(&mut self) {
        let ago = Duration::from_secs(self.group_rekey_secs.saturating_add(1));
        self.last_group_rekey = Instant::now().checked_sub(ago).unwrap_or(self.last_group_rekey);
    }

    /// Test hook: clear the per-station auth/assoc backoff so an immediate
    /// re-authentication is treated as a genuine new session (not a retransmit),
    /// as a real reconnect seconds/minutes later would be.
    #[doc(hidden)]
    pub fn test_clear_auth_backoff(&mut self) {
        for s in self.stations.values_mut() {
            s.last_auth = None;
            s.last_assoc = None;
        }
    }

    /// Test hook: age every pending EAPOL frame past the retransmit timeout so a
    /// subsequent [`Ap::tick`] retransmits (or times out) deterministically.
    #[doc(hidden)]
    pub fn test_expire_eapol(&mut self) {
        let past = Instant::now() - EAPOL_TIMEOUT - Duration::from_millis(1);
        for s in self.stations.values_mut() {
            if s.pending_eapol.is_some() {
                s.eapol_tx = past;
            }
        }
    }

    /// Log a failed authentication / decryption attempt, fingerprinted by the
    /// client (its MAC plus the traits hash captured at association).
    /// Insert a PMK into the PMKSA cache, evicting one entry when at capacity so
    /// the cache stays bounded ([`PMKSA_CACHE_MAX`]) instead of growing forever.
    fn cache_pmksa(&mut self, id: [u8; 16], pmk: [u8; 32], sha256: bool) {
        if self.pmksa_cache.len() >= PMKSA_CACHE_MAX && !self.pmksa_cache.contains_key(&id) {
            if let Some(victim) = self.pmksa_cache.keys().next().copied() {
                self.pmksa_cache.remove(&victim);
            }
        }
        self.pmksa_cache.insert(id, (pmk, sha256));
    }

    /// Test hook: insert a dummy PMKSA entry (exercises the cache bound).
    #[doc(hidden)]
    pub fn test_cache_pmksa(&mut self, id: [u8; 16]) {
        self.cache_pmksa(id, [0u8; 32], true);
    }

    /// Number of cached PMKSA entries (for tests).
    #[doc(hidden)]
    pub fn pmksa_len(&self) -> usize {
        self.pmksa_cache.len()
    }

    fn record_failure(&mut self, sta: &[u8; 6], kind: crate::failures::FailureKind) {
        let traits = self.stations.get(sta).map(|s| s.traits).unwrap_or(0);
        let count = self.failures.record(*sta, traits, kind);
        self.events.push(ApEvent::AuthFailed { mac: *sta, kind, count });
        eprintln!(
            "AP: {} failure from {} (attempt #{count}, traits {:#018x})",
            kind.label(),
            crate::util::bytes_to_mac(sta),
            traits
        );
    }

    /// Remove a station, emitting a `Disconnected` event if it had completed the
    /// 4-way — so connect/disconnect events pair up like hostapd's. A station
    /// torn down mid-handshake never connected, so it produces no event.
    fn disconnect(&mut self, sta: &[u8; 6], reason: u16) {
        if let Some(s) = self.stations.remove(sta) {
            if s.associated {
                self.events.push(ApEvent::Disconnected { mac: *sta, reason });
                // hostapd `wpa_strict_rekey`: an authorized station that held the
                // GTK is leaving — rotate the GTK so it can't read future group
                // traffic. Only worthwhile if other stations remain to receive
                // the new key; the next tick performs the rekey.
                if self.strict_rekey && self.stations.values().any(|o| o.associated) {
                    self.group_rekey_due = true;
                }
            }
        }
    }

    /// Drain the control events (connect/disconnect/auth-fail) queued since the
    /// last call — consumed by the control interface and event logging.
    pub fn drain_events(&mut self) -> Vec<ApEvent> {
        std::mem::take(&mut self.events)
    }

    /// The MAC addresses of every known station (for the control interface).
    pub fn station_macs(&self) -> Vec<[u8; 6]> {
        self.stations.keys().copied().collect()
    }

    /// The capability IE block from a station's (Re)Assoc Request (HT/VHT/HE/
    /// rates), for handing to the kernel on association so rate control works.
    pub fn station_assoc_ies(&self, sta: &[u8; 6]) -> Option<&[u8]> {
        self.stations.get(sta).map(|s| s.assoc_ies.as_slice())
    }

    /// Administratively deauthenticate a station: tears it down (emitting a
    /// `Disconnected` event) and returns the radiotap-prefixed deauth to send,
    /// or `None` if the station is unknown. PMF stations get a protected deauth.
    pub fn kick(&mut self, mac: &[u8; 6]) -> Option<Vec<u8>> {
        if !self.stations.contains_key(mac) {
            return None;
        }
        let frame = self
            .protected_deauth(mac, 3)
            .unwrap_or_else(|| prepend_radiotap(dot11::build_deauth(&self.mac, mac, 3)));
        self.disconnect(mac, 3);
        Some(frame)
    }

    /// The deduplicated, fingerprinted log of failed auth / decryption attempts.
    pub fn failures(&self) -> &crate::failures::FailureLog {
        &self.failures
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
        matches!(self.security_mode(), dot11::SecurityMode::Wpa3Sae | dot11::SecurityMode::Owe | dot11::SecurityMode::Transition)
    }

    /// Rotate the GTK (and IGTK) and run the Group Key Handshake: send Group Key
    /// message 1 to every associated station. Returns the frames to transmit.
    /// Mirrors hostapd's `wpa_group_rekey`. Each message 1 is armed for retransmit
    /// (`pending_eapol`) and the station is marked `group_rekeying` until it ACKs
    /// with message 2, so a dropped rekey frame doesn't strand a station on the
    /// old GTK. If a rekey is already in flight (any station still awaiting its
    /// message 2) this is a no-op, matching hostapd's coalescing.
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
        let gtk_full = random_bytes::<32>();
        self.gtk.copy_from_slice(&gtk_full[..16]);
        self.group_pn = 1;
        // Two-phase group rekey (hostapd): the rotated GTK/IGTK go in at the
        // OTHER key index (toggle 1<->2 for the GTK, 4<->5 for the IGTK), so the
        // new key is advertised + installed at a fresh index and the IPN may be
        // reset (a fresh key id gets a fresh IPN).
        self.gtk_key_id = if self.gtk_key_id == 1 { 2 } else { 1 };
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
            let (kck, kek, sha256, owe, replay) = {
                let s = self.stations.get_mut(&sta).unwrap();
                s.eapol_replay += 1;
                (s.kck, s.kek, s.sha256, s.owe, s.eapol_replay)
            };
            let igtk_kde = if sha256 { Some((igtk_key_id, igtk_ipn, igtk)) } else { None };
            let sc = self.next_sc();
            let frame = dot11::build_group_key_msg1(&self.mac, &sta, &kck, &kek, gtk_key_id, &gtk, igtk_kde, replay, sc, dot11::KeyMic::select(sha256, owe));
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
    fn rekey_gtk_per_sta(&mut self) -> Vec<Vec<u8>> {
        // The per-station GTK index is a fixed constant (1): each station's own
        // GTK *value* (its own key, isolated in its own AP_VLAN) is what separates
        // them, so the index never moves and is not a shared, toggling counter —
        // only the value rotates per station (below), overwriting the old one at
        // the same index 1. The BSS-wide IGTK (management-frame BIP, genuinely one
        // key per radio) still rotates with its own 4<->5 index toggle.
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
            let (kck, kek, sha256, owe, replay, gtk) = {
                let s = self.stations.get_mut(&sta).unwrap();
                // Rotate this station's own GTK *value*; it goes in at the shared
                // (already-toggled) BSS-wide index.
                let gtk_full = random_bytes::<32>();
                s.gtk.copy_from_slice(&gtk_full[..16]);
                s.eapol_replay += 1;
                (s.kck, s.kek, s.sha256, s.owe, s.eapol_replay, s.gtk)
            };
            let igtk_kde = if sha256 { Some((igtk_key_id, igtk_ipn, igtk)) } else { None };
            let sc = self.next_sc();
            let frame = dot11::build_group_key_msg1(&self.mac, &sta, &kck, &kek, gtk_key_id, &gtk, igtk_kde, replay, sc, dot11::KeyMic::select(sha256, owe));
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
        let frame = dot11::build_group_deauth_bip(&self.mac, &self.igtk, self.igtk_key_id, &self.igtk_ipn, reason, sc);
        let mut f = dot11::RADIOTAP_TX.to_vec();
        f.extend_from_slice(&frame);
        f
    }
}
