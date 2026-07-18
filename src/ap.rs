//! The access-point state machine, ported from `ap.py`'s `AP`/`BSS`/`Station`.
//!
//! Unlike the threaded Python original, this is a single-threaded state machine:
//! incoming 802.11 frames are fed to [`Ap::handle_incoming`], which mutates
//! state and returns the frames to transmit plus any decrypted Ethernet packets
//! destined for the AP's network stack. The driver wires those to real I/O.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

use crate::crypto;
use crate::dot11;

/// Per-station auth/assoc backoff (matches `BACKOFF = 0.25`).
const BACKOFF: Duration = Duration::from_millis(250);

/// Retransmit a pending EAPOL m1/m3 if its m2/m4 hasn't arrived within this long
/// (hostapd's `eapol_key_timeout_subseq`), up to [`MAX_EAPOL_RETRIES`] times
/// before giving up and deauthenticating.
const EAPOL_TIMEOUT: Duration = Duration::from_millis(1000);
/// The *first* retransmit fires much sooner, mirroring hostapd's
/// `eapol_key_timeout_first = 100 ms`. This matters on real hardware: an m1 sent
/// the instant the STA associates can be dropped before the driver has the
/// station fully set up for downlink control-port TX. Waiting a full second to
/// resend lets the client's own post-association 4-way timer fire first — it then
/// deauthenticates and reconnects, and because each reconnect mints a fresh
/// ANonce, the client's Message 2 ends up keyed to a stale m1's ANonce and the
/// MIC never verifies (a self-sustaining livelock seen on ath12k). Resending
/// within ~100 ms lands a second m1 (identical ANonce) inside the *same*
/// association, exactly as hostapd does, so the handshake completes.
const EAPOL_FIRST_TIMEOUT: Duration = Duration::from_millis(100);
/// Match the normal authenticator retry budget. In particular, do not use a
/// large retry count to compensate for a slow hardware TX-status event: every
/// retry is another real frame queued in the driver, and flooding that queue can
/// put message 3 behind dozens of stale message-1 copies.
/// hostapd's default dot11RSNAConfigPairwiseUpdateCount is four total sends:
/// the initial message plus three retransmissions.
const MAX_EAPOL_RETRIES: u8 = 3;

/// How long an unconsumed message-1 ANonce/replay pair is held for a reconnecting
/// station. The pair is destroyed as soon as message 2 verifies, before either
/// peer can install the PTK.
const ANONCE_HOLD: Duration = Duration::from_secs(10);

/// Cap on the PMKSA (fast-reconnect PMK) cache. hostapd bounds + expires these;
/// we cap the size so the cache can't grow without bound over a long uptime with
/// many distinct clients. An evicted client simply re-runs the full SAE/auth.
const PMKSA_CACHE_MAX: usize = 256;
/// IEEE 802.11's default PMKSA lifetime (12 hours).
const PMKSA_LIFETIME: Duration = Duration::from_secs(12 * 60 * 60);
/// Require an SAE anti-clogging token once this many exchanges are incomplete.
const SAE_ANTI_CLOGGING_THRESHOLD: usize = 5;
/// Absolute cap even for peers that returned a valid anti-clogging token.
const SAE_INCOMPLETE_MAX: usize = 64;
/// Incomplete SAE state is short-lived and must not accumulate indefinitely.
const SAE_AUTH_TIMEOUT: Duration = Duration::from_secs(5);
/// Stateless anti-clogging tokens are intentionally short-lived so an attacker
/// cannot harvest them ahead of time and bypass overload protection later.
const SAE_TOKEN_LIFETIME: Duration = Duration::from_secs(10);

struct PmksaEntry {
    identity: [u8; 6],
    pmk: [u8; 32],
    sha256: bool,
    expires_at: Instant,
}

impl Drop for PmksaEntry {
    fn drop(&mut self) {
        self.pmk.zeroize();
    }
}

#[derive(Clone, Copy)]
struct PendingHandshake {
    anonce: [u8; 32],
    replay_counter: u64,
    created_at: Instant,
}

#[derive(Clone)]
struct PtkCandidate {
    m3_replay_counter: u64,
    kck: [u8; 16],
    kek: [u8; 16],
    tk: [u8; 16],
}

impl Drop for PtkCandidate {
    fn drop(&mut self) {
        self.kck.zeroize();
        self.kek.zeroize();
        self.tk.zeroize();
    }
}

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
    /// Replay counter from the message 1 this 4-way is answering. It remains
    /// valid while awaiting M4 so hostapd-compatible changed-SNonce M2 retries
    /// can be evaluated without regressing to a new handshake.
    m1_replay: u64,
    /// PTKs derived from valid M2 retries in this one 4-way. They are not exposed
    /// to the driver until one candidate's M4 verifies.
    ptk_candidates: Vec<PtkCandidate>,
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
    /// Beacon periods the station may sleep between wakeups, copied from the
    /// fixed fields of its latest (Re)Association Request.
    pub listen_interval: u16,
    /// Capability Information from the station's (Re)Association Request.
    pub capability: u16,
    /// The last EAPOL m1/m3 (radiotap-prefixed) sent to this station that is
    /// still awaiting its m2/m4. Retransmitted on a timer if no reply arrives,
    /// so a single dropped handshake frame doesn't stall the 4-way forever.
    pub pending_eapol: Option<Vec<u8>>,
    /// When `pending_eapol` was last (re)transmitted, and how many times.
    pub eapol_tx: Instant,
    pub eapol_retries: u8,
    /// Whether the kernel reported an 802.11 ACK for the initial message 1 TX
    /// (via `CONTROL_PORT_FRAME_TX_STATUS`). hostapd extends that message's short
    /// initial timeout after an ACK; message 3 keeps the short first timeout.
    pub eapol_acked: bool,
    /// Awaiting this station's Group Key Handshake message 2 (its ACK of a GTK
    /// rekey). Cleared on msg 2; while any station has it set, a fresh rekey is
    /// not started (hostapd coalesces — `GKeyDoneStations`).
    pub group_rekeying: bool,
    /// The station's MLD MAC address, when it associated as an 802.11be MLD (its
    /// (Re)Assoc Request carried a Basic Multi-Link element). `None` for a
    /// non-MLD (single-link) station. When set, the 4-way PTK is derived from the
    /// MLD MAC addresses rather than the per-link addresses.
    pub client_mld_mac: Option<[u8; 6]>,
    /// Additional link addresses advertised by a non-AP MLD station in its
    /// association request, keyed by Link ID. The association-link address is
    /// still `mac`.
    pub client_mld_links: Vec<(u8, [u8; 6])>,
    /// Cached SAE commit+confirm auth-response frames, resent verbatim when the
    /// STA retries an identical commit (a lost response on a flaky medium), so
    /// the exchange recovers instead of resetting our scalar and desyncing into
    /// an authentication loop.
    pub sae_resp: Vec<Vec<u8>>,
    /// The peer SAE commit payload we last answered — recognizes an identical
    /// retry vs. a genuinely fresh commit.
    pub sae_commit: Vec<u8>,
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
            client_mld_mac: None,
            client_mld_links: Vec::new(),
            sae_resp: Vec::new(),
            sae_commit: Vec::new(),
            client_pn: 1, // CCMP PN starts at 1
            last_rx_pn: 0,
            last_rx_mgmt_pn: 0,
            eapol_replay: 0,
            m1_replay: 0,
            ptk_candidates: Vec::new(),
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
            listen_interval: 0,
            capability: 0,
            pending_eapol: None,
            eapol_tx: Instant::now(),
            eapol_retries: 0,
            eapol_acked: false,
            group_rekeying: false,
        }
    }

    fn next_client_pn(&mut self) -> u64 {
        let pn = self.client_pn;
        self.client_pn += 1;
        pn
    }

    fn set_pmk(&mut self, pmk: Option<[u8; 32]>) {
        if let Some(old) = self.pmk.as_mut() {
            old.zeroize();
        }
        self.pmk = pmk;
    }
}

impl Drop for Station {
    fn drop(&mut self) {
        self.kck.zeroize();
        self.kek.zeroize();
        self.tk.zeroize();
        self.gtk.zeroize();
        if let Some(pmk) = self.pmk.as_mut() {
            pmk.zeroize();
        }
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
    AuthFailed {
        mac: [u8; 6],
        kind: crate::failures::FailureKind,
        count: u64,
    },
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
            // SPR's hostapd action scripts consume TYPE and REASON as the two
            // arguments following the MAC. Keep those tokens whitespace-free;
            // the count remains an optional trailing diagnostic field.
            ApEvent::AuthFailed {
                mac,
                kind: crate::failures::FailureKind::FourWayMic,
                count,
            } => format!(
                "AP-STA-POSSIBLE-PSK-MISMATCH {} wpa mismatch count={count}",
                bytes_to_mac(mac)
            ),
            ApEvent::AuthFailed {
                mac,
                kind: crate::failures::FailureKind::Sae,
                count,
            } => format!(
                "AP-STA-POSSIBLE-PSK-MISMATCH {} sae mismatch count={count}",
                bytes_to_mac(mac)
            ),
            ApEvent::AuthFailed { mac, kind, count } => format!(
                "AP-STA-AUTH-FAILED {} kind={} count={count}",
                bytes_to_mac(mac),
                kind.label()
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MldLink {
    pub link_id: u8,
    pub mac: [u8; 6],
    pub channel: u8,
    pub width: u16,
    pub band6: bool,
}

pub struct Ap {
    pub mac: [u8; 6],
    pub ssid: Vec<u8>,
    /// 2-letter regulatory country code advertised in the beacon Country IE.
    pub country: [u8; 2],
    pub channel: u8,
    /// Channel width in MHz (20/40/80/160/320); 20 unless widened.
    pub channel_width: u16,
    /// 802.11be preamble-puncturing bitmap: one bit per 20 MHz subchannel of the
    /// operating width, 1 = punctured/disabled. 0 = no puncturing. Advertised in
    /// the EHT Operation element's Disabled Subchannel Bitmap.
    pub punct: u16,
    /// 802.11be AP MLD: when set, the BSS is an affiliated AP of an MLD — it
    /// advertises a Basic Multi-Link element (MLD MAC + Link ID) and runs the
    /// association + 4-way at the MLD level (PTK from MLD MACs). Off by default;
    /// advertising the ML element without the MLD assoc/4-way path would break
    /// MLD-capable clients, so the whole path is gated on this one flag.
    pub mld: bool,
    /// This MLD's MAC address (shared across its affiliated links); distinct from
    /// the per-link BSSID (`mac`).
    pub mld_mac: [u8; 6],
    /// This affiliated link's Link ID (0-15).
    pub link_id: u8,
    /// BSS Parameters Change Count advertised in the Basic ML element.
    pub bss_change_count: u8,
    /// Affiliated links for a netlink AP MLD. Empty means "single configured
    /// link" and is resolved from `mac`/`channel`/`link_id`.
    pub mld_links: Vec<MldLink>,
    /// Advertised TID-to-link mapping shared by all eight TIDs. Each set bit is
    /// an MLD Link ID allowed for both uplink and downlink; `None` leaves link
    /// selection to the peer and driver.
    mld_default_link_mask: Option<u16>,
    /// AP-mode EML and MLD capabilities exposed by nl80211 for this driver.
    /// Netlink mode fills these before constructing beacon/response MLEs.
    mld_eml_capability: u16,
    mld_driver_capability: Option<u16>,
    /// Real, band-specific radio capabilities for each affiliated link.
    /// Partner-link profiles must use these just like the outer response does.
    mld_link_phy_capabilities: HashMap<u8, dot11::PhyCapabilities>,
    /// PHY generation advertised on 2.4/5 GHz: ac (VHT), ax (HE), or be (EHT).
    /// 6 GHz is always HE+. Defaults to VHT to match prior behaviour.
    phy_mode: dot11::PhyMode,
    pub pmk: [u8; 32],
    /// hostapd credential-file model: candidate PMKs, each optionally bound to a
    /// station MAC. `None` MAC = wildcard onboarding entry.
    /// On the 4-way, MAC-specific entries are tried before wildcards; the one
    /// whose PTK verifies message 2's MIC is that station's password.
    psk_candidates: Vec<(Option<[u8; 6]>, [u8; 32])>,
    /// The passphrases behind `psk_candidates`, retained so the same SPR
    /// per-device credential file can select an SAE password by station MAC.
    /// SAE has to choose its password before replying to the peer's commit, so
    /// unlike WPA2 it cannot discover the matching credential from message 2's
    /// MIC later in the exchange.
    credential_passwords: Vec<(Option<[u8; 6]>, Vec<u8>)>,
    /// A configured credential file is the complete access-control database.
    /// Never fall back to the JSON/CLI passphrase when it is true, including
    /// when the file is empty or unreadable (fail closed).
    credential_file_authoritative: bool,
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
    /// PMKSA cache keyed by PMKID and the authenticated station identity. For an
    /// MLD this identity is the stable MLD MAC; otherwise it is the link MAC.
    pmksa_cache: HashMap<([u8; 16], [u8; 6]), PmksaEntry>,
    /// ANonce held for a station whose *initial* 4-way has not yet completed,
    /// keyed by MAC so it survives the STA being torn down and rebuilt. A real
    /// client that can't finish the first handshake (e.g. our m1 was dropped)
    /// deauthenticates and reconnects — often via a PMKSA fast-reconnect — but
    /// keeps answering the m1 it *did* receive. Minting a fresh ANonce on each
    /// reconnect leaves us one ANonce ahead of the client forever (its Message 2
    /// keys to a stale ANonce and the MIC never verifies): a livelock seen on
    /// ath12k. Reusing the same ANonce and replay counter until message 2 verifies
    /// keeps both sides in lock-step. The entry is consumed before message 3 is
    /// sent (and therefore before a PTK can be installed), and expires after
    /// `ANONCE_HOLD`.
    pending_anonce: HashMap<[u8; 6], PendingHandshake>,
    /// Process-wide monotonically increasing EAPOL replay counter. It starts at
    /// a random non-zero value so frames from an earlier AP lifetime cannot be
    /// valid in a new lifetime.
    eapol_replay_counter: u64,
    /// Secret for stateless SAE anti-clogging tokens.
    sae_token_key: [u8; 32],
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

fn random_nonzero_u64() -> u64 {
    loop {
        let value = u64::from_be_bytes(random_bytes());
        if value != 0 && value != u64::MAX {
            return value;
        }
    }
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

fn expected_key_descriptor_version(sha256: bool, owe: bool) -> u16 {
    if sha256 || owe {
        0
    } else {
        2
    }
}

fn key_info_matches(key_info: u16, expected: u16) -> bool {
    // hostapd accepts the two reserved upper bits and encrypted M2/M4 Key Data.
    // Compare every state-bearing bit while deliberately ignoring only those.
    key_info & !(0xc000 | 0x1000) == expected
}

fn message_2_security_matches(assoc_ies: &[u8], key_data: &[u8]) -> bool {
    let Ok(Some(assoc_rsn)) = dot11::find_ie_strict(assoc_ies, 48) else {
        return false;
    };
    let Ok(Some(m2_rsn)) = dot11::find_ie_strict(key_data, 48) else {
        return false;
    };
    if !dot11::rsn_negotiation_matches(assoc_rsn, m2_rsn) {
        return false;
    }
    let Ok(assoc_rsnxe) = dot11::find_ie_strict(assoc_ies, 0xf4) else {
        return false;
    };
    let Ok(m2_rsnxe) = dot11::find_ie_strict(key_data, 0xf4) else {
        return false;
    };
    assoc_rsnxe == m2_rsnxe
}

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
            pmk: [0u8; 32],
            psk_candidates: Vec::new(),
            credential_passwords: Vec::new(),
            credential_file_authoritative: false,
            password: Vec::new(),
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
            pending_anonce: HashMap::new(),
            eapol_replay_counter: random_nonzero_u64(),
            sae_token_key: random_bytes(),
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
        // Golden frame vectors use replay counters 1 and 2.
        self.eapol_replay_counter = 0;
    }

    fn next_sc(&mut self) -> u16 {
        self.sc = (self.sc + 1).rem_euclid(4096);
        (self.sc * 16) as u16
    }

    fn next_aid(&mut self) -> u16 {
        self.aid = (self.aid + 1) % 2008;
        self.aid
    }

    fn next_eapol_replay(&mut self) -> u64 {
        self.eapol_replay_counter = self.eapol_replay_counter.wrapping_add(1);
        if self.eapol_replay_counter == 0 {
            self.eapol_replay_counter = 1;
        }
        self.eapol_replay_counter
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

    pub fn set_mld_links(&mut self, links: Vec<MldLink>) {
        self.mld_links = links;
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

    fn mld_link_info_for(&self, link_id: u8) -> Vec<u8> {
        let mut info = Vec::new();
        if !self.mld {
            return info;
        }
        for link in self.active_mld_links() {
            if link.link_id == link_id {
                continue;
            }
            let mut inner = dot11::ap_mld_profile_inner(
                &self.ssid,
                link.channel,
                &self.country,
                link.width,
                link.band6,
                self.wmm,
                self.phy_mode,
                self.security_mode(),
                self.punct,
            );
            if let Some(caps) = self.mld_link_phy_capabilities.get(&link.link_id) {
                // Capability Information occupies the first two bytes.
                dot11::apply_phy_capabilities(&mut inner, 2, caps);
            }
            info.extend_from_slice(&dot11::per_sta_profile(link.link_id, &link.mac, &inner));
        }
        info
    }

    /// Build the Link Info field for an MLO (Re)Association Response. Only
    /// partner links requested by this station are included, and each profile
    /// uses the association-response fixed fields (Capability + Status Code)
    /// rather than the beacon/probe-response shape.
    fn mld_assoc_link_info_for(&self, requested: &[(u8, [u8; 6])]) -> Vec<u8> {
        let mut info = Vec::new();
        if !self.mld {
            return info;
        }
        for link in self.active_mld_links() {
            if !requested
                .iter()
                .any(|(requested_link_id, _)| *requested_link_id == link.link_id)
            {
                continue;
            }
            let mut inner = dot11::ap_mld_assoc_profile_inner(
                &self.ssid,
                link.channel,
                &self.country,
                link.width,
                link.band6,
                self.wmm,
                self.phy_mode,
                self.punct,
            );
            if let Some(caps) = self.mld_link_phy_capabilities.get(&link.link_id) {
                // Capability Information + Status Code occupy the first four
                // bytes of an association-response Per-STA Profile.
                dot11::apply_phy_capabilities(&mut inner, 4, caps);
            }
            info.extend_from_slice(&dot11::per_sta_profile(link.link_id, &link.mac, &inner));
        }
        info
    }

    fn mld_max_simultaneous_links_minus_one(&self) -> u8 {
        self.active_mld_links().len().saturating_sub(1).min(0x0f) as u8
    }

    /// Apply the AP-mode MLD capabilities reported by the kernel. This mirrors
    /// hostapd: AP transition/padding delays are zeroed, the active-link count
    /// replaces the hardware maximum, unsupported TID-to-link negotiation is
    /// cleared, and link reconfiguration support is advertised.
    pub fn set_mld_driver_capabilities(&mut self, eml: u16, mld: u16) {
        const EMLSR_DELAY_MASKS: u16 = 0x000e | 0x0070;
        self.mld_eml_capability = eml & !EMLSR_DELAY_MASKS;
        self.mld_driver_capability = Some(mld);
    }

    /// Set the driver's capability payloads for one affiliated link.
    pub fn set_mld_link_phy_capabilities(
        &mut self,
        link_id: u8,
        capabilities: dot11::PhyCapabilities,
    ) {
        self.mld_link_phy_capabilities.insert(link_id, capabilities);
    }

    fn advertised_mld_capability(&self) -> u16 {
        const MAX_SIMULTANEOUS_LINKS_MASK: u16 = 0x000f;
        const TID_TO_LINK_NEGOTIATION_MASK: u16 = 0x0060;
        const LINK_RECONFIGURATION_SUPPORT: u16 = 0x2000;
        let active = u16::from(self.mld_max_simultaneous_links_minus_one());
        match self.mld_driver_capability {
            Some(driver) => {
                let maximum = driver & MAX_SIMULTANEOUS_LINKS_MASK;
                (driver & !(MAX_SIMULTANEOUS_LINKS_MASK | TID_TO_LINK_NEGOTIATION_MASK))
                    | active.min(maximum)
                    | LINK_RECONFIGURATION_SUPPORT
            }
            None => active,
        }
    }

    fn mld_basic_element(&self, link_id: u8, link_info: &[u8]) -> Vec<u8> {
        dot11::multi_link_ap_basic_capabilities(
            &self.mld_mac,
            link_id,
            self.bss_change_count,
            self.mld_eml_capability,
            self.advertised_mld_capability(),
            link_info,
        )
    }

    fn mld_tid_to_link_element(&self) -> Vec<u8> {
        self.mld_default_link_mask
            .map(dot11::tid_to_link_mapping_same_set)
            .unwrap_or_default()
    }

    fn mld_link_disabled(&self, link_id: u8) -> bool {
        self.mld_default_link_mask
            .is_some_and(|mask| mask & (1u16 << link_id) == 0)
    }

    /// Advertise every other affiliated link using the MLD form of the Reduced
    /// Neighbor Report. hostapd emits this independently of its generic `rnr`
    /// option: it is how a client on (for example) the 5 GHz association link
    /// learns the real 6 GHz BSSID, channel, width-derived operating class and
    /// Link ID before it can include that partner in its association MLE.
    fn mld_rnr_for(&self, reporting_link_id: u8) -> Vec<u8> {
        if !self.mld {
            return Vec::new();
        }
        let mut reports = Vec::new();
        for link in self.active_mld_links() {
            if link.link_id == reporting_link_id {
                continue;
            }
            reports.extend_from_slice(&dot11::mld_reduced_neighbor_report_with_disabled(
                &link.mac,
                &self.ssid,
                dot11::operating_class(link.channel, link.width, link.band6),
                link.channel,
                0,
                link.link_id,
                self.bss_change_count,
                self.mld_link_disabled(link.link_id),
            ));
        }
        reports
    }

    fn is_valid_peer_mac(mac: &[u8; 6]) -> bool {
        mac.iter().any(|b| *b != 0) && (mac[0] & 0x01 == 0)
    }

    fn reject_assoc(&mut self, sta: &[u8; 6], reassoc: bool, out: &mut Outgoing) {
        self.reject_assoc_status(sta, reassoc, dot11::STATUS_UNSPECIFIED_FAILURE, out);
    }

    fn reject_assoc_status(
        &mut self,
        sta: &[u8; 6],
        reassoc: bool,
        status: u16,
        out: &mut Outgoing,
    ) {
        let sub = if reassoc {
            0x03
        } else {
            dot11::SUBTYPE_ASSOC_RESP
        };
        let sc = self.next_sc();
        out.tx(dot11::build_assoc_resp_reject(
            &self.mac, sta, status, sub, sc,
        ));
    }

    fn peer_mac_in_use_by_other_station(&self, sta: &[u8; 6], mac: &[u8; 6]) -> bool {
        self.stations.iter().any(|(other, s)| {
            other != sta
                && (*other == *mac
                    || s.client_mld_mac.as_ref() == Some(mac)
                    || s.client_mld_links
                        .iter()
                        .any(|(_, link_mac)| link_mac == mac))
        })
    }

    fn validate_mld_assoc_links(
        &self,
        sta: &[u8; 6],
        client_mld: &[u8; 6],
        assoc_ies: &[u8],
    ) -> Option<Vec<(u8, [u8; 6])>> {
        let active_links = self.active_mld_links();
        let configured: HashSet<u8> = active_links.iter().map(|l| l.link_id).collect();
        let mut ap_addrs: HashSet<[u8; 6]> = active_links.iter().map(|l| l.mac).collect();
        ap_addrs.insert(self.mld_mac);

        if !Self::is_valid_peer_mac(sta)
            || !Self::is_valid_peer_mac(client_mld)
            || ap_addrs.contains(sta)
            || ap_addrs.contains(client_mld)
            || self.peer_mac_in_use_by_other_station(sta, client_mld)
        {
            return None;
        }

        let mut seen_link_ids = HashSet::new();
        let mut seen_macs = HashSet::new();
        let mut peer_addrs = HashSet::new();
        peer_addrs.insert(*sta);
        peer_addrs.insert(*client_mld);

        let mut links = Vec::new();
        for (link_id, link_mac) in dot11::parse_mld_link_macs_checked(assoc_ies)? {
            if !configured.contains(&link_id)
                || link_id == self.link_id
                || !Self::is_valid_peer_mac(&link_mac)
                || ap_addrs.contains(&link_mac)
                || peer_addrs.contains(&link_mac)
                || !seen_link_ids.insert(link_id)
                || !seen_macs.insert(link_mac)
                || self.peer_mac_in_use_by_other_station(sta, &link_mac)
            {
                return None;
            }
            links.push((link_id, link_mac));
        }
        Some(links)
    }

    fn mld_data_rx_sec_addrs(
        &self,
        sta: &[u8; 6],
        frame: &dot11::Dot11,
    ) -> Option<([u8; 6], [u8; 6], [u8; 6])> {
        if !self.mld {
            return None;
        }
        let sta_mld = self.stations.get(sta).and_then(|s| s.client_mld_mac)?;
        let sec_a3 = if frame.addr3 == self.mac || frame.addr3 == self.mld_mac {
            self.mld_mac
        } else {
            frame.addr3
        };
        Some((self.mld_mac, sta_mld, sec_a3))
    }

    fn mld_data_tx_sec_addrs(
        &self,
        sta: &[u8; 6],
        src: &[u8; 6],
    ) -> Option<([u8; 6], [u8; 6], [u8; 6])> {
        if !self.mld {
            return None;
        }
        let sta_mld = self.stations.get(sta).and_then(|s| s.client_mld_mac)?;
        let sec_a3 = if *src == self.mac || *src == self.mld_mac {
            self.mld_mac
        } else {
            *src
        };
        Some((sta_mld, self.mld_mac, sec_a3))
    }

    fn mld_mgmt_rx_sec_addrs(&self, sta: &[u8; 6]) -> Option<([u8; 6], [u8; 6], [u8; 6])> {
        if !self.mld {
            return None;
        }
        let sta_mld = self.stations.get(sta).and_then(|s| s.client_mld_mac)?;
        Some((self.mld_mac, sta_mld, self.mld_mac))
    }

    fn mld_mgmt_tx_sec_addrs(&self, sta: &[u8; 6]) -> Option<([u8; 6], [u8; 6], [u8; 6])> {
        if !self.mld {
            return None;
        }
        let sta_mld = self.stations.get(sta).and_then(|s| s.client_mld_mac)?;
        Some((sta_mld, self.mld_mac, self.mld_mac))
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

    /// PHY generation advertised by this BSS (used by the hostapd-compatible
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

    /// Install the hostapd-style credential-file candidates: `(mac, passphrase)`
    /// pairs (`None` mac = wildcard onboarding entry). Each passphrase is turned
    /// into a PMK against this AP's SSID. Once called, this file is authoritative:
    /// the BSS passphrase is no longer an authentication fallback.
    pub fn set_psk_file(&mut self, entries: &[(Option<[u8; 6]>, String)]) {
        // Reload is a revocation boundary: cached SAE PMKs were authenticated
        // under the old credential database and must not survive replacement.
        self.pmksa_cache.clear();
        for (_, pmk) in &mut self.psk_candidates {
            pmk.zeroize();
        }
        for (_, password) in &mut self.credential_passwords {
            password.zeroize();
        }
        self.psk_candidates.clear();
        self.credential_passwords.clear();
        self.credential_file_authoritative = true;
        let ssid = String::from_utf8_lossy(&self.ssid).to_string();
        self.psk_candidates = entries
            .iter()
            .map(|(m, pass)| (*m, crypto::pbkdf2_pmk(pass, &ssid)))
            .collect();
        self.credential_passwords = entries
            .iter()
            .map(|(m, pass)| (*m, pass.as_bytes().to_vec()))
            .collect();
        // The file is authoritative, so the JSON passphrase is no longer a
        // fallback and should not remain resident.
        self.pmk.zeroize();
        self.password.zeroize();
    }

    /// Select an SAE credential using hostapd's non-AP MLD identity rules. An
    /// exact MLD-MAC entry wins over an exact per-link entry, then the pending
    /// wildcard is considered. This matters for Apple MLO clients whose SAE
    /// frame source address can change between affiliated links while the MLD
    /// address remains the stable SPR device identity.
    fn sae_password_for(
        &self,
        identity: &[u8; 6],
        link_identity: Option<&[u8; 6]>,
    ) -> Option<&[u8]> {
        let exact = |wanted: &[u8; 6]| {
            self.credential_passwords
                .iter()
                .find(|(mac, _)| mac.as_ref() == Some(wanted))
        };
        exact(identity)
            .or_else(|| link_identity.and_then(exact))
            .or_else(|| {
                self.credential_passwords
                    .iter()
                    .find(|(mac, _)| mac.is_none())
            })
            .map(|(_, password)| password.as_slice())
            .or_else(|| (!self.credential_file_authoritative).then_some(self.password.as_slice()))
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

    pub fn beacon_frame_unprotected_for_link(&self, link: &MldLink) -> Vec<u8> {
        let ts = self.current_timestamp();
        let tail = dot11::security_tail(self.security_mode());
        let mut frame = if link.band6 {
            dot11::build_beacon_6ghz(
                &link.mac,
                &self.ssid,
                link.channel,
                ts,
                &tail,
                &self.country,
                link.width,
                self.wmm,
                self.phy_mode,
                self.punct,
            )
        } else {
            dot11::build_beacon(
                &link.mac,
                &self.ssid,
                link.channel,
                ts,
                &tail,
                &self.country,
                link.width,
                self.wmm,
                self.phy_mode,
                self.punct,
            )
        };
        if self.beacon_prot {
            dot11::enable_beacon_protection_capability(&mut frame[36..]);
        }
        if self.multi_bssid {
            frame.extend_from_slice(&dot11::multiple_bssid_element(0));
        }
        if let Some(ch6) = self.rnr_6ghz {
            let mut nb = link.mac;
            nb[5] ^= 0x10;
            frame.extend_from_slice(&dot11::reduced_neighbor_report(&nb, 131, ch6));
        }
        if self.mld {
            frame.extend_from_slice(&self.mld_rnr_for(link.link_id));
            let info = self.mld_link_info_for(link.link_id);
            frame.extend_from_slice(&self.mld_basic_element(link.link_id, &info));
            frame.extend_from_slice(&self.mld_tid_to_link_element());
        }
        frame
    }

    fn beacon_frame_inner(&mut self, protect: bool) -> Vec<u8> {
        let ts = self.current_timestamp();
        let tail = dot11::security_tail(self.security_mode());
        let mut frame = if self.band6 {
            dot11::build_beacon_6ghz(
                &self.mac,
                &self.ssid,
                self.channel,
                ts,
                &tail,
                &self.country,
                self.channel_width,
                self.wmm,
                self.phy_mode,
                self.punct,
            )
        } else {
            dot11::build_beacon(
                &self.mac,
                &self.ssid,
                self.channel,
                ts,
                &tail,
                &self.country,
                self.channel_width,
                self.wmm,
                self.phy_mode,
                self.punct,
            )
        };
        if self.beacon_prot {
            dot11::enable_beacon_protection_capability(&mut frame[36..]);
        }
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
        // 802.11be AP MLD: advertise the Basic Multi-Link element (MLD MAC + this
        // link's Link ID) so MLD-capable clients associate at the MLD level.
        if self.mld {
            frame.extend_from_slice(&self.mld_rnr_for(self.link_id));
            let info = self.mld_link_info_for(self.link_id);
            frame.extend_from_slice(&self.mld_basic_element(self.link_id, &info));
            frame.extend_from_slice(&self.mld_tid_to_link_element());
        }
        if self.beacon_prot && protect {
            // Protect the beacon body with a BIP Management MIC Element (BIGTK).
            // The BIGTK IPN is the same little-endian counter as the IGTK's.
            inc_ipn_le(&mut self.bigtk_ipn);
            let (fc0, fc1) = (frame[0], frame[1]);
            let bcast = [0xffu8; 6];
            let body = dot11::bip_protect(
                &self.bigtk,
                self.bigtk_key_id,
                &self.bigtk_ipn,
                fc0,
                fc1,
                &bcast,
                &self.mac,
                &self.mac,
                &frame[24..],
            );
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
                dot11::SUBTYPE_ASSOC_REQ | dot11::SUBTYPE_REASSOC_REQ => {
                    self.handle_assoc_req(&frame, &mut out)
                }
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
        let mut frame = dot11::build_probe_resp(
            &self.mac,
            dst,
            &self.ssid,
            self.channel,
            ts,
            sc,
            &dot11::security_tail(self.security_mode()),
            &self.country,
            self.channel_width,
            self.band6,
            self.wmm,
            self.phy_mode,
            self.punct,
        );
        if self.beacon_prot {
            dot11::enable_beacon_protection_capability(&mut frame[36..]);
        }
        if self.mld {
            frame.extend_from_slice(&self.mld_rnr_for(self.link_id));
            let info = self.mld_link_info_for(self.link_id);
            frame.extend_from_slice(&self.mld_basic_element(self.link_id, &info));
            frame.extend_from_slice(&self.mld_tid_to_link_element());
        }
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

        // A SAE AP still accepts open-system Authentication, because WPA3-SAE
        // *PMKSA caching* (fast reconnect) skips a fresh SAE exchange and does
        // open-auth followed by (Re)Association carrying the cached PMKID — a
        // client that already ran SAE once (e.g. reconnecting after a link
        // glitch) uses exactly this path. Rejecting open-auth here (status 13)
        // breaks that reconnect and loops the STA in AUTHENTICATING. The
        // anti-downgrade guarantee is preserved at *association*: a SAE/OWE-only
        // AP rejects an assoc with no SAE/OWE/cached PMK (see `handle_assoc_req`),
        // so an open-auth station that has no valid PMKID never reaches a 4-way
        // and can never fall back to the bare PSK path.

        // Open-system authentication (algorithm 0) -- WPA2/PSK, or SAE PMKSA reconnect
        let now = Instant::now();
        let mut restarted_association = None;
        {
            let entry = self
                .stations
                .entry(sta)
                .or_insert_with(|| Station::new(sta));
            // A duplicate auth within the backoff window is a retransmission (the
            // STA didn't get our response and retried). Re-answer it idempotently
            // — dropping it would stall a client over a lossy link — but do NOT
            // restart the session (that's only for a genuinely new auth).
            let retransmit = entry
                .last_auth
                .map(|t| now.duration_since(t) < BACKOFF)
                .unwrap_or(false);
            // A (re-)Authentication restarts the station's session, as in
            // hostapd: drop any prior 4-way / association state so a reconnecting
            // client derives a fresh PTK against a fresh ANonce. Without this, a
            // station that left without a (seen) deauth keeps its stale ANonce and
            // keys, and the reconnect's 4-way fails with a MIC/"wrong key".
            //
            // BUT: a re-Auth that interrupts an *in-flight initial 4-way* must NOT
            // regenerate the ANonce. Real clients fall back to a PMKSA-cached
            // reconnect (a second Auth+Assoc) mid-handshake; if each Association
            // mints a fresh ANonce, the client's in-flight Message 2 — keyed to the
            // ANonce we already sent it — never verifies, and every retry advances
            // us one ANonce ahead of the client: a permanent off-by-one livelock
            // (observed on ath12k, where the client always PMKSA-reconnects). While
            // mid-handshake (we sent m1 but have not accepted m2) reuse the
            // existing ANonce/replay pair. Once m2 verifies, `eapol_ready` is
            // cleared and the pending pair is consumed before m3 can install a
            // PTK, so any later authentication gets a full reset.
            let mid_handshake = entry.anonce.is_some() && entry.eapol_ready && !entry.awaiting_m4;
            if std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
                eprintln!(
                    "AP: AUTH-REQ sta={} retransmit={retransmit} mid_handshake={mid_handshake} anonce_set={} associated={} eapol_ready={}",
                    crate::util::bytes_to_mac(&sta),
                    entry.anonce.is_some(),
                    entry.associated,
                    entry.eapol_ready,
                );
            }
            if !retransmit && !mid_handshake {
                if entry.associated {
                    restarted_association = Some(entry.client_mld_mac.unwrap_or(sta));
                }
                entry.last_auth = Some(now);
                entry.anonce = None;
                entry.eapol_ready = false;
                entry.awaiting_m4 = false;
                entry.associated = false;
                entry.eapol_replay = 0;
                entry.m1_replay = 0;
                entry.ptk_candidates.clear();
                entry.kck.zeroize();
                entry.kek.zeroize();
                entry.tk.zeroize();
                entry.gtk.zeroize();
                entry.gtk = random_bytes::<16>();
                entry.pending_eapol = None; // no stale m1/m3 to retransmit
                                            // Drop any psk_file PMK pinned by a previous 4-way so the
                                            // candidate trial (per-MAC -> wildcard -> default) re-runs — a
                                            // re-onboarded device may use a different password now. (SAE uses
                                            // algorithm-3 auth and never reaches this open-auth reset; PMKSA
                                            // fast-reconnect re-sets `pmk` from the cache at association.)
                entry.set_pmk(None);
            } else if !retransmit {
                // Mid-message-1 re-auth: keep the ANonce/replay state, just
                // note the auth time so the backoff window tracks the latest attempt.
                entry.last_auth = Some(now);
            }
        }
        if let Some(mac) = restarted_association {
            eprintln!(
                "AP: station {} started a fresh authentication while associated; retiring old session",
                crate::util::bytes_to_mac(&mac)
            );
            self.events.push(ApEvent::Disconnected { mac, reason: 0 });
            if self.strict_rekey && self.stations.values().any(|s| s.associated) {
                self.group_rekey_due = true;
            }
        }

        // recv_pkt resets the sequence counter on auth
        self.sc = -1;
        let sc = self.next_sc();
        let auth = dot11::build_auth(&self.mac, &sta, sc);
        out.tx(auth);
    }

    fn sae_commit_token(payload: &[u8], h2e: bool) -> Option<(Vec<u8>, Option<[u8; 32]>)> {
        const COMMIT_LEN: usize = 2 + 3 * 32;
        if payload.len() < COMMIT_LEN {
            return None;
        }
        if !h2e {
            // Legacy SAE inserts the fixed-size token after the group ID and
            // before scalar/element. With no token, the core commit is 98 bytes.
            if payload.len() >= COMMIT_LEN + 32 {
                let mut token = [0u8; 32];
                token.copy_from_slice(&payload[2..34]);
                let mut commit = Vec::with_capacity(payload.len() - 32);
                commit.extend_from_slice(&payload[..2]);
                commit.extend_from_slice(&payload[34..]);
                return Some((commit, Some(token)));
            }
            return Some((payload.to_vec(), None));
        }

        // H2E carries the token in Extension IE 93 after scalar/element. Strip
        // exactly one well-formed token container while retaining other IEs
        // (Rejected Groups and MLO identity) in the canonical commit.
        let mut commit = payload[..COMMIT_LEN].to_vec();
        let mut token = None;
        let mut pos = COMMIT_LEN;
        while pos < payload.len() {
            if payload.len() - pos < 2 {
                return None;
            }
            let len = payload[pos + 1] as usize;
            let end = pos
                .checked_add(2 + len)
                .filter(|end| *end <= payload.len())?;
            if payload[pos] == 255 && len == 33 && payload[pos + 2] == 93 {
                if token.is_some() {
                    return None;
                }
                let mut value = [0u8; 32];
                value.copy_from_slice(&payload[pos + 3..end]);
                token = Some(value);
            } else {
                commit.extend_from_slice(&payload[pos..end]);
            }
            pos = end;
        }
        Some((commit, token))
    }

    fn sae_token_at(
        &self,
        sta: &[u8; 6],
        h2e: bool,
        commit: &[u8],
        issued_at_secs: u64,
    ) -> [u8; 32] {
        let method = [u8::from(h2e)];
        let issued = issued_at_secs.to_be_bytes();
        let mut input =
            Vec::with_capacity(19 + issued.len() + sta.len() + method.len() + commit.len());
        input.extend_from_slice(b"rustap-sae-token-v1");
        input.extend_from_slice(&issued);
        input.extend_from_slice(sta);
        input.extend_from_slice(&method);
        input.extend_from_slice(commit);
        let mut mac = crypto::hmac_sha256(&self.sae_token_key, &input);
        let mut token = [0u8; 32];
        token[..8].copy_from_slice(&issued);
        token[8..].copy_from_slice(&mac[..24]);
        mac.zeroize();
        token
    }

    fn sae_token(&self, sta: &[u8; 6], h2e: bool, commit: &[u8]) -> [u8; 32] {
        self.sae_token_at(sta, h2e, commit, self.boottime.elapsed().as_secs())
    }

    fn valid_sae_token(&self, sta: &[u8; 6], h2e: bool, commit: &[u8], token: &[u8; 32]) -> bool {
        let issued_at_secs = u64::from_be_bytes(token[..8].try_into().expect("token timestamp"));
        let now = self.boottime.elapsed().as_secs();
        let Some(age) = now.checked_sub(issued_at_secs) else {
            return false;
        };
        if age > SAE_TOKEN_LIFETIME.as_secs() {
            return false;
        }
        let mut expected = self.sae_token_at(sta, h2e, commit, issued_at_secs);
        let valid = crypto::constant_time_eq(&token[8..], &expected[8..]);
        expected.zeroize();
        valid
    }

    fn request_sae_token(&mut self, sta: &[u8; 6], h2e: bool, commit: &[u8], out: &mut Outgoing) {
        let Some(group) = commit.get(..2) else {
            return;
        };
        let token = self.sae_token(sta, h2e, commit);
        let mut body = group.to_vec();
        if h2e {
            body.extend_from_slice(&[255, 33, 93]);
        }
        body.extend_from_slice(&token);
        let sc = self.next_sc();
        out.tx(dot11::build_sae_auth(
            sta,
            &self.mac,
            &self.mac,
            0,
            sc,
            1,
            dot11::STATUS_ANTI_CLOGGING_TOKEN_REQ,
            &body,
        ));
    }

    fn incomplete_sae_count(&self) -> usize {
        self.stations
            .values()
            .filter(|s| s.sae.is_some() && !s.sae_confirmed)
            .count()
    }

    /// Drive the SAE (Dragonfly) exchange. Commit (seq 1) yields our commit +
    /// confirm; the peer's confirm (seq 2) completes authentication.
    fn handle_sae_auth(
        &mut self,
        sta: &[u8; 6],
        seq: u16,
        status: u16,
        payload: &[u8],
        out: &mut Outgoing,
    ) {
        if std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
            let grp = if seq == 1 && payload.len() >= 2 {
                u16::from_le_bytes([payload[0], payload[1]])
            } else {
                0
            };
            eprintln!(
                "AP: SAE seq={seq} status={status} group={grp} payload_len={} from {}",
                payload.len(),
                crate::util::bytes_to_mac(sta)
            );
        }
        if seq == 1 && !matches!(status, dot11::STATUS_SUCCESS | dot11::STATUS_SAE_H2E) {
            // SAE-PK (127) and other non-success commit status values are not
            // legacy SAE. hostapd answers these unsupported commit methods with
            // status 1 instead of feeding their payload into hunting-and-pecking.
            let sc = self.next_sc();
            out.tx(dot11::build_sae_auth(
                sta,
                &self.mac,
                &self.mac,
                0,
                sc,
                1,
                dot11::STATUS_UNSPECIFIED_FAILURE,
                &[],
            ));
            return;
        }
        if seq == 1 {
            let Some(group_bytes) = payload.get(..2) else {
                self.record_failure(sta, crate::failures::FailureKind::Sae);
                return;
            };
            let group = u16::from_le_bytes([group_bytes[0], group_bytes[1]]);
            if group != crate::sae::SAE_GROUP_19 {
                // SAE group negotiation depends on an explicit status 77:
                // wpa_supplicant then advances to its next configured group.
                // Silently dropping an unsupported commit leaves it retrying
                // the same group until authentication times out.
                let sc = self.next_sc();
                out.tx(dot11::build_sae_auth(
                    sta,
                    &self.mac,
                    &self.mac,
                    0,
                    sc,
                    1,
                    dot11::STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED,
                    group_bytes,
                ));
                return;
            }
            let h2e = status == dot11::STATUS_SAE_H2E;
            let Some((commit_payload, supplied_token)) = Self::sae_commit_token(payload, h2e)
            else {
                self.record_failure(sta, crate::failures::FailureKind::Sae);
                return;
            };
            // Idempotent retry: if the STA re-sends the identical commit while
            // SAE is still in progress, resend the cached commit+confirm instead
            // of resetting our scalar. A lost response on a flaky medium then
            // recovers rather than desyncing into an authentication loop.
            if let Some(s) = self.stations.get(sta) {
                if s.sae.is_some()
                    && !s.sae_confirmed
                    && !s.sae_resp.is_empty()
                    && s.sae_commit == commit_payload
                {
                    for f in s.sae_resp.clone() {
                        out.tx(f);
                    }
                    return;
                }
            }
            let incomplete = self.incomplete_sae_count();
            let existing_exchange = self
                .stations
                .get(sta)
                .map(|s| s.sae.is_some() && !s.sae_confirmed)
                .unwrap_or(false);
            if !existing_exchange && incomplete >= SAE_INCOMPLETE_MAX {
                // Do no ECC work and allocate no state while the hard cap is
                // full. Expiration in tick/prune_idle makes this self-healing.
                self.request_sae_token(sta, h2e, &commit_payload, out);
                return;
            }
            if incomplete >= SAE_ANTI_CLOGGING_THRESHOLD {
                let valid = supplied_token
                    .as_ref()
                    .map(|token| self.valid_sae_token(sta, h2e, &commit_payload, token))
                    .unwrap_or(false);
                if !valid {
                    self.request_sae_token(sta, h2e, &commit_payload, out);
                    return;
                }
            }
            // Pick the PWE method the STA advertised: status 126 = Hash-to-Element
            // (the preferred, side-channel-free derivation), otherwise legacy
            // hunting-and-pecking (whose derivation is made constant-time in
            // `derive_pwe_hunting_pecking` so it has no Dragonblood timing leak).
            let auth_mld = self
                .mld
                .then(|| Self::sae_auth_mld_mac(seq, &commit_payload))
                .flatten();
            // Apple can first try a cached-PMKSA MLO association and only then
            // fall back to full SAE. That association has already supplied and
            // validated the non-AP MLD identity. Some drivers deliver the
            // subsequent SAE commit link-addressed or without exposing its
            // Authentication MLE to userspace; in that case retain the stable
            // identity instead of attempting credential lookup by the rotating
            // link MAC. The later association-to-SAE identity check still
            // rejects any conflicting MLD address.
            let known_mld = self
                .mld
                .then(|| self.stations.get(sta).and_then(|s| s.client_mld_mac))
                .flatten();
            let peer_mld = auth_mld.or(known_mld);
            // Match hostapd's ap_sta_is_mld() split: an MLD AP still uses its
            // link address for a legacy station. The MLD address is an SAE
            // identity only when the peer's Authentication frame identifies
            // that peer as an MLD.
            let sae_ap = if peer_mld.is_some() {
                self.mld_mac
            } else {
                self.mac
            };
            let sae_sta = peer_mld.unwrap_or(*sta);
            // A hostapd-style credential file may bind a different SAE
            // password to each link-addressed station. Select and own it before
            // mutably borrowing the SAE/station state below.
            let Some(mut password) = self
                .sae_password_for(&sae_sta, peer_mld.as_ref().map(|_| sta))
                .map(<[u8]>::to_vec)
            else {
                eprintln!(
                    "AP: SAE credential lookup failed link={} auth_mld={} known_mld={} identity={}",
                    crate::util::bytes_to_mac(sta),
                    auth_mld
                        .as_ref()
                        .map(crate::util::bytes_to_mac)
                        .unwrap_or_else(|| "-".to_string()),
                    known_mld
                        .as_ref()
                        .map(crate::util::bytes_to_mac)
                        .unwrap_or_else(|| "-".to_string()),
                    crate::util::bytes_to_mac(&sae_sta)
                );
                self.record_failure(sta, crate::failures::FailureKind::Sae);
                return;
            };
            eprintln!(
                "AP: SAE commit link={} auth_mld={} known_mld={} identity={} ap_identity={} h2e={h2e}",
                crate::util::bytes_to_mac(sta),
                auth_mld
                    .as_ref()
                    .map(crate::util::bytes_to_mac)
                    .unwrap_or_else(|| "-".to_string()),
                known_mld
                    .as_ref()
                    .map(crate::util::bytes_to_mac)
                    .unwrap_or_else(|| "-".to_string()),
                crate::util::bytes_to_mac(&sae_sta),
                crate::util::bytes_to_mac(&sae_ap),
            );
            let mut sae = if h2e {
                crate::sae::Sae::new_h2e(&self.ssid, &password, None, &sae_ap, &sae_sta)
            } else {
                match crate::sae::Sae::new_hunting_pecking(&password, &sae_ap, &sae_sta) {
                    Some(s) => s,
                    None => {
                        password.zeroize();
                        return;
                    }
                }
            };
            password.zeroize();
            if let Err(err) = sae.parse_peer_commit(&commit_payload) {
                eprintln!(
                    "AP: SAE commit parse failed from {}: {err:?}",
                    crate::util::bytes_to_mac(sta)
                );
                self.record_failure(sta, crate::failures::FailureKind::Sae);
                return;
            }
            let rejected_groups = sae.peer_rejected_groups();
            if !rejected_groups.is_empty() {
                eprintln!(
                    "AP: SAE H2E peer {} rejected groups {}; applying negotiated key salt",
                    crate::util::bytes_to_mac(&sae_sta),
                    rejected_groups
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
            sae.prepare_commit(None);
            // Reject a reflected commit (peer echoing our own scalar + element).
            if sae.is_reflection() {
                eprintln!(
                    "AP: SAE reflected commit from {}",
                    crate::util::bytes_to_mac(sta)
                );
                self.record_failure(sta, crate::failures::FailureKind::Sae);
                return;
            }
            if let Err(err) = sae.process_commit() {
                eprintln!(
                    "AP: SAE commit processing failed from {}: {err:?}",
                    crate::util::bytes_to_mac(sta)
                );
                self.record_failure(sta, crate::failures::FailureKind::Sae);
                return;
            }

            let mut commit_body = sae.write_commit();
            let mut confirm_body = sae.write_confirm();
            if peer_mld.is_some() {
                let ml = dot11::multi_link_auth(&self.mld_mac);
                commit_body.extend_from_slice(&ml);
                confirm_body.extend_from_slice(&ml);
            }
            let resp_status = if h2e {
                dot11::STATUS_SAE_H2E
            } else {
                dot11::STATUS_SUCCESS
            };

            self.sc = -1;
            let sc1 = self.next_sc();
            let commit = dot11::build_sae_auth(
                sta,
                &self.mac,
                &self.mac,
                0,
                sc1,
                1,
                resp_status,
                &commit_body,
            );
            let sc2 = self.next_sc();
            let confirm = dot11::build_sae_auth(
                sta,
                &self.mac,
                &self.mac,
                0,
                sc2,
                2,
                dot11::STATUS_SUCCESS,
                &confirm_body,
            );

            let mut pmk = [0u8; 32];
            pmk.copy_from_slice(&sae.pmk);
            let entry = self
                .stations
                .entry(*sta)
                .or_insert_with(|| Station::new(*sta));
            entry.sae = Some(sae);
            entry.set_pmk(Some(pmk));
            pmk.zeroize();
            entry.sae_confirmed = false;
            entry.sha256 = true; // WPA3-SAE uses SHA-256 key descriptors + PMF
            if let Some(mld) = peer_mld {
                entry.client_mld_mac = Some(mld);
            }
            // Cache this response so an identical retried commit is answered
            // idempotently (see the guard above).
            entry.sae_resp = vec![commit.clone(), confirm.clone()];
            entry.sae_commit = commit_payload;
            entry.last_activity = Instant::now();

            out.tx(commit);
            out.tx(confirm);
        } else if seq == 2 {
            eprintln!(
                "AP: SAE confirm received from {} payload_len={}",
                crate::util::bytes_to_mac(sta),
                payload.len(),
            );
            // Verify the peer's confirm. Only a verified confirm completes SAE:
            // it gates association (see `handle_assoc_req`) and is the point at
            // which the PMK becomes mutually authenticated, so the PMKSA is
            // cached *here*, not on the unconfirmed commit.
            let confirm_result = self
                .stations
                .get(sta)
                .and_then(|s| s.sae.as_ref())
                .map(|sae| sae.check_confirm(payload));
            match confirm_result {
                Some(Ok(())) => {}
                // Confirm present but invalid -> wrong password / forged confirm.
                Some(Err(err)) => {
                    eprintln!(
                        "AP: SAE confirm verification failed from {}: {err:?}",
                        crate::util::bytes_to_mac(sta)
                    );
                    self.record_failure(sta, crate::failures::FailureKind::Sae);
                    return;
                }
                None => {
                    eprintln!(
                        "AP: SAE confirm from {} has no matching commit state",
                        crate::util::bytes_to_mac(sta)
                    );
                    return;
                }
            }
            let confirmed = self
                .stations
                .get(sta)
                .and_then(|s| s.sae.as_ref())
                .map(|sae| (sae.pmkid.clone(), sae.pmk.clone()));
            let identity = self
                .stations
                .get(sta)
                .and_then(|s| s.client_mld_mac)
                .unwrap_or(*sta);
            if let Some(s) = self.stations.get_mut(sta) {
                s.sae_confirmed = true;
            }
            eprintln!(
                "AP: SAE confirm verified for {}",
                crate::util::bytes_to_mac(sta),
            );
            if let Some((pmkid, mut pmk)) = confirmed {
                if std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
                    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
                    eprintln!("AP: SAE confirmed pmkid={} pmk={}", hex(&pmkid), hex(&pmk));
                }
                if pmkid.len() == 16 && pmk.len() == 32 {
                    let mut id = [0u8; 16];
                    id.copy_from_slice(&pmkid);
                    let mut k = [0u8; 32];
                    k.copy_from_slice(&pmk);
                    self.cache_pmksa(id, identity, k, true);
                    k.zeroize();
                }
                pmk.zeroize();
            }
        }
    }

    fn sae_auth_mld_mac(seq: u16, payload: &[u8]) -> Option<[u8; 6]> {
        const SAE_GROUP19_COMMIT_LEN: usize = 2 + 3 * 32;
        const SAE_CONFIRM_LEN: usize = 2 + 32;
        let ies = match seq {
            1 => payload.get(SAE_GROUP19_COMMIT_LEN..)?,
            2 => payload.get(SAE_CONFIRM_LEN..)?,
            _ => return None,
        };
        dot11::parse_mld_mac(ies)
    }

    fn handle_assoc_req(&mut self, frame: &dot11::Dot11, out: &mut Outgoing) {
        if frame.addr1 != self.mac {
            return;
        }
        let sta = frame.addr2;
        let reassoc = frame.subtype() == dot11::SUBTYPE_REASSOC_REQ;

        // PMF SA Query takes precedence over parsing a repeated association
        // request: the frame may be spoofed and intentionally malformed. Do not
        // let it overwrite station state or turn the required status-30 comeback
        // into a negotiation error.
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
            let sec = self.mld_mgmt_tx_sec_addrs(&sta);
            out.tx(dot11::build_protected_sa_query_sec(
                &self.mac, &sta, false, false, trans, sc, pn, &tk, sec,
            ));
            return;
        }

        let ie_off = if reassoc { 10 } else { 4 };
        let Some(assoc_ies) = frame.body.get(ie_off..) else {
            self.reject_assoc_status(&sta, reassoc, dot11::STATUS_INVALID_IE, out);
            return;
        };
        let assoc_rsn = match dot11::find_ie_strict(assoc_ies, 48) {
            Ok(Some(rsn)) => rsn,
            _ => {
                self.reject_assoc_status(&sta, reassoc, dot11::STATUS_INVALID_IE, out);
                return;
            }
        };
        if let Err(status) = dot11::validate_assoc_rsn(assoc_rsn, self.security_mode()) {
            self.reject_assoc_status(&sta, reassoc, status, out);
            return;
        }
        let requests_sae = dot11::rsn_has_akm(assoc_rsn, 8);
        if requests_sae {
            match dot11::find_ie_strict(assoc_ies, 0xf4) {
                Ok(Some(rsnxe)) if dot11::rsnxe_has_sae_h2e(rsnxe) => {}
                _ => {
                    self.reject_assoc_status(&sta, reassoc, dot11::STATUS_INVALID_IE, out);
                    return;
                }
            }
        }
        let mld_assoc = if self.mld {
            let client_mld = dot11::parse_mld_mac(assoc_ies);
            if dot11::has_basic_multi_link_element(assoc_ies) && client_mld.is_none() {
                self.reject_assoc_status(&sta, reassoc, dot11::STATUS_INVALID_IE, out);
                return;
            }
            if let Some(client_mld) = client_mld {
                let sae_mld = self.stations.get(&sta).and_then(|s| s.client_mld_mac);
                if sae_mld.map(|prev| prev != client_mld).unwrap_or(false) {
                    self.reject_assoc(&sta, reassoc, out);
                    return;
                }
                let Some(links) = self.validate_mld_assoc_links(&sta, &client_mld, assoc_ies)
                else {
                    self.reject_assoc(&sta, reassoc, out);
                    return;
                };
                Some((client_mld, links))
            } else {
                None
            }
        } else {
            None
        };

        // Fingerprint the client from its association characteristics (for the
        // failure log), and note whether it negotiated WMM (the IE block starts
        // after the fixed fields: 4 bytes for Assoc, 10 for Reassoc).
        let ap_wmm = self.wmm;
        let client_wmm = frame.body.len() > ie_off && dot11::has_wmm_ie(&frame.body[ie_off..]);
        {
            let s = self
                .stations
                .entry(sta)
                .or_insert_with(|| Station::new(sta));
            s.traits = crate::failures::client_traits(&frame.body);
            s.wmm = ap_wmm && client_wmm;
            if frame.body.len() >= 4 {
                s.capability = u16::from_le_bytes([frame.body[0], frame.body[1]]);
                s.listen_interval = u16::from_le_bytes([frame.body[2], frame.body[3]]);
            }
            // Remember the station's capability IEs (HT/VHT/HE/rates) so the
            // netlink station setup can hand them to the driver for rate control.
            s.assoc_ies = frame.body.get(ie_off..).unwrap_or(&[]).to_vec();
            if let Some((client_mld, links)) = mld_assoc.as_ref() {
                s.client_mld_mac = Some(*client_mld);
                s.client_mld_links = links.clone();
            }
        }
        if std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
            let ies = frame.body.get(ie_off..).unwrap_or(&[]);
            let ml = dot11::parse_mld_mac(ies);
            let rsn_hex: String = dot11::find_ie(ies, 48)
                .map(|r| r.iter().map(|b| format!("{b:02x}")).collect())
                .unwrap_or_default();
            eprintln!(
                "AP: DBG-ASSOC sta={} has_ml_element={} client_mld={:?} rsn={}",
                crate::util::bytes_to_mac(&sta),
                ml.is_some(),
                ml.map(|m| crate::util::bytes_to_mac(&m)),
                rsn_hex
            );
        }
        if let Some((client_mld, links)) = mld_assoc {
            eprintln!(
                "AP: MLD association sta={} mld={} requested_links={}",
                crate::util::bytes_to_mac(&sta),
                crate::util::bytes_to_mac(&client_mld),
                links
                    .iter()
                    .map(|(link_id, mac)| format!("{}:{}", link_id, crate::util::bytes_to_mac(mac)))
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }

        // A station that began SAE must have a *verified* confirm before it may
        // associate — otherwise the mutual authentication is incomplete and we'd
        // derive a PTK from an unconfirmed PMK. (The anti-downgrade check that a
        // WPA3-only AP doesn't fall back to the PSK 4-way lives in `handle_eapol`,
        // so PMKSA fast-reconnect — which skips SAE with a cached PMK — still works.)
        if let Some(s) = self.stations.get(&sta) {
            if s.sae.is_some() && !s.sae_confirmed {
                eprintln!(
                    "AP: association from {} deferred because SAE confirm is not complete",
                    crate::util::bytes_to_mac(&sta),
                );
                return;
            }
        }

        let now = Instant::now();
        {
            let entry = self
                .stations
                .entry(sta)
                .or_insert_with(|| Station::new(sta));
            if let Some(t) = entry.last_assoc {
                if now.duration_since(t) < BACKOFF {
                    return;
                }
            }
            entry.last_assoc = Some(now);
        }

        // PMKSA caching: if the (re)assoc request carries a PMKID we have cached,
        // skip a fresh SAE exchange and run the 4-way with the cached PMK.
        let requested_pmkid = dot11::parse_rsn_pmkid(assoc_rsn);
        let pmksa_identity = self
            .stations
            .get(&sta)
            .and_then(|s| s.client_mld_mac)
            .unwrap_or(sta);
        self.expire_pmksa();
        if let Some(pmkid) = requested_pmkid {
            if let Some(entry) = self.pmksa_cache.get(&(pmkid, pmksa_identity)) {
                let pmk = entry.pmk;
                let sha256 = entry.sha256;
                if let Some(s) = self.stations.get_mut(&sta) {
                    s.set_pmk(Some(pmk));
                    s.sha256 = sha256;
                }
            }
        }

        // Match hostapd/802.11 PMKSA fallback: an SAE station that open-auths
        // with a PMKID the AP no longer knows must receive status 53. A generic
        // failure leaves Apple clients retrying that stale PMKID indefinitely;
        // INVALID_PMKID tells them to discard it and perform full SAE again.
        // A PMK already established by a fresh SAE exchange remains valid even
        // if that association happens to include an unknown PMKID.
        if requests_sae
            && requested_pmkid.is_some()
            && self
                .stations
                .get(&sta)
                .map(|s| s.pmk.is_none())
                .unwrap_or(true)
        {
            let sc = self.next_sc();
            out.tx(dot11::build_assoc_resp_reject(
                &self.mac,
                &sta,
                dot11::STATUS_INVALID_PMKID,
                if reassoc {
                    dot11::SUBTYPE_REASSOC_RESP
                } else {
                    dot11::SUBTYPE_ASSOC_RESP
                },
                sc,
            ));
            return;
        }

        // OWE: if the (re)assoc request carries a DH Parameter element, run the
        // Diffie-Hellman exchange and key the 4-way with the resulting PMK.
        let mut owe_dh_resp: Option<Vec<u8>> = None;
        if self.owe && frame.body.len() > 4 {
            if let Some((group, sta_pub)) = dot11::parse_dh_param(&frame.body[4..]) {
                if group != 19 {
                    self.reject_assoc_status(
                        &sta,
                        reassoc,
                        dot11::STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED,
                        out,
                    );
                    return;
                }
                let (ap_priv, ap_pub) = crate::sae::owe_keypair();
                if let Some((pmk, _pmkid)) =
                    crate::sae::owe_derive(&ap_priv, &sta_pub, &sta_pub, &ap_pub, group)
                {
                    if let Some(s) = self.stations.get_mut(&sta) {
                        s.set_pmk(Some(pmk));
                        s.sha256 = true;
                        s.owe = true; // OWE uses the HMAC-SHA256 EAPOL MIC
                    }
                    owe_dh_resp = Some(dot11::build_dh_param_element(group, &ap_pub));
                }
            }
        }

        let resp_subtype = if reassoc {
            0x03
        } else {
            dot11::SUBTYPE_ASSOC_RESP
        };

        // Anti-downgrade: a WPA3-SAE-only or OWE-only AP must not associate a
        // station that has no SAE/OWE/cached PMK — otherwise it would fall back
        // to the bare PSK 4-way (`self.pmk`), defeating WPA3/OWE and exposing the
        // password to offline attack. SAE sets `pmk` at auth; OWE sets it from the
        // DH element above (so an OWE assoc that *omits* the DH Parameter element
        // leaves `pmk` unset and is rejected here, never falling back to the PSK
        // 4-way); PMKSA fast-reconnect sets it from the cache. A station that did
        // none of those is denied with status 1. Transition/WPA2 modes intentionally
        // still allow the PSK path.
        if matches!(
            self.security_mode(),
            dot11::SecurityMode::Wpa3Sae | dot11::SecurityMode::Owe
        ) && self
            .stations
            .get(&sta)
            .map(|s| s.pmk.is_none())
            .unwrap_or(true)
        {
            let sc = self.next_sc();
            out.tx(dot11::build_assoc_resp_reject(
                &self.mac,
                &sta,
                dot11::STATUS_UNSPECIFIED_FAILURE,
                resp_subtype,
                sc,
            ));
            return;
        }

        let aid = self.next_aid();
        let sc = self.next_sc();
        let mut assoc = dot11::build_assoc_resp(
            &self.mac,
            &sta,
            &self.ssid,
            self.channel,
            aid,
            sc,
            resp_subtype,
            &self.country,
            self.channel_width,
            self.band6,
            self.wmm,
            self.phy_mode,
            self.punct,
        );
        if self.beacon_prot {
            // Association Response fixed fields are Capability, Status and AID.
            dot11::enable_beacon_protection_capability(&mut assoc[30..]);
        }
        // Advertise a BSS Max Idle Period (~300 s) so the STA sends keep-alives.
        assoc.extend_from_slice(&dot11::bss_max_idle_element(300));
        // 802.11be MLD: echo our Basic Multi-Link element to an MLD station so it
        // completes the MLD (re)association.
        if self.mld
            && self
                .stations
                .get(&sta)
                .map(|s| s.client_mld_mac.is_some())
                .unwrap_or(false)
        {
            let requested = self
                .stations
                .get(&sta)
                .map(|s| s.client_mld_links.as_slice())
                .unwrap_or(&[]);
            let info = self.mld_assoc_link_info_for(requested);
            assoc.extend_from_slice(&self.mld_basic_element(self.link_id, &info));
            assoc.extend_from_slice(&self.mld_tid_to_link_element());
        }
        if let Some(dh) = owe_dh_resp {
            assoc.extend_from_slice(&dh); // OWE DH Parameter element
        }

        // If the 4-way has already advanced to Message 3 (we verified this STA's
        // m2 and are awaiting m4), a repeated Association Request must NOT regress
        // the handshake back to m1: rebuilding m1 here would replace the cached m3
        // and derive a fresh PTK, so the STA — which already has the PTK from m3 —
        // could never finish. Re-send the Assoc Response and let the pending m3
        // keep retransmitting. (Seen with iPhones, which re-associate aggressively
        // via PMKSA between m2 and m3.)
        let awaiting_m4 = self
            .stations
            .get(&sta)
            .map(|s| s.awaiting_m4 && s.pending_eapol.is_some())
            .unwrap_or(false);
        if awaiting_m4 {
            out.tx(assoc);
            if let Some(m3) = self
                .stations
                .get(&sta)
                .and_then(|s| s.pending_eapol.clone())
            {
                if let Some(s) = self.stations.get_mut(&sta) {
                    s.eapol_tx = Instant::now();
                    s.eapol_retries = 0;
                    s.eapol_acked = false;
                }
                out.frames.push(m3); // already radiotap-prefixed
            }
            return;
        }

        // Prepare EAPOL message 1. The ANonce must stay STABLE for the whole of a
        // station's *initial* 4-way — including across a deauthenticate+reconnect
        // — so the client's Message 2 (keyed to whichever m1 it received) always
        // verifies. A fresh ANonce per Association Request instead leaves us one
        // ANonce ahead of a client that is still answering an earlier m1, which
        // never converges (the ath12k livelock). Priority: (1) the ANonce already
        // on a still-in-progress station, (2) the ANonce held for this MAC from a
        // torn-down-but-incomplete handshake (`pending_anonce`), else a fresh one.
        //
        // Reuse is KRACK-safe because this ANonce/replay pair is consumed as soon
        // as m2 verifies, before m3 can install a PTK at either peer.
        let now = Instant::now();
        self.pending_anonce
            .retain(|_, pending| now.duration_since(pending.created_at) < ANONCE_HOLD);
        let existing_station = self
            .stations
            .get(&sta)
            .filter(|s| s.eapol_ready)
            .and_then(|s| s.anonce.map(|anonce| (anonce, s.eapol_replay)));
        let existing_pending = self
            .pending_anonce
            .get(&sta)
            .map(|pending| (pending.anonce, pending.replay_counter));
        let (anonce, m1_replay) = match existing_station.or(existing_pending) {
            Some(pending) => pending,
            None => (
                self.test_anonce.unwrap_or_else(random_bytes::<32>),
                self.next_eapol_replay(),
            ),
        };
        self.pending_anonce.insert(
            sta,
            PendingHandshake {
                anonce,
                replay_counter: m1_replay,
                created_at: now,
            },
        );
        {
            let entry = self.stations.get_mut(&sta).unwrap();
            entry.anonce = Some(anonce);
            entry.eapol_ready = true;
            entry.eapol_replay = m1_replay;
            entry.m1_replay = m1_replay;
            entry.ptk_candidates.clear();
        }
        let (sha256, owe) = self
            .stations
            .get(&sta)
            .map(|s| (s.sha256, s.owe))
            .unwrap_or((false, false));
        let m1_sc = self.next_sc();
        let mld_station = self.mld
            && self
                .stations
                .get(&sta)
                .and_then(|s| s.client_mld_mac)
                .is_some();
        let m1 = if mld_station {
            dot11::build_eapol_m1_mld(
                &self.mac,
                &sta,
                &anonce,
                m1_replay,
                m1_sc,
                dot11::KeyMic::select(sha256, owe),
                &self.mld_mac,
            )
        } else {
            dot11::build_eapol_m1(
                &self.mac,
                &sta,
                &anonce,
                m1_replay,
                m1_sc,
                dot11::KeyMic::select(sha256, owe),
            )
        };

        // Cache m1 (radiotap-prefixed) so it can be retransmitted if m2 is lost.
        if let Some(entry) = self.stations.get_mut(&sta) {
            entry.pending_eapol = Some(prepend_radiotap(m1.clone()));
            entry.eapol_tx = Instant::now();
            entry.eapol_retries = 0;
            entry.eapol_acked = false;
        }

        if std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
            eprintln!(
                "AP: TX m1 anonce={} sc={m1_sc}",
                anonce
                    .iter()
                    .map(|x| format!("{x:02x}"))
                    .collect::<String>()
            );
        }
        out.tx(assoc);
        out.tx(m1);
    }

    fn handle_eapol(&mut self, frame: &dot11::Dot11, out: &mut Outgoing) {
        let sta = frame.addr2;
        if frame.addr1 != self.mac {
            return;
        }
        let (
            anonce,
            ready,
            awaiting_m4,
            kck,
            sha256_m4,
            owe_m4,
            group_rekeying,
            eapol_replay,
            m1_replay,
        ) = match self.stations.get(&sta) {
            Some(s) => (
                s.anonce,
                s.eapol_ready,
                s.awaiting_m4,
                s.kck,
                s.sha256,
                s.owe,
                s.group_rekeying,
                s.eapol_replay,
                s.m1_replay,
            ),
            None => return,
        };

        let Some(eapol_frame) = frame.eapol_frame() else {
            return;
        };
        let Some(key_body) = frame.eapol_key_body() else {
            return;
        };
        let Some(ek) = dot11::EapolKey::parse(key_body) else {
            return;
        };

        if std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
            eprintln!(
                "AP: EAPOL rx from {} replay={} key_info=0x{:04x} ready={} anonce_set={} awaiting_m4={} rekey={}",
                crate::util::bytes_to_mac(&sta),
                ek.key_replay_counter,
                ek.key_info,
                ready,
                anonce.is_some(),
                awaiting_m4,
                group_rekeying,
            );
        }

        // Group Key Handshake message 2: an associated station's ACK of a GTK
        // rekey (its replay counter echoes the message 1 we sent). Verify the MIC,
        // then clear its rekey state; once every station has ACKed, the BSS is
        // fully on the new GTK (hostapd's GKeyDoneStations reaching 0).
        if group_rekeying && ek.key_replay_counter == eapol_replay {
            let version = expected_key_descriptor_version(sha256_m4, owe_m4);
            if !key_info_matches(ek.key_info, 0x0300 | version)
                || ek.key_length != 0
                || ek.key_nonce != [0u8; 32]
                || !ek.key_data.is_empty()
            {
                return;
            }
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
                eprintln!(
                    "AP: group-key handshake completed for {} replay={}",
                    crate::util::bytes_to_mac(&sta),
                    ek.key_replay_counter,
                );
            } else {
                eprintln!(
                    "AP: group-key message 2 MIC failed for {} replay={}",
                    crate::util::bytes_to_mac(&sta),
                    ek.key_replay_counter,
                );
            }
            return;
        }

        // Message 4: accept the PTK candidate whose MIC verifies. hostapd keeps
        // both the old and new PTK when a station retries M2 with a changed
        // SNonce, so either subsequent M4 can finish the same 4-way.
        let version = expected_key_descriptor_version(sha256_m4, owe_m4);
        let is_m4 = key_info_matches(ek.key_info, 0x0308 | version)
            && ek.key_length == 0
            && ek.key_nonce == [0u8; 32];
        if awaiting_m4 && is_m4 {
            let mic_off = 4 + ek.mic_offset;
            if eapol_frame.len() < mic_off + 16 {
                return;
            }
            let mut to_check = eapol_frame.to_vec();
            for b in to_check[mic_off..mic_off + 16].iter_mut() {
                *b = 0;
            }
            let candidates: Vec<PtkCandidate> = self
                .stations
                .get(&sta)
                .map(|s| {
                    s.ptk_candidates
                        .iter()
                        .filter(|candidate| candidate.m3_replay_counter == ek.key_replay_counter)
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            let expected_mld = self
                .mld
                .then(|| self.stations.get(&sta).and_then(|s| s.client_mld_mac))
                .flatten();
            let mut selected = None;
            for candidate in candidates {
                let mut computed =
                    dot11::KeyMic::select(sha256_m4, owe_m4).compute(&candidate.kck, &to_check);
                let mic_valid = crypto::constant_time_eq(&computed[..16], &ek.key_mic);
                computed.zeroize();
                if !mic_valid {
                    continue;
                }

                // The encrypted-data bit promises RFC 3394 wrapped data. Even a
                // valid MIC must not authorize the port if unwrap fails. For a
                // non-MLD station, successfully unwrapped extra elements are
                // allowed; an MLD station must additionally carry its MAC KDE.
                let mut unwrapped = None;
                let key_data = if ek.encrypted_key_data() {
                    unwrapped = crypto::aes_unwrap(&candidate.kek, &ek.key_data);
                    let Some(ref data) = unwrapped else {
                        continue;
                    };
                    dot11::trim_key_data_padding(data)
                } else {
                    ek.key_data.as_slice()
                };
                let key_data_valid = expected_mld
                    .map(|expected| dot11::parse_mac_addr_kde(key_data) == Some(expected))
                    .unwrap_or(true);
                if let Some(data) = unwrapped.as_mut() {
                    data.zeroize();
                }
                if key_data_valid {
                    selected = Some(candidate);
                    break;
                }
            }

            if let Some(candidate) = selected {
                let mut event_mac = None;
                if let Some(s) = self.stations.get_mut(&sta) {
                    s.kck.zeroize();
                    s.kek.zeroize();
                    s.tk.zeroize();
                    s.kck = candidate.kck;
                    s.kek = candidate.kek;
                    s.tk = candidate.tk;
                    s.ptk_candidates.clear();
                    s.associated = true;
                    s.awaiting_m4 = false;
                    s.pending_eapol = None; // 4-way complete, nothing to retransmit
                    event_mac = Some(s.client_mld_mac.unwrap_or(sta));
                }
                if let Some(mac) = event_mac {
                    self.events.push(ApEvent::Connected { mac });
                }
                // 4-way complete: release the held ANonce so any *future*
                // reassociation derives a fresh one (KRACK-safe rekey).
                self.pending_anonce.remove(&sta);
            }
            return;
        }

        // Message 2 must be expected and echo the replay counter from message 1.
        // While awaiting M4, keep accepting valid M2 retries for this same M1;
        // this is the hostapd retry1b/1c/1d behavior.
        if !ready && !awaiting_m4 {
            return;
        }
        let Some(anonce) = anonce else { return };
        if ek.key_replay_counter != m1_replay {
            return;
        }
        if !key_info_matches(ek.key_info, 0x0108 | version) || ek.key_length != 0 {
            return;
        }

        let snonce = ek.key_nonce;
        // 802.11be MLD: the PTK is derived from the MLD MAC addresses (AA = AP
        // MLD MAC, SPA = STA MLD MAC), not the per-link addresses — both peers
        // key the link off the MLD identity. Falls back to the link addresses
        // for a non-MLD station.
        let client_mld = self.stations.get(&sta).and_then(|s| s.client_mld_mac);
        let (amac, smac) = match client_mld {
            Some(cmld) if self.mld => (self.mld_mac, cmld),
            _ => (self.mac, sta),
        };

        // Use the SAE-derived PMK + SHA-256 key descriptors when the station
        // authenticated via WPA3-SAE; otherwise the PSK (PBKDF2) PMK + SHA-1.
        // Anti-downgrade backstop: on a WPA3-SAE-only or OWE-only AP, a station
        // with no SAE/OWE-derived or cached PMK must not be silently keyed via
        // the PSK 4-way fallback.
        if matches!(
            self.security_mode(),
            dot11::SecurityMode::Wpa3Sae | dot11::SecurityMode::Owe
        ) && self
            .stations
            .get(&sta)
            .map(|s| s.pmk.is_none())
            .unwrap_or(true)
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
        // whose MAC matches this station, then the wildcard onboarding entries.
        // The single BSS passphrase is considered only when no authoritative
        // credential file is configured. The candidate whose PTK verifies
        // message 2's MIC is this station's password.
        let mut candidates: Vec<[u8; 32]> = if let Some(p) = sta_pmk {
            vec![p]
        } else {
            let mut v: Vec<[u8; 32]> = Vec::new();
            v.extend(
                self.psk_candidates
                    .iter()
                    .filter(|(m, _)| *m == Some(sta))
                    .map(|(_, p)| *p),
            );
            v.extend(
                self.psk_candidates
                    .iter()
                    .filter(|(m, _)| m.is_none())
                    .map(|(_, p)| *p),
            );
            if !self.credential_file_authoritative {
                v.push(self.pmk);
            }
            v
        };

        let mic_off_in_eapol = 4 + ek.mic_offset; // EAPOL header (4) + body offset
        if std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
            eprintln!(
                "AP: m2 PTK amac={} smac={} client_mld={:?} sta={} sha256={sha256} cands={} pmk[..8]={}",
                crate::util::bytes_to_mac(&amac),
                crate::util::bytes_to_mac(&smac),
                client_mld.map(|m| crate::util::bytes_to_mac(&m)),
                crate::util::bytes_to_mac(&sta),
                candidates.len(),
                candidates.first().map(|p| p[..8].iter().map(|x| format!("{x:02x}")).collect::<String>()).unwrap_or_default(),
            );
        }
        if std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
            let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
            eprintln!("AP: m2 anonce={}", hex(&anonce));
            eprintln!("AP: m2 snonce={}", hex(&snonce));
            eprintln!(
                "AP: m2 mic_off_in_eapol={mic_off_in_eapol} eapol_len={}",
                eapol_frame.len()
            );
            eprintln!("AP: m2 eapol_frame={}", hex(eapol_frame));
            eprintln!("AP: m2 recv_mic={}", hex(&ek.key_mic));
        }
        let mut kck = [0u8; 16];
        let mut kek = [0u8; 16];
        let mut tk = [0u8; 16];
        let mut matched_pmk: Option<[u8; 32]> = None;
        for pmk in &candidates {
            if sha256 {
                let mut ptk = crypto::derive_ptk_sha256(pmk, &amac, &smac, &anonce, &snonce);
                kck.copy_from_slice(&ptk[..16]);
                kek.copy_from_slice(&ptk[16..32]);
                tk.copy_from_slice(&ptk[32..48]);
                ptk.zeroize();
            } else {
                let mut ptk = crypto::custom_prf512(pmk, &amac, &smac, &anonce, &snonce);
                kck.copy_from_slice(&ptk[..16]);
                kek.copy_from_slice(&ptk[16..32]);
                tk.copy_from_slice(&ptk[32..48]);
                ptk.zeroize();
            }
            let mut to_check = eapol_frame.to_vec();
            for b in to_check[mic_off_in_eapol..mic_off_in_eapol + 16].iter_mut() {
                *b = 0;
            }
            let mut computed = dot11::KeyMic::select(sha256, owe).compute(&kck, &to_check);
            if std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
                let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
                eprintln!(
                    "AP: m2 try kck={} computed_mic={}",
                    hex(&kck),
                    hex(&computed[..16])
                );
            }
            let mic_valid = crypto::constant_time_eq(&computed, &ek.key_mic);
            computed.zeroize();
            if mic_valid {
                matched_pmk = Some(*pmk);
                break;
            }
        }
        if matched_pmk.is_none() && std::env::var_os("RUSTAP_NL_DEBUG").is_some() {
            eprintln!("AP: m2 MIC did not match the pending handshake");
        }
        let mut matched_pmk = match matched_pmk {
            None => {
                candidates.zeroize();
                kck.zeroize();
                kek.zeroize();
                tk.zeroize();
                // A bad first M2 means the configured password did not verify.
                // Once at least one M2 has already verified, however, a bad
                // retry must not destroy the valid pending candidate.
                if awaiting_m4 {
                    return;
                }
                self.record_failure(&sta, crate::failures::FailureKind::FourWayMic);
                let deauth = dot11::build_deauth(&self.mac, &sta, 1);
                out.tx(deauth);
                self.disconnect(&sta, 1);
                return;
            }
            Some(p) => p,
        };
        candidates.zeroize();

        let mut m2_key_data = if ek.encrypted_key_data() {
            match crypto::aes_unwrap(&kek, &ek.key_data) {
                Some(data) => data,
                None => {
                    matched_pmk.zeroize();
                    kck.zeroize();
                    kek.zeroize();
                    tk.zeroize();
                    return;
                }
            }
        } else {
            ek.key_data.clone()
        };
        let unpadded_len = dot11::trim_key_data_padding(&m2_key_data).len();
        m2_key_data.truncate(unpadded_len);
        let assoc_ies = self
            .stations
            .get(&sta)
            .map(|s| s.assoc_ies.as_slice())
            .unwrap_or(&[]);
        if !message_2_security_matches(assoc_ies, &m2_key_data) {
            m2_key_data.zeroize();
            matched_pmk.zeroize();
            kck.zeroize();
            kek.zeroize();
            tk.zeroize();
            return;
        }

        // Pin the matched password to this station so m3 retransmits and GTK
        // rekeys reuse the same PMK.
        if let Some(s) = self.stations.get_mut(&sta) {
            s.set_pmk(Some(matched_pmk));
        }
        matched_pmk.zeroize();

        // Operating Channel Validation: message 2's OCI must match our channel.
        if self.ocv {
            match dot11::parse_oci_kde(&m2_key_data) {
                Some((oc, ch))
                    if ch == self.channel
                        && dot11::oci_class_matches_band(oc, self.channel, self.band6) => {}
                _ => {
                    m2_key_data.zeroize();
                    kck.zeroize();
                    kek.zeroize();
                    tk.zeroize();
                    return;
                } // missing or mismatched OCI -> possible MITM, drop
            }
        }
        m2_key_data.zeroize();

        // The first valid M2 consumes the cross-reassociation M1 hold and gets a
        // fresh M3 replay counter. Changed-SNonce retries remain inside this same
        // 4-way and reuse that M3 counter, matching hostapd retry1c/1d.
        if !awaiting_m4 {
            self.pending_anonce.remove(&sta);
        }
        let m3_replay = if awaiting_m4 {
            eapol_replay
        } else {
            self.next_eapol_replay()
        };

        // Retain a bounded set of valid PTK candidates until M4 selects one.
        // Nothing is exposed to the driver until `associated` becomes true.
        {
            let s = self.stations.get_mut(&sta).unwrap();
            if !s
                .ptk_candidates
                .iter()
                .any(|candidate| candidate.m3_replay_counter == m3_replay && candidate.kck == kck)
            {
                if s.ptk_candidates.len() >= 8 {
                    s.ptk_candidates.remove(0);
                }
                s.ptk_candidates.push(PtkCandidate {
                    m3_replay_counter: m3_replay,
                    kck,
                    kek,
                    tk,
                });
            }
            s.eapol_ready = false;
            s.client_pn = 1;
            s.eapol_replay = m3_replay;
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
            Some((
                dot11::operating_class(self.channel, self.channel_width, self.band6),
                self.channel,
            ))
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
        let mld_station = self.mld && client_mld.is_some();
        let m3 = if mld_station {
            let negotiated = self.station_mld_link_ids(&sta);
            let configured = self.active_mld_links();
            let link_kdes: Vec<(u8, [u8; 6], &[u8])> = configured
                .iter()
                .filter(|link| negotiated.contains(&link.link_id))
                .map(|link| (link.link_id, link.mac, ap_rsn.as_slice()))
                .collect();
            dot11::build_eapol_m3_mld_links(
                &self.mac,
                &sta,
                &anonce,
                &kck,
                &kek,
                &self.mld_mac,
                &link_kdes,
                gtk_key_id,
                &gtk,
                igtk,
                bigtk,
                oci,
                m3_replay,
                sc,
                dot11::KeyMic::select(sha256, owe),
            )
        } else {
            dot11::build_eapol_m3(
                &self.mac,
                &sta,
                &anonce,
                &kck,
                &kek,
                &ap_rsn,
                gtk_key_id,
                &gtk,
                igtk,
                bigtk,
                oci,
                m3_replay,
                sc,
                dot11::KeyMic::select(sha256, owe),
            )
        };
        // Keys are derived and m3 is sent, but the station is not authorized
        // until its m4 ACK verifies (see the top of `handle_eapol`). Cache m3 so
        // it can be retransmitted if m4 is lost (m2 arrived, so the m1 cache is
        // replaced by m3).
        if let Some(s) = self.stations.get_mut(&sta) {
            s.awaiting_m4 = true;
            s.pending_eapol = Some(prepend_radiotap(m3.clone()));
            s.eapol_tx = Instant::now();
            s.eapol_retries = 0;
            s.eapol_acked = false;
        }
        kck.zeroize();
        kek.zeroize();
        tk.zeroize();
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

        let sec = self.mld_data_rx_sec_addrs(&sta, frame);
        match dot11::decrypt_ccmp_sec(frame, &tk, false, sec) {
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

        let (key_id, pn, tk, a1, qos_tid, sec_addrs) = if is_multicast(&dst) || is_broadcast(&dst) {
            let pn = self.next_group_pn();
            // Group-addressed: encrypt at the current GTK key index (toggles
            // 1<->2 on rekey), the same index advertised in the GTK KDE and
            // installed in the kernel, so receivers select the matching key.
            (self.gtk_key_id, pn, self.gtk, dst, None, None)
        } else {
            match self.stations.get(&dst) {
                Some(s) if s.associated => {}
                _ => return frames,
            }
            let s = self.stations.get_mut(&dst).unwrap();
            let pn = s.next_client_pn();
            // QoS Data to a WMM station, with the user priority derived from the
            // packet's DSCP (so voice/video/etc. land in the right access category).
            let qos = if s.wmm {
                Some(dot11::wmm_tid(eth))
            } else {
                None
            };
            let tk = s.tk;
            let sec = self.mld_data_tx_sec_addrs(&dst, &src);
            (0u8, pn, tk, dst, qos, sec)
        };

        let sc = self.next_sc();
        let frame = match sec_addrs {
            Some((sec_a1, sec_a2, sec_a3)) => dot11::build_ccmp_data_sec(
                &a1,
                &self.mac,
                &src,
                &sec_a1,
                &sec_a2,
                &sec_a3,
                dot11::FC_FROMDS | dot11::FC_PROTECTED,
                sc,
                pn,
                key_id,
                &tk,
                ethertype,
                inner,
                qos_tid,
            ),
            None => dot11::build_ccmp_data(
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
            ),
        };
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
            if let Some(tk) = self.installed_tk(&sta) {
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
                if let Some(plain) =
                    dot11::decrypt_ccmp_mgmt_sec(frame, &tk, self.mld_mgmt_rx_sec_addrs(&sta))
                {
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
    fn handle_action(&mut self, frame: &dot11::Dot11, out: &mut Outgoing) {
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
        let Some(tk) = self.installed_tk(&sta) else {
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
        let Some(plain) =
            dot11::decrypt_ccmp_mgmt_sec(frame, &tk, self.mld_mgmt_rx_sec_addrs(&sta))
        else {
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
                out.tx(dot11::build_protected_sa_query_sec(
                    &self.mac, &sta, false, true, trans, sc, pn, &tk, sec,
                ));
            }
        }
    }

    /// The kernel reported an 802.11 ACK (`CONTROL_PORT_FRAME_TX_STATUS`) for
    /// EAPOL message 1. Like hostapd, stretch the short initial timeout to the
    /// normal interval from the ACK time. Message 3 keeps its short first timeout.
    pub fn note_eapol_acked(&mut self, sta: &[u8; 6]) {
        if let Some(s) = self.stations.get_mut(sta) {
            if !s.awaiting_m4 && !s.group_rekeying {
                s.eapol_acked = true;
                s.eapol_tx = Instant::now();
            }
        }
    }

    /// The transport held the first EAPOL-Key frame until the successful
    /// Association Response was acknowledged and is releasing it now. Start the
    /// retry clock at the real transmission time instead of when the AP state
    /// machine originally produced the frame.
    pub fn note_eapol_transmitted(&mut self, sta: &[u8; 6]) {
        if let Some(s) = self.stations.get_mut(sta) {
            s.eapol_tx = Instant::now();
            s.eapol_retries = 0;
            s.eapol_acked = false;
        }
    }

    /// The successful Association Response was not acknowledged. The netlink
    /// transport removes the kernel station in this case, so cancel the 4-way
    /// work that was prepared speculatively before the response was sent. Keep
    /// the authentication/ANonce state so a retransmitted association request
    /// can restart cleanly without racing an obsolete EAPOL retry.
    pub fn note_assoc_response_not_acked(&mut self, sta: &[u8; 6]) {
        if let Some(s) = self.stations.get_mut(sta) {
            s.pending_eapol = None;
            s.eapol_ready = false;
            s.awaiting_m4 = false;
            s.ptk_candidates.clear();
            s.kck.zeroize();
            s.kek.zeroize();
            s.tk.zeroize();
            s.eapol_retries = 0;
            s.eapol_acked = false;
        }
    }

    /// Whether a station has completed the handshake.
    pub fn is_associated(&self, sta: &[u8; 6]) -> bool {
        self.stations
            .get(sta)
            .map(|s| s.associated)
            .unwrap_or(false)
    }

    /// Periodic maintenance for handshake reliability: retransmit any pending
    /// EAPOL m1/m3 whose m2/m4 hasn't arrived within [`EAPOL_TIMEOUT`], and
    /// deauthenticate (and drop) a station whose 4-way still hasn't completed
    /// after [`MAX_EAPOL_RETRIES`]. The transport calls this on its tick so a
    /// single dropped handshake frame self-heals instead of stalling forever.
    pub fn tick(&mut self) -> Outgoing {
        let mut out = Outgoing::default();
        let now = Instant::now();
        self.pending_anonce
            .retain(|_, pending| now.duration_since(pending.created_at) < ANONCE_HOLD);
        let stale_sae: Vec<[u8; 6]> = self
            .stations
            .iter()
            .filter(|(_, s)| {
                !s.associated
                    && s.sae.is_some()
                    && now.duration_since(s.last_activity) >= SAE_AUTH_TIMEOUT
            })
            .map(|(mac, _)| *mac)
            .collect();
        for mac in stale_sae {
            self.disconnect(&mac, 15);
        }
        self.expire_pmksa();

        // Key lifecycle: a queued strict rekey (a station left) or the periodic
        // `wpa_group_rekey` interval triggers a Group Key Handshake. rekey_gtk()
        // coalesces if one is already in flight, and arms each msg 1 for
        // retransmit through the loop below.
        let periodic = self.group_rekey_secs > 0
            && now.duration_since(self.last_group_rekey)
                >= Duration::from_secs(self.group_rekey_secs)
            && self.stations.values().any(|s| s.associated);
        if self.group_rekey_due || periodic {
            self.group_rekey_due = false;
            out.frames.extend(self.rekey_gtk());
        }

        let mut timed_out: Vec<[u8; 6]> = Vec::new();
        for (mac, s) in self.stations.iter_mut() {
            let Some(frame) = s.pending_eapol.as_ref() else {
                continue;
            };
            // The first message-1 attempt gets the authenticator's short retry
            // timeout. An ACK stretches that first timeout to the normal interval,
            // and every later attempt also waits the normal interval. Do not
            // aggressively enqueue a new copy merely because TX status is still
            // pending: ath12k can report status late, and the old 40-ms loop filled
            // its queue with 31 stale m1/m3 copies before the first status arrived.
            let timeout = if s.eapol_retries == 0 && !s.eapol_acked {
                EAPOL_FIRST_TIMEOUT
            } else {
                EAPOL_TIMEOUT
            };
            if now.duration_since(s.eapol_tx) < timeout {
                continue;
            }
            if s.eapol_retries >= MAX_EAPOL_RETRIES {
                eprintln!(
                    "AP: {} timeout for {} after {} retries",
                    if s.group_rekeying {
                        "group-key handshake"
                    } else if s.awaiting_m4 {
                        "4-way message 3"
                    } else {
                        "4-way message 1"
                    },
                    crate::util::bytes_to_mac(mac),
                    s.eapol_retries,
                );
                timed_out.push(*mac);
            } else {
                out.frames.push(frame.clone()); // already radiotap-prefixed
                s.eapol_tx = now;
                s.eapol_retries += 1;
                s.eapol_acked = false; // awaiting the ACK for this resend
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
        self.last_group_rekey = Instant::now()
            .checked_sub(ago)
            .unwrap_or(self.last_group_rekey);
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

    /// Test hook: age every incomplete SAE exchange past its authentication
    /// timeout so the next maintenance tick removes it.
    #[doc(hidden)]
    pub fn test_expire_incomplete_sae(&mut self) {
        let past = Instant::now() - SAE_AUTH_TIMEOUT - Duration::from_millis(1);
        for station in self.stations.values_mut() {
            if station.sae.is_some() && !station.sae_confirmed {
                station.last_activity = past;
            }
        }
    }

    /// Test hook: advance the token epoch beyond its accepted lifetime.
    #[doc(hidden)]
    pub fn test_expire_sae_tokens(&mut self) {
        self.boottime -= SAE_TOKEN_LIFETIME + Duration::from_secs(1);
    }

    /// Insert a PMK into the PMKSA cache, evicting one entry when at capacity so
    /// the cache stays bounded ([`PMKSA_CACHE_MAX`]) instead of growing forever.
    fn cache_pmksa(&mut self, id: [u8; 16], identity: [u8; 6], pmk: [u8; 32], sha256: bool) {
        self.expire_pmksa();
        let key = (id, identity);
        if self.pmksa_cache.len() >= PMKSA_CACHE_MAX && !self.pmksa_cache.contains_key(&key) {
            if let Some(victim) = self.pmksa_cache.keys().next().copied() {
                self.pmksa_cache.remove(&victim);
            }
        }
        self.pmksa_cache.insert(
            key,
            PmksaEntry {
                identity,
                pmk,
                sha256,
                expires_at: Instant::now() + PMKSA_LIFETIME,
            },
        );
    }

    fn expire_pmksa(&mut self) {
        let now = Instant::now();
        self.pmksa_cache
            .retain(|(_, identity), entry| *identity == entry.identity && entry.expires_at > now);
    }

    /// Test hook: insert a dummy PMKSA entry (exercises the cache bound).
    #[doc(hidden)]
    pub fn test_cache_pmksa(&mut self, id: [u8; 16]) {
        let mut identity = [0u8; 6];
        identity.copy_from_slice(&id[..6]);
        self.cache_pmksa(id, identity, [0u8; 32], true);
    }

    /// Test hook: expire every cached PMKSA entry.
    #[doc(hidden)]
    pub fn test_expire_pmksa(&mut self) {
        let expired = Instant::now() - Duration::from_millis(1);
        for entry in self.pmksa_cache.values_mut() {
            entry.expires_at = expired;
        }
        self.expire_pmksa();
    }

    /// Number of cached PMKSA entries (for tests).
    #[doc(hidden)]
    pub fn pmksa_len(&self) -> usize {
        self.pmksa_cache.len()
    }

    fn record_failure(&mut self, sta: &[u8; 6], kind: crate::failures::FailureKind) {
        let traits = self.stations.get(sta).map(|s| s.traits).unwrap_or(0);
        let count = self.failures.record(*sta, traits, kind);
        self.events.push(ApEvent::AuthFailed {
            mac: *sta,
            kind,
            count,
        });
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
                self.events.push(ApEvent::Disconnected {
                    mac: s.client_mld_mac.unwrap_or(*sta),
                    reason,
                });
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

    /// Listen interval advertised in the station's latest association request.
    pub fn station_listen_interval(&self, sta: &[u8; 6]) -> Option<u16> {
        self.stations.get(sta).map(|s| s.listen_interval)
    }

    pub fn station_capability(&self, sta: &[u8; 6]) -> Option<u16> {
        self.stations.get(sta).map(|s| s.capability)
    }

    /// The station's MLD MAC, when this link-addressed station authenticated as
    /// a non-AP MLD.
    pub fn station_mld_mac(&self, sta: &[u8; 6]) -> Option<[u8; 6]> {
        self.stations.get(sta).and_then(|s| s.client_mld_mac)
    }

    pub fn station_mld_link_macs(&self, sta: &[u8; 6]) -> Vec<(u8, [u8; 6])> {
        self.stations
            .get(sta)
            .map(|s| s.client_mld_links.clone())
            .unwrap_or_default()
    }

    /// MLD links negotiated by this station, including the association link.
    /// Group keys are installed and delivered per link even though the compact
    /// userspace key model currently uses one per-station GTK value.
    pub fn station_mld_link_ids(&self, sta: &[u8; 6]) -> Vec<u8> {
        let Some(s) = self.stations.get(sta) else {
            return Vec::new();
        };
        if !self.mld || s.client_mld_mac.is_none() {
            return Vec::new();
        }
        let mut ids = vec![self.link_id];
        for (link_id, _) in &s.client_mld_links {
            if !ids.contains(link_id)
                && self
                    .mld_links
                    .iter()
                    .any(|configured| configured.link_id == *link_id)
            {
                ids.push(*link_id);
            }
        }
        ids.sort_unstable();
        ids
    }

    /// Find the link-addressed station entry that corresponds to a STA MLD MAC.
    pub fn station_link_for_mld(&self, mld: &[u8; 6]) -> Option<[u8; 6]> {
        self.stations
            .iter()
            .find_map(|(link, s)| (s.client_mld_mac.as_ref() == Some(mld)).then_some(*link))
    }

    /// Resolve any address belonging to a non-AP MLD (its MLD MAC, association
    /// link MAC, or an affiliated partner-link MAC) to the single association-
    /// link station record used by the userspace MLME. This mirrors hostapd's
    /// MLO address translation and prevents one client from being treated as
    /// several independent stations as it sends frames on different links.
    pub fn station_link_for_peer(&self, peer: &[u8; 6]) -> Option<[u8; 6]> {
        if self.stations.contains_key(peer) {
            return Some(*peer);
        }
        self.stations.iter().find_map(|(link, s)| {
            (s.client_mld_mac.as_ref() == Some(peer)
                || s.client_mld_links.iter().any(|(_, mac)| mac == peer))
            .then_some(*link)
        })
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
        self.stations
            .get(sta)
            .filter(|s| s.associated)
            .map(|s| s.tk)
    }

    /// The session TK for a station (test/inspection helper).
    pub fn station_tk(&self, sta: &[u8; 6]) -> Option<[u8; 16]> {
        self.stations.get(sta).map(|s| s.tk)
    }

    /// 802.11v: send a (CCMP-protected) BSS Transition Management request, e.g.
    /// to steer or kick a station (`disassoc_imminent`).
    pub fn btm_request(
        &mut self,
        sta: &[u8; 6],
        disassoc_imminent: bool,
        disassoc_timer: u16,
    ) -> Option<Vec<u8>> {
        let tk = self.installed_tk(sta)?;
        let pn = self.stations.get_mut(sta)?.next_client_pn();
        let sc = self.next_sc();
        let sec = self.mld_mgmt_tx_sec_addrs(sta);
        let frame = dot11::build_protected_btm_request_sec(
            &self.mac,
            sta,
            1,
            disassoc_imminent,
            disassoc_timer,
            sc,
            pn,
            &tk,
            sec,
        );
        Some(prepend_radiotap(frame))
    }

    /// 802.11k: send a (CCMP-protected) Neighbor Report Response listing this AP.
    pub fn neighbor_report(&mut self, sta: &[u8; 6]) -> Option<Vec<u8>> {
        let tk = self.installed_tk(sta)?;
        let pn = self.stations.get_mut(sta)?.next_client_pn();
        let sc = self.next_sc();
        let op_class = if dot11::is_5ghz(self.channel) {
            115
        } else {
            81
        };
        let neighbor = dot11::neighbor_report_element(&self.mac, op_class, self.channel);
        let sec = self.mld_mgmt_tx_sec_addrs(sta);
        let frame = dot11::build_protected_neighbor_report_sec(
            &self.mac, sta, 1, &neighbor, sc, pn, &tk, sec,
        );
        Some(prepend_radiotap(frame))
    }

    /// Build a CCMP-protected unicast Deauthentication toward a PMF station.
    pub fn protected_deauth(&mut self, sta: &[u8; 6], reason: u16) -> Option<Vec<u8>> {
        let tk = self.installed_tk(sta)?;
        let pn = self.stations.get_mut(sta)?.next_client_pn();
        let sc = self.next_sc();
        let sec = self.mld_mgmt_tx_sec_addrs(sta);
        let frame = dot11::build_protected_deauth_sec(&self.mac, sta, reason, sc, pn, &tk, sec);
        let mut f = dot11::RADIOTAP_TX.to_vec();
        f.extend_from_slice(&frame);
        Some(f)
    }

    /// Disassociate stations idle longer than `max_idle` (hostapd
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
        let mut gtk_full = random_bytes::<32>();
        self.gtk.zeroize();
        self.gtk.copy_from_slice(&gtk_full[..16]);
        gtk_full.zeroize();
        self.group_pn = 1;
        // Two-phase group rekey (hostapd): the rotated GTK/IGTK go in at the
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
    fn rekey_gtk_per_sta(&mut self) -> Vec<Vec<u8>> {
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

impl Drop for Ap {
    fn drop(&mut self) {
        self.pmk.zeroize();
        for (_, pmk) in &mut self.psk_candidates {
            pmk.zeroize();
        }
        for (_, password) in &mut self.credential_passwords {
            password.zeroize();
        }
        self.password.zeroize();
        self.gtk.zeroize();
        self.igtk.zeroize();
        self.bigtk.zeroize();
        self.sae_token_key.zeroize();
        if let Some(anonce) = self.test_anonce.as_mut() {
            anonce.zeroize();
        }
    }
}
