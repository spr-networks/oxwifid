//! Access-point state and orchestration.
//!
//! Incoming 802.11 frames are fed to [`Ap::handle_incoming`], which mutates
//! state and returns frames to transmit plus decrypted Ethernet packets for the
//! AP network stack. Protocol-specific behavior lives in the focused child
//! modules; this facade owns shared state and the stable public API.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

use crate::auth::{crypto, wpa3::sae};
use crate::frames as dot11;

/// Per-station auth/assoc backoff (matches `BACKOFF = 0.25`).
const BACKOFF: Duration = Duration::from_millis(250);
const REQUEST_RATE_WINDOW: Duration = Duration::from_secs(1);
const AUTH_REQUEST_BURST: u16 = 16;
const ASSOC_REQUEST_BURST: u16 = 8;
const REQUEST_RATE_ENTRY_MAX: usize = 1024;

/// Retransmit a pending EAPOL m1/m3 if its m2/m4 hasn't arrived within this long
/// (reference AP's `eapol_key_timeout_subseq`), up to [`MAX_EAPOL_RETRIES`] times
/// before giving up and deauthenticating.
const EAPOL_TIMEOUT: Duration = Duration::from_millis(1000);
/// The *first* retransmit fires much sooner, mirroring reference AP's
/// `eapol_key_timeout_first = 100 ms`. This matters on real hardware: an m1 sent
/// the instant the STA associates can be dropped before the driver has the
/// station fully set up for downlink control-port TX. Waiting a full second to
/// resend lets the client's own post-association 4-way timer fire first — it then
/// deauthenticates and reconnects, and because each reconnect mints a fresh
/// ANonce, the client's Message 2 ends up keyed to a stale m1's ANonce and the
/// MIC never verifies (a self-sustaining livelock seen on ath12k). Resending
/// within ~100 ms lands a second m1 (identical ANonce) inside the *same*
/// association, exactly as reference AP does, so the handshake completes.
const EAPOL_FIRST_TIMEOUT: Duration = Duration::from_millis(100);
/// Match the normal authenticator retry budget. In particular, do not use a
/// large retry count to compensate for a slow hardware TX-status event: every
/// retry is another real frame queued in the driver, and flooding that queue can
/// put message 3 behind dozens of stale message-1 copies.
/// reference AP's default dot11RSNAConfigPairwiseUpdateCount is four total sends:
/// the initial message plus three retransmissions.
const MAX_EAPOL_RETRIES: u8 = 3;

/// How long an associated PMF station has to answer the SA Query provoked by an
/// unprotected Authentication or (Re)Association Request bearing its address
/// (IEEE 802.11 `dot11AssociationSAQueryMaximumTimeout`, 1000 TU). If it stays
/// silent the association really is stale and is torn down, so a genuine
/// reconnect is delayed by ~1 s rather than blocked; if it answers, the spoofed
/// frame is discarded without disturbing the session.
const SA_QUERY_TIMEOUT: Duration = Duration::from_millis(1024);

/// How long an unconsumed message-1 ANonce/replay pair is held for a reconnecting
/// station. The pair is destroyed as soon as message 2 verifies, before either
/// peer can install the PTK.
const ANONCE_HOLD: Duration = Duration::from_secs(10);

/// Cap on the PMKSA (fast-reconnect PMK) cache. reference AP bounds + expires these;
/// we cap the size so the cache can't grow without bound over a long uptime with
/// many distinct clients. An evicted client simply re-runs the full SAE/auth.
const PMKSA_CACHE_MAX: usize = 256;
/// IEEE 802.11's default PMKSA lifetime (12 hours).
const PMKSA_LIFETIME: Duration = Duration::from_secs(12 * 60 * 60);
/// Require an SAE anti-clogging token once this many exchanges are incomplete.
const SAE_ANTI_CLOGGING_THRESHOLD: usize = 5;
/// Absolute cap even for peers that returned a valid anti-clogging token.
const SAE_INCOMPLETE_MAX: usize = 64;
const MAX_PACKET_NUMBER: u64 = 0x0000_ffff_ffff_ffff;
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

struct RequestRate {
    auth_window: Instant,
    auth_count: u16,
    assoc_window: Instant,
    assoc_count: u16,
    last_seen: Instant,
}

impl RequestRate {
    fn new(now: Instant) -> RequestRate {
        RequestRate {
            auth_window: now,
            auth_count: 0,
            assoc_window: now,
            assoc_count: 0,
            last_seen: now,
        }
    }
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

struct SaeCommitJob {
    id: u64,
    sta: [u8; 6],
    h2e: bool,
    ssid: Vec<u8>,
    password: Vec<u8>,
    sae_ap: [u8; 6],
    sae_sta: [u8; 6],
    peer_mld: Option<[u8; 6]>,
    commit_payload: Vec<u8>,
}

impl Drop for SaeCommitJob {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

enum SaeCommitOutcome {
    Complete {
        sae: Box<sae::Sae>,
        commit_body: Vec<u8>,
        confirm_body: Vec<u8>,
        rejected_groups: Vec<u16>,
    },
    Reflection,
    Failed(String),
}

struct SaeCommitResult {
    id: u64,
    sta: [u8; 6],
    h2e: bool,
    peer_mld: Option<[u8; 6]>,
    commit_payload: Vec<u8>,
    outcome: SaeCommitOutcome,
}

struct PendingSaeCommit {
    id: u64,
    commit_payload: Vec<u8>,
    queued_at: Instant,
    pending_confirm: Option<Vec<u8>>,
}

struct AsyncSae {
    jobs: mpsc::SyncSender<SaeCommitJob>,
    results: mpsc::Receiver<SaeCommitResult>,
    pending: HashMap<[u8; 6], PendingSaeCommit>,
    next_id: u64,
}

#[derive(Clone)]
struct PtkCandidate {
    m3_replay_counter: u64,
    kck: [u8; 16],
    kek: [u8; 16],
    tk: [u8; 32],
}

pub(crate) struct PreparedPskFile {
    candidates_by_mac: HashMap<[u8; 6], Vec<[u8; 32]>>,
    wildcard_candidates: Vec<[u8; 32]>,
    passwords_by_mac: HashMap<[u8; 6], Vec<u8>>,
    wildcard_password: Option<Vec<u8>>,
}

impl PreparedPskFile {
    pub(crate) fn derive(ssid: &[u8], entries: &[(Option<[u8; 6]>, String)]) -> PreparedPskFile {
        let ssid = String::from_utf8_lossy(ssid);
        let mut prepared = PreparedPskFile {
            candidates_by_mac: HashMap::new(),
            wildcard_candidates: Vec::new(),
            passwords_by_mac: HashMap::new(),
            wildcard_password: None,
        };
        for (mac, pass) in entries {
            let pmk = crypto::pbkdf2_pmk(pass, &ssid);
            match mac {
                Some(mac) => {
                    prepared
                        .candidates_by_mac
                        .entry(*mac)
                        .or_default()
                        .push(pmk);
                    // SAE must choose before a MIC can identify among duplicate
                    // entries, matching the prior first-entry behavior.
                    prepared
                        .passwords_by_mac
                        .entry(*mac)
                        .or_insert_with(|| pass.as_bytes().to_vec());
                }
                None => {
                    prepared.wildcard_candidates.push(pmk);
                    if prepared.wildcard_password.is_none() {
                        prepared.wildcard_password = Some(pass.as_bytes().to_vec());
                    }
                }
            }
        }
        prepared
    }
}

impl Drop for PreparedPskFile {
    fn drop(&mut self) {
        for candidates in self.candidates_by_mac.values_mut() {
            candidates.zeroize();
        }
        self.wildcard_candidates.zeroize();
        for password in self.passwords_by_mac.values_mut() {
            password.zeroize();
        }
        if let Some(password) = self.wildcard_password.as_mut() {
            password.zeroize();
        }
    }
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
    /// Full negotiated pairwise TK. The first 16 bytes mirror `tk` for the
    /// legacy userspace CCMP-128 path; Linux netlink offload consumes 16 or 32
    /// bytes according to `Ap::pairwise_cipher`.
    pairwise_tk: [u8; 32],
    pub client_pn: u64,
    /// Highest received CCMP packet number (replay protection). CCMP replay
    /// counters are per traffic identifier — a transmitter keeps one PN sequence
    /// per TID, so a single shared counter would drop legitimate frames whenever
    /// two access categories interleave. Slots 0-15 are QoS TIDs; slot 16 is the
    /// non-QoS replay domain.
    pub last_rx_pn: [u64; 17],
    /// Highest received CCMP PN for protected management frames (separate replay
    /// counter, so a captured protected Deauth/Disassoc/Action can't be replayed).
    pub last_rx_mgmt_pn: u64,
    /// EAPOL-Key replay counter for downlink key messages (m1=1, m3=2, rekeys 3+).
    pub eapol_replay: u64,
    /// Replay counter from the message 1 this 4-way is answering. It remains
    /// valid while awaiting M4 so reference AP-compatible changed-SNonce M2 retries
    /// can be evaluated without regressing to a new handshake.
    m1_replay: u64,
    /// PTKs derived from valid M2 retries in this one 4-way. They are not exposed
    /// to the driver until one candidate's M4 verifies.
    ptk_candidates: Vec<PtkCandidate>,
    pub last_auth: Option<Instant>,
    pub last_assoc: Option<Instant>,
    /// In-progress SAE exchange (WPA3); `None` for WPA2/PSK stations.
    pub sae: Option<sae::Sae>,
    /// PMK established by SAE; when set it overrides the AP's PSK-derived PMK.
    pub pmk: Option<[u8; 32]>,
    pub sae_confirmed: bool,
    /// The completed SAE exchange selected Hash-to-Element and therefore
    /// requires the association request to carry the SAE H2E RSNXE bit.
    pub sae_h2e: bool,
    /// SHA-256 key hierarchy: the PTK comes from the SHA-256 KDF rather than
    /// PRF-512. True for WPA3-SAE, OWE, and PSK-SHA256 stations. This says
    /// nothing about management-frame protection — see `pmf`.
    pub sha256: bool,
    /// OWE station: the EAPOL-Key MIC is HMAC-SHA256 (not SAE's AES-CMAC).
    pub owe: bool,
    /// PSK-SHA256 station (AKM 00-0F-AC:6): SHA-256 PTK with an AES-128-CMAC
    /// key MIC at Key Descriptor Version 3.
    pub psk_sha256: bool,
    /// Management frame protection is in force for this station, so it must be
    /// given the IGTK, its robust management frames must be protected, and its
    /// association may not be torn down by unprotected Auth/Assoc frames. Set
    /// for SAE and OWE. Deliberately distinct from `sha256`: PSK-SHA256 shares
    /// the SHA-256 key hierarchy without negotiating PMF, so keying the two off
    /// one flag would hand it an IGTK it never asked for and silently claim PMF
    /// guarantees it does not have.
    pub pmf: bool,
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
    /// (via `CONTROL_PORT_FRAME_TX_STATUS`). reference AP extends that message's short
    /// initial timeout after an ACK; message 3 keeps the short first timeout.
    pub eapol_acked: bool,
    /// Generation of the currently armed EAPOL deadline. Heap entries from an
    /// older message/retry are discarded without scanning the station table.
    eapol_timer_generation: u64,
    /// Awaiting this station's Group Key Handshake message 2 (its ACK of a GTK
    /// rekey). Cleared on msg 2; while any station has it set, a fresh rekey is
    /// not started (reference AP coalesces — `GKeyDoneStations`).
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
    /// The affiliated AP link this station associated on. This is recorded for
    /// both MLD peers and legacy single-link stations on an AP MLD. MLD peers
    /// need it to key every held link; legacy peers need its BSSID for PTK
    /// derivation. M2/M3 arrive over the control port, where the per-frame RX
    /// link is not always available.
    pub assoc_link_id: Option<u8>,
    /// Cached SAE commit+confirm auth-response frames, resent verbatim when the
    /// STA retries an identical commit (a lost response on a flaky medium), so
    /// the exchange recovers instead of resetting our scalar and desyncing into
    /// an authentication loop.
    pub sae_resp: Vec<Vec<u8>>,
    /// The peer SAE commit payload we last answered — recognizes an identical
    /// retry vs. a genuinely fresh commit.
    pub sae_commit: Vec<u8>,
    /// The transaction identifier and start time of the SA Query provoked by an
    /// unprotected Authentication or (Re)Association Request, if one is
    /// outstanding. Cleared by a protected SA Query Response carrying that same
    /// identifier; if it is still set after [`SA_QUERY_TIMEOUT`] the station is
    /// presumed gone and torn down.
    pub sa_query: Option<(u16, Instant)>,
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
            pairwise_tk: [0; 32],
            client_mld_mac: None,
            client_mld_links: Vec::new(),
            assoc_link_id: None,
            sae_resp: Vec::new(),
            sae_commit: Vec::new(),
            client_pn: 1, // CCMP PN starts at 1
            last_rx_pn: [0; 17],
            last_rx_mgmt_pn: 0,
            sa_query: None,
            eapol_replay: 0,
            m1_replay: 0,
            ptk_candidates: Vec::new(),
            last_auth: None,
            last_assoc: None,
            sae: None,
            pmk: None,
            sae_confirmed: false,
            sae_h2e: false,
            sha256: false,
            owe: false,
            psk_sha256: false,
            pmf: false,
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
            eapol_timer_generation: 0,
            group_rekeying: false,
        }
    }

    fn next_client_pn(&mut self) -> Option<u64> {
        if self.client_pn > MAX_PACKET_NUMBER {
            return None;
        }
        let pn = self.client_pn;
        self.client_pn += 1;
        Some(pn)
    }

    /// The EAPOL-Key MIC algorithm (and Key Descriptor Version) this station's
    /// AKM selects. Derived from the negotiation flags rather than stored, so it
    /// can never fall out of step with them.
    fn key_mic(&self) -> dot11::KeyMic {
        if !self.sha256 {
            dot11::KeyMic::HmacSha1
        } else if self.owe {
            dot11::KeyMic::HmacSha256
        } else if self.psk_sha256 {
            dot11::KeyMic::AesCmacV3
        } else {
            dot11::KeyMic::AesCmac
        }
    }

    fn set_pmk(&mut self, pmk: Option<[u8; 32]>) {
        if let Some(old) = self.pmk.as_mut() {
            old.zeroize();
        }
        self.pmk = pmk;
    }
}

fn allow_request(window: &mut Instant, count: &mut u16, burst: u16, now: Instant) -> bool {
    if now.duration_since(*window) >= REQUEST_RATE_WINDOW {
        *window = now;
        *count = 0;
    }
    if *count >= burst {
        return false;
    }
    *count += 1;
    true
}

impl Ap {
    fn request_rate_entry(&mut self, sta: [u8; 6], now: Instant) -> Option<&mut RequestRate> {
        if !self.request_rates.contains_key(&sta)
            && self.request_rates.len() >= REQUEST_RATE_ENTRY_MAX
        {
            self.request_rates
                .retain(|_, rate| now.duration_since(rate.last_seen) < REQUEST_RATE_WINDOW);
            if self.request_rates.len() >= REQUEST_RATE_ENTRY_MAX {
                return None;
            }
        }
        let rate = self
            .request_rates
            .entry(sta)
            .or_insert_with(|| RequestRate::new(now));
        rate.last_seen = now;
        Some(rate)
    }

    fn allow_auth_request(&mut self, sta: [u8; 6], now: Instant) -> bool {
        let Some(rate) = self.request_rate_entry(sta, now) else {
            return false;
        };
        allow_request(
            &mut rate.auth_window,
            &mut rate.auth_count,
            AUTH_REQUEST_BURST,
            now,
        )
    }

    fn allow_assoc_request(&mut self, sta: [u8; 6], now: Instant) -> bool {
        let Some(rate) = self.request_rate_entry(sta, now) else {
            return false;
        };
        allow_request(
            &mut rate.assoc_window,
            &mut rate.assoc_count,
            ASSOC_REQUEST_BURST,
            now,
        )
    }
}

impl Drop for Station {
    fn drop(&mut self) {
        self.kck.zeroize();
        self.kek.zeroize();
        self.tk.zeroize();
        self.pairwise_tk.zeroize();
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
/// mirrors reference AP's `AP-STA-*` control events.
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
    /// Render as a reference AP-style control line, e.g. `AP-STA-CONNECTED 02:..:01`.
    pub fn to_line(&self) -> String {
        use crate::util::bytes_to_mac;
        match self {
            ApEvent::Connected { mac } => format!("AP-STA-CONNECTED {}", bytes_to_mac(mac)),
            ApEvent::Disconnected { mac, reason } => {
                format!("AP-STA-DISCONNECTED {} reason={reason}", bytes_to_mac(mac))
            }
            // SPR's reference AP action scripts consume TYPE and REASON as the two
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
    /// Negotiated RSN pairwise cipher. Group traffic remains CCMP-128.
    pairwise_cipher: dot11::DataCipher,
    pub pmk: [u8; 32],
    /// Credential-file PMKs indexed before the radio starts (or on the reload
    /// worker). Message 2 lookup is O(matches) rather than scanning every device
    /// credential on the radio loop.
    psk_candidates_by_mac: HashMap<[u8; 6], Vec<[u8; 32]>>,
    wildcard_psk_candidates: Vec<[u8; 32]>,
    /// The passphrases behind `psk_candidates`, retained so the same SPR
    /// per-device credential file can select an SAE password by station MAC.
    /// SAE has to choose its password before replying to the peer's commit, so
    /// unlike WPA2 it cannot discover the matching credential from message 2's
    /// MIC later in the exchange.
    credential_passwords_by_mac: HashMap<[u8; 6], Vec<u8>>,
    wildcard_credential_password: Option<Vec<u8>>,
    /// A configured credential file is the complete access-control database.
    /// Never fall back to the JSON/CLI passphrase when it is true, including
    /// when the file is empty or unreadable (fail closed).
    credential_file_authoritative: bool,
    /// A control-plane credential reload is being derived off-thread. New
    /// authentications fail closed until the prepared database is installed.
    credential_reload_pending: bool,
    /// Passphrase, retained for WPA3-SAE PWE derivation.
    password: Vec<u8>,
    /// When true, accept WPA3-SAE (H2E) authentication.
    sae_enabled: bool,
    /// When true, the BSS additionally offers the PSK-SHA256 AKM (00-0F-AC:6).
    psk_sha256: bool,
    /// When true, advertise WPA2/WPA3 transition mode (mixed PSK + SAE).
    transition: bool,
    boottime: Instant,
    sc: i32,
    aid: u16,
    group_pn: u64,
    gtk: [u8; 16],
    /// GTK key id (CCMP key index). Toggles 1<->2 on each group rekey so a fresh
    /// GTK gets a fresh index (reference AP's two-phase group rekey); stations and the
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
    /// Guest BSS: client isolation. The AP never carries traffic between its
    /// own stations — the kernel data path gets `NL80211_ATTR_AP_ISOLATE` and
    /// the userspace data path drops station-to-station deliveries.
    guest: bool,
    /// The BSS credential is a static guest password (SPR `GuestPassword`):
    /// the device credential database never applies to this BSS, so
    /// `set_psk_file` — including a control-socket RELOAD — is a no-op. The
    /// reference AP equivalent is `wpa_psk_file=/dev/null` + `wpa_passphrase`.
    static_credential: bool,
    /// The affiliated link the management frame being processed arrived on
    /// (netlink MLD path; set per frame by the driver loop). A probe response
    /// must be built entirely for THIS link — its channel/band IEs, its own
    /// MLE Link ID, and an RNR naming its partners — otherwise an MLO client
    /// sees the response contradict the link's beacon and quietly falls back
    /// to a single-link association.
    mgmt_rx_link: Option<u8>,
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
    /// Earliest expiry among SAE/SA Query/ANonce/PMKSA state. Expensive table
    /// maintenance is performed only when this deadline is reached.
    maintenance_deadline: Option<Instant>,
    /// Per-station EAPOL deadlines. Stale entries are invalidated by the
    /// station's generation counter, so the normal radio-loop tick is O(1).
    eapol_deadlines: BinaryHeap<Reverse<(Instant, u64, [u8; 6])>>,
    /// Stations removed from the portable state machine since the transport
    /// last reconciled its kernel/VLAN bookkeeping.
    removed_stations: Vec<[u8; 6]>,
    /// Stations whose four-way handshake just completed and whose keys now need
    /// installation/authorization by the transport.
    key_ready_stations: Vec<[u8; 6]>,
    /// Incremented whenever GTK/IGTK/BIGTK material rotates.
    group_key_epoch: u64,
    /// Optional Linux runtime SAE worker. Unit tests and raw-frame mode retain
    /// the synchronous path unless explicitly enabled.
    async_sae: Option<AsyncSae>,
    /// Process-wide monotonically increasing EAPOL replay counter. It starts at
    /// a random non-zero value so frames from an earlier AP lifetime cannot be
    /// valid in a new lifetime.
    eapol_replay_counter: u64,
    /// Secret for stateless SAE anti-clogging tokens.
    sae_token_key: [u8; 32],
    /// Bounded per-source authentication/association request windows. Kept
    /// outside station state so rejected requests allocate no station.
    request_rates: HashMap<[u8; 6], RequestRate>,
    stations: HashMap<[u8; 6], Station>,
    /// Deduplicated log of failed auth / decryption attempts, fingerprinted by
    /// client (intrusion detection).
    failures: crate::failures::FailureLog,
    /// Queued control events (connect/disconnect/auth-fail) drained by the run
    /// loop / control interface.
    events: Vec<ApEvent>,
    /// GTK rekey period (reference AP `wpa_group_rekey`, default 600 s; 0 disables).
    group_rekey_secs: u64,
    /// Rekey the GTK when an authorized station leaves so it can no longer read
    /// group traffic (reference AP `wpa_strict_rekey`, default on).
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

/// The Key Descriptor Version an EAPOL-Key from this station must carry. It is
/// exactly the version of the MIC algorithm its AKM selects (2 for HMAC-SHA1,
/// 0 for SAE/OWE, 3 for PSK-SHA256).
fn expected_key_descriptor_version(mic: dot11::KeyMic) -> u16 {
    u16::from(mic.version())
}

fn key_info_matches(key_info: u16, expected: u16) -> bool {
    // The two top bits are reserved. Every defined state bit, including
    // Encrypted Key Data, must match the expected handshake message.
    key_info & !0xc000 == expected
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
    let Ok(assoc_rsnxe) = dot11::find_ie_consistent(assoc_ies, 0xf4) else {
        return false;
    };
    let Ok(m2_rsnxe) = dot11::find_ie_consistent(key_data, 0xf4) else {
        return false;
    };
    assoc_rsnxe == m2_rsnxe
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transmit_packet_numbers_stop_at_48_bits() {
        let mac = [0x02, 0, 0, 0, 0, 1];
        let mut station = Station::new(mac);
        station.client_pn = MAX_PACKET_NUMBER;
        assert_eq!(station.next_client_pn(), Some(MAX_PACKET_NUMBER));
        assert_eq!(station.next_client_pn(), None);

        let mut ap = Ap::new("pn-test", "device-password", [0x02, 0, 0, 0, 0, 0], 1);
        ap.group_pn = MAX_PACKET_NUMBER;
        assert_eq!(ap.next_group_pn(), Some(MAX_PACKET_NUMBER));
        assert_eq!(ap.next_group_pn(), None);
    }
}

mod association;
mod beacon;
mod configuration;
mod data;
mod group_keys;
mod handshake;
mod lifecycle;
mod management;
mod mlo;
mod receive;
mod roaming;
mod sae_auth;

impl Drop for Ap {
    fn drop(&mut self) {
        self.pmk.zeroize();
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
