use super::{random_bytes, MAX_PACKET_NUMBER};
use crate::auth::{crypto, wpa3::sae};
use crate::frames as dot11;
use std::collections::HashMap;
use std::time::Instant;
use zeroize::Zeroize;

#[derive(Clone)]
pub(super) struct PtkCandidate {
    pub(super) m3_replay_counter: u64,
    pub(super) kck: [u8; 16],
    pub(super) kek: [u8; 16],
    pub(super) tk: [u8; 32],
}

pub(crate) struct PreparedPskFile {
    pub(super) candidates_by_mac: HashMap<[u8; 6], Vec<[u8; 32]>>,
    pub(super) wildcard_candidates: Vec<[u8; 32]>,
    pub(super) passwords_by_mac: HashMap<[u8; 6], Vec<u8>>,
    pub(super) wildcard_password: Option<Vec<u8>>,
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
    pub(super) pairwise_tk: [u8; 32],
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
    pub(super) m1_replay: u64,
    /// PTKs derived from valid M2 retries in this one 4-way. They are not exposed
    /// to the driver until one candidate's M4 verifies.
    pub(super) ptk_candidates: Vec<PtkCandidate>,
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
    pub(super) eapol_timer_generation: u64,
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
    pub(super) fn new(mac: [u8; 6]) -> Station {
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

    pub(super) fn next_client_pn(&mut self) -> Option<u64> {
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
    pub(super) fn key_mic(&self) -> dot11::KeyMic {
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

    pub(super) fn set_pmk(&mut self, pmk: Option<[u8; 32]>) {
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
        self.pairwise_tk.zeroize();
        self.gtk.zeroize();
        if let Some(pmk) = self.pmk.as_mut() {
            pmk.zeroize();
        }
    }
}
