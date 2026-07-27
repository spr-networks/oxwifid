use super::{ApEvent, AsyncSae, MldLink, PendingHandshake, PmksaEntry, RequestRate, Station};
use crate::frames as dot11;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::time::Instant;
use zeroize::Zeroize;

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
    pub(super) mld_default_link_mask: Option<u16>,
    /// AP-mode EML and MLD capabilities exposed by nl80211 for this driver.
    /// Netlink mode fills these before constructing beacon/response MLEs.
    pub(super) mld_eml_capability: u16,
    pub(super) mld_driver_capability: Option<u16>,
    /// Real, band-specific radio capabilities for each affiliated link.
    /// Partner-link profiles must use these just like the outer response does.
    pub(super) mld_link_phy_capabilities: HashMap<u8, dot11::PhyCapabilities>,
    /// PHY generation advertised on 2.4/5 GHz: ac (VHT), ax (HE), or be (EHT).
    /// 6 GHz is always HE+. Defaults to VHT to match prior behaviour.
    pub(super) phy_mode: dot11::PhyMode,
    /// Negotiated RSN pairwise cipher. Group traffic remains CCMP-128.
    pub(super) pairwise_cipher: dot11::DataCipher,
    pub pmk: [u8; 32],
    /// Credential-file PMKs indexed before the radio starts (or on the reload
    /// worker). Message 2 lookup is O(matches) rather than scanning every device
    /// credential on the radio loop.
    pub(super) psk_candidates_by_mac: HashMap<[u8; 6], Vec<[u8; 32]>>,
    pub(super) wildcard_psk_candidates: Vec<[u8; 32]>,
    /// The passphrases behind `psk_candidates`, retained so the same SPR
    /// per-device credential file can select an SAE password by station MAC.
    /// SAE has to choose its password before replying to the peer's commit, so
    /// unlike WPA2 it cannot discover the matching credential from message 2's
    /// MIC later in the exchange.
    pub(super) credential_passwords_by_mac: HashMap<[u8; 6], Vec<u8>>,
    pub(super) wildcard_credential_password: Option<Vec<u8>>,
    /// A configured credential file is the complete access-control database.
    /// Never fall back to the JSON/CLI passphrase when it is true, including
    /// when the file is empty or unreadable (fail closed).
    pub(super) credential_file_authoritative: bool,
    /// A control-plane credential reload is being derived off-thread. New
    /// authentications fail closed until the prepared database is installed.
    pub(super) credential_reload_pending: bool,
    /// Passphrase, retained for WPA3-SAE PWE derivation.
    pub(super) password: Vec<u8>,
    /// When true, accept WPA3-SAE (H2E) authentication.
    pub(super) sae_enabled: bool,
    /// When true, the BSS additionally offers the PSK-SHA256 AKM (00-0F-AC:6).
    pub(super) psk_sha256: bool,
    /// When true, advertise WPA2/WPA3 transition mode (mixed PSK + SAE).
    pub(super) transition: bool,
    pub(super) boottime: Instant,
    pub(super) sc: i32,
    pub(super) aid: u16,
    pub(super) group_pn: u64,
    pub(super) gtk: [u8; 16],
    /// GTK key id (CCMP key index). Toggles 1<->2 on each group rekey so a fresh
    /// GTK gets a fresh index (reference AP's two-phase group rekey); stations and the
    /// kernel are told which index the current GTK lives at.
    pub(super) gtk_key_id: u8,
    /// Integrity GTK + key id + IPN, delivered to PMF stations for BIP.
    pub(super) igtk: [u8; 16],
    pub(super) igtk_key_id: u16,
    pub(super) igtk_ipn: [u8; 6],
    /// Beacon Integrity GTK (Beacon Protection / 802.11 BIGTK).
    pub(super) bigtk: [u8; 16],
    pub(super) bigtk_key_id: u16,
    pub(super) bigtk_ipn: [u8; 6],
    pub(super) beacon_prot: bool,
    /// Pending Channel Switch Announcement (new channel, remaining count).
    pub(super) pending_csa: Option<(u8, u8)>,
    /// Advertise the Multiple BSSID element.
    pub(super) multi_bssid: bool,
    /// 802.11v: send a BSS Transition Management Request after each handshake.
    pub(super) btm: bool,
    /// Advertise a co-located 6 GHz AP via a Reduced Neighbor Report.
    pub(super) rnr_6ghz: Option<u8>,
    /// Operate on 6 GHz (HE-only beacon; `channel` is a 6 GHz channel number).
    pub(super) band6: bool,
    /// Per-station VIF: each station gets its own GTK (for an nl80211 AP_VLAN),
    /// isolating broadcast/multicast traffic between stations.
    pub(super) per_sta_vif: bool,
    /// Guest BSS: client isolation. The AP never carries traffic between its
    /// own stations — the kernel data path gets `NL80211_ATTR_AP_ISOLATE` and
    /// the userspace data path drops station-to-station deliveries.
    pub(super) guest: bool,
    /// The BSS credential is a static guest password (SPR `GuestPassword`):
    /// the device credential database never applies to this BSS, so
    /// `set_psk_file` — including a control-socket RELOAD — is a no-op. The
    /// reference AP equivalent is `wpa_psk_file=/dev/null` + `wpa_passphrase`.
    pub(super) static_credential: bool,
    /// The affiliated link the management frame being processed arrived on
    /// (netlink MLD path; set per frame by the driver loop). A probe response
    /// must be built entirely for THIS link — its channel/band IEs, its own
    /// MLE Link ID, and an RNR naming its partners — otherwise an MLO client
    /// sees the response contradict the link's beacon and quietly falls back
    /// to a single-link association.
    pub(super) mgmt_rx_link: Option<u8>,
    /// WMM/WME QoS: advertise the WMM parameter element and send QoS Data frames
    /// to stations that negotiated WMM.
    pub(super) wmm: bool,
    /// Operating Channel Validation (OCV): include + validate the OCI KDE.
    pub(super) ocv: bool,
    /// OWE (Opportunistic Wireless Encryption): open + DH key exchange.
    pub(super) owe: bool,
    pub(super) sa_query_id: u16,
    /// PMKSA cache keyed by PMKID and the authenticated station identity. For an
    /// MLD this identity is the stable MLD MAC; otherwise it is the link MAC.
    pub(super) pmksa_cache: HashMap<([u8; 16], [u8; 6]), PmksaEntry>,
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
    pub(super) pending_anonce: HashMap<[u8; 6], PendingHandshake>,
    /// Earliest expiry among SAE/SA Query/ANonce/PMKSA state. Expensive table
    /// maintenance is performed only when this deadline is reached.
    pub(super) maintenance_deadline: Option<Instant>,
    /// Per-station EAPOL deadlines. Stale entries are invalidated by the
    /// station's generation counter, so the normal radio-loop tick is O(1).
    pub(super) eapol_deadlines: BinaryHeap<Reverse<(Instant, u64, [u8; 6])>>,
    /// Stations removed from the portable state machine since the transport
    /// last reconciled its kernel/VLAN bookkeeping.
    pub(super) removed_stations: Vec<[u8; 6]>,
    /// Stations whose four-way handshake just completed and whose keys now need
    /// installation/authorization by the transport.
    pub(super) key_ready_stations: Vec<[u8; 6]>,
    /// Incremented whenever GTK/IGTK/BIGTK material rotates.
    pub(super) group_key_epoch: u64,
    /// Optional Linux runtime SAE worker. Unit tests and raw-frame mode retain
    /// the synchronous path unless explicitly enabled.
    pub(super) async_sae: Option<AsyncSae>,
    /// Process-wide monotonically increasing EAPOL replay counter. It starts at
    /// a random non-zero value so frames from an earlier AP lifetime cannot be
    /// valid in a new lifetime.
    pub(super) eapol_replay_counter: u64,
    /// Secret for stateless SAE anti-clogging tokens.
    pub(super) sae_token_key: [u8; 32],
    /// Bounded per-source authentication/association request windows. Kept
    /// outside station state so rejected requests allocate no station.
    pub(super) request_rates: HashMap<[u8; 6], RequestRate>,
    pub(super) stations: HashMap<[u8; 6], Station>,
    /// Deduplicated log of failed auth / decryption attempts, fingerprinted by
    /// client (intrusion detection).
    pub(super) failures: crate::failures::FailureLog,
    /// Queued control events (connect/disconnect/auth-fail) drained by the run
    /// loop / control interface.
    pub(super) events: Vec<ApEvent>,
    /// GTK rekey period (reference AP `wpa_group_rekey`, default 600 s; 0 disables).
    pub(super) group_rekey_secs: u64,
    /// Rekey the GTK when an authorized station leaves so it can no longer read
    /// group traffic (reference AP `wpa_strict_rekey`, default on).
    pub(super) strict_rekey: bool,
    /// When the GTK was last rotated (drives the periodic group rekey).
    pub(super) last_group_rekey: Instant,
    /// A strict rekey is queued (a station left); the next `tick` performs it.
    pub(super) group_rekey_due: bool,
    /// Deterministic randomness hook for tests; `None` uses the OS RNG.
    pub(super) test_anonce: Option<[u8; 32]>,
}

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
