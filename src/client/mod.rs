//! Station/client state and orchestration.
//!
//! Protocol-specific behavior lives in focused child modules while this facade
//! owns shared state, key zeroization, output collection, and the stable public
//! API used by the raw-frame and command-line transports.

use crate::auth::{crypto, wpa3::sae};
use crate::frames as dot11;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

const AUTH_ASSOC_TIMEOUT: Duration = Duration::from_secs(3);
const FOUR_WAY_TIMEOUT: Duration = Duration::from_secs(5);
const LINK_SILENCE_TIMEOUT: Duration = Duration::from_secs(20);
const PMKSA_CACHE_LIFETIME: Duration = Duration::from_secs(12 * 60 * 60);

#[derive(Default)]
pub struct ClientOut {
    /// 802.11 frames to transmit (radiotap-prefixed).
    pub frames: Vec<Vec<u8>>,
    /// Decrypted Ethernet frames received from the AP.
    pub to_network: Vec<Vec<u8>>,
}

impl ClientOut {
    fn tx(&mut self, frame: Vec<u8>) {
        let mut f = dot11::RADIOTAP_TX.to_vec();
        f.extend_from_slice(&frame);
        self.frames.push(f);
    }
}

/// A PTK derived from a message 1 but not yet authenticated.
///
/// Message 1 carries no MIC, so anything derived from it is attacker-influenced
/// until the matching message 3 verifies under the derived KCK. Holding it aside
/// — rather than overwriting the live keys at message 2 — is what makes an
/// authenticator-initiated PTK rekey safe: the existing PTK keeps carrying data
/// throughout, a forged message 1 costs one wasted derivation instead of the
/// working session, and the replay counter only advances on an authenticated
/// message 3 (so a forged counter of `u64::MAX` cannot wedge the supplicant).
struct PendingPtk {
    anonce: [u8; 32],
    snonce: [u8; 32],
    /// Replay counter of the message 1 this candidate answers.
    replay: u64,
    kck: [u8; 16],
    kek: [u8; 16],
    tk: [u8; 16],
    pairwise_tk: [u8; 32],
}

impl Drop for PendingPtk {
    fn drop(&mut self) {
        self.anonce.zeroize();
        self.snonce.zeroize();
        self.kck.zeroize();
        self.kek.zeroize();
        self.tk.zeroize();
        self.pairwise_tk.zeroize();
    }
}

pub struct Client {
    pub mac: [u8; 6],
    ssid: Vec<u8>,
    pmk: [u8; 32],
    bssid: Option<[u8; 6]>,
    target_bssid: Option<[u8; 6]>,
    /// 0=idle, 1=auth sent, 2=associated, 4=fully authenticated.
    pub connected: u8,
    /// 0=awaiting m1, 1=awaiting m3, 2=done.
    eapol_state: u8,
    anonce: [u8; 32],
    snonce: [u8; 32],
    kck: [u8; 16],
    kek: [u8; 16],
    tk: [u8; 16],
    pairwise_tk: [u8; 32],
    pairwise_cipher: dot11::DataCipher,
    /// Whether the pairwise key (`tk`) has actually been installed by the 4-way
    /// handshake. Until then `tk` is all zeros and must NOT be used to validate
    /// protected management frames (otherwise a forged "NULL-key" Deauth would
    /// be accepted mid-handshake once SAE/OWE has set `sae_pmk`/PMF).
    ptk_installed: bool,
    /// PTK candidate derived from the message 1 currently being answered, held
    /// until its message 3 authenticates it. See [`PendingPtk`].
    pending_ptk: Option<PendingPtk>,
    gtk: [u8; 16],
    /// Whether `gtk` holds a real installed key. Used as the "is set" marker by
    /// the key-reinstallation guard, so an all-zero initial value is never
    /// mistaken for a key the AP just re-delivered.
    gtk_set: bool,
    /// The CCMP key index the current GTK is installed at (1 or 2, toggled by the
    /// AP on each group rekey), so group-addressed downlink is matched to it.
    gtk_key_id: u8,
    sc: i32,
    client_pn: u64,
    /// Replay protection: highest received pairwise / group CCMP packet numbers,
    /// and the highest EAPOL-Key replay counter seen from the AP.
    /// CCMP replay counters are per traffic identifier. Slots 0-15 are QoS TIDs;
    /// slot 16 is the non-QoS replay domain.
    last_rx_pn: [u64; 17],
    last_rx_gpn: [u64; 17],
    /// Highest received PN/IPN for protected management frames (unicast CCMP and
    /// group BIP), so a captured protected Deauth/Disassoc/Action/BTM can't be
    /// replayed.
    last_rx_mgmt_pn: u64,
    /// Highest received IGTK IPN, tracked together with the IGTK key id it
    /// belongs to: a new IGTK (new key id) on rekey resets the per-key replay
    /// window, so a post-rekey BIP frame with a fresh IPN isn't wrongly rejected.
    last_rx_igtk_ipn: u64,
    igtk_key_id: Option<u16>,
    eapol_replay: u64,
    test_snonce: Option<[u8; 32]>,
    // WPA3-SAE
    password: Vec<u8>,
    sae_enabled: bool,
    /// Use Hash-to-Element (true) or legacy hunting-and-pecking (false).
    sae_h2e: bool,
    sae: Option<sae::Sae>,
    sae_pmk: Option<[u8; 32]>,
    /// IGTK installed from EAPOL message 3 (PMF), for BIP verification.
    igtk: Option<[u8; 16]>,
    /// BIGTK installed from EAPOL message 3 (Beacon Protection).
    bigtk: Option<[u8; 16]>,
    /// PMKSA cache for fast reconnect (bssid, PMKID, PMK).
    cached_pmksa: Option<([u8; 6], [u8; 16], [u8; 32])>,
    cached_pmksa_at: Option<Instant>,
    pmksa_reconnect: bool,
    /// Operating Channel Validation: include + validate the OCI.
    ocv: bool,
    /// Operating channel (learned from the beacon's DS Parameter Set).
    channel: u8,
    /// OWE (Opportunistic Wireless Encryption) state.
    owe: bool,
    owe_priv: Option<sae::SecretScalar>,
    owe_pub: Option<Vec<u8>>,
    /// WMM/WME QoS: advertise the WMM element in (Re)Assoc Requests and send QoS
    /// Data uplink. Default on.
    wmm: bool,
    /// WMM is a negotiated capability, not a unilateral transmit setting.
    /// `ap_wmm` is learned from the selected beacon and `wmm_negotiated` from
    /// the association response.
    ap_wmm: bool,
    wmm_negotiated: bool,
    /// Test override: force this WMM user priority (TID 0-7) on all uplink data
    /// instead of deriving it from each packet's DSCP. `None` = derive per packet.
    wmm_tid_override: Option<u8>,
    /// 802.11be MLD: STA MLD MAC, link-1 MAC, and the AP's MLD MAC. When set, the
    /// assoc carries a per-STA profile for link 1 and the 4-way derives the PTK
    /// from the MLD MAC addresses (not the per-link addresses).
    mld_mac: Option<[u8; 6]>,
    link1_mac: Option<[u8; 6]>,
    ap_mld_mac: Option<[u8; 6]>,
    /// PSK-SHA256 (AKM 00-0F-AC:6): SHA-256 PTK + AES-CMAC v3 MIC.
    psk_sha256: bool,
    /// Pause at EAPOL message 3: decrypt + log each m3 (incl. retransmissions) but
    /// never send m4, so the AP keeps rebuilding/retransmitting m3 (UAF leak window).
    pause_m3: bool,
    /// State/liveness timers used by the production event loop. A lost auth,
    /// assoc, or EAPOL response must return to scanning instead of wedging until
    /// process restart; a vanished AP must similarly trigger reassociation.
    state_since: Instant,
    last_ap_seen: Instant,
}

impl Drop for Client {
    fn drop(&mut self) {
        self.pmk.zeroize();
        self.anonce.zeroize();
        self.snonce.zeroize();
        self.kck.zeroize();
        self.kek.zeroize();
        self.tk.zeroize();
        self.pairwise_tk.zeroize();
        self.gtk.zeroize();
        self.password.zeroize();
        if let Some(pmk) = self.sae_pmk.as_mut() {
            pmk.zeroize();
        }
        if let Some(key) = self.igtk.as_mut() {
            key.zeroize();
        }
        if let Some(key) = self.bigtk.as_mut() {
            key.zeroize();
        }
        if let Some((_, _, pmk)) = self.cached_pmksa.as_mut() {
            pmk.zeroize();
        }
    }
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("OS RNG available");
    b
}

mod configuration;
mod data;
mod group_keys;
mod handshake;
mod inspection;
mod management;
mod receive;
mod sae_auth;
mod session;

fn hex_str(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{:02x}", x);
    }
    s
}

fn inet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
