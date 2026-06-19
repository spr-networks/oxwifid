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
    pub last_auth: Option<Instant>,
    pub last_assoc: Option<Instant>,
    /// In-progress SAE exchange (WPA3); `None` for WPA2/PSK stations.
    pub sae: Option<crate::sae::Sae>,
    /// PMK established by SAE; when set it overrides the AP's PSK-derived PMK.
    pub pmk: Option<[u8; 32]>,
    pub sae_confirmed: bool,
    /// SHA-256 key descriptors + PMF (true for WPA3-SAE stations).
    pub sha256: bool,
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
            client_pn: 0,
            last_auth: None,
            last_assoc: None,
            sae: None,
            pmk: None,
            sae_confirmed: false,
            sha256: false,
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
    pub channel: u8,
    pub pmk: [u8; 32],
    /// Passphrase, retained for WPA3-SAE PWE derivation.
    password: Vec<u8>,
    /// When true, accept WPA3-SAE (H2E) authentication.
    sae_enabled: bool,
    boottime: Instant,
    sc: i32,
    aid: u16,
    group_pn: u64,
    gtk: [u8; 16],
    /// Integrity GTK + key id + IPN, delivered to PMF stations for BIP.
    igtk: [u8; 16],
    igtk_key_id: u16,
    igtk_ipn: [u8; 6],
    sa_query_id: u16,
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

impl Ap {
    pub fn new(ssid: &str, psk: &str, mac: [u8; 6], channel: u8) -> Ap {
        let pmk = crypto::pbkdf2_pmk(psk, ssid);
        let gtk_full = random_bytes::<32>();
        let mut gtk = [0u8; 16];
        gtk.copy_from_slice(&gtk_full[..16]);
        Ap {
            mac,
            ssid: ssid.as_bytes().to_vec(),
            channel,
            pmk,
            password: psk.as_bytes().to_vec(),
            sae_enabled: false,
            boottime: Instant::now(),
            sc: 0,
            aid: 0,
            group_pn: 0,
            gtk,
            igtk: random_bytes::<16>(),
            igtk_key_id: 4, // IGTK key ids are 4/5
            igtk_ipn: [0; 6],
            sa_query_id: 0,
            stations: HashMap::new(),
            test_anonce: None,
        }
    }

    /// Enable WPA3-SAE (H2E) authentication on this AP.
    pub fn enable_sae(&mut self) {
        self.sae_enabled = true;
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

    /// One beacon frame for the beacon ticker.
    pub fn beacon_frame(&mut self) -> Vec<u8> {
        let ts = self.current_timestamp();
        let frame = dot11::build_beacon(&self.mac, &self.ssid, self.channel, ts, &dot11::security_tail(self.sae_enabled));
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

        // EAPOL (unprotected data carrying 802.1X) -> 4-way handshake message 2
        if frame.is_eapol() {
            self.handle_eapol(&frame, &mut out);
            return out;
        }

        // Encrypted uplink data (to-DS + protected)
        if frame.frame_type() == dot11::TYPE_DATA && frame.protected() {
            if frame.to_ds() {
                self.handle_data_uplink(&frame, &mut out);
            }
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
        let frame = dot11::build_probe_resp(&self.mac, dst, &self.ssid, self.channel, ts, sc, &dot11::security_tail(self.sae_enabled));
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
            // Pick the PWE method the STA advertised: status 126 = Hash-to-Element,
            // status 0 = legacy hunting-and-pecking.
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
            // Verify the peer's confirm.
            let Some(station) = self.stations.get_mut(sta) else {
                return;
            };
            let Some(sae) = station.sae.as_ref() else {
                return;
            };
            if sae.check_confirm(payload).is_ok() {
                station.sae_confirmed = true;
            }
        }
    }

    fn handle_assoc_req(&mut self, frame: &dot11::Dot11, out: &mut Outgoing) {
        if frame.addr1 != self.mac {
            return;
        }
        let sta = frame.addr2;
        let reassoc = frame.subtype() == dot11::SUBTYPE_REASSOC_REQ;

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

        let resp_subtype = if reassoc { 0x03 } else { dot11::SUBTYPE_ASSOC_RESP };
        let aid = self.next_aid();
        let sc = self.next_sc();
        let assoc = dot11::build_assoc_resp(&self.mac, &sta, &self.ssid, self.channel, aid, sc, resp_subtype);

        // prepare EAPOL message 1 (assign ANONCE if needed)
        let anonce = {
            let entry = self.stations.get_mut(&sta).unwrap();
            if entry.anonce.is_none() {
                entry.anonce = Some(self.test_anonce.unwrap_or_else(random_bytes::<32>));
            }
            entry.eapol_ready = true;
            entry.anonce.unwrap()
        };
        let sha256 = self.stations.get(&sta).map(|s| s.sha256).unwrap_or(false);
        let m1_sc = self.next_sc();
        let m1 = dot11::build_eapol_m1(&self.mac, &sta, &anonce, m1_sc, sha256);

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

        let snonce = ek.key_nonce;
        let amac = self.mac;
        let smac = sta;

        // Use the SAE-derived PMK + SHA-256 key descriptors when the station
        // authenticated via WPA3-SAE; otherwise the PSK (PBKDF2) PMK + SHA-1.
        let (pmk, sha256) = self
            .stations
            .get(&sta)
            .map(|s| (s.pmk.unwrap_or(self.pmk), s.sha256))
            .unwrap_or((self.pmk, false));
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
        // MIC field zeroed (HMAC-SHA256 for SAE, HMAC-SHA1 for WPA2).
        let mic_off_in_eapol = 4 + ek.mic_offset; // EAPOL header (4) + body offset
        let mut to_check = eapol_frame.to_vec();
        for b in to_check[mic_off_in_eapol..mic_off_in_eapol + 16].iter_mut() {
            *b = 0;
        }
        let computed = if sha256 {
            crypto::hmac_sha256(&kck, &to_check)[..16].to_vec()
        } else {
            crypto::hmac_sha1(&kck, &to_check)[..16].to_vec()
        };
        if !crypto::constant_time_eq(&computed[..16], &ek.key_mic) {
            // bad MIC -> deauth and drop the station
            let deauth = dot11::build_deauth(&self.mac, &sta, 1);
            out.tx(deauth);
            self.stations.remove(&sta);
            return;
        }

        // good: install keys, send message 3
        {
            let s = self.stations.get_mut(&sta).unwrap();
            s.kck = kck;
            s.kek = kek;
            s.tk = tk;
            s.eapol_ready = false;
            s.client_pn = 0;
        }
        // Deliver the IGTK KDE to PMF (WPA3-SAE) stations so they can validate
        // BIP-protected group-addressed management frames.
        let igtk = if sha256 {
            Some((self.igtk_key_id, self.igtk_ipn, self.igtk))
        } else {
            None
        };
        let sc = self.next_sc();
        let m3 = dot11::build_eapol_m3(&self.mac, &sta, &anonce, &kck, &kek, &self.gtk, igtk, sc, sha256);
        out.tx(m3);
        if let Some(s) = self.stations.get_mut(&sta) {
            s.associated = true;
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

        if let Some(eth) = dot11::decrypt_ccmp(frame, &tk, false) {
            // sanity: source MAC in the Ethernet frame must match the station
            if eth.len() >= 12 && eth[6..12] == sta {
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
        let Some((pmf, tk)) = self.stations.get(&sta).map(|s| (s.sha256, s.tk)) else {
            return;
        };
        if pmf {
            if frame.protected() && dot11::decrypt_ccmp_mgmt(frame, &tk).is_some() {
                self.stations.remove(&sta);
            }
            // else: drop an unprotected (likely spoofed) robust mgmt frame
        } else {
            self.stations.remove(&sta);
        }
    }

    /// Handle a (PMF-protected) SA Query Action frame: respond to a Request, and
    /// accept a Response as proof the station is alive.
    fn handle_action(&mut self, frame: &dot11::Dot11, out: &mut Outgoing) {
        let sta = frame.addr2;
        let Some((pmf, tk)) = self.stations.get(&sta).map(|s| (s.sha256, s.tk)) else {
            return;
        };
        if !pmf || !frame.protected() {
            return; // robust action frames must be protected under PMF
        }
        let Some(plain) = dot11::decrypt_ccmp_mgmt(frame, &tk) else {
            return;
        };
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

    /// The session TK for a station (test/inspection helper).
    pub fn station_tk(&self, sta: &[u8; 6]) -> Option<[u8; 16]> {
        self.stations.get(sta).map(|s| s.tk)
    }

    /// Build a CCMP-protected unicast Deauthentication toward a PMF station.
    pub fn protected_deauth(&mut self, sta: &[u8; 6], reason: u16) -> Option<Vec<u8>> {
        let tk = self.stations.get(sta)?.tk;
        let pn = self.stations.get_mut(sta)?.next_client_pn();
        let sc = self.next_sc();
        let frame = dot11::build_protected_deauth(&self.mac, sta, reason, sc, pn, &tk);
        let mut f = dot11::RADIOTAP_TX.to_vec();
        f.extend_from_slice(&frame);
        Some(f)
    }

    /// The current IGTK (for PMF / BIP).
    pub fn igtk(&self) -> [u8; 16] {
        self.igtk
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
