//! A minimal WPA2/CCMP station, ported from `client.py`.
//!
//! Drives the supplicant side of the 4-way handshake so we can test the Rust AP
//! (and the reference Python AP) from the other end of an stdio bridge.

use crate::crypto;
use crate::dot11;

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
    /// Whether the pairwise key (`tk`) has actually been installed by the 4-way
    /// handshake. Until then `tk` is all zeros and must NOT be used to validate
    /// protected management frames (otherwise a forged "NULL-key" Deauth would
    /// be accepted mid-handshake once SAE/OWE has set `sae_pmk`/PMF).
    ptk_installed: bool,
    gtk: [u8; 16],
    /// The CCMP key index the current GTK is installed at (1 or 2, toggled by the
    /// AP on each group rekey), so group-addressed downlink is matched to it.
    gtk_key_id: u8,
    sc: i32,
    client_pn: u64,
    /// Replay protection: highest received pairwise / group CCMP packet numbers,
    /// and the highest EAPOL-Key replay counter seen from the AP.
    last_rx_pn: u64,
    last_rx_gpn: u64,
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
    sae: Option<crate::sae::Sae>,
    sae_pmk: Option<[u8; 32]>,
    /// IGTK installed from EAPOL message 3 (PMF), for BIP verification.
    igtk: Option<[u8; 16]>,
    /// BIGTK installed from EAPOL message 3 (Beacon Protection).
    bigtk: Option<[u8; 16]>,
    /// PMKSA cache for fast reconnect (bssid, PMKID, PMK).
    cached_pmksa: Option<([u8; 6], [u8; 16], [u8; 32])>,
    pmksa_reconnect: bool,
    /// Operating Channel Validation: include + validate the OCI.
    ocv: bool,
    /// Operating channel (learned from the beacon's DS Parameter Set).
    channel: u8,
    /// OWE (Opportunistic Wireless Encryption) state.
    owe: bool,
    owe_priv: Option<num_bigint::BigUint>,
    owe_pub: Option<Vec<u8>>,
    /// WMM/WME QoS: advertise the WMM element in (Re)Assoc Requests and send QoS
    /// Data uplink. Default on.
    wmm: bool,
    /// Test override: force this WMM user priority (TID 0-7) on all uplink data
    /// instead of deriving it from each packet's DSCP. `None` = derive per packet.
    wmm_tid_override: Option<u8>,
    /// 802.11be MLD: STA MLD MAC, link-1 MAC, and the AP's MLD MAC. When set, the
    /// assoc carries a per-STA profile for link 1 and the 4-way derives the PTK
    /// from the MLD MAC addresses (not the per-link addresses).
    mld_mac: Option<[u8; 6]>,
    link1_mac: Option<[u8; 6]>,
    ap_mld_mac: Option<[u8; 6]>,
    /// PSK-SHA256 (AKM 00-0F-AC:6): SHA-256 PTK + AES-CMAC v3 MIC (MLO-capable PSK).
    psk_sha256: bool,
    /// Pause at EAPOL message 3: decrypt + log each m3 (incl. retransmissions) but
    /// never send m4, so the AP keeps rebuilding/retransmitting m3 (UAF leak window).
    pause_m3: bool,
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("OS RNG available");
    b
}

impl Client {
    pub fn new(ssid: &str, psk: &str, mac: [u8; 6]) -> Client {
        Client {
            mac,
            ssid: ssid.as_bytes().to_vec(),
            pmk: crypto::pbkdf2_pmk(psk, ssid),
            bssid: None,
            target_bssid: None,
            connected: 0,
            eapol_state: 0,
            anonce: [0; 32],
            snonce: [0; 32],
            kck: [0; 16],
            kek: [0; 16],
            tk: [0; 16],
            ptk_installed: false,
            gtk: [0; 16],
            gtk_key_id: 1,
            sc: 0,
            client_pn: 1,
            last_rx_pn: 0,
            last_rx_gpn: 0,
            last_rx_mgmt_pn: 0,
            last_rx_igtk_ipn: 0,
            igtk_key_id: None,
            eapol_replay: 0,
            test_snonce: None,
            password: psk.as_bytes().to_vec(),
            sae_enabled: false,
            sae_h2e: true,
            sae: None,
            sae_pmk: None,
            igtk: None,
            bigtk: None,
            cached_pmksa: None,
            pmksa_reconnect: false,
            ocv: false,
            channel: 1,
            owe: false,
            owe_priv: None,
            owe_pub: None,
            wmm: true,
            wmm_tid_override: None,
            mld_mac: None,
            link1_mac: None,
            ap_mld_mac: None,
            psk_sha256: false,
            pause_m3: false,
        }
    }

    /// Enable 2-link MLD: the (re)assoc carries a per-STA profile for link 1, and
    /// the SAE auth + 4-way derive keys from the MLD MAC addresses. Combine with
    /// `enable_sae()` (the MLD AP on hwsim is SAE).
    pub fn enable_mld(&mut self, mld_mac: [u8; 6], link1_mac: [u8; 6], ap_mld_mac: [u8; 6]) {
        self.mld_mac = Some(mld_mac);
        self.link1_mac = Some(link1_mac);
        self.ap_mld_mac = Some(ap_mld_mac);
    }

    /// Pause at EAPOL message 3 (decrypt + log, never ack) for the m3-retransmit leak.
    pub fn set_pause_m3(&mut self) {
        self.pause_m3 = true;
    }

    /// The EAPOL-Key MIC algorithm for this association's AKM.
    fn key_mic(&self) -> dot11::KeyMic {
        if self.psk_sha256 {
            dot11::KeyMic::AesCmacV3
        } else {
            dot11::KeyMic::select(self.sae_pmk.is_some(), self.owe)
        }
    }

    fn mld_mgmt_rx_sec_addrs(&self) -> Option<([u8; 6], [u8; 6], [u8; 6])> {
        let sta_mld = self.mld_mac?;
        let ap_mld = self.ap_mld_mac?;
        Some((sta_mld, ap_mld, ap_mld))
    }

    fn mld_mgmt_tx_sec_addrs(&self) -> Option<([u8; 6], [u8; 6], [u8; 6])> {
        let sta_mld = self.mld_mac?;
        let ap_mld = self.ap_mld_mac?;
        Some((ap_mld, sta_mld, ap_mld))
    }

    /// Enable/disable WMM (advertise the WMM element + send QoS Data uplink).
    pub fn set_wmm(&mut self, wmm: bool) {
        self.wmm = wmm;
    }

    /// Test override: force a fixed WMM user priority (TID 0-7) on uplink data,
    /// regardless of the packet's DSCP. `None` restores per-packet classification.
    pub fn set_wmm_tid(&mut self, tid: Option<u8>) {
        self.wmm_tid_override = tid.map(|t| t & 0x07);
    }

    /// Append the WMM Information element to a (Re)Assoc Request when WMM is on.
    fn with_wmm(&self, mut frame: Vec<u8>) -> Vec<u8> {
        if self.wmm {
            frame.extend_from_slice(&dot11::wmm_information());
        }
        frame
    }

    /// Enable Operating Channel Validation (anti-MITM).
    pub fn enable_ocv(&mut self) {
        self.ocv = true;
    }

    /// Enable OWE (Opportunistic Wireless Encryption): connect to an open BSS
    /// with a Diffie-Hellman exchange that keys the 4-way handshake.
    pub fn enable_owe(&mut self) {
        self.owe = true;
    }

    /// Use WPA3-SAE (H2E by default) instead of open-system auth + PSK.
    pub fn enable_sae(&mut self) {
        self.sae_enabled = true;
    }

    /// Use the legacy hunting-and-pecking PWE instead of Hash-to-Element.
    pub fn use_hunting_pecking(&mut self) {
        self.sae_h2e = false;
    }

    pub fn set_test_snonce(&mut self, snonce: [u8; 32]) {
        self.test_snonce = Some(snonce);
    }

    fn next_sc(&mut self) -> u16 {
        self.sc = (self.sc + 1).rem_euclid(4096);
        (self.sc * 16) as u16
    }

    fn next_client_pn(&mut self) -> u64 {
        let pn = self.client_pn;
        self.client_pn += 1;
        pn
    }

    pub fn handle_incoming(&mut self, radiotap_frame: &[u8]) -> ClientOut {
        let mut out = ClientOut::default();
        if dot11::radiotap_bad_fcs(radiotap_frame) {
            return out;
        }
        let Some(body) = dot11::strip_radiotap(radiotap_frame) else {
            return out;
        };
        let Some(frame) = dot11::Dot11::parse(body) else {
            return out;
        };
        if frame.addr2 == self.mac {
            return out; // ignore our own frames
        }

        let is_mgmt = frame.frame_type() == dot11::TYPE_MGMT;

        // PMF enforcement: robust management frames (Deauth/Disassoc/Action).
        if is_mgmt
            && self.connected >= 2
            && (frame.subtype() == dot11::SUBTYPE_DEAUTH
                || frame.subtype() == dot11::SUBTYPE_DISASSOC
                || frame.subtype() == dot11::SUBTYPE_ACTION)
        {
            self.handle_robust_mgmt(&frame, &mut out);
            return out;
        }

        // Beacon -> authenticate (SAE commit or open-system auth)
        if self.connected == 0 && is_mgmt && frame.subtype() == dot11::SUBTYPE_BEACON {
            if let Some(t) = self.target_bssid {
                if frame.addr3 != t {
                    return out;
                }
            }
            let bssid = frame.addr2;
            self.bssid = Some(bssid);
            self.connected = 1;
            // Learn the operating channel from the DS Parameter Set (for OCV).
            if frame.body.len() > 12 {
                if let Some(ds) = dot11::find_ie(&frame.body[12..], 3) {
                    if !ds.is_empty() {
                        self.channel = ds[0];
                    }
                }
            }
            // PMKSA caching fast reconnect: if we have a cached PMKSA for this
            // BSS, do open-system auth and restore the cached PMK (no SAE).
            if let Some((cbssid, _pmkid, pmk)) = self.cached_pmksa {
                if cbssid == bssid {
                    self.sae_pmk = Some(pmk);
                    self.pmksa_reconnect = true;
                    let sc = self.next_sc();
                    out.tx(dot11::build_auth_req(&bssid, &self.mac, sc));
                    return out;
                }
            }
            if self.sae_enabled {
                self.start_sae(&bssid, &mut out);
            } else {
                let sc = self.next_sc();
                out.tx(dot11::build_auth_req(&bssid, &self.mac, sc));
            }
            return out;
        }

        // Authentication frame from the AP
        if self.connected == 1 && is_mgmt && frame.subtype() == dot11::SUBTYPE_AUTH {
            if let Some(auth) = dot11::parse_auth(&frame.body) {
                if auth.algo == dot11::AUTH_ALG_SAE {
                    self.handle_sae_auth(auth.seq, auth.payload, &mut out);
                    return out;
                }
            }
            // open-system auth response -> associate
            let bssid = frame.addr2;
            self.bssid = Some(bssid);
            let sc = self.next_sc();
            let ssid = self.ssid.clone();
            if self.pmksa_reconnect {
                if let Some((_, pmkid, _)) = self.cached_pmksa {
                    out.tx(self.with_wmm(dot11::build_assoc_req_pmkid(
                        &bssid, &self.mac, &ssid, &pmkid, sc,
                    )));
                    return out;
                }
            }
            if self.owe {
                // OWE: generate an ephemeral DH key and send it in the assoc req.
                let (priv_k, pub_b) = crate::sae::owe_keypair();
                let dh = dot11::build_dh_param_element(19, &pub_b);
                self.owe_priv = Some(priv_k);
                self.owe_pub = Some(pub_b);
                out.tx(self.with_wmm(dot11::build_assoc_req_owe(
                    &bssid, &self.mac, &ssid, &dh, sc,
                )));
                return out;
            }
            if let (Some(mld), Some(l1)) = (self.mld_mac, self.link1_mac) {
                out.tx(dot11::build_assoc_req_mld(
                    &bssid, &self.mac, &mld, &l1, &ssid, sc,
                ));
            } else {
                out.tx(self.with_wmm(dot11::build_assoc_req(&bssid, &self.mac, &ssid, sc)));
            }
            return out;
        }

        // Association response
        if self.connected == 1 && is_mgmt && frame.subtype() == dot11::SUBTYPE_ASSOC_RESP {
            // OWE: derive the PMK from the AP's DH Parameter element.
            if self.owe && frame.body.len() > 6 {
                if let (Some(priv_k), Some(own_pub)) = (self.owe_priv.clone(), self.owe_pub.clone())
                {
                    if let Some((group, ap_pub)) = dot11::parse_dh_param(&frame.body[6..]) {
                        if let Some((pmk, _pmkid)) =
                            crate::sae::owe_derive(&priv_k, &ap_pub, &own_pub, &ap_pub, group)
                        {
                            self.sae_pmk = Some(pmk);
                        }
                    }
                }
            }
            self.connected = 2;
            return out;
        }

        // EAPOL key frames from the AP
        if self.connected > 1 && frame.is_eapol() {
            if !frame.from_ds() || frame.addr1 != self.mac {
                return out;
            }
            // Group Key Handshake message 1 (GTK rekey) — a group (non-pairwise)
            // EAPOL-Key with Key Ack set, sent after association.
            if self.connected >= 4 {
                if let Some(ek) = frame.eapol_key_body().and_then(dot11::EapolKey::parse) {
                    if !ek.is_pairwise() && ek.key_ack() {
                        self.handle_group_rekey(&frame, &ek, &mut out);
                        return out;
                    }
                }
            }
            if self.eapol_state == 0 {
                self.send_eapol2(&frame, &mut out);
            } else if self.eapol_state == 1 {
                self.send_eapol4(&frame, &mut out);
            }
            return out;
        }

        // Encrypted downlink data
        if self.connected > 3
            && frame.frame_type() == dot11::TYPE_DATA
            && frame.protected()
            && frame.from_ds()
        {
            let key_id = frame.ccmp_key_id();
            let group_ra = frame.addr1[0] & 0x01 != 0; // multicast/broadcast RA
                                                       // The GTK (a group key, key id 1/2) may only decrypt group-addressed
                                                       // frames. A unicast frame addressed to us must use the pairwise key
                                                       // (key id 0); a unicast frame arriving under a group key id is forged
                                                       // (any peer that knows the GTK could otherwise inject AP-sourced
                                                       // unicast), so drop it.
            let use_group = key_id == self.gtk_key_id && key_id != 0;
            if use_group && !group_ra {
                return out; // unicast under a group key id — reject
            }
            if !use_group && (group_ra || key_id != 0) {
                return out; // group-addressed under a non-group key, or unknown key id
            }
            let tk = if use_group { self.gtk } else { self.tk };
            let Some(pn) = frame.ccmp_pn() else {
                return out;
            };
            // CCMP replay protection (separate counters for pairwise and group).
            let last = if use_group {
                self.last_rx_gpn
            } else {
                self.last_rx_pn
            };
            if pn <= last {
                return out; // replayed frame
            }
            // 802.11be (MLO) pairwise downlink: the AP CCMP-protects with the
            // MLD addresses while the header carries link addresses, so decrypt
            // with the MLD security context (mirroring the uplink translation).
            // Group (GTK) frames keep their as-sent addresses.
            let sec = match (use_group, self.mld_mac, self.ap_mld_mac, self.bssid) {
                (false, Some(mld), Some(ap_mld), Some(bssid)) => {
                    let sec_a1 = mld; // RA: our link addr -> our MLD
                    let sec_a2 = ap_mld; // TA: AP link0 BSSID -> AP MLD
                    let sec_a3 = if frame.addr3 == bssid {
                        ap_mld
                    } else {
                        frame.addr3
                    };
                    Some((sec_a1, sec_a2, sec_a3))
                }
                _ => None,
            };
            if let Some(eth) = dot11::decrypt_ccmp_sec(&frame, &tk, true, sec) {
                if use_group {
                    self.last_rx_gpn = pn;
                } else {
                    self.last_rx_pn = pn;
                }
                out.to_network.push(eth);
            }
        }

        out
    }

    /// PMF enforcement for received robust management frames. Under PMF,
    /// unprotected Deauth/Disassoc/Action frames are dropped; only BIP-valid
    /// group frames or CCMP-valid unicast frames are acted upon. Without PMF
    /// (WPA2), deauth/disassoc are honoured as before.
    fn handle_robust_mgmt(&mut self, frame: &dot11::Dot11, out: &mut ClientOut) {
        let pmf = self.sae_pmk.is_some();
        let group = frame.addr1[0] & 0x01 != 0;

        if frame.subtype() == dot11::SUBTYPE_ACTION {
            // Only SA Query is handled, and only when PMF-protected. Require the
            // PTK to be installed (never validate with the all-zero placeholder
            // key) and reject replays (PN must strictly increase).
            if !pmf || !frame.protected() || !self.ptk_installed {
                return;
            }
            let Some(plain) =
                dot11::decrypt_ccmp_mgmt_sec(frame, &self.tk, self.mld_mgmt_rx_sec_addrs())
            else {
                return;
            };
            match frame.ccmp_pn() {
                Some(pn) if pn > self.last_rx_mgmt_pn => self.last_rx_mgmt_pn = pn,
                _ => return, // replay or missing PN
            }
            // 802.11v BTM request: disassociate on disassoc-imminent.
            if plain.len() >= 4
                && plain[0] == dot11::ACTION_CATEGORY_WNM
                && plain[1] == dot11::WNM_BTM_REQUEST
            {
                if plain[3] & 0x04 != 0 {
                    self.disconnect();
                }
                return;
            }
            if let Some((action, trans_id)) = dot11::parse_sa_query(&plain) {
                if action == dot11::SA_QUERY_REQUEST {
                    if let Some(bssid) = self.bssid {
                        let pn = self.next_client_pn();
                        let sc = self.next_sc();
                        let sec = self.mld_mgmt_tx_sec_addrs();
                        out.tx(dot11::build_protected_sa_query_sec(
                            &bssid, &self.mac, true, true, trans_id, sc, pn, &self.tk, sec,
                        ));
                    }
                }
            }
            return;
        }

        // Deauthentication / Disassociation
        let accept = if !pmf {
            true // legacy WPA2: no PMF, honour the frame
        } else if group {
            // Group-addressed: BIP-protected; verify the MIC, then require a
            // strictly increasing IPN (reject a replayed protected deauth).
            match self.igtk {
                Some(igtk)
                    if dot11::bip_verify(
                        &igtk,
                        frame.fc0,
                        frame.fc1,
                        &frame.addr1,
                        &frame.addr2,
                        &frame.addr3,
                        &frame.body,
                    ) =>
                {
                    match dot11::bip_ipn(&frame.body) {
                        Some(ipn) if ipn > self.last_rx_igtk_ipn => {
                            self.last_rx_igtk_ipn = ipn;
                            true
                        }
                        _ => false,
                    }
                }
                _ => false,
            }
        } else {
            // Unicast: only with an installed PTK, valid CCMP MIC, and a
            // strictly increasing PN (anti replay).
            if self.ptk_installed
                && frame.protected()
                && dot11::decrypt_ccmp_mgmt_sec(frame, &self.tk, self.mld_mgmt_rx_sec_addrs())
                    .is_some()
            {
                match frame.ccmp_pn() {
                    Some(pn) if pn > self.last_rx_mgmt_pn => {
                        self.last_rx_mgmt_pn = pn;
                        true
                    }
                    _ => false,
                }
            } else {
                false
            }
        };
        if accept {
            self.disconnect();
        }
    }

    /// Install the GTK / IGTK / BIGTK KDEs from an unwrapped EAPOL key-data
    /// blob (shared by EAPOL m3 and Group Key msg1). Tracks the GTK key index so
    /// group downlink is matched to it, and resets the BIP replay window when a
    /// new IGTK (new key id) is installed so a post-rekey frame whose IPN was
    /// reset isn't mistaken for a replay.
    fn install_group_keys(&mut self, unwrapped: &[u8], reset_group_pn: bool) {
        if let Some((key_id, gtk)) = dot11::parse_gtk_kde_full(unwrapped) {
            if gtk.len() == 16 {
                self.gtk.copy_from_slice(&gtk);
                self.gtk_key_id = key_id;
                if reset_group_pn {
                    self.last_rx_gpn = 0;
                }
            }
        } else if let Some((_link_id, key_id, _pn, gtk)) = dot11::parse_mlo_gtk_kde_full(unwrapped)
        {
            if gtk.len() == 16 {
                self.gtk.copy_from_slice(&gtk);
                self.gtk_key_id = key_id;
                if reset_group_pn {
                    self.last_rx_gpn = 0;
                }
            }
        }
        if let Some((id, _ipn, igtk)) = dot11::parse_igtk_kde(unwrapped) {
            self.igtk = Some(igtk);
            // A fresh IGTK key id starts a fresh IPN window (per-key replay
            // protection); only then is resetting the counter safe.
            if self.igtk_key_id != Some(id) {
                self.igtk_key_id = Some(id);
                self.last_rx_igtk_ipn = 0;
            }
        } else if let Some((_link_id, id, _ipn, igtk)) = dot11::parse_mlo_igtk_kde(unwrapped) {
            self.igtk = Some(igtk);
            if self.igtk_key_id != Some(id) {
                self.igtk_key_id = Some(id);
                self.last_rx_igtk_ipn = 0;
            }
        }
        if let Some((_id, _ipn, bigtk)) = dot11::parse_bigtk_kde(unwrapped) {
            self.bigtk = Some(bigtk);
        } else if let Some((_link_id, _id, _ipn, bigtk)) = dot11::parse_mlo_bigtk_kde(unwrapped) {
            self.bigtk = Some(bigtk);
        }
    }

    /// Handle Group Key Handshake message 1: verify, install the new GTK/IGTK,
    /// and reply with message 2.
    fn handle_group_rekey(
        &mut self,
        frame: &dot11::Dot11,
        ek: &dot11::EapolKey,
        out: &mut ClientOut,
    ) {
        let Some(bssid) = self.bssid else { return };
        let Some(eapol_frame) = frame.eapol_frame() else {
            return;
        };
        let sha256 = self.sae_pmk.is_some();

        // verify MIC
        let mic_off = 4 + ek.mic_offset;
        if eapol_frame.len() < mic_off + 16 {
            return;
        }
        let mut to_check = eapol_frame.to_vec();
        for b in to_check[mic_off..mic_off + 16].iter_mut() {
            *b = 0;
        }
        let computed = dot11::KeyMic::select(sha256, self.owe)
            .compute(&self.kck, &to_check)
            .to_vec();
        if !crypto::constant_time_eq(&computed[..16], &ek.key_mic) {
            return;
        }
        // EAPOL replay-counter check
        if ek.key_replay_counter <= self.eapol_replay {
            return;
        }
        self.eapol_replay = ek.key_replay_counter;

        // install the new GTK (and IGTK), resetting the group replay counter and
        // the per-key BIP replay window
        if let Some(unwrapped) = crypto::aes_unwrap(&self.kek, &ek.key_data) {
            self.install_group_keys(&unwrapped, true);
        }

        let sc = self.next_sc();
        let kck = self.kck;
        out.tx(dot11::build_group_key_msg2(
            &bssid,
            &self.mac,
            &kck,
            ek.key_replay_counter,
            sc,
            dot11::KeyMic::select(sha256, self.owe),
        ));
    }

    fn disconnect(&mut self) {
        self.connected = 0;
        self.eapol_state = 0;
        self.ptk_installed = false;
        self.last_rx_mgmt_pn = 0;
        self.last_rx_igtk_ipn = 0;
        self.igtk_key_id = None;
        self.gtk_key_id = 1;
        self.tk = [0; 16];
        self.gtk = [0; 16];
        self.igtk = None;
        self.sae = None;
        self.sae_pmk = None;
    }

    /// Send our SAE commit to start the exchange (status 126 for H2E, 0 for
    /// hunting-and-pecking).
    fn start_sae(&mut self, bssid: &[u8; 6], out: &mut ClientOut) {
        // MLD SAE: because the auth frames carry the STA's MLD MAC (multi_link_auth),
        // the AP derives the SAE PWE/keys from the MLD MAC addresses — so we must too.
        // The auth frames themselves stay link-addressed.
        let sae_sta = self.mld_mac.unwrap_or(self.mac);
        let sae_ap = self.ap_mld_mac.unwrap_or(*bssid);
        let sae = if self.sae_h2e {
            Some(crate::sae::Sae::new_h2e(
                &self.ssid,
                &self.password,
                None,
                &sae_sta,
                &sae_ap,
            ))
        } else {
            crate::sae::Sae::new_hunting_pecking(&self.password, &sae_sta, &sae_ap)
        };
        let Some(mut sae) = sae else { return };
        sae.prepare_commit(None);
        let mut commit = sae.write_commit();
        // MLD: carry the STA's MLD MAC in the SAE commit so the AP records it
        // (the assoc's MLD MAC must match the auth's).
        if let Some(mld) = self.mld_mac {
            commit.extend_from_slice(&dot11::multi_link_auth(&mld));
        }
        let status = if self.sae_h2e {
            dot11::STATUS_SAE_H2E
        } else {
            dot11::STATUS_SUCCESS
        };
        let sc = self.next_sc();
        out.tx(dot11::build_sae_auth(
            bssid,
            &self.mac,
            bssid,
            dot11::FC_TODS,
            sc,
            1,
            status,
            &commit,
        ));
        self.sae = Some(sae);
    }

    /// Handle an SAE authentication frame from the AP (commit then confirm).
    fn handle_sae_auth(&mut self, seq: u16, payload: &[u8], out: &mut ClientOut) {
        match seq {
            1 => {
                // AP commit -> derive keys, send our confirm
                let mut confirm = {
                    let Some(sae) = self.sae.as_mut() else { return };
                    if sae.parse_peer_commit(payload).is_err() || sae.process_commit().is_err() {
                        return;
                    }
                    sae.write_confirm()
                };
                if let Some(mld) = self.mld_mac {
                    confirm.extend_from_slice(&dot11::multi_link_auth(&mld));
                }
                let Some(bssid) = self.bssid else { return };
                let sc = self.next_sc();
                out.tx(dot11::build_sae_auth(
                    &bssid,
                    &self.mac,
                    &bssid,
                    dot11::FC_TODS,
                    sc,
                    2,
                    dot11::STATUS_SUCCESS,
                    &confirm,
                ));
            }
            2 => {
                // AP confirm -> verify, store PMK, associate
                let verified = self
                    .sae
                    .as_ref()
                    .map(|s| s.check_confirm(payload).is_ok())
                    .unwrap_or(false);
                if !verified {
                    return;
                }
                let pmk_pmkid = self.sae.as_ref().map(|s| {
                    let mut p = [0u8; 32];
                    p.copy_from_slice(&s.pmk);
                    let mut id = [0u8; 16];
                    id.copy_from_slice(&s.pmkid);
                    (p, id)
                });
                self.sae_pmk = pmk_pmkid.map(|(p, _)| p);
                let Some(bssid) = self.bssid else { return };
                // Cache the PMKSA for fast reconnect.
                if let Some((pmk, pmkid)) = pmk_pmkid {
                    self.cached_pmksa = Some((bssid, pmkid, pmk));
                }
                let sc = self.next_sc();
                let ssid = self.ssid.clone();
                // SAE associations must advertise the SAE AKM, not WPA2-PSK,
                // otherwise the AP rejects with "Invalid AKMP". For MLD, send the
                // 2-link assoc carrying the per-STA profile.
                if let (Some(mld), Some(l1)) = (self.mld_mac, self.link1_mac) {
                    out.tx(dot11::build_assoc_req_mld(
                        &bssid, &self.mac, &mld, &l1, &ssid, sc,
                    ));
                } else {
                    out.tx(self.with_wmm(dot11::build_assoc_req_sae(&bssid, &self.mac, &ssid, sc)));
                }
            }
            _ => {}
        }
    }

    fn send_eapol2(&mut self, m1: &dot11::Dot11, out: &mut ClientOut) {
        let Some(bssid) = self.bssid else { return };
        let Some(key_body) = m1.eapol_key_body() else {
            return;
        };
        let Some(ek) = dot11::EapolKey::parse(key_body) else {
            return;
        };

        self.eapol_replay = ek.key_replay_counter; // remember m1's replay counter
        self.anonce = ek.key_nonce;
        self.snonce = self.test_snonce.unwrap_or_else(random_bytes::<32>);

        // SAE/OWE/PSK-SHA256 use the SHA-256 key hierarchy; plain WPA2-PSK SHA-1.
        // For MLD the 4-way derives the PTK from the MLD MAC addresses.
        let sha256 = self.sae_pmk.is_some() || self.psk_sha256;
        let pmk = self.sae_pmk.unwrap_or(self.pmk);
        let aa = self.ap_mld_mac.unwrap_or(bssid);
        let spa = self.mld_mac.unwrap_or(self.mac);
        if sha256 {
            let ptk = crypto::derive_ptk_sha256(&pmk, &aa, &spa, &self.anonce, &self.snonce);
            self.kck.copy_from_slice(&ptk[..16]);
            self.kek.copy_from_slice(&ptk[16..32]);
            self.tk.copy_from_slice(&ptk[32..48]);
        } else {
            let ptk = crypto::custom_prf512(&pmk, &aa, &spa, &self.anonce, &self.snonce);
            self.kck.copy_from_slice(&ptk[..16]);
            self.kek.copy_from_slice(&ptk[16..32]);
            self.tk.copy_from_slice(&ptk[32..48]);
        }
        self.client_pn = 1;

        let sc = self.next_sc();
        let kck = self.kck;
        let snonce = self.snonce;
        let oci = if self.ocv {
            Some((
                dot11::operating_class(self.channel, 20, false),
                self.channel,
            )) // 20 MHz STA data plane
        } else {
            None
        };
        // m2 must echo the RSN this STA advertised in its assoc request.
        let mut supp_rsn: Vec<u8> = if self.mld_mac.is_some() {
            let mut r = dot11::AMLD_RSN_SAE.to_vec();
            r.extend_from_slice(&dot11::RSNXE_H2E);
            r
        } else if self.psk_sha256 {
            dot11::AMLD_RSN_PSK256.to_vec()
        } else if self.owe {
            dot11::RSN_OWE.to_vec()
        } else if sha256 {
            let mut r = dot11::RSN_WPA3.to_vec();
            r.extend_from_slice(&dot11::RSNXE_H2E);
            r
        } else {
            dot11::RSN.to_vec()
        };
        // MLD: m2 must carry the STA's MLD MAC in a MAC Address KDE (00-0F-AC:3)
        // plus one MLO Link KDE (00-0F-AC:19) per affiliated link (link 1 here),
        // else the AP rejects ("Invalid MLD address" / "Expecting N MLD links").
        if let Some(mld) = self.mld_mac {
            supp_rsn.extend_from_slice(&[0xdd, 0x0a, 0x00, 0x0f, 0xac, 0x03]);
            supp_rsn.extend_from_slice(&mld);
            if let Some(l1) = self.link1_mac {
                // link info = link_id 1, no RSNE; then the link-1 STA MAC.
                supp_rsn.extend_from_slice(&[0xdd, 0x0b, 0x00, 0x0f, 0xac, 0x13, 0x01]);
                supp_rsn.extend_from_slice(&l1);
            }
        }
        let mic = self.key_mic();
        out.tx(dot11::build_eapol_m2(
            &bssid, &self.mac, &snonce, &kck, &supp_rsn, sc, mic, oci,
        ));
        self.eapol_state = 1;
    }

    fn send_eapol4(&mut self, m3: &dot11::Dot11, out: &mut ClientOut) {
        let Some(bssid) = self.bssid else { return };
        let Some(eapol_frame) = m3.eapol_frame() else {
            return;
        };
        let Some(key_body) = m3.eapol_key_body() else {
            return;
        };
        let Some(ek) = dot11::EapolKey::parse(key_body) else {
            return;
        };

        // Replay enforcement — skipped while paused at m3 so each retransmission
        // (including the post-reclaim UAF leak) is decrypted, not dropped.
        if !self.pause_m3 && ek.key_replay_counter <= self.eapol_replay {
            return;
        }

        // verify the AP's MIC over message 3
        let mic_off = 4 + ek.mic_offset;
        let mut to_check = eapol_frame.to_vec();
        if to_check.len() < mic_off + 16 {
            return;
        }
        for b in to_check[mic_off..mic_off + 16].iter_mut() {
            *b = 0;
        }
        let computed = self.key_mic().compute(&self.kck, &to_check).to_vec();
        if !crypto::constant_time_eq(&computed[..16], &ek.key_mic) {
            return; // bad MIC, drop
        }
        self.eapol_replay = ek.key_replay_counter;

        // unwrap and install the GTK / IGTK / BIGTK from the KEK-wrapped key data.
        if let Some(unwrapped) = crypto::aes_unwrap(&self.kek, &ek.key_data) {
            if self.pause_m3 {
                // The UAF-leaked IGTK (back-indexed heap bytes) rides in here.
                eprintln!("M3_KEYDATA {}", hex_str(&unwrapped));
            }
            self.install_group_keys(&unwrapped, false);
            if self.ocv {
                // The AP's OCI carries ITS operating class (e.g. 128 at 80 MHz)
                // — pin the primary channel + band, not an identical class.
                match dot11::parse_oci_kde(&unwrapped) {
                    Some((oc, ch))
                        if ch == self.channel
                            && dot11::oci_class_matches_band(oc, self.channel, false) => {}
                    _ => return, // missing or mismatched OCI -> possible MITM, drop
                }
            }
        } else if self.pause_m3 {
            eprintln!("M3_UNWRAP_FAIL kd_len={}", ek.key_data.len());
        }

        if self.pause_m3 {
            // Never ack m3: stay at eapol_state=1 so the AP keeps retransmitting it.
            return;
        }

        let sc = self.next_sc();
        let kck = self.kck;
        let mic = self.key_mic();
        // MLD: m4 must carry the STA's MLD MAC (MAC Address KDE), like m2, or the
        // AP rejects msg 4/4 and never authorizes the port (uplink data dropped).
        out.tx(dot11::build_eapol_m4_mld(
            &bssid,
            &self.mac,
            &kck,
            sc,
            mic,
            self.mld_mac.as_ref(),
        ));
        self.connected = 4;
        // The pairwise key is now installed (m3 verified, m4 sent); only from
        // here may protected unicast management frames be validated with `tk`.
        self.ptk_installed = true;
        self.eapol_state = 2;
    }

    /// Encrypt and frame an Ethernet payload toward the AP (uplink, to-DS).
    pub fn encrypt_uplink(&mut self, eth: &[u8]) -> Option<Vec<u8>> {
        let bssid = self.bssid?;
        if self.connected < 4 || eth.len() < 14 {
            return None;
        }
        let mut dst = [0u8; 6];
        dst.copy_from_slice(&eth[0..6]);
        let ethertype = u16::from_be_bytes([eth[12], eth[13]]);
        let inner = &eth[14..];
        let pn = self.next_client_pn();
        let sc = self.next_sc();
        let tk = self.tk;
        // QoS Data when WMM is on: force the test override TID if set, else
        // derive the user priority from the packet's DSCP. Plain Data otherwise.
        let qos_tid = if self.wmm {
            Some(self.wmm_tid_override.unwrap_or_else(|| dot11::wmm_tid(eth)))
        } else {
            None
        };
        // 802.11be (MLO): the MAC header carries the link addresses so the frame
        // traverses link 0, but the CCMP nonce/AAD (and thus the AP's STA lookup)
        // must use the MLD addresses — the same basis the PTK was derived from in
        // the 4-way handshake (`ap_mld_mac` / `mld_mac`). Without this the AP
        // can't map the frame to the MLD STA and drops it as "not associated".
        let frame = if let (Some(mld), Some(ap_mld)) = (self.mld_mac, self.ap_mld_mac) {
            // Map each link address in the header to its MLD counterpart for the
            // security context (A1=AP, A2=STA, A3=DA — only the AP/STA link
            // addresses translate; a DA for some other device stays as-is).
            let sec_a1 = ap_mld; // RA: AP link0 BSSID -> AP MLD
            let sec_a2 = mld; // TA: STA link0 addr -> STA MLD
            let sec_a3 = if dst == bssid { ap_mld } else { dst };
            dot11::build_ccmp_data_sec(
                &bssid,
                &self.mac,
                &dst,
                &sec_a1,
                &sec_a2,
                &sec_a3,
                dot11::FC_TODS | dot11::FC_PROTECTED,
                sc,
                pn,
                0,
                &tk,
                ethertype,
                inner,
                qos_tid,
            )
        } else {
            dot11::build_ccmp_data(
                &bssid,
                &self.mac,
                &dst,
                dot11::FC_TODS | dot11::FC_PROTECTED,
                sc,
                pn,
                0,
                &tk,
                ethertype,
                inner,
                qos_tid,
            )
        };
        let mut f = dot11::RADIOTAP_TX.to_vec();
        f.extend_from_slice(&frame);
        Some(f)
    }

    /// Build a ping (ICMP echo) Ethernet frame from `src_ip` to `dst_ip` for the
    /// gateway MAC.
    pub fn build_ping(
        &self,
        dst_mac: &[u8; 6],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        tos: u8,
    ) -> Vec<u8> {
        let mut icmp = vec![8u8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01];
        icmp.extend_from_slice(b"barely-ap-rust-ping");
        let ck = inet_checksum(&icmp);
        icmp[2..4].copy_from_slice(&ck.to_be_bytes());

        let total = 20 + icmp.len();
        let mut ip = Vec::with_capacity(total);
        // `tos` carries the DSCP (DSCP << 2) so the WMM classifier can derive UP.
        ip.extend_from_slice(&[0x45, tos]);
        ip.extend_from_slice(&(total as u16).to_be_bytes());
        ip.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 64, 1, 0, 0]);
        ip.extend_from_slice(&src_ip);
        ip.extend_from_slice(&dst_ip);
        let ipck = inet_checksum(&ip);
        ip[10..12].copy_from_slice(&ipck.to_be_bytes());
        ip.extend_from_slice(&icmp);

        let mut eth = Vec::with_capacity(14 + ip.len());
        eth.extend_from_slice(dst_mac);
        eth.extend_from_slice(&self.mac);
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        eth
    }

    /// If `req_eth` is an ARP request for `my_ip`, build the ARP reply Ethernet
    /// frame (sender = us). The AP's kernel ARPs for our IP before it can route
    /// the ICMP echo *reply* back to us, so without this the ping never returns.
    pub fn build_arp_reply(&self, req_eth: &[u8], my_ip: [u8; 4]) -> Option<Vec<u8>> {
        if req_eth.len() < 14 + 28 || req_eth[12..14] != [0x08, 0x06] {
            return None; // not ARP
        }
        let arp = &req_eth[14..14 + 28];
        if arp[0..2] != [0x00, 0x01] || arp[2..4] != [0x08, 0x00] || arp[6..8] != [0x00, 0x01] {
            return None; // not an Ethernet/IPv4 ARP *request*
        }
        if arp[24..28] != my_ip {
            return None; // not asking for our IP
        }
        let sender_mac = &arp[8..14];
        let sender_ip = &arp[14..18];
        let mut eth = Vec::with_capacity(42);
        eth.extend_from_slice(sender_mac); // dst = requester
        eth.extend_from_slice(&self.mac); // src = us
        eth.extend_from_slice(&[0x08, 0x06]); // ARP
        eth.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02]); // reply
        eth.extend_from_slice(&self.mac); // sender hw = us
        eth.extend_from_slice(&my_ip); // sender ip = us
        eth.extend_from_slice(sender_mac); // target hw = requester
        eth.extend_from_slice(sender_ip); // target ip = requester
        Some(eth)
    }

    pub fn bssid(&self) -> Option<[u8; 6]> {
        self.bssid
    }

    /// The IGTK installed via PMF (EAPOL message 3), if any.
    pub fn igtk(&self) -> Option<[u8; 16]> {
        self.igtk
    }

    /// The currently installed GTK (test/inspection helper).
    pub fn gtk(&self) -> [u8; 16] {
        self.gtk
    }

    /// The BIGTK installed via Beacon Protection (EAPOL message 3), if any.
    pub fn bigtk(&self) -> Option<[u8; 16]> {
        self.bigtk
    }

    /// Verify a beacon's BIP Management MIC Element against the installed BIGTK
    /// (Beacon Protection). Returns true if protected and valid.
    pub fn verify_beacon(&self, radiotap_frame: &[u8]) -> bool {
        let Some(bigtk) = self.bigtk else {
            return false;
        };
        let Some(body) = dot11::strip_radiotap(radiotap_frame) else {
            return false;
        };
        let Some(frame) = dot11::Dot11::parse(body) else {
            return false;
        };
        dot11::bip_verify(
            &bigtk,
            frame.fc0,
            frame.fc1,
            &frame.addr1,
            &frame.addr2,
            &frame.addr3,
            &frame.body,
        )
    }

    /// Verify a received BIP-protected group-addressed management frame against
    /// the installed IGTK.
    pub fn verify_group_mgmt(&self, radiotap_frame: &[u8]) -> bool {
        let Some(igtk) = self.igtk else { return false };
        let Some(body) = dot11::strip_radiotap(radiotap_frame) else {
            return false;
        };
        let Some(frame) = dot11::Dot11::parse(body) else {
            return false;
        };
        dot11::bip_verify(
            &igtk,
            frame.fc0,
            frame.fc1,
            &frame.addr1,
            &frame.addr2,
            &frame.addr3,
            &frame.body,
        )
    }
}

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
