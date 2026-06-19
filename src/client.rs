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
    gtk: [u8; 16],
    sc: i32,
    client_pn: u64,
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
            gtk: [0; 16],
            sc: 0,
            client_pn: 0,
            test_snonce: None,
            password: psk.as_bytes().to_vec(),
            sae_enabled: false,
            sae_h2e: true,
            sae: None,
            sae_pmk: None,
            igtk: None,
        }
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
        if is_mgmt && self.connected >= 2 && (frame.subtype() == dot11::SUBTYPE_DEAUTH || frame.subtype() == dot11::SUBTYPE_DISASSOC || frame.subtype() == dot11::SUBTYPE_ACTION) {
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
            out.tx(dot11::build_assoc_req(&bssid, &self.mac, &ssid, sc));
            return out;
        }

        // Association response
        if self.connected == 1 && is_mgmt && frame.subtype() == dot11::SUBTYPE_ASSOC_RESP {
            self.connected = 2;
            return out;
        }

        // EAPOL key frames from the AP
        if self.connected > 1 && frame.is_eapol() {
            if !frame.from_ds() || frame.addr1 != self.mac {
                return out;
            }
            if self.eapol_state == 0 {
                self.send_eapol2(&frame, &mut out);
            } else if self.eapol_state == 1 {
                self.send_eapol4(&frame, &mut out);
            }
            return out;
        }

        // Encrypted downlink data
        if self.connected > 3 && frame.frame_type() == dot11::TYPE_DATA && frame.protected() && frame.from_ds() {
            let key_id = frame.ccmp_key_id();
            let tk = if key_id == 1 { self.gtk } else { self.tk };
            if let Some(eth) = dot11::decrypt_ccmp(&frame, &tk, true) {
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
            // Only SA Query is handled, and only when PMF-protected.
            if !pmf || !frame.protected() {
                return;
            }
            if let Some(plain) = dot11::decrypt_ccmp_mgmt(frame, &self.tk) {
                if let Some((action, trans_id)) = dot11::parse_sa_query(&plain) {
                    if action == dot11::SA_QUERY_REQUEST {
                        if let Some(bssid) = self.bssid {
                            let pn = self.next_client_pn();
                            let sc = self.next_sc();
                            out.tx(dot11::build_protected_sa_query(&bssid, &self.mac, true, true, trans_id, sc, pn, &self.tk));
                        }
                    }
                }
            }
            return;
        }

        // Deauthentication / Disassociation
        let accept = if !pmf {
            true // legacy WPA2: no PMF, honour the frame
        } else if group {
            self.igtk
                .map(|igtk| dot11::bip_verify(&igtk, frame.fc0, frame.fc1, &frame.addr1, &frame.addr2, &frame.addr3, &frame.body))
                .unwrap_or(false)
        } else {
            frame.protected() && dot11::decrypt_ccmp_mgmt(frame, &self.tk).is_some()
        };
        if accept {
            self.disconnect();
        }
    }

    fn disconnect(&mut self) {
        self.connected = 0;
        self.eapol_state = 0;
        self.tk = [0; 16];
        self.gtk = [0; 16];
        self.igtk = None;
        self.sae = None;
        self.sae_pmk = None;
    }

    /// Send our SAE commit to start the exchange (status 126 for H2E, 0 for
    /// hunting-and-pecking).
    fn start_sae(&mut self, bssid: &[u8; 6], out: &mut ClientOut) {
        let sae = if self.sae_h2e {
            Some(crate::sae::Sae::new_h2e(&self.ssid, &self.password, None, &self.mac, bssid))
        } else {
            crate::sae::Sae::new_hunting_pecking(&self.password, &self.mac, bssid)
        };
        let Some(mut sae) = sae else { return };
        sae.prepare_commit(None);
        let commit = sae.write_commit();
        let status = if self.sae_h2e { dot11::STATUS_SAE_H2E } else { dot11::STATUS_SUCCESS };
        let sc = self.next_sc();
        out.tx(dot11::build_sae_auth(bssid, &self.mac, bssid, dot11::FC_TODS, sc, 1, status, &commit));
        self.sae = Some(sae);
    }

    /// Handle an SAE authentication frame from the AP (commit then confirm).
    fn handle_sae_auth(&mut self, seq: u16, payload: &[u8], out: &mut ClientOut) {
        match seq {
            1 => {
                // AP commit -> derive keys, send our confirm
                let confirm = {
                    let Some(sae) = self.sae.as_mut() else { return };
                    if sae.parse_peer_commit(payload).is_err() || sae.process_commit().is_err() {
                        return;
                    }
                    sae.write_confirm()
                };
                let Some(bssid) = self.bssid else { return };
                let sc = self.next_sc();
                out.tx(dot11::build_sae_auth(&bssid, &self.mac, &bssid, dot11::FC_TODS, sc, 2, dot11::STATUS_SUCCESS, &confirm));
            }
            2 => {
                // AP confirm -> verify, store PMK, associate
                let verified = self.sae.as_ref().map(|s| s.check_confirm(payload).is_ok()).unwrap_or(false);
                if !verified {
                    return;
                }
                let pmk = self.sae.as_ref().map(|s| {
                    let mut p = [0u8; 32];
                    p.copy_from_slice(&s.pmk);
                    p
                });
                self.sae_pmk = pmk;
                let Some(bssid) = self.bssid else { return };
                let sc = self.next_sc();
                let ssid = self.ssid.clone();
                out.tx(dot11::build_assoc_req(&bssid, &self.mac, &ssid, sc));
            }
            _ => {}
        }
    }

    fn send_eapol2(&mut self, m1: &dot11::Dot11, out: &mut ClientOut) {
        let Some(bssid) = self.bssid else { return };
        let Some(key_body) = m1.eapol_key_body() else { return };
        let Some(ek) = dot11::EapolKey::parse(key_body) else { return };

        self.anonce = ek.key_nonce;
        self.snonce = self.test_snonce.unwrap_or_else(random_bytes::<32>);

        // Use the SAE PMK + SHA-256 key descriptors when present (WPA3), else
        // the PSK-derived PMK + SHA-1 (WPA2).
        let sha256 = self.sae_pmk.is_some();
        let pmk = self.sae_pmk.unwrap_or(self.pmk);
        if sha256 {
            let ptk = crypto::derive_ptk_sha256(&pmk, &bssid, &self.mac, &self.anonce, &self.snonce);
            self.kck.copy_from_slice(&ptk[..16]);
            self.kek.copy_from_slice(&ptk[16..32]);
            self.tk.copy_from_slice(&ptk[32..48]);
        } else {
            let ptk = crypto::custom_prf512(&pmk, &bssid, &self.mac, &self.anonce, &self.snonce);
            self.kck.copy_from_slice(&ptk[..16]);
            self.kek.copy_from_slice(&ptk[16..32]);
            self.tk.copy_from_slice(&ptk[32..48]);
        }
        self.client_pn = 0;

        let sc = self.next_sc();
        let kck = self.kck;
        let snonce = self.snonce;
        out.tx(dot11::build_eapol_m2(&bssid, &self.mac, &snonce, &kck, sc, sha256));
        self.eapol_state = 1;
    }

    fn send_eapol4(&mut self, m3: &dot11::Dot11, out: &mut ClientOut) {
        let Some(bssid) = self.bssid else { return };
        let Some(eapol_frame) = m3.eapol_frame() else { return };
        let Some(key_body) = m3.eapol_key_body() else { return };
        let Some(ek) = dot11::EapolKey::parse(key_body) else { return };

        // verify the AP's MIC over message 3
        let mic_off = 4 + ek.mic_offset;
        let mut to_check = eapol_frame.to_vec();
        if to_check.len() < mic_off + 16 {
            return;
        }
        for b in to_check[mic_off..mic_off + 16].iter_mut() {
            *b = 0;
        }
        let sha256 = self.sae_pmk.is_some();
        let computed = if sha256 {
            crypto::hmac_sha256(&self.kck, &to_check)[..16].to_vec()
        } else {
            crypto::hmac_sha1(&self.kck, &to_check)[..16].to_vec()
        };
        if !crypto::constant_time_eq(&computed[..16], &ek.key_mic) {
            return; // bad MIC, drop
        }

        // unwrap and install the GTK (RSN || GTK-KDE [|| IGTK-KDE] inside the
        // wrapped key data). The GTK lies 8 bytes into the GTK KDE, which
        // follows the 22-byte RSN element; a trailing IGTK KDE does not move it.
        if let Some(unwrapped) = crypto::aes_unwrap(&self.kek, &ek.key_data) {
            if unwrapped.len() >= 46 {
                self.gtk.copy_from_slice(&unwrapped[30..46]);
            }
            // Install the IGTK (PMF) if the AP delivered one.
            if let Some((_id, _ipn, igtk)) = dot11::parse_igtk_kde(&unwrapped) {
                self.igtk = Some(igtk);
            }
        }

        let sc = self.next_sc();
        let kck = self.kck;
        out.tx(dot11::build_eapol_m4(&bssid, &self.mac, &kck, sc, sha256));
        self.connected = 4;
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
        let frame = dot11::build_ccmp_data(
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
        );
        let mut f = dot11::RADIOTAP_TX.to_vec();
        f.extend_from_slice(&frame);
        Some(f)
    }

    /// Build a ping (ICMP echo) Ethernet frame from `src_ip` to `dst_ip` for the
    /// gateway MAC.
    pub fn build_ping(&self, dst_mac: &[u8; 6], src_ip: [u8; 4], dst_ip: [u8; 4]) -> Vec<u8> {
        let mut icmp = vec![8u8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01];
        icmp.extend_from_slice(b"barely-ap-rust-ping");
        let ck = inet_checksum(&icmp);
        icmp[2..4].copy_from_slice(&ck.to_be_bytes());

        let total = 20 + icmp.len();
        let mut ip = Vec::with_capacity(total);
        ip.extend_from_slice(&[0x45, 0x00]);
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

    pub fn bssid(&self) -> Option<[u8; 6]> {
        self.bssid
    }

    /// The IGTK installed via PMF (EAPOL message 3), if any.
    pub fn igtk(&self) -> Option<[u8; 16]> {
        self.igtk
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
        dot11::bip_verify(&igtk, frame.fc0, frame.fc1, &frame.addr1, &frame.addr2, &frame.addr3, &frame.body)
    }
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
