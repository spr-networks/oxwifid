//! Group-key installation and group-key handshake processing.

use super::*;

fn packet_number(bytes: [u8; 6]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], 0, 0,
    ])
}

impl Client {
    /// Install the GTK / IGTK / BIGTK KDEs from an unwrapped EAPOL key-data
    /// blob (shared by EAPOL m3 and Group Key msg1). Tracks the GTK key index so
    /// group downlink is matched to it. The authenticated RSC/IPN values seed
    /// the receive replay windows, preventing frames captured earlier under a
    /// still-current GTK/IGTK from being accepted by a newly joined client.
    pub(super) fn install_group_keys(&mut self, unwrapped: &[u8], key_rsc: u64) -> bool {
        if key_rsc > 0x0000_ffff_ffff_ffff {
            return false;
        }
        let gtk = dot11::parse_gtk_kde_full(unwrapped)
            .and_then(|(key_id, gtk)| (gtk.len() == 16).then_some((key_id, key_rsc, gtk)))
            .or_else(|| {
                dot11::parse_mlo_gtk_kde_full(unwrapped).and_then(|(_link_id, key_id, pn, gtk)| {
                    (gtk.len() == 16).then_some((key_id, packet_number(pn), gtk))
                })
            });
        let igtk = dot11::parse_igtk_kde(unwrapped).or_else(|| {
            dot11::parse_mlo_igtk_kde(unwrapped).map(|(_link_id, id, ipn, igtk)| (id, ipn, igtk))
        });
        // Every secured association needs a GTK. SAE/OWE negotiate mandatory
        // PMF and must also receive an IGTK; accepting M3 without it would mark
        // the port connected while being unable to authenticate group robust
        // management frames.
        let Some((gtk_key_id, gtk_rsc, gtk)) = gtk else {
            return false;
        };
        if self.sae_pmk.is_some() && igtk.is_none() {
            return false;
        }

        self.gtk.zeroize();
        self.gtk.copy_from_slice(&gtk);
        self.gtk_key_id = gtk_key_id;
        self.last_rx_gpn = [gtk_rsc; 17];

        if let Some((id, ipn, igtk)) = igtk {
            if let Some(old) = self.igtk.as_mut() {
                old.zeroize();
            }
            self.igtk = Some(igtk);
            self.igtk_key_id = Some(id);
            self.last_rx_igtk_ipn = packet_number(ipn);
        }
        if let Some((_id, _ipn, bigtk)) = dot11::parse_bigtk_kde(unwrapped) {
            if let Some(old) = self.bigtk.as_mut() {
                old.zeroize();
            }
            self.bigtk = Some(bigtk);
        } else if let Some((_link_id, _id, _ipn, bigtk)) = dot11::parse_mlo_bigtk_kde(unwrapped) {
            if let Some(old) = self.bigtk.as_mut() {
                old.zeroize();
            }
            self.bigtk = Some(bigtk);
        }
        true
    }

    /// Handle Group Key Handshake message 1: verify, install the new GTK/IGTK,
    /// and reply with message 2.
    pub(super) fn handle_group_rekey(
        &mut self,
        eapol_frame: &[u8],
        ek: &dot11::EapolKey,
        protected_transport: bool,
        out: &mut ClientOut,
    ) {
        let Some(bssid) = self.bssid else { return };
        let key_mic = self.key_mic();

        // verify MIC
        let mic_off = 4 + ek.mic_offset;
        if eapol_frame.len() < mic_off + 16 {
            return;
        }
        let mut to_check = eapol_frame.to_vec();
        for b in to_check[mic_off..mic_off + 16].iter_mut() {
            *b = 0;
        }
        let mut computed = key_mic.compute(&self.kck, &to_check);
        let mic_valid = crypto::constant_time_eq(&computed, &ek.key_mic);
        computed.zeroize();
        if !mic_valid {
            return;
        }
        // A lower replay counter is stale. An equal counter is the AP retrying
        // message 1 after our message 2 was lost: re-ACK it below without
        // reinstalling the GTK/IGTK or resetting any receive replay window.
        if ek.key_replay_counter < self.eapol_replay {
            return;
        }
        let first_delivery = ek.key_replay_counter > self.eapol_replay;
        if first_delivery {
            // Install only on the first delivery. The unwrapped buffer contains
            // live group keys and is explicitly cleared after copying.
            let Some(mut unwrapped) = crypto::aes_unwrap(&self.kek, &ek.key_data) else {
                return;
            };
            if !self.install_group_keys(&unwrapped, ek.key_rsc) {
                unwrapped.zeroize();
                return;
            }
            unwrapped.zeroize();
            self.eapol_replay = ek.key_replay_counter;
        }

        let sc = self.next_sc();
        let kck = self.kck;
        let message_2 = dot11::build_group_key_msg2(
            &bssid,
            &self.mac,
            &kck,
            ek.key_replay_counter,
            sc,
            key_mic,
        );
        if protected_transport {
            let Some(eapol) = dot11::Dot11::parse(&message_2)
                .and_then(|frame| frame.eapol_frame().map(ToOwned::to_owned))
            else {
                return;
            };
            let mut ethernet = Vec::with_capacity(14 + eapol.len());
            ethernet.extend_from_slice(&bssid);
            ethernet.extend_from_slice(&self.mac);
            ethernet.extend_from_slice(&dot11::ETHERTYPE_EAPOL.to_be_bytes());
            ethernet.extend_from_slice(&eapol);
            if let Some(protected) = self.encrypt_uplink(&ethernet) {
                out.frames.push(protected);
            }
        } else {
            out.tx(message_2);
        }
    }
}
