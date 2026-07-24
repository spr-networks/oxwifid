//! Protected uplink decryption and downlink Ethernet delivery.

use super::*;

impl Ap {
    pub(super) fn handle_data_uplink(&mut self, frame: &dot11::Dot11, out: &mut Outgoing) {
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
            Some(s) if s.associated => s.pairwise_tk,
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
        match dot11::decrypt_protected_data_sec(
            self.pairwise_cipher,
            frame,
            &tk[..self.pairwise_cipher.key_len()],
            false,
            sec,
        ) {
            // sanity: source MAC in the Ethernet frame must match the station
            Some(eth) if eth.len() >= 12 && eth[6..12] == sta => {
                if let Some(s) = self.stations.get_mut(&sta) {
                    s.last_rx_pn = pn;
                }
                // Guest BSS client isolation: a frame addressed to another of
                // this AP's stations must not be carried. It still counts for
                // replay state (last_rx_pn above) — it was a valid frame from
                // the station, just not one the AP will forward.
                if self.guest {
                    let mut dst = [0u8; 6];
                    dst.copy_from_slice(&eth[0..6]);
                    if matches!(self.stations.get(&dst), Some(d) if d.associated) {
                        return;
                    }
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

        // Guest BSS client isolation: a frame whose source is one of this AP's
        // own stations is station-to-station traffic reflected back by an
        // external bridge (the direct path is already dropped on uplink).
        // Covers hairpinned unicast and re-broadcast alike.
        if self.guest && matches!(self.stations.get(&src), Some(s) if s.associated) {
            return frames;
        }

        let (cipher, key_id, pn, tk, a1, qos_tid, sec_addrs) =
            if is_multicast(&dst) || is_broadcast(&dst) {
                let Some(pn) = self.next_group_pn() else {
                    return frames;
                };
                // Group-addressed: encrypt at the current GTK key index (toggles
                // 1<->2 on rekey), the same index advertised in the GTK KDE and
                // installed in the kernel, so receivers select the matching key.
                let mut gtk = [0u8; 32];
                gtk[..16].copy_from_slice(&self.gtk);
                (
                    dot11::DataCipher::Ccmp128,
                    self.gtk_key_id,
                    pn,
                    gtk,
                    dst,
                    None,
                    None,
                )
            } else {
                match self.stations.get(&dst) {
                    Some(s) if s.associated => {}
                    _ => return frames,
                }
                let s = self.stations.get_mut(&dst).unwrap();
                let Some(pn) = s.next_client_pn() else {
                    return frames;
                };
                // QoS Data to a WMM station, with the user priority derived from the
                // packet's DSCP (so voice/video/etc. land in the right access category).
                let qos = if s.wmm {
                    Some(dot11::wmm_tid(eth))
                } else {
                    None
                };
                let tk = s.pairwise_tk;
                let sec = self.mld_data_tx_sec_addrs(&dst, &src);
                (self.pairwise_cipher, 0u8, pn, tk, dst, qos, sec)
            };

        let sc = self.next_sc();
        let (sec_a1, sec_a2, sec_a3) = sec_addrs.unwrap_or((a1, self.mac, src));
        let frame = dot11::build_protected_data_sec(
            cipher,
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
            &tk[..cipher.key_len()],
            ethertype,
            inner,
            qos_tid,
        );
        let mut f = dot11::RADIOTAP_TX.to_vec();
        f.extend_from_slice(&frame);
        frames.push(f);
        frames
    }
}
