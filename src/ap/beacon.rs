//! Beacon and probe-independent BSS advertisement construction.

use super::*;

impl Ap {
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
        let tail = dot11::security_tail_for_cipher(self.security_mode(), self.pairwise_cipher);
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

    pub(super) fn beacon_frame_inner(&mut self, protect: bool) -> Vec<u8> {
        let ts = self.current_timestamp();
        let tail = dot11::security_tail_for_cipher(self.security_mode(), self.pairwise_cipher);
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
}
