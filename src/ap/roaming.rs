//! Station key inspection and protected roaming/steering frame generation.

use super::*;

impl Ap {
    /// The *installed* pairwise key for a station: the TK only once the 4-way is
    /// complete (`associated`). Returns `None` beforehand so no code path ever
    /// performs CCMP with the all-zero placeholder key — i.e. a station that
    /// skipped ahead in the auth sequence cannot trigger crypto with a NULL key.
    pub(super) fn installed_pairwise_key(&self, sta: &[u8; 6]) -> Option<[u8; 32]> {
        self.stations
            .get(sta)
            .filter(|s| s.associated)
            .map(|s| s.pairwise_tk)
    }

    /// The session TK for a station (test/inspection helper).
    pub fn station_tk(&self, sta: &[u8; 6]) -> Option<[u8; 16]> {
        self.stations.get(sta).map(|s| s.tk)
    }

    /// Full negotiated pairwise key for Linux nl80211 installation.
    pub fn station_pairwise_key(&self, sta: &[u8; 6]) -> Option<&[u8]> {
        self.stations
            .get(sta)
            .map(|s| &s.pairwise_tk[..self.pairwise_cipher.key_len()])
    }

    /// 802.11v: send a (CCMP-protected) BSS Transition Management request, e.g.
    /// to steer or kick a station (`disassoc_imminent`).
    pub fn btm_request(
        &mut self,
        sta: &[u8; 6],
        disassoc_imminent: bool,
        disassoc_timer: u16,
    ) -> Option<Vec<u8>> {
        let tk = self.installed_pairwise_key(sta)?;
        let pn = self.stations.get_mut(sta)?.next_client_pn()?;
        let sc = self.next_sc();
        let sec = self.mld_mgmt_tx_sec_addrs(sta);
        let frame = dot11::build_protected_btm_request_for_cipher_sec(
            self.pairwise_cipher,
            &self.mac,
            sta,
            1,
            disassoc_imminent,
            disassoc_timer,
            sc,
            pn,
            &tk[..self.pairwise_cipher.key_len()],
            sec,
        );
        Some(prepend_radiotap(frame))
    }

    /// 802.11k: send a (CCMP-protected) Neighbor Report Response listing this AP.
    pub fn neighbor_report(&mut self, sta: &[u8; 6]) -> Option<Vec<u8>> {
        let tk = self.installed_pairwise_key(sta)?;
        let pn = self.stations.get_mut(sta)?.next_client_pn()?;
        let sc = self.next_sc();
        let op_class = if dot11::is_5ghz(self.channel) {
            115
        } else {
            81
        };
        let neighbor = dot11::neighbor_report_element(&self.mac, op_class, self.channel);
        let sec = self.mld_mgmt_tx_sec_addrs(sta);
        let frame = dot11::build_protected_neighbor_report_for_cipher_sec(
            self.pairwise_cipher,
            &self.mac,
            sta,
            1,
            &neighbor,
            sc,
            pn,
            &tk[..self.pairwise_cipher.key_len()],
            sec,
        );
        Some(prepend_radiotap(frame))
    }

    /// Build a CCMP-protected unicast Deauthentication toward a PMF station.
    pub fn protected_deauth(&mut self, sta: &[u8; 6], reason: u16) -> Option<Vec<u8>> {
        let tk = self.installed_pairwise_key(sta)?;
        let pn = self.stations.get_mut(sta)?.next_client_pn()?;
        let sc = self.next_sc();
        let sec = self.mld_mgmt_tx_sec_addrs(sta);
        let frame = dot11::build_protected_deauth_for_cipher_sec(
            self.pairwise_cipher,
            &self.mac,
            sta,
            reason,
            sc,
            pn,
            &tk[..self.pairwise_cipher.key_len()],
            sec,
        );
        let mut f = dot11::RADIOTAP_TX.to_vec();
        f.extend_from_slice(&frame);
        Some(f)
    }
}
