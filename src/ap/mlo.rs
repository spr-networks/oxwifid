//! Multi-Link Operation advertisement, association, and address translation.

use super::*;

impl Ap {
    pub(super) fn mld_link_info_for(&self, link_id: u8) -> Vec<u8> {
        let mut info = Vec::new();
        if !self.mld {
            return info;
        }
        for link in self.active_mld_links() {
            if link.link_id == link_id {
                continue;
            }
            let mut inner = dot11::ap_mld_profile_inner(
                &self.ssid,
                link.channel,
                &self.country,
                link.width,
                link.band6,
                self.wmm,
                self.phy_mode,
                self.security_mode(),
                self.punct,
            );
            if let Some(caps) = self.mld_link_phy_capabilities.get(&link.link_id) {
                // Capability Information occupies the first two bytes.
                dot11::apply_phy_capabilities(&mut inner, 2, caps);
            }
            info.extend_from_slice(&dot11::per_sta_profile(link.link_id, &link.mac, &inner));
        }
        info
    }

    /// Build the Link Info field for an MLO (Re)Association Response. Only
    /// partner links requested by this station are included, and each profile
    /// uses the association-response fixed fields (Capability + Status Code)
    /// rather than the beacon/probe-response shape.
    pub(super) fn mld_assoc_link_info_for(&self, requested: &[(u8, [u8; 6])]) -> Vec<u8> {
        let mut info = Vec::new();
        if !self.mld {
            return info;
        }
        for link in self.active_mld_links() {
            if !requested
                .iter()
                .any(|(requested_link_id, _)| *requested_link_id == link.link_id)
            {
                continue;
            }
            let mut inner = dot11::ap_mld_assoc_profile_inner(
                &self.ssid,
                link.channel,
                &self.country,
                link.width,
                link.band6,
                self.wmm,
                self.phy_mode,
                self.punct,
            );
            if let Some(caps) = self.mld_link_phy_capabilities.get(&link.link_id) {
                // Capability Information + Status Code occupy the first four
                // bytes of an association-response Per-STA Profile.
                dot11::apply_phy_capabilities(&mut inner, 4, caps);
            }
            info.extend_from_slice(&dot11::per_sta_profile(link.link_id, &link.mac, &inner));
        }
        info
    }

    pub(super) fn mld_max_simultaneous_links_minus_one(&self) -> u8 {
        self.active_mld_links().len().saturating_sub(1).min(0x0f) as u8
    }

    /// Apply the AP-mode MLD capabilities reported by the kernel. This mirrors
    /// reference AP: AP transition/padding delays are zeroed, the active-link count
    /// replaces the hardware maximum, unsupported TID-to-link negotiation is
    /// cleared, and link reconfiguration support is advertised.
    pub fn set_mld_driver_capabilities(&mut self, eml: u16, mld: u16) {
        const EMLSR_DELAY_MASKS: u16 = 0x000e | 0x0070;
        self.mld_eml_capability = eml & !EMLSR_DELAY_MASKS;
        self.mld_driver_capability = Some(mld);
    }

    /// Set the driver's capability payloads for one affiliated link.
    pub fn set_mld_link_phy_capabilities(
        &mut self,
        link_id: u8,
        capabilities: dot11::PhyCapabilities,
    ) {
        self.mld_link_phy_capabilities.insert(link_id, capabilities);
    }

    pub(super) fn advertised_mld_capability(&self) -> u16 {
        const MAX_SIMULTANEOUS_LINKS_MASK: u16 = 0x000f;
        const TID_TO_LINK_NEGOTIATION_MASK: u16 = 0x0060;
        const LINK_RECONFIGURATION_SUPPORT: u16 = 0x2000;
        let active = u16::from(self.mld_max_simultaneous_links_minus_one());
        match self.mld_driver_capability {
            Some(driver) => {
                let maximum = driver & MAX_SIMULTANEOUS_LINKS_MASK;
                (driver & !(MAX_SIMULTANEOUS_LINKS_MASK | TID_TO_LINK_NEGOTIATION_MASK))
                    | active.min(maximum)
                    | LINK_RECONFIGURATION_SUPPORT
            }
            None => active,
        }
    }

    pub(super) fn mld_basic_element(&self, link_id: u8, link_info: &[u8]) -> Vec<u8> {
        dot11::multi_link_ap_basic_capabilities(
            &self.mld_mac,
            link_id,
            self.bss_change_count,
            self.mld_eml_capability,
            self.advertised_mld_capability(),
            link_info,
        )
    }

    pub(super) fn mld_tid_to_link_element(&self) -> Vec<u8> {
        self.mld_default_link_mask
            .map(dot11::tid_to_link_mapping_same_set)
            .unwrap_or_default()
    }

    pub(super) fn mld_link_disabled(&self, link_id: u8) -> bool {
        self.mld_default_link_mask
            .is_some_and(|mask| mask & (1u16 << link_id) == 0)
    }

    /// Advertise every other affiliated link using the MLD form of the Reduced
    /// Neighbor Report. reference AP emits this independently of its generic `rnr`
    /// option: it is how a client on (for example) the 5 GHz association link
    /// learns the real 6 GHz BSSID, channel, width-derived operating class and
    /// Link ID before it can include that partner in its association MLE.
    pub(super) fn mld_rnr_for(&self, reporting_link_id: u8) -> Vec<u8> {
        if !self.mld {
            return Vec::new();
        }
        let mut reports = Vec::new();
        for link in self.active_mld_links() {
            if link.link_id == reporting_link_id {
                continue;
            }
            reports.extend_from_slice(&dot11::mld_reduced_neighbor_report_with_disabled(
                &link.mac,
                &self.ssid,
                dot11::operating_class(link.channel, link.width, link.band6),
                link.channel,
                0,
                link.link_id,
                self.bss_change_count,
                self.mld_link_disabled(link.link_id),
            ));
        }
        reports
    }

    pub(super) fn is_valid_peer_mac(mac: &[u8; 6]) -> bool {
        mac.iter().any(|b| *b != 0) && (mac[0] & 0x01 == 0)
    }

    pub(super) fn reject_assoc(&mut self, sta: &[u8; 6], reassoc: bool, out: &mut Outgoing) {
        self.reject_assoc_status(sta, reassoc, dot11::STATUS_UNSPECIFIED_FAILURE, out);
    }

    pub(super) fn reject_assoc_status(
        &mut self,
        sta: &[u8; 6],
        reassoc: bool,
        status: u16,
        out: &mut Outgoing,
    ) {
        let sub = if reassoc {
            0x03
        } else {
            dot11::SUBTYPE_ASSOC_RESP
        };
        let sc = self.next_sc();
        out.tx(dot11::build_assoc_resp_reject(
            &self.mac, sta, status, sub, sc,
        ));
    }

    pub(super) fn peer_mac_in_use_by_other_station(&self, sta: &[u8; 6], mac: &[u8; 6]) -> bool {
        self.stations.iter().any(|(other, s)| {
            other != sta
                && (*other == *mac
                    || s.client_mld_mac.as_ref() == Some(mac)
                    || s.client_mld_links
                        .iter()
                        .any(|(_, link_mac)| link_mac == mac))
        })
    }

    pub(super) fn validate_mld_assoc_links(
        &self,
        sta: &[u8; 6],
        client_mld: &[u8; 6],
        assoc_ies: &[u8],
    ) -> Option<Vec<(u8, [u8; 6])>> {
        let active_links = self.active_mld_links();
        let configured: HashSet<u8> = active_links.iter().map(|l| l.link_id).collect();
        let mut ap_addrs: HashSet<[u8; 6]> = active_links.iter().map(|l| l.mac).collect();
        ap_addrs.insert(self.mld_mac);

        if !Self::is_valid_peer_mac(sta)
            || !Self::is_valid_peer_mac(client_mld)
            || ap_addrs.contains(sta)
            || ap_addrs.contains(client_mld)
            || self.peer_mac_in_use_by_other_station(sta, client_mld)
        {
            return None;
        }

        let mut seen_link_ids = HashSet::new();
        let mut seen_macs = HashSet::new();
        let mut peer_addrs = HashSet::new();
        peer_addrs.insert(*sta);
        peer_addrs.insert(*client_mld);

        let mut links = Vec::new();
        for (link_id, link_mac) in dot11::parse_mld_link_macs_checked(assoc_ies)? {
            if !configured.contains(&link_id)
                || link_id == self.link_id
                || !Self::is_valid_peer_mac(&link_mac)
                || ap_addrs.contains(&link_mac)
                || peer_addrs.contains(&link_mac)
                || !seen_link_ids.insert(link_id)
                || !seen_macs.insert(link_mac)
                || self.peer_mac_in_use_by_other_station(sta, &link_mac)
            {
                return None;
            }
            links.push((link_id, link_mac));
        }
        Some(links)
    }

    pub(super) fn mld_data_rx_sec_addrs(
        &self,
        sta: &[u8; 6],
        frame: &dot11::Dot11,
    ) -> Option<([u8; 6], [u8; 6], [u8; 6])> {
        if !self.mld {
            return None;
        }
        let sta_mld = self.stations.get(sta).and_then(|s| s.client_mld_mac)?;
        let sec_a3 = if frame.addr3 == self.mac || frame.addr3 == self.mld_mac {
            self.mld_mac
        } else {
            frame.addr3
        };
        Some((self.mld_mac, sta_mld, sec_a3))
    }

    pub(super) fn mld_data_tx_sec_addrs(
        &self,
        sta: &[u8; 6],
        src: &[u8; 6],
    ) -> Option<([u8; 6], [u8; 6], [u8; 6])> {
        if !self.mld {
            return None;
        }
        let sta_mld = self.stations.get(sta).and_then(|s| s.client_mld_mac)?;
        let sec_a3 = if *src == self.mac || *src == self.mld_mac {
            self.mld_mac
        } else {
            *src
        };
        Some((sta_mld, self.mld_mac, sec_a3))
    }

    pub(super) fn mld_mgmt_rx_sec_addrs(
        &self,
        sta: &[u8; 6],
    ) -> Option<([u8; 6], [u8; 6], [u8; 6])> {
        if !self.mld {
            return None;
        }
        let sta_mld = self.stations.get(sta).and_then(|s| s.client_mld_mac)?;
        Some((self.mld_mac, sta_mld, self.mld_mac))
    }

    pub(super) fn mld_mgmt_tx_sec_addrs(
        &self,
        sta: &[u8; 6],
    ) -> Option<([u8; 6], [u8; 6], [u8; 6])> {
        if !self.mld {
            return None;
        }
        let sta_mld = self.stations.get(sta).and_then(|s| s.client_mld_mac)?;
        Some((sta_mld, self.mld_mac, self.mld_mac))
    }
}
