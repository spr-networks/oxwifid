use super::*;

/// Select the nl80211 link scopes used for a per-station AP_VLAN and its GTK.
///
/// A non-MLO AP has no link attribute. A legacy peer on an MLD AP belongs only
/// to its association link. An MLO peer must be updated on every negotiated
/// link, just as the reference AP walks every partner `hostapd_data`.
pub(super) fn per_station_link_ids(
    ap_mld: bool,
    peer_mld: bool,
    association_link: u8,
    mut negotiated_links: Vec<u8>,
) -> Vec<Option<u8>> {
    if !ap_mld {
        return vec![None];
    }
    if !peer_mld {
        return vec![Some(association_link)];
    }
    if !negotiated_links.contains(&association_link) {
        negotiated_links.push(association_link);
    }
    negotiated_links.sort_unstable();
    negotiated_links.dedup();
    negotiated_links.into_iter().map(Some).collect()
}

pub(super) fn set_sta_vlan_message(
    family: u16,
    ap_ifindex: u32,
    sta: &[u8; 6],
    vlan_ifindex: u32,
    link_id: Option<u8>,
    seq: u32,
) -> GenlMessage {
    let mut m = GenlMessage::new(family, NL80211_CMD_SET_STATION, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ap_ifindex))
        .attr(Attr::bytes(NL80211_ATTR_MAC, sta))
        .attr(Attr::u32(NL80211_ATTR_STA_VLAN, vlan_ifindex));
    if let Some(link_id) = link_id {
        m = m.attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id));
    }
    m
}

/// Move one station link into an AP_VLAN (SET_STATION +
/// NL80211_ATTR_STA_VLAN), so its data path and group key live on that
/// per-station interface.
pub(super) fn nl_set_sta_vlan(
    sock: &mut NetlinkSocket,
    family: u16,
    ap_ifindex: u32,
    sta: &[u8; 6],
    vlan_ifindex: u32,
    link_id: Option<u8>,
) -> io::Result<()> {
    let seq = sock.next_seq();
    let m = set_sta_vlan_message(family, ap_ifindex, sta, vlan_ifindex, link_id, seq);
    sock.request_ack(m)
}

#[cfg(test)]
mod station_vlan_tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn mld_peer_binds_every_negotiated_link() {
        assert_eq!(
            per_station_link_ids(true, true, 1, vec![1, 0, 1]),
            vec![Some(0), Some(1)]
        );
        assert_eq!(
            per_station_link_ids(true, true, 1, vec![0]),
            vec![Some(0), Some(1)],
            "association link is retained even if partner parsing omitted it"
        );
    }

    #[test]
    fn legacy_peer_uses_its_actual_mld_ap_association_link() {
        assert_eq!(
            per_station_link_ids(true, false, 1, Vec::new()),
            vec![Some(1)]
        );
        assert_eq!(
            per_station_link_ids(false, false, 0, Vec::new()),
            vec![None]
        );
    }

    #[test]
    fn sta_vlan_message_scopes_the_requested_mlo_link() {
        let sta = [0x02, 0, 0, 0, 0, 1];
        let msg = set_sta_vlan_message(42, 7, &sta, 88, Some(1), 9);
        assert_eq!(msg.cmd, NL80211_CMD_SET_STATION);
        assert_eq!(
            msg.attrs
                .iter()
                .find(|attr| attr.typ == NL80211_ATTR_STA_VLAN)
                .map(|attr| attr.data.as_slice()),
            Some(88u32.to_ne_bytes().as_slice())
        );
        assert_eq!(
            msg.attrs
                .iter()
                .find(|attr| attr.typ == NL80211_ATTR_MLO_LINK_ID)
                .map(|attr| attr.data.as_slice()),
            Some([1u8].as_slice())
        );
    }

    #[test]
    fn pairwise_key_delete_is_explicit_and_station_scoped() {
        let sta = [0x02, 0, 0, 0, 0, 1];
        let msg = del_pairwise_key_message(42, 9, 7, &sta);
        assert_eq!(msg.cmd, NL80211_CMD_DEL_KEY);
        assert_eq!(
            msg.attrs
                .iter()
                .find(|attr| attr.typ == NL80211_ATTR_IFINDEX)
                .map(|attr| attr.data.as_slice()),
            Some(7u32.to_ne_bytes().as_slice())
        );
        assert_eq!(
            msg.attrs
                .iter()
                .find(|attr| attr.typ == NL80211_ATTR_MAC)
                .map(|attr| attr.data.as_slice()),
            Some(sta.as_slice())
        );
        let key = msg
            .attrs
            .iter()
            .find(|attr| attr.typ & !msg::NLA_F_NESTED == NL80211_ATTR_KEY)
            .expect("nested key attributes");
        let key_attrs = msg::parse_attrs(&key.data);
        assert_eq!(
            msg::find_attr(&key_attrs, NL80211_KEY_IDX),
            Some([0u8].as_slice())
        );
    }

    #[test]
    fn retiring_vif_id_is_reserved_until_final_interface_release() {
        let sta = [0x02, 0, 0, 0, 0, 1];
        let now = Instant::now();
        let mut vlan = VlanRegistry {
            enabled: true,
            base_iface: "wlan0".to_string(),
            map: HashMap::new(),
            ifindices: HashSet::new(),
        };
        vlan.insert(
            sta,
            VlanAssignment {
                ifindex: 88,
                vlan_id: PER_STA_VLAN_ID_START,
                ifname: format!("wlan0.{PER_STA_VLAN_ID_START}"),
                sta_addr: sta,
                station_may_be_on_base: false,
                retire_at: Some(now),
                station_removed: false,
                station_cleanup_id: Some(41),
                station_retry_at: None,
                interface_cleanup_id: None,
                interface_retry_at: None,
            },
        );

        assert_eq!(vlan.allocate().unwrap().0, PER_STA_VLAN_ID_START + 1);

        // DEL_STATION completion still does not release the AP_VLAN.
        {
            let assignment = vlan.map.get_mut(&sta).unwrap();
            assignment.station_cleanup_id = None;
            assignment.station_removed = true;
            assignment.interface_cleanup_id = Some(42);
        }
        assert_eq!(vlan.allocate().unwrap().0, PER_STA_VLAN_ID_START + 1);

        // Neither a stale completion nor a matching failure releases it.
        assert!(vlan
            .complete_interface_cleanup(&sta, 41, true, now)
            .is_none());
        assert!(vlan
            .complete_interface_cleanup(&sta, 42, false, now)
            .is_none());
        assert_eq!(vlan.allocate().unwrap().0, PER_STA_VLAN_ID_START + 1);

        // Simulate the retry being assigned a fresh generation. A delayed
        // success from the old job still cannot release the live reservation.
        vlan.map.get_mut(&sta).unwrap().interface_cleanup_id = Some(43);
        assert!(vlan
            .complete_interface_cleanup(&sta, 42, true, now)
            .is_none());
        assert_eq!(vlan.allocate().unwrap().0, PER_STA_VLAN_ID_START + 1);

        // Only the matching successful/absent DEL_INTERFACE ACK frees the id.
        assert!(vlan
            .complete_interface_cleanup(&sta, 43, true, now)
            .is_some());
        assert_eq!(vlan.allocate().unwrap().0, PER_STA_VLAN_ID_START);
    }
}

/// Delete a dynamically-created interface by ifindex. An already-absent
/// interface is success so cleanup retries remain idempotent.
pub(super) fn nl_del_iface(sock: &mut NetlinkSocket, family: u16, ifindex: u32) -> io::Result<()> {
    let seq = sock.next_seq();
    let m = GenlMessage::new(family, NL80211_CMD_DEL_INTERFACE, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex));
    match sock.request_ack(m) {
        Err(error) if kernel_object_is_absent(&error) => Ok(()),
        result => result,
    }
}

/// Allow an attached reference AP control client action enough time to query
/// `STA <mac>` and remove SPR DHCP/firewall state after a disconnect event.
/// The VIF stays reserved throughout this grace period and until the kernel
/// acknowledges its final DEL_INTERFACE.
pub(super) const VLAN_EVENT_GRACE: Duration = Duration::from_secs(5);
pub(super) const CLEANUP_RETRY_DELAY: Duration = Duration::from_millis(100);

#[derive(Clone, Debug)]
pub(super) struct VlanAssignment {
    pub(super) ifindex: u32,
    pub(super) vlan_id: u32,
    pub(super) ifname: String,
    /// nl80211 indexes an MLO peer by its MLD MAC even though RustAP's frame
    /// state remains keyed by the association-link MAC.
    pub(super) sta_addr: [u8; 6],
    /// True only while SET_STA_VLAN may have failed after a partial move. A
    /// normally-bound peer is deleted solely through its AP_VLAN; sending a
    /// redundant base-BSS DEL_STATION can be rejected by strict drivers.
    pub(super) station_may_be_on_base: bool,
    pub(super) retire_at: Option<Instant>,
    pub(super) station_removed: bool,
    pub(super) station_cleanup_id: Option<u64>,
    pub(super) station_retry_at: Option<Instant>,
    pub(super) interface_cleanup_id: Option<u64>,
    pub(super) interface_retry_at: Option<Instant>,
}

#[derive(Clone, Debug)]
pub(super) struct BaseStationCleanup {
    pub(super) kernel_sta: [u8; 6],
    pub(super) cleanup_id: Option<u64>,
    pub(super) retry_at: Instant,
}

/// Per-station-VIF bookkeeping. IDs and names follow reference AP's wildcard VLAN
/// convention (`wlan3.#` -> `wlan3.4096`, `wlan3.4097`, ...).
pub(super) struct VlanRegistry {
    pub(super) enabled: bool,
    pub(super) base_iface: String,
    pub(super) map: std::collections::HashMap<[u8; 6], VlanAssignment>,
    /// AP_VLAN ifindices accepted by the radio's event filter. Keeping this
    /// reverse index avoids scanning every station VIF for every nl80211 event.
    pub(super) ifindices: std::collections::HashSet<u32>,
}

impl VlanRegistry {
    pub(super) fn allocate(&self) -> io::Result<(u32, String)> {
        let vlan_id = first_free_per_sta_vlan_id(self.map.values().map(|v| v.vlan_id))
            .ok_or_else(|| io::Error::other("no free per-station VIF id"))?;
        let ifname = per_sta_vif_name(&self.base_iface, vlan_id).map_err(io::Error::other)?;
        Ok((vlan_id, ifname))
    }

    pub(super) fn assignment_for(&self, mac: &[u8; 6]) -> Option<&VlanAssignment> {
        self.map.get(mac).or_else(|| {
            self.map
                .values()
                .find(|assignment| &assignment.sta_addr == mac)
        })
    }

    pub(super) fn core_key_for(&self, mac: &[u8; 6]) -> Option<[u8; 6]> {
        self.map.contains_key(mac).then_some(*mac).or_else(|| {
            self.map.iter().find_map(|(core_sta, assignment)| {
                (assignment.sta_addr == *mac).then_some(*core_sta)
            })
        })
    }

    pub(super) fn begin_retirement(&mut self, core_sta: &[u8; 6], delete_after: Instant) -> bool {
        let Some(assignment) = self.map.get_mut(core_sta) else {
            return false;
        };
        assignment.retire_at = Some(
            assignment
                .retire_at
                .map(|existing| existing.min(delete_after))
                .unwrap_or(delete_after),
        );
        assignment.station_retry_at.get_or_insert(Instant::now());
        true
    }

    pub(super) fn insert(&mut self, sta: [u8; 6], assignment: VlanAssignment) {
        let ifindex = assignment.ifindex;
        if let Some(old) = self.map.insert(sta, assignment) {
            self.ifindices.remove(&old.ifindex);
        }
        self.ifindices.insert(ifindex);
    }

    pub(super) fn remove(&mut self, sta: &[u8; 6]) -> Option<VlanAssignment> {
        let assignment = self.map.remove(sta)?;
        self.ifindices.remove(&assignment.ifindex);
        Some(assignment)
    }

    /// Apply a generation-tagged DEL_INTERFACE completion. The allocation
    /// becomes visible as free only in the successful matching branch.
    pub(super) fn complete_interface_cleanup(
        &mut self,
        sta: &[u8; 6],
        cleanup_id: u64,
        success: bool,
        now: Instant,
    ) -> Option<VlanAssignment> {
        let assignment = self.map.get_mut(sta)?;
        if assignment.interface_cleanup_id != Some(cleanup_id) {
            return None;
        }
        assignment.interface_cleanup_id = None;
        if !success {
            assignment.interface_retry_at = Some(now + CLEANUP_RETRY_DELAY);
            return None;
        }
        self.remove(sta)
    }
}
