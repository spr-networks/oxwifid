use super::*;

/// Select the link contexts that bind a station to its AP_VLAN.
///
/// A non-MLO AP has no link attribute. A legacy peer on an MLD AP belongs only
/// to its association link. An MLO peer is bound from every negotiated link
/// context, always using the same peer MLD address and AP_VLAN ifindex.
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
    negotiated_links.retain(|link_id| *link_id != association_link);
    negotiated_links.sort_unstable();
    negotiated_links.dedup();
    std::iter::once(Some(association_link))
        .chain(negotiated_links.into_iter().map(Some))
        .collect()
}

#[derive(Clone, Copy)]
pub(super) struct VlanBinding {
    pub(super) ifindex: u32,
    pub(super) id: u32,
    pub(super) offload: bool,
}

pub(super) fn set_sta_vlan_message(
    family: u16,
    ap_ifindex: u32,
    sta: &[u8; 6],
    vlan: VlanBinding,
    link_id: Option<u8>,
    seq: u32,
) -> GenlMessage {
    let mut m = GenlMessage::new(family, NL80211_CMD_SET_STATION, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ap_ifindex))
        .attr(Attr::bytes(NL80211_ATTR_MAC, sta));
    if vlan.offload && vlan.id != 0 {
        m = m.attr(Attr::u16v(NL80211_ATTR_VLAN_ID, vlan.id as u16));
    }
    if let Some(link_id) = link_id {
        m = m.attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id));
    }
    m.attr(Attr::u32(NL80211_ATTR_STA_VLAN, vlan.ifindex))
}

/// Move one station into an AP_VLAN. For an MLD peer, invoke this once per link
/// context with the peer MLD MAC and that context's `MLO_LINK_ID`; all calls
/// target the same AP_VLAN.
pub(super) fn nl_set_sta_vlan(
    sock: &mut NetlinkSocket,
    family: u16,
    ap_ifindex: u32,
    sta: &[u8; 6],
    vlan: VlanBinding,
    link_id: Option<u8>,
) -> io::Result<()> {
    let seq = sock.next_seq();
    let m = set_sta_vlan_message(family, ap_ifindex, sta, vlan, link_id, seq);
    sock.request_ack(m)
}

/// Create and group-key a station's private AP_VLAN before transmitting the
/// successful Association Response.
///
/// Create the per-station interface while processing the station's
/// authentication/ACL state. Do not bind the kernel station here; binding runs
/// later, only after the successful Association Response has been acknowledged.
#[derive(Clone, Copy)]
pub(super) struct StationVlanIdentity {
    pub(super) sta: Mac,
    pub(super) mld_mac: Option<Mac>,
    pub(super) association_link: u8,
}

pub(super) fn prepare_associated_station_vlan(
    io: &mut RadioIo,
    ap: &crate::ap::Ap,
    topology: &RadioTopology,
    group_keys: &mut GroupKeyStore,
    vlans: &mut VlanRegistry,
    identity: StationVlanIdentity,
) -> bool {
    let StationVlanIdentity {
        sta,
        mld_mac,
        association_link,
    } = identity;
    if !vlans.enabled {
        return true;
    }

    if !vlans.map.contains_key(&sta) {
        let (vlan_id, name) = match vlans.allocate() {
            Ok(allocation) => allocation,
            Err(error) => {
                eprintln!("netlink AP: allocate per-station VIF failed: {error}");
                return false;
            }
        };
        let parent_addr = ap_vlan_parent_addr(ap);
        let ifindex = match nl_create_ap_vlan(
            &mut io.commands,
            io.family,
            topology.wdev,
            &name,
            &parent_addr,
        ) {
            Ok(ifindex) => ifindex,
            Err(error) => {
                eprintln!("netlink AP: create AP_VLAN {name} failed: {error}");
                return false;
            }
        };
        vlans.insert(
            sta,
            VlanAssignment {
                ifindex,
                vlan_id,
                ifname: name,
                sta_addr: mld_mac.unwrap_or(sta),
                station_may_be_on_base: true,
                data_path_prepared: false,
                retire_at: None,
                station_removed: false,
                station_cleanup_id: None,
                station_retry_at: None,
                interface_cleanup_id: None,
                interface_retry_at: None,
            },
        );
    }

    let assignment = vlans
        .map
        .get(&sta)
        .expect("AP_VLAN reservation exists")
        .clone();
    let links = per_station_link_ids(
        ap.mld,
        mld_mac.is_some(),
        association_link,
        ap.station_mld_link_ids(&sta),
    );

    // Initialize the WPA group before binding the station, and seed every
    // negotiated MLD link's multicast-key slot on the one shared AP_VLAN
    // netdev.
    let key_id = ap.station_gtk_key_id(&sta);
    let key_material = ap.station_gtk(&sta);
    for &link_id in &links {
        let state_key = (sta, link_id);
        if group_keys.vlan_gtk.get(&state_key) == Some(&(key_id, key_material)) {
            continue;
        }
        let key = KeyInstall::group(assignment.ifindex, key_id, &key_material, link_id)
            .with_vlan_offload(assignment.vlan_id, topology.vlan_offload);
        if !nl_install_key(&mut io.commands, io.family, key) {
            return false;
        }
        group_keys
            .vlan_gtk
            .insert(state_key, (key_id, key_material));
    }
    if ap.is_pmf() {
        let key_id = ap.station_igtk_key_id(&sta) as u8;
        let key_material = ap.station_igtk(&sta);
        let sequence = ap.station_igtk_ipn(&sta);
        for &link_id in &links {
            let state_key = (sta, link_id);
            if group_keys.vlan_igtk.get(&state_key) == Some(&(key_id, key_material)) {
                continue;
            }
            let key = KeyInstall::integrity(
                assignment.ifindex,
                key_id,
                &key_material,
                &sequence,
                link_id,
                false,
            )
            .with_vlan_offload(assignment.vlan_id, topology.vlan_offload);
            if !nl_install_key(&mut io.commands, io.family, key) {
                return false;
            }
            group_keys
                .vlan_igtk
                .insert(state_key, (key_id, key_material));
        }
    }

    true
}

/// Attach the newly-published station AP_VLAN to SPR's bridge/XDP data path.
///
/// The ordering is NEW_STATION, Authentication response TX submission, bridge
/// add, then the pre-association flags refresh. In particular, bridge membership
/// is not established before the driver peer exists. mt7996 keys
/// its per-vdev station lookup during this window, so keep the helper at the
/// same boundary rather than running it during AP_VLAN allocation.
pub(super) fn prepare_station_vlan_data_path(
    vlans: &mut VlanRegistry,
    notifier: Option<&crate::spr::SprNotifier>,
    sta: &Mac,
) {
    let Some(assignment) = vlans.map.get(sta).cloned() else {
        return;
    };
    if assignment.data_path_prepared {
        return;
    }
    let Some(notifier) = notifier else {
        return;
    };
    let mac = crate::util::bytes_to_mac(&assignment.sta_addr);
    match notifier.prepare_data_path(&assignment.ifname, &mac) {
        Ok(true) => {
            if let Some(current) = vlans.map.get_mut(sta) {
                current.data_path_prepared = true;
            }
            eprintln!(
                "netlink AP: prepared SPR data path for {} after station publication",
                assignment.ifname
            );
        }
        Ok(false) => {}
        Err(error) => {
            // Keep the integration best-effort. The connected event retries
            // the helper if this association-time preparation failed.
            eprintln!(
                "netlink AP: association-time SPR DHCP/XDP helper failed for {}: {error}",
                assignment.ifname
            );
        }
    }
}

/// Complete the successful Association Response callback.
///
/// The exact order is AP_VLAN binding, then a station-flags refresh, then WPA
/// message 1. The caller owns the last step and must keep EAPOL held unless this
/// function succeeds.
pub(super) fn finalize_associated_station(
    io: &mut RadioIo,
    ap: &mut crate::ap::Ap,
    topology: &RadioTopology,
    group_keys: &mut GroupKeyStore,
    vlans: &mut VlanRegistry,
    sta: Mac,
    association_link: u8,
) -> bool {
    let mld_mac = ap.mld.then(|| ap.station_mld_mac(&sta)).flatten();
    let kernel_sta = mld_mac.unwrap_or(sta);

    if vlans.enabled {
        let Some(assignment) = vlans.map.get(&sta).cloned() else {
            eprintln!(
                "netlink AP: AP_VLAN missing at association completion for {}",
                crate::util::bytes_to_mac(&sta),
            );
            return false;
        };
        let links = per_station_link_ids(
            ap.mld,
            mld_mac.is_some(),
            association_link,
            ap.station_mld_link_ids(&sta),
        );

        if assignment.station_may_be_on_base {
            // Enable mac80211's multicast-to-unicast conversion on the base AP
            // immediately before its per-station VLAN bind. Keep this command
            // in the same peer transition window; issuing it later can
            // leave already-enqueued group traffic attached to the old context.
            if !nl_enable_multicast_to_unicast(&mut io.commands, io.family, topology.ifindex) {
                return false;
            }
            let vlan = VlanBinding {
                ifindex: assignment.ifindex,
                id: assignment.vlan_id,
                offload: topology.vlan_offload,
            };

            // driver_nl80211 clears pairwise key slot 0 before moving an
            // associated station to an AP_VLAN. This is not just stale-key
            // cleanup on mt7996: it resets the firmware's protected-TX
            // context while the peer still belongs to the base AP.
            if let Err(error) = nl_del_pairwise_key(
                &mut io.commands,
                io.family,
                topology.ifindex,
                &assignment.sta_addr,
            ) {
                eprintln!("netlink AP: pre-VLAN pairwise key reset failed: {error}");
                return false;
            }

            for &link_id in &links {
                if let Err(error) = nl_set_sta_vlan(
                    &mut io.commands,
                    io.family,
                    topology.ifindex,
                    &assignment.sta_addr,
                    vlan,
                    link_id,
                ) {
                    eprintln!("netlink AP: set_sta_vlan link={link_id:?} failed: {error}");
                    return false;
                }
            }
            vlans
                .map
                .get_mut(&sta)
                .expect("bound AP_VLAN reservation")
                .station_may_be_on_base = false;
            eprintln!(
                "netlink AP: station {} -> {} (vlan_id {}, ifindex {}, vlan_offload={}, links={links:?})",
                crate::util::bytes_to_mac(&assignment.sta_addr),
                assignment.ifname,
                assignment.vlan_id,
                assignment.ifindex,
                topology.vlan_offload,
            );

            // Apply the post-bind station update sequence before WPA message 1:
            // refresh flags, clear key slot 0 through both association
            // key-cleanup paths, then refresh the final flags. On drivers with
            // per-vdev security state this ensures the
            // PTK installed by the 4-way handshake is created on the newly
            // bound AP_VLAN context.
            let total_flags = associated_station_flags(
                ap.station_capability(&sta).unwrap_or(0),
                ap.station_uses_wmm(&sta),
                ap.station_uses_pmf(&sta),
            );
            if !nl_refresh_associated_station_flags(
                &mut io.commands,
                io.family,
                topology.wdev,
                &kernel_sta,
                total_flags,
            ) {
                return false;
            }
            for _ in 0..2 {
                if let Err(error) = nl_del_pairwise_key(
                    &mut io.commands,
                    io.family,
                    topology.ifindex,
                    &assignment.sta_addr,
                ) {
                    eprintln!("netlink AP: post-VLAN pairwise key reset failed: {error}");
                    return false;
                }
            }
            if !nl_clear_authorized(
                &mut io.commands,
                io.family,
                topology.wdev,
                &kernel_sta,
                total_flags,
            ) {
                return false;
            }

            // Binding the first station drives the private WPA group from its
            // provisional GTK/IGTK slots 1/4 to fresh material in slots 2/5.
            // This is a real per-VLAN group transition, not a reinstall of
            // the same BSS keys. It happens before M1; M3 will therefore carry
            // exactly the new material installed below.
            let initialized = ap.initialize_station_vlan_group(&sta);
            let gtk_id = ap.station_gtk_key_id(&sta);
            let gtk = ap.station_gtk(&sta);
            let igtk_id = ap.station_igtk_key_id(&sta);
            let igtk = ap.station_igtk(&sta);
            let igtk_ipn = ap.station_igtk_ipn(&sta);
            for &link_id in &links {
                let key = KeyInstall::group(assignment.ifindex, gtk_id, &gtk, link_id)
                    .with_vlan_offload(assignment.vlan_id, topology.vlan_offload);
                if !nl_install_key(&mut io.commands, io.family, key) {
                    return false;
                }
                group_keys.vlan_gtk.insert((sta, link_id), (gtk_id, gtk));
                if ap.is_pmf() {
                    let key = KeyInstall::integrity(
                        assignment.ifindex,
                        igtk_id as u8,
                        &igtk,
                        &igtk_ipn,
                        link_id,
                        false,
                    )
                    .with_vlan_offload(assignment.vlan_id, topology.vlan_offload);
                    if !nl_install_key(&mut io.commands, io.family, key) {
                        return false;
                    }
                    group_keys
                        .vlan_igtk
                        .insert((sta, link_id), (igtk_id as u8, igtk));
                }
            }
            eprintln!(
                "netlink AP: initialized bound AP_VLAN group for {} (new={initialized}, GTK={}, IGTK={})",
                assignment.ifname, gtk_id, igtk_id,
            );
        }
    }

    // The per-VLAN path already emitted both post-bind flag updates above. A
    // third broad refresh here used to mutate WME/MFP/preamble state after the
    // VLAN group's key installs.
    if vlans.enabled {
        return true;
    }

    let total_flags = associated_station_flags(
        ap.station_capability(&sta).unwrap_or(0),
        ap.station_uses_wmm(&sta),
        ap.station_uses_pmf(&sta),
    );
    nl_refresh_associated_station_flags(
        &mut io.commands,
        io.family,
        topology.wdev,
        &kernel_sta,
        total_flags,
    )
}

#[cfg(test)]
mod station_vlan_tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn mld_peer_uses_every_negotiated_link_context() {
        assert_eq!(
            per_station_link_ids(true, true, 1, vec![1, 0, 1]),
            vec![Some(1), Some(0)],
            "bind the association link before walking partner links"
        );
        assert_eq!(
            per_station_link_ids(true, true, 1, vec![0]),
            vec![Some(1), Some(0)],
            "association link is inserted first if partner parsing omitted it"
        );
    }

    #[test]
    fn legacy_peer_uses_only_its_association_link_context() {
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
    fn sta_vlan_message_scopes_an_mld_station_link_like_driver_nl80211() {
        let sta = [0x02, 0, 0, 0, 0, 1];
        let msg = set_sta_vlan_message(
            42,
            7,
            &sta,
            VlanBinding {
                ifindex: 88,
                id: 4096,
                offload: false,
            },
            Some(1),
            9,
        );
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
        let types: Vec<u16> = msg.attrs.iter().map(|attr| attr.typ).collect();
        assert_eq!(
            types,
            vec![
                NL80211_ATTR_IFINDEX,
                NL80211_ATTR_MAC,
                NL80211_ATTR_MLO_LINK_ID,
                NL80211_ATTR_STA_VLAN,
            ],
            "match driver_nl80211 attribute order"
        );
    }

    #[test]
    fn sta_vlan_message_includes_vlan_id_only_for_driver_offload() {
        let sta = [0x02, 0, 0, 0, 0, 1];
        let offload = set_sta_vlan_message(
            42,
            7,
            &sta,
            VlanBinding {
                ifindex: 88,
                id: 4096,
                offload: true,
            },
            None,
            9,
        );
        assert_eq!(
            offload
                .attrs
                .iter()
                .find(|attr| attr.typ == NL80211_ATTR_VLAN_ID)
                .map(|attr| attr.data.as_slice()),
            Some(4096u16.to_ne_bytes().as_slice())
        );
        let types: Vec<u16> = offload.attrs.iter().map(|attr| attr.typ).collect();
        assert_eq!(
            types,
            vec![
                NL80211_ATTR_IFINDEX,
                NL80211_ATTR_MAC,
                NL80211_ATTR_VLAN_ID,
                NL80211_ATTR_STA_VLAN,
            ]
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
                data_path_prepared: false,
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
    /// The SPR bridge/XDP helper completed its `add` action before the kernel
    /// station was published. AP-STA-CONNECTED must not repeat that action.
    pub(super) data_path_prepared: bool,
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
