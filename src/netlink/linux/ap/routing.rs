use super::*;

/// Resolve the affiliated link carrying a received MLD management frame.
///
/// nl80211 normally supplies `MLO_LINK_ID`, but ath12k can omit it for
/// pre-association Authentication frames. In that case the on-air RA/BSSID
/// identifies a unique link; an MLD-addressed frame can additionally be
/// disambiguated by the event frequency. Some drivers report an inconsistent
/// link ID even when the frame's RA/BSSID names one affiliated BSS exactly; in
/// that case the on-air address is authoritative.
pub(super) fn resolve_mld_rx_link(
    link_params: &std::collections::HashMap<u8, ([u8; 6], u32)>,
    reported_link_id: Option<u8>,
    event_freq: Option<u32>,
    ra: &[u8; 6],
    frame_bssid: &[u8; 6],
    ap_mld_mac: &[u8; 6],
    allow_broadcast: bool,
) -> Option<u8> {
    let broadcast = [0xff; 6];
    let address_matches = |link_bssid: &[u8; 6]| {
        (ra == link_bssid || ra == ap_mld_mac || (allow_broadcast && ra == &broadcast))
            && (frame_bssid == link_bssid
                || frame_bssid == ap_mld_mac
                || (allow_broadcast && frame_bssid == &broadcast))
    };

    let addressed: Vec<u8> = link_params
        .iter()
        .filter(|(_, (link_bssid, _))| {
            (ra == link_bssid || frame_bssid == link_bssid) && address_matches(link_bssid)
        })
        .map(|(link_id, _)| *link_id)
        .collect();
    if addressed.len() == 1 {
        return Some(addressed[0]);
    }

    if let Some(link_id) = reported_link_id {
        return link_params
            .get(&link_id)
            .filter(|(link_bssid, _)| address_matches(link_bssid))
            .map(|_| link_id);
    }

    let candidates: Vec<(u8, u32)> = link_params
        .iter()
        .filter(|(_, (link_bssid, _))| address_matches(link_bssid))
        .map(|(link_id, (_, freq))| (*link_id, *freq))
        .collect();
    if candidates.len() == 1 {
        return Some(candidates[0].0);
    }
    event_freq.and_then(|freq| {
        let matching: Vec<u8> = candidates
            .iter()
            .filter(|(_, link_freq)| *link_freq == freq)
            .map(|(link_id, _)| *link_id)
            .collect();
        (matching.len() == 1).then_some(matching[0])
    })
}

/// Convert the protocol engine's raw-frame representation into nl80211's
/// management-TX representation.
///
/// Raw mode encrypts robust unicast management frames in userspace. nl80211
/// must instead receive the plaintext body: mac80211 owns encryption and the
/// shared pairwise PN space once the PTK is installed. The kernel station
/// registry deliberately retains key/address material through retirement, so
/// a final protected Deauth can still be converted after the protocol station
/// has already been removed.
pub(super) fn management_for_kernel(
    frame: &dot11::Dot11,
    cipher: dot11::DataCipher,
    ap_mld: &[u8; 6],
    stations: &StationRegistry,
) -> Option<Vec<u8>> {
    if !frame.protected() {
        return Some(dot11::rebuild_plaintext_mgmt(frame, None, &frame.body));
    }

    let owner = stations.owner_for_kernel_address(&frame.addr1)?;
    let key = stations.pairwise_key(&owner)?;
    let kernel_address = stations.kernel_address(&owner).unwrap_or(owner);
    let security_addresses =
        (kernel_address != owner).then_some((kernel_address, *ap_mld, *ap_mld));
    let plaintext = dot11::decrypt_protected_mgmt_sec(cipher, frame, key, security_addresses)?;
    dot11::rebuild_plaintext_mgmt(frame, security_addresses, &plaintext).into()
}

/// Route state-machine output through the kernel-facing components.
///
/// This is intentionally the only boundary that translates a protocol frame
/// into a management TX, station publication, or control-port EAPOL request.
pub(super) fn route_outputs(
    io: &mut RadioIo,
    out: &crate::ap::Outgoing,
    station_state: &mut StationRegistry,
    vlan: &mut VlanRegistry,
    ap: &mut crate::ap::Ap,
    topology: &RadioTopology,
) {
    for f in &out.frames {
        let Some(body) = dot11::strip_radiotap(f) else {
            continue;
        };
        let Some(d) = dot11::Dot11::parse(body) else {
            continue;
        };
        if d.frame_type() == dot11::TYPE_MGMT {
            if d.subtype() == dot11::SUBTYPE_BEACON {
                continue; // the kernel beacons
            }
            let is_assoc_resp = matches!(
                d.subtype(),
                dot11::SUBTYPE_ASSOC_RESP | dot11::SUBTYPE_REASSOC_RESP
            );
            let assoc_succeeded = is_assoc_resp
                && d.body.len() >= 6
                && u16::from_le_bytes([d.body[2], d.body[3]]) == 0;

            // reference AP's add_associated_sta() runs before send_assoc_resp(). It
            // deliberately puts the kernel station into associated state early:
            // otherwise cfg80211/the driver can drop EAPOL data before the
            // Association Response TX-status is processed. Our old order was the
            // reverse (send response, DEL/NEW/SET station, send m1), so ath12k
            // could apply the DEL_STATION after accepting the response for TX and
            // leave the ensuing 4-way frames queued against a torn-down peer.
            // Configure only successful responses; rejected associations must
            // never create a kernel station.
            let sta_addr = ap.station_link_for_peer(&d.addr1).unwrap_or(d.addr1);
            if assoc_succeeded && station_state.is_retiring(&sta_addr) {
                // A new protocol session raced the teardown of an older kernel
                // peer with the same address. Do not let it inherit that peer or
                // its AP_VLAN. Accelerate the final interface deletion, suppress
                // this success response, cancel the userspace 4-way prepared
                // alongside it, and let the client retry after the generation-
                // tagged cleanup completion releases the address.
                station_state.pending_assoc.remove(&d.addr1);
                station_state.held_eapol.remove(&d.addr1);
                ap.note_assoc_response_not_acked(&sta_addr);
                vlan.begin_retirement(&sta_addr, Instant::now());
                eprintln!(
                    "netlink AP: defer association for {} until kernel cleanup completes",
                    crate::util::bytes_to_mac(&sta_addr),
                );
                continue;
            }
            if assoc_succeeded
                && station_state.is_live(&sta_addr)
                && station_state.is_authorized(&sta_addr)
            {
                // A genuinely new (re)association cannot mutate an authorized
                // kernel peer in place: it may still own a PTK, replay counters,
                // and an AP_VLAN. Retire the complete old incarnation first.
                station_state.begin_retirement(sta_addr);
                ap.note_assoc_response_not_acked(&sta_addr);
                vlan.begin_retirement(&sta_addr, Instant::now());
                eprintln!(
                    "netlink AP: retire previous kernel session for {} before reassociation",
                    crate::util::bytes_to_mac(&sta_addr),
                );
                continue;
            }
            if assoc_succeeded
                && !(station_state.is_live(&sta_addr) && !station_state.is_authorized(&sta_addr))
            {
                let aid = u16::from_le_bytes([d.body[4], d.body[5]]) & 0x3fff;
                let mld_mac = ap.mld.then(|| ap.station_mld_mac(&sta_addr)).flatten();
                // HT/VHT caps go in SET_STATION (the only place rate control reads
                // them); NEW_STATION adds the station unassociated first so SET can
                // apply them without EINVAL. RUSTAP_NO_STA_CAPS=1 disables caps
                // entirely as a driver-compatibility escape hatch.
                let sta_caps = if std::env::var_os("RUSTAP_NO_STA_CAPS").is_some() {
                    None
                } else {
                    ap.station_assoc_ies(&sta_addr)
                };
                let listen_interval = ap.station_listen_interval(&sta_addr).unwrap_or(0);
                let capability = ap.station_capability(&sta_addr).unwrap_or(0);
                // An AP MLD must scope every station add/modify request to its
                // association link — the link the (re)assoc frame arrived on,
                // which a client may freely choose (wpa_supplicant routinely
                // picks the 5/6 GHz link, not link 0). `link_route` records that
                // per-station RX link and already drives the response/EAPOL TX,
                // so the kernel station's primary link must match it; otherwise
                // m1 is sent on the association link while the station only
                // exists on link 0, and the 4-way times out. A legacy station
                // has no MLD_ADDR, but still needs MLO_LINK_ID or cfg80211
                // rejects NEW_STATION.
                let assoc_link_id = topology
                    .station_links
                    .get(&sta_addr)
                    .copied()
                    .unwrap_or(ap.link_id);
                let link_id = ap.mld.then_some(assoc_link_id);
                let eml_capability = sta_caps.and_then(dot11::parse_mld_eml_capability);
                let mld_capability = sta_caps.and_then(dot11::parse_mld_capability);
                if let Some(mld) = mld_mac {
                    eprintln!(
                        "netlink AP: MLD station link={} mld={} EML=0x{:04x} MLD=0x{:04x} max_simultaneous_links={} negotiated_links={:?}",
                        crate::util::bytes_to_mac(&sta_addr),
                        crate::util::bytes_to_mac(&mld),
                        eml_capability.unwrap_or(0),
                        mld_capability.unwrap_or(0),
                        mld_capability.map(|cap| (cap & 0x000f) + 1).unwrap_or(0),
                        ap.station_mld_link_ids(&sta_addr),
                    );
                }
                // Match reference AP's MLO state-transition order exactly:
                //
                //   1. NEW_STATION creates the association-link peer unassociated.
                //   2. ADD_LINK_STA creates every negotiated partner peer.
                //   3. SET_STATION advances the complete MLD to ASSOCIATED.
                //
                // ath12k prepares its firmware peer-association MLO partner list
                // only during step 3. Associating the primary before step 2 leaves
                // num_partner_links=0 in WMI; ADD_LINK_STA then succeeds in the
                // kernel but never enrolls that late peer in firmware scheduling.
                let kernel_addr = mld_mac.unwrap_or(sta_addr);
                // Record ownership before issuing NEW_STATION. Even an error ACK
                // may follow a partially-applied driver operation, so every
                // failure path must schedule idempotent key/station cleanup.
                station_state.record_associated(sta_addr, kernel_addr);
                if !nl_new_station(
                    &mut io.commands,
                    io.family,
                    topology.ifindex,
                    &sta_addr,
                    mld_mac.as_ref(),
                    link_id,
                ) {
                    station_state.begin_retirement(sta_addr);
                    continue;
                }
                let mut setup_ok = true;
                if let Some(mld) = mld_mac {
                    let link_profiles = sta_caps
                        .map(dot11::parse_mld_link_profiles)
                        .unwrap_or_default();
                    for (peer_link_id, peer_link_mac) in ap.station_mld_link_macs(&sta_addr) {
                        // The association link is already created by NEW_STATION;
                        // only the *other* negotiated links get ADD_LINK_STA.
                        if peer_link_id == assoc_link_id {
                            continue;
                        }
                        let profile = link_profiles.iter().find(|profile| {
                            profile.link_id == peer_link_id && profile.mac == peer_link_mac
                        });
                        if !nl_add_link_station(
                            &mut io.commands,
                            io.family,
                            topology.ifindex,
                            &mld,
                            peer_link_id,
                            &peer_link_mac,
                            aid,
                            listen_interval,
                            profile
                                .and_then(|profile| profile.capability)
                                .unwrap_or(capability),
                            sta_caps,
                            profile.map(|profile| profile.ies.as_slice()),
                            eml_capability,
                            ap.station_uses_pmf(&sta_addr),
                        ) {
                            setup_ok = false;
                            break;
                        }
                    }
                }
                if setup_ok {
                    setup_ok = nl_set_station_assoc(
                        &mut io.commands,
                        io.family,
                        topology.ifindex,
                        &sta_addr,
                        aid,
                        listen_interval,
                        capability,
                        sta_caps,
                        mld_mac.as_ref(),
                        link_id,
                        eml_capability,
                        mld_mac.is_some(),
                        ap.station_uses_pmf(&sta_addr),
                    );
                }
                if !setup_ok {
                    station_state.begin_retirement(sta_addr);
                    continue;
                }
            }
            if assoc_succeeded && body.len() >= 24 {
                let sc = u16::from_le_bytes([body[22], body[23]]);
                station_state.pending_assoc.insert(
                    d.addr1,
                    PendingAssocTx {
                        sc,
                        sent_at: Instant::now(),
                    },
                );
            }
            // MLD TX translation: send on the client's link, and rewrite the
            // source (addr2 TA + addr3 BSSID) from the canonical `bssid` to that
            // link's BSSID so the client sees the response from the address it
            // targeted.
            let (tfreq, tlink) = topology.route(ap, &d.addr1);
            let kernel_owns_protection = d.protected();
            let mut tx =
                match management_for_kernel(&d, ap.pairwise_cipher(), &ap.mld_mac, station_state) {
                    Some(frame) => frame,
                    None => {
                        eprintln!(
                            "netlink AP: cannot prepare protected management frame for {}",
                            crate::util::bytes_to_mac(&d.addr1),
                        );
                        continue;
                    }
                };
            let peer_is_mld = station_state
                .kernel_address(&sta_addr)
                .is_some_and(|kernel| kernel != sta_addr);
            if !(kernel_owns_protection && peer_is_mld) {
                if let Some(lb) = tlink
                    .and_then(|link| topology.links.get(&link))
                    .map(|(bssid, _)| *bssid)
                {
                    if tx.len() >= 22 {
                        tx[10..16].copy_from_slice(&lb);
                        tx[16..22].copy_from_slice(&lb);
                    }
                }
            }
            if let Some(caps) = tlink
                .and_then(|link_id| topology.capabilities.get(&link_id))
                .or_else(|| topology.capabilities.get(&ap.link_id))
            {
                apply_wiphy_capabilities(&mut tx, caps);
            }
            nl_send_mgmt(&mut io.events, io.family, topology.wdev, tfreq, &tx, tlink);
        } else if d.frame_type() == dot11::TYPE_DATA && d.body.len() > 8 {
            if station_state.pending_assoc.contains_key(&d.addr1) {
                // Keep only the newest copy. tick() may produce a retry while the
                // management-frame TX status is pending; queueing every copy here
                // would recreate the stale-frame flood this gate is meant to stop.
                station_state.held_eapol.insert(d.addr1, f.clone());
                if crate::util::netlink_debug_enabled() {
                    eprintln!(
                        "netlink AP: hold EAPOL for ASSOC-RESP ACK sta={}",
                        crate::util::bytes_to_mac(&d.addr1)
                    );
                }
                continue;
            }
            let core_sta = ap.station_link_for_peer(&d.addr1).unwrap_or(d.addr1);
            if station_state.is_retiring(&core_sta) {
                continue;
            }
            let mld_mac = ap.mld.then(|| ap.station_mld_mac(&core_sta)).flatten();
            let dst = mld_mac.as_ref().unwrap_or(&d.addr1);
            // Match the reference AP's nl80211 driver: control-port EAPOL always
            // uses the BSS driver's base AP ifindex, even after SET_STA_VLAN
            // moves the peer's data path to an AP_VLAN. AP_VLAN is not a valid
            // CONTROL_PORT_FRAME TX interface on mac80211 (EOPNOTSUPP). The
            // destination MAC and, for MLO, link id select the peer.
            let (_f, link_id) = topology.route(ap, &core_sta);
            let eapol = &d.body[8..];
            io.eapol
                .send(topology.ifindex, *dst, eapol.to_vec(), link_id);
        }
    }
}

#[cfg(test)]
mod mld_rx_link_tests {
    use super::{management_for_kernel, resolve_mld_rx_link, StationRegistry};
    use crate::frames as dot11;
    use std::collections::HashMap;

    fn links() -> HashMap<u8, ([u8; 6], u32)> {
        HashMap::from([
            (0, ([0x06, 0xf0, 0x21, 0xc9, 0x1e, 0xef], 5180)),
            (1, ([0x06, 0xf0, 0x21, 0xc9, 0x1e, 0xee], 6135)),
        ])
    }

    #[test]
    fn missing_link_id_is_inferred_from_link_bssid() {
        let links = links();
        let mld = [0x04, 0xf0, 0x21, 0xc9, 0x1e, 0xff];
        let link1 = links[&1].0;
        assert_eq!(
            resolve_mld_rx_link(&links, None, None, &link1, &link1, &mld, false),
            Some(1)
        );
    }

    #[test]
    fn mld_address_is_disambiguated_by_event_frequency() {
        let links = links();
        let mld = [0x04, 0xf0, 0x21, 0xc9, 0x1e, 0xff];
        assert_eq!(
            resolve_mld_rx_link(&links, None, Some(6135), &mld, &mld, &mld, false),
            Some(1)
        );
    }

    #[test]
    fn explicit_link_bssid_overrides_inconsistent_reported_link() {
        let links = links();
        let mld = [0x04, 0xf0, 0x21, 0xc9, 0x1e, 0xff];
        let link1 = links[&1].0;
        assert_eq!(
            resolve_mld_rx_link(&links, Some(0), Some(6135), &link1, &link1, &mld, false,),
            Some(1)
        );
    }

    #[test]
    fn broadcast_probe_uses_reported_link() {
        let links = links();
        let mld = [0x04, 0xf0, 0x21, 0xc9, 0x1e, 0xff];
        let broadcast = [0xff; 6];
        assert_eq!(
            resolve_mld_rx_link(
                &links,
                Some(0),
                Some(5180),
                &broadcast,
                &broadcast,
                &mld,
                true,
            ),
            Some(0)
        );
    }

    #[test]
    fn directed_probe_with_broadcast_ra_uses_reported_link() {
        let links = links();
        let mld = [0x04, 0xf0, 0x21, 0xc9, 0x1e, 0xff];
        let broadcast = [0xff; 6];
        let link1 = links[&1].0;
        assert_eq!(
            resolve_mld_rx_link(&links, Some(1), Some(6135), &broadcast, &link1, &mld, true,),
            Some(1)
        );
    }

    #[test]
    fn nl80211_gets_plaintext_and_owns_robust_management_pn() {
        let ap = [0x02, 0, 0, 0, 0, 1];
        let sta = [0x02, 0, 0, 0, 0, 2];
        let key = [0x44; 16];
        let protected = dot11::build_protected_mgmt_sec(
            dot11::DataCipher::Ccmp128,
            dot11::SUBTYPE_ACTION,
            &sta,
            &ap,
            &ap,
            None,
            0,
            0x20,
            77,
            0,
            &key,
            &[
                dot11::ACTION_CATEGORY_SA_QUERY,
                dot11::SA_QUERY_REQUEST,
                7,
                0,
            ],
        );
        let parsed = dot11::Dot11::parse(&protected).unwrap();
        let mut stations = StationRegistry::new();
        stations.record_associated(sta, sta);
        stations.set_pairwise_key(&sta, key.to_vec());

        let kernel =
            management_for_kernel(&parsed, dot11::DataCipher::Ccmp128, &ap, &stations).unwrap();
        assert_eq!(kernel.len(), 28, "CCMP header/tag are not sent twice");
        let kernel = dot11::Dot11::parse(&kernel).unwrap();
        assert!(!kernel.protected(), "mac80211 sets the Protected bit");
        assert_eq!(
            kernel.body,
            [
                dot11::ACTION_CATEGORY_SA_QUERY,
                dot11::SA_QUERY_REQUEST,
                7,
                0
            ]
        );
    }

    #[test]
    fn mld_robust_management_uses_mld_security_addresses() {
        let ap_link = [0x02, 0, 0, 0, 0, 1];
        let ap_mld = [0x02, 0, 0, 0, 0, 0x11];
        let sta_link = [0x02, 0, 0, 0, 0, 2];
        let sta_mld = [0x02, 0, 0, 0, 0, 0x22];
        let key = [0x55; 16];
        let mld_addresses = (sta_mld, ap_mld, ap_mld);
        let security_addresses = Some(mld_addresses);
        let protected = dot11::build_protected_mgmt_sec(
            dot11::DataCipher::Ccmp128,
            dot11::SUBTYPE_DEAUTH,
            &sta_link,
            &ap_link,
            &ap_link,
            security_addresses,
            0,
            0x30,
            8,
            0,
            &key,
            &3u16.to_le_bytes(),
        );
        let parsed = dot11::Dot11::parse(&protected).unwrap();
        let mut stations = StationRegistry::new();
        stations.record_associated(sta_link, sta_mld);
        stations.set_pairwise_key(&sta_link, key.to_vec());

        let kernel =
            management_for_kernel(&parsed, dot11::DataCipher::Ccmp128, &ap_mld, &stations).unwrap();
        let kernel = dot11::Dot11::parse(&kernel).unwrap();
        assert_eq!((kernel.addr1, kernel.addr2, kernel.addr3), mld_addresses);
        assert_eq!(kernel.body, 3u16.to_le_bytes());
    }
}
