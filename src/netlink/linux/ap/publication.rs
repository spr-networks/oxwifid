use super::*;

// Projection of authenticated protocol state into kernel stations and keys.

impl RadioRuntime {
    pub(super) fn reconcile_stations(&mut self) -> bool {
        let ifindex = self.topology.ifindex;
        // Reconcile only actual state changes. The previous implementation
        // rebuilt a live HashSet and rescanned every station/VLAN every 20 ms.
        for sta in self.ap.drain_removed_stations() {
            self.stations.begin_retirement(sta);
            if let Some(worker) = self.telemetry.as_mut() {
                worker.forget(&sta);
            }
            self.vlans
                .begin_retirement(&sta, Instant::now() + VLAN_EVENT_GRACE);
        }

        // Install keys for any station that just completed the 4-way. Match the
        // reference per_sta_vif ordering exactly:
        //
        //   1. messages 1-4 run on the base AP;
        //   2. install the PTK and authorize the station on the base AP;
        //   3. create and group-key the private AP_VLAN;
        //   4. bind the already-authorized station into the AP_VLAN.
        //
        // SET_STA_VLAN changes the peer's data-path attachment. A later
        // base-ifindex authorization update is not the same operation as
        // authorizing that peer before the move, so preserve the reference
        // implementation's ordering instead of relying on driver tolerance.
        self.stations
            .key_pending
            .extend(self.ap.drain_key_ready_stations());
        let mut newly_keyed = false;
        let pending_keys: Vec<[u8; 6]> = self.stations.key_pending.iter().copied().collect();
        for sta in &pending_keys {
            if self.stations.is_retiring(sta) {
                self.stations.key_pending.remove(sta);
                continue;
            }
            if !self.ap.is_associated(sta) {
                self.stations.key_pending.remove(sta);
                continue;
            }
            if let Some(tk) = self.ap.station_pairwise_key(sta) {
                let already_authorized = self.stations.is_authorized(sta);
                let mld_mac = self.ap.mld.then(|| self.ap.station_mld_mac(sta)).flatten();
                let key_sta = mld_mac.as_ref().unwrap_or(sta);
                let assoc_link_id = self
                    .topology
                    .station_links
                    .get(sta)
                    .copied()
                    .unwrap_or(self.ap.link_id);
                // MLO pairwise keys are addressed to the peer MLD. The kernel
                // rejects MLO_LINK_ID on pairwise NEW_KEY; per-link scoping only
                // applies to group/management keys.
                let kernel_has_key = self
                    .stations
                    .pairwise_key(sta)
                    .is_some_and(|installed| installed == tk);
                if !kernel_has_key {
                    if !nl_install_key(
                        &mut self.io.commands,
                        self.io.family,
                        KeyInstall::pairwise(
                            ifindex,
                            key_sta,
                            tk,
                            self.ap.pairwise_cipher().suite_selector(),
                        ),
                    ) {
                        continue;
                    }
                    self.stations.set_pairwise_key(sta, tk.to_vec());
                }
                if already_authorized {
                    // Authenticator-initiated PTK rekey: the station remains on
                    // its existing VLAN and authorized throughout. A changed TK
                    // was installed above; an identical TK was deliberately not
                    // re-installed, preserving the kernel's packet counters.
                    self.stations.key_pending.remove(sta);
                    eprintln!(
                        "netlink AP: station {} pairwise rekey complete (changed={})",
                        crate::util::bytes_to_mac(sta),
                        !kernel_has_key,
                    );
                    continue;
                }

                // reference AP authorizes the kernel station before its
                // per_sta_vif callback creates and binds the private AP_VLAN.
                // Keep this ahead of every AP_VLAN operation: the authorization
                // update is MLD-level state addressed through the base BSS.
                if !nl_authorize(&mut self.io.commands, self.io.family, ifindex, key_sta) {
                    continue;
                }

                let key_if = if self.vlans.enabled {
                    if !self.vlans.map.contains_key(sta) {
                        // Create the private interface only after m4 and base-BSS
                        // authorization. The station remains on the base AP until
                        // its group key is installed and SET_STA_VLAN succeeds.
                        let (vlan_id, name) = match self.vlans.allocate() {
                            Ok(v) => v,
                            Err(e) => {
                                eprintln!("netlink AP: allocate per-station VIF failed: {e}");
                                self.stations.begin_retirement(*sta);
                                continue;
                            }
                        };
                        let parent_addr = ap_vlan_parent_addr(&self.ap);
                        let vidx = match nl_create_ap_vlan(
                            &mut self.io.commands,
                            self.io.family,
                            ifindex,
                            &name,
                            &parent_addr,
                        ) {
                            Ok(vidx) => vidx,
                            Err(e) => {
                                eprintln!("netlink AP: create AP_VLAN {name} failed: {e}");
                                self.stations.begin_retirement(*sta);
                                continue;
                            }
                        };
                        // Reserve the id/name immediately after NEW_INTERFACE.
                        // From this point onward every failure goes through the
                        // asynchronous retirement state machine; no allocator
                        // can observe the VIF as free before DEL_INTERFACE ACKs.
                        let kernel_addr = mld_mac.unwrap_or(*sta);
                        self.vlans.insert(
                            *sta,
                            VlanAssignment {
                                ifindex: vidx,
                                vlan_id,
                                ifname: name.clone(),
                                sta_addr: kernel_addr,
                                station_may_be_on_base: true,
                                retire_at: None,
                                station_removed: false,
                                station_cleanup_id: None,
                                station_retry_at: None,
                                interface_cleanup_id: None,
                                interface_retry_at: None,
                            },
                        );
                    }
                    self.vlans
                        .map
                        .get(sta)
                        .map(|assignment| assignment.ifindex)
                        .unwrap_or(ifindex)
                } else {
                    ifindex
                };

                if self.vlans.enabled {
                    // The GTK index is BSS-wide (the advertised key id, shared by
                    // every station); only the per-station GTK *value* differs.
                    let gidx = self.ap.gtk_key_id();
                    let gkey = self.ap.station_gtk(sta);
                    let group_links = per_station_link_ids(
                        self.ap.mld,
                        mld_mac.is_some(),
                        assoc_link_id,
                        self.ap.station_mld_link_ids(sta),
                    );
                    let mut group_keys_ok = true;
                    for link_id in group_links {
                        if !nl_install_key(
                            &mut self.io.commands,
                            self.io.family,
                            KeyInstall::group(key_if, gidx, &gkey, link_id),
                        ) {
                            group_keys_ok = false;
                            continue;
                        }
                        self.group_keys
                            .vlan_gtk
                            .insert((*sta, link_id), (gidx, gkey));
                    }
                    if !group_keys_ok {
                        // The station is already authorized on the base AP.
                        // Never leave it there after private-VIF setup failed.
                        self.stations.begin_retirement(*sta);
                        self.vlans.begin_retirement(sta, Instant::now());
                        self.stations.key_pending.remove(sta);
                        continue;
                    }

                    // cfg80211 stores an MLO peer under its MLD MAC. Match the
                    // reference AP and bind the already-authorized station on
                    // every negotiated MLO link only after the AP_VLAN GTK is
                    // ready. Binding only the association link leaves partner
                    // traffic on the base BSS.
                    let assignment = self
                        .vlans
                        .map
                        .get(sta)
                        .expect("AP_VLAN reservation must exist before binding");
                    if assignment.station_may_be_on_base {
                        let vidx = assignment.ifindex;
                        let vlan_id = assignment.vlan_id;
                        let name = assignment.ifname.clone();
                        let kernel_addr = assignment.sta_addr;
                        let vlan_links = per_station_link_ids(
                            self.ap.mld,
                            mld_mac.is_some(),
                            assoc_link_id,
                            self.ap.station_mld_link_ids(sta),
                        );
                        let mut vlan_bind_error = None;
                        for &link_id in &vlan_links {
                            if let Err(e) = nl_set_sta_vlan(
                                &mut self.io.commands,
                                self.io.family,
                                ifindex,
                                &kernel_addr,
                                vidx,
                                link_id,
                            ) {
                                vlan_bind_error = Some((link_id, e));
                                break;
                            }
                        }
                        if let Some((link_id, e)) = vlan_bind_error {
                            eprintln!("netlink AP: set_sta_vlan link={link_id:?} failed: {e}");
                            self.stations.begin_retirement(*sta);
                            self.vlans.begin_retirement(sta, Instant::now());
                            self.stations.key_pending.remove(sta);
                            continue;
                        }
                        self.vlans
                            .map
                            .get_mut(sta)
                            .expect("bound AP_VLAN reservation")
                            .station_may_be_on_base = false;
                        eprintln!(
                        "netlink AP: station {} -> {name} (vlan_id {vlan_id}, ifindex {vidx}, links={vlan_links:?})",
                        crate::util::bytes_to_mac(&kernel_addr),
                    );
                    }
                }
                self.stations.mark_authorized(sta);
                self.stations.key_pending.remove(sta);
                newly_keyed = true;
                eprintln!(
                    "netlink AP: station {} keyed + authorized",
                    crate::util::bytes_to_mac(sta)
                );
            }
        }

        newly_keyed
    }

    pub(super) fn reconcile_group_keys(&mut self, newly_keyed: bool) {
        let ifindex = self.topology.ifindex;
        let group_keys_changed = self.group_keys.changed(&self.ap);
        let mut group_keys_installed = true;

        // BSS-wide GTK: install once a station is keyed, and re-install whenever
        // the AP rotates it (group rekey). The kernel must end up using exactly
        // the GTK bytes + index that rekey_gtk() handed the stations — otherwise
        // a departed STA can still read kernel group traffic. (Per-STA-VIF mode
        // has no BSS-wide group key; each AP_VLAN is keyed below instead.)
        if !self.vlans.enabled
            && (newly_keyed || group_keys_changed)
            && self.stations.has_authorized()
        {
            let gtk_idx = self.ap.gtk_key_id();
            let gtk = self.ap.gtk();
            let group_links: Vec<Option<u8>> = if self.ap.mld {
                self.ap
                    .active_mld_links()
                    .into_iter()
                    .map(|l| Some(l.link_id))
                    .collect()
            } else {
                vec![None]
            };
            for link_id in group_links {
                if self.group_keys.gtk.get(&link_id) != Some(&(gtk_idx, gtk)) {
                    // Keep the alternate GTK slot until the next rotation
                    // overwrites it. This is the reference AP's bounded two-slot
                    // behavior and avoids a delete window while stations finish
                    // the group-key handshake.
                    if nl_install_key(
                        &mut self.io.commands,
                        self.io.family,
                        KeyInstall::group(ifindex, gtk_idx, &gtk, link_id),
                    ) {
                        self.group_keys.gtk.insert(link_id, (gtk_idx, gtk));
                    } else {
                        group_keys_installed = false;
                    }
                }
            }
        }

        // Per-STA-VIF rekey: install each station's own rotated GTK on its
        // AP_VLAN at the new (toggled) index. The alternate slot remains until
        // a later rotation overwrites it, preserving the two-phase rekey window.
        // Without this, a periodic/strict rekey
        // would hand stations a new key while the AP_VLAN kernel key stayed
        // stale. The initial install above seeds vlan_gtk, so this only fires on
        // an actual rotation.
        if self.vlans.enabled && group_keys_changed {
            let authorized: Vec<[u8; 6]> = self.stations.authorized().collect();
            for sta in authorized {
                let Some(assignment) = self.vlans.map.get(&sta) else {
                    continue;
                };
                let vidx = assignment.ifindex;
                // Shared BSS-wide index, per-station value (see initial install).
                let gidx = self.ap.gtk_key_id();
                let gkey = self.ap.station_gtk(&sta);
                let mld_station = self.ap.mld && self.ap.station_mld_mac(&sta).is_some();
                let assoc_link_id = self
                    .topology
                    .station_links
                    .get(&sta)
                    .copied()
                    .unwrap_or(self.ap.link_id);
                let group_links = per_station_link_ids(
                    self.ap.mld,
                    mld_station,
                    assoc_link_id,
                    self.ap.station_mld_link_ids(&sta),
                );
                for link_id in group_links {
                    let state_key = (sta, link_id);
                    if self.group_keys.vlan_gtk.get(&state_key) != Some(&(gidx, gkey)) {
                        if nl_install_key(
                            &mut self.io.commands,
                            self.io.family,
                            KeyInstall::group(vidx, gidx, &gkey, link_id),
                        ) {
                            self.group_keys.vlan_gtk.insert(state_key, (gidx, gkey));
                        } else {
                            group_keys_installed = false;
                        }
                    }
                }
            }
        }

        // IGTK for PMF (SAE/OWE): BSS-wide (one BIP key for the radio's robust
        // management frames), installed on the main AP interface in both modes so
        // the kernel can BIP-protect/validate them; re-install on rotation.
        if self.ap.is_pmf() && (newly_keyed || group_keys_changed) && self.stations.has_authorized()
        {
            let igtk_idx = self.ap.igtk_key_id() as u8;
            let igtk = self.ap.igtk();
            let mgmt_links: Vec<Option<u8>> = if self.ap.mld {
                self.ap
                    .active_mld_links()
                    .into_iter()
                    .map(|l| Some(l.link_id))
                    .collect()
            } else {
                vec![None]
            };
            for link_id in mgmt_links {
                if self.group_keys.igtk.get(&link_id) != Some(&(igtk_idx, igtk)) {
                    if nl_install_key(
                        &mut self.io.commands,
                        self.io.family,
                        KeyInstall::integrity(
                            ifindex,
                            igtk_idx,
                            &igtk,
                            &self.ap.igtk_ipn(),
                            link_id,
                            false,
                        ),
                    ) {
                        self.group_keys.igtk.insert(link_id, (igtk_idx, igtk));
                    } else {
                        group_keys_installed = false;
                    }
                }
            }

            // BIGTK (Beacon Protection): install into the kernel so mac80211
            // generates the per-beacon MME. If the kernel rejects it (no offload
            // support), latch beacon protection off — the static beacon already
            // carries no MME, so beacons simply go unprotected rather than ship a
            // replayable fixed-IPN MME.
            if self.group_keys.beacon_protection {
                let bigtk_idx = self.ap.bigtk_key_id() as u8;
                let bigtk = self.ap.bigtk();
                let beacon_links: Vec<Option<u8>> = if self.ap.mld {
                    self.ap
                        .active_mld_links()
                        .into_iter()
                        .map(|l| Some(l.link_id))
                        .collect()
                } else {
                    vec![None]
                };
                for link_id in beacon_links {
                    if self.group_keys.bigtk.get(&link_id) == Some(&(bigtk_idx, bigtk)) {
                        continue;
                    }
                    if nl_install_key(
                        &mut self.io.commands,
                        self.io.family,
                        KeyInstall::integrity(
                            ifindex,
                            bigtk_idx,
                            &bigtk,
                            &self.ap.bigtk_ipn(),
                            link_id,
                            true,
                        ),
                    ) {
                        self.group_keys.bigtk.insert(link_id, (bigtk_idx, bigtk));
                        eprintln!("netlink AP: Beacon Protection enabled (BIGTK idx {bigtk_idx} installed; kernel stamps per-beacon MME)");
                    } else {
                        self.group_keys.beacon_protection = false;
                        eprintln!("netlink AP: kernel rejected BIGTK — Beacon Protection DISABLED (beacons unprotected; no MME emitted)");
                        break;
                    }
                }
            }
        }
        if newly_keyed || group_keys_changed {
            // Do not advance userspace's installed epoch until every required
            // kernel key ACKs. Successful links are skipped during retry.
            self.group_keys
                .finish_reconciliation(&self.ap, group_keys_installed);
        }
    }
}
