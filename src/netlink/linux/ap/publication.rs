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

        // Install a verified M2's PTK immediately after transmitting M3,
        // before receiving M4 and before authorizing the station. This is
        // required when a supplicant protects M4 at the 802.11 layer.
        self.stations
            .key_install_pending
            .extend(self.ap.drain_key_install_stations());
        let pending_installs: Vec<[u8; 6]> =
            self.stations.key_install_pending.iter().copied().collect();
        for sta in &pending_installs {
            if self.stations.is_retiring(sta) || !self.stations.is_live(sta) {
                self.stations.key_install_pending.remove(sta);
                continue;
            }
            let Some(tk) = self.ap.station_pending_pairwise_key(sta) else {
                self.stations.key_install_pending.remove(sta);
                continue;
            };
            let mld_mac = self.ap.mld.then(|| self.ap.station_mld_mac(sta)).flatten();
            let key_sta = mld_mac.as_ref().unwrap_or(sta);
            let kernel_has_key = self
                .stations
                .pairwise_key(sta)
                .is_some_and(|installed| installed == tk);
            if !kernel_has_key
                && !nl_install_key(
                    &mut self.io.commands,
                    self.io.family,
                    KeyInstall::pairwise(
                        ifindex,
                        key_sta,
                        tk,
                        self.ap.station_pairwise_cipher(sta).suite_selector(),
                    ),
                )
            {
                continue;
            }
            if !kernel_has_key {
                self.stations.set_pairwise_key(sta, tk.to_vec());
            }
            self.stations.key_install_pending.remove(sta);
            eprintln!(
                "netlink AP: station {} PTK installed (unauthorized, awaiting M4)",
                crate::util::bytes_to_mac(key_sta),
            );
        }

        // Authorize any station that just completed the four-way.
        // per_sta_vif association publication has already:
        //
        //   1. create and group-key the private AP_VLAN;
        //   2. bind the still-unauthorized station to it;
        //   3. install the M2-derived PTK before M4, with the port closed;
        //   4. verify M4 and authorize the MLD station.
        //
        // In particular, never move an already-keyed/authorized station here.
        // Drivers build peer/key data-path state using the VIF selected before
        // PTK installation.
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
                if self.vlans.enabled
                    && !self
                        .vlans
                        .map
                        .get(sta)
                        .is_some_and(|assignment| !assignment.station_may_be_on_base)
                {
                    eprintln!(
                        "netlink AP: refusing to key {} before AP_VLAN association binding",
                        crate::util::bytes_to_mac(sta),
                    );
                    self.stations.begin_retirement(*sta);
                    self.vlans.begin_retirement(sta, Instant::now());
                    self.stations.key_pending.remove(sta);
                    continue;
                }
                // MLO pairwise keys are addressed to the peer MLD. The kernel
                // rejects MLO_LINK_ID on pairwise NEW_KEY; per-link and VLAN
                // scoping apply only to group/management keys. Keep pairwise
                // keys on the base BSS after SET_STA_VLAN.
                let kernel_has_key = self
                    .stations
                    .pairwise_key(sta)
                    .is_some_and(|installed| installed == tk);
                // The verified-M2 install is the station's real RX/TX PTK:
                // install it once between M3 and M4, then retain that same
                // kernel key while opening the controlled port.
                // Deleting/recreating the slot after M4 resets the driver's
                // pairwise data-path context after the supplicant has committed
                // to the original installation.
                let install_rx_tx = !kernel_has_key;
                if install_rx_tx {
                    if !nl_install_key(
                        &mut self.io.commands,
                        self.io.family,
                        KeyInstall::pairwise(
                            ifindex,
                            key_sta,
                            tk,
                            self.ap.station_pairwise_cipher(sta).suite_selector(),
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

                // Authorization is MLD-level state addressed through the base
                // BSS. In per_sta_vif mode the station has already been moved
                // before the four-way.
                let total_flags = associated_station_flags(
                    self.ap.station_capability(sta).unwrap_or(0),
                    self.ap.station_uses_wmm(sta),
                    self.ap.station_uses_pmf(sta),
                ) | (1u32 << NL80211_STA_FLAG_AUTHORIZED);
                if !nl_authorize(
                    &mut self.io.commands,
                    self.io.family,
                    self.topology.wdev,
                    key_sta,
                    total_flags,
                ) {
                    continue;
                }
                self.stations.mark_authorized(sta);
                self.stations.key_pending.remove(sta);
                newly_keyed = true;
                eprintln!(
                    "netlink AP: station {} M4 verified + authorized with installed PTK (core link {})",
                    crate::util::bytes_to_mac(key_sta),
                    crate::util::bytes_to_mac(sta),
                );
            }
        }

        newly_keyed
    }

    pub(super) fn reconcile_group_keys(&mut self, newly_keyed: bool) {
        let ifindex = self.topology.ifindex;
        let group_keys_changed = self.group_keys.changed(&self.ap);
        let mut group_keys_installed = true;

        // BSS-wide GTK: install this immediately after START_AP, even when
        // per_sta_vif is enabled. Dynamic AP_VLANs get additional private group
        // contexts; they do not replace the base BSS key context. Some
        // FullMAC firmware (including mt7996) initializes protected-TX state for
        // the BSS from this publication before any station/PTK is installed.
        if newly_keyed || group_keys_changed {
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
        // stale. Association publication seeds vlan_gtk, so this only fires on
        // an actual rotation.
        if self.vlans.enabled && group_keys_changed {
            let authorized: Vec<[u8; 6]> = self.stations.authorized().collect();
            for sta in authorized {
                let Some(assignment) = self.vlans.map.get(&sta) else {
                    continue;
                };
                let vidx = assignment.ifindex;
                let gidx = self.ap.station_gtk_key_id(&sta);
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
                        let key = KeyInstall::group(vidx, gidx, &gkey, link_id)
                            .with_vlan_offload(assignment.vlan_id, self.topology.vlan_offload);
                        if nl_install_key(&mut self.io.commands, self.io.family, key) {
                            self.group_keys.vlan_gtk.insert(state_key, (gidx, gkey));
                        } else {
                            group_keys_installed = false;
                        }
                    }
                    if self.ap.is_pmf() {
                        let igtk_idx = self.ap.station_igtk_key_id(&sta) as u8;
                        let igtk = self.ap.station_igtk(&sta);
                        let igtk_ipn = self.ap.station_igtk_ipn(&sta);
                        if self.group_keys.vlan_igtk.get(&state_key) != Some(&(igtk_idx, igtk)) {
                            let key = KeyInstall::integrity(
                                vidx, igtk_idx, &igtk, &igtk_ipn, link_id, false,
                            )
                            .with_vlan_offload(assignment.vlan_id, self.topology.vlan_offload);
                            if nl_install_key(&mut self.io.commands, self.io.family, key) {
                                self.group_keys
                                    .vlan_igtk
                                    .insert(state_key, (igtk_idx, igtk));
                            } else {
                                group_keys_installed = false;
                            }
                        }
                    }
                }
            }
        }

        // IGTK for PMF (SAE/OWE): publish it with the GTK at BSS startup, then
        // re-install it on rotation. Waiting for the first authorized station
        // leaves the base firmware security context incomplete while that
        // station is being bound and pairwise-keyed.
        if self.ap.is_pmf() && (newly_keyed || group_keys_changed) {
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
