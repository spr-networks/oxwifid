use super::*;

// Generation-safe station, key, and AP_VLAN retirement.

impl RadioRuntime {
    pub(super) fn apply_cleanup_results(&mut self) {
        // Apply cleanup completions only when their generation still matches
        // the reservation in the main radio thread. Until the final interface
        // completion, VlanRegistry::map continues to reserve the name/id and keeps
        // its ifindex admitted by the event filter.
        while let Ok(result) = self.io.cleanup.results.try_recv() {
            for warning in &result.warnings {
                eprintln!(
                    "netlink AP: cleanup id={} sta={} {warning}",
                    result.id,
                    crate::util::bytes_to_mac(&result.core_sta),
                );
            }
            match result.kind {
                KernelCleanupKind::Station => {
                    let vlan_match =
                        self.vlans
                            .map
                            .get_mut(&result.core_sta)
                            .is_some_and(|assignment| {
                                if assignment.station_cleanup_id != Some(result.id) {
                                    return false;
                                }
                                assignment.station_cleanup_id = None;
                                if result.success {
                                    assignment.station_removed = true;
                                    assignment.station_retry_at = None;
                                } else {
                                    assignment.station_retry_at =
                                        Some(Instant::now() + CLEANUP_RETRY_DELAY);
                                }
                                true
                            });
                    if vlan_match {
                        if result.success {
                            self.stations.clear_kernel_publication(&result.core_sta);
                        }
                        continue;
                    }
                    let base_match = self
                        .stations
                        .base_cleanup
                        .get_mut(&result.core_sta)
                        .is_some_and(|cleanup| {
                            if cleanup.cleanup_id != Some(result.id) {
                                return false;
                            }
                            cleanup.cleanup_id = None;
                            if !result.success {
                                cleanup.retry_at = Instant::now() + CLEANUP_RETRY_DELAY;
                            }
                            true
                        });
                    if base_match && result.success {
                        self.stations.forget(&result.core_sta);
                    }
                }
                KernelCleanupKind::Interface => {
                    if self
                        .vlans
                        .complete_interface_cleanup(
                            &result.core_sta,
                            result.id,
                            result.success,
                            Instant::now(),
                        )
                        .is_some()
                    {
                        // Atomic release point: only now, after the worker saw a
                        // successful/absent DEL_INTERFACE ACK, can allocate()
                        // observe this VLAN id and interface name as free.
                        self.group_keys
                            .vlan_gtk
                            .retain(|(known, _), _| known != &result.core_sta);
                        self.group_keys
                            .vlan_igtk
                            .retain(|(known, _), _| known != &result.core_sta);
                        self.stations.forget(&result.core_sta);
                    }
                }
            }
        }
    }

    pub(super) fn schedule_cleanup(&mut self) {
        let ifindex = self.topology.ifindex;
        // Drive pending cleanup without waiting in the radio loop. A station
        // cleanup always precedes AP_VLAN deletion; interface ids remain
        // reserved during both the event grace period and any driver retries.
        let now = Instant::now();
        let retiring: Vec<[u8; 6]> = self.stations.retiring().collect();
        for core_sta in retiring {
            if let Some(assignment) = self.vlans.map.get_mut(&core_sta) {
                if assignment.retire_at.is_none() {
                    assignment.retire_at = Some(now + VLAN_EVENT_GRACE);
                    assignment.station_retry_at = Some(now);
                }
                if !assignment.station_removed
                    && assignment.station_cleanup_id.is_none()
                    && assignment.station_retry_at.is_none_or(|retry| retry <= now)
                {
                    let id = self.stations.allocate_cleanup_id();
                    let job = KernelCleanupJob {
                        id,
                        core_sta,
                        action: KernelCleanupAction::Station {
                            base_ifindex: ifindex,
                            station_ifindex: assignment.ifindex,
                            kernel_sta: assignment.sta_addr,
                            delete_on_base_too: assignment.station_may_be_on_base,
                        },
                    };
                    if self.io.cleanup.schedule(job) {
                        assignment.station_cleanup_id = Some(id);
                        assignment.station_retry_at = None;
                    }
                }
                let delete_due = assignment.retire_at.is_some_and(|deadline| deadline <= now);
                if assignment.station_removed
                    && delete_due
                    && assignment.interface_cleanup_id.is_none()
                    && assignment
                        .interface_retry_at
                        .is_none_or(|retry| retry <= now)
                {
                    let id = self.stations.allocate_cleanup_id();
                    let job = KernelCleanupJob {
                        id,
                        core_sta,
                        action: KernelCleanupAction::Interface {
                            ifindex: assignment.ifindex,
                        },
                    };
                    if self.io.cleanup.schedule(job) {
                        assignment.interface_cleanup_id = Some(id);
                        assignment.interface_retry_at = None;
                    }
                }
                continue;
            }

            let kernel_address = self.stations.kernel_address(&core_sta);
            if let std::collections::hash_map::Entry::Vacant(entry) =
                self.stations.base_cleanup.entry(core_sta)
            {
                if let Some(kernel_sta) = kernel_address {
                    entry.insert(BaseStationCleanup {
                        kernel_sta,
                        cleanup_id: None,
                        retry_at: now,
                    });
                } else {
                    // NEW_STATION never succeeded, so there is no kernel
                    // resource to retire and no identifier to reserve.
                    self.stations.forget(&core_sta);
                    continue;
                }
            }
            let kernel_sta = self
                .stations
                .base_cleanup
                .get(&core_sta)
                .filter(|cleanup| cleanup.cleanup_id.is_none() && cleanup.retry_at <= now)
                .map(|cleanup| cleanup.kernel_sta);
            if let Some(kernel_sta) = kernel_sta {
                let id = self.stations.allocate_cleanup_id();
                let job = KernelCleanupJob {
                    id,
                    core_sta,
                    action: KernelCleanupAction::Station {
                        base_ifindex: ifindex,
                        station_ifindex: ifindex,
                        kernel_sta,
                        delete_on_base_too: false,
                    },
                };
                if self.io.cleanup.schedule(job) {
                    self.stations
                        .base_cleanup
                        .get_mut(&core_sta)
                        .expect("cleanup entry was selected above")
                        .cleanup_id = Some(id);
                }
            }
        }
    }
}
