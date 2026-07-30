use super::*;

// Runtime control socket, telemetry, and SPR event publication.

impl RadioRuntime {
    pub(in crate::netlink::linux::ap) fn service_control(&mut self) {
        // Control interface: service pending commands (sending any frames they
        // produce, e.g. an admin DEAUTH), then surface AP-STA-* events to the
        // log and to any attached clients.
        if let Some(ctrl) = self.control.as_mut() {
            let ctrl_frames = {
                // Cache misses only enqueue work on the telemetry thread.
                let telemetry = std::cell::RefCell::new(&mut self.telemetry);
                let station_info = |mac: &[u8; 6]| {
                    self.vlans.assignment_for(mac).map(|assignment| {
                        let telemetry = telemetry
                            .borrow_mut()
                            .as_mut()
                            .and_then(|worker| worker.get(*mac));
                        crate::control::StationControlInfo {
                            vlan_id: assignment.vlan_id,
                            ifname: assignment.ifname.clone(),
                            telemetry,
                        }
                    })
                };
                ctrl.service(&mut self.ap, &station_info)
            };
            if !ctrl_frames.is_empty() {
                let out = crate::ap::Outgoing {
                    frames: ctrl_frames,
                    to_network: Vec::new(),
                };
                route_outputs(
                    &mut self.io,
                    &out,
                    &mut self.stations,
                    &mut self.group_keys,
                    &mut self.vlans,
                    &mut self.ap,
                    RouteEnvironment {
                        topology: &self.topology,
                        notifier: self.notifier.as_ref(),
                    },
                );
            }
        }
    }

    pub(in crate::netlink::linux::ap) fn publish_events(&mut self) {
        for ev in self.ap.drain_events() {
            if let crate::ap::ApEvent::Disconnected { mac, .. } = &ev {
                let core_sta = self
                    .ap
                    .station_link_for_peer(mac)
                    .or_else(|| self.vlans.core_key_for(mac))
                    .or_else(|| self.stations.owner_for_kernel_address(mac))
                    .unwrap_or(*mac);
                self.stations.begin_retirement(core_sta);
                self.vlans
                    .begin_retirement(&core_sta, Instant::now() + VLAN_EVENT_GRACE);
            }
            // reference AP adds `vlanid` (no underscore) to the connect event. SPR's
            // action script ignores that extra argv today and synchronously asks
            // `STA <mac>` for `vlan_id`, which the control responder above serves.
            let line = match &ev {
                crate::ap::ApEvent::Connected { mac } => match self.vlans.assignment_for(mac) {
                    Some(assignment) => {
                        format!("{} vlanid={}", ev.to_line(), assignment.vlan_id)
                    }
                    None => ev.to_line(),
                },
                _ => ev.to_line(),
            };
            eprintln!("{line}");
            if let Some(ctrl) = self.control.as_mut() {
                ctrl.broadcast(&line);
            }
            if let Some(notifier) = self.notifier.as_ref() {
                use crate::ap::ApEvent;
                use crate::spr::SprEvent;

                let mac = match &ev {
                    ApEvent::Connected { mac }
                    | ApEvent::Disconnected { mac, .. }
                    | ApEvent::AuthFailed { mac, .. } => mac,
                };
                let iface = self
                    .vlans
                    .assignment_for(mac)
                    .map(|assignment| assignment.ifname.clone())
                    .unwrap_or_else(|| self.vlans.base_iface.clone());
                let helper_prepared = matches!(&ev, ApEvent::Connected { .. })
                    && self
                        .vlans
                        .assignment_for(mac)
                        .is_some_and(|assignment| assignment.data_path_prepared);
                let mac = crate::util::bytes_to_mac(mac);
                let spr_event = match &ev {
                    ApEvent::Connected { .. } => Some(SprEvent::Connected { iface, mac }),
                    ApEvent::Disconnected { .. } => Some(SprEvent::Disconnected { iface, mac }),
                    ApEvent::AuthFailed { kind, .. } => SprEvent::auth_failure(iface, mac, *kind),
                };
                if let Some(event) = spr_event {
                    if helper_prepared {
                        notifier.notify_without_dhcp_helper(event);
                    } else {
                        notifier.notify(event);
                    }
                }
            }
        }
    }
}
