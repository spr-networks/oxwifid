use super::*;

pub(super) fn native_u32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_ne_bytes(bytes.get(..4)?.try_into().ok()?))
}

pub fn run_offload_ap(
    ap: crate::ap::Ap,
    iface: &str,
    channel: u8,
    ctrl_path: Option<&str>,
    psk_file: Option<&str>,
    spr_api_socket: Option<&str>,
    spr_dhcp_helper: Option<&str>,
) -> io::Result<()> {
    let StartedRadio {
        ap,
        events,
        family,
        topology,
        bssid,
    } = start_radio(ap, iface, channel)?;
    let ifindex = topology.ifindex;
    let group_keys = GroupKeyStore::new(&ap);
    let vlans = VlanRegistry {
        enabled: ap.per_sta_vif(),
        base_iface: iface.to_string(),
        map: std::collections::HashMap::new(),
        ifindices: std::collections::HashSet::new(),
    };

    let mut io = RadioIo::start(events, family)?;
    let telemetry = match StationTelemetryWorker::start(io.family, ifindex) {
        Ok(worker) => Some(worker),
        Err(err) => {
            eprintln!("netlink AP: station telemetry worker unavailable: {err}");
            None
        }
    };

    // A SIGKILL/OOM/container restart can strand this radio's per-station VIFs
    // from the previous run (the SOCKET_OWNER reap only fires on a clean socket
    // close). The allocator only knows this process's own live map, so it would
    // re-propose the same ids and collide. Sweep the radio's leftover
    // `<iface>.<id>` AP_VLAN netdevs before serving any station.
    if vlans.enabled {
        flush_stale_ap_vlans(&mut io.commands, io.family, iface);
    }

    // Optional reference AP-style runtime control socket (STATUS / STA-DUMP / DEAUTH /
    // FAILURES / ATTACH) carrying live AP-STA-* events to attached clients.
    let control =
        ctrl_path.and_then(
            |p| match crate::control::ControlServer::bind(p, iface, psk_file) {
                Ok(c) => {
                    eprintln!("netlink AP: control interface on {p}");
                    Some(c)
                }
                Err(e) => {
                    eprintln!("netlink AP: control interface bind {p} failed: {e}");
                    None
                }
            },
        );
    let notifier = spr_api_socket.map(|path| {
        eprintln!("netlink AP: direct SPR events on Unix socket {path}");
        if let Some(helper) = spr_dhcp_helper {
            eprintln!("netlink AP: SPR DHCP/XDP helper {helper}");
        }
        crate::spr::SprNotifier::new(path, spr_dhcp_helper.map(std::path::PathBuf::from))
    });

    RadioRuntime {
        ap,
        io,
        topology,
        stations: StationRegistry::new(),
        group_keys,
        vlans,
        telemetry,
        control,
        notifier,
        bssid,
        event_buffer: vec![0u8; 65536],
    }
    .run()
}

impl RadioRuntime {
    pub(super) fn run(mut self) -> io::Result<()> {
        loop {
            self.apply_cleanup_results();
            self.schedule_cleanup();
            self.receive_events()?;
            self.release_stalled_association();
            self.tick_protocol();
            let newly_keyed = self.reconcile_stations();
            self.reconcile_group_keys(newly_keyed);
            self.service_control();
            self.publish_events();
        }
    }
}
