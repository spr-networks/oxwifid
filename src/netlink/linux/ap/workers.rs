use super::*;

pub(super) struct EapolTxJob {
    pub(super) ifindex: u32,
    pub(super) dst: [u8; 6],
    pub(super) eapol: Vec<u8>,
    pub(super) encrypt: bool,
    pub(super) link_id: Option<u8>,
    pub(super) completion: Option<std::sync::mpsc::SyncSender<io::Result<()>>>,
}

pub(super) struct PendingEapolAck {
    pub(super) dst: [u8; 6],
    pub(super) len: usize,
    pub(super) sent_at: Instant,
}

pub(super) struct PendingAssocTx {
    pub(super) sc: u16,
    pub(super) sent_at: Instant,
}

/// Drivers normally report Association Response TX status immediately. Keep
/// reference ordering when they do, but do not let a missing multicast status
/// event hold message 1 until the authenticator's retry budget expires.
pub(super) const ASSOC_TX_STATUS_GRACE: Duration = Duration::from_millis(250);

pub(super) fn drain_eapol_acks(
    sock: &NetlinkSocket,
    pending: &mut std::collections::HashMap<u32, PendingEapolAck>,
    recv_buf: &mut [u8],
) {
    while let Some(len) = sock.recv_into(Duration::ZERO, recv_buf) {
        for parsed in msg::messages(&recv_buf[..len]) {
            let Some(code) = parsed.error_code() else {
                continue;
            };
            let Some(sent) = pending.remove(&parsed.seq) else {
                continue;
            };
            if code != 0 {
                eprintln!(
                    "netlink AP: TX EAPOL to {} len={} FAILED: {}",
                    crate::util::bytes_to_mac(&sent.dst),
                    sent.len,
                    io::Error::from_raw_os_error(-code),
                );
            }
        }
    }

    // An ACK is diagnostic, not the on-air delivery signal (the MLME
    // TX-STATUS event is). Do not retain metadata forever if a driver/kernel
    // loses one; the AP's normal EAPOL timer handles actual retransmission.
    let now = Instant::now();
    pending.retain(|_, sent| now.duration_since(sent.sent_at) < Duration::from_secs(2));
}

/// The radio loop only performs a bounded, nonblocking enqueue. This worker
/// submits control-port frames without waiting for each ACK, then drains the
/// dedicated socket's ACK/error stream asynchronously. Per-station frame order
/// is retained while a delayed ACK can no longer head-of-line-block unrelated
/// clients.
pub(super) struct EapolTxWorker {
    pub(super) requests: std::sync::mpsc::SyncSender<EapolTxJob>,
}

impl EapolTxWorker {
    pub(super) fn start(family: u16) -> io::Result<EapolTxWorker> {
        let mut sock = NetlinkSocket::open()?;
        let (request_tx, request_rx) = std::sync::mpsc::sync_channel::<EapolTxJob>(128);
        std::thread::Builder::new()
            .name("rustap-eapol-tx".to_string())
            .spawn(move || {
                let mut pending = std::collections::HashMap::new();
                let mut recv_buf = vec![0u8; 65536];
                loop {
                    let disconnected = match request_rx.recv_timeout(Duration::from_millis(5)) {
                        Ok(job) => {
                            if let Some(completion) = job.completion {
                                let seq = sock.next_seq();
                                let message = control_port_eapol_message(
                                    family,
                                    seq,
                                    job.ifindex,
                                    &job.dst,
                                    &job.eapol,
                                    job.encrypt,
                                    job.link_id,
                                );
                                let result = sock.request_ack(message);
                                let _ = completion.send(result);
                            } else {
                                match nl_queue_eapol(
                                    &mut sock,
                                    family,
                                    job.ifindex,
                                    &job.dst,
                                    &job.eapol,
                                    job.encrypt,
                                    job.link_id,
                                ) {
                                    Ok(seq) => {
                                        pending.insert(
                                            seq,
                                            PendingEapolAck {
                                                dst: job.dst,
                                                len: job.eapol.len(),
                                                sent_at: Instant::now(),
                                            },
                                        );
                                    }
                                    Err(err) => eprintln!(
                                        "netlink AP: TX EAPOL to {} len={} FAILED: {err}",
                                        crate::util::bytes_to_mac(&job.dst),
                                        job.eapol.len(),
                                    ),
                                }
                            }
                            false
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => false,
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => true,
                    };
                    drain_eapol_acks(&sock, &mut pending, &mut recv_buf);
                    if disconnected {
                        break;
                    }
                }
            })?;
        Ok(EapolTxWorker {
            requests: request_tx,
        })
    }

    pub(super) fn send(
        &self,
        ifindex: u32,
        dst: [u8; 6],
        eapol: Vec<u8>,
        encrypt: bool,
        link_id: Option<u8>,
    ) {
        let len = eapol.len();
        match self.requests.try_send(EapolTxJob {
            ifindex,
            dst,
            eapol,
            encrypt,
            link_id,
            completion: None,
        }) {
            Ok(()) => {}
            Err(std::sync::mpsc::TrySendError::Full(_)) => eprintln!(
                "netlink AP: EAPOL TX queue full; dropped frame to {} len={len}",
                crate::util::bytes_to_mac(&dst),
            ),
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => eprintln!(
                "netlink AP: EAPOL TX worker stopped; dropped frame to {} len={len}",
                crate::util::bytes_to_mac(&dst),
            ),
        }
    }

    /// Submit an EAPOL frame and wait until nl80211 acknowledges the control-
    /// port command. Use this barrier for M3 before installing the pairwise
    /// key; without it, mt7996 can process NEW_KEY while M3 is still queued
    /// against the pre-key peer.
    pub(super) fn send_and_wait(
        &self,
        ifindex: u32,
        dst: [u8; 6],
        eapol: Vec<u8>,
        encrypt: bool,
        link_id: Option<u8>,
    ) -> io::Result<()> {
        let (completion_tx, completion_rx) = std::sync::mpsc::sync_channel(1);
        self.requests
            .send(EapolTxJob {
                ifindex,
                dst,
                eapol,
                encrypt,
                link_id,
                completion: Some(completion_tx),
            })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "EAPOL TX worker stopped"))?;
        completion_rx
            .recv_timeout(Duration::from_secs(2))
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "EAPOL TX ACK timed out"))?
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum KernelCleanupKind {
    Station,
    Interface,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum KernelCleanupAction {
    Station {
        base_ifindex: u32,
        station_ifindex: u32,
        kernel_sta: [u8; 6],
        delete_on_base_too: bool,
    },
    Interface {
        ifindex: u32,
    },
}

#[derive(Clone, Copy, Debug)]
pub(super) struct KernelCleanupJob {
    pub(super) id: u64,
    pub(super) core_sta: [u8; 6],
    pub(super) action: KernelCleanupAction,
}

#[derive(Debug)]
pub(super) struct KernelCleanupResult {
    pub(super) id: u64,
    pub(super) core_sta: [u8; 6],
    pub(super) kind: KernelCleanupKind,
    pub(super) success: bool,
    pub(super) warnings: Vec<String>,
}

/// Key/station/interface deletion can block waiting for a sick driver's ACK.
/// Keep those waits off the radio loop, but return a generation-tagged result:
/// the main thread retains ownership of every station and VIF identifier until
/// the final matching completion, so a stale worker result can never release a
/// resource that a newer client owns.
pub(super) struct KernelCleanupWorker {
    pub(super) requests: std::sync::mpsc::SyncSender<KernelCleanupJob>,
    pub(super) results: std::sync::mpsc::Receiver<KernelCleanupResult>,
}

impl KernelCleanupWorker {
    pub(super) fn start(family: u16) -> io::Result<KernelCleanupWorker> {
        let mut sock = NetlinkSocket::open()?;
        let (request_tx, request_rx) = std::sync::mpsc::sync_channel::<KernelCleanupJob>(128);
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel::<KernelCleanupResult>(128);
        std::thread::Builder::new()
            .name("rustap-kernel-cleanup".to_string())
            .spawn(move || {
                while let Ok(job) = request_rx.recv() {
                    let mut warnings = Vec::new();
                    let (kind, success) = match job.action {
                        KernelCleanupAction::Station {
                            base_ifindex,
                            station_ifindex,
                            kernel_sta,
                            delete_on_base_too,
                        } => {
                            if let Err(error) =
                                nl_del_pairwise_key(&mut sock, family, base_ifindex, &kernel_sta)
                            {
                                warnings.push(format!("DEL_KEY PTK failed: {error}"));
                            }
                            let mut success = match nl_del_station(
                                &mut sock,
                                family,
                                station_ifindex,
                                &kernel_sta,
                            ) {
                                Ok(()) => true,
                                Err(error) => {
                                    warnings.push(format!("DEL_STATION failed: {error}"));
                                    false
                                }
                            };
                            // SET_STA_VLAN can fail after a driver partially
                            // moves a peer, and drivers disagree about which
                            // family interface accepts the subsequent delete.
                            // Deleting on both scopes is idempotent and ensures
                            // no base-BSS peer survives a successful VIF cleanup.
                            if delete_on_base_too && station_ifindex != base_ifindex {
                                if let Err(error) =
                                    nl_del_station(&mut sock, family, base_ifindex, &kernel_sta)
                                {
                                    warnings.push(format!(
                                        "DEL_STATION on base interface failed: {error}"
                                    ));
                                    success = false;
                                }
                            }
                            (KernelCleanupKind::Station, success)
                        }
                        KernelCleanupAction::Interface { ifindex } => {
                            let success = match nl_del_iface(&mut sock, family, ifindex) {
                                Ok(()) => true,
                                Err(error) => {
                                    warnings.push(format!("DEL_INTERFACE failed: {error}"));
                                    false
                                }
                            };
                            (KernelCleanupKind::Interface, success)
                        }
                    };
                    if result_tx
                        .send(KernelCleanupResult {
                            id: job.id,
                            core_sta: job.core_sta,
                            kind,
                            success,
                            warnings,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            })?;
        Ok(KernelCleanupWorker {
            requests: request_tx,
            results: result_rx,
        })
    }

    pub(super) fn schedule(&self, job: KernelCleanupJob) -> bool {
        match self.requests.try_send(job) {
            Ok(()) => true,
            Err(std::sync::mpsc::TrySendError::Full(_)) => false,
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                eprintln!("netlink AP: kernel cleanup worker stopped");
                false
            }
        }
    }
}

/// Live station measurements are optional control-plane data, so a slow
/// `GET_STATION` must never hold up management or EAPOL processing. This worker
/// owns a separate command socket and feeds a short-lived cache.
pub(super) struct StationTelemetryWorker {
    pub(super) requests: std::sync::mpsc::SyncSender<[u8; 6]>,
    pub(super) results:
        std::sync::mpsc::Receiver<([u8; 6], Option<crate::control::StationTelemetry>)>,
    pub(super) pending: std::collections::HashSet<[u8; 6]>,
    pub(super) cache:
        std::collections::HashMap<[u8; 6], (Instant, Option<crate::control::StationTelemetry>)>,
}

impl StationTelemetryWorker {
    pub(super) fn start(family: u16, ifindex: u32) -> io::Result<StationTelemetryWorker> {
        let mut sock = NetlinkSocket::open()?;
        let (request_tx, request_rx) = std::sync::mpsc::sync_channel::<[u8; 6]>(64);
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("rustap-station-telemetry".to_string())
            .spawn(move || {
                while let Ok(mac) = request_rx.recv() {
                    let telemetry = nl_get_station_telemetry(&mut sock, family, ifindex, &mac);
                    if result_tx.send((mac, telemetry)).is_err() {
                        break;
                    }
                }
            })?;
        Ok(StationTelemetryWorker {
            requests: request_tx,
            results: result_rx,
            pending: std::collections::HashSet::new(),
            cache: std::collections::HashMap::new(),
        })
    }

    pub(super) fn refresh(&mut self) {
        while let Ok((mac, telemetry)) = self.results.try_recv() {
            self.pending.remove(&mac);
            self.cache.insert(mac, (Instant::now(), telemetry));
        }
    }

    pub(super) fn get(&mut self, mac: [u8; 6]) -> Option<crate::control::StationTelemetry> {
        const CACHE_AGE: Duration = Duration::from_secs(1);
        self.refresh();
        let now = Instant::now();
        let fresh = self
            .cache
            .get(&mac)
            .is_some_and(|(at, _)| now.duration_since(*at) <= CACHE_AGE);
        if !fresh && !self.pending.contains(&mac) {
            match self.requests.try_send(mac) {
                Ok(()) => {
                    self.pending.insert(mac);
                }
                Err(std::sync::mpsc::TrySendError::Full(_)) => {}
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                    self.pending.clear();
                }
            }
        }
        self.cache
            .get(&mac)
            .and_then(|(_, telemetry)| telemetry.clone())
    }

    pub(super) fn forget(&mut self, mac: &[u8; 6]) {
        self.pending.remove(mac);
        self.cache.remove(mac);
    }
}
