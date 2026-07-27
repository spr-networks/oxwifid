use super::*;

use std::collections::{HashMap, HashSet};

pub(super) type Mac = [u8; 6];
pub(super) type LinkId = Option<u8>;
pub(super) type GroupKey = (u8, [u8; 16]);

/// Kernel state owned by one radio.
///
/// The protocol state machine remains in `Ap`; this registry records only what
/// has been published to nl80211. Keeping that boundary explicit prevents a
/// reconnect from inheriting a retiring kernel peer, VIF, key, or replay state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum KernelStationPhase {
    /// NEW_STATION/SET_STATION completed; the four-way is not published yet.
    Associated,
    /// PTK installation and authorization completed.
    Authorized,
    /// No new work may target this incarnation; cleanup owns it.
    Retiring,
}

#[derive(Debug)]
pub(super) struct KernelStation {
    pub(super) kernel_address: Option<Mac>,
    pub(super) pairwise_key: Option<Vec<u8>>,
    pub(super) phase: KernelStationPhase,
}

pub(super) struct StationRegistry {
    pub(super) peers: HashMap<Mac, KernelStation>,
    pub(super) key_pending: HashSet<Mac>,
    pub(super) pending_assoc: HashMap<Mac, PendingAssocTx>,
    pub(super) held_eapol: HashMap<Mac, Vec<u8>>,
    pub(super) base_cleanup: HashMap<Mac, BaseStationCleanup>,
    pub(super) next_cleanup_id: u64,
}

impl StationRegistry {
    pub(super) fn new() -> Self {
        Self {
            peers: HashMap::new(),
            key_pending: HashSet::new(),
            pending_assoc: HashMap::new(),
            held_eapol: HashMap::new(),
            base_cleanup: HashMap::new(),
            next_cleanup_id: 1,
        }
    }

    pub(super) fn record_associated(&mut self, mac: Mac, kernel_address: Mac) {
        self.peers.insert(
            mac,
            KernelStation {
                kernel_address: Some(kernel_address),
                pairwise_key: None,
                phase: KernelStationPhase::Associated,
            },
        );
    }

    pub(super) fn is_live(&self, mac: &Mac) -> bool {
        self.peers
            .get(mac)
            .is_some_and(|peer| peer.phase != KernelStationPhase::Retiring)
    }

    pub(super) fn is_authorized(&self, mac: &Mac) -> bool {
        self.peers
            .get(mac)
            .is_some_and(|peer| peer.phase == KernelStationPhase::Authorized)
    }

    pub(super) fn is_retiring(&self, mac: &Mac) -> bool {
        self.peers
            .get(mac)
            .is_some_and(|peer| peer.phase == KernelStationPhase::Retiring)
    }

    pub(super) fn mark_authorized(&mut self, mac: &Mac) {
        if let Some(peer) = self.peers.get_mut(mac) {
            peer.phase = KernelStationPhase::Authorized;
        }
    }

    pub(super) fn set_pairwise_key(&mut self, mac: &Mac, key: Vec<u8>) {
        if let Some(peer) = self.peers.get_mut(mac) {
            peer.pairwise_key = Some(key);
        }
    }

    pub(super) fn pairwise_key(&self, mac: &Mac) -> Option<&[u8]> {
        self.peers.get(mac)?.pairwise_key.as_deref()
    }

    pub(super) fn kernel_address(&self, mac: &Mac) -> Option<Mac> {
        self.peers.get(mac)?.kernel_address
    }

    pub(super) fn owner_for_kernel_address(&self, address: &Mac) -> Option<Mac> {
        self.peers.iter().find_map(|(owner, peer)| {
            (*owner == *address || peer.kernel_address == Some(*address)).then_some(*owner)
        })
    }

    pub(super) fn retiring(&self) -> impl Iterator<Item = Mac> + '_ {
        self.peers
            .iter()
            .filter_map(|(mac, peer)| (peer.phase == KernelStationPhase::Retiring).then_some(*mac))
    }

    pub(super) fn authorized(&self) -> impl Iterator<Item = Mac> + '_ {
        self.peers.iter().filter_map(|(mac, peer)| {
            (peer.phase == KernelStationPhase::Authorized).then_some(*mac)
        })
    }

    pub(super) fn has_authorized(&self) -> bool {
        self.peers
            .values()
            .any(|peer| peer.phase == KernelStationPhase::Authorized)
    }

    pub(super) fn begin_retirement(&mut self, mac: Mac) {
        self.peers
            .entry(mac)
            .and_modify(|peer| peer.phase = KernelStationPhase::Retiring)
            .or_insert(KernelStation {
                kernel_address: None,
                pairwise_key: None,
                phase: KernelStationPhase::Retiring,
            });
        self.key_pending.remove(&mac);
        self.pending_assoc.remove(&mac);
        self.held_eapol.remove(&mac);
    }

    /// The kernel station/key are gone, but an AP_VLAN may remain reserved
    /// until its own generation-tagged DEL_INTERFACE completion.
    pub(super) fn clear_kernel_publication(&mut self, mac: &Mac) {
        if let Some(peer) = self.peers.get_mut(mac) {
            peer.kernel_address = None;
            peer.pairwise_key = None;
        }
    }

    pub(super) fn forget(&mut self, mac: &Mac) {
        self.peers.remove(mac);
        self.key_pending.remove(mac);
        self.pending_assoc.remove(mac);
        self.held_eapol.remove(mac);
        self.base_cleanup.remove(mac);
    }

    pub(super) fn allocate_cleanup_id(&mut self) -> u64 {
        let id = self.next_cleanup_id;
        self.next_cleanup_id = self.next_cleanup_id.wrapping_add(1).max(1);
        id
    }
}

/// Installed group-key state for one radio.
///
/// Values are recorded only after the kernel acknowledges the corresponding
/// operation, making reconciliation naturally idempotent.
pub(super) struct GroupKeyStore {
    pub(super) gtk: HashMap<LinkId, GroupKey>,
    pub(super) igtk: HashMap<LinkId, GroupKey>,
    pub(super) bigtk: HashMap<LinkId, GroupKey>,
    pub(super) vlan_gtk: HashMap<(Mac, LinkId), GroupKey>,
    pub(super) beacon_protection: bool,
    pub(super) installed_epoch: u64,
    pub(super) install_pending: bool,
}

impl GroupKeyStore {
    pub(super) fn new(ap: &crate::ap::Ap) -> Self {
        Self {
            gtk: HashMap::new(),
            igtk: HashMap::new(),
            bigtk: HashMap::new(),
            vlan_gtk: HashMap::new(),
            beacon_protection: ap.beacon_prot(),
            installed_epoch: ap.group_key_epoch(),
            install_pending: false,
        }
    }

    pub(super) fn changed(&self, ap: &crate::ap::Ap) -> bool {
        self.install_pending || self.installed_epoch != ap.group_key_epoch()
    }

    pub(super) fn finish_reconciliation(&mut self, ap: &crate::ap::Ap, complete: bool) {
        self.install_pending = !complete;
        if complete {
            self.installed_epoch = ap.group_key_epoch();
        }
    }
}

/// Per-link addressing and capability data fixed for the lifetime of a radio.
pub(super) struct RadioTopology {
    pub(super) ifindex: u32,
    pub(super) wdev: u64,
    pub(super) channel: u8,
    pub(super) frequency: u32,
    pub(super) links: HashMap<u8, (Mac, u32)>,
    pub(super) station_links: HashMap<Mac, u8>,
    pub(super) capabilities: HashMap<u8, WiphyCapabilities>,
}

impl RadioTopology {
    pub(super) fn route(&self, ap: &crate::ap::Ap, destination: &Mac) -> (u32, Option<u8>) {
        if !ap.mld {
            return (self.frequency, None);
        }
        let link_id = self
            .station_links
            .get(destination)
            .copied()
            .filter(|link_id| self.links.contains_key(link_id))
            .unwrap_or(ap.link_id);
        self.links
            .get(&link_id)
            .map(|(_, frequency)| (*frequency, Some(link_id)))
            .unwrap_or((self.frequency, None))
    }
}

/// Linux I/O owned by the hot radio loop.
///
/// The event socket is receive-only after startup. Every request that waits for
/// an ACK uses the command socket or a dedicated worker socket, so synchronous
/// netlink traffic can never consume an MLME/control-port event.
pub(super) struct RadioIo {
    pub(super) family: u16,
    pub(super) events: NetlinkSocket,
    pub(super) commands: NetlinkSocket,
    pub(super) eapol: EapolTxWorker,
    pub(super) cleanup: KernelCleanupWorker,
}

impl RadioIo {
    pub(super) fn start(events: NetlinkSocket, family: u16) -> io::Result<Self> {
        Ok(Self {
            family,
            events,
            commands: NetlinkSocket::open()?,
            eapol: EapolTxWorker::start(family)?,
            cleanup: KernelCleanupWorker::start(family)?,
        })
    }
}

/// Long-lived state for one Linux AP radio.
///
/// Each field has a single owner and the event loop advances it through short,
/// ordered phases. Protocol state (`ap`) and kernel publication state
/// (`stations`, `vlans`, `group_keys`) are deliberately separate.
pub(super) struct RadioRuntime {
    pub(super) ap: crate::ap::Ap,
    pub(super) io: RadioIo,
    pub(super) topology: RadioTopology,
    pub(super) stations: StationRegistry,
    pub(super) group_keys: GroupKeyStore,
    pub(super) vlans: VlanRegistry,
    pub(super) telemetry: Option<StationTelemetryWorker>,
    pub(super) control: Option<crate::control::ControlServer>,
    pub(super) notifier: Option<crate::spr::SprNotifier>,
    pub(super) bssid: Mac,
    pub(super) event_buffer: Vec<u8>,
}
