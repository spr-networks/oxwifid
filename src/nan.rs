//! NAN USD — Wi-Fi Aware Unsynchronized Service Discovery, ported from hostap's
//! `nan_de.c`.
//!
//! Implements the service-discovery half of NAN (Neighbor Awareness Networking):
//! Publish, Subscribe, Follow-up, and matching, carried in Service Discovery
//! Frames (Public Action frames with the NAN vendor type). The synchronized
//! data path (NDP/NDL) is out of scope.

use crate::crypto;
use crate::dot11;

// Public Action frame + NAN vendor type (OUI 50:6F:9A, type 0x13).
pub const WLAN_ACTION_PUBLIC: u8 = 4;
pub const WLAN_PA_VENDOR_SPECIFIC: u8 = 9;
pub const NAN_SDF_VENDOR_TYPE: u32 = 0x50_6f_9a_13;
pub const OUI_WFA: u32 = 0x50_6f_9a;

// NAN attribute ids.
pub const NAN_ATTR_SDA: u8 = 0x03; // Service Descriptor attribute
pub const NAN_ATTR_SDEA: u8 = 0x0e; // Service Descriptor Extension attribute
pub const NAN_SERVICE_ID_LEN: usize = 6;

// Service control type (low 2 bits of the Service Control field).
pub const NAN_SRV_CTRL_PUBLISH: u8 = 0;
pub const NAN_SRV_CTRL_SUBSCRIBE: u8 = 1;
pub const NAN_SRV_CTRL_FOLLOW_UP: u8 = 2;

/// The NAN Network ID (a group address) used as both the destination (A1) and
/// BSSID (A3) of USD Service Discovery Frames, per hostap's `nan_de.c`.
const NAN_NETWORK_ID: [u8; 6] = [0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00];

/// Derive the 6-byte NAN Service ID: SHA-256 of the lowercased service name.
pub fn service_id(service_name: &str) -> [u8; 6] {
    let lower = service_name.to_ascii_lowercase();
    let hash = crypto::sha256(lower.as_bytes());
    let mut id = [0u8; 6];
    id.copy_from_slice(&hash[..6]);
    id
}

/// A parsed Service Descriptor (SDA + optional SDEA service info).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceDescriptor {
    pub service_id: [u8; 6],
    pub instance_id: u8,
    pub requestor_instance_id: u8,
    pub control: u8,
    pub service_info: Option<Vec<u8>>,
}

impl ServiceDescriptor {
    pub fn ctrl_type(&self) -> u8 {
        self.control & 0x07
    }
}

/// Build a NAN Service Discovery Frame body (Public Action + NAN attributes).
pub fn build_sdf(ctrl_type: u8, service_id: &[u8; 6], instance_id: u8, req_instance_id: u8, ssi: Option<&[u8]>, srv_proto_type: u8) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(WLAN_ACTION_PUBLIC);
    v.push(WLAN_PA_VENDOR_SPECIFIC);
    v.extend_from_slice(&NAN_SDF_VENDOR_TYPE.to_be_bytes());

    // Service Descriptor attribute
    let sda_len: u16 = (NAN_SERVICE_ID_LEN + 3) as u16; // service_id + instance + req + ctrl
    v.push(NAN_ATTR_SDA);
    v.extend_from_slice(&sda_len.to_le_bytes());
    v.extend_from_slice(service_id);
    v.push(instance_id);
    v.push(req_instance_id);
    v.push(ctrl_type);

    // Service Descriptor Extension attribute (always for publish, or when ssi)
    if ctrl_type == NAN_SRV_CTRL_PUBLISH || ssi.is_some() {
        let mut sdea = Vec::new();
        sdea.push(instance_id);
        sdea.extend_from_slice(&0u16.to_le_bytes()); // SDEA control
        if let Some(ssi) = ssi {
            // Service Info: len(2) || OUI_WFA(3 BE) || proto(1) || ssi
            sdea.extend_from_slice(&((4 + ssi.len()) as u16).to_le_bytes());
            sdea.extend_from_slice(&OUI_WFA.to_be_bytes()[1..]); // 3-byte OUI
            sdea.push(srv_proto_type);
            sdea.extend_from_slice(ssi);
        }
        v.push(NAN_ATTR_SDEA);
        v.extend_from_slice(&(sdea.len() as u16).to_le_bytes());
        v.extend_from_slice(&sdea);
    }
    v
}

/// Parse a NAN SDF body, returning the service descriptors it carries.
pub fn parse_sdf(body: &[u8]) -> Option<Vec<ServiceDescriptor>> {
    if body.len() < 6 {
        return None;
    }
    if body[0] != WLAN_ACTION_PUBLIC || body[1] != WLAN_PA_VENDOR_SPECIFIC {
        return None;
    }
    if u32::from_be_bytes([body[2], body[3], body[4], body[5]]) != NAN_SDF_VENDOR_TYPE {
        return None;
    }

    let attrs = &body[6..];
    // Collect SDAs and (by instance id) SDEAs.
    let mut sdas: Vec<ServiceDescriptor> = Vec::new();
    let mut sdeas: Vec<(u8, Vec<u8>)> = Vec::new(); // (instance_id, service_info)

    let mut i = 0;
    while i + 3 <= attrs.len() {
        let id = attrs[i];
        let len = u16::from_le_bytes([attrs[i + 1], attrs[i + 2]]) as usize;
        if i + 3 + len > attrs.len() {
            break;
        }
        let a = &attrs[i + 3..i + 3 + len];
        if id == NAN_ATTR_SDA && a.len() >= 9 {
            let mut sid = [0u8; 6];
            sid.copy_from_slice(&a[..6]);
            sdas.push(ServiceDescriptor {
                service_id: sid,
                instance_id: a[6],
                requestor_instance_id: a[7],
                control: a[8],
                service_info: None,
            });
        } else if id == NAN_ATTR_SDEA && a.len() >= 3 {
            let instance = a[0];
            // a[1..3] = SDEA control; a[3..] = optional service info
            let info = if a.len() > 3 + 2 {
                let si_len = u16::from_le_bytes([a[3], a[4]]) as usize;
                if a.len() >= 5 + si_len && si_len >= 4 {
                    // skip OUI(3) + proto(1), keep the ssi
                    Some(a[5 + 4..5 + si_len].to_vec())
                } else {
                    None
                }
            } else {
                None
            };
            if let Some(info) = info {
                sdeas.push((instance, info));
            }
        }
        i += 3 + len;
    }

    // attach SDEA service info to its SDA by instance id
    for sda in &mut sdas {
        if let Some((_, info)) = sdeas.iter().find(|(inst, _)| *inst == sda.instance_id) {
            sda.service_info = Some(info.clone());
        }
    }
    Some(sdas)
}

// ---------------------------------------------------------------------------
// Discovery Engine
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Service {
    instance_id: u8,
    service_id: [u8; 6],
    ssi: Option<Vec<u8>>,
    is_publish: bool,
}

/// An event surfaced by the discovery engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NanEvent {
    /// A subscriber matched a peer's published service.
    Discovered {
        peer: [u8; 6],
        service_id: [u8; 6],
        peer_instance: u8,
        service_info: Option<Vec<u8>>,
    },
    /// A publisher saw a peer subscribe to one of its services.
    SubscribeReceived { peer: [u8; 6], service_id: [u8; 6] },
    /// A Follow-up message arrived from a peer.
    FollowupReceived { peer: [u8; 6], service_info: Option<Vec<u8>> },
}

/// A NAN USD discovery engine for one device.
pub struct NanDe {
    pub mac: [u8; 6],
    next_instance: u8,
    services: Vec<Service>,
    sc: u16,
}

impl NanDe {
    pub fn new(mac: [u8; 6]) -> NanDe {
        NanDe {
            mac,
            next_instance: 1,
            services: Vec::new(),
            sc: 0,
        }
    }

    fn next_sc(&mut self) -> u16 {
        self.sc = self.sc.wrapping_add(1) % 4096;
        self.sc * 16
    }

    fn alloc_instance(&mut self) -> u8 {
        let id = self.next_instance;
        self.next_instance = self.next_instance.wrapping_add(1).max(1);
        id
    }

    /// Publish a service; returns its instance id.
    pub fn publish(&mut self, service_name: &str, ssi: Option<&[u8]>) -> u8 {
        let instance_id = self.alloc_instance();
        self.services.push(Service {
            instance_id,
            service_id: service_id(service_name),
            ssi: ssi.map(|s| s.to_vec()),
            is_publish: true,
        });
        instance_id
    }

    /// Subscribe to a service; returns its instance id.
    pub fn subscribe(&mut self, service_name: &str) -> u8 {
        let instance_id = self.alloc_instance();
        self.services.push(Service {
            instance_id,
            service_id: service_id(service_name),
            ssi: None,
            is_publish: false,
        });
        instance_id
    }

    fn wrap(&mut self, dst: [u8; 6], body: &[u8]) -> Vec<u8> {
        let sc = self.next_sc();
        let frame = dot11::build_action_frame(&dst, &self.mac, &NAN_NETWORK_ID, sc, body);
        let mut f = dot11::RADIOTAP_TX.to_vec();
        f.extend_from_slice(&frame);
        f
    }

    /// Frames to broadcast this round: an (unsolicited) Publish SDF for each
    /// published service and a Subscribe SDF for each subscription.
    pub fn periodic_frames(&mut self) -> Vec<Vec<u8>> {
        let services = self.services.clone();
        let mut frames = Vec::new();
        for s in &services {
            let body = if s.is_publish {
                build_sdf(NAN_SRV_CTRL_PUBLISH, &s.service_id, s.instance_id, 0, s.ssi.as_deref(), 2)
            } else {
                build_sdf(NAN_SRV_CTRL_SUBSCRIBE, &s.service_id, s.instance_id, 0, None, 2)
            };
            frames.push(self.wrap(NAN_NETWORK_ID, &body));
        }
        frames
    }

    /// Build a unicast Follow-up SDF to a discovered peer.
    pub fn followup(&mut self, peer: [u8; 6], peer_instance: u8, my_instance: u8, sid: &[u8; 6], ssi: &[u8]) -> Vec<u8> {
        let body = build_sdf(NAN_SRV_CTRL_FOLLOW_UP, sid, my_instance, peer_instance, Some(ssi), 2);
        self.wrap(peer, &body)
    }

    /// Process a received SDF (radiotap-prefixed). Returns discovery events and
    /// any solicited response frames to transmit.
    pub fn process_frame(&mut self, radiotap_frame: &[u8]) -> (Vec<NanEvent>, Vec<Vec<u8>>) {
        let mut events = Vec::new();
        let mut responses = Vec::new();
        let Some(body) = dot11::strip_radiotap(radiotap_frame) else {
            return (events, responses);
        };
        let Some(frame) = dot11::Dot11::parse(body) else {
            return (events, responses);
        };
        if frame.frame_type() != dot11::TYPE_MGMT || frame.subtype() != dot11::SUBTYPE_ACTION {
            return (events, responses);
        }
        if frame.addr2 == self.mac {
            return (events, responses); // ignore our own frames
        }
        let peer = frame.addr2;
        let Some(descriptors) = parse_sdf(&frame.body) else {
            return (events, responses);
        };

        for d in descriptors {
            let t = d.ctrl_type();
            if t == NAN_SRV_CTRL_PUBLISH && self.services.iter().any(|s| !s.is_publish && s.service_id == d.service_id) {
                // A subscriber matches a peer's publish.
                events.push(NanEvent::Discovered {
                    peer,
                    service_id: d.service_id,
                    peer_instance: d.instance_id,
                    service_info: d.service_info.clone(),
                });
            } else if t == NAN_SRV_CTRL_SUBSCRIBE {
                // A publisher answers a matching subscribe with a solicited
                // (unicast) Publish SDF.
                let matching: Vec<Service> = self.services.iter().filter(|s| s.is_publish && s.service_id == d.service_id).cloned().collect();
                for s in matching {
                    events.push(NanEvent::SubscribeReceived { peer, service_id: d.service_id });
                    let resp = build_sdf(NAN_SRV_CTRL_PUBLISH, &s.service_id, s.instance_id, d.instance_id, s.ssi.as_deref(), 2);
                    responses.push(self.wrap(peer, &resp));
                }
            } else if t == NAN_SRV_CTRL_FOLLOW_UP && self.services.iter().any(|s| s.instance_id == d.requestor_instance_id) {
                // Follow-up addressed to one of our service instances.
                events.push(NanEvent::FollowupReceived {
                    peer,
                    service_info: d.service_info.clone(),
                });
            }
        }
        (events, responses)
    }
}
