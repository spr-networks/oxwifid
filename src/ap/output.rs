use crate::frames as dot11;

/// What [`super::Ap::handle_incoming`] produced for one inbound frame.
#[derive(Default)]
pub struct Outgoing {
    /// 802.11 frames to transmit (already radiotap-prefixed).
    pub frames: Vec<Vec<u8>>,
    /// Decrypted Ethernet frames for the AP's network backend (TUN / fakenet).
    pub to_network: Vec<Vec<u8>>,
}

impl Outgoing {
    pub(super) fn tx(&mut self, frame: Vec<u8>) {
        // sendp prepends the TX radiotap header
        let mut f = dot11::RADIOTAP_TX.to_vec();
        f.extend_from_slice(&frame);
        self.frames.push(f);
    }
}

/// A notable AP state change, surfaced to the control interface and the log —
/// mirrors reference AP's `AP-STA-*` control events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApEvent {
    /// A station completed the 4-way handshake and is authorized to pass data.
    Connected { mac: [u8; 6] },
    /// A previously-connected station was torn down (it left, was reaped for
    /// inactivity, or was kicked).
    Disconnected { mac: [u8; 6], reason: u16 },
    /// A fingerprinted failed-auth / decryption attempt — the `count` is how many
    /// times this identical (station, fingerprint, kind) tuple has been seen.
    AuthFailed {
        mac: [u8; 6],
        kind: crate::failures::FailureKind,
        count: u64,
    },
}

impl ApEvent {
    /// Render as a reference AP-style control line, e.g. `AP-STA-CONNECTED 02:..:01`.
    pub fn to_line(&self) -> String {
        use crate::util::bytes_to_mac;
        match self {
            ApEvent::Connected { mac } => format!("AP-STA-CONNECTED {}", bytes_to_mac(mac)),
            ApEvent::Disconnected { mac, reason } => {
                format!("AP-STA-DISCONNECTED {} reason={reason}", bytes_to_mac(mac))
            }
            // SPR's reference AP action scripts consume TYPE and REASON as the two
            // arguments following the MAC. Keep those tokens whitespace-free;
            // the count remains an optional trailing diagnostic field.
            ApEvent::AuthFailed {
                mac,
                kind: crate::failures::FailureKind::FourWayMic,
                count,
            } => format!(
                "AP-STA-POSSIBLE-PSK-MISMATCH {} wpa mismatch count={count}",
                bytes_to_mac(mac)
            ),
            ApEvent::AuthFailed {
                mac,
                kind: crate::failures::FailureKind::Sae,
                count,
            } => format!(
                "AP-STA-POSSIBLE-PSK-MISMATCH {} sae mismatch count={count}",
                bytes_to_mac(mac)
            ),
            ApEvent::AuthFailed { mac, kind, count } => format!(
                "AP-STA-AUTH-FAILED {} kind={} count={count}",
                bytes_to_mac(mac),
                kind.label()
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MldLink {
    pub link_id: u8,
    pub mac: [u8; 6],
    pub channel: u8,
    pub width: u16,
    pub band6: bool,
}
