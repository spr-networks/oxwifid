//! Raw-frame I/O: the transport abstraction, the event loop, and the
//! radiotap-frame transports.
//!
//! Transports all carry radiotap-prefixed 802.11 frames and implement [`Link`]:
//!   * [`StdioLink`] — length-prefixed frames on stdin/stdout (portable; wire
//!     compatible with the reference `ap.py` stdio mode).
//!   * [`af_packet::IfaceLink`] — a Linux monitor-mode `AF_PACKET` raw socket
//!     (real radios / `mac80211_hwsim`).
//!
//! The netlink (`nl80211`) transport in [`crate::netlink`] implements the same
//! [`Link`] trait, so the AP/client event loop drives either backend.

use std::io::{Read, Write};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use crate::ap::Ap;
use crate::client::Client;
use crate::fakenet::FakeNet;

pub mod af_packet;

#[cfg(target_os = "linux")]
pub use af_packet::IfaceLink;

/// A bidirectional link carrying radiotap-prefixed 802.11 frames.
pub trait Link {
    /// Wait up to `timeout` for an inbound frame.
    fn try_recv(&mut self, timeout: Duration) -> Option<Vec<u8>>;
    /// Transmit a frame.
    fn send(&mut self, frame: &[u8]);
}

/// A protocol participant driven by the event loop.
pub trait Node {
    /// How often [`Node::on_tick`] should run.
    fn tick_interval(&self) -> Duration;
    /// Periodic work (e.g. beacons); returns frames to transmit.
    fn on_tick(&mut self) -> Vec<Vec<u8>>;
    /// Handle one inbound frame; returns frames to transmit.
    fn on_frame(&mut self, frame: &[u8]) -> Vec<Vec<u8>>;
}

/// The event loop: tick on a timer, and dispatch every inbound frame to `node`.
pub fn run<L: Link, N: Node>(mut node: N, mut link: L) {
    let interval = node.tick_interval();
    let mut last_tick = Instant::now().checked_sub(interval).unwrap_or_else(Instant::now);
    loop {
        let now = Instant::now();
        if now.duration_since(last_tick) >= interval {
            for f in node.on_tick() {
                link.send(&f);
            }
            last_tick = now;
        }
        let wait = interval
            .checked_sub(Instant::now().duration_since(last_tick))
            .unwrap_or_default();

        if let Some(frame) = link.try_recv(wait) {
            for f in node.on_frame(&frame) {
                link.send(&f);
            }
        }
    }
}

/// Node wrapping the AP plus its fake network: beacons on tick, and for each
/// inbound frame runs the state machine, forwarding decrypted traffic through
/// the network and re-encrypting its replies.
pub struct ApNode {
    pub ap: Ap,
    pub net: FakeNet,
    pub beacon_interval: Duration,
}

impl Node for ApNode {
    fn tick_interval(&self) -> Duration {
        self.beacon_interval
    }
    fn on_tick(&mut self) -> Vec<Vec<u8>> {
        // Disassociate stations idle past the advertised BSS Max Idle period
        // (hostapd `ap_max_inactivity`, default 300 s) — a station that vanishes
        // without deauthing is otherwise never reaped.
        let mut frames = vec![self.ap.beacon_frame()];
        frames.extend(self.ap.prune_idle(Duration::from_secs(300)));
        frames
    }
    fn on_frame(&mut self, frame: &[u8]) -> Vec<Vec<u8>> {
        let out = self.ap.handle_incoming(frame);
        let mut frames = out.frames;
        for eth in &out.to_network {
            for reply in self.net.input(eth) {
                frames.extend(self.ap.deliver_to_station(&reply));
            }
        }
        frames
    }
}

/// Node wrapping the station: once authenticated it can fire one ICMP echo and
/// reports progress on stderr (`AUTHENTICATED` / `PING_REPLY_OK`).
pub struct ClientNode {
    pub client: Client,
    pub tick: Duration,
    pub ping_gateway: Option<([u8; 6], [u8; 4], [u8; 4])>, // (gw_mac, src_ip, gw_ip)
    announced: bool,
    pinged: bool,
}

impl ClientNode {
    pub fn new(client: Client, tick: Duration, ping_gateway: Option<([u8; 6], [u8; 4], [u8; 4])>) -> ClientNode {
        ClientNode {
            client,
            tick,
            ping_gateway,
            announced: false,
            pinged: false,
        }
    }
}

impl Node for ClientNode {
    fn tick_interval(&self) -> Duration {
        self.tick
    }

    fn on_tick(&mut self) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        if self.client.connected == 4 && !self.announced {
            eprintln!("AUTHENTICATED");
            self.announced = true;
        }
        if self.client.connected == 4 && !self.pinged {
            if let Some((gw_mac, src_ip, gw_ip)) = self.ping_gateway {
                let eth = self.client.build_ping(&gw_mac, src_ip, gw_ip);
                if let Some(f) = self.client.encrypt_uplink(&eth) {
                    frames.push(f);
                    self.pinged = true;
                    eprintln!("PING_SENT");
                }
            }
        }
        frames
    }

    fn on_frame(&mut self, frame: &[u8]) -> Vec<Vec<u8>> {
        let out = self.client.handle_incoming(frame);
        for eth in &out.to_network {
            if is_icmp_echo_reply(eth) {
                eprintln!("PING_REPLY_OK");
            }
        }
        out.frames
    }
}

fn is_icmp_echo_reply(eth: &[u8]) -> bool {
    if eth.len() < 14 + 20 + 8 {
        return false;
    }
    if u16::from_be_bytes([eth[12], eth[13]]) != 0x0800 {
        return false;
    }
    let ip = &eth[14..];
    let ihl = (ip[0] & 0x0f) as usize * 4;
    if ip.len() < ihl + 8 || ip[9] != 1 {
        return false;
    }
    ip[ihl] == 0 // ICMP echo reply
}

/// Split a streaming buffer into length-prefixed frames (`<u32-le len><frame>`),
/// returning the complete frames and the number of bytes consumed.
pub(crate) fn extract_frames(buf: &[u8]) -> (Vec<Vec<u8>>, usize) {
    let mut frames = Vec::new();
    let mut off = 0;
    while buf.len() - off >= 4 {
        let wanted = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) as usize;
        if buf.len() - off < 4 + wanted {
            break;
        }
        frames.push(buf[off + 4..off + 4 + wanted].to_vec());
        off += 4 + wanted;
    }
    (frames, off)
}

// ---------------------------------------------------------------------------
// stdio transport
// ---------------------------------------------------------------------------

pub struct StdioLink {
    rx: Receiver<Vec<u8>>,
    out: std::io::Stdout,
}

impl StdioLink {
    pub fn new() -> StdioLink {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut stdin = std::io::stdin().lock();
            let mut acc: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 65536];
            loop {
                match stdin.read(&mut chunk) {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        acc.extend_from_slice(&chunk[..n]);
                        let (frames, consumed) = extract_frames(&acc);
                        acc.drain(..consumed);
                        for f in frames {
                            if tx.send(f).is_err() {
                                return;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        StdioLink {
            rx,
            out: std::io::stdout(),
        }
    }
}

impl Default for StdioLink {
    fn default() -> Self {
        Self::new()
    }
}

impl Link for StdioLink {
    fn try_recv(&mut self, timeout: Duration) -> Option<Vec<u8>> {
        self.rx.recv_timeout(timeout).ok()
    }

    fn send(&mut self, frame: &[u8]) {
        let mut buf = Vec::with_capacity(4 + frame.len());
        buf.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        buf.extend_from_slice(frame);
        let _ = self.out.write_all(&buf);
        let _ = self.out.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_extraction_handles_partial_and_multiple() {
        // two frames back-to-back, plus a trailing partial
        let mut buf = Vec::new();
        buf.extend_from_slice(&3u32.to_le_bytes());
        buf.extend_from_slice(&[1, 2, 3]);
        buf.extend_from_slice(&2u32.to_le_bytes());
        buf.extend_from_slice(&[4, 5]);
        buf.extend_from_slice(&5u32.to_le_bytes()); // length says 5
        buf.extend_from_slice(&[9, 9]); // but only 2 bytes present
        let (frames, consumed) = extract_frames(&buf);
        assert_eq!(frames, vec![vec![1, 2, 3], vec![4, 5]]);
        assert_eq!(consumed, 4 + 3 + 4 + 2);
    }
}
