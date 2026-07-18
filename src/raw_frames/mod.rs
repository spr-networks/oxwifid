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

#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};

use crate::ap::Ap;
use crate::client::Client;
use crate::fakenet::FakeNet;

pub mod af_packet;
#[cfg(target_os = "linux")]
pub mod tap;

#[cfg(target_os = "linux")]
pub use af_packet::IfaceLink;
#[cfg(target_os = "linux")]
pub use tap::TapDevice;

#[cfg(target_os = "linux")]
static CLIENT_SHUTDOWN: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "linux")]
extern "C" fn request_client_shutdown(_signal: libc::c_int) {
    // Atomic stores are async-signal-safe; all filesystem work stays in the
    // normal event loop after this handler returns.
    CLIENT_SHUTDOWN.store(true, Ordering::Relaxed);
}

/// A bidirectional link carrying radiotap-prefixed 802.11 frames.
pub trait Link {
    /// Wait up to `timeout` for an inbound frame.
    fn try_recv(&mut self, timeout: Duration) -> Option<Vec<u8>>;
    /// Transmit a frame.
    fn send(&mut self, frame: &[u8]);
    /// Whether the link has closed (e.g. stdin reached EOF). The event loop
    /// stops when this is true; a transport that never closes (a raw socket)
    /// keeps the default `false`. Without this, a closed channel makes
    /// `try_recv` return immediately every iteration and the loop busy-spins.
    fn is_closed(&self) -> bool {
        false
    }
    /// Retune a channel-aware transport after a fresh BSS scan. Portable/test
    /// transports do not support this operation.
    fn retune(&mut self, _channel: u8, _band6: bool) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "transport cannot retune",
        ))
    }
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
    let mut last_tick = Instant::now()
        .checked_sub(interval)
        .unwrap_or_else(Instant::now);
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
        // Stop cleanly once the transport closes (stdin EOF) rather than
        // busy-spinning on a disconnected channel.
        if link.is_closed() {
            break;
        }
    }
}

/// Production station data loop: drive the Wi-Fi state machine and bridge its
/// decrypted Ethernet side to a TAP interface. Addressing and routes remain
/// owned by the host/SPR; this loop never runs DHCP or changes an IP route.
#[cfg(target_os = "linux")]
pub fn run_client_tap<L: Link>(
    client: Client,
    wifi: L,
    tap: TapDevice,
    state_file: Option<&std::path::Path>,
) -> std::io::Result<()> {
    run_client_tap_inner(client, wifi, tap, state_file, None)
}

/// TAP client loop with a native scan/reselection hook. The hook runs only
/// while the client is disconnected, so a multi-channel scan cannot interrupt
/// an authenticated data path or an in-progress four-way handshake.
#[cfg(target_os = "linux")]
pub fn run_client_tap_with_rescan<L, F>(
    client: Client,
    wifi: L,
    tap: TapDevice,
    state_file: Option<&std::path::Path>,
    mut rescan: F,
) -> std::io::Result<()>
where
    L: Link,
    F: FnMut(&mut Client, &mut L) -> std::io::Result<()>,
{
    run_client_tap_inner(client, wifi, tap, state_file, Some(&mut rescan))
}

#[cfg(target_os = "linux")]
fn run_client_tap_inner<L: Link>(
    mut client: Client,
    mut wifi: L,
    mut tap: TapDevice,
    state_file: Option<&std::path::Path>,
    mut rescan: Option<&mut dyn FnMut(&mut Client, &mut L) -> std::io::Result<()>>,
) -> std::io::Result<()> {
    CLIENT_SHUTDOWN.store(false, Ordering::Relaxed);
    clear_client_state(state_file);
    // SAFETY: the handler only performs an atomic store and has C signal
    // calling convention. This client loop owns TERM/INT handling for the
    // remaining lifetime of the process.
    unsafe {
        let handler = request_client_shutdown as *const () as libc::sighandler_t;
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGINT, handler);
    }
    // Keep both sides responsive under a saturated uplink. A short receive
    // poll avoids adding 20 ms bursts to TAP traffic, while a bounded TAP batch
    // prevents a continuously writable host stack from starving Wi-Fi RX,
    // EAPOL group rekeys, and liveness maintenance.
    let tick = Duration::from_millis(2);
    const TAP_BATCH: usize = 64;
    let mut announced = false;
    let mut next_rescan = Instant::now() + Duration::from_secs(5);
    loop {
        if CLIENT_SHUTDOWN.load(Ordering::Relaxed) {
            clear_client_state(state_file);
            return Ok(());
        }
        if client.maintenance(Instant::now()) && announced {
            announced = false;
            clear_client_state(state_file);
            eprintln!("DISCONNECTED timeout");
            next_rescan = Instant::now();
        }

        if let Some(frame) = wifi.try_recv(tick) {
            let was_connected = client.connected == 4;
            let out = client.handle_incoming(&frame);
            for transmit in out.frames {
                wifi.send(&transmit);
            }
            for ethernet in out.to_network {
                if std::env::var_os("RUSTAP_CLIENT_DEBUG").is_some() {
                    eprintln!(
                        "client TAP downlink len={} ethertype={:02x}{:02x} {}",
                        ethernet.len(),
                        ethernet.get(12).copied().unwrap_or_default(),
                        ethernet.get(13).copied().unwrap_or_default(),
                        ethernet_debug(&ethernet)
                    );
                }
                tap.send(&ethernet)?;
            }
            if was_connected && client.connected != 4 {
                announced = false;
                clear_client_state(state_file);
                eprintln!("DISCONNECTED");
                next_rescan = Instant::now();
            }
        }

        if client.connected == 0 && Instant::now() >= next_rescan {
            if let Some(reselect) = rescan.as_deref_mut() {
                match reselect(&mut client, &mut wifi) {
                    Ok(()) => eprintln!("RESCAN selected a matching BSS"),
                    Err(error) => eprintln!("RESCAN failed: {error}"),
                }
            }
            next_rescan = Instant::now() + Duration::from_secs(10);
        }

        for _ in 0..TAP_BATCH {
            let Some(ethernet) = tap.try_recv()? else {
                break;
            };
            if std::env::var_os("RUSTAP_CLIENT_DEBUG").is_some() {
                eprintln!(
                    "client TAP uplink len={} ethertype={:02x}{:02x} connected={} {}",
                    ethernet.len(),
                    ethernet.get(12).copied().unwrap_or_default(),
                    ethernet.get(13).copied().unwrap_or_default(),
                    client.connected,
                    ethernet_debug(&ethernet)
                );
            }
            if let Some(frame) = client.encrypt_uplink(&ethernet) {
                wifi.send(&frame);
            }
        }

        if client.connected == 4 && !announced {
            announced = true;
            write_client_state(state_file)?;
            eprintln!(
                "AUTHENTICATED tap={} bssid={}",
                tap.name(),
                client
                    .bssid()
                    .map(|bssid| crate::util::bytes_to_mac(&bssid))
                    .unwrap_or_else(|| "unknown".to_string())
            );
        }
        if wifi.is_closed() {
            clear_client_state(state_file);
            return Ok(());
        }
    }
}

#[cfg(target_os = "linux")]
fn ethernet_debug(frame: &[u8]) -> String {
    if frame.len() < 14 {
        return "truncated".to_string();
    }
    let mac = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    let mut detail = format!("{} -> {}", mac(&frame[6..12]), mac(&frame[0..6]));
    if frame[12..14] == [0x08, 0x06] && frame.len() >= 42 {
        detail.push_str(&format!(
            " arp-op={} {}.{}.{}.{} -> {}.{}.{}.{}",
            u16::from_be_bytes([frame[20], frame[21]]),
            frame[28],
            frame[29],
            frame[30],
            frame[31],
            frame[38],
            frame[39],
            frame[40],
            frame[41]
        ));
    }
    detail
}

#[cfg(target_os = "linux")]
fn write_client_state(path: Option<&std::path::Path>) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(path) = path else { return Ok(()) };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut nonce = [0u8; 8];
    getrandom::getrandom(&mut nonce)
        .map_err(|error| std::io::Error::other(format!("OS RNG failed: {error}")))?;
    let nonce = u64::from_ne_bytes(nonce);
    let temporary = path.with_extension(format!("tmp.{}.{nonce:016x}", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        // `create_new` is atomic and refuses to follow a pre-created symlink.
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)?;
    writeln!(file, "CONNECTED {timestamp}")?;
    file.sync_all()?;
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn clear_client_state(path: Option<&std::path::Path>) {
    if let Some(path) = path {
        let _ = std::fs::remove_file(path);
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
        // Retransmit any pending EAPOL m1/m3 whose m2/m4 was lost (handshake
        // reliability); deauth stations whose 4-way never completes.
        frames.extend(self.ap.tick().frames);
        for ev in self.ap.drain_events() {
            eprintln!("{}", ev.to_line());
        }
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
        for ev in self.ap.drain_events() {
            eprintln!("{}", ev.to_line());
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
    /// IP ToS byte (DSCP << 2) stamped on the test ping, so the WMM classifier
    /// picks the matching access category.
    pub ping_tos: u8,
    announced: bool,
    pinged: bool,
}

impl ClientNode {
    pub fn new(
        client: Client,
        tick: Duration,
        ping_gateway: Option<([u8; 6], [u8; 4], [u8; 4])>,
    ) -> ClientNode {
        ClientNode {
            client,
            tick,
            ping_gateway,
            ping_tos: 0,
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
        if self.client.maintenance(Instant::now()) {
            self.announced = false;
            self.pinged = false;
            eprintln!("DISCONNECTED timeout");
        }
        if self.client.connected == 4 && !self.announced {
            eprintln!("AUTHENTICATED");
            self.announced = true;
        }
        if self.client.connected == 4 && !self.pinged {
            if let Some((gw_mac, src_ip, gw_ip)) = self.ping_gateway {
                let eth = self
                    .client
                    .build_ping(&gw_mac, src_ip, gw_ip, self.ping_tos);
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
        let was_connected = self.client.connected == 4;
        let out = self.client.handle_incoming(frame);
        if was_connected && self.client.connected != 4 {
            self.announced = false;
            self.pinged = false;
            eprintln!("DISCONNECTED");
        }
        let mut frames = out.frames;
        for eth in &out.to_network {
            if is_icmp_echo_reply(eth) {
                eprintln!("PING_REPLY_OK");
            }
            // Answer the AP's ARP request for our IP so it can route the ICMP
            // echo reply back to us (the AP's kernel needs our MAC first).
            if let Some((_, src_ip, _)) = self.ping_gateway {
                if let Some(reply) = self.client.build_arp_reply(eth, src_ip) {
                    if let Some(f) = self.client.encrypt_uplink(&reply) {
                        frames.push(f);
                    }
                }
            }
        }
        frames
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
        let wanted =
            u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) as usize;
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
    /// Set once stdin reaches EOF (the reader thread exits and the channel
    /// disconnects), so the event loop exits instead of busy-spinning.
    closed: bool,
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
            closed: false,
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
        use std::sync::mpsc::RecvTimeoutError;
        match self.rx.recv_timeout(timeout) {
            Ok(frame) => Some(frame),
            Err(RecvTimeoutError::Timeout) => None,
            // stdin reached EOF: the reader thread exited and dropped the sender.
            // Recording it lets the loop stop; otherwise `recv_timeout` returns
            // immediately every call and the loop spins at 100% CPU.
            Err(RecvTimeoutError::Disconnected) => {
                self.closed = true;
                None
            }
        }
    }

    fn is_closed(&self) -> bool {
        self.closed
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

    // Regression: a closed link (stdin EOF) must end the loop, not busy-spin.
    #[test]
    fn run_exits_when_link_closes() {
        use std::sync::mpsc;
        use std::thread;

        struct ClosedLink;
        impl Link for ClosedLink {
            fn try_recv(&mut self, _t: Duration) -> Option<Vec<u8>> {
                None
            }
            fn send(&mut self, _f: &[u8]) {}
            fn is_closed(&self) -> bool {
                true
            }
        }
        struct NoopNode;
        impl Node for NoopNode {
            fn tick_interval(&self) -> Duration {
                Duration::from_millis(10)
            }
            fn on_tick(&mut self) -> Vec<Vec<u8>> {
                vec![]
            }
            fn on_frame(&mut self, _f: &[u8]) -> Vec<Vec<u8>> {
                vec![]
            }
        }

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            run(NoopNode, ClosedLink);
            let _ = tx.send(());
        });
        assert!(
            rx.recv_timeout(Duration::from_secs(2)).is_ok(),
            "run() must exit when the link closes (no busy-spin on stdin EOF)"
        );
    }

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
