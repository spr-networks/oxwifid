//! Runtime control interface, modelled on hostapd's `ctrl_interface`.
//!
//! A Unix datagram socket carries text commands (`STATUS`, `STA-DUMP`,
//! `DEAUTH <mac>`, `FAILURES`, `PING`) and an event subscription (`ATTACH` /
//! `DETACH`). Subscribed clients receive `AP-STA-*` event lines as they happen
//! (connect / disconnect / failed-auth), the same way `hostapd_cli` does.
//!
//! [`handle_command`] is portable and unit-tested; the socket server is gated to
//! Unix targets.

use crate::ap::Ap;
use crate::util::{bytes_to_mac, mac_to_bytes};

/// Execute one control command against the AP, returning the text reply and any
/// frames to transmit (e.g. the deauth produced by `DEAUTH`). `ATTACH`/`DETACH`
/// are handled by the socket server, not here.
pub fn handle_command(ap: &mut Ap, cmd: &str) -> (String, Vec<Vec<u8>>) {
    let mut it = cmd.split_whitespace();
    match it.next().unwrap_or("") {
        "PING" => ("PONG\n".to_string(), vec![]),
        "STATUS" => {
            let macs = ap.station_macs();
            let assoc = macs.iter().filter(|m| ap.is_associated(m)).count();
            (
                format!(
                    "ssid={}\nchannel={}\nwidth={}\nstations={}\nassociated={}\n",
                    String::from_utf8_lossy(&ap.ssid),
                    ap.channel,
                    ap.channel_width,
                    macs.len(),
                    assoc,
                ),
                vec![],
            )
        }
        "STA-DUMP" | "LIST-STA" => {
            let mut s = String::new();
            for m in ap.station_macs() {
                let state = if ap.is_associated(&m) { "ASSOCIATED" } else { "HANDSHAKING" };
                s.push_str(&format!("{} {}\n", bytes_to_mac(&m), state));
            }
            if s.is_empty() {
                s.push_str("(no stations)\n");
            }
            (s, vec![])
        }
        "DEAUTH" => match it.next() {
            Some(arg) => {
                let mac = mac_to_bytes(arg);
                match ap.kick(&mac) {
                    Some(f) => ("OK\n".to_string(), vec![f]),
                    None => ("FAIL unknown station\n".to_string(), vec![]),
                }
            }
            None => ("FAIL usage: DEAUTH <mac>\n".to_string(), vec![]),
        },
        "FAILURES" => {
            let mut s = String::new();
            for r in ap.failures().records() {
                s.push_str(&format!(
                    "{} kind={} count={} traits={:#018x}\n",
                    bytes_to_mac(&r.mac),
                    r.kind.label(),
                    r.count,
                    r.traits,
                ));
            }
            if s.is_empty() {
                s.push_str("(no failures)\n");
            }
            (s, vec![])
        }
        "" => ("FAIL empty command\n".to_string(), vec![]),
        other => (format!("UNKNOWN COMMAND '{other}'\n"), vec![]),
    }
}

#[cfg(test)]
mod tests {
    use super::handle_command;
    use crate::ap::Ap;
    use crate::util::mac_to_bytes;

    fn ap() -> Ap {
        Ap::new("turtlenet", "password1234", mac_to_bytes("02:00:00:00:00:00"), 6)
    }

    #[test]
    fn ping_status_and_unknown() {
        let mut ap = ap();
        assert_eq!(handle_command(&mut ap, "PING").0, "PONG\n");
        let status = handle_command(&mut ap, "STATUS").0;
        assert!(status.contains("ssid=turtlenet"), "{status}");
        assert!(status.contains("channel=6"), "{status}");
        assert!(status.contains("stations=0"), "{status}");
        assert!(handle_command(&mut ap, "BOGUS").0.starts_with("UNKNOWN COMMAND"));
        assert!(handle_command(&mut ap, "").0.starts_with("FAIL"));
    }

    #[test]
    fn dump_and_failures_when_empty() {
        let mut ap = ap();
        assert_eq!(handle_command(&mut ap, "STA-DUMP").0, "(no stations)\n");
        assert_eq!(handle_command(&mut ap, "FAILURES").0, "(no failures)\n");
    }

    #[test]
    fn deauth_unknown_station_fails_with_no_frame() {
        let mut ap = ap();
        let (reply, frames) = handle_command(&mut ap, "DEAUTH 02:00:00:00:ab:cd");
        assert!(reply.starts_with("FAIL"), "{reply}");
        assert!(frames.is_empty());
        // Missing argument is rejected, not panicked on.
        assert!(handle_command(&mut ap, "DEAUTH").0.starts_with("FAIL"));
    }
}

#[cfg(unix)]
pub use server::ControlServer;

#[cfg(unix)]
mod server {
    use super::{handle_command, Ap};
    use std::io;
    use std::os::unix::net::UnixDatagram;
    use std::path::PathBuf;

    /// A bound control socket plus the set of clients subscribed to events.
    pub struct ControlServer {
        sock: UnixDatagram,
        path: PathBuf,
        attached: Vec<PathBuf>,
    }

    impl ControlServer {
        /// Bind the control socket at `path` (replacing any stale socket file).
        pub fn bind(path: &str) -> io::Result<ControlServer> {
            let _ = std::fs::remove_file(path);
            let sock = UnixDatagram::bind(path)?;
            sock.set_nonblocking(true)?;
            Ok(ControlServer { sock, path: PathBuf::from(path), attached: Vec::new() })
        }

        /// Drain and handle every pending command (non-blocking), returning any
        /// frames the AP wants transmitted (e.g. an admin `DEAUTH`).
        pub fn service(&mut self, ap: &mut Ap) -> Vec<Vec<u8>> {
            let mut frames = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let (n, peer) = match self.sock.recv_from(&mut buf) {
                    Ok((n, addr)) => match addr.as_pathname() {
                        Some(p) => (n, p.to_path_buf()),
                        None => continue, // unnamed peer: nowhere to reply
                    },
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                };
                let cmd = String::from_utf8_lossy(&buf[..n]);
                let cmd = cmd.trim();
                let reply = match cmd {
                    "ATTACH" => {
                        if !self.attached.contains(&peer) {
                            self.attached.push(peer.clone());
                        }
                        "OK\n".to_string()
                    }
                    "DETACH" => {
                        self.attached.retain(|p| p != &peer);
                        "OK\n".to_string()
                    }
                    _ => {
                        let (r, fs) = handle_command(ap, cmd);
                        frames.extend(fs);
                        r
                    }
                };
                let _ = self.sock.send_to(reply.as_bytes(), &peer);
            }
            frames
        }

        /// Push one event line to every attached client; drop clients whose
        /// socket has gone away. hostapd prefixes events with a `<prio>` tag.
        pub fn broadcast(&mut self, line: &str) {
            let msg = format!("<3>{line}\n");
            let sock = &self.sock;
            self.attached.retain(|peer| sock.send_to(msg.as_bytes(), peer).is_ok());
        }
    }

    impl Drop for ControlServer {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
