//! Direct SPR event delivery over its Unix-domain HTTP socket.
//!
//! This replaces the hot-path `reference AP control client -> action.sh -> curl` process chain.
//! The AP loop only performs a bounded, non-blocking queue operation; a worker
//! thread does the local Unix-socket HTTP request and validates the response.

#![cfg(unix)]

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::time::Duration;

use serde_json::{json, Value};

use crate::failures::FailureKind;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SprEvent {
    Connected {
        iface: String,
        mac: String,
    },
    Disconnected {
        iface: String,
        mac: String,
    },
    AuthFailure {
        iface: String,
        mac: String,
        auth_type: &'static str,
        reason: &'static str,
    },
}

impl SprEvent {
    pub fn auth_failure(iface: String, mac: String, kind: FailureKind) -> Option<SprEvent> {
        let auth_type = match kind {
            FailureKind::FourWayMic => "wpa",
            FailureKind::Sae => "sae",
            FailureKind::CcmpData | FailureKind::ProtectedMgmt => return None,
        };
        Some(SprEvent::AuthFailure {
            iface,
            mac,
            auth_type,
            reason: "mismatch",
        })
    }

    fn request(&self) -> (&'static str, Value) {
        match self {
            SprEvent::Connected { iface, mac } => (
                "/reportPSKAuthSuccess",
                json!({"Iface": iface, "Event": "AP-STA-CONNECTED", "Mac": mac}),
            ),
            SprEvent::Disconnected { iface, mac } => (
                "/reportDisconnect",
                json!({"Iface": iface, "Event": "AP-STA-DISCONNECTED", "Mac": mac}),
            ),
            SprEvent::AuthFailure {
                iface,
                mac,
                auth_type,
                reason,
            } => (
                "/reportPSKAuthFailure",
                json!({"Iface": iface, "Type": auth_type, "Mac": mac, "Reason": reason}),
            ),
        }
    }

    fn dhcp_helper_args(&self) -> Option<(&'static str, &str, &str)> {
        match self {
            SprEvent::Connected { iface, mac } => Some(("add", iface, mac)),
            SprEvent::Disconnected { iface, mac } => Some(("remove", iface, mac)),
            SprEvent::AuthFailure { .. } => None,
        }
    }
}

pub struct SprNotifier {
    tx: SyncSender<SprNotification>,
    dhcp_helper: Option<PathBuf>,
}

struct SprNotification {
    event: SprEvent,
    run_dhcp_helper: bool,
}

impl SprNotifier {
    pub fn new(socket_path: impl Into<PathBuf>, dhcp_helper: Option<PathBuf>) -> SprNotifier {
        let path = socket_path.into();
        let worker_dhcp_helper = dhcp_helper.clone();
        let (tx, rx) = mpsc::sync_channel::<SprNotification>(64);
        let _ = std::thread::Builder::new()
            .name("rustap-spr-events".to_string())
            .spawn(move || {
                while let Ok(notification) = rx.recv() {
                    let SprNotification {
                        event,
                        run_dhcp_helper: should_run_dhcp_helper,
                    } = notification;
                    if should_run_dhcp_helper {
                        if let Some(helper) = worker_dhcp_helper.as_ref() {
                            match run_dhcp_helper(helper, &event) {
                                Ok(true) if std::env::var_os("RUSTAP_SPR_DEBUG").is_some() => {
                                    eprintln!("SPR DHCP/XDP helper completed")
                                }
                                Ok(_) => {}
                                Err(e) => eprintln!("SPR DHCP/XDP helper failed: {e}"),
                            }
                        }
                    }
                    match put_event_with_retry(&path, &event) {
                        Ok(()) if std::env::var_os("RUSTAP_SPR_DEBUG").is_some() => {
                            eprintln!("SPR event delivered: {}", event.request().0)
                        }
                        Ok(()) => {}
                        Err(e) => eprintln!("SPR event delivery failed: {e}"),
                    }
                }
            });
        SprNotifier { tx, dhcp_helper }
    }

    /// Prepare a newly-created AP_VLAN after publishing the station peer and
    /// submitting its Authentication response. This is synchronous so the
    /// following station-state transition cannot race ahead of bridge/XDP
    /// setup.
    pub fn prepare_data_path(&self, iface: &str, mac: &str) -> io::Result<bool> {
        let Some(helper) = self.dhcp_helper.as_ref() else {
            return Ok(false);
        };
        run_dhcp_helper(
            helper,
            &SprEvent::Connected {
                iface: iface.to_string(),
                mac: mac.to_string(),
            },
        )
    }

    fn enqueue(&self, event: SprEvent, run_dhcp_helper: bool) {
        match self.tx.try_send(SprNotification {
            event,
            run_dhcp_helper,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => eprintln!("SPR event queue full; dropping event"),
            Err(TrySendError::Disconnected(_)) => {
                eprintln!("SPR event worker stopped; dropping event")
            }
        }
    }

    /// Queue without blocking the AP's management/EAPOL event loop.
    pub fn notify(&self, event: SprEvent) {
        self.enqueue(event, true);
    }

    /// Publish an event whose helper action was completed before association.
    pub fn notify_without_dhcp_helper(&self, event: SprEvent) {
        self.enqueue(event, false);
    }
}

/// Reproduce wifid's action-script call to `spr_dhcp_helper`. The helper
/// owns stale nft-map cleanup, generic-XDP attachment, and the new map element.
/// Normal events use the background worker; association-time AP_VLAN
/// preparation invokes this synchronously to retain bridge-add ordering
/// relative to station publication.
/// A helper failure is reported but does not suppress the API event, matching
/// action.sh (which continues to curl without `set -e`).
fn run_dhcp_helper(helper: &PathBuf, event: &SprEvent) -> io::Result<bool> {
    let Some((action, iface, mac)) = event.dhcp_helper_args() else {
        return Ok(false);
    };
    let output = Command::new(helper)
        .arg(action)
        .arg(iface)
        .arg(mac)
        .output()?;
    if output.status.success() {
        return Ok(true);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(io::Error::other(format!(
        "{} {action} {iface} {mac} exited {}: {}",
        helper.display(),
        output.status,
        stderr.trim()
    )))
}

fn put_event_with_retry(socket_path: &PathBuf, event: &SprEvent) -> io::Result<()> {
    const RETRY_DELAYS: [Duration; 2] = [Duration::from_millis(100), Duration::from_millis(250)];
    let mut last_error = None;
    for attempt in 0..=RETRY_DELAYS.len() {
        match put_event(socket_path, event) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
        if let Some(delay) = RETRY_DELAYS.get(attempt) {
            std::thread::sleep(*delay);
        }
    }
    Err(last_error.expect("at least one SPR delivery attempt"))
}

fn put_event(socket_path: &PathBuf, event: &SprEvent) -> io::Result<()> {
    let (endpoint, value) = event.request();
    let body = serde_json::to_vec(&value).map_err(io::Error::other)?;
    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    write!(
        stream,
        "PUT {endpoint} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    stream.flush()?;

    let mut response = [0u8; 512];
    let n = stream.read(&mut response)?;
    let status = String::from_utf8_lossy(&response[..n]);
    let first_line = status.lines().next().unwrap_or("");
    if !(first_line.starts_with("HTTP/1.1 2") || first_line.starts_with("HTTP/1.0 2")) {
        let detail: String = status
            .split_once("\r\n\r\n")
            .map(|(_, body)| body.trim())
            .unwrap_or("")
            .chars()
            .take(256)
            .collect();
        return Err(io::Error::other(format!(
            "{endpoint} returned {first_line:?}: {detail}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn sends_spr_compatible_http_and_json_without_exec() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "barely-ap-spr-{}-{unique}.sock",
            std::process::id()
        ));
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            loop {
                let mut chunk = [0u8; 1024];
                let n = stream.read(&mut chunk).unwrap();
                assert!(n > 0, "client closed before sending the complete request");
                request.extend_from_slice(&chunk[..n]);
                let Some(header_end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_len = headers
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("Content-Length: ")
                            .and_then(|value| value.parse::<usize>().ok())
                    })
                    .expect("Content-Length header");
                if request.len() >= header_end + 4 + content_len {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .unwrap();
            String::from_utf8(request).unwrap()
        });

        put_event(
            &path,
            &SprEvent::Connected {
                iface: "wlan3.4096".to_string(),
                mac: "02:00:00:00:00:01".to_string(),
            },
        )
        .unwrap();
        let request = server.join().unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(
            request.starts_with("PUT /reportPSKAuthSuccess HTTP/1.1\r\n"),
            "request was {request:?}"
        );
        assert!(request.contains("\"Iface\":\"wlan3.4096\""));
        assert!(request.contains("\"Event\":\"AP-STA-CONNECTED\""));
        assert!(request.contains("\"Mac\":\"02:00:00:00:00:01\""));
    }

    #[test]
    fn retries_mesh_delivery_failures_and_preserves_error_details() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "barely-ap-spr-retry-{}-{unique}.sock",
            std::process::id()
        ));
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            for status in [
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 15\r\nConnection: close\r\n\r\nmesh nft failed"
                    .as_slice(),
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 15\r\nConnection: close\r\n\r\nmesh nft failed"
                    .as_slice(),
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".as_slice(),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 2048];
                let _ = stream.read(&mut request).unwrap();
                stream.write_all(status).unwrap();
            }
        });

        put_event_with_retry(
            &path,
            &SprEvent::Connected {
                iface: "wlan3.4096".to_string(),
                mac: "02:00:00:00:00:01".to_string(),
            },
        )
        .unwrap();
        server.join().unwrap();
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn reports_api_error_body() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "barely-ap-spr-error-{}-{unique}.sock",
            std::process::id()
        ));
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 14\r\nConnection: close\r\n\r\nnft add failed",
                )
                .unwrap();
        });

        let error = put_event(
            &path,
            &SprEvent::Connected {
                iface: "wlan3.4096".to_string(),
                mac: "02:00:00:00:00:01".to_string(),
            },
        )
        .unwrap_err();
        server.join().unwrap();
        let _ = std::fs::remove_file(path);
        assert!(error.to_string().contains("nft add failed"), "{error}");
    }

    #[test]
    fn auth_failure_values_match_spr_validation() {
        let wpa = SprEvent::auth_failure(
            "wlan3".to_string(),
            "02:00:00:00:00:01".to_string(),
            FailureKind::FourWayMic,
        )
        .unwrap();
        let (_, body) = wpa.request();
        assert_eq!(body["Type"], "wpa");
        assert_eq!(body["Reason"], "mismatch");

        let sae = SprEvent::auth_failure(
            "wlan3".to_string(),
            "02:00:00:00:00:01".to_string(),
            FailureKind::Sae,
        )
        .unwrap();
        let (_, body) = sae.request();
        assert_eq!(body["Type"], "sae");
        assert_eq!(body["Reason"], "mismatch");
    }

    #[test]
    fn dhcp_helper_gets_action_vlan_iface_and_mac() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir();
        let helper = dir.join(format!("barely-ap-helper-{unique}.sh"));
        let log = dir.join(format!("barely-ap-helper-{unique}.log"));
        std::fs::write(
            &helper,
            format!("#!/bin/sh\nprintf '%s\\n' \"$@\" >> {:?}\n", log),
        )
        .unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();

        let mac = "02:00:00:00:00:01".to_string();
        assert!(run_dhcp_helper(
            &helper,
            &SprEvent::Connected {
                iface: "wlan3.4096".to_string(),
                mac: mac.clone(),
            },
        )
        .unwrap());
        assert!(run_dhcp_helper(
            &helper,
            &SprEvent::Disconnected {
                iface: "wlan3.4096".to_string(),
                mac,
            },
        )
        .unwrap());
        assert!(!run_dhcp_helper(
            &helper,
            &SprEvent::AuthFailure {
                iface: "wlan3".to_string(),
                mac: "02:00:00:00:00:01".to_string(),
                auth_type: "sae",
                reason: "mismatch",
            },
        )
        .unwrap());

        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            "add\nwlan3.4096\n02:00:00:00:00:01\nremove\nwlan3.4096\n02:00:00:00:00:01\n"
        );
        let _ = std::fs::remove_file(helper);
        let _ = std::fs::remove_file(log);
    }

    #[test]
    fn prepared_data_path_runs_helper_synchronously() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir();
        let helper = dir.join(format!("barely-ap-prepared-helper-{unique}.sh"));
        let log = dir.join(format!("barely-ap-prepared-helper-{unique}.log"));
        std::fs::write(
            &helper,
            format!("#!/bin/sh\nprintf '%s\\n' \"$@\" >> {:?}\n", log),
        )
        .unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();

        let notifier = SprNotifier::new(
            dir.join(format!("barely-ap-unused-{unique}.sock")),
            Some(helper.clone()),
        );
        assert!(notifier
            .prepare_data_path("wlan3.4096", "02:00:00:00:00:01")
            .unwrap());

        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            "add\nwlan3.4096\n02:00:00:00:00:01\n"
        );
        let _ = std::fs::remove_file(helper);
        let _ = std::fs::remove_file(log);
    }
}
