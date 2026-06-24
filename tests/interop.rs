//! Live stdio-bridge interop, run in both role directions over real pipes:
//! Python-client -> Rust-AP, Rust-client -> Rust-AP, and Rust-client ->
//! Python-AP (the reverse). Each asserts a full WPA2/CCMP handshake plus an
//! ICMP ping round-trip.
//!
//! Skips (passes) gracefully if python3 or scapy is unavailable.

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn python_with_scapy() -> Option<String> {
    // These tests bridge against the *reference* Python implementation under
    // ../barely-ap/src (ap.py, ccmp.py, client.py). Skip gracefully if that
    // reference tree isn't checked out next to this repo, or if scapy is
    // missing — otherwise the tests would fail on a Python ImportError that has
    // nothing to do with the Rust code under test.
    if !repo_root().join("barely-ap/src/ap.py").exists() {
        eprintln!("SKIP: reference Python tree (barely-ap/src) not present");
        return None;
    }
    for py in ["python3", "python"] {
        let ok = Command::new(py)
            .args(["-c", "import scapy"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return Some(py.to_string());
        }
    }
    None
}

/// Run the generic stdio bridge between two command lines, requiring all the
/// given marker strings to appear. Returns true on BRIDGE_OK.
fn run_bridge(py: &str, a_cmd: &str, b_cmd: &str, needs: &[&str], env: &[(&str, &str)]) -> bool {
    let bridge = repo_root().join("tools").join("bridge.py");
    let mut cmd = Command::new(py);
    cmd.arg(&bridge)
        .arg("--a")
        .arg(a_cmd)
        .arg("--b")
        .arg(b_cmd)
        .arg("--timeout")
        .arg("30")
        .current_dir(repo_root());
    for n in needs {
        cmd.arg("--need").arg(n);
    }
    for (k, v) in env {
        cmd.arg("--env").arg(format!("{k}={v}"));
    }
    let output = cmd.output().expect("run bridge");
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("--- bridge ---\n{stderr}\n--------------");
    stderr.contains("BRIDGE_OK")
}

const AP_BIN: &str = env!("CARGO_BIN_EXE_barely-ap");
const CLI_BIN: &str = env!("CARGO_BIN_EXE_barely-cli");

#[test]
fn python_client_to_rust_ap() {
    let Some(py) = python_with_scapy() else {
        eprintln!("SKIP: python3 + scapy unavailable");
        return;
    };
    let ap = format!("{AP_BIN} --mode stdio --mac 02:00:00:00:00:00 --ssid turtlenet --psk password1234");
    let cli = format!("{py} tools/run_client.py");
    assert!(
        run_bridge(&py, &ap, &cli, &["Fully Authenticated", "PING_REPLY_OK"], &[("BARELY_PING", "1"), ("AP_MAC", "02:00:00:00:00:00"), ("STA_MAC", "02:00:00:00:ab:cd")]),
        "python client should authenticate + ping through the Rust AP"
    );
}

#[test]
fn rust_client_to_rust_ap() {
    let Some(py) = python_with_scapy() else {
        eprintln!("SKIP: python3 + scapy unavailable");
        return;
    };
    let ap = format!("{AP_BIN} --mode stdio --mac 02:00:00:00:00:00 --ssid turtlenet --psk password1234");
    let cli = format!("{CLI_BIN} --ping --mac 02:00:00:00:ab:cd --gw-mac 02:00:00:00:00:00 --ssid turtlenet --psk password1234");
    assert!(
        run_bridge(&py, &ap, &cli, &["AUTHENTICATED", "PING_REPLY_OK"], &[]),
        "rust client should authenticate + ping through the rust AP"
    );
}

#[test]
fn wpa3_sae_rust_client_to_rust_ap() {
    let Some(py) = python_with_scapy() else {
        eprintln!("SKIP: python3 + scapy unavailable");
        return;
    };
    let ap = format!("{AP_BIN} --mode stdio --sae --mac 02:00:00:00:00:00 --ssid turtlenet --psk password1234");
    let cli = format!("{CLI_BIN} --ping --sae --mac 02:00:00:00:ab:cd --gw-mac 02:00:00:00:00:00 --ssid turtlenet --psk password1234");
    assert!(
        run_bridge(&py, &ap, &cli, &["AUTHENTICATED", "PING_REPLY_OK"], &[]),
        "WPA3-SAE: rust client should authenticate + ping through the rust AP"
    );
}

#[test]
fn wpa3_sae_hunting_and_pecking_rust_client_to_rust_ap() {
    let Some(py) = python_with_scapy() else {
        eprintln!("SKIP: python3 + scapy unavailable");
        return;
    };
    let ap = format!("{AP_BIN} --mode stdio --sae --mac 02:00:00:00:00:00 --ssid turtlenet --psk password1234");
    let cli = format!("{CLI_BIN} --ping --sae-hnp --mac 02:00:00:00:ab:cd --gw-mac 02:00:00:00:00:00 --ssid turtlenet --psk password1234");
    assert!(
        run_bridge(&py, &ap, &cli, &["AUTHENTICATED", "PING_REPLY_OK"], &[]),
        "WPA3-SAE (hunting-and-pecking): rust client should authenticate + ping through the rust AP"
    );
}

#[test]
fn python_sae_matches_ieee_j10() {
    let Some(py) = python_with_scapy() else {
        eprintln!("SKIP: python3 unavailable");
        return;
    };
    // The independent Python SAE self-checks against IEEE 802.11-2020 Annex J.10
    // (H2E PWE, hunting-and-pecking, commit, KCK/PMK/PMKID).
    let out = Command::new(&py)
        .arg("tools/wpa3_sae.py")
        .current_dir(repo_root())
        .output()
        .expect("run python sae self-test");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success() && stdout.contains("True"), "python SAE J.10 self-test failed: {stdout}");
}

/// WPA3 cross-validation: the independent Python SAE must interoperate with the
/// Rust AP/client in both roles, for both PWE methods.
#[test]
fn wpa3_python_client_to_rust_ap() {
    let Some(py) = python_with_scapy() else {
        eprintln!("SKIP: python3 + scapy unavailable");
        return;
    };
    let ap = format!("{AP_BIN} --mode stdio --sae --mac 02:00:00:00:00:00 --ssid turtlenet --psk password1234");
    let cli = format!("{py} tools/wpa3_client.py");
    let env = [("AP_MAC", "02:00:00:00:00:00"), ("STA_MAC", "02:00:00:00:ab:cd")];
    assert!(run_bridge(&py, &ap, &cli, &["AUTHENTICATED", "PING_REPLY_OK"], &env), "python H2E client -> rust AP");
    let mut env_hnp = env.to_vec();
    env_hnp.push(("SAE_HNP", "1"));
    assert!(run_bridge(&py, &ap, &cli, &["AUTHENTICATED", "PING_REPLY_OK"], &env_hnp), "python H&P client -> rust AP");
}

#[test]
fn wpa3_rust_client_to_python_ap() {
    let Some(py) = python_with_scapy() else {
        eprintln!("SKIP: python3 + scapy unavailable");
        return;
    };
    let ap = format!("{py} tools/wpa3_ap.py");
    let env = [("AP_MAC", "02:00:00:00:00:00")];
    let cli_h2e = format!("{CLI_BIN} --ping --sae --mac 02:00:00:00:ab:cd --gw-mac 02:00:00:00:00:00");
    assert!(run_bridge(&py, &ap, &cli_h2e, &["AUTHENTICATED", "PING_REPLY_OK"], &env), "rust H2E client -> python AP");
    let cli_hnp = format!("{CLI_BIN} --ping --sae-hnp --mac 02:00:00:00:ab:cd --gw-mac 02:00:00:00:00:00");
    assert!(run_bridge(&py, &ap, &cli_hnp, &["AUTHENTICATED", "PING_REPLY_OK"], &env), "rust H&P client -> python AP");
}

#[test]
fn rust_client_to_python_ap() {
    let Some(py) = python_with_scapy() else {
        eprintln!("SKIP: python3 + scapy unavailable");
        return;
    };
    let ap = format!("{py} tools/run_ap.py");
    let cli = format!("{CLI_BIN} --ping --mac 02:00:00:00:ab:cd --gw-mac 02:00:00:00:00:00 --ssid turtlenet --psk password1234");
    assert!(
        run_bridge(&py, &ap, &cli, &["AUTHENTICATED", "PING_REPLY_OK"], &[("AP_MAC", "02:00:00:00:00:00")]),
        "rust client should authenticate + ping through the reference Python AP"
    );
}
