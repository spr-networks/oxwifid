//! Print the WPA2 PMK (== PSK) for a configured SSID/passphrase, for cross-checking
//! against wpa_supplicant's `wpa_passphrase`.
//!
//! Usage: cargo run --example show_pmk -- <config.json>

use zeroize::Zeroize;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: show_pmk <config.json>");
        std::process::exit(2);
    }
    let mut text = std::fs::read_to_string(&args[1]).unwrap_or_else(|e| {
        eprintln!("show_pmk: cannot read {:?}: {e}", args[1]);
        std::process::exit(1);
    });
    let cfg = match barely_ap::config::Config::from_json(&text) {
        Ok(cfg) => cfg,
        Err(e) => {
            text.zeroize();
            eprintln!("show_pmk: {:?}: {e}", args[1]);
            std::process::exit(1);
        }
    };
    text.zeroize();
    if cfg.passphrase.is_empty() {
        eprintln!("show_pmk: config must contain passphrase (psk_file is ambiguous)");
        std::process::exit(1);
    }
    let mut pmk = barely_ap::crypto::pbkdf2_pmk(&cfg.passphrase, &cfg.ssid);
    let mut hex: String = pmk.iter().map(|b| format!("{b:02x}")).collect();
    println!("{hex}");
    hex.zeroize();
    pmk.zeroize();
}
