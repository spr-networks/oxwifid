//! Print the WPA2 PMK (== PSK) for an SSID/passphrase, for cross-checking
//! against wpa_supplicant's `wpa_passphrase`.
//!
//! Usage: cargo run --example show_pmk -- <ssid> <passphrase>

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: show_pmk <ssid> <passphrase>");
        std::process::exit(2);
    }
    let pmk = barely_ap::crypto::pbkdf2_pmk(&args[2], &args[1]);
    let hex: String = pmk.iter().map(|b| format!("{b:02x}")).collect();
    println!("{hex}");
}
