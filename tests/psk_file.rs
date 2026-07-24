//! reference AP-style `wpa_psk_file` candidate selection: per-MAC entries tried
//! before wildcard onboarding entries, verified against the
//! 4-way handshake's message-2 MIC. Deterministic in-process handshakes (no
//! hwsim) so the credential-matching logic is tested independent of the medium.

use barely_ap::ap::Ap;
use barely_ap::client::Client;
use barely_ap::fakenet::FakeNet;
use barely_ap::util::mac_to_bytes;

fn ap_step(ap: &mut Ap, net: &mut FakeNet, frame: &[u8]) -> Vec<Vec<u8>> {
    let out = ap.handle_incoming(frame);
    let mut frames = out.frames;
    for eth in &out.to_network {
        for reply in net.input(eth) {
            frames.extend(ap.deliver_to_station(&reply));
        }
    }
    frames
}

/// Drive the beacon→auth→assoc→4-way exchange; return the station's final
/// `connected` level (4 == fully authenticated).
fn try_connect(ap: &mut Ap, net: &mut FakeNet, sta: &mut Client) -> u8 {
    let mut to_client = vec![ap.beacon_frame()];
    let mut to_ap: Vec<Vec<u8>> = Vec::new();
    let mut rounds = 0;
    while sta.connected < 4 && rounds < 50 {
        rounds += 1;
        let mut nxt = Vec::new();
        for f in to_client.drain(..) {
            nxt.extend(sta.handle_incoming(&f).frames);
        }
        to_ap.extend(nxt);
        let mut nxt2 = Vec::new();
        for f in to_ap.drain(..) {
            nxt2.extend(ap_step(ap, net, &f));
        }
        to_client.extend(nxt2);
    }
    sta.connected
}

fn ap_with_file(entries: &[(Option<[u8; 6]>, &str)]) -> (Ap, FakeNet) {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    // The AP's own single passphrase is deliberately WRONG for these clients —
    // only the psk_file entries can authenticate them.
    let mut ap = Ap::new("pnet", "the-default-psk", ap_mac, 1);
    let owned: Vec<(Option<[u8; 6]>, String)> =
        entries.iter().map(|(m, p)| (*m, p.to_string())).collect();
    ap.set_psk_file(&owned);
    (ap, FakeNet::new(ap_mac, [10, 10, 10, 1]))
}

fn sae_ap_with_file(entries: &[(Option<[u8; 6]>, &str)]) -> (Ap, FakeNet) {
    let (mut ap, net) = ap_with_file(entries);
    ap.enable_sae();
    (ap, net)
}

#[test]
fn wildcard_onboarding_authenticates() {
    // Only a wildcard entry: any MAC using that password gets on.
    let (mut ap, mut net) = ap_with_file(&[(None, "onboardpass")]);
    let mut sta = Client::new("pnet", "onboardpass", mac_to_bytes("02:00:00:00:00:aa"));
    assert_eq!(
        try_connect(&mut ap, &mut net, &mut sta),
        4,
        "wildcard onboarding failed"
    );
}

#[test]
fn mac_specific_password_authenticates() {
    let sta_mac = mac_to_bytes("02:00:00:00:00:bb");
    let (mut ap, mut net) = ap_with_file(&[(None, "onboardpass"), (Some(sta_mac), "devicepass")]);
    let mut sta = Client::new("pnet", "devicepass", sta_mac);
    assert_eq!(
        try_connect(&mut ap, &mut net, &mut sta),
        4,
        "mac-specific password failed"
    );
}

#[test]
fn wildcard_fallback_when_mac_entry_exists() {
    // The station HAS a MAC-specific entry but connects with the wildcard
    // password: the candidate loop must fall past the MAC entry to the wildcard.
    let sta_mac = mac_to_bytes("02:00:00:00:00:cc");
    let (mut ap, mut net) = ap_with_file(&[(None, "onboardpass"), (Some(sta_mac), "devicepass")]);
    let mut sta = Client::new("pnet", "onboardpass", sta_mac);
    assert_eq!(
        try_connect(&mut ap, &mut net, &mut sta),
        4,
        "wildcard fallback failed"
    );
}

#[test]
fn wrong_password_is_rejected() {
    let sta_mac = mac_to_bytes("02:00:00:00:00:dd");
    let (mut ap, mut net) = ap_with_file(&[(None, "onboardpass"), (Some(sta_mac), "devicepass")]);
    let mut sta = Client::new("pnet", "totally-wrong", sta_mac);
    assert_ne!(
        try_connect(&mut ap, &mut net, &mut sta),
        4,
        "wrong password wrongly accepted"
    );
}

#[test]
fn configured_bss_password_is_not_a_fallback_when_file_is_authoritative() {
    let sta_mac = mac_to_bytes("02:00:00:00:00:df");
    let (mut ap, mut net) = ap_with_file(&[(None, "onboardpass")]);
    let mut sta = Client::new("pnet", "the-default-psk", sta_mac);
    assert_ne!(
        try_connect(&mut ap, &mut net, &mut sta),
        4,
        "JSON/default password bypassed the authoritative credential file"
    );
}

#[test]
fn empty_authoritative_file_fails_closed() {
    let sta_mac = mac_to_bytes("02:00:00:00:00:e0");
    let (mut ap, mut net) = ap_with_file(&[]);
    let mut sta = Client::new("pnet", "the-default-psk", sta_mac);
    assert_ne!(
        try_connect(&mut ap, &mut net, &mut sta),
        4,
        "empty credential file fell back to the configured password"
    );
}

#[test]
fn re_auth_with_different_password_after_pin() {
    // Onboard on the wildcard (pins that PMK), then the SAME station re-auths
    // with its now-assigned device password — the stale wildcard pin must be
    // cleared so the MAC-specific candidate matches.
    let sta_mac = mac_to_bytes("02:00:00:00:00:ee");
    let (mut ap, mut net) = ap_with_file(&[(None, "onboardpass"), (Some(sta_mac), "devicepass")]);
    let mut sta1 = Client::new("pnet", "onboardpass", sta_mac);
    assert_eq!(
        try_connect(&mut ap, &mut net, &mut sta1),
        4,
        "onboarding failed"
    );
    // A real reconnect is seconds/minutes later; clear the 250ms retransmit
    // backoff so this instant same-MAC re-auth is treated as a genuine session.
    ap.test_clear_auth_backoff();
    // Same MAC comes back with the device password.
    let mut sta2 = Client::new("pnet", "devicepass", sta_mac);
    assert_eq!(
        try_connect(&mut ap, &mut net, &mut sta2),
        4,
        "re-auth with device pw failed"
    );
}

#[test]
fn sae_uses_mac_specific_credential() {
    let sta_mac = mac_to_bytes("02:00:00:00:00:f1");
    let (mut ap, mut net) = sae_ap_with_file(&[(Some(sta_mac), "devicepass")]);
    let mut sta = Client::new("pnet", "devicepass", sta_mac);
    sta.enable_sae();
    assert_eq!(try_connect(&mut ap, &mut net, &mut sta), 4);
}

#[test]
fn sae_rejects_configured_fallback_for_unlisted_station() {
    let allowed = mac_to_bytes("02:00:00:00:00:f1");
    let (mut ap, mut net) = sae_ap_with_file(&[(Some(allowed), "devicepass")]);
    let mut sta = Client::new("pnet", "the-default-psk", mac_to_bytes("02:00:00:00:00:f2"));
    sta.enable_sae();
    assert_ne!(
        try_connect(&mut ap, &mut net, &mut sta),
        4,
        "SAE bypassed the authoritative per-device credential file"
    );
}
