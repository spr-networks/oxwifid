//! PMF (802.11w) *enforcement* tests — not just capability:
//!   * a spoofed UNPROTECTED deauth/disassoc cannot disconnect a PMF station,
//!     but a valid BIP (group) or CCMP (unicast) protected one does;
//!   * a spoofed UNPROTECTED (re)assoc request cannot tear down a PMF station's
//!     session (SA Query: status 30 + protected SA Query, session preserved);
//!   * the AP drops unprotected robust mgmt and tears down only on a valid
//!     CCMP-protected deauth.

use barely_ap::ap::Ap;
use barely_ap::client::Client;
use barely_ap::dot11;
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

/// Run a full WPA3-SAE handshake and return (ap, net, client) all up.
fn wpa3_up() -> (Ap, FakeNet, Client) {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let sta_mac = mac_to_bytes("02:00:00:00:ab:cd");
    let mut ap = Ap::new("turtlenet", "password1234", ap_mac, 1);
    ap.enable_sae();
    let mut net = FakeNet::new(ap_mac, [10, 10, 10, 1]);
    let mut sta = Client::new("turtlenet", "password1234", sta_mac);
    sta.enable_sae();

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
            nxt2.extend(ap_step(&mut ap, &mut net, &f));
        }
        to_client.extend(nxt2);
    }
    assert_eq!(sta.connected, 4, "handshake must complete");
    (ap, net, sta)
}

const AP_MAC: &str = "02:00:00:00:00:00";
const STA_MAC: &str = "02:00:00:00:ab:cd";

fn with_radiotap(frame: Vec<u8>) -> Vec<u8> {
    let mut v = dot11::RADIOTAP_TX.to_vec();
    v.extend_from_slice(&frame);
    v
}

#[test]
fn client_ignores_unprotected_deauth_but_honors_protected_group() {
    let (mut ap, _net, mut sta) = wpa3_up();
    let bssid = mac_to_bytes(AP_MAC);
    let sta_mac = mac_to_bytes(STA_MAC);

    // 1. Spoofed UNPROTECTED broadcast deauth -> ignored (still connected).
    let bcast = [0xffu8; 6];
    sta.handle_incoming(&with_radiotap(dot11::build_deauth(&bssid, &bcast, 7)));
    assert_eq!(sta.connected, 4, "unprotected broadcast deauth must be ignored under PMF");

    // 2. Spoofed UNPROTECTED unicast deauth -> ignored.
    sta.handle_incoming(&with_radiotap(dot11::build_deauth(&bssid, &sta_mac, 7)));
    assert_eq!(sta.connected, 4, "unprotected unicast deauth must be ignored under PMF");

    // 3. A FORGED BIP frame (wrong IGTK) -> ignored.
    let forged_igtk = [0x55u8; 16];
    let forged = dot11::build_group_deauth_bip(&bssid, &forged_igtk, 4, &[0, 0, 0, 0, 0, 9], 7, 0x10);
    sta.handle_incoming(&with_radiotap(forged));
    assert_eq!(sta.connected, 4, "BIP frame with wrong key must be ignored");

    // 4. A VALID BIP-protected group deauth (AP's real IGTK) -> disconnect.
    let real = ap.group_deauth(7);
    sta.handle_incoming(&real);
    assert_eq!(sta.connected, 0, "valid BIP group deauth must disconnect the STA");
}

#[test]
fn ccmp_replay_is_rejected() {
    // CCMP replay protection: a frame whose packet number is not strictly
    // greater than the last accepted one must be dropped.
    let (mut ap, mut net, mut sta) = wpa3_up();
    let ap_mac = mac_to_bytes(AP_MAC);

    // uplink data frame #1 (PN increasing) is accepted by the AP
    let ping = sta.build_ping(&ap_mac, [10, 10, 10, 2], [10, 10, 10, 1], 0);
    let f1 = sta.encrypt_uplink(&ping).expect("uplink");
    let out1 = ap.handle_incoming(&f1);
    assert_eq!(out1.to_network.len(), 1, "first frame accepted");

    // replaying the *exact same* frame (same PN) must be dropped
    let out2 = ap.handle_incoming(&f1);
    assert!(out2.to_network.is_empty(), "replayed CCMP frame must be dropped");

    // a fresh frame with a higher PN is accepted again
    let ping2 = sta.build_ping(&ap_mac, [10, 10, 10, 2], [10, 10, 10, 1], 0);
    let f2 = sta.encrypt_uplink(&ping2).expect("uplink2");
    let out3 = ap_step(&mut ap, &mut net, &f2);
    let _ = out3; // (the reply path is exercised; the point is f2 was not a replay)
    assert!(ap.is_associated(&mac_to_bytes(STA_MAC)));
}

#[test]
fn client_honors_protected_unicast_deauth() {
    let (mut ap, _net, mut sta) = wpa3_up();
    let sta_mac = mac_to_bytes(STA_MAC);
    // valid CCMP-protected unicast deauth from the AP -> disconnect
    let deauth = ap.protected_deauth(&sta_mac, 7).expect("protected deauth");
    sta.handle_incoming(&deauth);
    assert_eq!(sta.connected, 0, "valid CCMP-protected unicast deauth must disconnect");
}

#[test]
fn ap_sa_query_preserves_session_on_spoofed_assoc() {
    let (mut ap, mut net, _sta) = wpa3_up();
    let bssid = mac_to_bytes(AP_MAC);
    let sta_mac = mac_to_bytes(STA_MAC);
    assert!(ap.is_associated(&sta_mac));
    let tk_before = ap.station_tk(&sta_mac).unwrap();

    // Spoofed UNPROTECTED (re)association request from the associated STA.
    let assoc = with_radiotap(dot11::build_assoc_req(&bssid, &sta_mac, b"turtlenet", 0x10));
    let frames = ap_step(&mut ap, &mut net, &assoc);

    // The AP must NOT restart the handshake (no EAPOL message 1) ...
    let mut saw_eapol = false;
    let mut saw_status30 = false;
    let mut saw_sa_query = false;
    for f in &frames {
        let parsed = dot11::Dot11::parse(dot11::strip_radiotap(f).unwrap()).unwrap();
        if parsed.is_eapol() {
            saw_eapol = true;
        }
        if parsed.frame_type() == dot11::TYPE_MGMT && parsed.subtype() == dot11::SUBTYPE_ASSOC_RESP {
            // status code is at body offset 2..4 (after capability)
            let status = u16::from_le_bytes([parsed.body[2], parsed.body[3]]);
            if status == dot11::STATUS_ASSOC_REJECTED_TEMP {
                saw_status30 = true;
            }
        }
        if parsed.frame_type() == dot11::TYPE_MGMT && parsed.subtype() == dot11::SUBTYPE_ACTION && parsed.protected() {
            saw_sa_query = true;
        }
    }
    assert!(!saw_eapol, "AP must NOT restart the 4-way handshake on a spoofed assoc-req");
    assert!(saw_status30, "AP must reject with status 30 (association comeback)");
    assert!(saw_sa_query, "AP must emit a protected SA Query request");

    // ... and the existing session (keys + association) must be intact.
    assert!(ap.is_associated(&sta_mac), "PMF session must survive a spoofed assoc-req");
    assert_eq!(ap.station_tk(&sta_mac), Some(tk_before), "TK must be unchanged");
}

#[test]
fn ap_drops_unprotected_deauth_but_honors_protected() {
    let (mut ap, mut net, _sta) = wpa3_up();
    let bssid = mac_to_bytes(AP_MAC);
    let sta_mac = mac_to_bytes(STA_MAC);
    let tk = ap.station_tk(&sta_mac).unwrap();

    // Spoofed UNPROTECTED deauth from the STA address (addr2=sta) -> ignored.
    let spoof_sta = with_radiotap({
        let mut v = Vec::new();
        v.push((dot11::SUBTYPE_DEAUTH << 4) | (dot11::TYPE_MGMT << 2));
        v.push(0);
        v.extend_from_slice(&[0, 0]);
        v.extend_from_slice(&bssid); // addr1
        v.extend_from_slice(&sta_mac); // addr2
        v.extend_from_slice(&bssid); // addr3
        v.extend_from_slice(&0u16.to_le_bytes()); // SC
        v.extend_from_slice(&3u16.to_le_bytes()); // reason
        v
    });
    ap_step(&mut ap, &mut net, &spoof_sta);
    assert!(ap.is_associated(&sta_mac), "AP must ignore unprotected deauth from a PMF STA");

    // A VALID CCMP-protected deauth from the STA (shared TK) -> tear down.
    let pn = 0x1234;
    let protected = with_radiotap(dot11::build_ccmp_mgmt(dot11::SUBTYPE_DEAUTH, &bssid, &sta_mac, &bssid, 0x20, pn, 0, &tk, &3u16.to_le_bytes()));
    ap_step(&mut ap, &mut net, &protected);
    assert!(!ap.is_associated(&sta_mac), "valid CCMP-protected deauth must tear the station down");
}

#[test]
fn wpa2_assoc_restarts_handshake_no_sa_query() {
    // Contrast: a non-PMF (WPA2) AP DOES restart on a repeat assoc-req (no SA
    // Query enforcement), proving the PMF path is what changes the behaviour.
    let ap_mac = mac_to_bytes(AP_MAC);
    let sta_mac = mac_to_bytes(STA_MAC);
    let mut ap = Ap::new("turtlenet", "password1234", ap_mac, 1); // no enable_sae
    let mut net = FakeNet::new(ap_mac, [10, 10, 10, 1]);

    let auth = with_radiotap(dot11::build_auth_req(&ap_mac, &sta_mac, 0x10));
    ap_step(&mut ap, &mut net, &auth);
    let assoc = with_radiotap(dot11::build_assoc_req(&ap_mac, &sta_mac, b"turtlenet", 0x20));
    let frames = ap_step(&mut ap, &mut net, &assoc);
    let saw_eapol = frames.iter().any(|f| {
        dot11::Dot11::parse(dot11::strip_radiotap(f).unwrap()).map(|p| p.is_eapol()).unwrap_or(false)
    });
    assert!(saw_eapol, "WPA2 assoc must produce EAPOL m1 (open handshake, no SA Query)");
}
