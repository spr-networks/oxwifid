//! In-process WPA3-SAE (H2E) end-to-end: drive the Rust AP and Rust client
//! state machines against each other through the full SAE exchange, the 4-way
//! handshake (using the SAE PMK), and a CCMP ping.

use barely_ap::ap::Ap;
use barely_ap::client::Client;
use barely_ap::fakenet::FakeNet;
use barely_ap::util::mac_to_bytes;

/// Run the AP side for one inbound frame, including the fake-network round-trip.
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

#[test]
fn wpa3_sae_h2e_full_handshake_and_ping() {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let sta_mac = mac_to_bytes("02:00:00:00:ab:cd");

    let mut ap = Ap::new("turtlenet", "password1234", ap_mac, 1);
    ap.enable_sae();
    let mut net = FakeNet::new(ap_mac, [10, 10, 10, 1]);

    let mut sta = Client::new("turtlenet", "password1234", sta_mac);
    sta.enable_sae();

    // Kick off with a beacon; then shuttle frames until the STA is fully up.
    // Queue items are (to_ap: bool, frame).
    let mut to_client: Vec<Vec<u8>> = vec![ap.beacon_frame()];
    let mut to_ap: Vec<Vec<u8>> = Vec::new();

    let mut rounds = 0;
    while sta.connected < 4 && rounds < 50 {
        rounds += 1;
        // deliver everything queued for the client
        let mut next_to_ap = Vec::new();
        for f in to_client.drain(..) {
            let out = sta.handle_incoming(&f);
            next_to_ap.extend(out.frames);
        }
        to_ap.extend(next_to_ap);

        // deliver everything queued for the AP
        let mut next_to_client = Vec::new();
        for f in to_ap.drain(..) {
            next_to_client.extend(ap_step(&mut ap, &mut net, &f));
        }
        to_client.extend(next_to_client);
    }

    assert!(sta.connected >= 4, "STA must reach full authentication via SAE (rounds={rounds})");
    assert!(ap.is_associated(&sta_mac), "AP must consider the SAE station associated");

    // Now exchange a ping over the SAE-keyed CCMP link.
    let ping = sta.build_ping(&ap_mac, [10, 10, 10, 2], [10, 10, 10, 1], 0);
    let ping_frame = sta.encrypt_uplink(&ping).expect("uplink encrypts");
    let replies = ap_step(&mut ap, &mut net, &ping_frame);
    assert!(!replies.is_empty(), "AP should answer the ping");

    let mut got_reply = false;
    for f in replies {
        let out = sta.handle_incoming(&f);
        for eth in out.to_network {
            // ICMP echo reply: ethertype IPv4, proto ICMP, type 0
            if eth.len() >= 14 + 20 + 8 && eth[12] == 0x08 && eth[13] == 0x00 {
                let ihl = (eth[14] & 0x0f) as usize * 4;
                if eth[14 + 9] == 1 && eth[14 + ihl] == 0 {
                    got_reply = true;
                }
            }
        }
    }
    assert!(got_reply, "STA should decrypt the ICMP echo reply over the SAE-keyed link");
}

fn run_sae(mut sta: Client) -> (Ap, FakeNet, Client) {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let mut ap = Ap::new("turtlenet", "password1234", ap_mac, 1);
    ap.enable_sae();
    let mut net = FakeNet::new(ap_mac, [10, 10, 10, 1]);

    let mut to_client: Vec<Vec<u8>> = vec![ap.beacon_frame()];
    let mut to_ap: Vec<Vec<u8>> = Vec::new();
    let mut rounds = 0;
    while sta.connected < 4 && rounds < 50 {
        rounds += 1;
        let mut next_to_ap = Vec::new();
        for f in to_client.drain(..) {
            next_to_ap.extend(sta.handle_incoming(&f).frames);
        }
        to_ap.extend(next_to_ap);
        let mut next_to_client = Vec::new();
        for f in to_ap.drain(..) {
            next_to_client.extend(ap_step(&mut ap, &mut net, &f));
        }
        to_client.extend(next_to_client);
    }
    (ap, net, sta)
}

#[test]
fn wpa3_pmf_igtk_and_bip_protection() {
    // After a WPA3-SAE handshake the STA must have installed the IGTK delivered
    // in message 3, and must accept a BIP-protected group deauth from the AP
    // (and reject a tampered one).
    let mut sta = Client::new("turtlenet", "password1234", mac_to_bytes("02:00:00:00:ab:cd"));
    sta.enable_sae();
    let (mut ap, _net, sta) = run_sae(sta);
    assert!(sta.connected >= 4, "SAE must complete");

    assert_eq!(sta.igtk(), Some(ap.igtk()), "STA must install the AP's IGTK via PMF");

    let deauth = ap.group_deauth(3);
    assert!(sta.verify_group_mgmt(&deauth), "STA must validate the BIP-protected deauth");

    // tamper with the frame body -> verification must fail
    let mut tampered = deauth.clone();
    let n = tampered.len();
    tampered[n - 20] ^= 0xff;
    assert!(!sta.verify_group_mgmt(&tampered), "tampered group mgmt must fail BIP");
}

#[test]
fn wpa3_sae_hunting_and_pecking_handshake() {
    // Same flow but with the legacy hunting-and-pecking PWE (commit status 0).
    let mut sta = Client::new("turtlenet", "password1234", mac_to_bytes("02:00:00:00:ab:cd"));
    sta.enable_sae();
    sta.use_hunting_pecking();
    let (ap, _net, sta) = run_sae(sta);
    assert!(sta.connected >= 4, "hunting-and-pecking SAE must complete");
    assert!(ap.is_associated(&mac_to_bytes("02:00:00:00:ab:cd")));
}

/// Drive a client (WPA2 or WPA3) against a given AP to full association.
fn drive(ap: &mut Ap, net: &mut FakeNet, sta: &mut Client) {
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
}

#[test]
fn idle_station_is_pruned_with_protected_deauth() {
    let sta_mac = mac_to_bytes("02:00:00:00:ab:cd");
    let mut sta = Client::new("turtlenet", "password1234", sta_mac);
    sta.enable_sae();
    let (mut ap, _net, mut sta) = run_sae(sta);
    assert!(ap.is_associated(&sta_mac));

    // Let the station go idle, then prune with a small max-idle.
    std::thread::sleep(std::time::Duration::from_millis(15));
    let frames = ap.prune_idle(std::time::Duration::from_millis(5));
    assert_eq!(frames.len(), 1, "idle PMF station must be deauthed");
    assert!(!ap.is_associated(&sta_mac), "idle station must be removed");

    // The deauth is CCMP-protected (PMF), so the STA accepts it and disconnects.
    sta.handle_incoming(&frames[0]);
    assert_eq!(sta.connected, 0, "STA honours the protected inactivity deauth");
}

#[test]
fn pmksa_caching_fast_reconnect_skips_sae() {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let sta_mac = mac_to_bytes("02:00:00:00:ab:cd");
    let mut sta = Client::new("turtlenet", "password1234", sta_mac);
    sta.enable_sae();
    let (mut ap, mut net, mut sta) = run_sae(sta);
    assert_eq!(sta.connected, 4);
    let tk = ap.station_tk(&sta_mac).unwrap();

    // Tear the link down on both sides (caches are retained).
    let d2sta = ap.protected_deauth(&sta_mac, 3).unwrap();
    sta.handle_incoming(&d2sta);
    assert_eq!(sta.connected, 0);
    let mut d2ap = barely_ap::dot11::RADIOTAP_TX.to_vec();
    d2ap.extend_from_slice(&barely_ap::dot11::build_ccmp_mgmt(
        barely_ap::dot11::SUBTYPE_DEAUTH, &ap_mac, &sta_mac, &ap_mac, 0x30, 5, 0, &tk, &3u16.to_le_bytes(),
    ));
    ap.handle_incoming(&d2ap);
    assert!(!ap.is_associated(&sta_mac));

    // Reconnect: capture every frame and confirm NO SAE auth is used.
    let mut all = Vec::new();
    let mut to_client = vec![ap.beacon_frame()];
    let mut to_ap: Vec<Vec<u8>> = Vec::new();
    let mut rounds = 0;
    while sta.connected < 4 && rounds < 50 {
        rounds += 1;
        let mut nxt = Vec::new();
        for f in to_client.drain(..) {
            let o = sta.handle_incoming(&f);
            all.extend(o.frames.clone());
            nxt.extend(o.frames);
        }
        to_ap.extend(nxt);
        let mut nxt2 = Vec::new();
        for f in to_ap.drain(..) {
            let fr = ap_step(&mut ap, &mut net, &f);
            all.extend(fr.clone());
            nxt2.extend(fr);
        }
        to_client.extend(nxt2);
    }
    assert_eq!(sta.connected, 4, "PMKSA fast reconnect must complete the 4-way");
    assert!(ap.is_associated(&sta_mac));

    for f in &all {
        let p = barely_ap::dot11::Dot11::parse(barely_ap::dot11::strip_radiotap(f).unwrap()).unwrap();
        if p.frame_type() == barely_ap::dot11::TYPE_MGMT && p.subtype() == barely_ap::dot11::SUBTYPE_AUTH {
            if let Some(a) = barely_ap::dot11::parse_auth(&p.body) {
                assert_ne!(a.algo, barely_ap::dot11::AUTH_ALG_SAE, "PMKSA reconnect must not re-run SAE");
            }
        }
    }
}

#[test]
fn beacon_protection_bigtk() {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let sta_mac = mac_to_bytes("02:00:00:00:ab:cd");
    let mut ap = Ap::new("turtlenet", "password1234", ap_mac, 1);
    ap.enable_beacon_protection();
    let mut net = FakeNet::new(ap_mac, [10, 10, 10, 1]);
    let mut sta = Client::new("turtlenet", "password1234", sta_mac);
    sta.enable_sae();

    drive(&mut ap, &mut net, &mut sta);
    assert_eq!(sta.connected, 4, "handshake completes with beacon protection on");

    // The STA installed the BIGTK delivered in message 3.
    assert_eq!(sta.bigtk(), Some(ap.bigtk()), "STA installs the BIGTK");

    // A protected beacon from the AP verifies; a tampered one does not.
    let beacon = ap.beacon_frame();
    assert!(sta.verify_beacon(&beacon), "valid BIP-protected beacon must verify");
    let mut bad = beacon.clone();
    let n = bad.len();
    bad[n - 30] ^= 0xff;
    assert!(!sta.verify_beacon(&bad), "tampered beacon must fail BIP verification");
}

/// Netlink kernel-beacon path: the static beacon handed to START_AP must NOT
/// carry a BIP MME, even with Beacon Protection enabled — a single fixed-IPN MME
/// repeated forever by the kernel is replayable. (In netlink mode the BIGTK is
/// installed in the kernel instead, which stamps the per-beacon MME itself.)
#[test]
fn netlink_static_beacon_has_no_mme() {
    const EID_MME: u8 = 76;
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let mut ap = Ap::new("turtlenet", "password1234", ap_mac, 1);
    ap.enable_beacon_protection();

    // The userspace beacon appends an 18-octet MME (id 76, len 16); the netlink
    // static beacon omits it entirely.
    let protected = ap.beacon_frame();
    let unprotected = ap.beacon_frame_unprotected();
    assert_eq!(
        protected.len(),
        unprotected.len() + 18,
        "protected beacon carries an 18-octet MME the unprotected one does not"
    );
    assert_eq!(protected[protected.len() - 18], EID_MME, "protected beacon ends with the MME");
    // The unprotected beacon must not end with an MME element header.
    let u = &unprotected;
    assert!(
        !(u[u.len() - 18] == EID_MME && u[u.len() - 17] == 16),
        "netlink static beacon must not contain a trailing MME"
    );
}

#[test]
fn transition_mode_accepts_both_wpa2_and_wpa3_clients() {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    for use_sae in [false, true] {
        let sta_mac = mac_to_bytes("02:00:00:00:ab:cd");
        let mut ap = Ap::new("turtlenet", "password1234", ap_mac, 1);
        ap.enable_transition();
        let mut net = FakeNet::new(ap_mac, [10, 10, 10, 1]);
        let mut sta = Client::new("turtlenet", "password1234", sta_mac);
        if use_sae {
            sta.enable_sae();
        }
        drive(&mut ap, &mut net, &mut sta);
        assert_eq!(sta.connected, 4, "transition AP must accept use_sae={use_sae} client");
        assert!(ap.is_associated(&sta_mac));
    }
}

#[test]
fn wrong_password_sae_fails_to_associate() {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let sta_mac = mac_to_bytes("02:00:00:00:ab:cd");

    let mut ap = Ap::new("turtlenet", "password1234", ap_mac, 1);
    ap.enable_sae();
    let mut net = FakeNet::new(ap_mac, [10, 10, 10, 1]);

    let mut sta = Client::new("turtlenet", "wrong-password", sta_mac);
    sta.enable_sae();

    let mut to_client: Vec<Vec<u8>> = vec![ap.beacon_frame()];
    let mut to_ap: Vec<Vec<u8>> = Vec::new();
    let mut rounds = 0;
    while sta.connected < 4 && rounds < 30 {
        rounds += 1;
        let mut next_to_ap = Vec::new();
        for f in to_client.drain(..) {
            next_to_ap.extend(sta.handle_incoming(&f).frames);
        }
        to_ap.extend(next_to_ap);
        let mut next_to_client = Vec::new();
        for f in to_ap.drain(..) {
            next_to_client.extend(ap_step(&mut ap, &mut net, &f));
        }
        to_client.extend(next_to_client);
    }

    // Different PMKs -> the SAE confirm exchange fails, so the STA never reaches
    // full authentication.
    assert!(sta.connected < 4, "mismatched password must not authenticate");
    assert!(!ap.is_associated(&sta_mac));
}

/// Anti-downgrade: a WPA3-SAE-only AP must reject open-system Authentication
/// (status 13) so a station that never starts SAE cannot reach the WPA2 PSK
/// 4-way using the AP's PSK-derived PMK.
#[test]
fn sae_only_ap_rejects_open_system_auth() {
    use barely_ap::dot11;
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let sta_mac = mac_to_bytes("02:00:00:00:ab:cd");

    let mut ap = Ap::new("turtlenet", "password1234", ap_mac, 1);
    ap.enable_sae();

    // Open-system Authentication request (algo 0) from a downgrade attacker.
    let sc = 0u16;
    let req = dot11::build_auth_req(&ap_mac, &sta_mac, sc);
    let mut framed = dot11::RADIOTAP_TX.to_vec();
    framed.extend_from_slice(&req);
    let out = ap.handle_incoming(&framed);

    // The AP must answer with an Authentication reject (status != success), not
    // a success that would let the station proceed to associate + 4-way.
    assert_eq!(out.frames.len(), 1, "SAE-only AP must answer open auth with one reject frame");
    let body = dot11::strip_radiotap(&out.frames[0]).expect("radiotap");
    let frame = dot11::Dot11::parse(body).expect("parse");
    let auth = dot11::parse_auth(&frame.body).expect("auth body");
    assert_eq!(auth.algo, dot11::AUTH_ALG_OPEN, "reject echoes the open-system algorithm");
    assert_eq!(auth.status, dot11::STATUS_UNSUPPORTED_AUTH_ALG, "status 13 (unsupported auth algorithm)");

    // A subsequent association attempt must not associate (no PMK was derived).
    let ssid = b"turtlenet";
    let assoc = dot11::build_assoc_req(&ap_mac, &sta_mac, ssid, 16);
    let mut framed = dot11::RADIOTAP_TX.to_vec();
    framed.extend_from_slice(&assoc);
    ap.handle_incoming(&framed);
    assert!(!ap.is_associated(&sta_mac), "downgrade station must never associate on a SAE-only AP");
}
