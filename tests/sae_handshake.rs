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
    let ping = sta.build_ping(&ap_mac, [10, 10, 10, 2], [10, 10, 10, 1]);
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
