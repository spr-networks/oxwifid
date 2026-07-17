//! In-process WPA3-SAE (H2E) end-to-end: drive the Rust AP and Rust client
//! state machines against each other through the full SAE exchange, the 4-way
//! handshake (using the SAE PMK), and a CCMP ping.

use barely_ap::ap::{Ap, ApEvent, MldLink};
use barely_ap::client::Client;
use barely_ap::control::{handle_command_with_station_info, StationControlInfo};
use barely_ap::dot11;
use barely_ap::fakenet::FakeNet;
use barely_ap::sae::Sae;
use barely_ap::util::{bytes_to_mac, mac_to_bytes};

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

    assert!(
        sta.connected >= 4,
        "STA must reach full authentication via SAE (rounds={rounds})"
    );
    assert!(
        ap.is_associated(&sta_mac),
        "AP must consider the SAE station associated"
    );

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
    assert!(
        got_reply,
        "STA should decrypt the ICMP echo reply over the SAE-keyed link"
    );
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

fn mld_ap_for_tests() -> Ap {
    let ap_link0 = mac_to_bytes("02:00:00:00:10:01");
    let ap_link1 = mac_to_bytes("02:00:00:00:10:02");
    let ap_mld = mac_to_bytes("02:00:00:00:10:00");
    let mut ap = Ap::new("turtlenet", "password1234", ap_link0, 1);
    ap.mld = true;
    ap.mld_mac = ap_mld;
    ap.link_id = 0;
    ap.set_mld_links(vec![
        MldLink {
            link_id: 0,
            mac: ap_link0,
            channel: 1,
            width: 20,
            band6: false,
        },
        MldLink {
            link_id: 1,
            mac: ap_link1,
            channel: 36,
            width: 20,
            band6: false,
        },
    ]);
    ap
}

fn open_auth(ap: &mut Ap, sta: [u8; 6]) {
    let ap_link0 = mac_to_bytes("02:00:00:00:10:01");
    let mut auth = dot11::RADIOTAP_TX.to_vec();
    auth.extend_from_slice(&dot11::build_auth_req(&ap_link0, &sta, 0x10));
    ap.handle_incoming(&auth);
}

fn mld_assoc_req(sta: [u8; 6], sta_mld: [u8; 6], profiles: &[(u8, [u8; 6])]) -> Vec<u8> {
    let ap_link0 = mac_to_bytes("02:00:00:00:10:01");
    let mut link_info = Vec::new();
    for (link_id, link_mac) in profiles {
        link_info.extend_from_slice(&dot11::per_sta_profile(*link_id, link_mac, &[]));
    }
    let mut frame = dot11::build_assoc_req(&ap_link0, &sta, b"turtlenet", 0x20);
    frame.extend_from_slice(&dot11::multi_link_ap_basic(&sta_mld, 0, 0, 1, &link_info));
    let mut framed = dot11::RADIOTAP_TX.to_vec();
    framed.extend_from_slice(&frame);
    framed
}

fn assoc_status(frame: &[u8]) -> u16 {
    let parsed = dot11::strip_radiotap(frame)
        .and_then(dot11::Dot11::parse)
        .expect("assoc response parses");
    assert_eq!(parsed.subtype(), dot11::SUBTYPE_ASSOC_RESP);
    u16::from_le_bytes([parsed.body[2], parsed.body[3]])
}

fn assoc_mld_partner_status(frame: &[u8]) -> (u8, [u8; 6], u16) {
    let parsed = dot11::strip_radiotap(frame)
        .and_then(dot11::Dot11::parse)
        .expect("assoc response parses");
    let ies = parsed.body.get(6..).expect("assoc response fixed fields");
    let mut i = 0;
    while i + 2 <= ies.len() {
        let len = ies[i + 1] as usize;
        assert!(i + 2 + len <= ies.len(), "well-formed response IE");
        if ies[i] == 255 && len >= 4 && ies[i + 2] == 107 {
            let ml = &ies[i + 3..i + 2 + len];
            let common_len = ml[2] as usize;
            let p = 2 + common_len;
            let sub = &ml[p + 2..p + 2 + ml[p + 1] as usize];
            let control = u16::from_le_bytes([sub[0], sub[1]]);
            let link_id = (control & 0x0f) as u8;
            let info_len = sub[2] as usize;
            let mut link_mac = [0u8; 6];
            link_mac.copy_from_slice(&sub[3..9]);
            let profile = &sub[2 + info_len..];
            let status = u16::from_le_bytes([profile[2], profile[3]]);
            return (link_id, link_mac, status);
        }
        i += 2 + len;
    }
    panic!("association response has no Basic Multi-Link element");
}

#[test]
fn mld_assoc_response_carries_configured_tid_to_link_mapping() {
    let sta = mac_to_bytes("02:00:00:00:ab:01");
    let sta_mld = mac_to_bytes("02:00:00:00:ab:00");
    let sta_link1 = mac_to_bytes("02:00:00:00:ab:02");
    let mut ap = mld_ap_for_tests();
    ap.set_mld_default_link_mask(1 << 1);
    open_auth(&mut ap, sta);

    let out = ap.handle_incoming(&mld_assoc_req(sta, sta_mld, &[(1, sta_link1)]));
    assert_eq!(assoc_status(&out.frames[0]), dot11::STATUS_SUCCESS);
    let ttlm = dot11::tid_to_link_mapping_same_set(1 << 1);
    assert!(
        out.frames[0]
            .windows(ttlm.len())
            .any(|window| window == ttlm),
        "association response carries the same advertised mapping as the beacons"
    );
}

#[test]
fn wpa3_pmf_igtk_and_bip_protection() {
    // After a WPA3-SAE handshake the STA must have installed the IGTK delivered
    // in message 3, and must accept a BIP-protected group deauth from the AP
    // (and reject a tampered one).
    let mut sta = Client::new(
        "turtlenet",
        "password1234",
        mac_to_bytes("02:00:00:00:ab:cd"),
    );
    sta.enable_sae();
    let (mut ap, _net, sta) = run_sae(sta);
    assert!(sta.connected >= 4, "SAE must complete");

    assert_eq!(
        sta.igtk(),
        Some(ap.igtk()),
        "STA must install the AP's IGTK via PMF"
    );

    let deauth = ap.group_deauth(3);
    assert!(
        sta.verify_group_mgmt(&deauth),
        "STA must validate the BIP-protected deauth"
    );

    // tamper with the frame body -> verification must fail
    let mut tampered = deauth.clone();
    let n = tampered.len();
    tampered[n - 20] ^= 0xff;
    assert!(
        !sta.verify_group_mgmt(&tampered),
        "tampered group mgmt must fail BIP"
    );
}

#[test]
fn wpa3_sae_hunting_and_pecking_handshake() {
    // Same flow but with the legacy hunting-and-pecking PWE (commit status 0).
    let mut sta = Client::new(
        "turtlenet",
        "password1234",
        mac_to_bytes("02:00:00:00:ab:cd"),
    );
    sta.enable_sae();
    sta.use_hunting_pecking();
    let (ap, _net, sta) = run_sae(sta);
    assert!(sta.connected >= 4, "hunting-and-pecking SAE must complete");
    assert!(ap.is_associated(&mac_to_bytes("02:00:00:00:ab:cd")));
}

#[test]
fn legacy_sae_station_on_mld_ap_uses_link_address() {
    let ap_link = mac_to_bytes("02:00:00:00:00:00");
    let ap_mld = mac_to_bytes("02:00:00:11:22:33");
    let sta_link = mac_to_bytes("02:00:00:00:01:00");

    let mut ap = Ap::new("turtlenet", "password1234", ap_link, 1);
    ap.enable_sae();
    ap.mld = true;
    ap.mld_mac = ap_mld;

    // A non-MLO station does not carry a Multi-Link element in Authentication
    // and derives SAE using the AP link BSSID, even though the AP is an MLD.
    let mut sta_sae = Sae::new_h2e(b"turtlenet", b"password1234", None, &sta_link, &ap_link);
    sta_sae.prepare_commit(None);
    let auth = dot11::build_sae_auth(
        &ap_link,
        &sta_link,
        &ap_link,
        0,
        0,
        1,
        dot11::STATUS_SAE_H2E,
        &sta_sae.write_commit(),
    );
    let mut framed = dot11::RADIOTAP_TX.to_vec();
    framed.extend_from_slice(&auth);

    let out = ap.handle_incoming(&framed);
    assert_eq!(
        out.frames.len(),
        2,
        "SAE commit must yield AP commit + confirm"
    );

    let ap_commit_frame = dot11::strip_radiotap(&out.frames[0])
        .and_then(dot11::Dot11::parse)
        .expect("AP commit frame parses");
    assert_eq!(
        ap_commit_frame.addr2, ap_link,
        "SAE auth frame remains link-addressed"
    );
    let ap_commit = dot11::parse_auth(&ap_commit_frame.body).expect("AP commit auth body");
    assert_eq!(ap_commit.seq, 1);
    assert_eq!(
        ap_commit.payload.len(),
        2 + 3 * 32,
        "legacy SAE response must not append a Multi-Link element"
    );
    sta_sae
        .parse_peer_commit(ap_commit.payload)
        .expect("AP commit parses");
    sta_sae
        .process_commit()
        .expect("legacy SAE shared secret derives from link addresses");

    let ap_confirm_frame = dot11::strip_radiotap(&out.frames[1])
        .and_then(dot11::Dot11::parse)
        .expect("AP confirm frame parses");
    let ap_confirm = dot11::parse_auth(&ap_confirm_frame.body).expect("AP confirm auth body");
    assert_eq!(ap_confirm.seq, 2);
    sta_sae
        .check_confirm(ap_confirm.payload)
        .expect("AP confirm verifies with AP link SAE identity");
}

#[test]
fn mld_ap_sae_uses_sta_mld_from_auth_element() {
    let ap_link = mac_to_bytes("02:00:00:00:00:00");
    let ap_mld = mac_to_bytes("02:00:00:11:22:33");
    let sta_mld = mac_to_bytes("02:00:00:00:01:00");
    let sta_air = mac_to_bytes("32:4f:53:27:65:f3");

    let mut ap = Ap::new("turtlenet", "password1234", ap_link, 1);
    ap.enable_sae();
    ap.mld = true;
    ap.mld_mac = ap_mld;
    ap.set_psk_file(&[
        (Some(sta_air), "wrong-link-password".to_string()),
        (Some(sta_mld), "password1234".to_string()),
        (None, "wrong-wildcard-password".to_string()),
    ]);

    let mut sta_sae = Sae::new_h2e(b"turtlenet", b"password1234", None, &sta_mld, &ap_mld);
    sta_sae.prepare_commit(None);
    let mut payload = sta_sae.write_commit();
    payload.extend_from_slice(&dot11::multi_link_auth(&sta_mld));
    let auth = dot11::build_sae_auth(
        &ap_link,
        &sta_air,
        &ap_link,
        0,
        0,
        1,
        dot11::STATUS_SAE_H2E,
        &payload,
    );
    let mut framed = dot11::RADIOTAP_TX.to_vec();
    framed.extend_from_slice(&auth);

    let out = ap.handle_incoming(&framed);
    assert_eq!(
        out.frames.len(),
        2,
        "SAE commit must yield AP commit + confirm"
    );

    let ap_commit_frame = dot11::strip_radiotap(&out.frames[0])
        .and_then(dot11::Dot11::parse)
        .expect("AP commit frame parses");
    assert_eq!(ap_commit_frame.addr1, sta_air);
    assert_eq!(ap_commit_frame.addr2, ap_link);
    let ap_commit = dot11::parse_auth(&ap_commit_frame.body).expect("AP commit auth body");
    assert_eq!(ap_commit.seq, 1);
    sta_sae
        .parse_peer_commit(ap_commit.payload)
        .expect("AP commit parses");
    sta_sae
        .process_commit()
        .expect("MLD SAE shared secret derives from STA MLD");

    let ap_confirm_frame = dot11::strip_radiotap(&out.frames[1])
        .and_then(dot11::Dot11::parse)
        .expect("AP confirm frame parses");
    let ap_confirm = dot11::parse_auth(&ap_confirm_frame.body).expect("AP confirm auth body");
    assert_eq!(ap_confirm.seq, 2);
    sta_sae
        .check_confirm(ap_confirm.payload)
        .expect("AP confirm verifies with STA-MLD SAE identity");
}

#[test]
fn mld_sae_uses_identity_learned_from_prior_pmksa_assoc_attempt() {
    let ap_link = mac_to_bytes("02:00:00:00:10:01");
    let ap_mld = mac_to_bytes("02:00:00:00:10:00");
    let sta_mld = mac_to_bytes("02:00:00:00:01:00");
    let sta_air = mac_to_bytes("32:4f:53:27:65:f3");

    let mut ap = mld_ap_for_tests();
    ap.enable_sae();
    ap.set_psk_file(&[(Some(sta_mld), "password1234".to_string())]);

    // Model Apple's stale-PMKSA sequence: the first association attempt tells
    // the AP the stable MLD identity but cannot succeed because its PMKID is no
    // longer cached after an AP restart.
    open_auth(&mut ap, sta_air);
    let stale = ap.handle_incoming(&mld_assoc_req(
        sta_air,
        sta_mld,
        &[(1, mac_to_bytes("02:00:00:00:01:01"))],
    ));
    assert!(!stale.frames.is_empty());
    assert_eq!(ap.station_mld_mac(&sta_air), Some(sta_mld));

    // The subsequent full-SAE commit is link-addressed and deliberately omits
    // the Authentication MLE, as can happen with driver address translation.
    // RustAP must retain the known MLD identity for both credential lookup and
    // H2E PWE derivation.
    let mut sta_sae = Sae::new_h2e(b"turtlenet", b"password1234", None, &sta_mld, &ap_mld);
    sta_sae.prepare_commit(None);
    let auth = dot11::build_sae_auth(
        &ap_link,
        &sta_air,
        &ap_link,
        0,
        0,
        1,
        dot11::STATUS_SAE_H2E,
        &sta_sae.write_commit(),
    );
    let mut framed = dot11::RADIOTAP_TX.to_vec();
    framed.extend_from_slice(&auth);

    let out = ap.handle_incoming(&framed);
    assert_eq!(
        out.frames.len(),
        2,
        "known MLD identity must yield SAE commit and confirm responses"
    );
    let ap_commit_frame = dot11::strip_radiotap(&out.frames[0])
        .and_then(dot11::Dot11::parse)
        .expect("AP commit frame parses");
    let ap_commit = dot11::parse_auth(&ap_commit_frame.body).expect("AP commit auth body");
    sta_sae
        .parse_peer_commit(ap_commit.payload)
        .expect("AP commit parses");
    sta_sae
        .process_commit()
        .expect("known MLD identity derives the same shared secret");
    let ap_confirm_frame = dot11::strip_radiotap(&out.frames[1])
        .and_then(dot11::Dot11::parse)
        .expect("AP confirm frame parses");
    let ap_confirm = dot11::parse_auth(&ap_confirm_frame.body).expect("AP confirm auth body");
    sta_sae
        .check_confirm(ap_confirm.payload)
        .expect("AP confirm verifies with the retained MLD identity");
}

#[test]
fn mld_assoc_rejects_duplicate_and_reused_link_macs() {
    let mut ap = mld_ap_for_tests();
    let sta1 = mac_to_bytes("02:00:00:00:20:01");
    let mld1 = mac_to_bytes("02:00:00:00:20:00");
    let link1 = mac_to_bytes("02:00:00:00:20:11");
    open_auth(&mut ap, sta1);

    let ok = ap.handle_incoming(&mld_assoc_req(sta1, mld1, &[(1, link1)]));
    assert_eq!(assoc_status(&ok.frames[0]), dot11::STATUS_SUCCESS);
    assert_eq!(
        assoc_mld_partner_status(&ok.frames[0]),
        (1, mac_to_bytes("02:00:00:00:10:02"), dot11::STATUS_SUCCESS),
        "response accepts the requested partner link using the AP link address"
    );
    assert_eq!(ap.station_mld_mac(&sta1), Some(mld1));
    assert_eq!(ap.station_mld_link_macs(&sta1), vec![(1, link1)]);

    let sta2 = mac_to_bytes("02:00:00:00:30:01");
    let mld2 = mac_to_bytes("02:00:00:00:30:00");
    open_auth(&mut ap, sta2);
    let reused = ap.handle_incoming(&mld_assoc_req(sta2, mld2, &[(1, link1)]));
    assert_eq!(
        reused.frames.len(),
        1,
        "reused link MAC must fail before 4-way starts"
    );
    assert_ne!(assoc_status(&reused.frames[0]), dot11::STATUS_SUCCESS);
    assert_eq!(ap.station_mld_mac(&sta2), None);

    let mut ap = mld_ap_for_tests();
    let sta3 = mac_to_bytes("02:00:00:00:40:01");
    let mld3 = mac_to_bytes("02:00:00:00:40:00");
    let link_a = mac_to_bytes("02:00:00:00:40:11");
    let link_b = mac_to_bytes("02:00:00:00:40:12");
    open_auth(&mut ap, sta3);
    let duplicate = ap.handle_incoming(&mld_assoc_req(sta3, mld3, &[(1, link_a), (1, link_b)]));
    assert_eq!(
        duplicate.frames.len(),
        1,
        "duplicate link IDs must be rejected"
    );
    assert_ne!(assoc_status(&duplicate.frames[0]), dot11::STATUS_SUCCESS);
    assert_eq!(ap.station_mld_mac(&sta3), None);
}

#[test]
fn mld_sae_userspace_data_uses_mld_ccmp_addresses() {
    let ap_link0 = mac_to_bytes("02:00:00:00:10:01");
    let ap_mld = mac_to_bytes("02:00:00:00:10:00");
    let sta_link0 = mac_to_bytes("02:00:00:00:50:01");
    let sta_mld = mac_to_bytes("02:00:00:00:50:00");
    let sta_link1 = mac_to_bytes("02:00:00:00:50:11");

    let mut ap = mld_ap_for_tests();
    ap.enable_sae();
    let mut net = FakeNet::new(ap_link0, [10, 10, 10, 1]);

    let mut sta = Client::new("turtlenet", "password1234", sta_link0);
    sta.enable_sae();
    sta.enable_mld(sta_mld, sta_link1, ap_mld);
    drive(&mut ap, &mut net, &mut sta);

    assert_eq!(sta.connected, 4, "MLD SAE station must complete the 4-way");
    assert!(ap.is_associated(&sta_link0));
    assert_eq!(
        ap.station_link_for_peer(&sta_mld),
        Some(sta_link0),
        "MLD address resolves to the association station"
    );
    assert_eq!(
        ap.station_link_for_peer(&sta_link1),
        Some(sta_link0),
        "partner-link address resolves to the association station"
    );
    let station_info = |mac: &[u8; 6]| {
        (*mac == sta_mld).then(|| StationControlInfo {
            vlan_id: 4096,
            ifname: "wlan3.4096".to_string(),
            telemetry: None,
        })
    };
    let first = handle_command_with_station_info(&mut ap, "STA-FIRST", &station_info).0;
    assert!(
        first.starts_with(&format!("{}\n", bytes_to_mac(&sta_mld))),
        "hostapd control station identity must be the MLD MAC: {first}"
    );
    let by_mld = handle_command_with_station_info(
        &mut ap,
        &format!("STA {}", bytes_to_mac(&sta_mld)),
        &station_info,
    )
    .0;
    assert!(by_mld.contains("vlan_id=4096\n"), "{by_mld}");
    assert!(
        ap.drain_events()
            .contains(&ApEvent::Connected { mac: sta_mld }),
        "SPR connect event uses the stable MLD identity"
    );

    let ping = sta.build_ping(&ap_link0, [10, 10, 10, 2], [10, 10, 10, 1], 0);
    let ping_frame = sta.encrypt_uplink(&ping).expect("MLD uplink encrypts");
    let replies = ap_step(&mut ap, &mut net, &ping_frame);
    assert!(
        !replies.is_empty(),
        "AP must decrypt the MLD-secured uplink and answer"
    );

    let mut got_reply = false;
    for f in replies {
        let out = sta.handle_incoming(&f);
        got_reply |= out.to_network.iter().any(|eth| {
            eth.len() >= 14 + 20 + 8
                && eth[12] == 0x08
                && eth[13] == 0x00
                && eth[14 + 9] == 1
                && eth[14 + ((eth[14] & 0x0f) as usize * 4)] == 0
        });
    }
    assert!(got_reply, "STA must decrypt the MLD-secured downlink reply");

    let tk = ap
        .station_tk(&sta_link0)
        .expect("AP has the MLD station TK");
    let deauth_to_sta = ap
        .protected_deauth(&sta_link0, 7)
        .expect("protected MLD deauth");
    sta.handle_incoming(&deauth_to_sta);
    assert_eq!(
        sta.connected, 0,
        "STA must accept AP->STA MLD-protected deauth"
    );

    let mut deauth_to_ap = dot11::RADIOTAP_TX.to_vec();
    deauth_to_ap.extend_from_slice(&dot11::build_ccmp_mgmt_sec(
        dot11::SUBTYPE_DEAUTH,
        &ap_link0,
        &sta_link0,
        &ap_link0,
        Some((ap_mld, sta_mld, ap_mld)),
        0,
        0x40,
        77,
        0,
        &tk,
        &3u16.to_le_bytes(),
    ));
    ap.handle_incoming(&deauth_to_ap);
    assert!(
        !ap.is_associated(&sta_link0),
        "AP must accept STA->AP MLD-protected deauth"
    );
    assert!(
        ap.drain_events().contains(&ApEvent::Disconnected {
            mac: sta_mld,
            reason: 3,
        }),
        "SPR disconnect event uses the stable MLD identity and client reason"
    );
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
    assert_eq!(
        sta.connected, 0,
        "STA honours the protected inactivity deauth"
    );
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
        barely_ap::dot11::SUBTYPE_DEAUTH,
        &ap_mac,
        &sta_mac,
        &ap_mac,
        0x30,
        5,
        0,
        &tk,
        &3u16.to_le_bytes(),
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
    assert_eq!(
        sta.connected, 4,
        "PMKSA fast reconnect must complete the 4-way"
    );
    assert!(ap.is_associated(&sta_mac));

    for f in &all {
        let p =
            barely_ap::dot11::Dot11::parse(barely_ap::dot11::strip_radiotap(f).unwrap()).unwrap();
        if p.frame_type() == barely_ap::dot11::TYPE_MGMT
            && p.subtype() == barely_ap::dot11::SUBTYPE_AUTH
        {
            if let Some(a) = barely_ap::dot11::parse_auth(&p.body) {
                assert_ne!(
                    a.algo,
                    barely_ap::dot11::AUTH_ALG_SAE,
                    "PMKSA reconnect must not re-run SAE"
                );
            }
        }
    }
}

#[test]
fn unknown_sae_pmkid_is_rejected_with_status_53() {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let sta_mac = mac_to_bytes("02:00:00:00:ab:cd");
    let mut ap = Ap::new("turtlenet", "password1234", ap_mac, 1);
    ap.enable_sae();

    // PMKSA reconnect begins with Open-System auth. The station then presents
    // a PMKID from an earlier AP lifetime that this fresh AP does not have.
    let mut auth = dot11::RADIOTAP_TX.to_vec();
    auth.extend_from_slice(&dot11::build_auth_req(&ap_mac, &sta_mac, 0));
    let auth_out = ap.handle_incoming(&auth);
    assert_eq!(auth_out.frames.len(), 1, "open auth is accepted for PMKSA");

    let stale_pmkid = [0x5a; 16];
    let mut assoc = dot11::RADIOTAP_TX.to_vec();
    assoc.extend_from_slice(&dot11::build_assoc_req_pmkid(
        &ap_mac,
        &sta_mac,
        b"turtlenet",
        &stale_pmkid,
        16,
    ));
    let out = ap.handle_incoming(&assoc);
    assert_eq!(out.frames.len(), 1, "AP must explicitly reject stale PMKID");
    assert_eq!(
        assoc_status(&out.frames[0]),
        dot11::STATUS_INVALID_PMKID,
        "status 53 makes the station discard PMKSA and retry full SAE"
    );
    assert!(!ap.is_associated(&sta_mac));
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
    assert_eq!(
        sta.connected, 4,
        "handshake completes with beacon protection on"
    );

    // The STA installed the BIGTK delivered in message 3.
    assert_eq!(sta.bigtk(), Some(ap.bigtk()), "STA installs the BIGTK");

    // A protected beacon from the AP verifies; a tampered one does not.
    let beacon = ap.beacon_frame();
    let extcap = dot11::find_ie(&beacon[36..], 127).expect("Extended Capabilities");
    assert_ne!(
        extcap[10] & 0x10,
        0,
        "Beacon Protection mode advertises Extended Capability bit 84"
    );
    assert!(
        sta.verify_beacon(&beacon),
        "valid BIP-protected beacon must verify"
    );
    let mut bad = beacon.clone();
    let n = bad.len();
    bad[n - 30] ^= 0xff;
    assert!(
        !sta.verify_beacon(&bad),
        "tampered beacon must fail BIP verification"
    );
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
    assert_eq!(
        protected[protected.len() - 18],
        EID_MME,
        "protected beacon ends with the MME"
    );
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
        assert_eq!(
            sta.connected, 4,
            "transition AP must accept use_sae={use_sae} client"
        );
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
    assert!(
        sta.connected < 4,
        "mismatched password must not authenticate"
    );
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

    // Open-system Authentication request (algo 0). A SAE AP now *accepts* open
    // auth, because WPA3-SAE PMKSA fast-reconnect uses open-auth + a cached
    // PMKID (rejecting it here with status 13 breaks reconnect and loops the STA
    // in AUTHENTICATING). The anti-downgrade guarantee moves to association.
    let sc = 0u16;
    let req = dot11::build_auth_req(&ap_mac, &sta_mac, sc);
    let mut framed = dot11::RADIOTAP_TX.to_vec();
    framed.extend_from_slice(&req);
    let out = ap.handle_incoming(&framed);
    if let Some(f) = out.frames.first() {
        let body = dot11::strip_radiotap(f).expect("radiotap");
        let frame = dot11::Dot11::parse(body).expect("parse");
        if let Some(auth) = dot11::parse_auth(&frame.body) {
            assert_ne!(
                auth.status,
                dot11::STATUS_UNSUPPORTED_AUTH_ALG,
                "SAE AP must not reject open auth with status 13 (would break PMKSA reconnect)"
            );
        }
    }

    // The anti-downgrade guarantee: a station that open-authed but has NO
    // SAE/OWE/cached PMK must never associate on a SAE-only AP (so it can never
    // reach a 4-way and fall back to the bare PSK path).
    let ssid = b"turtlenet";
    let assoc = dot11::build_assoc_req(&ap_mac, &sta_mac, ssid, 16);
    let mut framed = dot11::RADIOTAP_TX.to_vec();
    framed.extend_from_slice(&assoc);
    ap.handle_incoming(&framed);
    assert!(
        !ap.is_associated(&sta_mac),
        "downgrade station (no PMK) must never associate on a SAE-only AP"
    );
}
