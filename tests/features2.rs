//! Tests for the second batch of standard reference AP features: 802.11v BTM,
//! 802.11k Neighbor Report, 802.11h CSA, and Multiple BSSID.

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
    assert_eq!(sta.connected, 4);
    (ap, net, sta)
}

fn parse(frame: &[u8]) -> dot11::Dot11 {
    dot11::Dot11::parse(dot11::strip_radiotap(frame).unwrap()).unwrap()
}

fn drive(ap: &mut Ap, net: &mut FakeNet, sta: &mut Client, max_rounds: u32) {
    let mut to_client = vec![ap.beacon_frame()];
    let mut to_ap: Vec<Vec<u8>> = Vec::new();
    let mut rounds = 0;
    while sta.connected < 4 && rounds < max_rounds {
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
fn owe_handshake_and_ping() {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let sta_mac = mac_to_bytes("02:00:00:00:ab:cd");
    let mut ap = Ap::new("turtlenet", "password1234", ap_mac, 1);
    ap.enable_owe();
    let mut net = FakeNet::new(ap_mac, [10, 10, 10, 1]);
    let mut sta = Client::new("turtlenet", "password1234", sta_mac);
    sta.enable_owe();

    drive(&mut ap, &mut net, &mut sta, 50);
    assert_eq!(
        sta.connected, 4,
        "OWE handshake (open + DH + 4-way) must complete"
    );
    assert!(ap.is_associated(&sta_mac));

    // Data round-trips over the OWE-keyed CCMP link.
    let ping = sta.build_ping(&ap_mac, [10, 10, 10, 2], [10, 10, 10, 1], 0);
    let f = sta.encrypt_uplink(&ping).expect("uplink");
    let replies = ap_step(&mut ap, &mut net, &f);
    let mut got = false;
    for r in replies {
        for eth in sta.handle_incoming(&r).to_network {
            if eth.len() >= 14 + 20 + 8 && eth[12] == 0x08 && eth[13] == 0x00 {
                let ihl = (eth[14] & 0x0f) as usize * 4;
                if eth[14 + 9] == 1 && eth[14 + ihl] == 0 {
                    got = true;
                }
            }
        }
    }
    assert!(got, "ICMP echo must round-trip over the OWE link");
}

#[test]
fn ocv_handshake_completes_when_both_enabled() {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let mut ap = Ap::new("turtlenet", "password1234", ap_mac, 1);
    ap.enable_sae();
    ap.enable_ocv();
    let mut net = FakeNet::new(ap_mac, [10, 10, 10, 1]);
    let mut sta = Client::new(
        "turtlenet",
        "password1234",
        mac_to_bytes("02:00:00:00:ab:cd"),
    );
    sta.enable_sae();
    sta.enable_ocv();
    drive(&mut ap, &mut net, &mut sta, 50);
    assert_eq!(
        sta.connected, 4,
        "OCV handshake (matching channel) must complete"
    );
}

#[test]
fn ocv_ap_rejects_client_without_oci() {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let mut ap = Ap::new("turtlenet", "password1234", ap_mac, 1);
    ap.enable_sae();
    ap.enable_ocv();
    let mut net = FakeNet::new(ap_mac, [10, 10, 10, 1]);
    let mut sta = Client::new(
        "turtlenet",
        "password1234",
        mac_to_bytes("02:00:00:00:ab:cd"),
    );
    sta.enable_sae(); // OCV NOT enabled -> message 2 omits the OCI
    drive(&mut ap, &mut net, &mut sta, 30);
    assert!(
        sta.connected < 4,
        "OCV-required AP must reject a client that omits the OCI"
    );
    assert!(!ap.is_associated(&mac_to_bytes("02:00:00:00:ab:cd")));
}

#[test]
fn btm_disassoc_imminent_disconnects_station() {
    let (mut ap, _net, mut sta) = wpa3_up();
    let sta_mac = mac_to_bytes("02:00:00:00:ab:cd");
    let btm = ap.btm_request(&sta_mac, true, 100).expect("btm");
    // it is a CCMP-protected Action frame in the WNM category
    let f = parse(&btm);
    assert_eq!(f.subtype(), dot11::SUBTYPE_ACTION);
    assert!(f.protected());
    let tk = ap.station_tk(&sta_mac).unwrap();
    let body = dot11::decrypt_ccmp_mgmt(&f, &tk).unwrap();
    assert_eq!(body[0], dot11::ACTION_CATEGORY_WNM);
    assert_eq!(body[1], dot11::WNM_BTM_REQUEST);

    sta.handle_incoming(&btm);
    assert_eq!(
        sta.connected, 0,
        "disassoc-imminent BTM must disconnect the STA"
    );
}

#[test]
fn neighbor_report_is_protected_and_lists_the_ap() {
    let (mut ap, _net, _sta) = wpa3_up();
    let sta_mac = mac_to_bytes("02:00:00:00:ab:cd");
    let nr = ap.neighbor_report(&sta_mac).expect("neighbor report");
    let f = parse(&nr);
    assert_eq!(f.subtype(), dot11::SUBTYPE_ACTION);
    let tk = ap.station_tk(&sta_mac).unwrap();
    let body = dot11::decrypt_ccmp_mgmt(&f, &tk).unwrap();
    assert_eq!(body[0], dot11::ACTION_CATEGORY_RADIO_MEAS);
    assert_eq!(body[1], dot11::RADIO_MEAS_NEIGHBOR_REPORT_RESP);
    // a Neighbor Report element (id 52) carrying the AP's BSSID
    assert!(
        dot11::find_ie(&body[3..], 52).is_some(),
        "must contain a Neighbor Report element"
    );
    assert_eq!(
        &dot11::find_ie(&body[3..], 52).unwrap()[..6],
        &mac_to_bytes("02:00:00:00:00:00")
    );
}

#[test]
fn channel_switch_announcement_and_apply() {
    let mut ap = Ap::new(
        "turtlenet",
        "password1234",
        mac_to_bytes("02:00:00:00:00:00"),
        1,
    );
    assert_eq!(ap.channel, 1);
    ap.announce_channel_switch(6, 2);

    // beacons advertise the CSA element with the new channel
    let b0 = parse(&ap.beacon_frame());
    let csa = dot11::find_ie(&b0.body[12..], 37).expect("CSA element");
    assert_eq!(csa[1], 6, "CSA new channel");
    assert_eq!(csa[2], 2, "CSA count");
    assert_eq!(ap.channel, 1, "still on the old channel during countdown");

    let _ = ap.beacon_frame(); // count 1
    let _ = ap.beacon_frame(); // count 0 -> switch applied
    assert_eq!(ap.channel, 6, "AP switched channels after the countdown");
    // CSA element no longer present once the switch is done
    let bdone = parse(&ap.beacon_frame());
    assert!(dot11::find_ie(&bdone.body[12..], 37).is_none());
}

#[test]
fn multiple_bssid_element_advertised() {
    let mut ap = Ap::new(
        "turtlenet",
        "password1234",
        mac_to_bytes("02:00:00:00:00:00"),
        1,
    );
    let b0 = parse(&ap.beacon_frame());
    assert!(dot11::find_ie(&b0.body[12..], 71).is_none());
    ap.enable_multi_bssid();
    let b1 = parse(&ap.beacon_frame());
    assert!(
        dot11::find_ie(&b1.body[12..], 71).is_some(),
        "Multiple BSSID element must be advertised when enabled"
    );
}

#[test]
fn pmksa_cache_is_bounded() {
    let mut ap = Ap::new(
        "turtlenet",
        "password1234",
        mac_to_bytes("02:00:00:00:00:00"),
        1,
    );
    // Insert far more distinct PMKSA entries than the cap. The cache must stay
    // bounded (evicting to within PMKSA_CACHE_MAX = 256) rather than growing
    // without bound over a long uptime with many distinct clients.
    for i in 0..2000u32 {
        let mut id = [0u8; 16];
        id[..4].copy_from_slice(&i.to_be_bytes());
        ap.test_cache_pmksa(id);
    }
    assert!(
        ap.pmksa_len() <= 256,
        "PMKSA cache must stay bounded, got {}",
        ap.pmksa_len()
    );
}
