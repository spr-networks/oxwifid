//! GTK rekeying via the Group Key Handshake (reference AP `wpa_group_rekey`).

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

/// Drive one client through the full handshake against `ap` until associated.
fn connect(ap: &mut Ap, net: &mut FakeNet, sta: &mut Client) {
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
    assert_eq!(sta.connected, 4);
}

fn wpa3_ap() -> (Ap, FakeNet) {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let mut ap = Ap::new("turtlenet", "password1234", ap_mac, 1);
    ap.enable_sae();
    let net = FakeNet::new(ap_mac, [10, 10, 10, 1]);
    (ap, net)
}

fn wpa3_sta(mac: &str) -> Client {
    let mut sta = Client::new("turtlenet", "password1234", mac_to_bytes(mac));
    sta.enable_sae();
    sta
}

fn wpa3_up() -> (Ap, FakeNet, Client) {
    let (mut ap, mut net) = wpa3_ap();
    let mut sta = wpa3_sta("02:00:00:00:ab:cd");
    connect(&mut ap, &mut net, &mut sta);
    (ap, net, sta)
}

#[test]
fn gtk_rekey_installs_new_key_on_station() {
    let (mut ap, _net, mut sta) = wpa3_up();

    let old_gtk = ap.gtk();
    assert_eq!(
        sta.gtk(),
        old_gtk,
        "STA has the original GTK after the handshake"
    );
    let old_igtk = sta.igtk().unwrap();

    // AP rotates the GTK and runs the Group Key Handshake.
    let msgs = ap.rekey_gtk();
    assert_eq!(
        msgs.len(),
        1,
        "one Group Key message 1 per associated station"
    );
    let new_gtk = ap.gtk();
    assert_ne!(new_gtk, old_gtk, "AP rotated the GTK");

    // The STA processes message 1, installs the new GTK/IGTK, and replies.
    let out = sta.handle_incoming(&msgs[0]);
    assert_eq!(sta.gtk(), new_gtk, "STA installed the rotated GTK");
    assert_ne!(
        sta.igtk().unwrap(),
        old_igtk,
        "STA installed the rotated IGTK"
    );
    assert_eq!(out.frames.len(), 1, "STA sends Group Key message 2");
    assert_eq!(sta.connected, 4, "STA stays associated across a rekey");
}

#[test]
fn protected_group_key_handshake_stays_on_the_controlled_port() {
    let (mut ap, _net, mut sta) = wpa3_up();
    let sta_mac = sta.mac;
    let tk = ap.station_tk(&sta_mac).expect("installed pairwise key");

    // Real reference AP sends the post-association Group-Key EAPOL exchange inside
    // CCMP-protected data. Re-wrap the Rust AP's canonical Message 1 that way.
    let message_1 = ap.rekey_gtk().remove(0);
    let eapol = dot11::strip_radiotap(&message_1)
        .and_then(dot11::Dot11::parse)
        .and_then(|frame| frame.eapol_frame().map(ToOwned::to_owned))
        .expect("Group-Key Message 1 EAPOL");
    let mut ethernet = Vec::with_capacity(14 + eapol.len());
    ethernet.extend_from_slice(&sta_mac);
    ethernet.extend_from_slice(&ap.mac);
    ethernet.extend_from_slice(&dot11::ETHERTYPE_EAPOL.to_be_bytes());
    ethernet.extend_from_slice(&eapol);
    let protected_message_1 = ap
        .deliver_to_station(&ethernet)
        .pop()
        .expect("CCMP-protected Group-Key Message 1");

    let response = sta.handle_incoming(&protected_message_1);
    assert!(
        response.to_network.is_empty(),
        "controlled-port EAPOL must not leak into the SPR TAP"
    );
    assert_eq!(response.frames.len(), 1, "station returns Message 2");
    assert_eq!(sta.gtk(), ap.gtk(), "station installs the rotated GTK");

    let response_frame = dot11::strip_radiotap(&response.frames[0])
        .and_then(dot11::Dot11::parse)
        .expect("protected response frame");
    assert!(
        response_frame.protected(),
        "post-association Group-Key Message 2 must use the PTK"
    );
    let response_eth =
        dot11::decrypt_ccmp(&response_frame, &tk, false).expect("valid response CCMP MIC");
    assert_eq!(
        response_eth.get(12..14),
        Some(dot11::ETHERTYPE_EAPOL.to_be_bytes().as_slice())
    );
    let response_eapol = &response_eth[14..];
    let response_body_len = u16::from_be_bytes([response_eapol[2], response_eapol[3]]) as usize;
    let key = dot11::EapolKey::parse(&response_eapol[4..4 + response_body_len])
        .expect("Group-Key Message 2");
    assert!(!key.is_pairwise());
    assert!(key.has_key_mic());
    assert!(key.secure());
}

#[test]
fn group_rekey_msg1_with_bad_mic_is_ignored() {
    let (mut ap, _net, mut sta) = wpa3_up();
    let old_gtk = sta.gtk();
    let mut msgs = ap.rekey_gtk();
    // corrupt a byte in the (MIC'd) message
    let m = &mut msgs[0];
    let n = m.len();
    m[n - 40] ^= 0xff;
    sta.handle_incoming(m);
    assert_eq!(
        sta.gtk(),
        old_gtk,
        "a tampered Group Key message must not install a GTK"
    );
}

#[test]
fn ap_processes_group_msg2_and_coalesces_rekeys() {
    let (mut ap, _net, mut sta) = wpa3_up();
    // First rekey: one msg 1; the station is now awaiting its msg 2 ACK.
    let msgs = ap.rekey_gtk();
    assert_eq!(msgs.len(), 1);
    // A second rekey while the first is still in flight is coalesced to nothing
    // (reference AP waits for GKeyDoneStations to reach 0 before starting another).
    assert!(
        ap.rekey_gtk().is_empty(),
        "rekey coalesces while one is in flight"
    );
    // The station ACKs (msg 2); feed it back to the AP, which clears its state.
    let reply = sta.handle_incoming(&msgs[0]);
    assert_eq!(reply.frames.len(), 1, "station emits Group Key msg 2");
    ap.handle_incoming(&reply.frames[0]);
    // With every station's msg 2 in, a fresh rekey is permitted again.
    assert_eq!(
        ap.rekey_gtk().len(),
        1,
        "rekey allowed again once all msg 2s are in"
    );
}

#[test]
fn periodic_group_rekey_fires_on_tick() {
    let (mut ap, _net, mut sta) = wpa3_up();
    // Well inside a long interval, tick must not rekey.
    ap.set_group_rekey(3600);
    assert!(
        ap.tick().frames.is_empty(),
        "no rekey well before the interval"
    );
    // Age the clock past a short interval and the next tick performs the rekey.
    ap.set_group_rekey(1);
    let old = ap.gtk();
    ap.test_expire_group_rekey();
    let out = ap.tick();
    assert_ne!(
        ap.gtk(),
        old,
        "periodic wpa_group_rekey rotated the GTK on tick"
    );
    for f in &out.frames {
        sta.handle_incoming(f);
    }
    assert_eq!(
        sta.gtk(),
        ap.gtk(),
        "station installed the periodically-rotated GTK"
    );
}

#[test]
fn periodic_group_rekey_clock_advances_while_idle() {
    let (mut ap, _net) = wpa3_ap();
    ap.set_group_rekey(1);
    ap.test_expire_group_rekey();
    let old = ap.gtk();

    let out = ap.tick();

    assert!(out.frames.is_empty(), "there are no stations to notify");
    assert_ne!(
        ap.gtk(),
        old,
        "the idle BSS still advances its periodic group-key clock"
    );
    assert!(
        ap.tick().frames.is_empty(),
        "the first future association must not inherit an overdue rekey"
    );
}

#[test]
fn disabling_periodic_rekey_stops_it() {
    let (mut ap, _net, _sta) = wpa3_up();
    ap.set_group_rekey(0); // disabled
    let old = ap.gtk();
    ap.test_expire_group_rekey();
    ap.tick();
    assert_eq!(
        ap.gtk(),
        old,
        "wpa_group_rekey=0 disables periodic group rekeying"
    );
}

#[test]
fn strict_rekey_on_authorized_leave() {
    let (mut ap, mut net) = wpa3_ap();
    let mut a = wpa3_sta("02:00:00:00:00:01");
    let mut b = wpa3_sta("02:00:00:00:00:02");
    connect(&mut ap, &mut net, &mut a);
    connect(&mut ap, &mut net, &mut b);

    let old = ap.gtk();
    // Kick A; with B still associated, wpa_strict_rekey rotates the GTK so the
    // departed A can no longer read group traffic.
    ap.kick(&mac_to_bytes("02:00:00:00:00:01"));
    let out = ap.tick();
    assert_ne!(
        ap.gtk(),
        old,
        "strict rekey rotated the GTK after an authorized STA left"
    );
    for f in &out.frames {
        b.handle_incoming(f);
    }
    assert_eq!(
        b.gtk(),
        ap.gtk(),
        "the remaining station installed the rotated GTK"
    );
}

#[test]
fn no_strict_rekey_when_last_station_leaves() {
    let (mut ap, _net, _sta) = wpa3_up();
    let old = ap.gtk();
    // The only station leaves — no one remains to protect, so no rekey.
    ap.kick(&mac_to_bytes("02:00:00:00:ab:cd"));
    ap.tick();
    assert_eq!(
        ap.gtk(),
        old,
        "no strict rekey when the last station leaves"
    );
}

#[test]
fn fresh_auth_cancels_stale_group_rekey_state() {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let mut ap = Ap::new("turtlenet", "password1234", ap_mac, 1);
    let mut net = FakeNet::new(ap_mac, [10, 10, 10, 1]);
    let mut old_a = Client::new(
        "turtlenet",
        "password1234",
        mac_to_bytes("02:00:00:00:00:01"),
    );
    let mut b = Client::new(
        "turtlenet",
        "password1234",
        mac_to_bytes("02:00:00:00:00:02"),
    );
    connect(&mut ap, &mut net, &mut old_a);
    connect(&mut ap, &mut net, &mut b);

    // Start a strict/periodic-style group rekey, but race a fresh
    // Authentication from A ahead of its Group-Key message 2. The new session's
    // four-way M2 must not be parsed as an ACK for the obsolete group exchange.
    assert_eq!(ap.rekey_gtk().len(), 2);
    ap.test_clear_auth_backoff();
    let mut new_a = Client::new(
        "turtlenet",
        "password1234",
        mac_to_bytes("02:00:00:00:00:01"),
    );
    connect(&mut ap, &mut net, &mut new_a);
    assert!(ap.is_associated(&new_a.mac));
}

/// Per-STA-VIF: a group rekey must rotate EACH station's OWN per-station GTK
/// *value* (so broadcast isolation is preserved) while every station shares the
/// single BSS-wide GTK *index* (what the RSNE advertises). The index toggles
/// once, together, for all stations — only the values differ. Regression test
/// for the over-engineered per-STA-VIF rekey that wrongly gave each station its
/// own key index.
#[test]
fn per_sta_vif_rekey_rotates_each_stations_own_gtk() {
    let (mut ap, mut net) = wpa3_ap();
    ap.enable_per_sta_vif();
    let a_mac = mac_to_bytes("02:00:00:00:00:01");
    let b_mac = mac_to_bytes("02:00:00:00:00:02");
    let mut a = wpa3_sta("02:00:00:00:00:01");
    let mut b = wpa3_sta("02:00:00:00:00:02");
    connect(&mut ap, &mut net, &mut a);
    connect(&mut ap, &mut net, &mut b);

    // Each station got its OWN distinct GTK value, but at the SAME BSS-wide
    // index (the advertised key id, 1 initially).
    let a_gtk0 = ap.station_gtk(&a_mac);
    let b_gtk0 = ap.station_gtk(&b_mac);
    assert_ne!(
        a_gtk0, b_gtk0,
        "per-STA-VIF: stations have distinct GTK values"
    );
    assert_eq!(a.gtk(), a_gtk0, "station A installed its own GTK");
    assert_eq!(b.gtk(), b_gtk0, "station B installed its own GTK");
    assert_eq!(ap.station_gtk_key_id(&a_mac), 1);
    assert_eq!(ap.station_gtk_key_id(&b_mac), 1);
    assert_eq!(
        ap.station_gtk_key_id(&a_mac),
        ap.station_gtk_key_id(&b_mac),
        "the GTK index is BSS-wide: every station shares the same key id",
    );

    // Rekey: one msg 1 per station, each carrying that station's own NEW value.
    let msgs = ap.rekey_gtk();
    assert_eq!(msgs.len(), 2, "one Group Key msg 1 per associated station");

    let a_gtk1 = ap.station_gtk(&a_mac);
    let b_gtk1 = ap.station_gtk(&b_mac);
    assert_ne!(a_gtk1, a_gtk0, "A's per-station GTK value rotated");
    assert_ne!(b_gtk1, b_gtk0, "B's per-station GTK value rotated");
    assert_ne!(
        a_gtk1, b_gtk1,
        "isolation preserved: rotated values still differ"
    );
    // The per-station GTK index is a fixed constant (1): it does NOT toggle on
    // rekey — only each station's own value rotates (above). The isolation is the
    // distinct values, never a per-station or a moving index.
    assert_eq!(
        ap.station_gtk_key_id(&a_mac),
        1,
        "index stays at constant 1 after rekey"
    );
    assert_eq!(
        ap.station_gtk_key_id(&b_mac),
        1,
        "index stays at constant 1 after rekey"
    );
    assert_eq!(
        ap.station_gtk_key_id(&a_mac),
        ap.station_gtk_key_id(&b_mac),
        "every station uses the same constant GTK index (1)",
    );

    // Each station installs the key from ITS OWN msg 1 (not the other's).
    for m in &msgs {
        a.handle_incoming(m);
        b.handle_incoming(m);
    }
    assert_eq!(a.gtk(), a_gtk1, "A installed its own rotated GTK");
    assert_eq!(b.gtk(), b_gtk1, "B installed its own rotated GTK");
    assert_ne!(
        a.gtk(),
        b.gtk(),
        "post-rekey, the two stations still hold different GTKs"
    );
}

// ---------------------------------------------------------------------------
// Pairwise (PTK) rekeying — an authenticator may restart the 4-way at any time
// on an established link. The station must answer it, must keep the installed
// key carrying traffic until the new one is authenticated, and must not let an
// unauthenticated message 1 disturb either.
// ---------------------------------------------------------------------------

fn framed(frame: Vec<u8>) -> Vec<u8> {
    let mut out = dot11::RADIOTAP_TX.to_vec();
    out.extend_from_slice(&frame);
    out
}

/// A plain WPA2 pair, connected. WPA2 (no PMF) is what lets a bare Association
/// Request drive the AP into a second 4-way; under PMF the AP answers that with
/// an SA Query instead, which is a different test.
fn wpa2_up() -> (Ap, FakeNet, Client) {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let mut ap = Ap::new("turtlenet", "password1234", ap_mac, 1);
    let mut net = FakeNet::new(ap_mac, [10, 10, 10, 1]);
    let mut sta = Client::new(
        "turtlenet",
        "password1234",
        mac_to_bytes("02:00:00:00:ab:cd"),
    );
    connect(&mut ap, &mut net, &mut sta);
    (ap, net, sta)
}

/// Whether a downlink frame the AP encrypts under its installed PTK still
/// decrypts at the station — i.e. both ends agree on the live pairwise key.
fn downlink_round_trips(ap: &mut Ap, sta: &mut Client) -> bool {
    let bssid = sta.bssid().expect("associated");
    let eth = [
        sta.mac.as_slice(),
        bssid.as_slice(),
        &[0x08, 0x00],
        b"downlink probe",
    ]
    .concat();
    let frames = ap.deliver_to_station(&eth);
    frames.len() == 1 && sta.handle_incoming(&frames[0]).to_network == vec![eth]
}

fn uplink_round_trips(ap: &mut Ap, sta: &mut Client) -> bool {
    let bssid = sta.bssid().expect("associated");
    let eth = [
        bssid.as_slice(),
        sta.mac.as_slice(),
        &[0x08, 0x00],
        b"uplink probe",
    ]
    .concat();
    match sta.encrypt_uplink(&eth) {
        Some(protected) => ap.handle_incoming(&protected).to_network == vec![eth],
        None => false,
    }
}

/// Make the AP start a second 4-way for an already-associated station and
/// return the frames it emits (Association Response + message 1).
fn start_ptk_rekey(ap: &mut Ap, sta: &Client) -> Vec<Vec<u8>> {
    ap.test_clear_auth_backoff();
    let assoc = dot11::build_assoc_req_for_cipher(
        &sta.bssid().expect("associated"),
        &sta.mac,
        b"turtlenet",
        0,
        dot11::DataCipher::Ccmp128,
    );
    ap.handle_incoming(&framed(assoc)).frames
}

fn pump(ap: &mut Ap, net: &mut FakeNet, sta: &mut Client, mut to_sta: Vec<Vec<u8>>) {
    for _ in 0..10 {
        if to_sta.is_empty() {
            break;
        }
        let mut to_ap = Vec::new();
        for f in to_sta.drain(..) {
            to_ap.extend(sta.handle_incoming(&f).frames);
        }
        for f in to_ap.drain(..) {
            to_sta.extend(ap_step(ap, net, &f));
        }
    }
}

#[test]
fn ap_initiated_ptk_rekey_replaces_the_key_without_dropping_the_link() {
    let (mut ap, mut net, mut sta) = wpa2_up();
    let sta_mac = sta.mac;
    let old_tk = ap.station_tk(&sta_mac).expect("pairwise key installed");

    let to_sta = start_ptk_rekey(&mut ap, &sta);
    pump(&mut ap, &mut net, &mut sta, to_sta);

    assert_eq!(
        sta.connected, 4,
        "the station stays associated across a rekey"
    );
    let new_tk = ap.station_tk(&sta_mac).expect("pairwise key installed");
    assert_ne!(new_tk, old_tk, "the 4-way installed a fresh PTK");
    assert!(
        downlink_round_trips(&mut ap, &mut sta),
        "downlink works under the rekeyed PTK"
    );
    assert!(
        uplink_round_trips(&mut ap, &mut sta),
        "uplink works under the rekeyed PTK"
    );
}

#[test]
fn identical_ptk_from_a_fresh_handshake_never_resets_packet_numbers() {
    let ap_mac = mac_to_bytes("02:00:00:00:00:00");
    let sta_mac = mac_to_bytes("02:00:00:00:ab:cd");
    let mut ap = Ap::new("turtlenet", "password1234", ap_mac, 1);
    let fixed_anonce = [0x33; 32];
    ap.set_test_fixtures([0x44; 16], fixed_anonce);
    let mut net = FakeNet::new(ap_mac, [10, 10, 10, 1]);
    let mut sta = Client::new("turtlenet", "password1234", sta_mac);
    sta.set_test_snonce([0x55; 32]);
    connect(&mut ap, &mut net, &mut sta);

    let uplink = [
        ap_mac.as_slice(),
        sta_mac.as_slice(),
        &[0x08, 0x00],
        b"uplink before identical rekey",
    ]
    .concat();
    let before_up = sta.encrypt_uplink(&uplink).expect("protected uplink");
    let before_up_pn = dot11::strip_radiotap(&before_up)
        .and_then(dot11::Dot11::parse)
        .and_then(|frame| frame.ccmp_pn())
        .expect("uplink PN");
    assert_eq!(
        ap.handle_incoming(&before_up).to_network,
        vec![uplink.clone()]
    );

    let downlink = [
        sta_mac.as_slice(),
        ap_mac.as_slice(),
        &[0x08, 0x00],
        b"downlink before identical rekey",
    ]
    .concat();
    let before_down = ap.deliver_to_station(&downlink).remove(0);
    let before_down_pn = dot11::strip_radiotap(&before_down)
        .and_then(dot11::Dot11::parse)
        .and_then(|frame| frame.ccmp_pn())
        .expect("downlink PN");
    assert_eq!(
        sta.handle_incoming(&before_down).to_network,
        vec![downlink.clone()]
    );

    // Both nonce overrides remain fixed, forcing the second handshake to
    // derive exactly the already-installed PTK under a newer EAPOL counter.
    let old_tk = ap.station_tk(&sta_mac).expect("installed PTK");
    let to_sta = start_ptk_rekey(&mut ap, &sta);
    pump(&mut ap, &mut net, &mut sta, to_sta);
    assert_eq!(ap.station_tk(&sta_mac), Some(old_tk));

    let next_up = sta.encrypt_uplink(&uplink).expect("post-rekey uplink");
    let next_up_pn = dot11::strip_radiotap(&next_up)
        .and_then(dot11::Dot11::parse)
        .and_then(|frame| frame.ccmp_pn())
        .expect("post-rekey uplink PN");
    assert_eq!(
        next_up_pn,
        before_up_pn + 1,
        "supplicant must not reinstall an unchanged PTK"
    );
    assert_eq!(ap.handle_incoming(&next_up).to_network, vec![uplink]);

    let next_down = ap.deliver_to_station(&downlink).remove(0);
    let next_down_pn = dot11::strip_radiotap(&next_down)
        .and_then(dot11::Dot11::parse)
        .and_then(|frame| frame.ccmp_pn())
        .expect("post-rekey downlink PN");
    assert_eq!(
        next_down_pn,
        before_down_pn + 1,
        "authenticator must not reinstall an unchanged PTK"
    );
    assert_eq!(sta.handle_incoming(&next_down).to_network, vec![downlink]);
}

#[test]
fn a_rekey_installs_nothing_at_message_2() {
    let (mut ap, _net, mut sta) = wpa2_up();
    let sta_mac = sta.mac;
    let old_tk = ap.station_tk(&sta_mac).expect("pairwise key installed");

    // Deliver ONLY message 1, so the station derives a candidate and answers
    // with message 2 — and stops there.
    let m1 = start_ptk_rekey(&mut ap, &sta)
        .into_iter()
        .find(|f| {
            dot11::strip_radiotap(f)
                .and_then(dot11::Dot11::parse)
                .is_some_and(|p| p.is_eapol())
        })
        .expect("the AP emits a fresh message 1");
    let reply = sta.handle_incoming(&m1);
    assert_eq!(
        reply.frames.len(),
        1,
        "the station answers a rekey message 1 with message 2"
    );

    // Neither peer may have moved off the old key yet: message 3 has not been
    // seen, so the candidate is unauthenticated. Installing at message 2 (and
    // resetting the packet number with it) is the key-reinstallation bug.
    assert_eq!(
        ap.station_tk(&sta_mac).expect("still keyed"),
        old_tk,
        "the AP holds the old PTK until message 4"
    );
    assert!(
        downlink_round_trips(&mut ap, &mut sta),
        "the station still decrypts under the old PTK after sending message 2"
    );
}

#[test]
fn a_forged_message_1_cannot_drop_or_wedge_an_established_session() {
    let (mut ap, mut net, mut sta) = wpa2_up();
    let sta_mac = sta.mac;
    let bssid = sta.bssid().expect("associated");
    let old_tk = ap.station_tk(&sta_mac).expect("pairwise key installed");

    // Message 1 carries no MIC, so anyone can inject one. This one claims a
    // replay counter no legitimate authenticator could ever exceed.
    let forged = dot11::build_eapol_m1_for_key_length(
        &bssid,
        &sta_mac,
        &[0xa5; 32],
        u64::MAX - 1,
        0,
        dot11::KeyMic::HmacSha1,
        16,
    );
    sta.handle_incoming(&framed(forged));

    assert_eq!(sta.connected, 4, "the session survives a forged message 1");
    assert!(
        downlink_round_trips(&mut ap, &mut sta),
        "the installed PTK still carries data after a forged message 1"
    );

    // And the forged counter must not have raised the replay bar: a genuine
    // rekey afterwards still completes. (Recording it would have locked the
    // station out of every future rekey until the AP gave up and deauthed.)
    let to_sta = start_ptk_rekey(&mut ap, &sta);
    pump(&mut ap, &mut net, &mut sta, to_sta);
    assert_eq!(sta.connected, 4);
    assert_ne!(
        ap.station_tk(&sta_mac).expect("still keyed"),
        old_tk,
        "a genuine rekey still completes after a forged message 1"
    );
    assert!(downlink_round_trips(&mut ap, &mut sta));
}

// ---------------------------------------------------------------------------
// Guards mirrored from the reference authenticator/supplicant: a re-delivered
// group key must not roll the receive replay window back, and a MIC-less
// pairwise key message must not be honoured in the clear once a PTK is
// installed under PMF.
// ---------------------------------------------------------------------------

/// Deliver a group-addressed frame under the AP's current GTK and report
/// whether the station accepted it.
fn group_frame_accepted(ap: &mut Ap, sta: &mut Client, payload: &[u8]) -> bool {
    let bssid = sta.bssid().expect("associated");
    let eth = [&[0xffu8; 6][..], bssid.as_slice(), &[0x08, 0x00], payload].concat();
    let frames = ap.deliver_to_station(&eth);
    frames.len() == 1 && sta.handle_incoming(&frames[0]).to_network == vec![eth]
}

#[test]
fn redelivering_the_same_gtk_does_not_roll_back_the_replay_window() {
    let (mut ap, _net, mut sta) = wpa3_up();

    // Capture a group frame the station has already accepted. Replaying it must
    // fail: its packet number is no longer ahead of the receive window.
    let bssid = sta.bssid().expect("associated");
    let eth = [
        &[0xffu8; 6][..],
        bssid.as_slice(),
        &[0x08, 0x00],
        b"group one",
    ]
    .concat();
    let captured = ap.deliver_to_station(&eth).remove(0);
    assert_eq!(sta.handle_incoming(&captured).to_network, vec![eth.clone()]);
    assert!(
        sta.handle_incoming(&captured).to_network.is_empty(),
        "a replayed group frame is rejected"
    );

    // Now the AP runs a Group Key Handshake that re-delivers the SAME GTK under
    // a fresh, properly MIC'd replay counter — which is exactly what the counter
    // checks cannot distinguish from a genuine rotation. The station must keep
    // its replay window rather than re-seed it from this message's RSC.
    let gtk_before = ap.gtk();
    let msgs = ap.test_rekey_gtk_without_rotation();
    assert_eq!(ap.gtk(), gtk_before, "the AP re-sent the same GTK");
    for m in &msgs {
        sta.handle_incoming(m);
    }
    assert_eq!(sta.gtk(), gtk_before, "station still holds that GTK");

    assert!(
        sta.handle_incoming(&captured).to_network.is_empty(),
        "the replay window must survive re-delivery of an unchanged GTK"
    );
    // Fresh group traffic still works, so the window was preserved, not frozen.
    assert!(group_frame_accepted(&mut ap, &mut sta, b"group two"));
}

#[test]
fn an_unprotected_rekey_message_1_is_ignored_once_a_ptk_is_installed_under_pmf() {
    let (mut ap, mut net, mut sta) = wpa3_up();
    let bssid = sta.bssid().expect("associated");

    // Under PMF the AP carries EAPOL inside protected data once keys exist, so a
    // plaintext MIC-less message 1 can only have been injected. Answering it
    // would let an off-path attacker churn the handshake state of a working
    // session (and clobber an in-flight rekey candidate).
    let forged = dot11::build_eapol_m1_for_key_length(
        &bssid,
        &sta.mac,
        &[0x5a; 32],
        u64::MAX - 1,
        0,
        dot11::KeyMic::AesCmac,
        16,
    );
    let out = sta.handle_incoming(&framed(forged));
    assert!(
        out.frames.is_empty(),
        "an unprotected message 1 must not be answered under PMF"
    );
    assert_eq!(sta.connected, 4, "and must not disturb the session");
    assert!(downlink_round_trips(&mut ap, &mut sta));
    assert!(uplink_round_trips(&mut ap, &mut sta));

    // The controlled port still works: a group rekey delivered over protected
    // data is processed normally.
    let _ = &mut net;
    let msgs = ap.rekey_gtk();
    for m in &msgs {
        sta.handle_incoming(m);
    }
    assert_eq!(
        sta.gtk(),
        ap.gtk(),
        "protected-port group rekey still works"
    );
}
