//! GTK rekeying via the Group Key Handshake (hostapd `wpa_group_rekey`).

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
    assert_eq!(sta.gtk(), old_gtk, "STA has the original GTK after the handshake");
    let old_igtk = sta.igtk().unwrap();

    // AP rotates the GTK and runs the Group Key Handshake.
    let msgs = ap.rekey_gtk();
    assert_eq!(msgs.len(), 1, "one Group Key message 1 per associated station");
    let new_gtk = ap.gtk();
    assert_ne!(new_gtk, old_gtk, "AP rotated the GTK");

    // The STA processes message 1, installs the new GTK/IGTK, and replies.
    let out = sta.handle_incoming(&msgs[0]);
    assert_eq!(sta.gtk(), new_gtk, "STA installed the rotated GTK");
    assert_ne!(sta.igtk().unwrap(), old_igtk, "STA installed the rotated IGTK");
    assert_eq!(out.frames.len(), 1, "STA sends Group Key message 2");
    assert_eq!(sta.connected, 4, "STA stays associated across a rekey");
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
    assert_eq!(sta.gtk(), old_gtk, "a tampered Group Key message must not install a GTK");
}

#[test]
fn ap_processes_group_msg2_and_coalesces_rekeys() {
    let (mut ap, _net, mut sta) = wpa3_up();
    // First rekey: one msg 1; the station is now awaiting its msg 2 ACK.
    let msgs = ap.rekey_gtk();
    assert_eq!(msgs.len(), 1);
    // A second rekey while the first is still in flight is coalesced to nothing
    // (hostapd waits for GKeyDoneStations to reach 0 before starting another).
    assert!(ap.rekey_gtk().is_empty(), "rekey coalesces while one is in flight");
    // The station ACKs (msg 2); feed it back to the AP, which clears its state.
    let reply = sta.handle_incoming(&msgs[0]);
    assert_eq!(reply.frames.len(), 1, "station emits Group Key msg 2");
    ap.handle_incoming(&reply.frames[0]);
    // With every station's msg 2 in, a fresh rekey is permitted again.
    assert_eq!(ap.rekey_gtk().len(), 1, "rekey allowed again once all msg 2s are in");
}

#[test]
fn periodic_group_rekey_fires_on_tick() {
    let (mut ap, _net, mut sta) = wpa3_up();
    // Well inside a long interval, tick must not rekey.
    ap.set_group_rekey(3600);
    assert!(ap.tick().frames.is_empty(), "no rekey well before the interval");
    // Age the clock past a short interval and the next tick performs the rekey.
    ap.set_group_rekey(1);
    let old = ap.gtk();
    ap.test_expire_group_rekey();
    let out = ap.tick();
    assert_ne!(ap.gtk(), old, "periodic wpa_group_rekey rotated the GTK on tick");
    for f in &out.frames {
        sta.handle_incoming(f);
    }
    assert_eq!(sta.gtk(), ap.gtk(), "station installed the periodically-rotated GTK");
}

#[test]
fn disabling_periodic_rekey_stops_it() {
    let (mut ap, _net, _sta) = wpa3_up();
    ap.set_group_rekey(0); // disabled
    let old = ap.gtk();
    ap.test_expire_group_rekey();
    ap.tick();
    assert_eq!(ap.gtk(), old, "wpa_group_rekey=0 disables periodic group rekeying");
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
    assert_ne!(ap.gtk(), old, "strict rekey rotated the GTK after an authorized STA left");
    for f in &out.frames {
        b.handle_incoming(f);
    }
    assert_eq!(b.gtk(), ap.gtk(), "the remaining station installed the rotated GTK");
}

#[test]
fn no_strict_rekey_when_last_station_leaves() {
    let (mut ap, _net, _sta) = wpa3_up();
    let old = ap.gtk();
    // The only station leaves — no one remains to protect, so no rekey.
    ap.kick(&mac_to_bytes("02:00:00:00:ab:cd"));
    ap.tick();
    assert_eq!(ap.gtk(), old, "no strict rekey when the last station leaves");
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
    assert_ne!(a_gtk0, b_gtk0, "per-STA-VIF: stations have distinct GTK values");
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
    assert_ne!(a_gtk1, b_gtk1, "isolation preserved: rotated values still differ");
    // The per-station GTK index is a fixed constant (1): it does NOT toggle on
    // rekey — only each station's own value rotates (above). The isolation is the
    // distinct values, never a per-station or a moving index.
    assert_eq!(ap.station_gtk_key_id(&a_mac), 1, "index stays at constant 1 after rekey");
    assert_eq!(ap.station_gtk_key_id(&b_mac), 1, "index stays at constant 1 after rekey");
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
    assert_ne!(a.gtk(), b.gtk(), "post-rekey, the two stations still hold different GTKs");
}
