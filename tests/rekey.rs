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
