//! NAN USD (Wi-Fi Aware service discovery) tests.

use barely_ap::nan::{self, NanDe, NanEvent};
use barely_ap::util::{mac_to_bytes, to_hex};

#[test]
fn service_id_is_sha256_of_lowercased_name() {
    // SHA-256("foo") = 2c26b46b68ff... -> first 6 bytes is the service id.
    assert_eq!(to_hex(&nan::service_id("foo")), "2c26b46b68ff");
    // case-insensitive
    assert_eq!(nan::service_id("Wi-Fi_Aware"), nan::service_id("wi-fi_aware"));
    // distinct names differ
    assert_ne!(nan::service_id("serviceA"), nan::service_id("serviceB"));
}

#[test]
fn sdf_build_parse_roundtrip() {
    let sid = nan::service_id("_chat");
    let ssi = b"hello-world";
    let body = nan::build_sdf(nan::NAN_SRV_CTRL_PUBLISH, &sid, 7, 0, Some(ssi), 2);

    // Byte-for-byte match against the hostap SDF layout (verified via Python).
    assert_eq!(
        to_hex(&body),
        "0409506f9a1303090079ff4a94ed190700000e14000700000f00506f9a0268656c6c6f2d776f726c64"
    );

    // Public Action + NAN vendor type header
    assert_eq!(body[0], nan::WLAN_ACTION_PUBLIC);
    assert_eq!(body[1], nan::WLAN_PA_VENDOR_SPECIFIC);
    assert_eq!(u32::from_be_bytes([body[2], body[3], body[4], body[5]]), nan::NAN_SDF_VENDOR_TYPE);

    let descriptors = nan::parse_sdf(&body).expect("parse");
    assert_eq!(descriptors.len(), 1);
    let d = &descriptors[0];
    assert_eq!(d.service_id, sid);
    assert_eq!(d.instance_id, 7);
    assert_eq!(d.ctrl_type(), nan::NAN_SRV_CTRL_PUBLISH);
    assert_eq!(d.service_info.as_deref(), Some(&ssi[..]));
}

#[test]
fn parse_rejects_non_nan_action() {
    // wrong vendor type
    let mut body = nan::build_sdf(nan::NAN_SRV_CTRL_SUBSCRIBE, &nan::service_id("x"), 1, 0, None, 2);
    body[2] ^= 0xff;
    assert!(nan::parse_sdf(&body).is_none());
}

#[test]
fn passive_subscriber_discovers_publisher() {
    let pub_mac = mac_to_bytes("02:00:00:00:00:01");
    let sub_mac = mac_to_bytes("02:00:00:00:00:02");
    let mut publisher = NanDe::new(pub_mac);
    let mut subscriber = NanDe::new(sub_mac);

    let pub_inst = publisher.publish("_camera._nan", Some(b"model=X100"));
    subscriber.subscribe("_camera._nan");

    // publisher broadcasts; subscriber processes and discovers
    let mut discovered = None;
    for f in publisher.periodic_frames() {
        let (events, _) = subscriber.process_frame(&f);
        for e in events {
            if let NanEvent::Discovered { peer, peer_instance, service_info, .. } = e {
                discovered = Some((peer, peer_instance, service_info));
            }
        }
    }
    let (peer, peer_instance, info) = discovered.expect("subscriber must discover the published service");
    assert_eq!(peer, pub_mac);
    assert_eq!(peer_instance, pub_inst);
    assert_eq!(info.as_deref(), Some(&b"model=X100"[..]));
}

#[test]
fn active_subscribe_triggers_solicited_publish_and_followup() {
    let pub_mac = mac_to_bytes("02:00:00:00:00:01");
    let sub_mac = mac_to_bytes("02:00:00:00:00:02");
    let mut publisher = NanDe::new(pub_mac);
    let mut subscriber = NanDe::new(sub_mac);

    publisher.publish("_printer._nan", Some(b"loc=lab"));
    let sub_inst = subscriber.subscribe("_printer._nan");

    // subscriber actively broadcasts a Subscribe SDF
    let mut solicited = Vec::new();
    for f in subscriber.periodic_frames() {
        let (events, responses) = publisher.process_frame(&f);
        assert!(events.iter().any(|e| matches!(e, NanEvent::SubscribeReceived { .. })), "publisher must see the subscribe");
        solicited.extend(responses);
    }
    assert!(!solicited.is_empty(), "publisher must answer with a solicited publish");

    // subscriber processes the solicited publish -> discovery
    let mut peer_inst = None;
    for f in &solicited {
        let (events, _) = subscriber.process_frame(f);
        for e in events {
            if let NanEvent::Discovered { peer_instance, .. } = e {
                peer_inst = Some(peer_instance);
            }
        }
    }
    let peer_inst = peer_inst.expect("subscriber discovers via solicited publish");

    // subscriber sends a Follow-up to the publisher's instance
    let sid = nan::service_id("_printer._nan");
    let fu = subscriber.followup(pub_mac, peer_inst, sub_inst, &sid, b"print job 42");
    let (events, _) = publisher.process_frame(&fu);
    assert!(
        events.iter().any(|e| matches!(e, NanEvent::FollowupReceived { service_info, .. } if service_info.as_deref() == Some(&b"print job 42"[..]))),
        "publisher must receive the follow-up payload"
    );
}

#[test]
fn no_match_for_unrelated_service() {
    let mut publisher = NanDe::new(mac_to_bytes("02:00:00:00:00:01"));
    let mut subscriber = NanDe::new(mac_to_bytes("02:00:00:00:00:02"));
    publisher.publish("_serviceA", None);
    subscriber.subscribe("_serviceB");
    for f in publisher.periodic_frames() {
        let (events, _) = subscriber.process_frame(&f);
        assert!(events.is_empty(), "different service names must not match");
    }
}
