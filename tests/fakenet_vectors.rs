//! Feed scapy-built DHCP/ARP/ICMP requests to the Rust `FakeNet` and validate
//! the replies are well-formed (correct fields and checksums) so a real client's
//! stack accepts them.

use barely_ap::fakenet::FakeNet;
use barely_ap::util::{from_hex, mac_to_bytes};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors.json")).expect("vectors.json parses")
}

fn new_net() -> FakeNet {
    FakeNet::new(mac_to_bytes("02:00:00:00:00:00"), [10, 10, 10, 1])
}

/// Internet checksum over a slice; a valid header/segment sums to 0xFFFF.
fn inet_sum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16
}

struct Eth<'a> {
    dst: &'a [u8],
    src: &'a [u8],
    ethertype: u16,
    payload: &'a [u8],
}

fn parse_eth(frame: &[u8]) -> Eth<'_> {
    Eth {
        dst: &frame[0..6],
        src: &frame[6..12],
        ethertype: u16::from_be_bytes([frame[12], frame[13]]),
        payload: &frame[14..],
    }
}

#[test]
fn dhcp_discover_yields_offer() {
    let v = vectors();
    let eth = from_hex(v["net"]["dhcp_discover"]["eth"].as_str().unwrap());
    let mut net = new_net();
    let replies = net.input(&eth);
    assert_eq!(replies.len(), 1, "discover must yield an offer");

    let e = parse_eth(&replies[0]);
    assert_eq!(e.dst, mac_to_bytes("02:00:00:00:ab:cd"));
    assert_eq!(e.src, mac_to_bytes("02:00:00:00:00:00"));
    assert_eq!(e.ethertype, 0x0800);

    let ip = e.payload;
    assert_eq!(ip[0] >> 4, 4, "IPv4");
    let ihl = (ip[0] & 0x0f) as usize * 4;
    assert_eq!(inet_sum(&ip[..ihl]), 0xFFFF, "IP header checksum valid");
    assert_eq!(ip[9], 17, "UDP");

    let udp = &ip[ihl..];
    assert_eq!(u16::from_be_bytes([udp[0], udp[1]]), 67, "src port 67");
    assert_eq!(u16::from_be_bytes([udp[2], udp[3]]), 68, "dst port 68");

    let bootp = &udp[8..];
    assert_eq!(bootp[0], 2, "BOOTREPLY");
    assert_eq!(&bootp[16..20], &[10, 10, 10, 2], "yiaddr 10.10.10.2");
    // magic cookie + options
    assert_eq!(&bootp[236..240], &[0x63, 0x82, 0x53, 0x63]);
    let opts = &bootp[240..];
    assert_eq!(&opts[0..3], &[53, 1, 2], "DHCP message-type = OFFER");
}

#[test]
fn dhcp_request_yields_ack_same_ip() {
    let v = vectors();
    let mut net = new_net();
    // discover first so the lease is the same, then request
    net.input(&from_hex(
        v["net"]["dhcp_discover"]["eth"].as_str().unwrap(),
    ));
    let replies = net.input(&from_hex(v["net"]["dhcp_request"]["eth"].as_str().unwrap()));
    assert_eq!(replies.len(), 1);
    let e = parse_eth(&replies[0]);
    let ip = e.payload;
    let ihl = (ip[0] & 0x0f) as usize * 4;
    let bootp = &ip[ihl..][8..];
    assert_eq!(&bootp[16..20], &[10, 10, 10, 2], "ack keeps 10.10.10.2");
    let opts = &bootp[240..];
    assert_eq!(&opts[0..3], &[53, 1, 5], "DHCP message-type = ACK");
}

#[test]
fn arp_who_has_gateway_is_answered() {
    let v = vectors();
    let mut net = new_net();
    let replies = net.input(&from_hex(
        v["net"]["arp_who_has_gw"]["eth"].as_str().unwrap(),
    ));
    assert_eq!(replies.len(), 1);
    let e = parse_eth(&replies[0]);
    assert_eq!(e.ethertype, 0x0806);
    let arp = e.payload;
    assert_eq!(u16::from_be_bytes([arp[6], arp[7]]), 2, "ARP reply");
    assert_eq!(
        &arp[8..14],
        &mac_to_bytes("02:00:00:00:00:00"),
        "gateway MAC"
    );
    assert_eq!(&arp[14..18], &[10, 10, 10, 1], "gateway IP");
    assert_eq!(
        &arp[18..24],
        &mac_to_bytes("02:00:00:00:ab:cd"),
        "target = requester"
    );
}

#[test]
fn icmp_echo_to_gateway_is_answered() {
    let v = vectors();
    let mut net = new_net();
    let replies = net.input(&from_hex(v["net"]["icmp_echo_gw"]["eth"].as_str().unwrap()));
    assert_eq!(replies.len(), 1);
    let e = parse_eth(&replies[0]);
    assert_eq!(e.ethertype, 0x0800);
    let ip = e.payload;
    let ihl = (ip[0] & 0x0f) as usize * 4;
    assert_eq!(inet_sum(&ip[..ihl]), 0xFFFF, "IP checksum valid");
    assert_eq!(&ip[12..16], &[10, 10, 10, 1], "reply src = gateway");
    assert_eq!(&ip[16..20], &[10, 10, 10, 2], "reply dst = station");

    let icmp = &ip[ihl..];
    assert_eq!(icmp[0], 0, "echo reply");
    assert_eq!(inet_sum(icmp), 0xFFFF, "ICMP checksum valid");
    let id = u16::from_be_bytes([icmp[4], icmp[5]]);
    let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
    assert_eq!(id as u64, v["net"]["icmp_echo_gw"]["id"].as_u64().unwrap());
    assert_eq!(
        seq as u64,
        v["net"]["icmp_echo_gw"]["seq"].as_u64().unwrap()
    );
    assert_eq!(&icmp[8..18], b"abcdefghij", "payload echoed");
}

#[test]
fn unknown_destination_gets_unreachable() {
    // ICMP echo to an unknown host -> ICMP destination unreachable
    let mut net = new_net();
    let mut eth = Vec::new();
    eth.extend_from_slice(&mac_to_bytes("02:00:00:00:00:00")); // dst AP
    eth.extend_from_slice(&mac_to_bytes("02:00:00:00:ab:cd")); // src STA
    eth.extend_from_slice(&[0x08, 0x00]);
    // IP header
    let mut ip = vec![0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 64, 1, 0, 0];
    ip.extend_from_slice(&[10, 10, 10, 2]); // src
    ip.extend_from_slice(&[10, 10, 10, 99]); // dst (unknown)
    let mut icmp = vec![8, 0, 0, 0, 0x11, 0x11, 0, 1];
    icmp.extend_from_slice(b"x");
    ip.extend_from_slice(&icmp);
    let total = ip.len() as u16;
    ip[2..4].copy_from_slice(&total.to_be_bytes());
    eth.extend_from_slice(&ip);

    let replies = net.input(&eth);
    assert_eq!(replies.len(), 1);
    let e = parse_eth(&replies[0]);
    let rip = e.payload;
    let ihl = (rip[0] & 0x0f) as usize * 4;
    assert_eq!(rip[ihl], 3, "ICMP type 3 (destination unreachable)");
}
