//! A self-contained fake IP network, ported (and de-bugged) from
//! `fakenet.py`'s `ScapyNetwork`.
//!
//! It consumes decrypted Ethernet frames from associated stations and answers
//! the bare minimum for a real client to come up: DHCP (offer/ack), ARP for the
//! gateway, and ICMP echo to the gateway. Anything else gets an ICMP
//! destination-unreachable, like the reference.

use std::collections::HashMap;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const IP_PROTO_ICMP: u8 = 1;
const IP_PROTO_UDP: u8 = 17;

pub struct FakeNet {
    pub mac: [u8; 6],
    pub ip: [u8; 4],
    subnet: [u8; 3],
    leases: HashMap<[u8; 6], [u8; 4]>,
    next_host: u8,
    ip_id: u16,
}

fn checksum16(data: &[u8]) -> u16 {
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
    !(sum as u16)
}

fn be16(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

impl FakeNet {
    pub fn new(mac: [u8; 6], ip: [u8; 4]) -> FakeNet {
        FakeNet {
            mac,
            ip,
            subnet: [ip[0], ip[1], ip[2]],
            leases: HashMap::new(),
            next_host: 2, // .1 is the gateway/AP
            ip_id: 0x1000,
        }
    }

    fn lease_for(&mut self, mac: [u8; 6]) -> [u8; 4] {
        if let Some(ip) = self.leases.get(&mac) {
            return *ip;
        }
        let host = self.next_host;
        self.next_host = self.next_host.wrapping_add(1).max(2);
        let ip = [self.subnet[0], self.subnet[1], self.subnet[2], host];
        self.leases.insert(mac, ip);
        ip
    }

    fn mac_for_ip(&self, ip: &[u8; 4]) -> Option<[u8; 6]> {
        if *ip == self.ip {
            return Some(self.mac);
        }
        self.leases.iter().find(|(_, v)| *v == ip).map(|(k, _)| *k)
    }

    /// Process one inbound Ethernet frame, returning any reply frames.
    pub fn input(&mut self, eth: &[u8]) -> Vec<Vec<u8>> {
        if eth.len() < 14 {
            return vec![];
        }
        let mut src_mac = [0u8; 6];
        src_mac.copy_from_slice(&eth[6..12]);
        let ethertype = u16::from_be_bytes([eth[12], eth[13]]);
        let payload = &eth[14..];

        match ethertype {
            ETHERTYPE_ARP => self.handle_arp(&src_mac, payload),
            ETHERTYPE_IPV4 => self.handle_ipv4(&src_mac, payload),
            _ => vec![],
        }
    }

    fn handle_arp(&mut self, src_mac: &[u8; 6], arp: &[u8]) -> Vec<Vec<u8>> {
        if arp.len() < 28 {
            return vec![];
        }
        let op = u16::from_be_bytes([arp[6], arp[7]]);
        if op != 1 {
            return vec![]; // only who-has
        }
        let mut spa = [0u8; 4];
        let mut tpa = [0u8; 4];
        spa.copy_from_slice(&arp[14..18]);
        tpa.copy_from_slice(&arp[24..28]);
        let Some(target_mac) = self.mac_for_ip(&tpa) else {
            return vec![];
        };

        // ARP reply: op=2, sha=target_mac, spa=tpa, tha=src_mac, tpa=spa
        let mut a = Vec::with_capacity(28);
        a.extend_from_slice(&be16(1)); // htype ethernet
        a.extend_from_slice(&be16(ETHERTYPE_IPV4)); // ptype
        a.push(6); // hlen
        a.push(4); // plen
        a.extend_from_slice(&be16(2)); // op reply
        a.extend_from_slice(&target_mac);
        a.extend_from_slice(&tpa);
        a.extend_from_slice(src_mac);
        a.extend_from_slice(&spa);

        vec![self.ethernet(src_mac, &target_mac, ETHERTYPE_ARP, &a)]
    }

    fn handle_ipv4(&mut self, src_mac: &[u8; 6], ip: &[u8]) -> Vec<Vec<u8>> {
        if ip.len() < 20 {
            return vec![];
        }
        let ihl = (ip[0] & 0x0F) as usize * 4;
        if ip.len() < ihl {
            return vec![];
        }
        let proto = ip[9];
        let mut src_ip = [0u8; 4];
        let mut dst_ip = [0u8; 4];
        src_ip.copy_from_slice(&ip[12..16]);
        dst_ip.copy_from_slice(&ip[16..20]);
        let l4 = &ip[ihl..];

        match proto {
            IP_PROTO_UDP => self.handle_udp(src_mac, &src_ip, &dst_ip, l4),
            IP_PROTO_ICMP => self.handle_icmp(src_mac, &src_ip, &dst_ip, l4),
            _ => self.icmp_unreachable(src_mac, &src_ip, ip),
        }
    }

    fn handle_udp(&mut self, src_mac: &[u8; 6], src_ip: &[u8; 4], dst_ip: &[u8; 4], udp: &[u8]) -> Vec<Vec<u8>> {
        if udp.len() < 8 {
            return vec![];
        }
        let dport = u16::from_be_bytes([udp[2], udp[3]]);
        let body = &udp[8..];
        // DHCP runs over UDP/67
        if dport == 67 {
            return self.handle_dhcp(src_mac, body);
        }
        // otherwise reject
        self.icmp_unreachable(src_mac, src_ip, &self.rebuild_ip(src_ip, dst_ip, IP_PROTO_UDP, udp))
    }

    fn handle_dhcp(&mut self, src_mac: &[u8; 6], bootp: &[u8]) -> Vec<Vec<u8>> {
        // BOOTP: op(1) htype(1) hlen(1) hops(1) xid(4) ... chaddr at 28..44,
        // then magic cookie (236..240) and options.
        if bootp.len() < 240 {
            return vec![];
        }
        if bootp[0] != 1 {
            return vec![]; // only BOOTREQUEST
        }
        let mut xid = [0u8; 4];
        xid.copy_from_slice(&bootp[4..8]);

        // find DHCP message-type option (53)
        let msg_type = parse_dhcp_msg_type(&bootp[240..]);
        let reply_type = match msg_type {
            Some(1) => 2, // DISCOVER -> OFFER
            Some(3) => 5, // REQUEST  -> ACK
            _ => return vec![],
        };

        let yiaddr = self.lease_for(*src_mac);
        let server = self.ip;

        // Build BOOTP reply
        let mut b = vec![0u8; 240];
        b[0] = 2; // BOOTREPLY
        b[1] = 1; // htype ethernet
        b[2] = 6; // hlen
        b[3] = 0;
        b[4..8].copy_from_slice(&xid);
        // yiaddr (16..20), siaddr (20..24)
        b[16..20].copy_from_slice(&yiaddr);
        b[20..24].copy_from_slice(&server);
        b[28..34].copy_from_slice(src_mac); // chaddr
        // magic cookie
        b[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);

        // options
        let mut opts: Vec<u8> = Vec::new();
        opts.extend_from_slice(&[53, 1, reply_type]); // message type
        opts.extend_from_slice(&[54, 4]); // server id
        opts.extend_from_slice(&server);
        opts.extend_from_slice(&[1, 4, 255, 255, 255, 0]); // subnet mask /24
        opts.extend_from_slice(&[3, 4]); // router
        opts.extend_from_slice(&server);
        opts.extend_from_slice(&[6, 4]); // dns
        opts.extend_from_slice(&server);
        opts.extend_from_slice(&[51, 4, 0, 0, 0x05, 0x39]); // lease 1337s
        opts.extend_from_slice(&[28, 4, self.subnet[0], self.subnet[1], self.subnet[2], 255]); // broadcast
        opts.push(255); // end
        b.extend_from_slice(&opts);

        // UDP 67 -> 68, IP server -> 255.255.255.255, Eth -> client
        let udp = build_udp(67, 68, &b);
        let ip = self.build_ip(&self.ip, &[255, 255, 255, 255], IP_PROTO_UDP, &udp);
        vec![self.ethernet(src_mac, &self.mac.clone(), ETHERTYPE_IPV4, &ip)]
    }

    fn handle_icmp(&mut self, src_mac: &[u8; 6], src_ip: &[u8; 4], dst_ip: &[u8; 4], icmp: &[u8]) -> Vec<Vec<u8>> {
        if icmp.len() < 8 {
            return vec![];
        }
        // only echo request (type 8)
        if icmp[0] != 8 {
            return vec![];
        }
        // Only answer for IPs we own / have leased.
        let Some(reply_src_mac) = self.mac_for_ip(dst_ip) else {
            return self.icmp_unreachable(src_mac, src_ip, &self.rebuild_ip(src_ip, dst_ip, IP_PROTO_ICMP, icmp));
        };
        let reply_src_ip = *dst_ip;

        // echo reply: type 0, copy id/seq/data
        let mut reply = Vec::with_capacity(icmp.len());
        reply.push(0); // echo reply
        reply.push(0); // code
        reply.extend_from_slice(&[0, 0]); // checksum placeholder
        reply.extend_from_slice(&icmp[4..]); // id, seq, data
        let ck = checksum16(&reply);
        reply[2..4].copy_from_slice(&be16(ck));

        let ip = self.build_ip(&reply_src_ip, src_ip, IP_PROTO_ICMP, &reply);
        vec![self.ethernet(src_mac, &reply_src_mac, ETHERTYPE_IPV4, &ip)]
    }

    fn icmp_unreachable(&self, src_mac: &[u8; 6], src_ip: &[u8; 4], orig_ip_packet: &[u8]) -> Vec<Vec<u8>> {
        // ICMP type 3 code 1 (host unreachable), echoing up to 28 bytes of the
        // offending IP header+payload.
        let mut reply = Vec::new();
        reply.push(3);
        reply.push(1);
        reply.extend_from_slice(&[0, 0]); // checksum
        reply.extend_from_slice(&[0, 0, 0, 0]); // unused
        let n = orig_ip_packet.len().min(28);
        reply.extend_from_slice(&orig_ip_packet[..n]);
        let ck = checksum16(&reply);
        reply[2..4].copy_from_slice(&be16(ck));

        let ip = self.build_ip(&self.ip, src_ip, IP_PROTO_ICMP, &reply);
        vec![self.ethernet(src_mac, &self.mac, ETHERTYPE_IPV4, &ip)]
    }

    // -- builders ----------------------------------------------------------

    fn build_ip(&self, src: &[u8; 4], dst: &[u8; 4], proto: u8, payload: &[u8]) -> Vec<u8> {
        let total_len = 20 + payload.len();
        let mut h = Vec::with_capacity(total_len);
        h.push(0x45); // version 4, IHL 5
        h.push(0x00); // DSCP/ECN
        h.extend_from_slice(&be16(total_len as u16));
        // id changes per packet; use a fixed-ish counter derived from state
        h.extend_from_slice(&be16(self.ip_id));
        h.extend_from_slice(&be16(0x0000)); // flags/frag
        h.push(64); // TTL
        h.push(proto);
        h.extend_from_slice(&[0, 0]); // checksum placeholder
        h.extend_from_slice(src);
        h.extend_from_slice(dst);
        let ck = checksum16(&h);
        h[10..12].copy_from_slice(&be16(ck));
        h.extend_from_slice(payload);
        h
    }

    fn rebuild_ip(&self, src: &[u8; 4], dst: &[u8; 4], proto: u8, payload: &[u8]) -> Vec<u8> {
        self.build_ip(src, dst, proto, payload)
    }

    fn ethernet(&self, dst: &[u8; 6], src: &[u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut e = Vec::with_capacity(14 + payload.len());
        e.extend_from_slice(dst);
        e.extend_from_slice(src);
        e.extend_from_slice(&be16(ethertype));
        e.extend_from_slice(payload);
        e
    }
}

fn build_udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let len = 8 + payload.len();
    let mut u = Vec::with_capacity(len);
    u.extend_from_slice(&be16(sport));
    u.extend_from_slice(&be16(dport));
    u.extend_from_slice(&be16(len as u16));
    u.extend_from_slice(&be16(0)); // checksum 0 = not computed (valid for IPv4)
    u.extend_from_slice(payload);
    u
}

fn parse_dhcp_msg_type(opts: &[u8]) -> Option<u8> {
    let mut i = 0;
    while i < opts.len() {
        let code = opts[i];
        if code == 255 {
            break;
        }
        if code == 0 {
            i += 1;
            continue;
        }
        if i + 1 >= opts.len() {
            break;
        }
        let len = opts[i + 1] as usize;
        if i + 2 + len > opts.len() {
            break;
        }
        if code == 53 && len >= 1 {
            return Some(opts[i + 2]);
        }
        i += 2 + len;
    }
    None
}
