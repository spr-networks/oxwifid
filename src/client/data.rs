//! Protected uplink framing and small Ethernet/ICMP/ARP helpers.

use super::*;

impl Client {
    /// Encrypt and frame an Ethernet payload toward the AP (uplink, to-DS).
    pub fn encrypt_uplink(&mut self, eth: &[u8]) -> Option<Vec<u8>> {
        let bssid = self.bssid?;
        if self.connected < 4 || eth.len() < 14 {
            return None;
        }
        let mut dst = [0u8; 6];
        dst.copy_from_slice(&eth[0..6]);
        let ethertype = u16::from_be_bytes([eth[12], eth[13]]);
        let inner = &eth[14..];
        let pn = self.next_client_pn()?;
        let sc = self.next_sc();
        let tk = &self.pairwise_tk[..self.pairwise_cipher.key_len()];
        // QoS Data when WMM is on: force the test override TID if set, else
        // derive the user priority from the packet's DSCP. Plain Data otherwise.
        let qos_tid = if self.wmm_negotiated {
            Some(self.wmm_tid_override.unwrap_or_else(|| dot11::wmm_tid(eth)))
        } else {
            None
        };
        // 802.11be (MLO): the MAC header carries the link addresses so the frame
        // traverses link 0, but the CCMP nonce/AAD (and thus the AP's STA lookup)
        // must use the MLD addresses — the same basis the PTK was derived from in
        // the 4-way handshake (`ap_mld_mac` / `mld_mac`). Without this the AP
        // can't map the frame to the MLD STA and drops it as "not associated".
        let frame = if let (Some(mld), Some(ap_mld)) = (self.mld_mac, self.ap_mld_mac) {
            // Map each link address in the header to its MLD counterpart for the
            // security context (A1=AP, A2=STA, A3=DA — only the AP/STA link
            // addresses translate; a DA for some other device stays as-is).
            let sec_a1 = ap_mld; // RA: AP link0 BSSID -> AP MLD
            let sec_a2 = mld; // TA: STA link0 addr -> STA MLD
            let sec_a3 = if dst == bssid { ap_mld } else { dst };
            dot11::build_protected_data_sec(
                self.pairwise_cipher,
                &bssid,
                &self.mac,
                &dst,
                &sec_a1,
                &sec_a2,
                &sec_a3,
                dot11::FC_TODS | dot11::FC_PROTECTED,
                sc,
                pn,
                0,
                tk,
                ethertype,
                inner,
                qos_tid,
            )
        } else {
            dot11::build_protected_data_sec(
                self.pairwise_cipher,
                &bssid,
                &self.mac,
                &dst,
                &bssid,
                &self.mac,
                &dst,
                dot11::FC_TODS | dot11::FC_PROTECTED,
                sc,
                pn,
                0,
                tk,
                ethertype,
                inner,
                qos_tid,
            )
        };
        let mut f = dot11::RADIOTAP_TX.to_vec();
        f.extend_from_slice(&frame);
        Some(f)
    }

    /// Build a ping (ICMP echo) Ethernet frame from `src_ip` to `dst_ip` for the
    /// gateway MAC.
    pub fn build_ping(
        &self,
        dst_mac: &[u8; 6],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        tos: u8,
    ) -> Vec<u8> {
        let mut icmp = vec![8u8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01];
        icmp.extend_from_slice(b"barely-ap-rust-ping");
        let ck = inet_checksum(&icmp);
        icmp[2..4].copy_from_slice(&ck.to_be_bytes());

        let total = 20 + icmp.len();
        let mut ip = Vec::with_capacity(total);
        // `tos` carries the DSCP (DSCP << 2) so the WMM classifier can derive UP.
        ip.extend_from_slice(&[0x45, tos]);
        ip.extend_from_slice(&(total as u16).to_be_bytes());
        ip.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 64, 1, 0, 0]);
        ip.extend_from_slice(&src_ip);
        ip.extend_from_slice(&dst_ip);
        let ipck = inet_checksum(&ip);
        ip[10..12].copy_from_slice(&ipck.to_be_bytes());
        ip.extend_from_slice(&icmp);

        let mut eth = Vec::with_capacity(14 + ip.len());
        eth.extend_from_slice(dst_mac);
        eth.extend_from_slice(&self.mac);
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        eth
    }

    /// If `req_eth` is an ARP request for `my_ip`, build the ARP reply Ethernet
    /// frame (sender = us). The AP's kernel ARPs for our IP before it can route
    /// the ICMP echo *reply* back to us, so without this the ping never returns.
    pub fn build_arp_reply(&self, req_eth: &[u8], my_ip: [u8; 4]) -> Option<Vec<u8>> {
        if req_eth.len() < 14 + 28 || req_eth[12..14] != [0x08, 0x06] {
            return None; // not ARP
        }
        let arp = &req_eth[14..14 + 28];
        if arp[0..2] != [0x00, 0x01] || arp[2..4] != [0x08, 0x00] || arp[6..8] != [0x00, 0x01] {
            return None; // not an Ethernet/IPv4 ARP *request*
        }
        if arp[24..28] != my_ip {
            return None; // not asking for our IP
        }
        let sender_mac = &arp[8..14];
        let sender_ip = &arp[14..18];
        let mut eth = Vec::with_capacity(42);
        eth.extend_from_slice(sender_mac); // dst = requester
        eth.extend_from_slice(&self.mac); // src = us
        eth.extend_from_slice(&[0x08, 0x06]); // ARP
        eth.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02]); // reply
        eth.extend_from_slice(&self.mac); // sender hw = us
        eth.extend_from_slice(&my_ip); // sender ip = us
        eth.extend_from_slice(sender_mac); // target hw = requester
        eth.extend_from_slice(sender_ip); // target ip = requester
        Some(eth)
    }
}
