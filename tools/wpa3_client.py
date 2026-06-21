#!/usr/bin/env python3
"""
Independent Python WPA3-SAE station (stdio), to validate the Rust AP.

Drives: beacon -> SAE commit/confirm -> assoc -> SHA-256 4-way -> CCMP ping.
Prints AUTHENTICATED and PING_REPLY_OK to stderr on success.
"""
import os
import sys

import wpa3_common as C
from wpa3_common import (
    Dot11,
    Dot11Auth,
    Dot11Beacon,
    Dot11CCMP,
    EAPOL,
    Ether,
    RadioTap,
)
from scapy.layers.inet import IP, ICMP
from scapy.packet import Raw
import wpa3_sae as sae

SSID = os.environ.get("SSID", "turtlenet").encode()
PSK = os.environ.get("PSK", "password1234").encode()
MAC = os.environ.get("STA_MAC", "02:00:00:00:ab:cd")
AP_MAC = os.environ.get("AP_MAC", "02:00:00:00:00:00")
USE_HNP = os.environ.get("SAE_HNP") == "1"


class Client:
    def __init__(self):
        self.mac = MAC
        self.bssid = None
        self.connected = 0
        self.sae = None
        self.kck = self.kek = self.tk = b""
        self.gtk = b""
        self.igtk = None
        self.snonce = b""
        self.sc = 0
        self.client_pn = 1  # CCMP PN starts at 1

    def next_sc(self):
        self.sc = (self.sc + 1) % 4096
        return self.sc * 16

    def send(self, pkt):
        sys.stdout.buffer.write(C.frame_bytes(pkt))
        sys.stdout.buffer.flush()

    def start_sae(self, bssid):
        if USE_HNP:
            self.sae = sae.Sae.hunting_pecking(PSK, C.mac_b(self.mac), C.mac_b(bssid))
            status = 0
        else:
            self.sae = sae.Sae.h2e(SSID, PSK, C.mac_b(self.mac), C.mac_b(bssid))
            status = 126
        self.sae.prepare_commit()
        body = self.sae.write_commit()
        self.send(C.build_sae_auth(bssid, self.mac, bssid, True, self.next_sc(), 1, status, body))

    def recv(self, pkt):
        if not pkt.haslayer(Dot11):
            return
        d = pkt[Dot11]
        if d.addr2 == self.mac:
            return

        if self.connected == 0 and pkt.haslayer(Dot11Beacon):
            self.bssid = d.addr2
            self.connected = 1
            self.start_sae(self.bssid)
            return

        if pkt.haslayer(Dot11Auth) and d.addr1 == self.mac:
            algo, seq, status, payload = C.parse_auth(pkt)
            if algo != 3:
                return
            if seq == 1:
                if not self.sae.parse_peer_commit(payload) or not self.sae.process_commit():
                    return
                self.send(C.build_sae_auth(self.bssid, self.mac, self.bssid, True, self.next_sc(), 2, 0, self.sae.write_confirm()))
            elif seq == 2:
                if self.sae.check_confirm(payload):
                    self.send(C.build_assoc_req(self.bssid, self.mac, SSID, self.next_sc()))
            return

        from scapy.layers.dot11 import Dot11AssoResp

        if self.connected == 1 and pkt.haslayer(Dot11AssoResp):
            self.connected = 2
            return

        if self.connected >= 2 and pkt.haslayer(EAPOL) and d.addr1 == self.mac and d.FCfield & 0x3 == 0x2:
            ek = C.parse_eapol_key(pkt)
            if not ek.key_ack:
                return
            if not ek.encrypted_key_data:
                self.handle_m1(ek)
            else:
                self.handle_m3(pkt, ek)
            return

        if self.connected >= 4 and pkt.haslayer(Dot11CCMP) and d.FCfield & 0x43 == 0x42:
            eth = C.decrypt_ccmp(pkt, self.tk, from_ap=True)
            if eth and eth.haslayer(ICMP) and eth[ICMP].type == 0:
                print("PING_REPLY_OK", file=sys.stderr, flush=True)

    def handle_m1(self, ek):
        anonce = ek.key_nonce
        self.snonce = os.urandom(32)
        pmk = self.sae.pmk
        ptk = sae.derive_ptk_sha256(pmk, C.mac_b(self.bssid), C.mac_b(self.mac), anonce, self.snonce)
        self.kck, self.kek, self.tk = ptk[:16], ptk[16:32], ptk[32:48]
        self.client_pn = 1  # CCMP PN starts at 1
        self.send(C.build_m2(self.bssid, self.mac, self.snonce, self.kck, self.next_sc()))

    def handle_m3(self, pkt, ek):
        if not C.eapol_mic_ok(self.kck, pkt):
            print("M3_MIC_FAIL", file=sys.stderr, flush=True)
            return
        unwrapped = ccmp_unwrap(self.kek, ek.key)
        if unwrapped and len(unwrapped) >= 46:
            self.gtk = unwrapped[30:46]
            self.igtk = C.find_igtk(unwrapped)
        self.send(C.build_m4(self.bssid, self.mac, self.kck, self.next_sc()))
        self.connected = 4
        print("AUTHENTICATED", file=sys.stderr, flush=True)
        # send a ping
        ping = (
            Ether(src=self.mac, dst=AP_MAC, type=0x0800)
            / IP(src="10.10.10.2", dst="10.10.10.1")
            / ICMP(type=8, id=0x1234, seq=1)
            / Raw(b"py-wpa3-ping")
        )
        pn = self.client_pn
        self.client_pn += 1
        self.send(C.encrypt_ccmp(ping, self.tk, pn, self.bssid, self.mac, tods=True, sc=self.next_sc()))


def ccmp_unwrap(kek, wrapped):
    try:
        return C.ccmp.aes_unwrap(kek, wrapped)
    except Exception:
        return None


def main():
    import struct

    c = Client()
    buf = b""
    while True:
        data = os.read(0, 65536)  # returns available bytes; b"" on EOF
        if not data:
            break
        buf += data
        while len(buf) >= 4:
            wanted = struct.unpack("<L", buf[:4])[0]
            if len(buf) < 4 + wanted:
                break
            fr = buf[4 : 4 + wanted]
            buf = buf[4 + wanted :]
            try:
                c.recv(RadioTap(fr))
            except Exception as e:
                print("recv error: %r" % e, file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
