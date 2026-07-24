#!/usr/bin/env python3
"""
Independent Python WPA3-SAE access point (stdio), to validate the Rust station.

Beacons; handles SAE (H2E and hunting-and-pecking, chosen by the STA's commit
status); association; the SHA-256 4-way (delivering GTK + IGTK); and answers an
ICMP echo to the gateway so the STA's ping round-trips.
"""
import os
import select
import struct
import sys
import time

import wpa3_common as C
from wpa3_common import Dot11, Dot11Auth, Dot11AssoReq, Dot11CCMP, EAPOL, Ether, RadioTap
from scapy.layers.inet import IP, ICMP
from scapy.packet import Raw
import wpa3_sae as sae

SSID = os.environ.get("SSID", "turtlenet").encode()
PSK = os.environ.get("PSK", "password1234").encode()
AP_MAC = os.environ.get("AP_MAC", "02:00:00:00:00:00")
GW_IP = "10.10.10.1"


class Station:
    def __init__(self, mac):
        self.mac = mac
        self.sae = None
        self.pmk = b""
        self.anonce = os.urandom(32)
        self.kck = self.kek = self.tk = b""
        self.associated = False
        self.pn = 1  # CCMP PN starts at 1


class AP:
    def __init__(self):
        self.mac = AP_MAC
        self.sc = 0
        self.aid = 0
        self.gtk = os.urandom(16)
        self.igtk = os.urandom(16)
        self.stations = {}
        self.boottime = time.time()

    def next_sc(self):
        self.sc = (self.sc + 1) % 4096
        return self.sc * 16

    def send(self, pkt):
        sys.stdout.buffer.write(C.frame_bytes(pkt))
        sys.stdout.buffer.flush()

    def beacon(self):
        ts = int((time.time() - self.boottime) * 1e6) & 0xFFFFFFFFFFFFFFFF
        self.send(C.build_beacon(self.mac, SSID, 0, ts))

    def recv(self, pkt):
        if not pkt.haslayer(Dot11):
            return
        d = pkt[Dot11]
        a1 = d.addr1
        if a1 != self.mac and a1 != "ff:ff:ff:ff:ff:ff":
            return

        if pkt.haslayer(Dot11Auth):
            self.handle_sae(pkt)
        elif pkt.haslayer(Dot11AssoReq):
            self.handle_assoc(pkt)
        elif pkt.haslayer(EAPOL) and d.FCfield & 0x3 == 0x1:
            self.handle_m2(pkt)
        elif pkt.haslayer(Dot11CCMP) and d.FCfield & 0x43 == 0x41:
            self.handle_data(pkt)

    def handle_sae(self, pkt):
        d = pkt[Dot11]
        sta = d.addr2
        algo, seq, status, payload = C.parse_auth(pkt)
        if algo != 3:
            return
        if seq == 1:
            h2e = status == 126
            if h2e:
                s = sae.Sae.h2e(SSID, PSK, C.mac_b(self.mac), C.mac_b(sta))
            else:
                s = sae.Sae.hunting_pecking(PSK, C.mac_b(self.mac), C.mac_b(sta))
            if s is None or not s.parse_peer_commit(payload):
                return
            s.prepare_commit()
            if not s.process_commit():
                return
            st = self.stations.setdefault(sta, Station(sta))
            st.sae = s
            st.pmk = s.pmk
            self.send(C.build_sae_auth(sta, self.mac, self.mac, False, self.next_sc(), 1, 126 if h2e else 0, s.write_commit()))
            self.send(C.build_sae_auth(sta, self.mac, self.mac, False, self.next_sc(), 2, 0, s.write_confirm()))
        elif seq == 2:
            st = self.stations.get(sta)
            if st and st.sae and st.sae.check_confirm(payload):
                pass  # confirmed

    def handle_assoc(self, pkt):
        sta = pkt[Dot11].addr2
        st = self.stations.setdefault(sta, Station(sta))
        self.aid += 1
        self.send(C.build_assoc_resp(self.mac, sta, self.next_sc(), self.aid))
        self.send(C.build_m1(self.mac, sta, st.anonce, self.next_sc()))

    def handle_m2(self, pkt):
        sta = pkt[Dot11].addr2
        st = self.stations.get(sta)
        if not st or not st.pmk or st.associated:
            return  # ignore message 4 (and retransmits) once associated
        ek = C.parse_eapol_key(pkt)
        if ek.key_replay_counter != 1:
            return  # message 2 uses replay counter 1
        snonce = ek.key_nonce
        ptk = sae.derive_ptk_sha256(st.pmk, C.mac_b(self.mac), C.mac_b(sta), st.anonce, snonce)
        st.kck, st.kek, st.tk = ptk[:16], ptk[16:32], ptk[32:48]
        if not C.eapol_mic_ok(st.kck, pkt):
            print("M2_MIC_FAIL", file=sys.stderr, flush=True)
            return
        self.send(C.build_m3(self.mac, sta, st.anonce, st.kck, st.kek, self.gtk, self.igtk, self.next_sc()))
        st.associated = True

    def handle_data(self, pkt):
        sta = pkt[Dot11].addr2
        st = self.stations.get(sta)
        if not st or not st.associated:
            return
        eth = C.decrypt_ccmp(pkt, st.tk, from_ap=False)
        if not eth:
            return
        # answer an ICMP echo to the gateway
        if eth.haslayer(ICMP) and eth[ICMP].type == 8 and eth.haslayer(IP) and eth[IP].dst == GW_IP:
            reply = (
                Ether(src=self.mac, dst=sta, type=0x0800)
                / IP(src=GW_IP, dst=eth[IP].src)
                / ICMP(type=0, id=eth[ICMP].id, seq=eth[ICMP].seq)
                / Raw(bytes(eth[ICMP].payload))
            )
            pn = st.pn
            st.pn += 1
            self.send(C.encrypt_ccmp(reply, st.tk, pn, self.mac, sta, tods=False, sc=self.next_sc()))


def main():
    ap = AP()
    print("python WPA3-SAE AP up", file=sys.stderr, flush=True)
    buf = b""
    last_beacon = 0.0
    while True:
        now = time.time()
        if now - last_beacon >= 0.05:
            ap.beacon()
            last_beacon = now
        r, _, _ = select.select([0], [], [], 0.05)
        if not r:
            continue
        data = os.read(0, 65536)
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
                ap.recv(RadioTap(fr))
            except Exception as e:
                print("recv error: %r" % e, file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
