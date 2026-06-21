#!/usr/bin/env python3
"""
Generate golden test vectors from the reference Python (ccmp.py + ap.py via
scapy) so the Rust port can assert byte-for-byte equality.

Run from repo root:  python3 tools/gen_vectors.py > tests/vectors.json

Notes on environment compatibility:
  * scapy >= 2.7 moved `get_if_raw_hwaddr`/`str2mac` and renamed the Dot11
    FCfield flags to use underscores. We shim both so the unmodified reference
    `ap.py` runs and we capture exactly what it would put on the wire.
  * `ap.py` BSS would open /dev/net/tun (Linux only); we stub the network.
"""
import json
import os
import sys

SRC = os.path.join(os.path.dirname(__file__), "..", "barely-ap", "src")
sys.path.insert(0, os.path.abspath(SRC))

import scapy.arch as _arch  # noqa: E402

if not hasattr(_arch, "get_if_raw_hwaddr"):
    _arch.get_if_raw_hwaddr = lambda *a, **k: (0, b"\x00" * 6)
if not hasattr(_arch, "str2mac"):
    _arch.str2mac = lambda b: ":".join("%02x" % x for x in b)

# Let ap.py's hyphenated FCfield strings ("from-DS+protected") keep working on
# scapy versions that renamed the flags to underscores.
import scapy.fields as _F  # noqa: E402

_orig_fixvalue = _F.FlagValue._fixvalue


def _patched_fixvalue(self, value):
    if isinstance(value, str):
        value = value.replace("-", "_")
    return _orig_fixvalue(self, value)


_F.FlagValue._fixvalue = _patched_fixvalue

import ap as apmod  # noqa: E402


class _StubNet:
    def __init__(self, *a, **k):
        pass

    def start(self):
        pass

    def write(self, p):
        pass


apmod.TunInterface = _StubNet

from ap import AP, Station, EAPOL_KEY, RSN  # noqa: E402
from scapy.layers.dot11 import Dot11Elt  # noqa: E402


_HT_CAP = bytes([0x6e, 0x00, 0x17, 0xff, 0xff]) + bytes(14) + bytes([0, 0, 0, 0, 0, 0, 0])
_WMM = bytes.fromhex("0050f20201010000") + bytes.fromhex("03a4000027a4000042435e0062322f00")


def _ht_op(channel):
    return bytes([channel]) + bytes(5) + bytes(16)


def _band_aware_beacon_ies(ssid_name, channel):
    """Band-aware IE block mirroring the Rust dot11::make_beacon_ies (incl. HT + WMM)."""
    ssid = ssid_name if isinstance(ssid_name, bytes) else ssid_name.encode()
    ies = Dot11Elt(ID="SSID", info=ssid)
    if channel > 14:
        ies = ies / Dot11Elt(ID="Rates", info=bytes([0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c]))
        ies = ies / Dot11Elt(ID="Country", info=b"US\x20" + bytes([36, 4, 23]))
    else:
        ies = ies / Dot11Elt(ID="Rates", info=bytes([0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24]))
        ies = ies / Dot11Elt(ID="DSset", info=bytes([channel]))
        ies = ies / Dot11Elt(ID="Country", info=b"US\x20" + bytes([1, 11, 30]))
        ies = ies / Dot11Elt(ID=50, info=bytes([0x30, 0x48, 0x60, 0x6c]))
    ies = ies / Dot11Elt(ID=45, info=_HT_CAP)
    ies = ies / Dot11Elt(ID=61, info=_ht_op(channel))
    if channel > 14:
        ies = ies / Dot11Elt(ID=191, info=bytes([0xb2, 0x01, 0x80, 0x33, 0xea, 0xff, 0x00, 0x00, 0xea, 0xff, 0x00, 0x00]))
        ies = ies / Dot11Elt(ID=192, info=bytes([0, 0, 0, 0, 0]))
    _extcap = bytearray(11)
    _extcap[2] |= 0x08
    _extcap[10] |= 0x10
    ies = ies / Dot11Elt(ID=127, info=bytes(_extcap))
    _cls = 115 if channel > 14 else 81
    ies = ies / Dot11Elt(ID=59, info=bytes([_cls, _cls]))
    ies = ies / Dot11Elt(ID=70, info=bytes([0x02, 0x00, 0x00, 0x00, 0x00]))
    ies = ies / Dot11Elt(ID=221, info=_WMM)
    return ies


# Drive the reference AP with band-aware IEs (the original ap.py advertised only
# 6 Mbps + a 2.4 GHz DSSS Parameter Set regardless of band).
apmod.make_beacon_ies = _band_aware_beacon_ies
make_beacon_ies = _band_aware_beacon_ies
import ccmp  # noqa: E402
from ccmp import (  # noqa: E402
    CCMPCrypto,
    aes_wrap,
    aes_unwrap,
    customPRF512,
    pad_key_data,
    ccmp_get_nonce,
    ccmp_get_aad,
    pn2bytes,
    pn2bin,
)
from scapy.layers.dot11 import *  # noqa: E402,F401,F403
from scapy.layers.eap import EAPOL  # noqa: E402
from scapy.layers.l2 import LLC, SNAP, Ether  # noqa: E402
from scapy.layers.inet import IP, ICMP, UDP, TCP  # noqa: E402
from scapy.packet import Raw  # noqa: E402
import hashlib, hmac  # noqa: E402


def h(b):
    return bytes(b).hex()


vectors = {}

# Deterministic test parameters shared across vectors
AP_MAC = "02:00:00:00:00:00"
STA_MAC = "02:00:00:00:ab:cd"
SSID = "turtlenet"
PSK = "password1234"
CHANNEL = 1
FIXED_TS = 0x0011223344556677
FIXED_ANONCE = bytes([(i * 7 + 3) & 0xFF for i in range(32)])
FIXED_SNONCE = bytes([(i * 5 + 11) & 0xFF for i in range(32)])
FIXED_GTK_FULL = bytes([(i * 13 + 1) & 0xFF for i in range(32)])

# ---------------------------------------------------------------------------
# Crypto vectors
# ---------------------------------------------------------------------------
PMK = hashlib.pbkdf2_hmac("sha1", PSK.encode(), SSID.encode(), 4096, 32)
amac = bytes.fromhex(AP_MAC.replace(":", ""))
smac = bytes.fromhex(STA_MAC.replace(":", ""))
PTK = customPRF512(PMK, amac, smac, FIXED_ANONCE, FIXED_SNONCE)

ccm_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
ccm_nonce = bytes([0x40 + i for i in range(13)])
ccm_aad = bytes(range(22))
ccm_plain = bytes([(i * 3) & 0xFF for i in range(48)])
ccm_cipher, ccm_tag = CCMPCrypto.run_ccmp_encrypt(ccm_key, ccm_nonce, ccm_aad, ccm_plain)

k = b"k" * 16
a = b"a" * 22
n = b"n" * 13
p = b"P" * 128
selftest_cipher, selftest_tag = CCMPCrypto.run_ccmp_encrypt(k, n, a, p)

kek = PTK[16:32]
wrap_plain = pad_key_data(RSN + bytes.fromhex("dd16000fac0100001122334455667788990011223344556677dd00"))
wrapped = aes_wrap(kek, wrap_plain)

vectors["crypto"] = {
    "psk": PSK,
    "ssid": SSID,
    "pmk": h(PMK),
    "amac": h(amac),
    "smac": h(smac),
    "anonce": h(FIXED_ANONCE),
    "snonce": h(FIXED_SNONCE),
    "ptk": h(PTK),
    "kck": h(PTK[:16]),
    "kek": h(PTK[16:32]),
    "tk": h(PTK[32:48]),
    "ccm_key": h(ccm_key),
    "ccm_nonce": h(ccm_nonce),
    "ccm_aad": h(ccm_aad),
    "ccm_plain": h(ccm_plain),
    "ccm_cipher": h(ccm_cipher),
    "ccm_tag": h(ccm_tag),
    "selftest_cipher": h(selftest_cipher),
    "selftest_tag": h(selftest_tag),
    "kek_for_wrap": h(kek),
    "wrap_plain": h(wrap_plain),
    "wrapped": h(wrapped),
    "pad_key_data_5": h(pad_key_data(b"\x01\x02\x03\x04\x05")),
    "pad_key_data_8": h(pad_key_data(b"\x01\x02\x03\x04\x05\x06\x07\x08")),
    "pn2bytes_demo": list(pn2bytes(0x0102030405)),
    "pn2bin_demo": h(pn2bin(0x0102030405)),
    "ccmp_get_nonce_demo": h(ccmp_get_nonce(0, STA_MAC, 0x0102030405)),
    "rsn": h(RSN),
    "hmac_sha1_demo": h(hmac.new(b"k" * 16, b"hello world", hashlib.sha1).digest()[:16]),
}

assert aes_unwrap(kek, wrapped) == wrap_plain
pt, ok = CCMPCrypto.run_ccmp_decrypt(ccm_key, ccm_nonce, ccm_aad, ccm_cipher, ccm_tag)
assert ok and pt == ccm_plain

# ---------------------------------------------------------------------------
# Frame vectors: drive the *actual* ap.py methods, capturing what it sends.
# ---------------------------------------------------------------------------
captured = []


def fresh_ap(channel=CHANNEL):
    """A fresh AP with deterministic timestamp / GTK and captured sendp."""
    captured.clear()
    ap = AP(SSID, PSK, mac=AP_MAC, mode="stdio", channel=channel)
    ap.current_timestamp = lambda: FIXED_TS
    ap.sendp = lambda packet, verbose=False: captured.append(bytes(packet.build()))
    bss = ap.bssids[AP_MAC]
    bss.gtk_full = FIXED_GTK_FULL
    bss.GTK = FIXED_GTK_FULL[:16]
    bss.MIC_AP_TO_GROUP = FIXED_GTK_FULL[16:24]
    from itertools import count

    bss.group_IV = count()
    return ap, bss


frames = {}

# --- beacons (built manually to include the beacon-only TIM element) ---
_TIM = Dot11Elt(ID=5, info=bytes([0x00, 0x01, 0x00, 0x00]))


def _beacon(channel):
    return (
        RadioTap()
        / Dot11(subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=AP_MAC, addr3=AP_MAC)
        / Dot11Beacon(cap=0x3101, timestamp=FIXED_TS, beacon_interval=0x64)
        / make_beacon_ies(SSID, channel)
        / Dot11Elt(ID=5, info=bytes([0x00, 0x01, 0x00, 0x00]))
        / Raw(RSN)
    )


frames["beacon"] = {"bytes": h(_beacon(CHANNEL)), "channel": CHANNEL}
frames["beacon_5ghz"] = {"bytes": h(_beacon(36)), "channel": 36}

# --- probe response ---
ap, bss = fresh_ap()
ap.dot11_probe_resp(AP_MAC, STA_MAC, SSID)
frames["probe_resp"] = {"sta": STA_MAC, "bytes": h(captured[0])}

# --- authentication response ---
ap, bss = fresh_ap()
ap.dot11_auth(AP_MAC, STA_MAC)
frames["auth_resp"] = {"sta": STA_MAC, "bytes": h(captured[0])}

# --- association response + EAPOL message 1 ---
ap, bss = fresh_ap()
st = Station(STA_MAC)
st.ANONCE = FIXED_ANONCE
bss.stations[STA_MAC] = st
assoc_req = Dot11(subtype=0, addr1=AP_MAC, addr2=STA_MAC, addr3=AP_MAC)
ap.dot11_assoc_resp(assoc_req, STA_MAC, 0)
frames["assoc_resp"] = {"sta": STA_MAC, "aid": 1, "bytes": h(captured[0])}
frames["eapol_m1"] = {"sta": STA_MAC, "anonce": h(FIXED_ANONCE), "bytes": h(captured[1])}

# --- EAPOL message 3 (driven by a valid client message 2) ---
# Build a correct message 2 the way the client would (ap.py's own EAPOL_KEY,
# carried as a Raw payload so create_eapol_3 finds `.payload.load`).
kck = PTK[:16]
m2_key0 = EAPOL_KEY(
    key_descriptor_type=2,
    key_descriptor_type_version=2,
    key_type=1,
    key_ack=0,
    has_key_mic=1,
    key_replay_counter=1,
    key_nonce=FIXED_SNONCE,
    key_length=0,
    wpa_key_length=22,
    key=RSN,
)
m2_eapol0 = EAPOL(version="802.1X-2004", type="EAPOL-Key") / m2_key0
m2_mic = hmac.new(kck, bytes(m2_eapol0), hashlib.sha1).digest()[:16]
m2_key0.key_mic = m2_mic
m2_key_bytes = bytes(m2_key0)
m2_eapol = EAPOL(version="802.1X-2004", type="EAPOL-Key") / Raw(m2_key_bytes)
m2_full = (
    Dot11(subtype=0, addr1=AP_MAC, addr2=STA_MAC, addr3=AP_MAC, SC=0)
    / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
    / SNAP(OUI=0, code=0x888E)
    / m2_eapol
)
m2_full.FCfield = 0x01  # to-DS

# capture m2 as an *incoming* vector for the parser, too
frames["eapol_m2_incoming"] = {
    "bytes": h(RadioTap() / m2_full),
    "snonce": h(FIXED_SNONCE),
    "key_mic": h(m2_mic),
    "addr1": AP_MAC,
    "addr2": STA_MAC,
}

# First confirm ap.py accepts our message 2 and produces a message 3 (exercises
# the reference MIC verification path).
ap.create_eapol_3(m2_full)
assert captured, "create_eapol_3 did not send message 3 (MIC check failed?)"

# Then build the golden message 3 with a *standard* GTK KDE (the reference adds a
# stray zero-length `DD 00` vendor element after the GTK; a real AP must not).
GTK16 = FIXED_GTK_FULL[:16]
gtk_kde_std = bytes([0xDD, len(GTK16) + 6]) + b"\x00\x0f\xac" + b"\x01\x00\x00" + GTK16
m3_plain = pad_key_data(RSN + gtk_kde_std)
m3_keydata = aes_wrap(PTK[16:32], m3_plain)  # KEK
m3_ek = EAPOL_KEY(
    key_descriptor_type=2,
    key_descriptor_type_version=2,
    install=1,
    key_type=1,
    key_ack=1,
    has_key_mic=1,
    secure=1,
    encrypted_key_data=1,
    key_replay_counter=2,
    key_nonce=FIXED_ANONCE,
    key_mic=b"\x00" * 16,
    key_length=16,
    key=m3_keydata,
    wpa_key_length=len(m3_keydata),
)
m3_eapol0 = EAPOL(version="802.1X-2004", type="EAPOL-Key") / m3_ek
m3_mic = hmac.new(PTK[:16], bytes(m3_eapol0), hashlib.sha1).digest()[:16]
m3_ek.key_mic = m3_mic
m3_packet = (
    RadioTap()
    / Dot11(subtype=0, FCfield="from-DS", addr1=STA_MAC, addr2=AP_MAC, addr3=AP_MAC, SC=48)
    / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
    / SNAP(OUI=0, code=0x888E)
    / EAPOL(version="802.1X-2004", type="EAPOL-Key")
    / m3_ek
)
frames["eapol_m3"] = {
    "sta": STA_MAC,
    "anonce": h(FIXED_ANONCE),
    "snonce": h(FIXED_SNONCE),
    "gtk": h(GTK16),
    "kck": h(PTK[:16]),
    "kek": h(PTK[16:32]),
    "bytes": h(m3_packet),
}

# --- CCMP data frame from AP to STA (downlink, from-DS) ---
ap, bss = fresh_ap()
st = Station(STA_MAC)
st.TK = PTK[32:48]
st.associated = True
bss.stations[STA_MAC] = st
inner = Ether(src=AP_MAC, dst=STA_MAC, type=0x0800) / IP(src="10.10.10.1", dst="10.10.10.2") / ICMP(type=0, id=1, seq=1) / Raw(b"barely-ap-rust!!")
data_pn = 0x0000_0000_0005
enc = ap.encrypt_ccmp(bss, STA_MAC, inner, PTK[32:48], data_pn, keyid=0)
frames["data_downlink"] = {
    "sta": STA_MAC,
    "bss_mac": AP_MAC,
    "src": AP_MAC,
    "dst": STA_MAC,
    "tk": h(PTK[32:48]),
    "pn": data_pn,
    "key_id": 0,
    "ethertype": 0x0800,
    "inner_payload": h(bytes((IP(src="10.10.10.1", dst="10.10.10.2") / ICMP(type=0, id=1, seq=1) / Raw(b"barely-ap-rust!!")))),
    "eth_src": AP_MAC,
    "eth_dst": STA_MAC,
    "sc": enc.SC,
    "bytes": h(enc),
}

# --- CCMP data frame from STA to AP (uplink, to-DS) — for the decrypt path ---
# Mirror client.encrypt_ccmp: addr1=bssid, addr2=sta, addr3=DA, to-DS+protected.
up_tk = PTK[32:48]
up_pn = 0x0000_0000_0007
up_da = AP_MAC  # destined to the AP's own stack (e.g. DHCP server)
up_inner_l3 = IP(src="10.10.10.2", dst="10.10.10.1") / ICMP(type=8, id=2, seq=3) / Raw(b"ping-from-station")
up_eth = Ether(src=STA_MAC, dst=up_da, type=0x0800) / up_inner_l3
up_d = Dot11(type="Data", addr1=AP_MAC, addr2=STA_MAC, addr3=up_da, SC=0x10)
up_d.FCfield = 0x41  # to-DS + protected
up_ccmp = Dot11CCMP()
pnb = pn2bytes(up_pn)
up_ccmp.PN0, up_ccmp.PN1, up_ccmp.PN2, up_ccmp.PN3, up_ccmp.PN4, up_ccmp.PN5 = pnb
up_ccmp.key_id = 0
up_ccmp.ext_iv = 1
up_d = up_d / up_ccmp
ccm_nonce_up = ccmp_get_nonce(0, STA_MAC, up_pn)
ccm_aad_up = ccmp_get_aad(up_d)
hdr = LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / SNAP(OUI=0, code=0x0800)
up_payload = bytes(hdr / up_eth.payload)
up_cipher, up_tag = CCMPCrypto.run_ccmp_encrypt(up_tk, ccm_nonce_up, ccm_aad_up, up_payload)
up_d.data = up_cipher + up_tag
frames["data_uplink"] = {
    "sta": STA_MAC,
    "bss_mac": AP_MAC,
    "da": up_da,
    "tk": h(up_tk),
    "pn": up_pn,
    "nonce": h(ccm_nonce_up),
    "aad": h(ccm_aad_up),
    "decrypted_eth": h(bytes(up_eth)),
    "bytes": h(RadioTap() / up_d),
    "dot11_bytes": h(up_d),
}

# ---------------------------------------------------------------------------
# Incoming management frames for the parser
# ---------------------------------------------------------------------------
incoming = {}

pr_named = (
    RadioTap()
    / Dot11(subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2=STA_MAC, addr3="ff:ff:ff:ff:ff:ff")
    / Dot11ProbeReq()
    / Dot11Elt(ID="SSID", info=SSID.encode())
    / Dot11Elt(ID="Rates", info=bytes([0x0C]))
)
incoming["probe_req_named"] = {"bytes": h(pr_named), "addr2": STA_MAC, "ssid": SSID, "ssid_len": len(SSID)}

pr_empty = (
    RadioTap()
    / Dot11(subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2=STA_MAC, addr3="ff:ff:ff:ff:ff:ff")
    / Dot11ProbeReq()
    / Dot11Elt(ID="SSID", info=b"")
)
incoming["probe_req_empty"] = {"bytes": h(pr_empty), "addr2": STA_MAC, "ssid": "", "ssid_len": 0}

auth_req = (
    RadioTap()
    / Dot11(subtype=0x0B, addr1=AP_MAC, addr2=STA_MAC, addr3=AP_MAC)
    / Dot11Auth(seqnum=1)
)
incoming["auth_req"] = {"bytes": h(auth_req), "addr1": AP_MAC, "addr2": STA_MAC, "subtype": 0x0B}

assoc_req = (
    RadioTap()
    / Dot11(subtype=0, addr1=AP_MAC, addr2=STA_MAC, addr3=AP_MAC)
    / Dot11AssoReq(cap=0x3101)
    / Dot11Elt(ID="SSID", info=SSID.encode())
    / Dot11Elt(ID="Rates", info=bytes([0x0C]))
    / RSN
)
incoming["assoc_req"] = {"bytes": h(assoc_req), "addr1": AP_MAC, "addr2": STA_MAC, "subtype": 0x00}

# --- QoS CCMP data frame from STA to AP (real clients use QoS data) ---
qtid = 0
qos_pn = 0x0000_0000_00AA
qos_eth = Ether(src=STA_MAC, dst=up_da, type=0x0800) / IP(src="10.10.10.2", dst="10.10.10.1") / UDP(sport=5000, dport=5001) / Raw(b"qos-data-frame!!")
qd = Dot11(type="Data", subtype=8, addr1=AP_MAC, addr2=STA_MAC, addr3=up_da, SC=0x20)
qd.FCfield = 0x41  # to-DS + protected
qd = qd / Dot11QoS(TID=qtid)
qos_ccmp = Dot11CCMP()
qpnb = pn2bytes(qos_pn)
qos_ccmp.PN0, qos_ccmp.PN1, qos_ccmp.PN2, qos_ccmp.PN3, qos_ccmp.PN4, qos_ccmp.PN5 = qpnb
qos_ccmp.key_id = 0
qos_ccmp.ext_iv = 1
qd = qd / qos_ccmp
qos_nonce = ccmp_get_nonce(qtid, STA_MAC, qos_pn)
qos_aad = ccmp_get_aad(qd)
qos_payload = bytes(LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / SNAP(OUI=0, code=0x0800) / qos_eth.payload)
qos_cipher, qos_tag = CCMPCrypto.run_ccmp_encrypt(up_tk, qos_nonce, qos_aad, qos_payload)
qd.data = qos_cipher + qos_tag
frames["data_uplink_qos"] = {
    "sta": STA_MAC,
    "tk": h(up_tk),
    "pn": qos_pn,
    "tid": qtid,
    "decrypted_eth": h(bytes(qos_eth)),
    "bytes": h(RadioTap() / qd),
}

vectors["frames"] = frames
vectors["incoming"] = incoming

# ---------------------------------------------------------------------------
# Network-layer request frames (Ethernet payloads) for the fake network
# ---------------------------------------------------------------------------
from scapy.layers.dhcp import BOOTP, DHCP  # noqa: E402
from scapy.layers.l2 import ARP  # noqa: E402

net = {}

# DHCP discover from the station
dhcp_discover = (
    Ether(src=STA_MAC, dst="ff:ff:ff:ff:ff:ff")
    / IP(src="0.0.0.0", dst="255.255.255.255")
    / UDP(sport=68, dport=67)
    / BOOTP(chaddr=bytes.fromhex(STA_MAC.replace(":", "")) + b"\x00" * 10, xid=0xABCD1234)
    / DHCP(options=[("message-type", "discover"), "end"])
)
net["dhcp_discover"] = {"eth": h(bytes(dhcp_discover)), "xid": "abcd1234"}

# DHCP request (after offer) from the station
dhcp_request = (
    Ether(src=STA_MAC, dst="ff:ff:ff:ff:ff:ff")
    / IP(src="0.0.0.0", dst="255.255.255.255")
    / UDP(sport=68, dport=67)
    / BOOTP(chaddr=bytes.fromhex(STA_MAC.replace(":", "")) + b"\x00" * 10, xid=0xABCD1234)
    / DHCP(options=[("message-type", "request"), ("requested_addr", "10.10.10.2"), "end"])
)
net["dhcp_request"] = {"eth": h(bytes(dhcp_request))}

# ARP who-has the gateway
arp_req = (
    Ether(src=STA_MAC, dst="ff:ff:ff:ff:ff:ff")
    / ARP(op=1, hwsrc=STA_MAC, psrc="10.10.10.2", pdst="10.10.10.1")
)
net["arp_who_has_gw"] = {"eth": h(bytes(arp_req))}

# ICMP echo request to the gateway
icmp_echo = (
    Ether(src=STA_MAC, dst=AP_MAC)
    / IP(src="10.10.10.2", dst="10.10.10.1")
    / ICMP(type=8, id=0x4242, seq=7)
    / Raw(b"abcdefghij")
)
net["icmp_echo_gw"] = {"eth": h(bytes(icmp_echo)), "id": 0x4242, "seq": 7, "payload": h(b"abcdefghij")}

vectors["net"] = net

print(json.dumps(vectors, indent=2))
