#!/usr/bin/env python3
"""
Shared frame/crypto helpers for the Python WPA3-SAE AP and station used to
cross-validate the Rust implementation over the stdio bridge.

Frames are built with scapy; CCMP and AES key-wrap reuse the reference `ccmp.py`;
SAE and the SHA-256 4-way use `wpa3_sae.py`.
"""
import os
import struct
import sys

SRC = os.path.join(os.path.dirname(__file__), "..", "barely-ap", "src")
sys.path.insert(0, os.path.abspath(SRC))
sys.path.insert(0, os.path.dirname(__file__))

import scapy.arch as _arch  # noqa: E402

if not hasattr(_arch, "get_if_raw_hwaddr"):
    _arch.get_if_raw_hwaddr = lambda *a, **k: (0, b"\x00" * 6)
if not hasattr(_arch, "str2mac"):
    _arch.str2mac = lambda b: ":".join("%02x" % x for x in b)

import scapy.fields as _F  # noqa: E402

_orig_fixvalue = _F.FlagValue._fixvalue
_F.FlagValue._fixvalue = lambda self, v: (_orig_fixvalue(self, v.replace("-", "_")) if isinstance(v, str) else _orig_fixvalue(self, v))

from scapy.layers.eap import EAPOL  # noqa: E402

EAPOL.payload_guess = []  # keep EAPOL key data as Raw

from scapy.layers.dot11 import (  # noqa: E402
    Dot11,
    Dot11Auth,
    Dot11AssoReq,
    Dot11Beacon,
    Dot11Elt,
    Dot11CCMP,
    RadioTap,
)
from scapy.layers.l2 import LLC, SNAP, Ether  # noqa: E402
from scapy.packet import Raw  # noqa: E402

import ccmp  # noqa: E402  (reference CCMP / key-wrap / pad)
import wpa3_sae as sae  # noqa: E402

RSN_WPA3 = bytes.fromhex("301a0100000fac040100000fac040100000fac08c000000000000fac06")
RSNXE_H2E = bytes.fromhex("f40120")


# ---------------------------------------------------------------------------
# EAPOL-Key (reference layout) -- import the class from ap.py
# ---------------------------------------------------------------------------
import ap as _apmod  # noqa: E402

EAPOL_KEY = _apmod.EAPOL_KEY


# ---------------------------------------------------------------------------
# stdio framing
# ---------------------------------------------------------------------------
def frame_bytes(pkt):
    x = bytes(pkt)
    return struct.pack("<L", len(x)) + x


def read_available(buf, fileobj):
    data = fileobj.read(65536)
    if data:
        buf += data
    frames = []
    while len(buf) >= 4:
        wanted = struct.unpack("<L", buf[:4])[0]
        if len(buf) < 4 + wanted:
            break
        frames.append(buf[4 : 4 + wanted])
        buf = buf[4 + wanted :]
    return buf, frames


def mac_b(mac):
    return bytes.fromhex(mac.replace(":", ""))


# ---------------------------------------------------------------------------
# SAE auth + management frames
# ---------------------------------------------------------------------------
def build_sae_auth(a1, a2, a3, tods, sc, seq, status, payload):
    d = Dot11(type=0, subtype=0x0B, addr1=a1, addr2=a2, addr3=a3, SC=sc)
    if tods:
        d.FCfield = 0x01
    return RadioTap() / d / Dot11Auth(algo=3, seqnum=seq, status=status) / Raw(payload)


def parse_auth(pkt):
    a = pkt[Dot11Auth]
    payload = bytes(a.payload) if a.payload else b""
    return a.algo, a.seqnum, a.status, payload


def build_assoc_req(bssid, sta, ssid, sc):
    d = Dot11(type=0, subtype=0, addr1=bssid, addr2=sta, addr3=bssid, SC=sc)
    d.FCfield = 0x01  # to-DS
    return (
        RadioTap()
        / d
        / Dot11AssoReq(cap=0x3101, listen_interval=0xC8)
        / Dot11Elt(ID="SSID", info=ssid)
        / Dot11Elt(ID="Rates", info=bytes([0x0C]))
        / Raw(RSN_WPA3)
        / Raw(RSNXE_H2E)
    )


def build_assoc_resp(bssid, sta, sc, aid):
    from scapy.layers.dot11 import Dot11AssoResp

    return (
        RadioTap()
        / Dot11(type=0, subtype=1, addr1=sta, addr2=bssid, addr3=bssid, SC=sc)
        / Dot11AssoResp(cap=0x3101, status=0, AID=aid)
        / Dot11Elt(ID="SSID", info=b"turtlenet")
        / Dot11Elt(ID="Rates", info=bytes([0x0C]))
    )


def build_beacon(bssid, ssid, sc, ts):
    return (
        RadioTap()
        / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
        / Dot11Beacon(cap=0x3101, timestamp=ts, beacon_interval=0x64)
        / Dot11Elt(ID="SSID", info=ssid)
        / Dot11Elt(ID="Rates", info=bytes([0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24]))
        / Dot11Elt(ID="DSset", info=bytes([1]))
        / Raw(RSN_WPA3)
        / Raw(RSNXE_H2E)
    )


# ---------------------------------------------------------------------------
# EAPOL 4-way (SHA-256 key descriptors for SAE)
# ---------------------------------------------------------------------------
def _eapol_data_hdr(a1, a2, a3, tods, sc):
    d = Dot11(type=2, subtype=0, addr1=a1, addr2=a2, addr3=a3, SC=sc)
    d.FCfield = 0x01 if tods else 0x02
    return RadioTap() / d / LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / SNAP(OUI=0, code=0x888E)


def _key_info(install=0, ack=0, mic=0, secure=0, enc=0, ktype=1, ver=0):
    return EAPOL_KEY(
        key_descriptor_type=2,
        key_descriptor_type_version=ver,
        install=install,
        key_ack=ack,
        has_key_mic=mic,
        secure=secure,
        encrypted_key_data=enc,
        key_type=ktype,
    )


def build_m2(bssid, sta, snonce, kck, sc, rsn=RSN_WPA3):
    ek = _key_info(mic=1, ver=0)
    ek.key_replay_counter = 1
    ek.key_nonce = snonce
    ek.key_length = 0
    ek.wpa_key_length = len(rsn)
    ek.key = rsn
    ek.key_mic = b"\x00" * 16
    eapol0 = EAPOL(version="802.1X-2004", type="EAPOL-Key") / ek
    mic = sae.eapol_mic_sha256(kck, bytes(eapol0))
    ek.key_mic = mic
    return _eapol_data_hdr(bssid, sta, bssid, True, sc) / EAPOL(version="802.1X-2004", type="EAPOL-Key") / ek


def build_m4(bssid, sta, kck, sc):
    ek = _key_info(mic=1, ver=0)
    ek.key_replay_counter = 2
    ek.key_length = 0
    ek.key_mic = b"\x00" * 16
    eapol0 = EAPOL(version="802.1X-2004", type="EAPOL-Key") / ek
    mic = sae.eapol_mic_sha256(kck, bytes(eapol0))
    ek.key_mic = mic
    return _eapol_data_hdr(bssid, sta, bssid, True, sc) / EAPOL(version="802.1X-2004", type="EAPOL-Key") / ek


def build_m1(bssid, sta, anonce, sc):
    ek = _key_info(ack=1, ver=0)
    ek.key_replay_counter = 1
    ek.key_nonce = anonce
    ek.key_length = 16
    return _eapol_data_hdr(sta, bssid, bssid, False, sc) / EAPOL(version="802.1X-2004", type="EAPOL-Key") / ek


def gtk_kde(gtk):
    return bytes([0xDD, len(gtk) + 6]) + b"\x00\x0f\xac\x01\x00\x00" + gtk


def igtk_kde(key_id, ipn, igtk):
    return bytes([0xDD, 4 + 2 + 6 + 16]) + b"\x00\x0f\xac\x09" + struct.pack("<H", key_id) + ipn + igtk


def build_m3(bssid, sta, anonce, kck, kek, gtk, igtk, sc):
    plain = ccmp.pad_key_data(RSN_WPA3 + gtk_kde(gtk) + igtk_kde(4, b"\x00" * 6, igtk))
    keydata = ccmp.aes_wrap(kek, plain)
    ek = _key_info(install=1, ack=1, mic=1, secure=1, enc=1, ver=0)
    ek.key_replay_counter = 2
    ek.key_nonce = anonce
    ek.key_length = 16
    ek.key = keydata
    ek.wpa_key_length = len(keydata)
    ek.key_mic = b"\x00" * 16
    eapol0 = EAPOL(version="802.1X-2004", type="EAPOL-Key") / ek
    mic = sae.eapol_mic_sha256(kck, bytes(eapol0))
    ek.key_mic = mic
    return _eapol_data_hdr(sta, bssid, bssid, False, sc) / EAPOL(version="802.1X-2004", type="EAPOL-Key") / ek


def parse_eapol_key(pkt):
    return EAPOL_KEY(bytes(pkt[EAPOL].payload.load))


def eapol_mic_ok(kck, pkt):
    eapol = pkt[EAPOL]
    ek = EAPOL_KEY(eapol.payload.load)
    to_check = eapol.build().replace(ek.key_mic, b"\x00" * len(ek.key_mic))
    return sae.eapol_mic_sha256(kck, to_check) == ek.key_mic


def find_igtk(unwrapped):
    i = 0
    while i + 2 <= len(unwrapped):
        eid = unwrapped[i]
        ln = unwrapped[i + 1]
        if i + 2 + ln > len(unwrapped):
            break
        body = unwrapped[i + 2 : i + 2 + ln]
        if eid == 0xDD and ln >= 28 and body[:3] == b"\x00\x0f\xac" and body[3] == 0x09:
            return body[12:28]
        i += 2 + ln
    return None


# ---------------------------------------------------------------------------
# CCMP data (reuse reference ccmp.py)
# ---------------------------------------------------------------------------
def encrypt_ccmp(eth, tk, pn, bssid, sta, tods, sc):
    SA = eth[Ether].src
    DA = eth[Ether].dst
    if tods:
        a1, a2, a3, fc = bssid, sta, DA, 0x41
    else:
        a1, a2, a3, fc = sta, bssid, SA, 0x42
    newp = Dot11(type="Data", addr1=a1, addr2=a2, addr3=a3, SC=sc)
    newp.FCfield = fc
    newp = newp / Dot11CCMP()
    pnb = ccmp.pn2bytes(pn)
    newp.PN0, newp.PN1, newp.PN2, newp.PN3, newp.PN4, newp.PN5 = pnb
    newp.key_id = 0
    newp.ext_iv = 1
    nonce = ccmp.ccmp_get_nonce(0, newp.addr2, pn)
    aad = ccmp.ccmp_get_aad(newp)
    header = LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / SNAP(OUI=0, code=eth[Ether].type)
    payload = bytes(header / eth.payload)
    cipher, tag = ccmp.CCMPCrypto.run_ccmp_encrypt(tk, nonce, aad, payload)
    newp.data = cipher + tag
    return RadioTap() / newp


def decrypt_ccmp(pkt, tk, from_ap):
    p = pkt[Dot11]
    ccmp_layer = pkt[Dot11CCMP]
    pn = ccmp.dot11_get_iv(p)
    priority = ccmp.dot11_get_priority(p)
    nonce = ccmp.ccmp_get_nonce(priority, p.addr2, pn)
    aad = ccmp.ccmp_get_aad(p)
    data = ccmp_layer.data
    tag = data[-8:]
    payload = data[:-8]
    plaintext, valid = ccmp.CCMPCrypto.run_ccmp_decrypt(tk, nonce, aad, payload, tag)
    if not valid:
        return None
    llc = LLC(plaintext)
    if from_ap:
        DA, SA = p.addr1, p.addr3
    else:
        DA, SA = p.addr3, p.addr2
    return Ether(ccmp.addr2bin(DA) + ccmp.addr2bin(SA) + struct.pack(">H", llc.payload.code) + llc.payload.payload.build())
