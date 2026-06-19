#!/usr/bin/env python3
"""
Run the *reference* Python WiFi client (client.py) in stdio mode, with the
compatibility shims needed on modern scapy. Used to prove the Rust AP
interoperates with a real 802.11 station implementation.

If BARELY_PING=1, once the handshake completes it injects an ICMP echo toward
the gateway and prints PING_REPLY_OK to stderr when the (CCMP-encrypted) reply
comes back — exercising the full data plane in both directions.
"""
import os
import sys
import threading
import time

SRC = os.path.join(os.path.dirname(__file__), "..", "barely-ap", "src")
sys.path.insert(0, os.path.abspath(SRC))

import scapy.arch as _arch

if not hasattr(_arch, "get_if_raw_hwaddr"):
    _arch.get_if_raw_hwaddr = lambda *a, **k: (0, b"\x00" * 6)
if not hasattr(_arch, "str2mac"):
    _arch.str2mac = lambda b: ":".join("%02x" % x for x in b)

import scapy.fields as _F

_orig_fixvalue = _F.FlagValue._fixvalue


def _patched_fixvalue(self, value):
    if isinstance(value, str):
        value = value.replace("-", "_")
    return _orig_fixvalue(self, value)


_F.FlagValue._fixvalue = _patched_fixvalue

# Modern scapy auto-dissects EAPOL payloads into its built-in EAPOL_KEY layer,
# but the reference client expects a Raw payload (`.payload.load`). Disable the
# guess so dissection leaves EAPOL key data as Raw, matching the era client.py
# was written for.
from scapy.layers.eap import EAPOL  # noqa: E402

EAPOL.payload_guess = []

# Avoid TUN; the client uses netmode="fake" so this is only an import guard.
import ap as apmod


class _StubNet:
    def __init__(self, *a, **k):
        pass

    def start(self):
        pass

    def write(self, p):
        pass


apmod.TunInterface = _StubNet

import client as climod  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402
from scapy.layers.inet import IP, ICMP  # noqa: E402
from scapy.packet import Raw  # noqa: E402

AP_MAC = os.environ.get("AP_MAC", "02:00:00:00:00:00")
STA_MAC = os.environ.get("STA_MAC", "02:00:00:00:ab:cd")

c = climod.Client("turtlenet", "password1234", mac=STA_MAC, mode="stdio", netmode="fake")


def driver():
    if os.environ.get("BARELY_PING") != "1":
        return
    # wait for full authentication
    for _ in range(2000):
        if c.connected == 4:
            break
        time.sleep(0.01)
    else:
        print("HANDSHAKE_TIMEOUT", file=sys.stderr, flush=True)
        return
    print("Fully Authenticated (driver saw connected=4)", file=sys.stderr, flush=True)

    captured = []
    orig_write = c.network.write
    def capture(pkt):
        captured.append(pkt)
        try:
            orig_write(pkt)
        except Exception:
            pass
    c.network.write = capture

    # inject an ICMP echo toward the gateway
    ping = (
        Ether(src=c.mac, dst=AP_MAC)
        / IP(src="10.10.10.2", dst="10.10.10.1")
        / ICMP(type=8, id=0x1234, seq=1)
        / Raw(b"barely-ap-ping")
    )
    time.sleep(0.2)
    c.enc_send(ping)

    for _ in range(500):
        if captured:
            break
        time.sleep(0.01)

    ok = False
    for pkt in captured:
        try:
            e = Ether(pkt) if isinstance(pkt, (bytes, bytearray)) else pkt
            if e.haslayer(ICMP) and e[ICMP].type == 0:
                ok = True
                break
        except Exception:
            pass
    if ok:
        print("PING_REPLY_OK", file=sys.stderr, flush=True)
    else:
        print("PING_REPLY_MISSING (captured %d frames)" % len(captured), file=sys.stderr, flush=True)


threading.Thread(target=driver, daemon=True).start()
c.run()
