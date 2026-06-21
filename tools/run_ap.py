#!/usr/bin/env python3
"""
Run the *reference* Python AP (ap.py) in stdio mode with compatibility shims,
backed by the in-memory ScapyNetwork (no TUN needed), so the Rust client can be
tested against it on any platform.
"""
import os
import sys

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

from scapy.layers.eap import EAPOL  # noqa: E402

EAPOL.payload_guess = []  # keep EAPOL key data as Raw (era-compatible)

import ap as apmod  # noqa: E402
from fakenet import ScapyNetwork  # noqa: E402


class _TunShim:
    """Stand in for TunInterface using the in-memory fake network."""

    def __init__(self, bss, ip=None, name="scapyap"):
        self._net = ScapyNetwork(bss, ip="10.10.10.1/24")

    def start(self):
        self._net.start()

    def write(self, pkt):
        self._net.write(pkt)


apmod.TunInterface = _TunShim

# CCMP PN must start at 1: ap.py seeds its per-station / group PN counters with
# itertools.count() (i.e. 0), which a standards-compliant receiver rejects as a
# replay. Patch the count() used by ap.py to start at 1.
import itertools as _it  # noqa: E402

apmod.count = lambda: _it.count(1)

AP_MAC = os.environ.get("AP_MAC", "02:00:00:00:00:00")

ap = apmod.AP("turtlenet", "password1234", mac=AP_MAC, mode="stdio", channel=1)
print("reference python AP up (stdio)", file=sys.stderr, flush=True)
ap.run()
