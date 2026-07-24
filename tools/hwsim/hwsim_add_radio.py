#!/usr/bin/env python3
"""Create mac80211_hwsim radios at runtime via HWSIM_CMD_NEW_RADIO.

Reloading mac80211_hwsim to get more radios destroys every radio already in
use (e.g. by a running AP), so test cells that must not disturb a live system
create their own radios dynamically instead:

    hwsim_add_radio.py [COUNT]

Prints the names of the newly created mac80211_hwsim netdevs, one per line.
Requires root (generic netlink to the mac80211_hwsim family).
"""

import os
import socket
import struct
import sys
import time

NETLINK_GENERIC = 16
NLM_F_REQUEST = 1
NLM_F_ACK = 4
NLMSG_ERROR = 2
GENL_ID_CTRL = 16
CTRL_CMD_GETFAMILY = 3
CTRL_ATTR_FAMILY_ID = 1
CTRL_ATTR_FAMILY_NAME = 2
HWSIM_CMD_NEW_RADIO = 4
HWSIM_ATTR_CHANNELS = 9
HWSIM_ATTR_USE_CHANCTX = 15
HWSIM_ATTR_MLO_SUPPORT = 25


def nlattr(attr_type: int, payload: bytes) -> bytes:
    header = struct.pack("<HH", 4 + len(payload), attr_type)
    pad = (4 - len(payload) % 4) % 4
    return header + payload + b"\0" * pad


def genl_message(family: int, cmd: int, seq: int, attrs: bytes) -> bytes:
    genl_header = struct.pack("<BBH", cmd, 1, 0)
    payload = genl_header + attrs
    nl_header = struct.pack(
        "<IHHII", 16 + len(payload), family, NLM_F_REQUEST | NLM_F_ACK, seq, 0
    )
    return nl_header + payload


def receive(sock: socket.socket, seq: int) -> bytes:
    """Return the payload of the reply matching seq; raise on NLMSG_ERROR."""
    while True:
        data = sock.recv(65536)
        offset = 0
        while offset + 16 <= len(data):
            length, msg_type, _flags, msg_seq, _pid = struct.unpack_from(
                "<IHHII", data, offset
            )
            body = data[offset + 16 : offset + length]
            if msg_seq == seq:
                if msg_type == NLMSG_ERROR:
                    (error,) = struct.unpack_from("<i", body)
                    # mac80211_hwsim's NEW_RADIO handler returns the new
                    # radio's index, which genetlink delivers as a positive
                    # "error" in the ACK. Only a negative value is a failure.
                    if error < 0:
                        raise OSError(-error, os.strerror(-error))
                    return b""
                return body
            offset += (length + 3) & ~3


def hwsim_family_id(sock: socket.socket) -> int:
    seq = 1
    name = b"MAC80211_HWSIM\0"
    sock.send(
        genl_message(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, seq, nlattr(CTRL_ATTR_FAMILY_NAME, name))
    )
    body = receive(sock, seq)
    # Skip the genl header, then walk the attributes.
    offset = 4
    while offset + 4 <= len(body):
        attr_len, attr_type = struct.unpack_from("<HH", body, offset)
        if attr_type == CTRL_ATTR_FAMILY_ID:
            (family,) = struct.unpack_from("<H", body, offset + 4)
            return family
        offset += (attr_len + 3) & ~3
    raise RuntimeError("mac80211_hwsim generic-netlink family not found (module loaded?)")


def hwsim_interfaces() -> set:
    found = set()
    for iface in os.listdir("/sys/class/net"):
        driver = os.path.join("/sys/class/net", iface, "device", "driver")
        try:
            if os.path.basename(os.readlink(driver)) == "mac80211_hwsim":
                found.add(iface)
        except OSError:
            continue
    return found


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    count = int(args[0]) if args else 1
    channels = 1
    mlo = False
    for arg in sys.argv[1:]:
        if arg.startswith("--channels="):
            channels = int(arg.split("=", 1)[1])
        elif arg == "--mlo":
            # MLO radios need multi-channel + chanctx support.
            mlo = True
            channels = max(channels, 2)
    attrs = b""
    if channels > 1:
        attrs += nlattr(HWSIM_ATTR_CHANNELS, struct.pack("<I", channels))
        attrs += nlattr(HWSIM_ATTR_USE_CHANCTX, b"")
    if mlo:
        attrs += nlattr(HWSIM_ATTR_MLO_SUPPORT, b"")
    before = hwsim_interfaces()
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    sock.bind((0, 0))
    family = hwsim_family_id(sock)
    for index in range(count):
        seq = 100 + index
        sock.send(genl_message(family, HWSIM_CMD_NEW_RADIO, seq, attrs))
        receive(sock, seq)
    # udev may take a moment to surface the new netdevs.
    deadline = time.monotonic() + 5
    new = set()
    while time.monotonic() < deadline:
        new = hwsim_interfaces() - before
        if len(new) >= count:
            break
        time.sleep(0.1)
    if len(new) < count:
        print(
            f"created {count} radio(s) but only {len(new)} new netdev(s) appeared",
            file=sys.stderr,
        )
        return 1
    for iface in sorted(new):
        print(iface)
    return 0


if __name__ == "__main__":
    sys.exit(main())
