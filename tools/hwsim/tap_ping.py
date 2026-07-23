#!/usr/bin/env python3
"""Send/receive one Ethernet ICMP echo through a TAP without configuring IP.

This keeps the AP and station test endpoints in one host namespace without
creating two conflicting local routes. The TAP frame still traverses the Rust
client, CCMP, reference AP/mac80211, and the AP host IPv4 stack in both directions.
"""

import argparse
import os
import select
import socket
import struct
import time


def checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def mac(text: str) -> bytes:
    value = bytes.fromhex(text.replace(":", ""))
    if len(value) != 6:
        raise ValueError("MAC must contain six octets")
    return value


def echo_frame(src_mac: bytes, dst_mac: bytes, src_ip: str, dst_ip: str) -> bytes:
    payload = b"barely-cli-tap-ping"
    identifier = os.getpid() & 0xFFFF
    icmp = struct.pack("!BBHHH", 8, 0, 0, identifier, 1) + payload
    icmp = icmp[:2] + struct.pack("!H", checksum(icmp)) + icmp[4:]
    source = socket.inet_aton(src_ip)
    destination = socket.inet_aton(dst_ip)
    total_length = 20 + len(icmp)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        identifier,
        0,
        64,
        socket.IPPROTO_ICMP,
        0,
        source,
        destination,
    )
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return dst_mac + src_mac + struct.pack("!H", 0x0800) + ip + icmp


def arp_reply(src_mac: bytes, dst_mac: bytes, src_ip: str, dst_ip: str) -> bytes:
    return (
        dst_mac
        + src_mac
        + struct.pack("!H", 0x0806)
        + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
        + src_mac
        + socket.inet_aton(src_ip)
        + dst_mac
        + socket.inet_aton(dst_ip)
    )


def is_arp_request(frame: bytes, wanted_ip: str) -> bool:
    return (
        len(frame) >= 42
        and frame[12:14] == b"\x08\x06"
        and frame[20:22] == b"\x00\x01"
        and frame[38:42] == socket.inet_aton(wanted_ip)
    )


def is_reply(frame: bytes, src_ip: str, dst_ip: str) -> bool:
    if len(frame) < 14 + 20 + 8 or frame[12:14] != b"\x08\x00":
        return False
    ip = frame[14:]
    header_length = (ip[0] & 0x0F) * 4
    if len(ip) < header_length + 8 or ip[9] != socket.IPPROTO_ICMP:
        return False
    if ip[12:16] != socket.inet_aton(dst_ip) or ip[16:20] != socket.inet_aton(src_ip):
        return False
    return ip[header_length] == 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("interface")
    parser.add_argument("--src-mac", required=True)
    parser.add_argument("--dst-mac", required=True)
    parser.add_argument("--src-ip", default="10.10.10.2")
    parser.add_argument("--dst-ip", default="10.10.10.1")
    args = parser.parse_args()

    packet = echo_frame(mac(args.src_mac), mac(args.dst_mac), args.src_ip, args.dst_ip)
    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    raw.bind((args.interface, 0))
    deadline = time.monotonic() + 6
    next_send = 0.0
    while time.monotonic() < deadline:
        now = time.monotonic()
        if now >= next_send:
            raw.send(packet)
            next_send = now + 0.5
        readable, _, _ = select.select([raw], [], [], 0.2)
        if readable:
            received = raw.recv(65535)
            if is_arp_request(received, args.src_ip):
                raw.send(
                    arp_reply(
                        mac(args.src_mac),
                        received[6:12],
                        args.src_ip,
                        args.dst_ip,
                    )
                )
            if is_reply(received, args.src_ip, args.dst_ip):
                print("TAP_PING_REPLY_OK")
                return 0
    print("TAP_PING_TIMEOUT")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
