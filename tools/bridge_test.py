#!/usr/bin/env python3
"""
End-to-end interop test: bridge the Rust AP (stdio) to the reference Python
client (stdio), cross-connecting their pipes, and confirm a real WPA2/CCMP
handshake (and optionally a CCMP ping) succeeds.

    python3 tools/bridge_test.py /path/to/barely-ap-binary

Exit code 0 on success.
"""
import os
import subprocess
import sys
import threading
import time

AP_BIN = sys.argv[1] if len(sys.argv) > 1 else "target/debug/barely-ap"
AP_MAC = "02:00:00:00:00:00"
STA_MAC = "02:00:00:00:ab:cd"
TIMEOUT = 20.0
CONFIG = os.path.join(os.path.dirname(os.path.dirname(__file__)), "tests", "interop-config.json")

env = dict(os.environ)
env["BARELY_PING"] = "1"
env["AP_MAC"] = AP_MAC
env["STA_MAC"] = STA_MAC

ap = subprocess.Popen(
    [AP_BIN, "--config", CONFIG, "--mode", "stdio", "--mac", AP_MAC, "--ssid", "turtlenet"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
)
client = subprocess.Popen(
    [sys.executable, os.path.join(os.path.dirname(__file__), "run_client.py")],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
)

stop = threading.Event()


def pump(src, dst, name):
    try:
        while not stop.is_set():
            b = src.read(1)
            if not b:
                break
            dst.write(b)
            dst.flush()
    except Exception:
        pass


def watch(stream, label, sink):
    for line in iter(stream.readline, b""):
        text = line.decode("utf-8", "replace").rstrip()
        sink.append(text)
        print(f"[{label}] {text}", file=sys.stderr)


ap_log, cli_log = [], []
threads = [
    threading.Thread(target=pump, args=(ap.stdout, client.stdin, "ap->cli"), daemon=True),
    threading.Thread(target=pump, args=(client.stdout, ap.stdin, "cli->ap"), daemon=True),
    threading.Thread(target=watch, args=(ap.stderr, "ap", ap_log), daemon=True),
    threading.Thread(target=watch, args=(client.stderr, "cli", cli_log), daemon=True),
]
for t in threads:
    t.start()

deadline = time.time() + TIMEOUT
authed = False
pinged = False
while time.time() < deadline:
    joined = "\n".join(cli_log)
    if "Fully Authenticated" in joined:
        authed = True
    if "PING_REPLY_OK" in joined:
        pinged = True
    if authed and pinged:
        break
    if client.poll() is not None or ap.poll() is not None:
        break
    time.sleep(0.05)

stop.set()
for p in (ap, client):
    try:
        p.terminate()
    except Exception:
        pass
time.sleep(0.2)
for p in (ap, client):
    try:
        p.kill()
    except Exception:
        pass

print("\n=== RESULT ===", file=sys.stderr)
print(f"handshake authenticated: {authed}", file=sys.stderr)
print(f"ccmp ping round-trip:    {pinged}", file=sys.stderr)

if authed and pinged:
    print("INTEROP_OK", file=sys.stderr)
    sys.exit(0)
sys.exit(1)
