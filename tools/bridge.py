#!/usr/bin/env python3
"""
Generic stdio bridge: spawn two processes and cross-connect their stdio
(A.stdout -> B.stdin, B.stdout -> A.stdin), watching both stderr streams for a
set of required marker strings. Exits 0 iff all markers are seen before timeout.

    python3 tools/bridge.py --need AUTHENTICATED --need PING_REPLY_OK \
        --timeout 25 --a "cmd a args" --b "cmd b args"
"""
import argparse
import shlex
import subprocess
import sys
import threading
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--a", required=True, help="command A (shell-split)")
    ap.add_argument("--b", required=True, help="command B (shell-split)")
    ap.add_argument("--need", action="append", default=[], help="required marker (repeatable)")
    ap.add_argument("--timeout", type=float, default=25.0)
    ap.add_argument("--env", action="append", default=[], help="KEY=VALUE for both children")
    args = ap.parse_args()

    import os
    env = dict(os.environ)
    for kv in args.env:
        k, _, v = kv.partition("=")
        env[k] = v

    a = subprocess.Popen(shlex.split(args.a), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    b = subprocess.Popen(shlex.split(args.b), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)

    stop = threading.Event()
    seen = set()

    def pump(src, dst):
        try:
            while not stop.is_set():
                chunk = src.read(1)
                if not chunk:
                    break
                dst.write(chunk)
                dst.flush()
        except Exception:
            pass

    def watch(stream, label):
        for line in iter(stream.readline, b""):
            text = line.decode("utf-8", "replace").rstrip()
            print(f"[{label}] {text}", file=sys.stderr)
            for m in args.need:
                if m in text:
                    seen.add(m)

    threads = [
        threading.Thread(target=pump, args=(a.stdout, b.stdin), daemon=True),
        threading.Thread(target=pump, args=(b.stdout, a.stdin), daemon=True),
        threading.Thread(target=watch, args=(a.stderr, "A"), daemon=True),
        threading.Thread(target=watch, args=(b.stderr, "B"), daemon=True),
    ]
    for t in threads:
        t.start()

    deadline = time.time() + args.timeout
    while time.time() < deadline:
        if all(m in seen for m in args.need):
            break
        if a.poll() is not None or b.poll() is not None:
            time.sleep(0.3)  # let final stderr flush
            break
        time.sleep(0.05)

    stop.set()
    for p in (a, b):
        try:
            p.terminate()
        except Exception:
            pass
    time.sleep(0.2)
    for p in (a, b):
        try:
            p.kill()
        except Exception:
            pass

    missing = [m for m in args.need if m not in seen]
    print("\n=== RESULT ===", file=sys.stderr)
    print(f"required: {args.need}", file=sys.stderr)
    print(f"seen:     {sorted(seen)}", file=sys.stderr)
    if not missing:
        print("BRIDGE_OK", file=sys.stderr)
        sys.exit(0)
    print(f"MISSING:  {missing}", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
