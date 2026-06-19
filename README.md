# barely-ap (Rust)

A Rust port of [`barely-ap`](./barely-ap) — a minimal IEEE 802.11 Access Point
that speaks **WPA2-PSK / CCMP-128**. It implements just enough of the protocol
to beacon, answer probes, run the full 4-way handshake, and carry encrypted data
to and from associated stations.

This is a faithful, byte-for-byte port of the Python/Scapy reference: every
frame the Rust AP emits is verified equal to what the original `ap.py` produces,
and the resulting AP has been driven end-to-end by the **unmodified reference
Python station** (`client.py`) — completing a real handshake and a CCMP-encrypted
ping round-trip.

> Like the original, this is a demonstration of the CCMP/WPA2 building blocks.
> It has **no protocol security hardening** and is not production software.

## Building

```bash
cargo build --release      # binary at target/release/barely-ap
cargo test                 # full test suite (see "Testing" below)
```

The only system dependency is a Rust toolchain. The cross-language tests
additionally use `python3` with `scapy` installed; they skip gracefully if those
are missing.

## Running

```
barely-ap [--ssid NAME] [--psk PASS] [--mac AA:BB:CC:DD:EE:FF]
          [--channel N] [--ip 10.10.10.1] [--mode stdio|iface] [--iface wlanN]
```

### stdio mode (default, all platforms)

Reads and writes length-prefixed radiotap frames (`<u32-le len><radiotap+802.11>`)
on stdin/stdout — wire-compatible with the reference `ap.py` stdio mode. Bridge
it to a station over a pipe or `socat`. This is how the interop test connects the
Rust AP to the Python client.

### iface mode (Linux)

Binds an `AF_PACKET` raw socket to a monitor-mode interface (real radios or
`mac80211_hwsim`) and sends/receives 802.11 frames directly. This is the mode you
would use against `wpa_supplicant`.

A built-in fake network backend answers DHCP, ARP, and ICMP echo for the AP's
subnet, so an associated client can get a lease (`10.10.10.2+`) and `ping`
the gateway (`10.10.10.1`) with no external services.

## Architecture

| Module        | Responsibility                                                        |
|---------------|-----------------------------------------------------------------------|
| `crypto`      | CCM\* (CCMP), AES-128, AES key-wrap, PBKDF2, PRF-512, HMAC-SHA1        |
| `sae`         | WPA3-SAE (Dragonfly) with Hash-to-Element, ECC group 19 (P-256)       |
| `dot11`       | 802.11 frame build/parse: beacon, probe/auth/assoc, EAPOL, SAE, CCMP   |
| `ap`          | The AP state machine: probe/auth/assoc, 4-way handshake, encrypt/decrypt |
| `client`      | A matching minimal station (the `barely-cli` binary), for interop tests |
| `fakenet`     | Minimal DHCP / ARP / ICMP responder for the AP subnet                 |
| `raw_frames`  | `Link`/`Node` event loop + raw-frame transports (stdio, AF_PACKET monitor) |
| `netlink`     | nl80211 (generic netlink) transport: radio setup + mgmt frame I/O (Linux) |
| `util`        | hex / MAC helpers                                                      |

### Transports (`--mode`)

All transports implement the `raw_frames::Link` trait, so the same event loop
drives any of them:

| `--mode`  | Backend                                  | Platform |
|-----------|------------------------------------------|----------|
| `stdio`   | length-prefixed frames on stdin/stdout   | all      |
| `iface`   | `AF_PACKET` raw socket on a monitor iface (`raw_frames::af_packet`) | Linux |
| `netlink` | nl80211 generic netlink (`netlink`)      | Linux    |

The raw-frame transports live under `src/raw_frames/`; the nl80211 transport
lives under `src/netlink/`. The netlink message-encoding layer
(`netlink::msg`) is platform-independent and unit-tested (`cargo test`), while
the socket layer is Linux-only. nl80211 mode configures the radio (interface
type + channel) and carries **management** frames via `NL80211_CMD_FRAME`;
userspace-encrypted CCMP **data** frames still use the monitor path. The
Linux-only code is type-checked here via
`cargo check --target x86_64-unknown-linux-gnu` but not run on non-Linux hosts.

Unlike the threaded Python original, the AP is a single-threaded state machine:
`Ap::handle_incoming(frame)` mutates state and returns `Outgoing { frames,
to_network }`. The driver transmits `frames`, hands `to_network` to the fake
network, and re-encrypts its replies via `Ap::deliver_to_station`.

## Testing — how Rust output is checked against the Python

`tools/gen_vectors.py` drives the **actual reference Python** (`ccmp.py`,
`ap.py` via scapy, with small shims for modern scapy) and emits golden vectors
into `tests/vectors.json`. The Rust tests assert byte-for-byte equality.

| Test file                 | What it proves                                                                 |
|---------------------------|--------------------------------------------------------------------------------|
| `tests/crypto_vectors.rs` | PMK, PTK/PRF-512, CCMP encrypt/decrypt, AES key-wrap, MIC == Python            |
| `tests/frame_vectors.rs`  | Beacon / probe / auth / assoc / EAPOL m1+m3 / CCMP data == scapy, and parsers  |
| `tests/ap_handshake.rs`   | The state machine reproduces `ap.py`'s handshake frames exactly; bad-MIC deauth |
| `tests/fakenet_vectors.rs`| DHCP/ARP/ICMP replies (built from scapy requests) are well-formed w/ checksums |
| `tests/interop.rs`        | **Live, both roles** over real stdio pipes (see below)                          |

### Live interop — both directions

The `barely-cli` binary is a matching minimal Rust station, so the stdio bridge is
tested with the roles swapped. All three complete a real WPA2/CCMP handshake **and**
an ICMP ping round-trip:

| Direction                              | What it proves                              |
|----------------------------------------|---------------------------------------------|
| Python `client.py` → **Rust AP**       | Rust AP serves the reference station        |
| **Rust client** → **Rust AP**          | the Rust pair interoperates                 |
| **Rust client** → Python `ap.py`       | Rust station is accepted by the reference AP|

Run them by hand with the generic bridge:

```bash
cargo build
# Rust client <-> Rust AP
python3 tools/bridge.py --need AUTHENTICATED --need PING_REPLY_OK \
  --a "target/debug/barely-ap  --mode stdio --mac 02:00:00:00:00:00" \
  --b "target/debug/barely-cli --ping       --mac 02:00:00:00:ab:cd"
# Rust client <-> reference Python AP
python3 tools/bridge.py --need AUTHENTICATED --need PING_REPLY_OK --env AP_MAC=02:00:00:00:00:00 \
  --a "python3 tools/run_ap.py" \
  --b "target/debug/barely-cli --ping --mac 02:00:00:00:ab:cd"
```

Regenerate the golden vectors after changing the reference:

```bash
python3 tools/gen_vectors.py > tests/vectors.json
```

Run the live interop bridge by hand:

```bash
cargo build
python3 tools/bridge_test.py target/debug/barely-ap   # prints INTEROP_OK
```

## WPA3-SAE (real-world)

The AP and client support **WPA3-Personal (SAE)**, enabled with `--sae`:

```bash
barely-ap  --mode stdio --sae --ssid turtlenet --psk password1234
barely-cli --mode stdio --sae --ping            # Hash-to-Element
barely-cli --mode stdio --sae-hnp --ping        # legacy hunting-and-pecking
```

Built to be accepted by a real WPA3 station:

- **Both PWE methods** — **Hash-to-Element** (group 19 / P-256) and legacy
  **hunting-and-pecking**; the AP selects per-STA from the commit status code.
- **Dragonfly** commit/confirm over Authentication frames → PMK.
- **SHA-256 4-way handshake** — `KDF-SHA256` PTK, `HMAC-SHA256-128` EAPOL MIC,
  Key Descriptor Version 0.
- **PMF / 802.11w** — RSN advertises MFPR|MFPC + **BIP-CMAC-128** group-mgmt
  cipher, an **RSNXE** advertises H2E, message 3 delivers the **IGTK**, and
  group-addressed robust management frames carry a BIP **Management MIC Element**.

### Verification — anchored to standards *and* an independent implementation

There are no Rust-only shortcuts for the WPA3 crypto. Every piece is anchored to
a published standard, and the full handshake is cross-checked against a second,
independent implementation:

- **IEEE 802.11-2020 Annex J.10** (`tests/sae_vectors.rs`): H2E PWE matches
  `pwe_19`; hunting-and-pecking PWE (derived independently from the password) +
  commit/k/KCK/PMK/PMKID match the standard's protocol vector.
- **RFC 4493** (`tests/crypto_vectors.rs`): AES-128-CMAC, the BIP primitive.
- **Independent Python SAE** (`tools/wpa3_sae.py`, a from-scratch pure-Python
  P-256 implementation, self-checked against J.10): `tests/interop.rs` runs the
  full SAE → SHA-256 4-way → CCMP-ping over the stdio bridge in **all four
  cross combinations** — Python-client↔Rust-AP and Rust-client↔Python-AP, each
  for H2E and hunting-and-pecking. Because the two implementations share no code,
  agreement on random handshakes validates the SHA-256 PTK/MIC and the frame
  formats, not just self-consistency.
- **PMF** (`tests/sae_handshake.rs`): after SAE the STA installs the AP's IGTK
  and accepts a BIP-protected group deauth (and rejects a tampered one); a wrong
  password fails to associate.

Remaining scope limits: group 19 only (not 20/21/FFC), and real
`wpa_supplicant`/hwsim interop isn't run on this host (macOS) — the independent
Python implementation stands in for that cross-check.

## Relationship to the original

The Python sources are preserved under [`barely-ap/`](./barely-ap) and are used
only as the reference for the golden vectors and the interop client — they are
not required to build or run the Rust AP.
