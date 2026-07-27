# barely-ap (Rust)

Auto-coded wifi 7 userland access point for linux.

> This is experimental software. Its WPA state machines include replay,
> cache-lifetime, anti-clogging, and key-erasure hardening, but it has not had
> the independent review expected for production authentication software.

## Building

```bash
cargo build --release      # binary at target/release/barely-ap
cargo test                 # full test suite (see "Testing" below)
```

## Running

Configuration comes from a JSON config file (`--config`), with CLI flags as
overrides:

```
barely-ap --config barely-ap.json
barely-ap --config FILE.json [--ssid NAME] [--mac AA:BB:CC:DD:EE:FF]
          [--channel N] [--ip 10.10.10.1] [--mode stdio|iface|netlink] [--iface wlanN]
          [--cipher ccmp-128|gcmp-128|ccmp-256|gcmp-256]
          [--band 2.4|5|6] [--sae|--owe|--transition] [--ocv] [--btm] [--rnr] [--per-sta-vif]
          [--guest]
```

The config file (see `barely-ap.example.json`) keeps shared settings such as
`ssid`, credentials, `key_mgmt`, `pairwise_cipher`, country, and policy toggles
at the top level. Per-radio settings (`interface`, `mac`, `band`, `channel`,
`width`, `phy`, and `ctrl_path`)

For the AP, non-default pairwise ciphers use Linux/mac80211
authenticated-encryption offload and therefore require `mode: "netlink"`.
`barely-cli` also implements WPA2 single-link CCMP/GCMP protection in userspace
(GCMP uses RustCrypto `aes-gcm`) for reverse-direction interop. 

Unknown keys and type mismatches are hard errors. See
[`src/config/`](src/config/).
Passwords are accepted only through the JSON `passphrase`, `wpa_psk_file`, or
`sae_psk_file`
settings;

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

### SPR uplink client (Linux)

`barely-cli` can expose its authenticated station data plane as a TAP netdev.
It does not assign an address, run DHCP, or install a route. Instead it writes
the same `CONNECTED <unix-epoch>` state file that SPR's `wifi_uplink` action
script produces, and SPR's existing DHCP client owns the TAP interface:

```bash
barely-cli --spr-config /configs/wifi_uplink/wpa.json --spr-iface wlan0 \
  --scan-iface wlan0-phy --mode iface --iface wlan0mon \
  --tap wlan0 --state-file /state/wifi_uplink/status.wlan0
```

The logical `--spr-iface` selects the entry in SPR's existing `wpa.json`.
`--scan-iface` is its managed VIF and `--iface` is a monitor VIF on the
same PHY. If SPR needs the TAP to retain the logical name (normally `wlan0`),
the startup wrapper can rename the VIF to `wlan0-phy` first. The
supervisor must create the monitor VIF and retain the managed sibling for ACKs;
barely-ap brings the scan VIF up and tunes the monitor after selection.
`--tap` creates and brings up only the Ethernet netdev. Credentials are read
directly from SPR JSON; command-line passwords are rejected.

The client validates SSID/BSSID/RSN/AKM/PMF before authenticating,
supports WPA2-PSK, WPA-PSK-SHA256, WPA3-SAE, and OWE, and handles protected
reference AP group rekeys. 

```bash
barely-cli --scan --scan-iface wlan0-phy
# Optional directed probe:
barely-cli --scan --scan-iface wlan0-phy --scan-ssid hidden-network
```

## Architecture

[`ARCHITECTURE.md`](ARCHITECTURE.md). The primary protocol domains are:

| Module | Responsibility |
| --- | --- |
| `auth` | Shared RSN/EAPOL/crypto plus dedicated `wpa2` and `wpa3` implementations |
| `frames` | Low-level management/data frames, channel helpers, and Wi-Fi 4/5/6/7 information elements |
| `mlo` | Multi-Link elements, association, EAPOL integration, and link-scoped keys |
| `group_keys` | GTK/IGTK/BIGTK, BIP, and group rekey messages |
| `roaming` | BSS Transition Management and neighbor reports |
| `action_frames` | SA Query, TWT, WNM, and Radio Measurement action frames |
| `structures` | Shared wire/security/PHY definitions plus the runtime-type discovery surface |
| `ap` / `client` | AP and station state-machine orchestration |
| `raw_frames` / `netlink` | Frame transports and Linux nl80211 integration |

### Transports (`--mode`)

All transports implement the `raw_frames::Link` trait, so the same event loop
drives any of them:

| `--mode`  | Backend                                  | Platform |
|-----------|------------------------------------------|----------|
| `stdio`   | length-prefixed frames on stdin/stdout   | all      |
| `iface`   | `AF_PACKET` raw socket on a monitor iface (`raw_frames::af_packet`) | Linux |
| `netlink` | nl80211 generic netlink (`netlink`)      | Linux    |

The raw-frame transports live under `src/raw_frames/`; the nl80211 transport
lives under `src/netlink/`. Its ABI constants, helper policy, and message
encoding are separate platform-independent modules, while socket and AP runtime
code live under `src/netlink/linux/`. nl80211 mode configures the radio,
publishes stations and keys, sends control-port EAPOL, and leaves the protected
data plane to mac80211. The Linux-only code is type-checked here via
`cargo check --target x86_64-unknown-linux-gnu` but not run on non-Linux hosts.

Unlike the threaded Python original, the AP is a single-threaded state machine:
`Ap::handle_incoming(frame)` mutates state and returns `Outgoing { frames,
to_network }`. The driver transmits `frames`, hands `to_network` to the fake
network, and re-encrypts its replies via `Ap::deliver_to_station`.

## Testing — how Rust output is checked against the Python

`tools/gen_vectors.py` drives the ** reference Python** (`ccmp.py`,
`ap.py` via scapy, with small shims for modern scapy) and emits test vectors
into `tests/vectors.json`. The Rust tests assert equality.

| Test file                 | What it proves                                                                 |
|---------------------------|--------------------------------------------------------------------------------|
| `tests/crypto_vectors.rs` | PMK, PTK/PRF-512, CCMP encrypt/decrypt, AES key-wrap, MIC == Python            |
| `tests/cipher_suites.rs`  | CCMP/GCMP selectors, TK/PTK sizing, EAPOL lengths, userspace crypto/tamper rejection |
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
  --a "target/debug/barely-ap  --config tests/interop-config.json --mode stdio --mac 02:00:00:00:00:00" \
  --b "target/debug/barely-cli --config tests/interop-config.json --ping --mac 02:00:00:00:ab:cd"
# Rust client <-> reference Python AP
python3 tools/bridge.py --need AUTHENTICATED --need PING_REPLY_OK --env AP_MAC=02:00:00:00:00:00 \
  --a "python3 tools/run_ap.py" \
  --b "target/debug/barely-cli --config tests/interop-config.json --ping --mac 02:00:00:00:ab:cd"
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

The AP and client support **WPA3-Personal (SAE)**, enabled with `--sae`.
The password in this test-only example is read from the config file:

```bash
barely-ap  --config tests/interop-config.json --mode stdio --sae --ssid turtlenet
barely-cli --config tests/interop-config.json --mode stdio --sae --ping      # Hash-to-Element
barely-cli --config tests/interop-config.json --mode stdio --sae-hnp --ping  # legacy hunting-and-pecking
```

Built to be accepted by a real WPA3 station:

- **Both PWE methods** — **Hash-to-Element** (group 19 / P-256) and legacy
  **hunting-and-pecking**; the AP selects per-STA from the commit status code.
- **Dragonfly** commit/confirm over Authentication frames → PMK.
- **SHA-256 4-way handshake** — `KDF-SHA256` PTK, `HMAC-SHA256-128` EAPOL MIC,
  Key Descriptor Version 0.
- **PMF / 802.11w (enforced, not just advertised)** — RSN advertises MFPR|MFPC +
  **BIP-CMAC-128** group-mgmt cipher, an **RSNXE** advertises H2E, message 3
  delivers the **IGTK**. Robust management frames are protected (CCMP for
  unicast, BIP **Management MIC Element** for group), and enforcement is real:
  - a PMF STA/AP **drops spoofed unprotected** Deauth/Disassoc/Action frames and
    acts only on BIP-valid (group) or CCMP-valid (unicast) ones;
  - the AP runs **SA Query** — a (re)association request from an already-PMF-
    associated STA is rejected with **status 30** + a protected SA Query and the
    live session is preserved, instead of being torn down by a spoofed frame.

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
- **PMF enforcement** (`tests/pmf.rs`): spoofed *unprotected* deauth/disassoc
  (broadcast and unicast) and a forged-key BIP frame are ignored while the
  session stays up; a valid BIP (group) or CCMP (unicast) deauth disconnects; a
  spoofed unprotected (re)assoc request triggers SA Query (status 30 + protected
  SA Query) and preserves the session; the AP drops unprotected robust mgmt and
  tears down only on a valid CCMP-protected deauth. A WPA2 control case shows the
  non-PMF AP restarts (no SA Query), confirming the PMF path is what changes it.

## Verified against real reference AP & wpa_supplicant (mac80211_hwsim)

Every combination below was run on Linux with `mac80211_hwsim` radios against
**real reference AP / wpa_supplicant v2.10**, completing the full handshake with data
flowing (ICMP ping replies through the AP's fakenet):

| direction | WPA2 | WPA3-SAE | OWE |
|---|---|---|---|
| Rust client → reference AP (2.4 / 5 GHz) | ✅ | ✅ | ✅ |
| Rust AP ← wpa_supplicant (2.4 / 5 GHz) | ✅ | ✅ | ✅ |

The AP also serves **multiple clients** (verified with two
wpa_supplicant stations, WPA2 + WPA3).

**NAN USD** interoperates with wpa_supplicant v2.12's NAN Discovery Engine both
ways: the Rust subscriber discovers a wpa_supplicant publish, and wpa_supplicant
discovers a Rust publish (`NAN-DISCOVERY-RESULT`), service IDs and service info
matching. The `barely-nan` binary runs the engine on a monitor interface.

Hwsim ACK note: a userspace monitor-injection endpoint has no vif address for
mac80211_hwsim to ACK, so an active co-located vif (an `ibss`/`mesh` vif on the
same phy, holding the channel) supplies the address — that is how the original
demo's co-located managed vif worked, made channel-stable for newer kernels.

### nl80211 kernel-offload AP (`--mode netlink`)

The netlink mode is a real nl80211 AP that offloads beaconing and data-plane
CCMP/GCMP to the kernel (`START_AP` + `NEW_KEY`), while the 4-way handshake stays in
`Ap`. The full handshake is verified end-to-end against `wpa_supplicant`
(`wpa_state=COMPLETED`): two-step station add (the reference AP "UNASSOC_STA
workaround"), 4-way over the nl80211 control port, PTK/GTK install, authorize,
and authenticated data both directions (**ping works**, STA in a netns). The
matrix explicitly covers CCMP-128, GCMP-128, CCMP-256, and GCMP-256 against
`wpa_supplicant`; the reverse Rust-client matrix covers the same four suites
against reference AP. See
`tools/hwsim/README.md`.

It picks the `START_AP` RSN AKM from the AP's security mode — **WPA2-PSK,
WPA3-SAE, or OWE** — so it is no longer PSK-only. The SAE/OWE exchange runs in
userspace (the kernel frames the BSS with `AUTH_TYPE=OPEN`, MFP signalled by the
beacon RSN), which is what makes a **6 GHz** AP possible (6 GHz mandates WPA3).
A WPA3-SAE 6 GHz AP at **320 MHz** is verified end-to-end (`scen_nl_320ping.sh`).

**Channel width** (`width` config / `--width`): 20/40/80/160/320 MHz. The HT/VHT
operation + capabilities (5 GHz) and HE/EHT operation + capabilities (6 GHz)
elements encode the width and center channel — including the VHT "Supported
Channel Width Set" and EHT "320 MHz in 6 GHz" capability bits, which a station
caps itself to regardless of the Operation element — and `START_AP` sets
`NL80211_ATTR_CHANNEL_WIDTH` + `CENTER_FREQ1`.

**80, 160 and 320 MHz are all verified end-to-end** on hwsim (AP + client both
report the same `width`):

- **80 MHz** (5 GHz) — direct.
- **160 MHz** (5 GHz) — needs the `hwsim6g` module to clear the DFS `RADAR`/
  `NO-IR` flags first (every 5 GHz 160 MHz block spans radar channels 52–64,
  which the kernel won't beacon on without a CAC).
- **320 MHz** (6 GHz, 802.11be) — AP + client both `width: 320 MHz, center1:
  6105`, **encrypted ping 3/3**. This required WPA3-SAE on the netlink path (6
  GHz mandates WPA3), the `hwsim6g` NO-IR clear, the EHT Capabilities advertising
  the "320 MHz in 6 GHz" bit with the correct per-bandwidth MCS maps, and the EHT
  Operation CCFS0/CCFS1 ordering (CCFS1 = the 320 MHz center). The
  `nl80211_chan_width` value for 320 is `13`, not the position-counted `6`.

The 6 GHz / 320 MHz path uses the **WPA3-SAE netlink AP** below.

Verified to scale and recover: **5 concurrent stations** all reach
`COMPLETED`/keyed, and a **client that disconnects and rejoins** re-handshakes
and passes data again. Reliability properties borrowed from reference AP:

- **EAPOL m1/m3 retransmission + 4-way timeout** — the AP caches the m1/m3 it
  last sent and, on a tick, retransmits it if the matching m2/m4 hasn't arrived
  within `EAPOL_TIMEOUT` (up to `MAX_EAPOL_RETRIES`), then deauthenticates and
  drops a station whose 4-way never completes. A single dropped handshake frame
  self-heals instead of stalling the association forever (the #1 flaky-link
  failure). Wired into both the raw `on_tick` and the netlink event loop.
- **Duplicate (re)Association tolerance** — a retried Assoc for a handshake
  already in progress re-sends the assoc-response and the **same** m1 (the ANonce
  is reused *only* while still awaiting that station's m2, which stays KRACK-safe
  because a reassociation still gets a fresh ANonce).
- **Idempotent Authentication re-answer** — a retransmitted Auth within the
  backoff window is re-answered instead of dropped, so a lost auth-response
  doesn't stall a client over a lossy link, without restarting the session.
- **Disconnect/resync detection** — an encrypted data frame from a station the
  AP has *no* state for (it restarted or pruned the STA) triggers a deauth so the
  client tears down and re-handshakes rather than sending into a black hole; a
  data frame from a station still mid-handshake is dropped, not deauthed.
- **Separate command vs event netlink sockets** — synchronous commands
  (`NEW_STATION`/`NEW_KEY`/…) run on their own socket so their ACK read-loop
  never swallows an async auth/assoc/EAPOL frame on the event socket.
- **Session restart on (re-)Authentication** — a new Auth drops the station's
  prior ANonce/keys/association, so a client that left without a deauth the AP
  could see still re-handshakes cleanly (otherwise the reconnect 4-way fails
  with a MIC/"wrong key" against stale state). Group key is installed once
  (BSS-wide), not per-station, so a rejoin doesn't reset the group PN.
- **Idle reaping** (`prune_idle`, reference AP `ap_max_inactivity`) — a station that
  vanishes without deauthing is disassociated after the advertised BSS Max Idle
  period so it doesn't leak state forever.

#### Per-station VIF / AP_VLAN (`--per-sta-vif`)

reference AP's `per_sta_vif`: each associated station is placed in its own kernel
`AP_VLAN` interface (`NEW_INTERFACE` iftype AP_VLAN → `SET_STATION` with
`NL80211_ATTR_STA_VLAN`) and gets its **own GTK** installed on that VLAN, so a
station cannot read broadcast/multicast addressed to another. Verified on hwsim:
two stations land on `apvlan1`/`apvlan2` (each its own group key), per-VLAN data
plane passes traffic (**ping works through the VLAN**), and rejoin recreates the
VLAN cleanly.

#### Intrusion logging (`failures.rs`)

Failed credential and decryption attempts are recorded in a fingerprinted,
deduplicated log (`Ap::failures()`): wrong-PSK (4-way m2 MIC mismatch), SAE
commit/confirm failures, CCMP data-frame MIC failures, and protected-management
(BIP/CMAC) failures. Each entry is keyed by a client fingerprint — its MAC plus
an FNV-1a hash of the association IEs, so a MAC-spoofing attacker is still
distinguishable — and a [`FailureKind`]. The log keeps the 25 most recent
*distinct* keys; an identical repeat bumps a counter (and the per-event log line
prints the running attempt number) instead of consuming a slot, so one client
hammering the AP can't evict the history of every other client.

#### WMM / WME QoS (`wmm` config, default on)

WMM is a config setting (`wmm` / `--width` companion). When on, the AP advertises
the WMM parameter element and the client advertises the WMM Information element in
its (Re)Assoc Request; both then exchange **QoS Data** frames (subtype 8, AC_BE /
TID 0), whose 2-byte QoS Control feeds the CCMP nonce + AAD. The AP only sends
QoS Data to a station that negotiated WMM (`Station.wmm`), falling back to plain
Data otherwise. Verified on hwsim: with a real `wpa_supplicant` client every data
frame to/from the Rust AP is QoS Data (`wlan.fc.type_subtype == 0x28`, both ToDS
and FromDS) and the ping passes; the Rust client's (Re)Assoc Request carries the
WMM IE (`dd07 0050f2 02 00 01`). Setting `wmm: false` omits the element and uses
plain Data both directions.

#### Runtime control interface (`--ctrl PATH` / `ctrl_path`)

A reference AP-style control socket (Unix datagram) for live management + monitoring
of the netlink AP. Clients send text commands and get replies; `ATTACH`
subscribes to the event stream. Commands: `PING`, `STATUS` (ssid / channel /
station counts), `STA-DUMP`, `DEAUTH <mac>` (admin kick), `FAILURES` (dump the
intrusion log), `ATTACH`/`DETACH`. The AP emits reference AP-style events —
`AP-STA-CONNECTED <mac>` (after a verified 4-way), `AP-STA-DISCONNECTED <mac>
reason=<n>`, `AP-STA-AUTH-FAILED <mac> kind=<k> count=<n>` — to the log in every
mode and to attached clients on the socket. Verified on hwsim: a `wpa_supplicant`
client connecting logs `AP-STA-CONNECTED`, `STATUS`/`STA-DUMP` report it, an admin
`DEAUTH` kicks it, and the attached client receives the live
`AP-STA-DISCONNECTED` event. The command layer (`control::handle_command`) is
portable and unit-tested.

#### Multiple BSSes (`bss` config array)

Several SSIDs on one radio. Each `bss` entry (its own `ssid`, `bssid`/`mac`, and
optional `key_mgmt`/`passphrase` — inheriting the primary's when omitted) gets
its own AP netdev (`NEW_INTERFACE` iftype AP on the primary's wiphy, assigned the
BSS's BSSID) and runs an **independent** `run_offload_ap` on its own thread — its
own 4-way, keys, and stations — so each BSS reuses the verified single-BSS path
unchanged. BSSIDs must be distinct; multi-BSS is netlink-only. Config parsing +
radio-parameter inheritance are unit-tested; the live netdev bring-up is pending
hwsim verification.

#### DBDC / multiple independent radios (`radios` config array)

A single process can operate multiple independent radios concurrently. This is
intended for DBDC cards that expose one netdev per band, such as 2.4 GHz on
`wlan1` and 5 GHz on `wlan2`. Put settings shared by every radio at the top
level, then override the identity and channel settings in each
`radios` entry:

```json
{
  "ssid": "s5210",
  "country": "US",
  "mode": "netlink",
  "key_mgmt": "sae",
  "sae_psk_file": "/configs/wifi/sae_passwords",
  "per_sta_vif": true,
  "ocv": false,
  "spr_api_socket": "/state/wifi/apisock",
  "spr_dhcp_helper": "/hostap_dhcp_helper",
  "radios": [
    {
      "iface": "wlan1",
      "mac": "02:00:00:00:00:01",
      "band": 2.4,
      "channel": 1,
      "width": 20,
      "phy": "ax",
      "ctrl_path": "/state/wifi/control_wlan1/wlan1"
    },
    {
      "iface": "wlan2",
      "mac": "04:f0:21:c9:1e:ff",
      "band": 5,
      "channel": 36,
      "width": 80,
      "phy": "ax",
      "ctrl_path": "/state/wifi/control_wlan2/wlan2"
    }
  ]
}
```

Replace each example MAC with that netdev's real MAC. Every entry uses the
top-level SSID, credentials, security, station-VIF policy, and SPR integration.
Radio entries deliberately cannot override those shared settings. Interfaces,
BSSIDs, and control paths must be unique, and multi-radio operation is
netlink-only. All seven fields are required in every radio entry so a
missing value cannot silently fall back to another radio's defaults. The
complete Linux runner includes a DBDC cell that associates SAE stations to the
2.4 GHz and 5 GHz radios simultaneously from one AP process. Radio-specific
CLI overrides are rejected when `radios` is present; edit the intended array
entry instead.

#### Guest network (`guest` / `ap_isolate`)

Client isolation, reference AP's `ap_isolate`: a guest BSS never carries traffic
between its own stations — upstream (gateway/uplink) traffic is unaffected. Set
`"guest": true` on a `bss` entry to isolate that SSID only, or top-level
(`--guest`) to isolate the primary BSS. Enforced in both data planes:

- **netlink mode** — `SET_BSS` sets `NL80211_ATTR_AP_ISOLATE`, so mac80211
  stops intra-BSS station-to-station bridging in the kernel.
- **userspace modes** — the AP drops a decrypted uplink frame addressed to
  another associated station, and drops a downlink frame whose *source* is one
  of its own stations (station traffic hairpinned back by an external bridge),
  so isolation holds even when `to_network` feeds a real bridge/TAP.

Unicast isolation only, like reference AP: stations still share the BSS group
key, so combine with `per_sta_vif` (per-station GTK on an AP_VLAN) when guests
must also be unable to read each other's broadcast/multicast. Network-level
segregation (separate subnet/VLAN, firewalling guest→LAN) remains the
supervisor's job — e.g. SPR policies keyed on the guest BSS's own netdev.
Tested in `tests/ap_handshake.rs` (isolation drops + gateway traffic control
cases) and config parsing unit tests.

#### DFS — 5 GHz radar channels (CAC + radar response)

Before beaconing on a DFS chandef (any 20 MHz subchannel in 52-64 / 100-144), the
AP runs the Channel Availability Check: `NL80211_CMD_RADAR_DETECT` → wait for the
`RADAR_CAC_FINISHED` event (60 s, or 600 s on ETSI weather channels) → `START_AP`.
A `RADAR_DETECTED` event during operation vacates the channel (`STOP_AP`) within
the move time and exits with a recommended non-DFS fallback channel
(`fallback_channel`, UNII-1/UNII-3) named in the log + error, so a supervisor can
restart there without a CAC. The kernel/driver performs the actual radar
detection; userspace only orchestrates the CAC and the response — no radar DSP in
userspace. `chandef_is_dfs` and `fallback_channel` are unit-tested.

Two pieces are deliberately box-gated and not yet done: (1) the live
`RADAR_DETECT` round-trip — the test radio returned `EOPNOTSUPP` (driver-dependent;
needs an strace-diff against reference AP to confirm message vs. driver support); and
(2) an *in-process* channel switch on radar (vs. the current vacate-and-exit),
which would restructure the verified beaconing loop and is only worth doing once
the CAC itself is confirmed on hardware.

### 6 GHz and 802.11be / MLD

6 GHz is fully implemented and **runs on air on 6 GHz**: HE Capabilities, HE
Operation (with 6 GHz Operation Information), HE 6 GHz Band Capabilities, 6 GHz
frequency encoding and a 6 GHz (HE-only) beacon builder, driven by `--band 6`.
With `--band 6` the AP beacons on 6 GHz (e.g. channel 37 / 6135 MHz) and
**Wireshark/`tshark` decodes the beacon** — frequency 6135 MHz, HE Capabilities
and HE Operation elements — confirming spec-compliant 6 GHz frames.

For 802.11be/MLD, the Basic Multi-Link element (carrying the MLD MAC) and EHT
Capabilities element are implemented and tested. The **Reduced Neighbor Report**
(`--rnr`) — how a 2.4/5 GHz AP advertises its co-located 6 GHz / MLD affiliated
AP for out-of-band discovery — is implemented and verified on air.

#### Enabling 6 GHz on a signed-regdb kernel

The test kernel sets `CONFIG_CFG80211_REQUIRE_SIGNED_REGDB=y` and every regdb
country flags 6 GHz `NO-IR` for AP mode (reference AP refuses it; reference implementation's own hwsim
tests `HwsimSkip` 6 GHz). For testing on the *virtual* hwsim radios, the small
reversible kernel module in `tools/hwsim/hwsim6g/` clears the `NO-IR` flag on
each hwsim wiphy's 6 GHz channels (`insmod hwsim6g.ko`; reset by reloading
`mac80211_hwsim`). With it loaded, both reference AP **and** this AP beacon on 6 GHz.
The full SAE handshake on 6 GHz additionally needs an ACK source for the raw
monitor-injection path (IBSS/mesh aren't permitted on 6 GHz) — i.e. the
nl80211 kernel-offload AP extended to SAE; the beacon/HE layer above is verified.

Remaining limits: group 19 only (not 20/21/FFC). Full MLD multi-link operation
(per-link profiles, multi-link (re)association and key derivation) is a larger
effort layered on the elements above.

## Standard AP/STA features (reference AP-style)

Beyond the handshakes, these standard features are implemented and tested:

| Feature | What | Test |
|---|---|---|
| CCMP replay protection | reject non-increasing packet numbers (PN starts at 1) | `tests/pmf.rs` |
| EAPOL-Key replay counters | reject replayed/forged 4-way + group messages | (handshake tests) |
| GTK rekeying | Group Key Handshake (`wpa_group_rekey`): rotate GTK/IGTK | `tests/rekey.rs` |
| 802.11n HT | HT Capabilities + HT Operation elements | `tests/frame_vectors.rs` |
| WMM/QoS | WMM Parameter element (default EDCA) | `tests/frame_vectors.rs` |
| TIM/DTIM | beacon TIM element | `tests/frame_vectors.rs` |
| PMKSA caching | cache PMK; fast reconnect skipping SAE (`okc`) | `tests/sae_handshake.rs` |
| Transition mode | mixed WPA2-PSK + WPA3-SAE RSN; accept both | `tests/sae_handshake.rs` |
| BSS Max Idle / inactivity | advertise max-idle; disassociate idle STAs | `tests/sae_handshake.rs` |
| Beacon Protection | BIGTK delivery + BIP-protected beacons (`beacon_prot`) | `tests/sae_handshake.rs` |
| 802.11ac VHT | VHT Capabilities + Operation (5 GHz) | `tests/frame_vectors.rs` |
| Extended Capabilities | BTM + Beacon Protection bits | `tests/frame_vectors.rs` |
| Supported Operating Classes | current operating class element | `tests/frame_vectors.rs` |
| 802.11k RRM | RRM Enabled Caps + Neighbor Report action | `tests/features2.rs` |
| 802.11v BTM | BSS Transition Management (steer / disassoc-imminent) | `tests/features2.rs` |
| OCV | Operating Channel Validation (OCI in 4-way, anti-MITM) | `tests/features2.rs` |
| OWE | Opportunistic Wireless Encryption (RFC 8110, P-256 DH) | `tests/features2.rs`, `tests/sae_vectors.rs` |
| 802.11h CSA | Channel Switch Announcement + apply | `tests/features2.rs` |
| Multiple BSSID | co-located BSS element | `tests/features2.rs` |
| WNM disassoc-imminent | STA disconnects on protected BTM | `tests/features2.rs` |

## Relationship to the original

The Python sources are preserved under [`barely-ap/`](./barely-ap) and are used
only as the reference for the golden vectors and the interop client — they are
not required to build or run the Rust AP.
