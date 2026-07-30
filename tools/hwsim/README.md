# hwsim interop harness

Scripts for testing `barely-ap` / `barely-cli` against a reference AP and
`wpa_supplicant` on a Linux box with `mac80211_hwsim` (no real radio needed).
These were used to validate the full interop matrix; keep them in-tree so the
setup isn't lost (they previously lived in `/tmp` and were wiped on reboot).

The repository does not embed vendor-specific executable names or source-tree
paths. Supply the installed test binaries through the environment:

```sh
export REFERENCE_AP=/path/to/reference-ap-binary
export REFERENCE_AP_CLI=/path/to/reference-ap-control-client
export WPAS=/path/to/wpa_supplicant
export WCLI=/path/to/wpa_cli
```

## Workflow

1. Cross-compile for the box (aarch64 Linux) and copy the binaries over:
   ```sh
   docker run --rm -v "$PWD":/src:ro -e CARGO_TARGET_DIR=/tmp/target \
     -w /src rust:1-bookworm cargo build --release
   scp /tmp/target/release/barely-{ap,cli} ubuntu@armbuild1.lan:/tmp/
   ```
2. Copy a scenario script over and run it with sudo (the box has passwordless sudo):
   ```sh
   scp tools/hwsim/scenB.sh ubuntu@armbuild1.lan:/tmp/
   ssh ubuntu@armbuild1.lan 'bash /tmp/scenB.sh wpa3 36'
   ```

## The hwsim ACK-provider trick (essential)

`mac80211_hwsim` only generates an ACK for a unicast frame if some **active,
non-monitor vif** on the phy holding the channel **owns the destination
address**. When `barely-ap`/`barely-cli` inject from a **monitor** vif (raw
mode), the monitor has no address, so the peer's frames to us go un-ACKed and
the handshake stalls ("did not acknowledge authentication response").

Fix: co-locate an **IBSS** vif on the same phy, give it **our** MAC, and join a
fixed-freq IBSS on a throwaway BSSID. It contributes the ACK address without
otherwise touching the air:

```sh
sudo iw phy $PHY interface add ibss0 type ibss
sudo ip link set ibss0 address 02:00:00:00:00:00   # = our AP/STA MAC
sudo ip link set ibss0 up
sudo iw dev ibss0 ibss join barelyack $FREQ fixed-freq 02:CA:FE:00:00:00
sudo iw phy $PHY interface add mon0 type monitor    # we inject here
sudo ip link set mon0 up
```

This is **only** needed for the raw monitor-injection modes. The nl80211
kernel-offload AP (`--mode netlink`) uses a real AP vif, which ACKs natively.

## Scenarios

| script            | direction                                   | covers |
|-------------------|---------------------------------------------|--------|
| `scenA.sh`        | Rust `barely-cli` station → reference AP  | wpa2/wpa3/owe × 2.4/5 GHz |
| `scenB.sh`        | real `wpa_supplicant` → Rust `barely-ap`    | wpa2/wpa3/owe × 2.4/5 GHz |
| `scenMulti.sh`    | several `wpa_supplicant` clients → `barely-ap` | multi-client |
| `scenNan.sh`      | NAN USD vs `wpa_supplicant` (v2.12)         | NAN publish/subscribe/followup |
| `scen6g.sh`       | 6 GHz attempt (needs reference AP ≥ 2.11 for LPI)| 6 GHz NO-IR / LPI |
| `scen_nl_full.sh` | `--mode netlink` kernel-offload AP → `wpa_supplicant` | nl80211 START_AP path |
| `scen_nl_multi.sh`| `--mode netlink` AP → 2 `wpa_supplicant`    | netlink multi-station |
| `scen_nl_5.sh`    | `--mode netlink` AP → 5 `wpa_supplicant`    | concurrent scale (5 STAs) |
| `scen_nl_rejoin_ping.sh` | `--mode netlink` AP, STA disconnect+rejoin | rejoin re-handshake + data |
| `scen_nl_vif.sh`  | `--mode netlink --per-sta-vif` → 2 STAs     | per-station AP_VLAN + own GTK |
| `scen_nl_vif_ping.sh` | `--mode netlink --per-sta-vif`, ping via VLAN | per-VLAN data plane |

Usage: `scenA.sh <wpa2|wpa3|owe> <channel>` (channel ≥ 36 → 5 GHz).

## nl80211 kernel-offload AP status (`--mode netlink`)

`scen_nl_full.sh` drives `src/netlink/linux.rs::run_offload_ap`. The full
handshake is **verified end-to-end** against `wpa_supplicant`
(`wpa_state=COMPLETED`):

- `START_AP` → the kernel beacons the AP (the old netlink mode emitted 0 beacons).
- Userspace MLME: **auth** and **assoc** complete.
- Two-step station add: `NEW_STATION` (unassoc, `set=0 mask=0xa0`) →
  `SET_STATION` (assoc) — reference AP's "UNASSOC_STA workaround" for drivers
  without `FULL_AP_CLIENT_STATE`.
- 4-way EAPOL over the nl80211 control port → `NEW_KEY` (PTK + GTK) →
  `SET_STATION` authorize.
- Data plane: CCMP frames flow both directions; **ping works (3/3)** with the
  STA in a netns.

The root cause of the long-standing `EOPNOTSUPP` was a **command-number bug**:
the `nl80211_commands` enum contains aliases (`NEW_BEACON = START_AP`,
`DEL_BEACON = STOP_AP`) that an early extraction counted as real values,
drifting every command after `START_AP` by +2 (so `NEW_STATION` was 21 instead
of 19, `CONTROL_PORT_FRAME` 134 instead of 129). Found via `ftrace` kretprobes
showing `nl80211_new_station` was never entered. The `nl80211_attrs` enum has
no such aliases, so attribute numbers were fine.

Test note: ping the AP with the STA in a separate netns (else both IPs are local
to one host). The test box is an SPR router whose nftables `INPUT` chain has
`policy drop`, so ICMP to the AP needs a temporary accept rule
(`nft insert rule inet filter INPUT iifname "wlan0" ... accept`) — with that,
ping is 3/3. ARP works regardless (not IP-firewalled).

## MLO AP_VLAN support on Linux 6.11

Linux 6.11 predates mac80211's complete MLO AP_VLAN implementation. A station
can associate to an AP MLD, but moving it to an AP_VLAN fails on a partner link
or leaves traffic on the base AP netdev. The backports in
[`patches/`](patches/) are upstream commits `90233b0ad215` and
`1a4a6a22552c`, adapted to v6.11:

- one AP_VLAN netdev receives internal link objects matching its parent MLD;
- each AP_VLAN link has its own default multicast-key slot;
- AP_VLAN multicast/broadcast traffic is transmitted on all MLO links.

Apply and build them against the running kernel's prepared source tree:

```sh
git -C "$LINUX_SRC" apply \
  "$BARELY_AP/tools/hwsim/patches/0001-mac80211-create-separate-links-for-vlan-interfaces.patch" \
  "$BARELY_AP/tools/hwsim/patches/0002-mac80211-vlan-traffic-in-multicast-path.patch"
make -C "/lib/modules/$(uname -r)/build" \
  M="$LINUX_SRC/net/mac80211" modules
```

On an isolated hwsim host, unload any real mac80211 drivers first, then load the
rebuilt core and create MLO-capable virtual radios:

```sh
sudo modprobe -r mac80211_hwsim mac80211
sudo insmod "$LINUX_SRC/net/mac80211/mac80211.ko"
sudo modprobe mac80211_hwsim radios=3 channels=2 mlo=1
```

`scripts/hwsim_mlo_single.sh` is the regression test. With `RUN_LEGACY=0`, it
focuses on the SAE/CCMP-128 MLO station: both links must be valid, ARP and ICMP
must enter and leave the single per-station AP_VLAN, and protected data frames
must be captured in both directions on each link. A second data phase enslaves
the AP_VLAN to a temporary Linux bridge and sends from a separate veth endpoint;
the capture must show that endpoint's non-AP Ethernet source as Address 3 on
protected downlink frames over both MLO links. The same test also checks the
security lifecycle from the AP log: the private VLAN group rotates from
GTK/IGTK slots 1/4 to fresh slots 2/5 before M1, and the M2-derived PTK reaches
the driver while unauthorized before verified M4 opens the controlled port.

## 6 GHz notes

Some older reference AP builds refuse 6 GHz channels ("NO-IR"); newer builds
have indoor-LPI beaconing logic. Build the reference implementation with
`CONFIG_IEEE80211AX/AC/BE`, `CONFIG_SAE`, `CONFIG_OWE` to test 6 GHz (which is
WPA3-only). The US regdb rule `5925-7125 @ NO-OUTDOOR, PASSIVE-SCAN, 12 dBm`
allows indoor LPI, so no custom regdb is required.
