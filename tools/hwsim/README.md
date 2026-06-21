# hwsim interop harness

Scripts for testing `barely-ap` / `barely-cli` against real `hostapd` /
`wpa_supplicant` on a Linux box with `mac80211_hwsim` (no real radio needed).
These were used to validate the full interop matrix; keep them in-tree so the
setup isn't lost (they previously lived in `/tmp` and were wiped on reboot).

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
| `scenA.sh`        | Rust `barely-cli` station → real `hostapd`  | wpa2/wpa3/owe × 2.4/5 GHz |
| `scenB.sh`        | real `wpa_supplicant` → Rust `barely-ap`    | wpa2/wpa3/owe × 2.4/5 GHz |
| `scenMulti.sh`    | several `wpa_supplicant` clients → `barely-ap` | multi-client |
| `scenNan.sh`      | NAN USD vs `wpa_supplicant` (v2.12)         | NAN publish/subscribe/followup |
| `scen6g.sh`       | 6 GHz attempt (needs hostapd ≥ 2.11 for LPI)| 6 GHz NO-IR / LPI |
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
  `SET_STATION` (assoc) — hostapd's "UNASSOC_STA workaround" for drivers
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

## 6 GHz notes

The system `hostapd` 2.10 refuses 6 GHz channels ("NO-IR"); 2.11+ has the
indoor-LPI beaconing logic. Build hostapd from `hostap` with
`CONFIG_IEEE80211AX/AC/BE`, `CONFIG_SAE`, `CONFIG_OWE` to test 6 GHz (which is
WPA3-only). The US regdb rule `5925-7125 @ NO-OUTDOOR, PASSIVE-SCAN, 12 dBm`
allows indoor LPI, so no custom regdb is required.
