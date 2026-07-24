#!/bin/bash
# One barely-ap process, two independent hwsim AP radios, and one SAE station
# on each band. This is the DBDC regression cell used by hwsim_e2e.sh.

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    exec sudo -n bash "$0" "$@"
fi

BINDIR=${1:?usage: hwsim_dbdc.sh BINS_DIR}
AP="$BINDIR/barely-ap"
WPAS=${WPAS:?set WPAS to the wpa_supplicant binary}
WORK=${RUN_LOG_DIR:-"/tmp/barely-hwsim-dbdc-$$"}
AP_LOG="$WORK/ap.log"
AP_PID=
NS24="rustap-dbdc24-$$"
NS5="rustap-dbdc5-$$"

mkdir -p "$WORK"

cleanup() {
    if [ -n "$AP_PID" ]; then
        kill "$AP_PID" 2>/dev/null || true
        wait "$AP_PID" 2>/dev/null || true
    fi
    for ns in "$NS24" "$NS5"; do
        ip netns exec "$ns" pkill -9 -x wpa_supplicant 2>/dev/null || true
        ip netns del "$ns" 2>/dev/null || true
    done
}
trap cleanup EXIT INT TERM

[ -x "$AP" ] || { echo "missing barely-ap: $AP" >&2; exit 2; }
[ -x "$WPAS" ] || { echo "missing wpa_supplicant: $WPAS" >&2; exit 2; }

# HWSIM_IFACES="AP24 AP5 STA24 STA5" pins the cell to specific radios — used
# on shared hosts where the first hwsim radios belong to a live AP and the
# test must run on its own dynamically-added ones (tools/hwsim/hwsim_add_radio.py).
if [ -n "${HWSIM_IFACES:-}" ]; then
    read -r AP24 AP5 STA24 STA5 <<<"$HWSIM_IFACES"
    [ -n "${STA5:-}" ] || {
        echo "HWSIM_IFACES needs four interface names: AP24 AP5 STA24 STA5" >&2
        exit 2
    }
else
    HW=()
    for _ in $(seq 1 100); do
        HW=()
        for path in /sys/class/net/*/phy80211; do
            iface=$(basename "$(dirname "$path")")
            driver=$(basename "$(readlink -f "/sys/class/net/$iface/device/driver" 2>/dev/null)" 2>/dev/null)
            [ "$driver" = mac80211_hwsim ] && HW+=("$iface")
        done
        IFS=$'\n' HW=($(printf '%s\n' "${HW[@]}" | sort -V))
        unset IFS
        [ "${#HW[@]}" -ge 4 ] && break
        sleep 0.1
    done
    [ "${#HW[@]}" -ge 4 ] || {
        echo "need four hwsim radios (got: ${HW[*]:-none})" >&2
        exit 2
    }
    AP24=${HW[0]}
    AP5=${HW[1]}
    STA24=${HW[2]}
    STA5=${HW[3]}
fi

# A freshly added radio can come up soft-blocked, which fails START_AP/scan
# with no useful diagnostic.
rfkill unblock all 2>/dev/null || true
MAC24=$(cat "/sys/class/net/$AP24/address")
MAC5=$(cat "/sys/class/net/$AP5/address")
PHY24=$(basename "$(readlink -f "/sys/class/net/$STA24/phy80211")")
PHY5=$(basename "$(readlink -f "/sys/class/net/$STA5/phy80211")")

mkdir -p "$WORK/control_$AP24" "$WORK/control_$AP5"
cat >"$WORK/ap.json" <<EOF
{
  "ssid": "rustap-dbdc",
  "passphrase": "password1234",
  "country": "US",
  "mode": "netlink",
  "key_mgmt": "sae",
  "per_sta_vif": true,
  "ocv": false,
  "spr_dhcp_helper": null,
  "radios": [
    {
      "iface": "$AP24",
      "mac": "$MAC24",
      "band": 2.4,
      "channel": 1,
      "width": 20,
      "phy": "ax",
      "ctrl_path": "$WORK/control_$AP24/$AP24"
    },
    {
      "iface": "$AP5",
      "mac": "$MAC5",
      "band": 5,
      "channel": 36,
      "width": 80,
      "phy": "ax",
      "ctrl_path": "$WORK/control_$AP5/$AP5"
    }
  ]
}
EOF

for spec in "$NS24:$STA24:$PHY24:2412" "$NS5:$STA5:$PHY5:5180"; do
    IFS=: read -r ns iface phy freq <<<"$spec"
    ip netns add "$ns"
    iw phy "$phy" set netns name "$ns"
    ip netns exec "$ns" ip link set lo up
    ip netns exec "$ns" ip link set "$iface" up
    ip netns exec "$ns" iw reg set US 2>/dev/null || true
    cat >"$WORK/$ns.conf" <<EOF
ctrl_interface=$WORK/ctrl-$ns
p2p_disabled=1
sae_pwe=1
network={
  ssid="rustap-dbdc"
  psk="password1234"
  key_mgmt=SAE
  ieee80211w=2
  scan_freq=$freq
}
EOF
done

"$AP" --config "$WORK/ap.json" >"$AP_LOG" 2>&1 &
AP_PID=$!

for _ in $(seq 1 100); do
    [ "$(grep -c 'START_AP.*ok' "$AP_LOG" 2>/dev/null || true)" -ge 2 ] && break
    kill -0 "$AP_PID" 2>/dev/null || {
        echo "DBDC AP exited during startup" >&2
        tail -100 "$AP_LOG" >&2
        exit 1
    }
    sleep 0.1
done
[ "$(grep -c 'START_AP.*ok' "$AP_LOG" 2>/dev/null || true)" -ge 2 ] || {
    echo "both DBDC radios did not start" >&2
    tail -100 "$AP_LOG" >&2
    exit 1
}

ip netns exec "$NS24" "$WPAS" -B -Dnl80211 -i"$STA24" -c "$WORK/$NS24.conf"
ip netns exec "$NS5" "$WPAS" -B -Dnl80211 -i"$STA5" -c "$WORK/$NS5.conf"

for _ in $(seq 1 300); do
    STATE24=$(ip netns exec "$NS24" wpa_cli -p "$WORK/ctrl-$NS24" -i"$STA24" status 2>/dev/null |
        sed -n 's/^wpa_state=//p' || true)
    STATE5=$(ip netns exec "$NS5" wpa_cli -p "$WORK/ctrl-$NS5" -i"$STA5" status 2>/dev/null |
        sed -n 's/^wpa_state=//p' || true)
    [ "$STATE24" = COMPLETED ] && [ "$STATE5" = COMPLETED ] && break
    sleep 0.1
done

if [ "${STATE24:-}" != COMPLETED ] || [ "${STATE5:-}" != COMPLETED ]; then
    echo "DBDC association failed: 2.4GHz=${STATE24:-unknown} 5GHz=${STATE5:-unknown}" >&2
    tail -160 "$AP_LOG" >&2
    exit 1
fi

grep -q "station .* -> $AP24\\.4096 " "$AP_LOG" || {
    echo "2.4 GHz station did not receive its radio-local per-station VIF" >&2
    tail -120 "$AP_LOG" >&2
    exit 1
}
grep -q "station .* -> $AP5\\.4096 " "$AP_LOG" || {
    echo "5 GHz station did not receive its radio-local per-station VIF" >&2
    tail -120 "$AP_LOG" >&2
    exit 1
}

echo "PASS: one process completed simultaneous SAE on $AP24/2.4GHz and $AP5/5GHz"
