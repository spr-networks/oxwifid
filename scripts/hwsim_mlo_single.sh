#!/bin/bash
# Single-interface MLD AP cell: barely-ap as a 2-link cross-band MLD
# (ch1/2.4GHz + ch36/5GHz) on ONE hwsim wiphy, wpa_supplicant MLD client on a
# second. Non-destructive twin of mld_e2e.sh for shared hosts: it never
# touches the mac80211_hwsim module — pin it to radios created with
# tools/hwsim/hwsim_add_radio.py --mlo via HWSIM_IFACES="AP STA".
#
# PASS = client wpa_state COMPLETED with both MLD links valid.

set -u

if [ "$EUID" -ne 0 ]; then
    exec sudo -n env WPAS="${WPAS:-}" WCLI="${WCLI:-}" \
        HWSIM_IFACES="${HWSIM_IFACES:-}" RUN_LOG_DIR="${RUN_LOG_DIR:-}" \
        bash "$0" "$@"
fi

BINDIR=${1:?usage: hwsim_mlo_single.sh BINS_DIR}
AP_BIN="$BINDIR/barely-ap"
WPAS=${WPAS:?set WPAS to the wpa_supplicant binary}
WCLI=${WCLI:?set WCLI to the wpa_cli binary}
HWSIM_IFACES=${HWSIM_IFACES:?set HWSIM_IFACES="AP_IFACE STA_IFACE" (MLO-capable hwsim radios)}
WORK=${RUN_LOG_DIR:-"/tmp/barely-hwsim-mlo-$$"}
NS="rustap-mlo-$$"
AP_PID=

read -r AP STA <<<"$HWSIM_IFACES"
[ -n "${STA:-}" ] || { echo "HWSIM_IFACES needs two interface names: AP STA" >&2; exit 2; }
[ -x "$AP_BIN" ] || { echo "missing barely-ap: $AP_BIN" >&2; exit 2; }

mkdir -p "$WORK/control_$AP"
AP_LOG="$WORK/ap.log"

cleanup() {
    if [ -n "$AP_PID" ]; then
        kill "$AP_PID" 2>/dev/null || true
        wait "$AP_PID" 2>/dev/null || true
    fi
    ip netns exec "$NS" pkill -9 -x wpa_supplicant 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

rfkill unblock all 2>/dev/null || true

MAC=$(cat "/sys/class/net/$AP/address")
STA_PHY=$(basename "$(readlink -f "/sys/class/net/$STA/phy80211")")

# Deterministic locally-administered link addresses derived from the radio MAC.
L0_MAC="0a:${MAC#*:}"
L1_MAC="0e:${MAC#*:}"

cat >"$WORK/ap.json" <<EOF
{
  "ssid": "rustap-mlo",
  "passphrase": "password1234",
  "country": "US",
  "mode": "netlink",
  "key_mgmt": "sae",
  "ocv": false,
  "spr_dhcp_helper": null,
  "radios": [
    {
      "iface": "$AP",
      "mac": "$MAC",
      "band": 2.4,
      "channel": 1,
      "width": 20,
      "phy": "be",
      "mld": true,
      "link_id": 0,
      "ctrl_path": "$WORK/control_$AP/$AP",
      "mld_links": [
        { "link_id": 0, "mac": "$L0_MAC", "band": 2.4, "channel": 1,  "width": 20 },
        { "link_id": 1, "mac": "$L1_MAC", "band": 5,   "channel": 36, "width": 80 }
      ]
    }
  ]
}
EOF

ip link set "$AP" down 2>/dev/null || true
iw dev "$AP" set type __ap 2>/dev/null || true
ip link set "$AP" up

"$AP_BIN" --config "$WORK/ap.json" >"$AP_LOG" 2>&1 &
AP_PID=$!

for _ in $(seq 1 100); do
    grep -q 'START_AP.*ok' "$AP_LOG" 2>/dev/null && break
    kill -0 "$AP_PID" 2>/dev/null || {
        echo "MLD AP exited during startup" >&2
        tail -60 "$AP_LOG" >&2
        exit 1
    }
    sleep 0.1
done
grep -q 'START_AP.*ok' "$AP_LOG" 2>/dev/null || {
    echo "MLD AP did not reach START_AP" >&2
    tail -60 "$AP_LOG" >&2
    exit 1
}

ip netns add "$NS"
iw phy "$STA_PHY" set netns name "$NS"
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip link set "$STA" up
ip netns exec "$NS" iw reg set US 2>/dev/null || true

cat >"$WORK/sta.conf" <<EOF
ctrl_interface=$WORK/ctrl-sta
p2p_disabled=1
sae_pwe=1
network={
  ssid="rustap-mlo"
  psk="password1234"
  key_mgmt=SAE
  ieee80211w=2
  scan_freq=2412 5180
}
EOF

# Scan-gate: wait for the STA's own scan to see the AP before launching
# wpa_supplicant, so it doesn't back off on a cold hwsim medium.
seen=0
for _ in $(seq 1 15); do
    ip netns exec "$NS" iw dev "$STA" scan 2>/dev/null | grep -q "SSID: rustap-mlo" && { seen=1; break; }
    sleep 1
done
[ "$seen" = 1 ] || echo "warning: scan-gate never saw the AP; continuing" >&2

ip netns exec "$NS" "$WPAS" -B -Dnl80211 -i"$STA" -c "$WORK/sta.conf"

STATE=
for k in $(seq 1 40); do
    STATE=$(ip netns exec "$NS" "$WCLI" -p "$WORK/ctrl-sta" -i"$STA" status 2>/dev/null |
        sed -n 's/^wpa_state=//p')
    [ "$STATE" = COMPLETED ] && break
    if { [ "$STATE" = SCANNING ] || [ "$STATE" = DISCONNECTED ] || [ -z "$STATE" ]; } &&
        [ $((k % 4)) -eq 0 ]; then
        ip netns exec "$NS" "$WCLI" -p "$WORK/ctrl-sta" -i"$STA" scan >/dev/null 2>&1
    fi
    sleep 1
done

STATUS=$(ip netns exec "$NS" "$WCLI" -p "$WORK/ctrl-sta" -i"$STA" status 2>/dev/null)
if [ "${STATE:-}" != COMPLETED ]; then
    echo "MLD association failed: wpa_state=${STATE:-unknown}" >&2
    echo "$STATUS" >&2
    tail -80 "$AP_LOG" >&2
    exit 1
fi

echo "$STATUS" | grep -iE "valid_links|mld_addr|ap_mld_addr|link_id|freq" || true
MLO=$(ip netns exec "$NS" "$WCLI" -p "$WORK/ctrl-sta" -i"$STA" mlo_status 2>/dev/null)
[ -z "$MLO" ] || { echo "-- mlo_status --"; echo "$MLO"; }
VALID=$(echo "$STATUS" | sed -n 's/^valid_links=//p')
# Older status formats omit valid_links; fall back to counting mlo_status links.
if [ -z "$VALID" ] && [ -n "$MLO" ]; then
    links=$(echo "$MLO" | grep -c "^link_id=")
    [ "$links" -ge 2 ] && VALID=3
fi
if [ -n "$VALID" ]; then
    # valid_links is a bitmask: links 0+1 => 0x3.
    case "$VALID" in
    3 | 0x3 | 0x0003) echo "PASS: MLD COMPLETED on $AP with both links valid (valid_links=$VALID)" ;;
    *)
        echo "PARTIAL: COMPLETED but valid_links=$VALID (expected 3)" >&2
        exit 1
        ;;
    esac
else
    echo "PARTIAL: COMPLETED but the client reports no valid_links (non-MLO association?)" >&2
    exit 1
fi
