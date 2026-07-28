#!/bin/bash
# Concurrent DBDC/per-station-VIF association stress over mac80211_hwsim.
#
# One barely-ap process serves independent 2.4 and 5 GHz radios in WPA2/SAE
# transition mode. CLIENTS station radios (half on each band, alternating
# WPA2/SAE) associate concurrently. Each wave disconnects and immediately
# reconnects half the fleet while the other half remains authorized, exercising
# AP_VLAN retirement/replacement and EAPOL message-1 delivery under churn.
#
# Usage:
#   WPAS=/path/to/wpa_supplicant \
#     scripts/hwsim_multiclient_stress.sh BINS_DIR
#
# Optional:
#   CLIENTS=12 WAVES=20 STRICT_REKEY=true PER_STA_VIF=true \
#     CLIENT_SECURITY=mixed WPA2_PMF=0 GROUP_REKEY=0 RUSTAP_NL_DEBUG=1 \
#     RUN_LOG_DIR=/tmp/barely-multiclient-stress

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    SUDO_ENV=(
        "WPAS=${WPAS:-}"
        "CLIENTS=${CLIENTS:-12}"
        "WAVES=${WAVES:-20}"
        "STRICT_REKEY=${STRICT_REKEY:-true}"
        "PER_STA_VIF=${PER_STA_VIF:-true}"
        "CLIENT_SECURITY=${CLIENT_SECURITY:-mixed}"
        "WPA2_PMF=${WPA2_PMF:-0}"
        "GROUP_REKEY=${GROUP_REKEY:-0}"
        "RUN_LOG_DIR=${RUN_LOG_DIR:-}"
    )
    if [ "${RUSTAP_NL_DEBUG+x}" = x ]; then
        SUDO_ENV+=("RUSTAP_NL_DEBUG=$RUSTAP_NL_DEBUG")
    fi
    exec sudo -n env "${SUDO_ENV[@]}" bash "$0" "$@"
fi

BINDIR=${1:?usage: hwsim_multiclient_stress.sh BINS_DIR}
AP="$BINDIR/barely-ap"
WPAS=${WPAS:?set WPAS to the wpa_supplicant binary}
CLIENTS=${CLIENTS:-12}
WAVES=${WAVES:-20}
STRICT_REKEY=${STRICT_REKEY:-true}
PER_STA_VIF=${PER_STA_VIF:-true}
CLIENT_SECURITY=${CLIENT_SECURITY:-mixed}
WPA2_PMF=${WPA2_PMF:-0}
GROUP_REKEY=${GROUP_REKEY:-0}
WORK=${RUN_LOG_DIR:-"/tmp/barely-multiclient-stress-$$"}
AP_LOG="$WORK/ap.log"
AP_PID=
PREFIX="rustap-load-$$"
HALF=$((CLIENTS / 2))
EXPECTED_ASSOC=$CLIENTS
MAX_RSS_KB=0

if [ "$CLIENTS" -lt 4 ] || [ $((CLIENTS % 2)) -ne 0 ]; then
    echo "CLIENTS must be an even number >= 4" >&2
    exit 2
fi
if [ "$STRICT_REKEY" != true ] && [ "$STRICT_REKEY" != false ]; then
    echo "STRICT_REKEY must be true or false" >&2
    exit 2
fi
if [ "$PER_STA_VIF" != true ] && [ "$PER_STA_VIF" != false ]; then
    echo "PER_STA_VIF must be true or false" >&2
    exit 2
fi
case "$CLIENT_SECURITY" in
    mixed|sae|wpa2) ;;
    *)
        echo "CLIENT_SECURITY must be mixed, sae, or wpa2" >&2
        exit 2
        ;;
esac
if [ "$WPA2_PMF" != 0 ] && [ "$WPA2_PMF" != 1 ]; then
    echo "WPA2_PMF must be 0 or 1" >&2
    exit 2
fi
case "$GROUP_REKEY" in
    ''|*[!0-9]*) echo "GROUP_REKEY must be a non-negative integer" >&2; exit 2 ;;
esac
[ -x "$AP" ] || { echo "missing barely-ap: $AP" >&2; exit 2; }
[ -x "$WPAS" ] || { echo "missing wpa_supplicant: $WPAS" >&2; exit 2; }

mkdir -p "$WORK"

cleanup() {
    set +e
    for i in $(seq 0 $((CLIENTS - 1))); do
        ns="$PREFIX-$i"
        pidfile="$WORK/sta-$i.pid"
        if [ -s "$pidfile" ]; then
            kill -9 "$(cat "$pidfile")" 2>/dev/null
        fi
        ip netns del "$ns" 2>/dev/null
    done
    if [ -n "$AP_PID" ]; then
        kill "$AP_PID" 2>/dev/null
        wait "$AP_PID" 2>/dev/null
    fi
}
trap cleanup EXIT INT TERM

pkill -9 wlantest 2>/dev/null || true
pkill -9 wmediumd 2>/dev/null || true
for ns in $(ip netns list 2>/dev/null | awk '/^rustap-load-/{print $1}'); do
    ip netns del "$ns" 2>/dev/null || true
done
if lsmod | grep -q '^mac80211_hwsim'; then
    rmmod mac80211_hwsim
fi
modprobe mac80211_hwsim rctbl=1 radios=$((CLIENTS + 2))
sleep 2
iw reg set US 2>/dev/null || true
rfkill unblock all 2>/dev/null || true

mapfile -t HW < <(
    for path in /sys/class/net/*/phy80211; do
        iface=$(basename "$(dirname "$path")")
        driver=$(basename "$(readlink -f "/sys/class/net/$iface/device/driver" 2>/dev/null)" 2>/dev/null)
        [ "$driver" = mac80211_hwsim ] && echo "$iface"
    done | sort -V
)
if [ "${#HW[@]}" -lt $((CLIENTS + 2)) ]; then
    echo "need $((CLIENTS + 2)) hwsim radios, got ${#HW[@]}: ${HW[*]:-none}" >&2
    exit 2
fi

AP24=${HW[0]}
AP5=${HW[1]}
STAS=("${HW[@]:2:CLIENTS}")
MAC24=$(cat "/sys/class/net/$AP24/address")
MAC5=$(cat "/sys/class/net/$AP5/address")
mkdir -p "$WORK/control-$AP24" "$WORK/control-$AP5"

: >"$WORK/wpa-credentials"
: >"$WORK/sae-credentials"
for i in $(seq 0 $((CLIENTS - 1))); do
    printf '02:11:22:33:%02x:%02x password1234\n' $((i / 256)) $((i % 256)) \
        >>"$WORK/wpa-credentials"
    printf 'password1234|mac=02:11:22:33:%02x:%02x\n' $((i / 256)) $((i % 256)) \
        >>"$WORK/sae-credentials"
done

cat >"$WORK/ap.json" <<EOF
{
  "ssid": "rustap-load",
  "wpa_psk_file": "$WORK/wpa-credentials",
  "sae_psk_file": "$WORK/sae-credentials",
  "country": "US",
  "mode": "netlink",
  "key_mgmt": "sae-transition",
  "per_sta_vif": $PER_STA_VIF,
  "ocv": false,
  "group_rekey": $GROUP_REKEY,
  "strict_rekey": $STRICT_REKEY,
  "spr_dhcp_helper": null,
  "radios": [
    {
      "iface": "$AP24",
      "mac": "$MAC24",
      "band": 2.4,
      "channel": 1,
      "width": 20,
      "phy": "ax",
      "ctrl_path": "$WORK/control-$AP24/$AP24"
    },
    {
      "iface": "$AP5",
      "mac": "$MAC5",
      "band": 5,
      "channel": 36,
      "width": 80,
      "phy": "ax",
      "ctrl_path": "$WORK/control-$AP5/$AP5"
    }
  ]
}
EOF

for i in $(seq 0 $((CLIENTS - 1))); do
    iface=${STAS[$i]}
    ns="$PREFIX-$i"
    phy=$(basename "$(readlink -f "/sys/class/net/$iface/phy80211")")
    mac=$(printf '02:11:22:33:%02x:%02x' $((i / 256)) $((i % 256)))
    if [ "$i" -lt "$HALF" ]; then
        freq=2412
    else
        freq=5180
    fi
    if [ "$CLIENT_SECURITY" = sae ] ||
        { [ "$CLIENT_SECURITY" = mixed ] && [ $((i % 2)) -eq 0 ]; }; then
        security=$'key_mgmt=SAE\n  ieee80211w=2\n  sae_pwe=1'
    else
        security=$(printf 'key_mgmt=WPA-PSK\n  ieee80211w=%s' "$WPA2_PMF")
    fi

    ip link set "$iface" down
    ip link set "$iface" address "$mac"
    ip netns add "$ns"
    iw phy "$phy" set netns name "$ns"
    ip netns exec "$ns" ip link set lo up
    ip netns exec "$ns" ip link set "$iface" up
    ip netns exec "$ns" iw reg set US 2>/dev/null || true
    mkdir -p "$WORK/ctrl-$i"
    cat >"$WORK/sta-$i.conf" <<EOF
ctrl_interface=$WORK/ctrl-$i
p2p_disabled=1
network={
  ssid="rustap-load"
  psk="password1234"
  $security
  proto=RSN
  pairwise=CCMP
  scan_freq=$freq
}
EOF
done

"$AP" --config "$WORK/ap.json" >"$AP_LOG" 2>&1 &
AP_PID=$!

for _ in $(seq 1 200); do
    [ "$(grep -c 'START_AP.*ok' "$AP_LOG" 2>/dev/null || true)" -ge 2 ] && break
    kill -0 "$AP_PID" 2>/dev/null || {
        echo "AP exited during startup" >&2
        tail -160 "$AP_LOG" >&2
        exit 1
    }
    sleep 0.1
done
[ "$(grep -c 'START_AP.*ok' "$AP_LOG" 2>/dev/null || true)" -ge 2 ] || {
    echo "both radios did not start" >&2
    tail -160 "$AP_LOG" >&2
    exit 1
}

start_client() {
    local i=$1
    local iface=${STAS[$i]}
    local ns="$PREFIX-$i"
    rm -f "$WORK/sta-$i.pid"
    ip netns exec "$ns" "$WPAS" -B -Dnl80211 -i"$iface" \
        -c "$WORK/sta-$i.conf" -f "$WORK/sta-$i.log" \
        -P "$WORK/sta-$i.pid" >/dev/null
}

stop_client() {
    local i=$1
    local iface=${STAS[$i]}
    local ns="$PREFIX-$i"
    local pidfile="$WORK/sta-$i.pid"
    local pid
    ip netns exec "$ns" wpa_cli -p "$WORK/ctrl-$i" -i"$iface" disconnect \
        >/dev/null 2>&1 || true
    # Give the station's Deauthentication frame time to reach the AP before
    # terminating its process. Killing immediately turns an orderly reconnect
    # into an RF-disappearance test and leaves the AP waiting for inactivity.
    sleep 0.5
    if [ -s "$pidfile" ]; then
        pid=$(cat "$pidfile")
        kill -TERM "$pid" 2>/dev/null || true
        for _ in $(seq 1 50); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.1
        done
        kill -9 "$pid" 2>/dev/null || true
        rm -f "$pidfile"
    fi
}

wait_all_completed() {
    local label=$1
    local completed=0
    for _ in $(seq 1 300); do
        completed=0
        for i in $(seq 0 $((CLIENTS - 1))); do
            iface=${STAS[$i]}
            ns="$PREFIX-$i"
            state=$(ip netns exec "$ns" wpa_cli -p "$WORK/ctrl-$i" -i"$iface" status \
                2>/dev/null | sed -n 's/^wpa_state=//p' || true)
            [ "$state" = COMPLETED ] && completed=$((completed + 1))
        done
        [ "$completed" -eq "$CLIENTS" ] && break
        sleep 0.1
    done
    if [ "$completed" -ne "$CLIENTS" ]; then
        echo "FAIL $label: only $completed/$CLIENTS stations completed" >&2
        for i in $(seq 0 $((CLIENTS - 1))); do
            iface=${STAS[$i]}
            ns="$PREFIX-$i"
            state=$(ip netns exec "$ns" wpa_cli -p "$WORK/ctrl-$i" -i"$iface" status \
                2>/dev/null | sed -n 's/^wpa_state=//p' || true)
            echo "  station $i ($iface): ${state:-missing}" >&2
        done
        tail -240 "$AP_LOG" >&2
        return 1
    fi
}

active_vif_count() {
    find /sys/class/net -maxdepth 1 -type l \
        \( -name "$AP24.4*" -o -name "$AP5.4*" \) | wc -l
}

record_health() {
    local label=$1
    local expected_vifs=0
    [ "$PER_STA_VIF" = true ] && expected_vifs=$CLIENTS

    # A disconnect intentionally keeps its AP_VLAN for five seconds so an
    # attached control client can query the departing station. With debug logs
    # disabled the reconnect wave can finish before that grace expires. Allow
    # the count to converge, but still fail if a retired interface survives
    # beyond the bounded grace window or an active station is missing its VIF.
    local vifs
    for _ in $(seq 1 70); do
        vifs=$(active_vif_count)
        [ "$vifs" -le "$expected_vifs" ] && break
        sleep 0.1
    done

    local rss
    rss=$(awk '/^VmRSS:/{print $2}' "/proc/$AP_PID/status")
    [ "$rss" -gt "$MAX_RSS_KB" ] && MAX_RSS_KB=$rss
    local connected
    connected=$(grep -c '^AP-STA-CONNECTED ' "$AP_LOG" 2>/dev/null || true)
    printf '%-24s completed=%d vifs=%d connected_events=%d rss_kb=%d\n' \
        "$label" "$CLIENTS" "$vifs" "$connected" "$rss"
    if [ "$vifs" -ne "$expected_vifs" ]; then
        echo "FAIL $label: expected $expected_vifs active AP_VLANs, found $vifs" >&2
        return 1
    fi
}

pids=()
for i in $(seq 0 $((CLIENTS - 1))); do
    start_client "$i" &
    pids+=("$!")
done
for pid in "${pids[@]}"; do
    wait "$pid"
done
wait_all_completed "initial association"
record_health "initial"

if [ "$GROUP_REKEY" -gt 0 ]; then
    # Wait for one complete periodic group-key handshake from every station.
    # This specifically exercises EAPOL after SET_STA_VLAN has moved each peer:
    # control-port group message 1 must still be sent through the base BSS
    # ifindex, matching the reference nl80211 driver.
    deadline=$((SECONDS + GROUP_REKEY + 15))
    while [ "$SECONDS" -lt "$deadline" ]; do
        completed_rekeys=$(grep -c '^AP: group-key handshake completed for ' "$AP_LOG" \
            2>/dev/null || true)
        [ "$completed_rekeys" -ge "$CLIENTS" ] && break
        sleep 0.1
    done
    if [ "${completed_rekeys:-0}" -lt "$CLIENTS" ]; then
        echo "FAIL: only ${completed_rekeys:-0}/$CLIENTS periodic group rekeys completed" >&2
        tail -240 "$AP_LOG" >&2
        exit 1
    fi
    wait_all_completed "periodic group rekey"
    record_health "group-rekey"
fi

for wave in $(seq 1 "$WAVES"); do
    parity=$((wave % 2))
    restarted=0
    pids=()
    for i in $(seq 0 $((CLIENTS - 1))); do
        if [ $((i % 2)) -eq "$parity" ]; then
            stop_client "$i" &
            pids+=("$!")
            restarted=$((restarted + 1))
        fi
    done
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
    sleep 1
    pids=()
    for i in $(seq 0 $((CLIENTS - 1))); do
        if [ $((i % 2)) -eq "$parity" ]; then
            start_client "$i" &
            pids+=("$!")
        fi
    done
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
    EXPECTED_ASSOC=$((EXPECTED_ASSOC + restarted))
    wait_all_completed "wave $wave"
    record_health "wave-$wave"
done

ERROR_RE='4-way message [13] timeout|group-key handshake timeout|wrong-psk|create AP_VLAN .* failed|set_sta_vlan failed|NEW_KEY .*failed|SET_STATION .*failed|cleanup id=.*failed|Out of memory|panicked'
if grep -Eiq "$ERROR_RE" "$AP_LOG"; then
    echo "FAIL: AP log contains handshake/key/VIF errors" >&2
    grep -Ei "$ERROR_RE" "$AP_LOG" | tail -80 >&2
    exit 1
fi

if [ "$PER_STA_VIF" = true ] &&
    [ "${RUSTAP_NL_DEBUG+x}" = x ] &&
    ! awk '
    $1 == "AP:" && $2 == "EAPOL" && $3 == "rx" && $4 == "from" &&
        $0 ~ /key_info=0x030[89ab]/ {
        completed_m4[$5]++
    }
    $1 == "netlink" && $2 == "AP:" && $3 == "station" && $5 == "->" {
        if (!completed_m4[$4]) {
            print "AP_VLAN assignment preceded M4 for " $4 > "/dev/stderr"
            bad = 1
        } else {
            completed_m4[$4]--
        }
    }
    END { exit bad }
' "$AP_LOG"; then
    echo "FAIL: a station was moved to AP_VLAN before completing the 4-way handshake" >&2
    exit 1
fi

CONNECTED=$(grep -c '^AP-STA-CONNECTED ' "$AP_LOG" 2>/dev/null || true)
if [ "$CONNECTED" -lt "$EXPECTED_ASSOC" ]; then
    echo "FAIL: expected at least $EXPECTED_ASSOC connection events, saw $CONNECTED" >&2
    exit 1
fi

pids=()
for i in $(seq 0 $((CLIENTS - 1))); do
    stop_client "$i" &
    pids+=("$!")
done
for pid in "${pids[@]}"; do
    wait "$pid"
done
# A station that disappears without a received Deauthentication is retained
# until the advertised 300-second idle timeout. Stop the AP itself for the
# terminal leak check; per-wave checks above prove AP_VLAN count stays bounded
# while the AP remains live.
kill "$AP_PID"
wait "$AP_PID" 2>/dev/null || true
AP_PID=
sleep 1
LEFT=$(active_vif_count)
if [ "$LEFT" -ne 0 ]; then
    echo "FAIL: $LEFT AP_VLAN interfaces remained after AP teardown" >&2
    find /sys/class/net -maxdepth 1 -type l \
        \( -name "$AP24.4*" -o -name "$AP5.4*" \) -printf '%f\n' >&2
    exit 1
fi

echo "PASS: $CLIENTS $CLIENT_SECURITY clients, $WAVES half-fleet reconnect waves"
echo "PASS: $CONNECTED completed associations, zero EAPOL/VIF/key errors"
echo "PASS: AP_VLAN count stayed bounded and returned to zero after AP teardown"
echo "peak_rss_kb=$MAX_RSS_KB logs=$WORK"
