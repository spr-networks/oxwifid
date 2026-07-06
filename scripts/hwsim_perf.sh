#!/bin/bash
# hwsim_perf.sh — reusable mac80211_hwsim performance sweep for barely-ap.
#
# Brings up the Rust AP + a wpa_supplicant client over the hwsim medium and
# measures iperf3 throughput (both directions) plus the negotiated rate
# (`iw station dump`) across a matrix of PHY mode / spatial streams / channel
# width. Rate control is real (hwsim `rctbl=1` runs minstrel), but the hwsim
# medium has no RF: iperf3 *numbers* are CPU/software-bound, NOT PHY rates.
# What's meaningful is (a) does the data path work for each config and
# (b) how throughput *scales* with NSS / width. Also note hwsim/iw report
# VHT-MCS even for HE/EHT associations (a kernel limitation, not a barely-ap
# bug) — so the surfaced MCS string is VHT-class regardless of --phy.
#
# Usage:  sudo ./scripts/hwsim_perf.sh [/path/to/barely-ap]
# Run on the hwsim box (e.g. ubuntu@10.168.0.18). Uses hwsim radios only and
# never touches real radios (r_wlan*). Safe to re-run.

set -u
BIN=${1:-$HOME/barely-ap/target/release/barely-ap}
SSID=hwperf
PSK=password1234
NS=staperf
CTRL=/run/wpa_${NS}

[ -x "$BIN" ] || { echo "binary not found/executable: $BIN" >&2; exit 1; }

teardown_run() {
    sudo pkill -9 -f "$BIN" 2>/dev/null
    sudo ip netns exec "$NS" pkill -9 wpa_supplicant 2>/dev/null
    sudo ip netns del "$NS" 2>/dev/null
    sudo pkill -9 -f "iperf3 -s" 2>/dev/null
}
trap teardown_run EXIT

# Load hwsim with the rate-control table + 2 radios (leaves an existing load alone).
lsmod | grep -q '^mac80211_hwsim' || sudo modprobe mac80211_hwsim rctbl=1 radios=2
sleep 1

# Pick the two mac80211_hwsim netdevs (explicitly skip real radios like r_wlan*).
HW=()
for d in /sys/class/net/*/phy80211; do
    n=$(basename "$(dirname "$d")")
    drv=$(basename "$(readlink "/sys/class/net/$n/device/driver" 2>/dev/null)" 2>/dev/null)
    [ "$drv" = mac80211_hwsim ] && HW+=("$n")
done
AP_IF=${HW[0]:-}; STA_IF=${HW[1]:-}
[ -n "$AP_IF" ] && [ -n "$STA_IF" ] || { echo "need >=2 hwsim radios (got: ${HW[*]:-none})" >&2; exit 1; }
echo "# AP=$AP_IF  STA=$STA_IF  bin=$BIN"
echo "# (hwsim throughput is software-bound; compare relative scaling, not absolute Mbit/s)"
printf '%-3s %-5s %-6s %-4s | %-9s | %-34s | %-13s %-13s\n' phy chan width nss assoc neg-rate up down

run_one() { # phy channel width nss
    local phy=$1 ch=$2 width=$3 nss=$4
    teardown_run; sleep 1

    local staphy
    staphy=$(cat "/sys/class/net/$STA_IF/phy80211/name")
    # NOTE: NSS is NOT settable from userspace on hwsim (`iw phy set antenna` ->
    # -EOPNOTSUPP; the radio reports "Available Antennas: TX 0 RX 0"). The $nss
    # column is informational only. To actually force 1 vs 2 SS you need a binary
    # that clamps the advertised VHT/HE MCS-NSS map (see header).
    sudo ip link set "$AP_IF" down 2>/dev/null

    # AP
    sudo iw dev "$AP_IF" set type __ap 2>/dev/null
    sudo ip link set "$AP_IF" up
    sudo ip addr flush dev "$AP_IF" 2>/dev/null
    sudo ip addr add 10.10.10.1/24 dev "$AP_IF"
    ( sudo "$BIN" --mode netlink --iface "$AP_IF" --channel "$ch" --width "$width" \
        --phy "$phy" --ssid "$SSID" --psk "$PSK" >/tmp/perf_ap.log 2>&1 & )
    sleep 4
    if ! grep -aq "START_AP ok" /tmp/perf_ap.log; then
        printf '%-3s %-5s %-6s %-4s | %-9s | %s\n' "$phy" "$ch" "$width" "$nss" AP-FAIL "$(tail -1 /tmp/perf_ap.log)"
        return
    fi

    # STA in its own netns so traffic crosses the hwsim medium.
    sudo ip netns add "$NS"
    sudo iw phy "$staphy" set netns name "$NS"
    sudo ip netns exec "$NS" ip link set lo up
    sudo ip netns exec "$NS" ip link set "$STA_IF" up
    printf 'ctrl_interface=%s\np2p_disabled=1\nnetwork={\n ssid="%s"\n psk="%s"\n key_mgmt=WPA-PSK\n}\n' \
        "$CTRL" "$SSID" "$PSK" > /tmp/perf_sta.conf
    sudo ip netns exec "$NS" wpa_supplicant -B -Dnl80211 -i"$STA_IF" -c /tmp/perf_sta.conf >/dev/null 2>&1
    local state=""
    for _ in $(seq 1 15); do
        sleep 1
        state=$(sudo ip netns exec "$NS" wpa_cli -p "$CTRL" -i"$STA_IF" status 2>/dev/null | sed -n 's/^wpa_state=//p')
        [ "$state" = COMPLETED ] && break
    done
    sudo ip netns exec "$NS" ip addr add 10.10.10.2/24 dev "$STA_IF" 2>/dev/null

    local up dn neg
    ( sudo timeout 20 iperf3 -s -1 -p 5301 >/dev/null 2>&1 & ); sleep 1
    up=$(sudo ip netns exec "$NS" iperf3 -c 10.10.10.1 -p 5301 -t 4 2>&1 | grep -ai sender | grep -oE '[0-9.]+ [MG]bits/sec' | tail -1)
    ( sudo timeout 20 iperf3 -s -1 -p 5302 >/dev/null 2>&1 & ); sleep 1
    dn=$(sudo ip netns exec "$NS" iperf3 -c 10.10.10.1 -p 5302 -R -t 4 2>&1 | grep -ai receiver | grep -oE '[0-9.]+ [MG]bits/sec' | tail -1)
    neg=$(sudo iw dev "$AP_IF" station dump 2>/dev/null | sed -n 's/.*tx bitrate:[ \t]*//p' | head -1)

    printf '%-3s %-5s %-6s %-4s | %-9s | %-34s | %-13s %-13s\n' \
        "$phy" "$ch" "$width" "$nss" "${state:-none}" "${neg:-?}" "${up:-0}" "${dn:-0}"
}

# The dimensions that ARE controllable + observable on stock hwsim: PHY mode and
# channel width. (All three PHY modes report VHT-MCS — a hwsim/iw limitation, not
# a barely-ap bug — so ac/ax/be look identical here; the width clearly scales the
# negotiated rate: 20MHz~346 Mbit MCS8, 80MHz~1733 Mbit MCS9.)
run_one ax  36 80  2     # baseline (ax / 80 MHz)
run_one ac  36 80  2     # PHY: VHT
run_one be  36 80  2     # PHY: EHT
run_one ax  36 20  2     # width: 20 MHz  (negotiated rate drops to ~346 Mbit)
run_one ax  36 40  2     # width: 40 MHz
# Omitted, and why (verified on this kernel/hwsim):
#  - 160 MHz: every 5 GHz 160 block is DFS under the US regdom and hwsim rejects
#    userspace CAC (RADAR_DETECT -> -EOPNOTSUPP), so the AP refuses to start.
#  - NSS 1 vs 2, guard interval, A-MPDU on/off: not userspace levers on stock
#    hwsim (no antenna control; GI auto-picked by rctbl; A-MPDU is a peer-honored
#    cap). Forcing them needs a binary that clamps the advertised MCS-NSS map /
#    HT A-MPDU byte (e.g. RUSTAP_MAX_NSS / RUSTAP_NO_AMPDU knobs) — they show up in
#    the `iw station dump` rate, not in (CPU-bound) hwsim throughput.

echo "# done. (cleanup runs on exit; hwsim module left loaded for re-runs)"
