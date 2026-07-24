#!/bin/bash
# sae_test.sh — isolated WPA3-SAE interop: barely-ap --sae <-> v2.12 wpa_supplicant.
# Writes STATE/KEY_MGMT/GROUP_MGMT/PING to /tmp/saetest/result.txt. Run as root.
set -u
B=${1:-/tmp/iopbin/barely-ap}
PHY=${2:-ax}
W=/tmp/saetest; NS=saecli
RUSTAP_CONFIG=${RUSTAP_CONFIG:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tests/interop-config.json}
WPAS=${WPAS:?set WPAS to the wpa_supplicant binary}
FIREWALL_COMMENT="barely-sae-$$"
cleanup() {
  pkill -9 -f "[b]arely-ap --mode" 2>/dev/null
  ip netns del "$NS" 2>/dev/null
  handle=$(nft -a list chain inet filter INPUT 2>/dev/null |
    awk -v marker="$FIREWALL_COMMENT" '$0 ~ marker { for (i=1; i<=NF; i++) if ($i == "handle") print $(i+1) }' |
    head -1)
  [ -z "$handle" ] || nft delete rule inet filter INPUT handle "$handle" 2>/dev/null
}
trap cleanup EXIT
pkill -9 -f "[b]arely-ap --mode" 2>/dev/null
ip netns del "$NS" 2>/dev/null; ip netns del sae 2>/dev/null
sleep 1; rm -rf "$W"; mkdir -p "$W"
HW=()
for n in $(ls /sys/class/net | grep -E '^wlan'); do
  d=$(basename "$(readlink "/sys/class/net/$n/device/driver" 2>/dev/null)" 2>/dev/null)
  [ "$d" = mac80211_hwsim ] && HW+=("$n")
done
AP=${HW[0]:-}; STA=${HW[1]:-}
[ -n "$AP" ] && [ -n "$STA" ] || { echo "ERR: need 2 hwsim radios (got ${HW[*]:-none})" > "$W/result.txt"; exit 1; }
nft insert rule inet filter INPUT iifname "$AP" ip daddr 10.10.10.1 \
  ip protocol icmp accept comment "$FIREWALL_COMMENT"
echo "AP=$AP STA=$STA phy=$PHY" > "$W/info.txt"
ip link set "$AP" down; iw dev "$AP" set type __ap; ip link set "$AP" up
ip addr flush dev "$AP"; ip addr add 10.10.10.1/24 dev "$AP"
setsid "$B" --config "$RUSTAP_CONFIG" --mode netlink --iface "$AP" --band 5 \
  --channel 36 --width 80 --phy "$PHY" --sae --ssid saetest \
  </dev/null >"$W/ap.log" 2>&1 &
sleep 5
grep -aqE "START_AP.*ok" "$W/ap.log" || { echo "ERR: AP failed: $(tail -1 "$W/ap.log")" > "$W/result.txt"; exit 1; }
STAPHY=$(cat "/sys/class/net/$STA/phy80211/name")
ip netns add "$NS"; iw phy "$STAPHY" set netns name "$NS"
ip netns exec "$NS" ip link set lo up; ip netns exec "$NS" ip link set "$STA" up
printf 'ctrl_interface=/run/wpa_sae\nnetwork={\n ssid="saetest"\n psk="password1234"\n key_mgmt=SAE\n ieee80211w=2\n}\n' > "$W/sta.conf"
ip netns exec "$NS" "$WPAS" -B -Dnl80211 -i"$STA" -c "$W/sta.conf" -dd -f "$W/sta.log"
ST=none
for i in $(seq 1 20); do
  sleep 1
  S=$(ip netns exec "$NS" wpa_cli -p /run/wpa_sae -i"$STA" status 2>/dev/null | sed -n 's/^wpa_state=//p')
  [ -n "$S" ] && ST=$S; [ "$S" = COMPLETED ] && break
done
ip netns exec "$NS" ip addr add 10.10.10.2/24 dev "$STA" 2>/dev/null
PING=FAIL; ip netns exec "$NS" ping -c2 -W2 10.10.10.1 >/dev/null 2>&1 && PING=OK
ST2=$(ip netns exec "$NS" wpa_cli -p /run/wpa_sae -i"$STA" status 2>/dev/null)
KM=$(echo "$ST2" | sed -n 's/^key_mgmt=//p'); GM=$(echo "$ST2" | sed -n 's/^mgmt_group_cipher=//p')
echo "STATE=$ST KEY_MGMT=$KM GROUP_MGMT=$GM PING=$PING" > "$W/result.txt"
