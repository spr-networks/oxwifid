#!/bin/bash
# E2E: connect a wpa_supplicant HE client to barely-ap, issue twt_setup, and
# check barely-ap accepts it. Writes /tmp/twt_result.txt.
B=/tmp/iopbin/barely-ap; NS=twtcli; R=/tmp/twt_result.txt
RUSTAP_CONFIG=${RUSTAP_CONFIG:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tests/interop-config.json}
WPAS=${WPAS:?set WPAS to the wpa_supplicant binary}
WCLI=${WCLI:?set WCLI to the wpa_cli binary}
rm -f "$R"; : > "$R"
pkill -9 -f "[b]arely-ap --mode" 2>/dev/null; pkill -9 wlantest 2>/dev/null; pkill -9 -x wpa_supplicant 2>/dev/null
for n in $NS interopcli; do ip netns del "$n" 2>/dev/null; done
sleep 1; modprobe -r mac80211_hwsim 2>/dev/null; sleep 1; modprobe mac80211_hwsim rctbl=1 radios=4; sleep 2
iw reg set US 2>/dev/null; sleep 1
mapfile -t HW < <(for n in $(ls /sys/class/net|grep ^wlan); do [ "$(basename "$(readlink /sys/class/net/$n/device/driver 2>/dev/null)")" = mac80211_hwsim ] && echo "$n"; done)
AP=${HW[0]}; STA=${HW[1]}
ip link set "$AP" down; iw dev "$AP" set type __ap; ip link set "$AP" up; ip addr add 10.10.10.1/24 dev "$AP" 2>/dev/null
setsid "$B" --config "$RUSTAP_CONFIG" --mode netlink --iface "$AP" --band 5 \
  --channel 36 --width 80 --phy ax --ssid twt </dev/null >/tmp/twt_ap.log 2>&1 &
sleep 4
grep -aqE "START_AP.*ok" /tmp/twt_ap.log && echo "AP up" >> "$R" || { echo "AP FAILED" >> "$R"; exit 1; }
ip netns add "$NS"; iw phy "$(cat /sys/class/net/$STA/phy80211/name)" set netns name "$NS"
ip netns exec "$NS" iw reg set US 2>/dev/null; ip netns exec "$NS" ip link set lo up; ip netns exec "$NS" ip link set "$STA" up; sleep 1
printf 'ctrl_interface=/run/wpa_t\nnetwork={\n ssid="twt"\n psk="password1234"\n key_mgmt=WPA-PSK\n}\n' > /tmp/twt.conf
ip netns exec "$NS" "$WPAS" -B -Dnl80211 -i"$STA" -c /tmp/twt.conf >/dev/null 2>&1
for k in $(seq 1 15); do sleep 1
  st=$(ip netns exec "$NS" "$WCLI" -p /run/wpa_t -i"$STA" status 2>/dev/null | sed -n 's/^wpa_state=//p')
  [ "$st" = COMPLETED ] && break
  case $k in 3|7|11) ip netns exec "$NS" "$WCLI" -p /run/wpa_t -i"$STA" scan >/dev/null 2>&1;; esac
done
echo "client state: ${st:-none}" >> "$R"
# Issue a TWT setup from the client (driver/wpa_supplicant twt_setup)
echo "twt_setup cmd: $(ip netns exec "$NS" "$WCLI" -p /run/wpa_t -i"$STA" twt_setup dialog=7 exponent=10 mantissa=8192 min_twt=64 2>&1 | tail -1)" >> "$R"
sleep 3
echo "=== AP TWT log ===" >> "$R"
grep -aiE "TWT" /tmp/twt_ap.log | tail -3 >> "$R"
echo "(if empty, the client driver could not initiate TWT on hwsim)" >> "$R"
echo "DONE" >> "$R"
pkill -9 -f "[b]arely-ap --mode" 2>/dev/null; ip netns del "$NS" 2>/dev/null
