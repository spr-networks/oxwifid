#!/bin/bash
# Minimal: AP started ONCE, file = wildcard + STA-MAC-specific. The STA's FIRST
# (fresh, no stale pin) connect uses the WILDCARD password -> must fall through
# the MAC-specific candidate to the wildcard. Then a 2nd connect uses devicepass.
B=/tmp/iopbin/barely-ap; NS=pskcli; R=/tmp/pskmin_result.txt
WPAS=${WPAS:?set WPAS to the wpa_supplicant binary}
rm -f "$R"; : > "$R"
pkill -9 -f "[b]arely-ap --mode" 2>/dev/null; pkill -9 wlantest 2>/dev/null
pkill -9 -x wpa_supplicant 2>/dev/null; for n in $NS interopcli; do ip netns del "$n" 2>/dev/null; done
sleep 1; modprobe -r mac80211_hwsim 2>/dev/null; sleep 1; modprobe mac80211_hwsim rctbl=1 radios=4; sleep 2
iw reg set US 2>/dev/null; sleep 1
mapfile -t HW < <(for n in $(ls /sys/class/net|grep ^wlan); do [ "$(basename "$(readlink /sys/class/net/$n/device/driver 2>/dev/null)")" = mac80211_hwsim ] && echo "$n"; done)
AP=${HW[0]}; STA=${HW[1]}; STAMAC=$(cat "/sys/class/net/$STA/address")
echo "AP=$AP STA=$STA STAMAC=$STAMAC" >> "$R"
printf '00:00:00:00:00:00 onboardpass\n%s devicepass\n' "$STAMAC" > /tmp/pskfile
cat > /tmp/ap.json <<EOF
{ "ssid": "psktest", "passphrase": "defaultpass", "key_mgmt": "psk",
  "band": 5, "channel": 36, "width": 80, "phy": "ax", "mode": "netlink",
  "iface": "$AP", "per_sta_vif": true, "wpa_psk_file": "/tmp/pskfile" }
EOF
ip link set "$AP" down; iw dev "$AP" set type __ap; ip link set "$AP" up; ip addr add 10.10.10.1/24 dev "$AP" 2>/dev/null
setsid "$B" --config /tmp/ap.json </dev/null >/tmp/pskmin_ap.log 2>&1 &
sleep 4; grep -aqE "START_AP.*ok" /tmp/pskmin_ap.log && echo "AP: START_AP ok" >> "$R" || { echo "AP FAILED" >> "$R"; exit 1; }
ip netns add "$NS"; iw phy "$(cat /sys/class/net/$STA/phy80211/name)" set netns name "$NS"
ip netns exec "$NS" iw reg set US 2>/dev/null; ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip link set "$STA" up; sleep 1

conn() { # $1 label  $2 password  $3 expect
  ip netns exec "$NS" pkill -9 wpa_supplicant 2>/dev/null; sleep 2
  printf 'ctrl_interface=/run/wpa_p\nnetwork={\n ssid="psktest"\n psk="%s"\n key_mgmt=WPA-PSK\n}\n' "$2" > /tmp/sta.conf
  ip netns exec "$NS" "$WPAS" -B -Dnl80211 -i"$STA" -c /tmp/sta.conf >/dev/null 2>&1
  local st=""
  for k in $(seq 1 18); do sleep 1
    st=$(ip netns exec "$NS" wpa_cli -p /run/wpa_p -i"$STA" status 2>/dev/null | sed -n 's/^wpa_state=//p')
    [ "$st" = COMPLETED ] && break
    case $k in 3|8|13) ip netns exec "$NS" wpa_cli -p /run/wpa_p -i"$STA" scan >/dev/null 2>&1;; esac
  done
  local got=FAIL; [ "$st" = COMPLETED ] && got=PASS
  local v=WRONG; [ "$got" = "$3" ] && v=OK
  echo "  [$v] $1: pw=$2 -> $got (expected $3)" >> "$R"
}

# FIRST, fresh station -> wildcard fallback (this is the pure candidate-logic test)
conn "wildcard(fresh)" onboardpass PASS
# then reconnect with the device-specific password (tests stale-pin clear)
conn "mac-specific(reconn)" devicepass PASS
echo "DONE" >> "$R"
pkill -9 -f "[b]arely-ap --mode" 2>/dev/null; ip netns del "$NS" 2>/dev/null
