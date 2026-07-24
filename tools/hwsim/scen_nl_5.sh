#!/bin/bash
RUSTAP_CONFIG=${RUSTAP_CONFIG:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/tests/interop-config.json}
sudo pkill -9 -f /tmp/barely 2>/dev/null; sudo pkill -9 wpa_supplicant 2>/dev/null
sudo iw reg set US 2>/dev/null
sudo modprobe -r mac80211_hwsim 2>/dev/null; sleep 1; sudo modprobe mac80211_hwsim radios=6; sleep 3
mapfile -t HW < <(for d in /sys/class/net/*/phy80211; do n=$(basename "$(dirname "$d")"); [ "$(basename "$(readlink "/sys/class/net/$n/device/driver" 2>/dev/null)" 2>/dev/null)" = mac80211_hwsim ] && echo "$n"; done)
AP_IF=${HW[0]}; STAS=("${HW[@]:1:5}")
sudo ip link set "$AP_IF" down; sudo iw dev "$AP_IF" set type __ap; sudo ip link set "$AP_IF" up
sudo /tmp/barely-ap --config "$RUSTAP_CONFIG" --mode netlink --iface "$AP_IF" --channel 1 --mac 02:00:00:00:00:00 --ssid turtlenet > /tmp/apnl.log 2>&1 &
sleep 2
cat > /tmp/cli.conf <<CFG
ctrl_interface=/run/wpa_n
network={
  ssid="turtlenet"
  psk="password1234"
  key_mgmt=WPA-PSK
  proto=RSN
  pairwise=CCMP
  scan_freq=2412
}
CFG
for i in 0 1 2 3 4; do sta=${STAS[$i]}; sudo ip link set "$sta" up; sudo wpa_supplicant -B -Dnl80211 -i"$sta" -c /tmp/cli.conf -f "/tmp/s$((i+1)).log" 2>/dev/null; done
for t in $(seq 1 12); do
  sleep 2; DONE=0
  for sta in "${STAS[@]}"; do
    S=$(sudo wpa_cli -p /run/wpa_n -i"$sta" status 2>/dev/null | awk -F= '/wpa_state/{print $2}')
    [ "$S" = COMPLETED ] && DONE=$((DONE+1))
  done
  [ "$DONE" = 5 ] && break
done
echo -n "netlink 5-STA: "; for i in 0 1 2 3 4; do sta=${STAS[$i]}; echo -n "STA$((i+1))=$(sudo wpa_cli -p /run/wpa_n -i"$sta" status 2>/dev/null | awk -F= '/wpa_state/{print $2}') "; done; echo
echo "AP keyed+authorized: $(sudo grep -ac 'keyed + authorized' /tmp/apnl.log) / 5"
echo "kernel stations on $AP_IF: $(sudo iw dev "$AP_IF" station dump 2>/dev/null | grep -c Station)"
sudo pkill -9 -f /tmp/barely 2>/dev/null; sudo pkill -9 wpa_supplicant 2>/dev/null
