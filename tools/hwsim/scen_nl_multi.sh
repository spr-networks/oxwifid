#!/bin/bash
RUSTAP_CONFIG=${RUSTAP_CONFIG:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/tests/interop-config.json}
sudo pkill -9 -f /tmp/barely 2>/dev/null; sudo pkill -9 wpa_supplicant 2>/dev/null
sudo iw reg set US 2>/dev/null
sudo modprobe -r mac80211_hwsim 2>/dev/null; sleep 1; sudo modprobe mac80211_hwsim radios=3; sleep 3
mapfile -t HW < <(for d in /sys/class/net/*/phy80211; do n=$(basename "$(dirname "$d")"); [ "$(basename "$(readlink "/sys/class/net/$n/device/driver" 2>/dev/null)" 2>/dev/null)" = mac80211_hwsim ] && echo "$n"; done)
AP_IF=${HW[0]}; STA1=${HW[1]}; STA2=${HW[2]}
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
sudo ip link set "$STA1" up; sudo ip link set "$STA2" up
sudo wpa_supplicant -B -Dnl80211 -i"$STA1" -c /tmp/cli.conf -f /tmp/s1.log 2>/dev/null
sudo wpa_supplicant -B -Dnl80211 -i"$STA2" -c /tmp/cli.conf -f /tmp/s2.log 2>/dev/null
for t in $(seq 1 9); do
  sleep 2
  S1=$(sudo wpa_cli -p /run/wpa_n -i"$STA1" status 2>/dev/null | awk -F= '/wpa_state/{print $2}')
  S2=$(sudo wpa_cli -p /run/wpa_n -i"$STA2" status 2>/dev/null | awk -F= '/wpa_state/{print $2}')
  [ "$S1" = COMPLETED ] && [ "$S2" = COMPLETED ] && break
done
echo "netlink: STA1=$S1 STA2=$S2"
echo "AP keyed: $(sudo grep -ac 'keyed + authorized' /tmp/apnl.log)"
sudo pkill -9 -f /tmp/barely 2>/dev/null; sudo pkill -9 wpa_supplicant 2>/dev/null
