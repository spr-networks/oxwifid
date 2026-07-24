#!/bin/bash
RUSTAP_CONFIG=${RUSTAP_CONFIG:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/tests/interop-config.json}
# scenMulti.sh <wpa2|wpa3|owe> : Rust barely-ap with TWO real wpa_supplicant clients
SEC=${1:-wpa2}; FREQ=2412
[ -z "${REFERENCE_AP:-}" ] || sudo pkill -x "$(basename "$REFERENCE_AP")" 2>/dev/null
sudo pkill -f /tmp/barely 2>/dev/null; sudo pkill -f wpa_supplicant 2>/dev/null
sudo systemctl stop wpa_supplicant NetworkManager 2>/dev/null
sudo iw reg set US 2>/dev/null
sudo modprobe -r mac80211_hwsim 2>/dev/null; sleep 1; sudo modprobe mac80211_hwsim radios=3; sleep 3; sudo rfkill unblock all
mapfile -t HW < <(for d in /sys/class/net/*/phy80211; do n=$(basename "$(dirname "$d")"); [ "$(basename "$(readlink "/sys/class/net/$n/device/driver" 2>/dev/null)" 2>/dev/null)" = mac80211_hwsim ] && echo "$n"; done)
AP_BASE=${HW[0]}; STA1=${HW[1]}; STA2=${HW[2]}
PHYA=$(cat "/sys/class/net/$AP_BASE/phy80211/name")
# AP on phyA: IBSS ack-provider + monitor
sudo iw dev "$AP_BASE" del
sudo iw phy $PHYA interface add ibss0 type ibss
sudo ip link set ibss0 address 02:00:00:00:00:00
sudo ip link set ibss0 up
sudo iw dev ibss0 ibss join barelyack $FREQ fixed-freq 02:CA:FE:00:00:00
sudo iw phy $PHYA interface add mon0 type monitor
sudo ip link set mon0 up
sleep 2
case $SEC in
  wpa2) APFLAG=''; SUPP=$'key_mgmt=WPA-PSK\n  psk="password1234"';;
  wpa3) APFLAG='--sae'; SUPP=$'key_mgmt=SAE\n  psk="password1234"\n  ieee80211w=2';;
  owe)  APFLAG='--owe'; SUPP=$'key_mgmt=OWE\n  ieee80211w=2';;
esac
sudo /tmp/barely-ap --config "$RUSTAP_CONFIG" --mode iface --iface mon0 --channel 1 --mac 02:00:00:00:00:00 --ssid turtlenet --ip 10.10.10.1 $APFLAG > /tmp/ap.log 2>&1 &
sleep 2
cat > /tmp/supp.conf <<CFG
ctrl_interface=/run/wpa_m
network={
  ssid="turtlenet"
  $SUPP
  proto=RSN
  pairwise=CCMP
  scan_freq=$FREQ
}
CFG
# two stations on dedicated hwsim radios
sudo ip link set "$STA1" up; sudo ip link set "$STA2" up
sudo wpa_supplicant -B -Dnl80211 -i"$STA1" -c /tmp/supp.conf -f /tmp/s1.log 2>/dev/null
sudo wpa_supplicant -B -Dnl80211 -i"$STA2" -c /tmp/supp.conf -f /tmp/s2.log 2>/dev/null
for t in $(seq 1 8); do
  sleep 2
  S1=$(sudo wpa_cli -p /run/wpa_m -i"$STA1" status 2>/dev/null | awk -F= '/wpa_state/{print $2}')
  S2=$(sudo wpa_cli -p /run/wpa_m -i"$STA2" status 2>/dev/null | awk -F= '/wpa_state/{print $2}')
  [ "$S1" = COMPLETED ] && [ "$S2" = COMPLETED ] && break
done
echo "[$SEC] STA1=$S1 STA2=$S2"
sudo ip addr add 10.10.10.2/24 dev "$STA1" 2>/dev/null
sudo ip addr add 10.10.10.3/24 dev "$STA2" 2>/dev/null
echo "[$SEC] STA1 ping: $(ping -I "$STA1" -c2 -W2 10.10.10.1 2>&1 | grep -oE '[0-9]+ received')"
echo "[$SEC] STA2 ping: $(ping -I "$STA2" -c2 -W2 10.10.10.1 2>&1 | grep -oE '[0-9]+ received')"
echo "[$SEC] AP associated stations: $(grep -ac 'AP-STA' /tmp/ap.log 2>/dev/null)"
sudo pkill -f /tmp/barely; sudo pkill -f wpa_supplicant
