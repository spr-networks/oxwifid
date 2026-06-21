#!/bin/bash
sudo pkill -9 -f /tmp/barely 2>/dev/null; sudo pkill -9 wpa_supplicant 2>/dev/null
for v in $(ip -o link show 2>/dev/null | awk -F': ' '/apvlan/{print $2}'); do sudo iw dev $v del 2>/dev/null; done
sudo iw reg set US 2>/dev/null
sudo modprobe -r mac80211_hwsim 2>/dev/null; sleep 1; sudo modprobe mac80211_hwsim radios=3; sleep 3
sudo ip link set wlan0 down; sudo iw dev wlan0 set type __ap; sudo ip link set wlan0 up
sudo /tmp/barely-ap --mode netlink --iface wlan0 --channel 1 --per-sta-vif --mac 02:00:00:00:00:00 --ssid turtlenet --psk password1234 > /tmp/apnl.log 2>&1 &
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
for i in 1 2; do sudo ip link set wlan$i up; sudo wpa_supplicant -B -Dnl80211 -iwlan$i -c /tmp/cli.conf -f /tmp/s$i.log 2>/dev/null; done
for t in $(seq 1 9); do sleep 2; D=0; for i in 1 2; do [ "$(sudo wpa_cli -p /run/wpa_n -iwlan$i status 2>/dev/null|awk -F= '/wpa_state/{print $2}')" = COMPLETED ] && D=$((D+1)); done; [ $D = 2 ] && break; done
echo -n "per-sta-vif: "; for i in 1 2; do echo -n "STA$i=$(sudo wpa_cli -p /run/wpa_n -iwlan$i status 2>/dev/null|awk -F= '/wpa_state/{print $2}') "; done; echo
echo "AP_VLAN interfaces: $(ip -o link show 2>/dev/null | grep -c apvlan)"
echo "--- iw dev AP_VLANs ---"; sudo iw dev 2>/dev/null | grep -E "Interface apvlan|type" | grep -A1 apvlan | head -6
echo "--- AP log ---"; sudo grep -aE "apvlan|keyed" /tmp/apnl.log | head -6
sudo pkill -9 -f /tmp/barely 2>/dev/null; sudo pkill -9 wpa_supplicant 2>/dev/null
