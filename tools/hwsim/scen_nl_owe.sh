#!/bin/bash
cleanup() { sudo pkill -9 -f /tmp/barely 2>/dev/null; sudo pkill -9 wpa_supplicant 2>/dev/null
  sudo iw phy $PHYB set netns 1 2>/dev/null; sudo ip netns del sta 2>/dev/null; }
trap cleanup EXIT
sudo pkill -9 -f /tmp/barely 2>/dev/null; sudo pkill -9 wpa_supplicant 2>/dev/null; sudo ip netns del sta 2>/dev/null
sudo iw reg set US 2>/dev/null
sudo modprobe -r mac80211_hwsim 2>/dev/null; sleep 1; sudo modprobe mac80211_hwsim radios=2; sleep 3; sudo iw reg set US; sleep 1
sudo ip link set wlan0 down; sudo iw dev wlan0 set type __ap; sudo ip link set wlan0 up
sudo /tmp/barely-ap --mode netlink --iface wlan0 --channel 36 --owe --mac 02:00:00:00:00:00 --ssid owenl > /tmp/apowe.log 2>&1 &
sleep 2
echo "START_AP ok: $(sudo grep -ac 'START_AP ok' /tmp/apowe.log)"
sudo ip netns add sta; PHYB=phy$(iw dev wlan1 info | awk '/wiphy/{print $2}'); sudo iw phy $PHYB set netns name sta
sudo ip netns exec sta ip link set wlan1 up
printf 'ctrl_interface=/run/wpa_n\nnetwork={\n ssid="owenl"\n key_mgmt=OWE\n ieee80211w=2\n scan_freq=5180\n}\n' > /tmp/cowe.conf
sudo ip netns exec sta wpa_supplicant -B -Dnl80211 -iwlan1 -c /tmp/cowe.conf -f /tmp/sowe.log 2>/dev/null
for t in $(seq 1 7); do sleep 2; [ "$(sudo ip netns exec sta wpa_cli -p /run/wpa_n -iwlan1 status 2>/dev/null|awk -F= '/wpa_state/{print $2}')" = COMPLETED ] && break; done
echo "OWE client state: $(sudo ip netns exec sta wpa_cli -p /run/wpa_n -iwlan1 status 2>/dev/null|awk -F= '/wpa_state/{print $2}')"
