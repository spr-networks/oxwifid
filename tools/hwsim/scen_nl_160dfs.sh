#!/bin/bash
RUSTAP_CONFIG=${RUSTAP_CONFIG:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/tests/interop-config.json}
sudo pkill -9 -f /tmp/barely 2>/dev/null; sudo pkill -9 wpa_supplicant 2>/dev/null
sudo rmmod hwsim6g 2>/dev/null
sudo modprobe -r mac80211_hwsim 2>/dev/null; sleep 1; sudo modprobe mac80211_hwsim radios=2; sleep 3
sudo iw reg set US; sleep 1
cd /tmp/hwsim6g && make clean >/tmp/mod160.log 2>&1; make >>/tmp/mod160.log 2>&1
sudo insmod /tmp/hwsim6g/hwsim6g.ko 2>>/tmp/mod160.log && echo "module: loaded ($(sudo dmesg | grep -a hwsim6g | tail -1 | sed 's/.*hwsim6g: //'))" || echo "module: FAILED ($(tail -1 /tmp/mod160.log))"
sudo ip link set wlan0 down; sudo iw dev wlan0 set type __ap; sudo ip link set wlan0 up
sudo /tmp/barely-ap --config "$RUSTAP_CONFIG" --mode netlink --iface wlan0 --band 5 --channel 36 --width 160 --mac 02:00:00:00:00:00 --ssid turtle160 > /tmp/ap160.log 2>&1 &
sleep 2
echo "START_AP ok: $(sudo grep -ac 'START_AP ok' /tmp/ap160.log)   err: $(sudo grep -aiE 'invalid|failed' /tmp/ap160.log | head -1)"
echo "AP chan: $(sudo iw dev wlan0 info 2>/dev/null | grep -iE 'channel|width' | tr '\n' ' ')"
printf 'ctrl_interface=/run/wpa_n\nnetwork={\n ssid="turtle160"\n psk="password1234"\n key_mgmt=WPA-PSK\n scan_freq=5180\n}\n' > /tmp/c160.conf
sudo ip link set wlan1 up
sudo wpa_supplicant -B -Dnl80211 -iwlan1 -c /tmp/c160.conf -f /tmp/s160.log 2>/dev/null
for t in $(seq 1 6); do sleep 2; [ "$(sudo wpa_cli -p /run/wpa_n -iwlan1 status 2>/dev/null|awk -F= '/wpa_state/{print $2}')" = COMPLETED ] && break; done
echo "client state: $(sudo wpa_cli -p /run/wpa_n -iwlan1 status 2>/dev/null|awk -F= '/wpa_state/{print $2}')"
echo "client chan: $(sudo iw dev wlan1 info 2>/dev/null | grep -iE 'channel|width' | tr '\n' ' ')"
sudo pkill -9 -f /tmp/barely 2>/dev/null; sudo pkill -9 wpa_supplicant 2>/dev/null; sudo rmmod hwsim6g 2>/dev/null
