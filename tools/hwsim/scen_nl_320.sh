#!/bin/bash
sudo pkill -9 -f /tmp/barely 2>/dev/null; sudo pkill -9 wpa_supplicant 2>/dev/null
sudo rmmod hwsim6g 2>/dev/null
sudo modprobe -r mac80211_hwsim 2>/dev/null; sleep 1; sudo modprobe mac80211_hwsim radios=2; sleep 3
sudo iw reg set US; sleep 1
sudo insmod /tmp/hwsim6g/hwsim6g.ko 2>/dev/null && echo "hwsim6g: $(sudo dmesg|grep -a hwsim6g|tail -1|sed 's/.*hwsim6g: //')"
sudo ip link set wlan0 down; sudo iw dev wlan0 set type __ap; sudo ip link set wlan0 up
sudo /tmp/barely-ap --mode netlink --iface wlan0 --channel 37 --width 320 --band6 --sae --ssid turtle320 --psk password1234 > /tmp/ap320.log 2>&1 &
sleep 2
echo "START_AP ok: $(sudo grep -ac 'START_AP ok' /tmp/ap320.log)   err: $(sudo grep -aiE 'invalid|failed|error' /tmp/ap320.log | head -1)"
echo "AP chan: $(sudo iw dev wlan0 info 2>/dev/null | grep -iE 'channel|width' | tr '\n' ' ')"
printf 'ctrl_interface=/run/wpa_n\nsae_pwe=2\nnetwork={\n ssid="turtle320"\n sae_password="password1234"\n key_mgmt=SAE\n ieee80211w=2\n scan_freq=6135\n freq_list=6135\n}\n' > /tmp/c320.conf
sudo ip link set wlan1 up
sudo wpa_supplicant -B -Dnl80211 -iwlan1 -c /tmp/c320.conf -f /tmp/s320.log 2>/dev/null
for t in $(seq 1 8); do sleep 2; [ "$(sudo wpa_cli -p /run/wpa_n -iwlan1 status 2>/dev/null|awk -F= '/wpa_state/{print $2}')" = COMPLETED ] && break; done
echo "client state: $(sudo wpa_cli -p /run/wpa_n -iwlan1 status 2>/dev/null|awk -F= '/wpa_state/{print $2}')"
echo "client chan: $(sudo iw dev wlan1 info 2>/dev/null | grep -iE 'channel|width' | tr '\n' ' ')"
sudo pkill -9 -f /tmp/barely 2>/dev/null; sudo pkill -9 wpa_supplicant 2>/dev/null; sudo rmmod hwsim6g 2>/dev/null
