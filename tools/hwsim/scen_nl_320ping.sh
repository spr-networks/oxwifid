#!/bin/bash
RUSTAP_CONFIG=${RUSTAP_CONFIG:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/tests/interop-config.json}
cleanup() { sudo pkill -9 -f /tmp/barely 2>/dev/null; sudo pkill -9 wpa_supplicant 2>/dev/null
  sudo iw phy $PHYB set netns 1 2>/dev/null; sudo ip netns del sta 2>/dev/null
  [ -n "$FWH" ] && sudo nft delete rule inet filter INPUT handle $FWH 2>/dev/null; sudo rmmod hwsim6g 2>/dev/null; }
trap cleanup EXIT
sudo pkill -9 -f /tmp/barely 2>/dev/null; sudo pkill -9 wpa_supplicant 2>/dev/null; sudo ip netns del sta 2>/dev/null; sudo rmmod hwsim6g 2>/dev/null
sudo iw reg set US 2>/dev/null
sudo modprobe -r mac80211_hwsim 2>/dev/null; sleep 1; sudo modprobe mac80211_hwsim radios=2; sleep 3
sudo iw reg set US; sleep 1
sudo insmod /tmp/hwsim6g/hwsim6g.ko 2>/dev/null && echo "hwsim6g loaded"
sudo ip link set wlan0 down; sudo iw dev wlan0 set type __ap; sudo ip link set wlan0 up
sudo ip addr flush dev wlan0 2>/dev/null; sudo ip addr add 192.168.213.1/24 dev wlan0
sudo /tmp/barely-ap --config "$RUSTAP_CONFIG" --mode netlink --iface wlan0 --channel 37 --width 320 --band 6 --sae --mac 02:00:00:00:00:00 --ssid turtle320 > /tmp/ap320.log 2>&1 &
sleep 2
echo "START_AP ok: $(sudo grep -acE 'START_AP.*ok' /tmp/ap320.log)"
echo "AP width: $(sudo iw dev wlan0 info 2>/dev/null | grep -oiE 'width: [0-9]+ MHz')"
sudo ip netns add sta; PHYB=phy$(iw dev wlan1 info | awk '/wiphy/{print $2}'); sudo iw phy $PHYB set netns name sta
sudo ip netns exec sta ip link set lo up; sudo ip netns exec sta ip link set wlan1 up
cat > /tmp/cli320.conf <<CFG
ctrl_interface=/run/wpa_n
sae_pwe=2
network={
  ssid="turtle320"
  sae_password="password1234"
  key_mgmt=SAE
  ieee80211w=2
  scan_freq=6135
  freq_list=6135
}
CFG
sudo ip netns exec sta wpa_supplicant -B -Dnl80211 -iwlan1 -c /tmp/cli320.conf -f /tmp/s320.log 2>/dev/null
for t in $(seq 1 8); do sleep 2; [ "$(sudo ip netns exec sta wpa_cli -p /run/wpa_n -iwlan1 status 2>/dev/null|awk -F= '/wpa_state/{print $2}')" = COMPLETED ] && break; done
echo "client state: $(sudo ip netns exec sta wpa_cli -p /run/wpa_n -iwlan1 status 2>/dev/null|awk -F= '/wpa_state/{print $2}')"
echo "client width: $(sudo ip netns exec sta iw dev wlan1 info 2>/dev/null | grep -oiE 'width: [0-9]+ MHz')"
sudo ip netns exec sta ip addr add 192.168.213.2/24 dev wlan1
sudo nft insert rule inet filter INPUT iifname "wlan0" ip saddr 192.168.213.0/24 accept comment \"barelytest\"
FWH=$(sudo nft -a list chain inet filter INPUT 2>/dev/null | awk '/barelytest/{print $NF}')
echo "ping (6GHz 320MHz, encrypted): $(sudo ip netns exec sta ping -c3 -W2 192.168.213.1 2>&1 | grep -oE '[0-9]+ received')"
