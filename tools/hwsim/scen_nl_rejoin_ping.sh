#!/bin/bash
RUSTAP_CONFIG=${RUSTAP_CONFIG:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/tests/interop-config.json}
cleanup() { sudo pkill -9 -f /tmp/barely 2>/dev/null; sudo pkill -9 wpa_supplicant 2>/dev/null
  sudo iw phy $PHYB set netns 1 2>/dev/null; sudo ip netns del sta 2>/dev/null
  [ -n "$FWH" ] && sudo nft delete rule inet filter INPUT handle $FWH 2>/dev/null; }
trap cleanup EXIT
sudo pkill -9 -f /tmp/barely 2>/dev/null; sudo pkill -9 wpa_supplicant 2>/dev/null; sudo ip netns del sta 2>/dev/null
sudo iw reg set US 2>/dev/null
sudo modprobe -r mac80211_hwsim 2>/dev/null; sleep 1; sudo modprobe mac80211_hwsim radios=2; sleep 3
sudo ip link set wlan0 down; sudo iw dev wlan0 set type __ap; sudo ip link set wlan0 up
sudo ip addr flush dev wlan0 2>/dev/null; sudo ip addr add 192.168.213.1/24 dev wlan0
sudo /tmp/barely-ap --config "$RUSTAP_CONFIG" --mode netlink --iface wlan0 --channel 1 --mac 02:00:00:00:00:00 --ssid turtlenet > /tmp/apnl.log 2>&1 &
sleep 2
sudo ip netns add sta; PHYB=phy$(iw dev wlan1 info | awk '/wiphy/{print $2}'); sudo iw phy $PHYB set netns name sta
sudo ip netns exec sta ip link set lo up; sudo ip netns exec sta ip link set wlan1 up
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
sudo ip netns exec sta wpa_supplicant -B -Dnl80211 -iwlan1 -c /tmp/cli.conf -f /tmp/s1.log 2>/dev/null
for t in $(seq 1 6); do sleep 2; [ "$(sudo ip netns exec sta wpa_cli -p /run/wpa_n -iwlan1 status 2>/dev/null|awk -F= '/wpa_state/{print $2}')" = COMPLETED ] && break; done
sudo ip netns exec sta ip addr add 192.168.213.2/24 dev wlan1
sudo nft insert rule inet filter INPUT iifname "wlan0" ip saddr 192.168.213.0/24 accept comment \"barelytest\"
FWH=$(sudo nft -a list chain inet filter INPUT 2>/dev/null | awk '/barelytest/{print $NF}')
echo "ping BEFORE rejoin: $(sudo ip netns exec sta ping -c2 -W2 192.168.213.1 2>&1 | grep -oE '[0-9]+ received')"
# disconnect + rejoin
sudo ip netns exec sta wpa_cli -p /run/wpa_n -iwlan1 disconnect >/dev/null 2>&1; sleep 3
sudo ip netns exec sta wpa_cli -p /run/wpa_n -iwlan1 reconnect >/dev/null 2>&1
for t in $(seq 1 6); do sleep 2; [ "$(sudo ip netns exec sta wpa_cli -p /run/wpa_n -iwlan1 status 2>/dev/null|awk -F= '/wpa_state/{print $2}')" = COMPLETED ] && break; done
sudo tcpdump -i wlan0 -nne -U -w /tmp/after.pcap 2>/dev/null & TD=$!
sleep 1
echo "ping AFTER rejoin:  $(sudo ip netns exec sta ping -c2 -W2 192.168.213.1 2>&1 | grep -oE '[0-9]+ received')"
sudo kill $TD 2>/dev/null; sleep 1
echo "=== wlan0 after rejoin (decrypted) ==="; sudo tcpdump -r /tmp/after.pcap -nn 2>/dev/null | grep -aiE "ARP|ICMP" | head -4
echo "kernel sta authorized: $(sudo iw dev wlan0 station dump 2>/dev/null | grep -A20 02:00:00:00:01:00 | awk '/authorized/{print $2}')"
