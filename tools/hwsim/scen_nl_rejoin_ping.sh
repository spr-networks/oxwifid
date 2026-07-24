#!/bin/bash
RUSTAP_CONFIG=${RUSTAP_CONFIG:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/tests/interop-config.json}
cleanup() { sudo pkill -9 -f /tmp/barely 2>/dev/null; sudo pkill -9 wpa_supplicant 2>/dev/null
  sudo iw phy $PHYB set netns 1 2>/dev/null; sudo ip netns del sta 2>/dev/null
  [ -n "$FWH" ] && sudo nft delete rule inet filter INPUT handle $FWH 2>/dev/null; }
trap cleanup EXIT
sudo pkill -9 -f /tmp/barely 2>/dev/null; sudo pkill -9 wpa_supplicant 2>/dev/null; sudo ip netns del sta 2>/dev/null
sudo iw reg set US 2>/dev/null
sudo modprobe -r mac80211_hwsim 2>/dev/null; sleep 1; sudo modprobe mac80211_hwsim radios=2; sleep 3
mapfile -t HW < <(for d in /sys/class/net/*/phy80211; do n=$(basename "$(dirname "$d")"); [ "$(basename "$(readlink "/sys/class/net/$n/device/driver" 2>/dev/null)" 2>/dev/null)" = mac80211_hwsim ] && echo "$n"; done)
AP_IF=${HW[0]}; STA_IF=${HW[1]}
sudo ip link set "$AP_IF" down; sudo iw dev "$AP_IF" set type __ap; sudo ip link set "$AP_IF" up
sudo ip addr flush dev "$AP_IF" 2>/dev/null; sudo ip addr add 192.168.213.1/24 dev "$AP_IF"
sudo /tmp/barely-ap --config "$RUSTAP_CONFIG" --mode netlink --iface "$AP_IF" --channel 1 --mac 02:00:00:00:00:00 --ssid turtlenet > /tmp/apnl.log 2>&1 &
sleep 2
sudo ip netns add sta; PHYB=$(cat "/sys/class/net/$STA_IF/phy80211/name"); sudo iw phy "$PHYB" set netns name sta
sudo ip netns exec sta ip link set lo up; sudo ip netns exec sta ip link set "$STA_IF" up
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
sudo ip netns exec sta wpa_supplicant -B -Dnl80211 -i"$STA_IF" -c /tmp/cli.conf -f /tmp/s1.log 2>/dev/null
for t in $(seq 1 6); do sleep 2; [ "$(sudo ip netns exec sta wpa_cli -p /run/wpa_n -i"$STA_IF" status 2>/dev/null|awk -F= '/wpa_state/{print $2}')" = COMPLETED ] && break; done
sudo ip netns exec sta ip addr add 192.168.213.2/24 dev "$STA_IF"
sudo nft insert rule inet filter INPUT iifname "$AP_IF" ip saddr 192.168.213.0/24 accept comment \"barelytest\"
FWH=$(sudo nft -a list chain inet filter INPUT 2>/dev/null | awk '/barelytest/{print $NF}')
echo "ping BEFORE rejoin: $(sudo ip netns exec sta ping -c2 -W2 192.168.213.1 2>&1 | grep -oE '[0-9]+ received')"
# disconnect + rejoin
sudo ip netns exec sta wpa_cli -p /run/wpa_n -i"$STA_IF" disconnect >/dev/null 2>&1; sleep 3
sudo ip netns exec sta wpa_cli -p /run/wpa_n -i"$STA_IF" reconnect >/dev/null 2>&1
for t in $(seq 1 6); do sleep 2; [ "$(sudo ip netns exec sta wpa_cli -p /run/wpa_n -i"$STA_IF" status 2>/dev/null|awk -F= '/wpa_state/{print $2}')" = COMPLETED ] && break; done
sudo tcpdump -i "$AP_IF" -nne -U -w /tmp/after.pcap 2>/dev/null & TD=$!
sleep 1
echo "ping AFTER rejoin:  $(sudo ip netns exec sta ping -c2 -W2 192.168.213.1 2>&1 | grep -oE '[0-9]+ received')"
sudo kill $TD 2>/dev/null; sleep 1
echo "=== $AP_IF after rejoin (decrypted) ==="; sudo tcpdump -r /tmp/after.pcap -nn 2>/dev/null | grep -aiE "ARP|ICMP" | head -4
echo "kernel sta authorized: $(sudo iw dev "$AP_IF" station dump 2>/dev/null | grep -A20 02:00:00:00:01:00 | awk '/authorized/{print $2}')"
