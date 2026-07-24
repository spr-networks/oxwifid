#!/bin/bash
RUSTAP_CONFIG=${RUSTAP_CONFIG:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/tests/interop-config.json}
cleanup(){ sudo pkill -9 -f /tmp/barely 2>/dev/null; sudo pkill -9 wpa_supplicant 2>/dev/null
  sudo iw phy $PHYB set netns 1 2>/dev/null; sudo ip netns del sta 2>/dev/null
  [ -n "$FWH" ] && sudo nft delete rule inet filter INPUT handle $FWH 2>/dev/null; }
trap cleanup EXIT
sudo pkill -9 -f /tmp/barely 2>/dev/null; sudo pkill -9 wpa_supplicant 2>/dev/null; sudo ip netns del sta 2>/dev/null
sudo iw reg set US 2>/dev/null
sudo modprobe -r mac80211_hwsim 2>/dev/null; sleep 1; sudo modprobe mac80211_hwsim radios=2; sleep 3
sudo ip link set wlan0 down; sudo iw dev wlan0 set type __ap; sudo ip link set wlan0 up
sudo /tmp/barely-ap --config "$RUSTAP_CONFIG" --mode netlink --iface wlan0 --channel 1 --per-sta-vif --mac 02:00:00:00:00:00 --ssid turtlenet > /tmp/apnl.log 2>&1 &
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
echo "STA state: $(sudo ip netns exec sta wpa_cli -p /run/wpa_n -iwlan1 status 2>/dev/null|awk -F= '/wpa_state/{print $2}')"
VLAN=$(ip -o link show 2>/dev/null | awk -F': ' '/apvlan/{print $2; exit}')
echo "station VLAN iface: $VLAN"
sudo ip addr add 192.168.213.1/24 dev $VLAN; sudo ip link set $VLAN up
sudo ip netns exec sta ip addr add 192.168.213.2/24 dev wlan1
sudo nft insert rule inet filter INPUT iifname "$VLAN" ip saddr 192.168.213.0/24 accept comment \"barelyvif\"
FWH=$(sudo nft -a list chain inet filter INPUT 2>/dev/null | awk '/barelyvif/{print $NF}')
echo "ping via per-STA VLAN: $(sudo ip netns exec sta ping -c3 -W2 192.168.213.1 2>&1 | grep -oE '[0-9]+ received')"
