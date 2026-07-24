#!/bin/bash
RUSTAP_CONFIG=${RUSTAP_CONFIG:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/tests/interop-config.json}
# Full netlink offload AP (kernel beacon + CCMP) vs real wpa_supplicant (WPA2)
sudo pkill -f /tmp/barely 2>/dev/null; sudo pkill -f wpa_supplicant 2>/dev/null
sudo systemctl stop wpa_supplicant NetworkManager 2>/dev/null
sudo iw reg set US 2>/dev/null
sudo modprobe -r mac80211_hwsim 2>/dev/null; sleep 1; sudo modprobe mac80211_hwsim radios=2; sleep 3; sudo rfkill unblock all
# wlan0 -> AP type + up + IP (the kernel IP stack is the AP's data backend)
sudo ip link set wlan0 down
sudo iw dev wlan0 set type __ap 2>&1 | head -1
sudo ip link set wlan0 up
sudo /tmp/barely-ap --config "$RUSTAP_CONFIG" --mode netlink --iface wlan0 --channel 1 --mac 02:00:00:00:00:00 --ssid turtlenet > /tmp/apnl.log 2>&1 &
sleep 3
sudo ip addr add 10.10.10.1/24 dev wlan0 2>/dev/null
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
sudo ip link set wlan1 up
sudo wpa_supplicant -B -Dnl80211 -iwlan1 -c /tmp/cli.conf -f /tmp/wpa.log 2>/dev/null
for t in 1 2 3 4 5 6 7; do sleep 2; ST=$(sudo wpa_cli -p /run/wpa_n -iwlan1 status 2>/dev/null | awk -F= '/wpa_state/{print $2}'); [ "$ST" = COMPLETED ] && break; done
echo "wpa_state=$ST"
sudo ip addr add 10.10.10.2/24 dev wlan1 2>/dev/null
echo "ping: $(ping -I wlan1 -c3 -W2 10.10.10.1 2>&1 | grep -oE '[0-9]+ received')"
echo "=== ap log ==="; sudo grep -aiE "START_AP|keyed|authorized|failed" /tmp/apnl.log | tail -4
echo "=== wpa ==="; sudo grep -aE "CTRL-EVENT-CONNECTED|4-Way|Key negotiation completed|reason" /tmp/wpa.log | tail -3
sudo pkill -f /tmp/barely 2>/dev/null; sudo pkill -f wpa_supplicant 2>/dev/null
