#!/bin/bash
RUSTAP_CONFIG=${RUSTAP_CONFIG:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/tests/interop-config.json}
sudo pkill -f /tmp/barely 2>/dev/null; sudo pkill -f wpa_supplicant 2>/dev/null; sudo pkill tcpdump 2>/dev/null
sudo iw reg set US 2>/dev/null
sudo modprobe -r mac80211_hwsim 2>/dev/null; sleep 1; sudo modprobe mac80211_hwsim radios=3; sleep 3; sudo rfkill unblock all
PHYA=phy$(iw dev wlan0 info | awk '/wiphy/{print $2}')
PHYC=phy$(iw dev wlan2 info | awk '/wiphy/{print $2}')
# AP side: IBSS ack-provider + monitor for injection (phyA)
sudo iw dev wlan0 del
sudo iw phy $PHYA interface add ibss0 type ibss; sudo ip link set ibss0 address 02:00:00:00:00:00; sudo ip link set ibss0 up
sudo iw dev ibss0 ibss join barelyack 2412 fixed-freq 02:CA:FE:00:00:00
sudo iw phy $PHYA interface add mon0 type monitor; sudo ip link set mon0 up
# capture monitor on phyC
sudo iw dev wlan2 del; sudo iw phy $PHYC interface add mon2 type monitor; sudo ip link set mon2 up; sudo iw dev mon2 set channel 1
sleep 2
sudo /tmp/barely-ap --config "$RUSTAP_CONFIG" --mode iface --iface mon0 --channel 1 --mac 02:00:00:00:00:00 --ssid turtlenet --rnr > /tmp/ap.log 2>&1 &
sleep 2
sudo timeout 5 tcpdump -i mon2 -nn -c 3 -w /tmp/br.pcap 'type mgt subtype beacon and wlan host 02:00:00:00:00:00' 2>/dev/null
echo "=== RNR element decoded by tshark ==="
sudo tshark -r /tmp/br.pcap -V 2>/dev/null | grep -aiE "Reduced Neighbor Report|Operating Class: 131|TBTT Information|BSSID: 02:00:00:00:00:10" | head -5
# wpa associates (beacon with RNR accepted)
cat > /tmp/supp.conf <<CFG
ctrl_interface=/run/wpa_b
network={ ssid="turtlenet"
key_mgmt=WPA-PSK
psk="password1234"
scan_freq=2412 }
CFG
sudo ip link set wlan1 up; sudo wpa_supplicant -B -Dnl80211 -iwlan1 -c /tmp/supp.conf -f /tmp/supp.log 2>/dev/null
for t in 1 2 3 4 5; do sleep 2; ST=$(sudo wpa_cli -p /run/wpa_b -iwlan1 status 2>/dev/null | awk -F= '/wpa_state/{print $2}'); [ "$ST" = COMPLETED ] && break; done
echo "wpa_state=$ST (beacon-with-RNR accepted)"
sudo pkill -f /tmp/barely 2>/dev/null; sudo pkill -f wpa_supplicant 2>/dev/null; sudo pkill tcpdump 2>/dev/null
