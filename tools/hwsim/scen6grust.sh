#!/bin/bash
RUSTAP_CONFIG=${RUSTAP_CONFIG:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/tests/interop-config.json}
sudo pkill -f /tmp/barely 2>/dev/null; sudo pkill -f wpa_supplicant 2>/dev/null; sudo pkill tcpdump 2>/dev/null
sudo rmmod hwsim6g 2>/dev/null
sudo iw reg set US 2>/dev/null
sudo modprobe -r mac80211_hwsim 2>/dev/null; sleep 1; sudo modprobe mac80211_hwsim radios=3; sleep 3; sudo iw reg set US; sleep 2
sudo insmod ~/hwsim6g/hwsim6g.ko
PHYA=phy$(iw dev wlan0 info | awk '/wiphy/{print $2}')
PHYC=phy$(iw dev wlan2 info | awk '/wiphy/{print $2}')
# AP injects on a monitor at 6135
sudo iw dev wlan0 del; sudo iw phy $PHYA interface add mon0 type monitor; sudo ip link set mon0 up; sudo iw dev mon0 set freq 6135 2>&1 | head -1
# capture monitor at 6135
sudo iw dev wlan2 del; sudo iw phy $PHYC interface add mon2 type monitor; sudo ip link set mon2 up; sudo iw dev mon2 set freq 6135
sleep 1
sudo /tmp/barely-ap --config "$RUSTAP_CONFIG" --mode iface --iface mon0 --channel 37 --band 6 --mac 02:00:00:00:00:00 --ssid turtle6 > /tmp/ap6.log 2>&1 &
sleep 2
sudo timeout 5 tcpdump -i mon2 -nn -c 2 -w /tmp/b6r.pcap 'type mgt subtype beacon and wlan host 02:00:00:00:00:00' 2>/dev/null
echo "=== rust 6GHz beacon decoded ==="
sudo tshark -r /tmp/b6r.pcap -V 2>/dev/null | grep -aiE "Frequency: 6135|SSID=turtle6|HE Capabilities|HE Operation|6 GHz Operation Information" | head -6
sudo pkill -f /tmp/barely 2>/dev/null; sudo pkill tcpdump 2>/dev/null
