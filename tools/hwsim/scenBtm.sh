#!/bin/bash
RUSTAP_CONFIG=${RUSTAP_CONFIG:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/tests/interop-config.json}
# scenB.sh <wpa2|wpa3|owe> <chan> : real wpa_supplicant -> Rust barely-ap
SEC=${1:-wpa2}; CHAN=${2:-1}
FREQ=2412; [ "$CHAN" -ge 36 ] && FREQ=5180
sudo pkill -f hostapd 2>/dev/null; sudo pkill -f /tmp/barely 2>/dev/null; sudo pkill -f wpa_supplicant 2>/dev/null
sudo systemctl stop wpa_supplicant NetworkManager 2>/dev/null
sudo iw reg set US 2>/dev/null
sudo modprobe -r mac80211_hwsim 2>/dev/null; sleep 1; sudo modprobe mac80211_hwsim radios=2; sleep 3; sudo rfkill unblock all
PHYA=phy$(iw dev wlan0 info | awk '/wiphy/{print $2}')
# AP side: IBSS ack-provider (02:00:00:00:00:00) + monitor mon0 on phyA
sudo iw dev wlan0 del
sudo iw phy $PHYA interface add ibss0 type ibss
sudo ip link set ibss0 address 02:00:00:00:00:00
sudo ip link set ibss0 up
sudo iw dev ibss0 ibss join barelyack $FREQ fixed-freq 02:CA:FE:00:00:00
sudo iw phy $PHYA interface add mon0 type monitor
sudo ip link set mon0 up
sleep 2
case $SEC in
  wpa2) APFLAG=''; SUPP=$'key_mgmt=WPA-PSK\n  psk="password1234"';;
  wpa3) APFLAG='--sae'; SUPP=$'key_mgmt=SAE\n  psk="password1234"\n  ieee80211w=2';;
  owe)  APFLAG='--owe'; SUPP=$'key_mgmt=OWE\n  ieee80211w=2';;
esac
sudo /tmp/barely-ap --config "$RUSTAP_CONFIG" --mode iface --iface mon0 --channel $CHAN --mac 02:00:00:00:00:00 --ssid turtlenet --ip 10.10.10.1 $APFLAG --btm > /tmp/ap.log 2>&1 &
sleep 2
cat > /tmp/supp.conf <<CFG
ctrl_interface=/run/wpa_b
network={
  ssid="turtlenet"
  $SUPP
  proto=RSN
  pairwise=CCMP
  scan_freq=$FREQ
}
CFG
sudo ip link set wlan1 up
sudo wpa_supplicant -B -dd -Dnl80211 -iwlan1 -c /tmp/supp.conf -f /tmp/supp.log 2>/dev/null
for t in 1 2 3 4 5 6; do sleep 2; ST=$(sudo wpa_cli -p /run/wpa_b -iwlan1 status 2>/dev/null | awk -F= '/wpa_state/{print $2}'); [ "$ST" = COMPLETED ] && break; done
echo "[$SEC ch$CHAN] supplicant wpa_state=$ST"
sudo ip addr add 10.10.10.2/24 dev wlan1 2>/dev/null
echo "[$SEC ch$CHAN] ping: $(ping -c2 -W2 10.10.10.1 2>&1 | grep -oE '[0-9]+ received' )"
sudo pkill -f /tmp/barely; sudo pkill -f wpa_supplicant
echo "=== wpa_supplicant BTM receipt ==="
sudo grep -aiE "BSS Transition Management Request|WNM: BSS|BSS-TM-REQ|RX BTM|nr_entries" /tmp/supp.log 2>/dev/null | grep -aivE hexdump | tail -3
echo "=== AP BTM response ==="; sudo grep -aiE "BTM Response" /tmp/ap.log | tail -2
