#!/bin/bash
RUSTAP_CONFIG=${RUSTAP_CONFIG:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/tests/interop-config.json}
sudo pkill -f /tmp/barely 2>/dev/null; sudo pkill -f wpa_supplicant 2>/dev/null
sudo rmmod hwsim6g 2>/dev/null; sudo iw reg set US 2>/dev/null
sudo modprobe -r mac80211_hwsim 2>/dev/null; sleep 1; sudo modprobe mac80211_hwsim radios=2; sleep 3; sudo iw reg set US; sleep 2
sudo insmod ~/hwsim6g/hwsim6g.ko
PHYA=phy$(iw dev wlan0 info | awk '/wiphy/{print $2}')
# AP side: IBSS ack-provider + monitor on phyA at 6135
sudo iw dev wlan0 del
sudo iw phy $PHYA interface add ibss0 type ibss 2>&1 | head -1
sudo ip link set ibss0 address 02:00:00:00:00:00; sudo ip link set ibss0 up
sudo iw dev ibss0 ibss join barelyack 6135 fixed-freq 02:CA:FE:00:00:00 2>&1 | head -1
sudo iw phy $PHYA interface add mon0 type monitor; sudo ip link set mon0 up
echo "ibss0 state: $(iw dev ibss0 info 2>/dev/null | awk '/type/{print $2}') / $(iw dev ibss0 link 2>/dev/null | head -1)"
sleep 2
sudo /tmp/barely-ap --config "$RUSTAP_CONFIG" --mode iface --iface mon0 --channel 37 --band 6 --mac 02:00:00:00:00:00 --ssid turtle6 --ip 10.10.10.1 > /tmp/ap6.log 2>&1 &
sleep 2
cat > /tmp/supp6.conf <<CFG
ctrl_interface=/run/wpa_b
network={
  ssid="turtle6"
  key_mgmt=SAE
  sae_password="password1234"
  ieee80211w=2
  proto=RSN
  pairwise=CCMP
  scan_freq=6135
}
CFG
sudo ip link set wlan1 up
sudo wpa_supplicant -B -Dnl80211 -iwlan1 -c /tmp/supp6.conf -f /tmp/supp6.log 2>/dev/null
for t in 1 2 3 4 5 6 7; do sleep 2; ST=$(sudo wpa_cli -p /run/wpa_b -iwlan1 status 2>/dev/null | awk -F= '/wpa_state/{print $2}'); [ "$ST" = COMPLETED ] && break; done
echo "wpa_state=$ST"
echo "=== wpa SAE/6GHz ==="; sudo grep -aiE "CTRL-EVENT-CONNECTED|SME: Trying to auth|SAE|6 GHz|selected BSS" /tmp/supp6.log 2>/dev/null | grep -aivE hexdump | tail -3
sudo pkill -f /tmp/barely 2>/dev/null; sudo pkill -f wpa_supplicant 2>/dev/null
