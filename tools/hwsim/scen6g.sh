#!/bin/bash
RUSTAP_CONFIG=${RUSTAP_CONFIG:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/tests/interop-config.json}
HWSIM6G=${HWSIM6G:-/tmp/hwsim6g/hwsim6g.ko}
# 6 GHz Scenario A: Rust barely-cli (SAE) -> reference AP on channel 37 (6135 MHz)
REFERENCE_AP=${REFERENCE_AP:?set REFERENCE_AP to the reference AP binary}
REFERENCE_AP_PROCESS=$(basename "$REFERENCE_AP")
SEC=${1:-wpa3}; CH=37; FREQ=6135
sudo pkill -x "$REFERENCE_AP_PROCESS" 2>/dev/null; sudo pkill -f /tmp/barely 2>/dev/null; sleep 1
sudo systemctl stop wpa_supplicant NetworkManager 2>/dev/null
sudo iw reg set US 2>/dev/null
sudo modprobe -r mac80211_hwsim 2>/dev/null; sleep 1; sudo modprobe mac80211_hwsim radios=2; sleep 3; sudo rfkill unblock all
sudo insmod "$HWSIM6G"
PHYB=phy$(iw dev wlan1 info | awk '/wiphy/{print $2}')
case $SEC in
  wpa3) KM=$'wpa_key_mgmt=SAE\nsae_pwe=2\nsae_password=password1234'; CLIFLAG='--sae';;
  owe)  KM='wpa_key_mgmt=OWE'; CLIFLAG='--owe';;
esac
cat > /tmp/h6.conf <<CFG
interface=wlan0
driver=nl80211
ssid=turtlenet
country_code=US
hw_mode=a
channel=$CH
op_class=131
ieee80211ax=1
ieee80211w=2
wpa=2
$KM
rsn_pairwise=CCMP
CFG
sudo "$REFERENCE_AP" -t /tmp/h6.conf > /tmp/h6.log 2>&1 &
sleep 4
grep -aq AP-ENABLED /tmp/h6.log && echo "reference AP 6GHz: UP" || { echo "reference AP 6GHz FAILED:"; sudo grep -aiE "Invalid|not allowed|6 GHz|line [0-9]|could not|Configuration file" /tmp/h6.log | head -4; exit 0; }
# client phyB: mesh ack-provider on 6GHz + monitor
sudo iw dev wlan1 del
sudo iw phy $PHYB interface add mesh1 type mp
sudo ip link set mesh1 address 02:00:00:00:01:00
sudo ip link set mesh1 up
sudo iw dev mesh1 mesh join barelymesh freq $FREQ 2>&1 | head -1
sudo iw phy $PHYB interface add mon1 type monitor
sudo ip link set mon1 up
sudo iw dev mon1 set freq $FREQ 2>&1 | head -1
sleep 2
echo -n "mon1 freq: "; iw dev mon1 info | awk "/channel/{print \$2,\$3}"
sudo timeout 14 /tmp/barely-cli --config "$RUSTAP_CONFIG" --mode iface --iface mon1 --channel $CH --mac 02:00:00:00:01:00 --gw-mac 02:00:00:00:00:00 --ssid turtlenet $CLIFLAG > /tmp/c6.log 2>&1
echo "[$SEC 6GHz] cli: $(grep -aoE 'AUTHENTICATED' /tmp/c6.log | tr '\n' ' ')"
echo "[$SEC 6GHz] reference AP: $(sudo grep -aoE 'AP-STA-CONNECTED|EAPOL-4WAY-HS-COMPLETED' /tmp/h6.log | sort -u | tr '\n' ' ')"
sudo pkill -x "$REFERENCE_AP_PROCESS"; sudo pkill -f /tmp/barely; sudo rmmod hwsim6g 2>/dev/null
