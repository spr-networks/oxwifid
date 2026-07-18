#!/bin/bash
RUSTAP_CONFIG=${RUSTAP_CONFIG:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/tests/interop-config.json}
# scenA.sh <wpa2|wpa3|owe> <chan> : Rust barely-cli station -> real hostapd AP
SEC=${1:-wpa2}; CHAN=${2:-1}
FREQ=2412; HWMODE=g; EXTRA=""
if [ "$CHAN" -ge 36 ]; then FREQ=5180; HWMODE=a; EXTRA=$'country_code=US\nieee80211d=1'; fi
sudo pkill -f hostapd 2>/dev/null; sudo pkill -f /tmp/barely 2>/dev/null; sleep 1
sudo systemctl stop wpa_supplicant NetworkManager 2>/dev/null
sudo iw reg set US 2>/dev/null
sudo modprobe -r mac80211_hwsim 2>/dev/null; sleep 1; sudo modprobe mac80211_hwsim radios=2; sleep 2; sudo rfkill unblock all
PHYB=phy$(iw dev wlan1 info | awk '/wiphy/{print $2}')
case $SEC in
  wpa2) KM='wpa_key_mgmt=WPA-PSK'; PMF=''; CRED='wpa_passphrase=password1234'; CLIFLAG='';;
  wpa3) KM='wpa_key_mgmt=SAE'; PMF=$'ieee80211w=2\nsae_require_mfp=1\nsae_pwe=2'; CRED=$'sae_password=password1234\nwpa_passphrase=password1234'; CLIFLAG='--sae';;
  owe)  KM='wpa_key_mgmt=OWE'; PMF='ieee80211w=2'; CRED='# OWE: no passphrase'; CLIFLAG='--owe';;
esac
cat > /tmp/h.conf <<CFG
interface=wlan0
driver=nl80211
ssid=turtlenet
hw_mode=$HWMODE
channel=$CHAN
$EXTRA
wpa=2
$KM
$PMF
rsn_pairwise=CCMP
$CRED
CFG
sudo hostapd -t /tmp/h.conf > /tmp/h.log 2>&1 &
sleep 3
grep -aq AP-ENABLED /tmp/h.log || { echo "[$SEC ch$CHAN] HOSTAPD FAILED:"; grep -aiE 'error|invalid|fail|not support' /tmp/h.log | head -3; }
sudo iw dev wlan1 del
sudo iw phy $PHYB interface add ibss1 type ibss
sudo ip link set ibss1 address 02:00:00:00:01:00
sudo ip link set ibss1 up
sudo iw dev ibss1 ibss join barelyibss $FREQ fixed-freq 02:CA:FE:00:00:01
sudo iw phy $PHYB interface add mon1 type monitor
sudo ip link set mon1 up
sleep 3
for attempt in 1 2 3; do
  sudo timeout 12 /tmp/barely-cli --config "$RUSTAP_CONFIG" --mode iface --iface mon1 --channel $CHAN --mac 02:00:00:00:01:00 --gw-mac 02:00:00:00:00:00 --ssid turtlenet $CLIFLAG > /tmp/cli.log 2>&1
  grep -aq AUTHENTICATED /tmp/cli.log && break
done
echo "[$SEC ch$CHAN] cli:     $(grep -aoE 'AUTHENTICATED|PING_REPLY_OK' /tmp/cli.log | tr '\n' ' ')"
echo "[$SEC ch$CHAN] hostapd: $(sudo grep -aoE 'AP-STA-CONNECTED|EAPOL-4WAY-HS-COMPLETED' /tmp/h.log | sort -u | tr '\n' ' ')"
sudo pkill -f hostapd; sudo pkill -f /tmp/barely
