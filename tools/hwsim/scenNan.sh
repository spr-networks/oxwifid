#!/bin/bash
# NAN USD interop: barely-nan (Rust) <-> wpa_supplicant v2.12 NAN USD
DIR=${1:-rx}   # rx = Rust subscribes <- wpa publishes ; tx = Rust publishes -> wpa subscribes
WPAS=~/hostap/wpa_supplicant/wpa_supplicant
WPACLI=~/hostap/wpa_supplicant/wpa_cli
sudo pkill -f wpa_supplicant 2>/dev/null; sudo pkill -f /tmp/barely 2>/dev/null
sudo systemctl stop wpa_supplicant NetworkManager 2>/dev/null
sudo iw reg set US 2>/dev/null
sudo modprobe -r mac80211_hwsim 2>/dev/null; sleep 1; sudo modprobe mac80211_hwsim radios=2; sleep 3; sudo rfkill unblock all
PHYB=phy$(iw dev wlan1 info | awk '/wiphy/{print $2}')
# wpa_supplicant (NAN USD) on wlan0
printf 'ctrl_interface=/run/wpa_nan\n' > /tmp/nan.conf
sudo ip link set wlan0 up
sudo $WPAS -B -Dnl80211 -iwlan0 -c /tmp/nan.conf -f /tmp/nan_wpas.log 2>/dev/null
sleep 2
# barely-nan on a monitor (phyB), NAN social channel 6
sudo iw dev wlan1 del
sudo iw phy $PHYB interface add mon1 type monitor
sudo ip link set mon1 up
sudo iw dev mon1 set channel 6
sleep 1

if [ "$DIR" = rx ]; then
  echo "=== wpa_supplicant PUBLISHES _test, barely-nan SUBSCRIBES ==="
  sudo $WPACLI -p /run/wpa_nan -iwlan0 NAN_PUBLISH service_name=_test srv_proto_type=2 ssi=6677 ttl=30 2>&1 | tail -1
  sudo timeout 15 /tmp/barely-nan --iface mon1 --channel 6 --mac 02:00:00:00:0e:01 --subscribe _test > /tmp/nan_rust.log 2>&1
  echo "--- barely-nan output ---"; grep -aE "NAN_DISCOVERED|NAN_SUBSCRIBE_RX" /tmp/nan_rust.log | head -2
else
  echo "=== barely-nan PUBLISHES _test, wpa_supplicant SUBSCRIBES ==="
  sudo timeout 18 /tmp/barely-nan --iface mon1 --channel 6 --mac 02:00:00:00:0e:01 --publish _test --ssi hello > /tmp/nan_rust.log 2>&1 &
  sleep 2
  sudo $WPACLI -p /run/wpa_nan -iwlan0 NAN_SUBSCRIBE service_name=_test active=1 srv_proto_type=2 2>&1 | tail -1
  sleep 12
  echo "--- wpa_supplicant NAN events ---"; sudo grep -aE "NAN-DISCOVERY-RESULT|NAN-RECEIVE" /tmp/nan_wpas.log | head -2
fi
sudo pkill -f wpa_supplicant 2>/dev/null; sudo pkill -f /tmp/barely 2>/dev/null
