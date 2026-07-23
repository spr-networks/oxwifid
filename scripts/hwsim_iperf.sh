#!/bin/bash
# iperf3 throughput over hwsim: barely-ap AP + wpa_supplicant client, then iperf3
# UPLINK (client->AP) and DOWNLINK (AP->client). Isolates whether a downlink
# throughput collapse is a barely-ap data-plane bug (reproduces here) or a
# real-card (mt7915e) issue (hwsim is fine). hwsim ONLY. Writes /tmp/iperf_result.txt.
B=/tmp/iopbin/barely-ap; NS=iperfcli; R=/tmp/iperf_result.txt
FIREWALL_COMMENT="barely-iperf-$$"
WPAS=${WPAS:?set WPAS to the wpa_supplicant binary}
WCLI=${WCLI:?set WCLI to the wpa_cli binary}
cleanup() {
  pkill -9 -x iperf3 2>/dev/null
  pkill -9 -f "[b]arely-ap --" 2>/dev/null
  ip netns del "$NS" 2>/dev/null
  handle=$(nft -a list chain inet filter INPUT 2>/dev/null |
    awk -v marker="$FIREWALL_COMMENT" '$0 ~ marker { for (i=1; i<=NF; i++) if ($i == "handle") print $(i+1) }' |
    head -1)
  [ -z "$handle" ] || nft delete rule inet filter INPUT handle "$handle" 2>/dev/null
}
trap cleanup EXIT
rm -f "$R"; : > "$R"
pkill -9 -f "[b]arely-ap --" 2>/dev/null; pkill -9 wlantest 2>/dev/null; pkill -9 wmediumd 2>/dev/null
pkill -9 -x wpa_supplicant 2>/dev/null; pkill -9 -x iperf3 2>/dev/null
ip netns del "$NS" 2>/dev/null
sleep 2; for _ in 1 2 3 4 5; do rmmod mac80211_hwsim 2>/dev/null && break; sleep 2; done; sleep 1
modprobe mac80211_hwsim rctbl=1 radios=4; sleep 2
iw reg set US 2>/dev/null; sleep 1
mapfile -t HW < <(for n in $(ls /sys/class/net|grep ^wlan); do [ "$(basename "$(readlink /sys/class/net/$n/device/driver 2>/dev/null)")" = mac80211_hwsim ] && echo "$n"; done)
AP=${HW[0]}; STA=${HW[1]}
nft insert rule inet filter INPUT iifname "$AP" ip daddr 10.10.10.1 \
  tcp dport 5201 accept comment "$FIREWALL_COMMENT"
echo "AP=$AP STA=$STA" >> "$R"

# barely-ap: VHT (ac) on ch36 80 MHz — hwsim's minstrel_ht gives HT/VHT rates
# (not HE/EHT), so ac maximises the achievable hwsim rate. WPA2-PSK for simplicity.
cat > /tmp/iperf.json <<EOF
{ "ssid": "iperf", "passphrase": "password1234", "key_mgmt": "psk",
  "phy": "ax", "mode": "netlink", "iface": "$AP", "band": 5, "channel": 36, "width": 80 }
EOF
ip link set "$AP" down 2>/dev/null; iw dev "$AP" set type __ap 2>/dev/null; ip link set "$AP" up
ip addr add 10.10.10.1/24 dev "$AP" 2>/dev/null
setsid "$B" --config /tmp/iperf.json </dev/null >/tmp/iperf_ap.log 2>&1 &
sleep 5
grep -aqE "START_AP.*ok" /tmp/iperf_ap.log && echo "AP up" >> "$R" || { echo "AP FAILED: $(tail -1 /tmp/iperf_ap.log)" >> "$R"; echo DONE >> "$R"; exit 1; }

ip netns add "$NS"; iw phy "$(cat /sys/class/net/$STA/phy80211/name)" set netns name "$NS"
ip netns exec "$NS" iw reg set US 2>/dev/null; ip netns exec "$NS" ip link set lo up; ip netns exec "$NS" ip link set "$STA" up; sleep 1
printf 'ctrl_interface=/run/wpa_i\nnetwork={\n ssid="iperf"\n psk="password1234"\n key_mgmt=WPA-PSK\n}\n' > /tmp/iperf.conf
# scan-gate (reliable connect)
for _ in $(seq 1 15); do
  ip netns exec "$NS" iw dev "$STA" scan 2>/dev/null | grep -aq "SSID: iperf" && break
  sleep 1
done
( ip netns exec "$NS" "$WPAS" -Dnl80211 -i"$STA" -c /tmp/iperf.conf >/tmp/iperf_cli.log 2>&1 & )
st=""
for k in $(seq 1 30); do sleep 1
  st=$(ip netns exec "$NS" "$WCLI" -p /run/wpa_i -i"$STA" status 2>/dev/null | sed -n 's/^wpa_state=//p')
  [ "$st" = COMPLETED ] && break
done
echo "client: ${st:-none}" >> "$R"
[ "$st" = COMPLETED ] || { echo DONE >> "$R"; exit 1; }
ip netns exec "$NS" ip addr add 10.10.10.2/24 dev "$STA" 2>/dev/null
sleep 2

# Negotiated rate + aggregation flags (the downlink-throughput smoking gun).
echo "-- AP's view of the station (rates / WME / aggregation) --" >> "$R"
iw dev "$AP" station dump 2>/dev/null | grep -aiE "tx bitrate|rx bitrate|tx packets|rx packets|authorized|WMM|TDLS|MFP|mesh" | head >> "$R"

# iperf3 server on the AP side, client drives both directions.
iperf3 -s -1 -B 10.10.10.1 -D 2>/dev/null; sleep 1
echo "-- UPLINK (client -> AP) --" >> "$R"
ip netns exec "$NS" iperf3 -c 10.10.10.1 -t 5 -O 1 2>/dev/null | grep -aE "sender|receiver" >> "$R"
iperf3 -s -1 -B 10.10.10.1 -D 2>/dev/null; sleep 1
echo "-- DOWNLINK (AP -> client, reverse) --" >> "$R"
ip netns exec "$NS" iperf3 -c 10.10.10.1 -R -t 5 -O 1 2>/dev/null | grep -aE "sender|receiver" >> "$R"
echo DONE >> "$R"
