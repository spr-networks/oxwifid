#!/bin/bash
# Controlled probe: static AP, scan the STA N times, count misses. Writes result
# to /tmp/probe_result.txt. Run detached: sudo setsid bash scan_probe.sh &
B=/tmp/iopbin/barely-ap; NS=probe; R=/tmp/probe_result.txt
rm -f "$R"
pkill -9 -f "[b]arely-ap --mode" 2>/dev/null; ip netns del $NS 2>/dev/null; sleep 1
mapfile -t HW < <(for n in $(ls /sys/class/net|grep ^wlan); do [ "$(basename "$(readlink /sys/class/net/$n/device/driver 2>/dev/null)")" = mac80211_hwsim ] && echo "$n"; done)
AP=${HW[0]}; STA=${HW[1]}
ip link set "$AP" down; iw dev "$AP" set type __ap; ip link set "$AP" up; ip addr add 10.10.10.1/24 dev "$AP" 2>/dev/null
setsid "$B" --mode netlink --iface "$AP" --channel 36 --width 80 --phy ax --ssid probe --psk password1234 </dev/null >/tmp/probe_ap.log 2>&1 &
sleep 5
grep -aq "START_AP ok" /tmp/probe_ap.log && APOK=yes || APOK=no
STAPHY=$(cat "/sys/class/net/$STA/phy80211/name")
ip netns add $NS; iw phy "$STAPHY" set netns name $NS; ip netns exec $NS ip link set "$STA" up; sleep 1
seen=0; miss=0
for i in $(seq 1 20); do
  if ip netns exec $NS iw dev "$STA" scan 2>/dev/null | grep -aq "SSID: probe"; then seen=$((seen+1)); else miss=$((miss+1)); fi
done
echo "AP=$AP STA=$STA APOK=$APOK  SEEN=$seen MISS=$miss  (static AP, never restarted)" > "$R"
pkill -9 -f "[b]arely-ap --mode" 2>/dev/null; ip netns del $NS 2>/dev/null
