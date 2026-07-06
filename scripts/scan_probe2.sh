#!/bin/bash
# Map hwsim medium: one AP, scan from every other radio in root-ns AND in a
# netns. Writes /tmp/probe2_result.txt. Run: sudo setsid bash scan_probe2.sh &
B=/tmp/iopbin/barely-ap; R=/tmp/probe2_result.txt
rm -f "$R"
pkill -9 -f "[b]arely-ap --mode" 2>/dev/null
for ns in interopcli saecli pskcli probe probe2 cli; do ip netns del "$ns" 2>/dev/null; done
sleep 1
modprobe -r mac80211_hwsim 2>/dev/null; sleep 1; modprobe mac80211_hwsim rctbl=1 radios=5; sleep 2
iw reg set US 2>/dev/null; sleep 1
mapfile -t HW < <(for n in $(ls /sys/class/net|grep ^wlan); do [ "$(basename "$(readlink /sys/class/net/$n/device/driver 2>/dev/null)")" = mac80211_hwsim ] && echo "$n"; done)
AP=${HW[0]}
ip link set "$AP" down; iw dev "$AP" set type __ap; ip link set "$AP" up; ip addr add 10.10.10.1/24 dev "$AP" 2>/dev/null
setsid "$B" --mode netlink --iface "$AP" --channel 36 --width 80 --phy ax --ssid probe --psk password1234 </dev/null >/tmp/probe2_ap.log 2>&1 &
sleep 5
grep -aq "START_AP ok" /tmp/probe2_ap.log && APOK=yes || APOK=no
{
  echo "AP=$AP APOK=$APOK radios=[${HW[*]}]"
  scan5() { local d=$1 pfx=$2; local s=0; for i in 1 2 3 4 5; do $pfx iw dev "$d" scan 2>/dev/null | grep -aq "SSID: probe" && s=$((s+1)); done; echo "$s"; }
  for STA in "${HW[@]:1}"; do
    ip link set "$STA" up 2>/dev/null; sleep 1
    echo "  $STA (root-ns): $(scan5 "$STA" "") /5"
  done
  # now move the 2nd radio into a netns and retest
  STA=${HW[1]}
  ip netns add probe2; iw phy "$(cat /sys/class/net/$STA/phy80211/name)" set netns name probe2
  ip netns exec probe2 iw reg set US 2>/dev/null
  ip netns exec probe2 ip link set "$STA" up; sleep 1
  echo "  $STA (netns): $(scan5 "$STA" "ip netns exec probe2") /5"
} > "$R"
pkill -9 -f "[b]arely-ap --mode" 2>/dev/null; ip netns del probe2 2>/dev/null
