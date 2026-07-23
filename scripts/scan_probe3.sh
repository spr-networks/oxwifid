#!/bin/bash
# FAST hwsim medium map: single-freq scans (ch36 only). For each STA radio test
# root-ns then netns delivery from a static AP. Writes /tmp/probe3_result.txt.
B=/tmp/iopbin/barely-ap; R=/tmp/probe3_result.txt
rm -f "$R"
# Nuke ALL leftover hwsim consumers from 11 days of churn (wlantest/wmediumd/etc)
pkill -9 -f "[b]arely-ap --mode" 2>/dev/null
pkill -9 wlantest 2>/dev/null; pkill -9 wmediumd 2>/dev/null
pkill -9 -x wpa_supplicant 2>/dev/null
for ns in $(ip -o netns list 2>/dev/null | awk -F'[ :]' '{print $1}'); do
  case $ns in interopcli|saecli|pskcli|probe|probe2|probe3|cli|sae|stamx|mldv) ip netns del "$ns" 2>/dev/null;; esac
done
sleep 1
modprobe -r mac80211_hwsim 2>/dev/null; sleep 1; modprobe mac80211_hwsim rctbl=1 radios=5; sleep 2
iw reg set US 2>/dev/null; sleep 1
mapfile -t HW < <(for n in $(ls /sys/class/net|grep ^wlan); do [ "$(basename "$(readlink /sys/class/net/$n/device/driver 2>/dev/null)")" = mac80211_hwsim ] && echo "$n"; done)
AP=${HW[0]}
ip link set "$AP" down; iw dev "$AP" set type __ap; ip link set "$AP" up; ip addr add 10.10.10.1/24 dev "$AP" 2>/dev/null
setsid "$B" --mode netlink --iface "$AP" --band 5 --channel 36 --width 80 --phy ax --ssid probe --psk password1234 </dev/null >/tmp/probe3_ap.log 2>&1 &
sleep 5
grep -aq "START_AP ok" /tmp/probe3_ap.log && APOK=yes || APOK=no
sc() { local d=$1 pfx=$2 s=0 i; for i in 1 2 3; do $pfx iw dev "$d" scan freq 5180 2>/dev/null | grep -aq "SSID: probe" && s=$((s+1)); done; echo "$s/3"; }
{
  echo "AP=$AP APOK=$APOK  (single-freq ch36 scans)"
  for STA in "${HW[@]:1}"; do
    ip link set "$STA" up 2>/dev/null
    root=$(sc "$STA" "")
    ns="ns_$STA"; ip netns add "$ns" 2>/dev/null
    iw phy "$(cat /sys/class/net/$STA/phy80211/name)" set netns name "$ns"
    ip netns exec "$ns" iw reg set US 2>/dev/null
    ip netns exec "$ns" ip link set "$STA" up 2>/dev/null; sleep 1
    net=$(sc "$STA" "ip netns exec $ns")
    echo "  $STA: root-ns=$root  netns=$net"
    ip netns del "$ns" 2>/dev/null
  done
} > "$R"
pkill -9 -f "[b]arely-ap --mode" 2>/dev/null
