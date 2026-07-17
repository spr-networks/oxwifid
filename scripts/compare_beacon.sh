#!/bin/bash
# Compare the HE/EHT beacon elements hostapd v2.12 advertises vs barely-ap, on
# the same hwsim radio. Scans from a station radio and greps the HE/EHT lines.
# Writes /tmp/cmp_result.txt.  Run: sudo setsid bash compare_beacon.sh &
HAPD=/home/ubuntu/hostap-hwsim/hostapd/hostapd
B=/tmp/iopbin/barely-ap; R=/tmp/cmp_result.txt
rm -f "$R"; : > "$R"
pkill -9 wlantest 2>/dev/null; pkill -9 wmediumd 2>/dev/null
pkill -9 -f "hostap-hwsim" 2>/dev/null; pkill -9 -f "[b]arely-ap --mode" 2>/dev/null; pkill -9 -x hostapd 2>/dev/null
sleep 1; modprobe -r mac80211_hwsim 2>/dev/null; sleep 1; modprobe mac80211_hwsim rctbl=1 radios=4; sleep 2
iw reg set US 2>/dev/null; sleep 1
mapfile -t HW < <(for n in $(ls /sys/class/net|grep ^wlan); do [ "$(basename "$(readlink /sys/class/net/$n/device/driver 2>/dev/null)")" = mac80211_hwsim ] && echo "$n"; done)
AP=${HW[0]}; SCAN=${HW[1]}
ip link set "$SCAN" up 2>/dev/null

grab() { # $1 ssid -> HE/EHT-relevant beacon lines
  sleep 1
  iw dev "$SCAN" scan 2>/dev/null \
    | grep -aiE "HE capab|HE Operation|MU EDCA|MU-EDCA|Spatial Reuse|TWT|EHT|6 GHz|punctur|BSS coloring|RSNX" \
    | sed 's/^[[:space:]]*/    /' | sort -u
}

# --- hostapd (HE) ---
cat > /tmp/hapd_he.conf <<EOF
interface=$AP
ssid=hapd-he
country_code=US
hw_mode=a
channel=36
ieee80211n=1
ieee80211ac=1
ieee80211ax=1
vht_oper_chwidth=1
he_oper_chwidth=1
vht_oper_centr_freq_seg0_idx=42
he_oper_centr_freq_seg0_idx=42
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_passphrase=password1234
rsn_pairwise=CCMP
EOF
ip link set "$AP" down 2>/dev/null; iw dev "$AP" set type managed 2>/dev/null; ip link set "$AP" up
setsid "$HAPD" -B /tmp/hapd_he.conf >/tmp/hapd.log 2>&1; sleep 3
echo "=== hostapd v2.12 (ieee80211ax) HE beacon elements ===" >> "$R"
grab hapd-he >> "$R"
pkill -9 -x hostapd 2>/dev/null; sleep 2

# --- barely-ap (--phy ax) ---
ip link set "$AP" down 2>/dev/null; iw dev "$AP" set type __ap 2>/dev/null; ip link set "$AP" up
ip addr add 10.10.10.1/24 dev "$AP" 2>/dev/null
setsid "$B" --mode netlink --iface "$AP" --channel 36 --width 80 --phy ax --ssid barely-he --psk password1234 </dev/null >/tmp/bap.log 2>&1 &
sleep 4
echo "" >> "$R"; echo "=== barely-ap (--phy ax) HE beacon elements ===" >> "$R"
grab barely-he >> "$R"
echo "DONE" >> "$R"
pkill -9 -f "[b]arely-ap --mode" 2>/dev/null
