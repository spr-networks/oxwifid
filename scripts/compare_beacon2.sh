#!/bin/bash
# Definitive HE/EHT beacon element diff: capture raw beacons from hostapd v2.12
# and barely-ap on the same hwsim radio, parse the element IDs (and ext-IDs for
# element 255) directly. Writes /tmp/cmp2_result.txt.
HAPD=/home/ubuntu/hostap-hwsim/hostapd/hostapd
B=/tmp/iopbin/barely-ap; R=/tmp/cmp2_result.txt
rm -f "$R" /tmp/h.pcap /tmp/b.pcap; : > "$R"
pkill -9 wlantest 2>/dev/null; pkill -9 wmediumd 2>/dev/null
pkill -9 -f "hostap-hwsim" 2>/dev/null; pkill -9 -f "[b]arely-ap --mode" 2>/dev/null; pkill -9 -x hostapd 2>/dev/null
sleep 1; modprobe -r mac80211_hwsim 2>/dev/null; sleep 1; modprobe mac80211_hwsim rctbl=1 radios=4; sleep 2
iw reg set US 2>/dev/null; sleep 1
mapfile -t HW < <(for n in $(ls /sys/class/net|grep ^wlan); do [ "$(basename "$(readlink /sys/class/net/$n/device/driver 2>/dev/null)")" = mac80211_hwsim ] && echo "$n"; done)
AP=${HW[0]}; MON=${HW[1]}
# monitor on ch36 to sniff beacons
ip link set "$MON" down; iw dev "$MON" set type monitor; ip link set "$MON" up; iw dev "$MON" set channel 36 2>/dev/null

cat > /tmp/parse.py <<'PY'
import sys, struct
def elems(pkt):
    # radiotap len at bytes 2-3 (le); 802.11 beacon fixed hdr = 24 + 12
    rtl = struct.unpack_from('<H', pkt, 2)[0]
    o = rtl
    if pkt[o] != 0x80: return None  # not a beacon
    o += 24 + 12
    ssid=None; ids=[]
    while o+2 <= len(pkt):
        eid=pkt[o]; ln=pkt[o+1]; d=pkt[o+2:o+2+ln]
        if eid==0: ssid=d.decode('latin1','replace')
        ids.append('255/%d'%d[0] if (eid==255 and d) else str(eid))
        o += 2+ln
    return ssid, ids
def pcap(path):
    data=open(path,'rb').read()
    o=24; seen={}
    while o+16<=len(data):
        il=struct.unpack_from('<I',data,o+8)[0]; o+=16
        pkt=data[o:o+il]; o+=il
        try:
            r=elems(pkt)
        except Exception: r=None
        if r and r[0] and r[0] not in seen: seen[r[0]]=r[1]
    return seen
for name,path in [('hostapd',sys.argv[1]),('barely-ap',sys.argv[2])]:
    for ssid,ids in pcap(path).items():
        print('%s ssid=%s: %s'%(name, ssid, ' '.join(ids)))
PY

# hostapd HE
cat > /tmp/hapd_he.conf <<EOF
interface=$AP
ssid=hapd-he
country_code=US
hw_mode=a
channel=36
ieee80211n=1
ieee80211ax=1
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_passphrase=password1234
rsn_pairwise=CCMP
EOF
setsid "$HAPD" -B /tmp/hapd_he.conf >/tmp/hapd.log 2>&1; sleep 3
timeout 4 tcpdump -i "$MON" -c 4 -w /tmp/h.pcap 'type mgt subtype beacon' >/dev/null 2>&1
echo "hostapd start: $(grep -c "Setup of interface done\|AP-ENABLED" /tmp/hapd.log)" >> "$R"
pkill -9 -x hostapd 2>/dev/null; sleep 2

# barely-ap HE
ip link set "$AP" down 2>/dev/null; iw dev "$AP" set type __ap 2>/dev/null; ip link set "$AP" up
ip addr add 10.10.10.1/24 dev "$AP" 2>/dev/null
setsid "$B" --mode netlink --iface "$AP" --band 5 --channel 36 --width 80 --phy ax --ssid barely-he --psk password1234 </dev/null >/tmp/bap.log 2>&1 &
sleep 4
timeout 4 tcpdump -i "$MON" -c 4 -w /tmp/b.pcap 'type mgt subtype beacon' >/dev/null 2>&1
echo "" >> "$R"; echo "=== element IDs (255/N = ext element N) ===" >> "$R"
python3 /tmp/parse.py /tmp/h.pcap /tmp/b.pcap >> "$R" 2>>"$R"
echo "DONE" >> "$R"
pkill -9 -f "[b]arely-ap --mode" 2>/dev/null
