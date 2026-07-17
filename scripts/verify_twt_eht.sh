#!/bin/bash
# Verify on-wire: (1) barely-ap HE caps advertise TWT Responder (MAC byte0 bit2),
# (2) an EHT (--phy be) beacon with punct_bitmap carries the puncturing bit +
# bitmap in EHT Operation (ext 106). Writes /tmp/twteht_result.txt.
B=/tmp/iopbin/barely-ap; R=/tmp/twteht_result.txt
rm -f "$R" /tmp/te.pcap; : > "$R"
pkill -9 wlantest 2>/dev/null; pkill -9 -f "hostap-hwsim" 2>/dev/null; pkill -9 -f "[b]arely-ap --mode" 2>/dev/null
sleep 1; modprobe -r mac80211_hwsim 2>/dev/null; sleep 1; modprobe mac80211_hwsim rctbl=1 radios=4; sleep 2
iw reg set US 2>/dev/null; sleep 1
mapfile -t HW < <(for n in $(ls /sys/class/net|grep ^wlan); do [ "$(basename "$(readlink /sys/class/net/$n/device/driver 2>/dev/null)")" = mac80211_hwsim ] && echo "$n"; done)
AP=${HW[0]}; MON=${HW[1]}
ip link set "$MON" down; iw dev "$MON" set type monitor; ip link set "$MON" up; iw dev "$MON" set channel 36 2>/dev/null

cat > /tmp/dump.py <<'PY'
import sys, struct
want=set(int(x) for x in sys.argv[2:])
data=open(sys.argv[1],'rb').read(); o=24
def show(pkt):
    rtl=struct.unpack_from('<H',pkt,2)[0]; o=rtl
    if pkt[o]!=0x80: return False
    o+=24+12
    while o+2<=len(pkt):
        eid=pkt[o]; ln=pkt[o+1]; d=pkt[o+2:o+2+ln]
        if eid==255 and d and d[0] in want:
            print("ext %d: %s" % (d[0], pkt[o:o+2+ln].hex()))
        o+=2+ln
    return True
seen=0
while o+16<=len(data) and not seen:
    il=struct.unpack_from('<I',data,o+8)[0]; o+=16
    try: seen=show(data[o:o+il])
    except Exception: pass
    o+=il
PY

# EHT (--phy be) 80 MHz with the 3rd 20 MHz subchannel punctured (bitmap 0x0004)
cat > /tmp/te.json <<EOF
{ "ssid": "te", "passphrase": "password1234", "key_mgmt": "sae",
  "channel": 36, "width": 80, "phy": "be", "mode": "netlink",
  "iface": "$AP", "punct_bitmap": 4 }
EOF
ip link set "$AP" down; iw dev "$AP" set type __ap; ip link set "$AP" up; ip addr add 10.10.10.1/24 dev "$AP" 2>/dev/null
setsid "$B" --config /tmp/te.json </dev/null >/tmp/te.log 2>&1 &
sleep 4
grep -aq "START_AP ok" /tmp/te.log && echo "AP: START_AP ok" >> "$R" || echo "AP FAILED: $(tail -1 /tmp/te.log)" >> "$R"
timeout 4 tcpdump -i "$MON" -c 4 -w /tmp/te.pcap 'type mgt subtype beacon' >/dev/null 2>&1
echo "=== HE caps (ext 35, byte after '23' = MAC byte0; bit2=TWT) + EHT op (ext 106) ===" >> "$R"
python3 /tmp/dump.py /tmp/te.pcap 35 106 >> "$R" 2>>"$R"
echo "DONE" >> "$R"
pkill -9 -f "[b]arely-ap --mode" 2>/dev/null
