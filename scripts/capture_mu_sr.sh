#!/bin/bash
# Capture the exact MU-EDCA (ext 38) + Spatial Reuse (ext 39) element bytes from
# a reference HE AP explicitly configured to emit them. Writes /tmp/musr_result.txt.
REFERENCE_AP=${REFERENCE_AP:?set REFERENCE_AP to the reference AP binary}
REFERENCE_AP_PROCESS=$(basename "$REFERENCE_AP")
R=/tmp/musr_result.txt
rm -f "$R" /tmp/hm.pcap; : > "$R"
pkill -9 wlantest 2>/dev/null; pkill -9 -x "$REFERENCE_AP_PROCESS" 2>/dev/null; pkill -9 -f "[b]arely-ap --mode" 2>/dev/null
sleep 1; modprobe -r mac80211_hwsim 2>/dev/null; sleep 1; modprobe mac80211_hwsim rctbl=1 radios=4; sleep 2
iw reg set US 2>/dev/null; sleep 1
mapfile -t HW < <(for n in $(ls /sys/class/net|grep ^wlan); do [ "$(basename "$(readlink /sys/class/net/$n/device/driver 2>/dev/null)")" = mac80211_hwsim ] && echo "$n"; done)
AP=${HW[0]}; MON=${HW[1]}
ip link set "$MON" down; iw dev "$MON" set type monitor; ip link set "$MON" up; iw dev "$MON" set channel 36 2>/dev/null

cat > /tmp/dump.py <<'PY'
import sys, struct
want=set(int(x) for x in sys.argv[2:])
data=open(sys.argv[1],'rb').read(); o=24
def parse(pkt):
    rtl=struct.unpack_from('<H',pkt,2)[0]; o=rtl
    if pkt[o]!=0x80: return
    o+=24+12
    while o+2<=len(pkt):
        eid=pkt[o]; ln=pkt[o+1]; d=pkt[o+2:o+2+ln]
        if eid==255 and d and d[0] in want:
            print("ext %d (len=%d): %s" % (d[0], ln, pkt[o:o+2+ln].hex()))
        o+=2+ln
seen=0
while o+16<=len(data) and seen<1:
    il=struct.unpack_from('<I',data,o+8)[0]; o+=16
    try:
        if data[o+struct.unpack_from('<H',data,o+2)[0]]==0x80:
            parse(data[o:o+il]); seen=1
    except Exception: pass
    o+=il
PY

cat > /tmp/hm.conf <<EOF
interface=$AP
ssid=hm
country_code=US
hw_mode=a
channel=36
ieee80211n=1
ieee80211ax=1
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_passphrase=password1234
rsn_pairwise=CCMP
he_mu_edca_qos_info_param_count=0
he_mu_edca_qos_info_q_ack=0
he_mu_edca_qos_info_queue_request=1
he_mu_edca_qos_info_txop_request=0
he_mu_edca_ac_be_aifsn=8
he_mu_edca_ac_be_aci=0
he_mu_edca_ac_be_ecwmin=9
he_mu_edca_ac_be_ecwmax=10
he_mu_edca_ac_be_timer=255
he_mu_edca_ac_bk_aifsn=15
he_mu_edca_ac_bk_aci=1
he_mu_edca_ac_bk_ecwmin=9
he_mu_edca_ac_bk_ecwmax=10
he_mu_edca_ac_bk_timer=255
he_mu_edca_ac_vi_aifsn=5
he_mu_edca_ac_vi_aci=2
he_mu_edca_ac_vi_ecwmin=5
he_mu_edca_ac_vi_ecwmax=7
he_mu_edca_ac_vi_timer=255
he_mu_edca_ac_vo_aifsn=5
he_mu_edca_ac_vo_aci=3
he_mu_edca_ac_vo_ecwmin=5
he_mu_edca_ac_vo_ecwmax=7
he_mu_edca_ac_vo_timer=255
he_bss_color=42
he_spr_sr_control=3
he_spr_non_srg_obss_pd_max_offset=20
EOF
setsid "$REFERENCE_AP" -B /tmp/hm.conf >/tmp/hm.log 2>&1; sleep 3
echo "reference AP up: $(grep -c "AP-ENABLED" /tmp/hm.log)" >> "$R"
grep -aiE "Invalid|unknown configuration|line " /tmp/hm.log | tail -3 >> "$R"
timeout 4 tcpdump -i "$MON" -c 4 -w /tmp/hm.pcap 'type mgt subtype beacon' >/dev/null 2>&1
echo "=== MU-EDCA (38) + Spatial Reuse (39) element bytes ===" >> "$R"
python3 /tmp/dump.py /tmp/hm.pcap 38 39 >> "$R" 2>>"$R"
echo "DONE" >> "$R"
pkill -9 -x "$REFERENCE_AP_PROCESS" 2>/dev/null
