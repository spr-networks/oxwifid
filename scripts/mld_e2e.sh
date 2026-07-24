#!/bin/bash
# MLD-AP e2e + feasibility probe. Brings up barely-ap as a 2-link cross-band MLD
# AP (ch1 2.4GHz + ch36 5GHz) on ONE hwsim wiphy, then points a wpa_supplicant
# MLD client at it. Reports each stage so the failure point (if any) is explicit.
# hwsim ONLY — never touches r_wlan1/rustap. Writes /tmp/mld_result.txt.
B=/tmp/iopbin/barely-ap; NS=mldcli; R=/tmp/mld_result.txt
FIREWALL_COMMENT="barely-mld-$$"
WPAS=${WPAS:?set WPAS to the wpa_supplicant binary}
WCLI=${WCLI:?set WCLI to the wpa_cli binary}
cleanup() {
  pkill -9 -f "[b]arely-ap --" 2>/dev/null
  ip netns del "$NS" 2>/dev/null
  handle=$(nft -a list chain inet filter INPUT 2>/dev/null |
    awk -v marker="$FIREWALL_COMMENT" '$0 ~ marker { for (i=1; i<=NF; i++) if ($i == "handle") print $(i+1) }' |
    head -1)
  [ -z "$handle" ] || nft delete rule inet filter INPUT handle "$handle" 2>/dev/null
}
trap cleanup EXIT
rm -f "$R"; : > "$R"
# Clean the hwsim medium the way hwsim_interop.sh does: kill EVERY consumer of
# the hwsim monitor (a leftover wlantest/wmediumd holds it open, rmmod fails, and
# the stale medium stops delivering frames), then retry rmmod until it succeeds.
pkill -9 -f "[b]arely-ap --" 2>/dev/null; pkill -9 wlantest 2>/dev/null; pkill -9 wmediumd 2>/dev/null
pkill -9 -x wpa_supplicant 2>/dev/null
for n in $NS; do ip netns del "$n" 2>/dev/null; done
sleep 2
for _ in 1 2 3 4 5; do rmmod mac80211_hwsim 2>/dev/null && break; sleep 2; done
sleep 1

# hwsim MLO capability: try the mlo param; report whether it exists.
echo "=== hwsim MLO support ===" >> "$R"
if modinfo mac80211_hwsim 2>/dev/null | grep -qiE "^parm: *mlo"; then
  echo "modinfo: mlo param present" >> "$R"; MLOPARAM="mlo=1"
else
  echo "modinfo: NO mlo param (kernel hwsim may still support MLO via multi-radio)" >> "$R"; MLOPARAM=""
fi
modprobe mac80211_hwsim $MLOPARAM radios=3 2>>"$R"; sleep 2
iw reg set US 2>/dev/null; sleep 1
mapfile -t HW < <(for n in $(ls /sys/class/net|grep ^wlan); do [ "$(basename "$(readlink /sys/class/net/$n/device/driver 2>/dev/null)")" = mac80211_hwsim ] && echo "$n"; done)
AP=${HW[0]}; STA=${HW[1]}; MON=${HW[2]}
nft insert rule inet filter INPUT iifname "$AP" ip daddr 10.10.10.1 \
  ip protocol icmp accept comment "$FIREWALL_COMMENT"
# Monitor on ch1 (link 0) to see whether the client's auth is on-air and whether
# the AP answers.
ip link set "$MON" down 2>/dev/null; iw dev "$MON" set type monitor 2>/dev/null; ip link set "$MON" up 2>/dev/null; iw dev "$MON" set channel 36 2>/dev/null
APHY=$(cat /sys/class/net/$AP/phy80211/name)
echo "AP=$AP ($APHY) STA=$STA" >> "$R"
echo "-- wiphy MLO/EHT indications --" >> "$R"
iw phy "$APHY" info 2>/dev/null | grep -iE "EHT|MLO|Multiple|number of.*links|VHT Capabilities|Band 1|Band 2" | head -8 >> "$R"

# barely-ap 2-link MLD config on the AP wiphy.
cat > /tmp/mld.json <<EOF
{ "ssid": "mld-test", "passphrase": "password1234", "key_mgmt": "sae",
  "phy": "be", "mode": "netlink", "iface": "$AP",
  "mld": true,
  "band": 2.4, "channel": 1, "width": 20, "link_id": 0,
  "mld_links": [
    { "link_id": 0, "mac": "02:00:00:00:aa:01", "band": 2.4, "channel": 1,  "width": 20 },
    { "link_id": 1, "mac": "02:00:00:00:aa:02", "band": 5, "channel": 36, "width": 80 } ] }
EOF
ip link set "$AP" down 2>/dev/null; iw dev "$AP" set type __ap 2>/dev/null; ip link set "$AP" up
ip addr add 10.10.10.1/24 dev "$AP" 2>/dev/null
RUSTAP_NL_DEBUG=1 setsid "$B" --config /tmp/mld.json </dev/null >/tmp/mld_ap.log 2>&1 &
sleep 5
echo "" >> "$R"; echo "=== barely-ap MLD bring-up ===" >> "$R"
grep -aiE "ADD_LINK|START_AP|error|fail|EOPNOTSUPP|EINVAL" /tmp/mld_ap.log | grep -av "MLD frame" | tail -12 >> "$R"

# If both links beacon, try a wpa_supplicant MLD client.
echo "" >> "$R"; echo "=== MLD client association ===" >> "$R"
ip netns add "$NS"; iw phy "$(cat /sys/class/net/$STA/phy80211/name)" set netns name "$NS"
ip netns exec "$NS" iw reg set US 2>/dev/null; ip netns exec "$NS" ip link set lo up; ip netns exec "$NS" ip link set "$STA" up; sleep 1
rm -f /tmp/mld_cli.log /tmp/mld_air.pcap
printf 'ctrl_interface=/run/wpa_m\nsae_pwe=2\nnetwork={\n ssid="mld-test"\n psk="password1234"\n key_mgmt=SAE\n ieee80211w=2\n freq_list=2412\n}\n' > /tmp/mldcli.conf
# Scan-gate (the key robustness from hwsim_interop.sh): the hwsim medium needs
# time to reliably deliver frames after START_AP, so wait until the STA's OWN
# scan actually sees the AP before launching wpa_supplicant. Without this the
# client scans a cold medium, finds nothing, and backs off into SCANNING.
seen=0
for _ in $(seq 1 15); do
  ip netns exec "$NS" iw dev "$STA" scan 2>/dev/null | grep -aq "SSID: mld-test" && { seen=1; break; }
  sleep 1
done
echo "scan-gate: STA sees AP=$seen" >> "$R"
timeout 22 tcpdump -i "$MON" -c 30 -e -w /tmp/mld_air.pcap 'type mgt' >/dev/null 2>&1 &
( ip netns exec "$NS" "$WPAS" -Dnl80211 -i"$STA" -c /tmp/mldcli.conf -dd -t >/tmp/mld_cli.log 2>&1 & )
for k in $(seq 1 30); do sleep 1
  st=$(ip netns exec "$NS" "$WCLI" -p /run/wpa_m -i"$STA" status 2>/dev/null | sed -n 's/^wpa_state=//p')
  [ "$st" = COMPLETED ] && break
  # Only rescan while genuinely idle (SCANNING/DISCONNECTED) — never poke the
  # client mid-auth/handshake, which would restart SAE and loop.
  if { [ "$st" = SCANNING ] || [ "$st" = DISCONNECTED ] || [ -z "$st" ]; } && [ $((k % 4)) -eq 0 ]; then
    ip netns exec "$NS" "$WCLI" -p /run/wpa_m -i"$STA" scan >/dev/null 2>&1
  fi
done
echo "client wpa_state: ${st:-none}" >> "$R"
# Data plane: give the client an IP and ping the AP over the MLD link.
if [ "$st" = COMPLETED ]; then
  ip netns exec "$NS" ip addr add 10.10.10.2/24 dev "$STA" 2>/dev/null
  sleep 1
  data=$(ip netns exec "$NS" ping -c 3 -W 2 10.10.10.1 2>/dev/null | grep -oE "[0-9]+ received" | head -1)
  echo "DATA ping 10.10.10.1: ${data:-0 received}" >> "$R"
  echo "client valid_links: $(ip netns exec "$NS" "$WCLI" -p /run/wpa_m -i"$STA" status 2>/dev/null | grep -aiE 'valid_links|link_id')" >> "$R"
fi
echo "-- client scan_results (does it see mld-test on ch1/ch36?) --" >> "$R"
ip netns exec "$NS" "$WCLI" -p /run/wpa_m -i"$STA" scan_results 2>/dev/null | head -8 >> "$R"
echo "-- client status --" >> "$R"
ip netns exec "$NS" "$WCLI" -p /run/wpa_m -i"$STA" status 2>/dev/null | grep -iE "valid_links|link_id|mld|freq|wpa_state|bssid|ssid" | head >> "$R"
echo "-- client debug log (selection/assoc/mld) --" >> "$R"
grep -aiE "selecting|select_bss|skip|mismatch|MLD|valid_links|link|associat|authent|SAE|reject|fail|denied|no suitable|candidate|EAPOL|4-Way|PTK|GTK|malformed" /tmp/mld_cli.log 2>/dev/null | tail -30 >> "$R"
echo "-- full barely-ap log (bssid, CTRL_PORT, m2 PTK, keys) --" >> "$R"
grep -av "MLD frame head" /tmp/mld_ap.log 2>/dev/null | tail -30 >> "$R"
echo "-- AP interface addr --" >> "$R"
ip link show "$AP" 2>/dev/null | grep -oE "link/ether [0-9a-f:]+" >> "$R"
echo "-- on-air auth/assoc frames on ch1 (src->dst subtype) --" >> "$R"
tcpdump -r /tmp/mld_air.pcap -e -n 2>/dev/null | sed -E 's/.*(SA:[^ ]+).*(DA:[^ ]+).*(Authentication|Assoc).*/\1 \2 \3/' | sort | uniq -c | head >> "$R"
tcpdump -r /tmp/mld_air.pcap -e -n 2>/dev/null | grep -aiE "auth|assoc" | head -6 >> "$R"
echo "DONE" >> "$R"
