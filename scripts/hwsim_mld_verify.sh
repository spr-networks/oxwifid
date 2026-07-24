#!/bin/bash
# hwsim_mld_verify.sh — verify barely-cli's MLD data-plane fix against a real
# a two-link reference MLD AP over mac80211_hwsim: one MLO radio, global control,
# two ADD <ifname> config= calls (link0 ch1 / link1 ch6 = one MLD AP), SAE+PMF.
#
# PASS = barely-cli prints PING_REPLY_OK and the reference AP stops logging
# "not associated STA". Run on the hwsim box. hwsim radios only.
set -u
REFERENCE_AP=${REFERENCE_AP:?set REFERENCE_AP to the reference AP binary}
REFERENCE_AP_CLI=${REFERENCE_AP_CLI:?set REFERENCE_AP_CLI to its control client}
CLI=${CLI:-/tmp/barely-cli}
CLIENT_CONFIG=${CLIENT_CONFIG:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tests/interop-config.json}
G=/var/run/reference-ap-mldg
W=/tmp/mldv
SSID=mldverify
PSK=password1234
# client MLD addressing (from the verified interop run)
C_L0=02:00:00:00:04:00; C_MLD=02:00:00:00:0a:00; C_L1=02:00:00:00:0b:00

cleanup() {
    sudo pkill -9 -f "$REFERENCE_AP .*$G" 2>/dev/null
    sudo pkill -9 -f "[b]arely-cli" 2>/dev/null
    sudo rm -rf "$W" 2>/dev/null
}
trap cleanup EXIT
sudo rm -rf "$W"; mkdir -p "$W"

# MLO-capable hwsim radios.
sudo rmmod mac80211_hwsim 2>/dev/null
sudo modprobe mac80211_hwsim mlo=1 radios=4
sleep 1
mapfile -t HW < <(for d in /sys/class/net/*/phy80211; do n=$(basename "$(dirname "$d")"); [ "$(basename "$(readlink "/sys/class/net/$n/device/driver" 2>/dev/null)" 2>/dev/null)" = mac80211_hwsim ] && echo "$n"; done)
AP_IF=${HW[0]}; CLI_IF=${HW[1]}
AP_PHY=$(cat /sys/class/net/$AP_IF/phy80211/name)
echo "# AP_IF=$AP_IF CLI_IF=$CLI_IF"

# Link configs: identical bar the channel; group_mgmt_cipher matches barely-cli's
# MLD RSN (BIP-GMAC-256). hw_mode=g => 2.4GHz; ch1 link0, ch6 link1.
mk() { cat > "$W/link$1.conf" <<EOF
interface=$AP_IF
ctrl_interface=$W/ctrl
ssid=$SSID
country_code=US
hw_mode=g
channel=$2
ieee80211n=1
ieee80211ax=1
ieee80211be=1
wpa=2
wpa_key_mgmt=SAE
rsn_pairwise=CCMP
sae_password=$PSK
ieee80211w=2
group_mgmt_cipher=BIP-GMAC-256
beacon_prot=1
sae_pwe=1
EOF
}
mk 0 1; mk 1 6

sudo "$REFERENCE_AP" -g "$G" -B -t -f "$W/ref_ap.log"
sleep 1
echo "# ADD link0"; sudo "$REFERENCE_AP_CLI" -g "$G" raw ADD "$AP_IF" config="$W/link0.conf"
sleep 1
echo "# ADD link1"; sudo "$REFERENCE_AP_CLI" -g "$G" raw ADD "$AP_IF" config="$W/link1.conf"
sleep 2

# AP MLD + link0 addresses, for barely-cli.
AP_MLD=$(sudo "$REFERENCE_AP_CLI" -p "$W/ctrl" -i "$AP_IF" status 2>/dev/null | sed -n 's/^mld_addr=//p' | head -1)
AP_L0=$(sudo "$REFERENCE_AP_CLI" -p "$W/ctrl" -i "$AP_IF" status 2>/dev/null | sed -n 's/^link_addr\[0\]=//p; s/^link_addr=//p' | head -1)
[ -z "$AP_L0" ] && AP_L0=$(cat /sys/class/net/$AP_IF/address)
echo "# AP_MLD=$AP_MLD AP_L0=$AP_L0"
sudo ip addr add 10.10.10.1/24 dev "$AP_IF" 2>/dev/null

# Client radio -> monitor on ch1 (link0).
sudo ip link set "$CLI_IF" down
sudo iw dev "$CLI_IF" set type monitor 2>/dev/null
sudo ip link set "$CLI_IF" up
sudo iw dev "$CLI_IF" set channel 1 2>/dev/null

[ -z "$AP_MLD" ] && { echo "FAIL: could not read AP mld_addr (AP may not have come up — see $W/ref_ap.log)"; sudo tail -5 "$W/ref_ap.log"; exit 1; }

echo "# running barely-cli MLD client (ping)…"
sudo timeout 30 "$CLI" --config "$CLIENT_CONFIG" --mode iface --iface "$CLI_IF" --channel 1 \
    --ssid "$SSID" --sae \
    --mac "$C_L0" --mld-mac "$C_MLD" --link1-mac "$C_L1" --ap-mld-mac "$AP_MLD" \
    --gw-ip 10.10.10.1 --src-ip 10.10.10.2 --gw-mac "$AP_L0" --ping 2>&1 | tee "$W/cli.log"

echo "=== VERDICT ==="
grep -aq PING_REPLY_OK "$W/cli.log" && echo "PASS: PING_REPLY_OK" || echo "NO PING_REPLY_OK"
echo "--- reference AP 'not associated' (should be empty after fix) ---"
sudo grep -a "not associated" "$W/ref_ap.log" | tail -3 || echo "(none)"
