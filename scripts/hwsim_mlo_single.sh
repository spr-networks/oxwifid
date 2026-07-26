#!/bin/bash
# Single-interface MLD AP cell: barely-ap as a 2-link cross-band MLD
# (ch1/2.4GHz + ch36/5GHz) on ONE hwsim wiphy, wpa_supplicant MLD client on a
# second, plus an independent legacy WPA2 client on a third radio.
# Non-destructive twin of mld_e2e.sh for shared hosts: it never
# touches the mac80211_hwsim module — pin it to radios created with
# tools/hwsim/hwsim_add_radio.py --mlo via
# HWSIM_IFACES="AP MLD_STA LEGACY_STA".
#
# PASS = an SAE MLD client completes with both links valid, its per-station
# AP_VLAN carries IP traffic in both directions, then a legacy WPA2-only client
# completes against the same transition-mode AP.

set -u

if [ "$EUID" -ne 0 ]; then
    exec sudo -n env WPAS="${WPAS:-}" WCLI="${WCLI:-}" \
        HWSIM_IFACES="${HWSIM_IFACES:-}" RUN_LOG_DIR="${RUN_LOG_DIR:-}" \
        bash "$0" "$@"
fi

BINDIR=${1:?usage: hwsim_mlo_single.sh BINS_DIR}
AP_BIN="$BINDIR/barely-ap"
WPAS=${WPAS:?set WPAS to the wpa_supplicant binary}
WCLI=${WCLI:?set WCLI to the wpa_cli binary}
HWSIM_IFACES=${HWSIM_IFACES:?set HWSIM_IFACES="AP_IFACE MLD_STA_IFACE LEGACY_STA_IFACE" (MLO-capable hwsim radios)}
WORK=${RUN_LOG_DIR:-"/tmp/barely-hwsim-mlo-$$"}
NS="rustap-mlo-$$"
FIREWALL_COMMENT="barely-mlo-vlan-$$"
AP_PID=
STA_PID_FILE=
LEGACY_PID_FILE=

read -r AP STA LEGACY_STA <<<"$HWSIM_IFACES"
[ -n "${LEGACY_STA:-}" ] ||
    { echo "HWSIM_IFACES needs three interface names: AP MLD_STA LEGACY_STA" >&2; exit 2; }
[ -x "$AP_BIN" ] || { echo "missing barely-ap: $AP_BIN" >&2; exit 2; }

mkdir -p "$WORK/control_$AP"
AP_LOG="$WORK/ap.log"

cleanup() {
    if [ -n "$AP_PID" ]; then
        kill "$AP_PID" 2>/dev/null || true
        wait "$AP_PID" 2>/dev/null || true
    fi
    if [ -n "$STA_PID_FILE" ] && [ -s "$STA_PID_FILE" ]; then
        kill "$(cat "$STA_PID_FILE")" 2>/dev/null || true
    fi
    if [ -n "$LEGACY_PID_FILE" ] && [ -s "$LEGACY_PID_FILE" ]; then
        kill "$(cat "$LEGACY_PID_FILE")" 2>/dev/null || true
    fi
    ip netns del "$NS" 2>/dev/null || true
    handle=$(nft -a list chain inet filter INPUT 2>/dev/null |
        awk -v marker="$FIREWALL_COMMENT" '$0 ~ marker { for (i=1; i<=NF; i++) if ($i == "handle") print $(i+1) }' |
        head -1)
    [ -z "${handle:-}" ] ||
        nft delete rule inet filter INPUT handle "$handle" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

rfkill unblock all 2>/dev/null || true

MAC=$(cat "/sys/class/net/$AP/address")
STA_PHY=$(basename "$(readlink -f "/sys/class/net/$STA/phy80211")")
LEGACY_PHY=$(basename "$(readlink -f "/sys/class/net/$LEGACY_STA/phy80211")")

cat >"$WORK/ap.json" <<EOF
{
  "ssid": "rustap-mlo",
  "passphrase": "password1234",
  "country": "US",
  "mode": "netlink",
  "key_mgmt": "sae-transition",
  "ocv": false,
  "per_sta_vif": true,
  "spr_dhcp_helper": null,
  "radios": [
    {
      "iface": "$AP",
      "band": 2.4,
      "channel": 1,
      "width": 20,
      "phy": "be",
      "mld": true,
      "link_id": 0,
      "ctrl_path": "$WORK/control_$AP/$AP",
      "mld_links": [
        { "link_id": 0, "band": 2.4, "channel": 1,  "width": 20 },
        { "link_id": 1, "band": 5,   "channel": 36, "width": 80 }
      ]
    }
  ]
}
EOF

ip link set "$AP" down 2>/dev/null || true
iw dev "$AP" set type __ap 2>/dev/null || true
ip link set "$AP" up

"$AP_BIN" --config "$WORK/ap.json" >"$AP_LOG" 2>&1 &
AP_PID=$!

for _ in $(seq 1 100); do
    grep -q 'START_AP.*ok' "$AP_LOG" 2>/dev/null && break
    kill -0 "$AP_PID" 2>/dev/null || {
        echo "MLD AP exited during startup" >&2
        tail -60 "$AP_LOG" >&2
        exit 1
    }
    sleep 0.1
done
grep -q 'START_AP.*ok' "$AP_LOG" 2>/dev/null || {
    echo "MLD AP did not reach START_AP" >&2
    tail -60 "$AP_LOG" >&2
    exit 1
}

# With no configured MLD or link addresses, match the reference AP: the netdev
# hardware address is the MLD address and every link keeps its first three
# octets, randomizes the final three, and forces local+unicast.
L0_MAC=$(sed -n 's/.*ADD_LINK link_id=0 mac=\([^ ]*\) ok.*/\1/p' "$AP_LOG" | tail -1)
L1_MAC=$(sed -n 's/.*ADD_LINK link_id=1 mac=\([^ ]*\) ok.*/\1/p' "$AP_LOG" | tail -1)
IFS=: read -r M0 M1 M2 _ <<<"$MAC"
printf -v LOCAL_FIRST '%02x' "$(( (16#$M0 & 0xfe) | 0x02 ))"
LINK_PREFIX="$LOCAL_FIRST:$M1:$M2:"
case "$L0_MAC" in
    "$LINK_PREFIX"*) ;;
    *) echo "link 0 MAC $L0_MAC does not retain MLD OUI $LINK_PREFIX" >&2; exit 1 ;;
esac
case "$L1_MAC" in
    "$LINK_PREFIX"*) ;;
    *) echo "link 1 MAC $L1_MAC does not retain MLD OUI $LINK_PREFIX" >&2; exit 1 ;;
esac
[ "$L0_MAC" != "$L1_MAC" ] ||
    { echo "MLD links received duplicate MAC $L0_MAC" >&2; exit 1; }
[ "$L0_MAC" != "$MAC" ] && [ "$L1_MAC" != "$MAC" ] ||
    { echo "an MLD link reused the MLD address $MAC" >&2; exit 1; }
echo "MLD address=$MAC randomized link0=$L0_MAC link1=$L1_MAC"

ip netns add "$NS"
iw phy "$STA_PHY" set netns name "$NS"
iw phy "$LEGACY_PHY" set netns name "$NS"
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip link set "$STA" up
ip netns exec "$NS" ip link set "$LEGACY_STA" up
ip netns exec "$NS" iw reg set US 2>/dev/null || true

cat >"$WORK/sta-sae.conf" <<EOF
ctrl_interface=$WORK/ctrl-sta-sae
p2p_disabled=1
sae_pwe=1
network={
  ssid="rustap-mlo"
  psk="password1234"
  key_mgmt=SAE
  ieee80211w=2
  scan_freq=2412 5180
}
EOF

# Scan-gate: wait for the STA's own scan to see the AP before launching
# wpa_supplicant, so it doesn't back off on a cold hwsim medium.
seen=0
for _ in $(seq 1 15); do
    ip netns exec "$NS" iw dev "$STA" scan 2>/dev/null | grep -q "SSID: rustap-mlo" && { seen=1; break; }
    sleep 1
done
[ "$seen" = 1 ] || echo "warning: scan-gate never saw the AP; continuing" >&2

STA_PID_FILE="$WORK/sta.pid"
ip netns exec "$NS" "$WPAS" -B -P "$STA_PID_FILE" -Dnl80211 -i"$STA" -c "$WORK/sta-sae.conf"

STATE=
for k in $(seq 1 40); do
    STATE=$(ip netns exec "$NS" "$WCLI" -p "$WORK/ctrl-sta-sae" -i"$STA" status 2>/dev/null |
        sed -n 's/^wpa_state=//p')
    [ "$STATE" = COMPLETED ] && break
    if { [ "$STATE" = SCANNING ] || [ "$STATE" = DISCONNECTED ] || [ -z "$STATE" ]; } &&
        [ $((k % 4)) -eq 0 ]; then
        ip netns exec "$NS" "$WCLI" -p "$WORK/ctrl-sta-sae" -i"$STA" scan >/dev/null 2>&1
    fi
    sleep 1
done

STATUS=$(ip netns exec "$NS" "$WCLI" -p "$WORK/ctrl-sta-sae" -i"$STA" status 2>/dev/null)
if [ "${STATE:-}" != COMPLETED ]; then
    echo "MLD association failed: wpa_state=${STATE:-unknown}" >&2
    echo "$STATUS" >&2
    tail -80 "$AP_LOG" >&2
    exit 1
fi

echo "$STATUS" | grep -iE "valid_links|mld_addr|ap_mld_addr|link_id|freq" || true
MLO=$(ip netns exec "$NS" "$WCLI" -p "$WORK/ctrl-sta-sae" -i"$STA" mlo_status 2>/dev/null)
[ -z "$MLO" ] || { echo "-- mlo_status --"; echo "$MLO"; }
VALID=$(echo "$STATUS" | sed -n 's/^valid_links=//p')
# Older status formats omit valid_links; fall back to counting mlo_status links.
if [ -z "$VALID" ] && [ -n "$MLO" ]; then
    links=$(echo "$MLO" | grep -c "^link_id=")
    [ "$links" -ge 2 ] && VALID=3
fi
if [ -n "$VALID" ]; then
    # valid_links is a bitmask: links 0+1 => 0x3.
    case "$VALID" in
    3 | 0x3 | 0x0003) echo "PASS: MLD COMPLETED on $AP with both links valid (valid_links=$VALID)" ;;
    *)
        echo "PARTIAL: COMPLETED but valid_links=$VALID (expected 3)" >&2
        exit 1
        ;;
    esac
else
    echo "PARTIAL: COMPLETED but the client reports no valid_links (non-MLO association?)" >&2
    exit 1
fi

# The AP must attach the private AP_VLAN to both negotiated MLO links. A
# handshake-only check missed the old bug: uplink could appear on one path while
# downlink/group traffic used the unbound partner link.
MLD_VIF=
for _ in $(seq 1 20); do
    MLD_VIF=$(sed -n 's/.*station .* -> \([^ ]*\) (vlan_id.*/\1/p' "$AP_LOG" | head -1)
    [ -n "$MLD_VIF" ] && [ -e "/sys/class/net/$MLD_VIF" ] && break
    sleep 0.1
done
[ -n "$MLD_VIF" ] && [ -e "/sys/class/net/$MLD_VIF" ] || {
    echo "MLD per-station AP_VLAN was not created" >&2
    tail -100 "$AP_LOG" >&2
    exit 1
}
grep -q 'links=\[Some(0), Some(1)\]' "$AP_LOG" || {
    echo "MLD AP_VLAN was not bound to both negotiated links" >&2
    tail -100 "$AP_LOG" >&2
    exit 1
}
STA_DATA_MAC=$(ip netns exec "$NS" cat "/sys/class/net/$STA/address")
iw dev "$MLD_VIF" station dump 2>/dev/null |
    grep -qi "^Station $STA_DATA_MAC " || {
    echo "kernel did not move MLD station $STA_DATA_MAC onto $MLD_VIF" >&2
    iw dev "$AP" station dump >&2 || true
    iw dev "$MLD_VIF" station dump >&2 || true
    exit 1
}
if [ -n "${RUSTAP_MLO_DEBUG_PAUSE:-}" ]; then
    echo "debug pause: AP_VLAN=$MLD_VIF"
    sleep "$RUSTAP_MLO_DEBUG_PAUSE"
fi

# The shared hwsim host may have a default-drop INPUT policy. Add one
# process-scoped ICMP exception and remove it by comment in cleanup.
nft insert rule inet filter INPUT iifname "$MLD_VIF" ip protocol icmp \
    accept comment "$FIREWALL_COMMENT" 2>/dev/null || true
ip addr flush dev "$MLD_VIF" 2>/dev/null || true
ip addr add 10.203.0.1/24 dev "$MLD_VIF"
ip netns exec "$NS" ip addr flush dev "$STA" 2>/dev/null || true
ip netns exec "$NS" ip addr add 10.203.0.2/24 dev "$STA"
# mac80211_hwsim currently delivers an MLD station's L2 broadcasts through the
# master AP even after `iw` reports the peer on AP_VLAN. Pin neighbours so this
# assertion measures the per-station unicast data path rather than that hwsim
# broadcast-demux limitation.
ip neigh replace 10.203.0.2 lladdr "$STA_DATA_MAC" nud permanent dev "$MLD_VIF"
ip netns exec "$NS" ip neigh replace 10.203.0.1 lladdr "$MAC" \
    nud permanent dev "$STA"
timeout 15 tcpdump -i any -e -n -l \
    'icmp and net 10.203.0.0/24' >"$WORK/vlan-data.log" 2>&1 &
TRACE_PID=$!
sleep 0.2
UPLINK=pass
DOWNLINK=pass
ip netns exec "$NS" ping -c 3 -W 2 10.203.0.1 >/dev/null 2>&1 || UPLINK=fail
ping -I "$MLD_VIF" -c 3 -W 2 10.203.0.2 >/dev/null 2>&1 || DOWNLINK=fail
kill "$TRACE_PID" 2>/dev/null || true
wait "$TRACE_PID" 2>/dev/null || true
if [ "$UPLINK" != pass ]; then
    echo "MLD per-station AP_VLAN uplink failed" >&2
    ip -details link show "$MLD_VIF" >&2 || true
    ip -s link show "$MLD_VIF" >&2 || true
    ip neigh show dev "$MLD_VIF" >&2 || true
    ip netns exec "$NS" ip neigh show dev "$STA" >&2 || true
    cat "$WORK/vlan-data.log" >&2
    tail -100 "$AP_LOG" >&2
    exit 1
fi
if [ "$DOWNLINK" != pass ]; then
    echo "MLD per-station AP_VLAN downlink failed" >&2
    ip neigh show dev "$MLD_VIF" >&2 || true
    ip netns exec "$NS" ip neigh show dev "$STA" >&2 || true
    cat "$WORK/vlan-data.log" >&2
    tail -100 "$AP_LOG" >&2
    exit 1
fi
echo "PASS: MLD per-station AP_VLAN $MLD_VIF carries bidirectional data on links 0+1"

# Connect an independent non-EHT, WPA2-only station while the SAE MLD station
# remains associated. This matches reference AP's EHT+MLO transition test and
# avoids reusing the first station's MLD identity as a legacy link address.
cat >"$WORK/sta-wpa2.conf" <<EOF
ctrl_interface=$WORK/ctrl-sta-wpa2
p2p_disabled=1
network={
  ssid="rustap-mlo"
  psk="password1234"
  key_mgmt=WPA-PSK
  proto=RSN
  pairwise=CCMP
  group=CCMP
  ieee80211w=1
  disable_eht=1
  scan_freq=2412 5180
}
EOF

LEGACY_PID_FILE="$WORK/legacy.pid"
ip netns exec "$NS" "$WPAS" -B -P "$LEGACY_PID_FILE" -Dnl80211 -i"$LEGACY_STA" -c "$WORK/sta-wpa2.conf"
STATE=
for k in $(seq 1 40); do
    STATUS=$(ip netns exec "$NS" "$WCLI" -p "$WORK/ctrl-sta-wpa2" -i"$LEGACY_STA" status 2>/dev/null)
    STATE=$(echo "$STATUS" | sed -n 's/^wpa_state=//p')
    [ "$STATE" = COMPLETED ] && break
    if { [ "$STATE" = SCANNING ] || [ "$STATE" = DISCONNECTED ] || [ -z "$STATE" ]; } &&
        [ $((k % 4)) -eq 0 ]; then
        ip netns exec "$NS" "$WCLI" -p "$WORK/ctrl-sta-wpa2" -i"$LEGACY_STA" scan >/dev/null 2>&1
    fi
    sleep 1
done

if [ "${STATE:-}" != COMPLETED ]; then
    echo "legacy WPA2 association failed: wpa_state=${STATE:-unknown}" >&2
    echo "$STATUS" >&2
    tail -100 "$AP_LOG" >&2
    exit 1
fi
echo "$STATUS" | grep -iE "^(bssid|freq|key_mgmt|ieee80211w)=" || true
echo "$STATUS" | grep -q '^key_mgmt=WPA2-PSK$' ||
    { echo "legacy client did not negotiate WPA2-PSK" >&2; exit 1; }
echo "PASS: legacy WPA2 client COMPLETED on the EHT MLD transition AP"
