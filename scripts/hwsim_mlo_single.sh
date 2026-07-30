#!/bin/bash
# Single-interface MLD AP cell: barely-ap as a 2-link cross-band MLD
# (ch1/2.4GHz + ch36/5GHz) on ONE hwsim wiphy, wpa_supplicant MLD client on a
# second, plus an independent legacy WPA2 client on a third radio.
# Non-destructive twin of mld_e2e.sh for shared hosts: it never
# touches the mac80211_hwsim module — pin it to radios created with
# tools/hwsim/hwsim_add_radio.py --mlo via
# HWSIM_IFACES="AP MLD_STA LEGACY_STA".
#
# PASS = an SAE/CCMP-128 MLD client completes with both links valid, its
# per-station AP_VLAN carries IP traffic in both directions, and protected data
# frames are observed in both directions on each negotiated link. Unless
# RUN_LEGACY=0, a legacy WPA2-only client is then checked against the same
# transition-mode AP.

set -u

if [ "$EUID" -ne 0 ]; then
    exec sudo -n env WPAS="${WPAS:-}" WCLI="${WCLI:-}" \
        HWSIM_IFACES="${HWSIM_IFACES:-}" RUN_LOG_DIR="${RUN_LOG_DIR:-}" \
        RUN_LEGACY="${RUN_LEGACY:-1}" \
        bash "$0" "$@"
fi

BINDIR=${1:?usage: hwsim_mlo_single.sh BINS_DIR}
AP_BIN="$BINDIR/barely-ap"
WPAS=${WPAS:?set WPAS to the wpa_supplicant binary}
WCLI=${WCLI:?set WCLI to the wpa_cli binary}
HWSIM_IFACES=${HWSIM_IFACES:?set HWSIM_IFACES="AP_IFACE MLD_STA_IFACE LEGACY_STA_IFACE" (MLO-capable hwsim radios)}
RUN_LEGACY=${RUN_LEGACY:-1}
WORK=${RUN_LOG_DIR:-"/tmp/barely-hwsim-mlo-$$"}
NS="rustap-mlo-$$"
UPSTREAM_NS="rustap-up-$$"
BRIDGE="rbr$$"
BRIDGE_PORT="rbp$$"
UPSTREAM_PORT="rup$$"
FIREWALL_COMMENT="barely-mlo-vlan-$$"
AP_PID=
STA_PID_FILE=
LEGACY_PID_FILE=
TRACE_PID=
OTA_PID=
HWSIM_MONITOR_WAS_UP=
MLD_VIF=

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
    if [ -n "$TRACE_PID" ]; then
        kill "$TRACE_PID" 2>/dev/null || true
    fi
    if [ -n "$OTA_PID" ]; then
        kill "$OTA_PID" 2>/dev/null || true
    fi
    if [ "$HWSIM_MONITOR_WAS_UP" = 0 ]; then
        ip link set hwsim0 down 2>/dev/null || true
    fi
    ip link set "$MLD_VIF" nomaster 2>/dev/null || true
    ip netns del "$UPSTREAM_NS" 2>/dev/null || true
    ip link del "$BRIDGE_PORT" 2>/dev/null || true
    ip link del "$BRIDGE" 2>/dev/null || true
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
  "cipher": "ccmp-128",
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

RUSTAP_NL_DEBUG=1 "$AP_BIN" --config "$WORK/ap.json" >"$AP_LOG" 2>&1 &
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
  proto=RSN
  pairwise=CCMP
  group=CCMP
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

echo "$STATUS" | grep -q '^key_mgmt=SAE$' ||
    { echo "MLD client did not negotiate SAE" >&2; echo "$STATUS" >&2; exit 1; }
echo "$STATUS" | grep -q '^pairwise_cipher=CCMP$' ||
    { echo "MLD client did not negotiate CCMP-128 pairwise protection" >&2; echo "$STATUS" >&2; exit 1; }
echo "$STATUS" | grep -q '^group_cipher=CCMP$' ||
    { echo "MLD client did not negotiate CCMP-128 group protection" >&2; echo "$STATUS" >&2; exit 1; }

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

mlo_link_value() {
    echo "$MLO" | awk -F= -v wanted="$1" -v field="$2" '
        $1 == "link_id" { in_link = ($2 == wanted) }
        in_link && $1 == field { print $2; exit }
    '
}
STA_L0_MAC=$(mlo_link_value 0 sta_link_addr)
STA_L1_MAC=$(mlo_link_value 1 sta_link_addr)
[ -n "$STA_L0_MAC" ] && [ -n "$STA_L1_MAC" ] || {
    echo "mlo_status did not report both STA link addresses" >&2
    echo "$MLO" >&2
    exit 1
}

# One AP_VLAN is shared across an MLD, then the MLD-addressed station is bound
# from every link context.
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
    echo "MLD AP_VLAN was not bound from both link contexts" >&2
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

# Enforce the security lifecycle that AP_VLAN data depends on. The private
# group must rotate from its provisional slots 1/4 to fresh GTK/IGTK slots 2/5
# before M1, and the M2-derived PTK must reach the driver while the controlled
# port is still closed. Authorization is emitted only after a verified M4.
first_log_line() {
    grep -n -m1 -F "$1" "$AP_LOG" 2>/dev/null | cut -d: -f1
}
GROUP_ROTATE_LINE=$(first_log_line 'initialized bound AP_VLAN group')
FIRST_EAPOL_LINE=$(first_log_line 'netlink AP: TX EAPOL')
PTK_INSTALL_LINE=$(first_log_line 'PTK installed (unauthorized, awaiting M4)')
AUTHORIZED_LINE=$(first_log_line 'keyed + authorized')
if [ -z "$GROUP_ROTATE_LINE" ] ||
    ! grep -Fq 'new=true, GTK=2, IGTK=5' "$AP_LOG"; then
    echo "private AP_VLAN did not perform its first-station GTK/IGTK rotation" >&2
    tail -120 "$AP_LOG" >&2
    exit 1
fi
if [ -z "$FIRST_EAPOL_LINE" ] || [ "$GROUP_ROTATE_LINE" -ge "$FIRST_EAPOL_LINE" ]; then
    echo "private AP_VLAN group rotation did not complete before M1" >&2
    tail -120 "$AP_LOG" >&2
    exit 1
fi
if [ -z "$PTK_INSTALL_LINE" ] || [ -z "$AUTHORIZED_LINE" ] ||
    [ "$PTK_INSTALL_LINE" -ge "$AUTHORIZED_LINE" ]; then
    echo "PTK was not installed before M4 released controlled-port authorization" >&2
    tail -120 "$AP_LOG" >&2
    exit 1
fi
echo "PASS: VLAN GTK/IGTK rotation precedes M1 and PTK installation precedes M4 authorization"

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
ip neigh flush dev "$MLD_VIF" 2>/dev/null || true
ip netns exec "$NS" ip neigh flush dev "$STA" 2>/dev/null || true
timeout 15 tcpdump -i any -e -n -l \
    'arp or (icmp and net 10.203.0.0/24)' >"$WORK/vlan-data.log" 2>&1 &
TRACE_PID=$!
command -v tshark >/dev/null 2>&1 ||
    { echo "tshark is required for per-link hwsim verification" >&2; exit 1; }
[ -e /sys/class/net/hwsim0 ] ||
    { echo "hwsim0 monitor is required for per-link verification" >&2; exit 1; }
if ip link show dev hwsim0 | grep -q '<[^>]*UP[>,]'; then
    HWSIM_MONITOR_WAS_UP=1
else
    HWSIM_MONITOR_WAS_UP=0
    ip link set hwsim0 up
fi
tcpdump -i hwsim0 -s 0 -U -w "$WORK/mlo-data.pcap" \
    >"$WORK/hwsim-tcpdump.log" 2>&1 &
OTA_PID=$!
sleep 0.2
kill -0 "$OTA_PID" 2>/dev/null || {
    echo "hwsim0 capture failed to start" >&2
    cat "$WORK/hwsim-tcpdump.log" >&2
    exit 1
}
UPLINK=pass
DOWNLINK=pass
ip netns exec "$NS" ping -c 3 -W 2 10.203.0.1 >/dev/null 2>&1 || UPLINK=fail
ping -I "$MLD_VIF" -c 3 -W 2 10.203.0.2 >/dev/null 2>&1 || DOWNLINK=fail
# Exercise all IP precedence classes so mac80211 gets traffic from every QoS
# TID that can be scheduled across the negotiated MLO links. These probes are
# additional traffic; the simple pings above remain the reachability verdict.
for tos in 0 32 64 96 128 160 192 224; do
    ip netns exec "$NS" ping -Q "$tos" -c 3 -i 0.02 -W 1 \
        10.203.0.1 >/dev/null 2>&1 || true
    ping -I "$MLD_VIF" -Q "$tos" -c 3 -i 0.02 -W 1 \
        10.203.0.2 >/dev/null 2>&1 || true
done
kill "$TRACE_PID" 2>/dev/null || true
wait "$TRACE_PID" 2>/dev/null || true
TRACE_PID=
kill "$OTA_PID" 2>/dev/null || true
wait "$OTA_PID" 2>/dev/null || true
OTA_PID=
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
if ! grep -q "$MLD_VIF In .*ethertype ARP" "$WORK/vlan-data.log" ||
    ! grep -q "$MLD_VIF Out .*ethertype ARP" "$WORK/vlan-data.log"; then
    echo "MLD ARP did not traverse the per-station AP_VLAN in both directions" >&2
    cat "$WORK/vlan-data.log" >&2
    exit 1
fi

link_frame_count() {
    local filter=$1
    local capture=${2:-"$WORK/mlo-data.pcap"}
    tshark -r "$capture" -Y "$filter" -T fields -e frame.number \
        2>/dev/null | wc -l | tr -d ' '
}
L0_UP=$(link_frame_count "wlan.fc.type == 2 && wlan.fc.protected == 1 && wlan.ra == $L0_MAC && wlan.ta == $STA_L0_MAC")
L0_DOWN=$(link_frame_count "wlan.fc.type == 2 && wlan.fc.protected == 1 && wlan.ra == $STA_L0_MAC && wlan.ta == $L0_MAC")
L1_UP=$(link_frame_count "wlan.fc.type == 2 && wlan.fc.protected == 1 && wlan.ra == $L1_MAC && wlan.ta == $STA_L1_MAC")
L1_DOWN=$(link_frame_count "wlan.fc.type == 2 && wlan.fc.protected == 1 && wlan.ra == $STA_L1_MAC && wlan.ta == $L1_MAC")
printf 'protected data frames: link0 up=%s down=%s; link1 up=%s down=%s\n' \
    "$L0_UP" "$L0_DOWN" "$L1_UP" "$L1_DOWN"
if [ "$L0_UP" -eq 0 ] || [ "$L0_DOWN" -eq 0 ] ||
    [ "$L1_UP" -eq 0 ] || [ "$L1_DOWN" -eq 0 ]; then
    echo "MLD traffic did not traverse both links in both directions" >&2
    tshark -r "$WORK/mlo-data.pcap" -Y 'wlan.fc.type == 2 && wlan.fc.protected == 1' \
        -T fields -e radiotap.channel.freq -e wlan.ra -e wlan.ta 2>/dev/null |
        sort | uniq -c >&2
    exit 1
fi

# Repeat the data-plane test with the AP_VLAN acting as a bridge port. The
# downlink Ethernet source is now a separate veth endpoint, not the AP/MLD
# address. A normal AP uses a three-address FromDS frame here:
#   A1 = STA link address, A2 = AP link BSSID, A3 = original Ethernet source.
# This is the mesh-facing regression case: a packet received from an Ethernet
# bridge port must retain that remote source in Address 3 and decrypt on either
# negotiated MLO link.
ip addr flush dev "$MLD_VIF" 2>/dev/null || true
ip netns exec "$NS" ip addr flush dev "$STA" 2>/dev/null || true
ip link add "$BRIDGE" type bridge
ip link set "$BRIDGE" up
ip link add "$BRIDGE_PORT" type veth peer name "$UPSTREAM_PORT"
ip link set "$BRIDGE_PORT" master "$BRIDGE"
ip link set "$MLD_VIF" master "$BRIDGE"
ip link set "$BRIDGE_PORT" up
ip netns add "$UPSTREAM_NS"
ip link set "$UPSTREAM_PORT" netns "$UPSTREAM_NS"
ip netns exec "$UPSTREAM_NS" ip link set lo up
ip netns exec "$UPSTREAM_NS" ip link set "$UPSTREAM_PORT" up
ip netns exec "$UPSTREAM_NS" ip addr add 10.204.0.1/24 dev "$UPSTREAM_PORT"
ip netns exec "$NS" ip addr add 10.204.0.2/24 dev "$STA"
UPSTREAM_MAC=$(ip netns exec "$UPSTREAM_NS" cat "/sys/class/net/$UPSTREAM_PORT/address")
[ "$UPSTREAM_MAC" != "$MAC" ] ||
    { echo "bridge test did not get an independent Ethernet source MAC" >&2; exit 1; }

tcpdump -i hwsim0 -s 0 -U -w "$WORK/mlo-bridge-data.pcap" \
    >"$WORK/hwsim-bridge-tcpdump.log" 2>&1 &
OTA_PID=$!
sleep 0.2
kill -0 "$OTA_PID" 2>/dev/null || {
    echo "hwsim0 bridge capture failed to start" >&2
    cat "$WORK/hwsim-bridge-tcpdump.log" >&2
    exit 1
}

BRIDGE_UPLINK=pass
BRIDGE_DOWNLINK=pass
# Uplink first teaches the bridge that the MLD station lives on the AP_VLAN.
ip netns exec "$NS" ping -c 3 -W 2 10.204.0.1 >/dev/null 2>&1 ||
    BRIDGE_UPLINK=fail
ip netns exec "$UPSTREAM_NS" ping -c 3 -W 2 10.204.0.2 >/dev/null 2>&1 ||
    BRIDGE_DOWNLINK=fail
for tos in 0 32 64 96 128 160 192 224; do
    ip netns exec "$NS" ping -Q "$tos" -c 3 -i 0.02 -W 1 \
        10.204.0.1 >/dev/null 2>&1 || true
    ip netns exec "$UPSTREAM_NS" ping -Q "$tos" -c 3 -i 0.02 -W 1 \
        10.204.0.2 >/dev/null 2>&1 || true
done
kill "$OTA_PID" 2>/dev/null || true
wait "$OTA_PID" 2>/dev/null || true
OTA_PID=

if [ "$BRIDGE_UPLINK" != pass ] || [ "$BRIDGE_DOWNLINK" != pass ]; then
    echo "MLD AP_VLAN bridge traffic failed: uplink=$BRIDGE_UPLINK downlink=$BRIDGE_DOWNLINK" >&2
    bridge fdb show br "$BRIDGE" >&2 || true
    ip -s link show "$MLD_VIF" >&2 || true
    tail -100 "$AP_LOG" >&2
    exit 1
fi

L0_REMOTE_DOWN=$(link_frame_count "wlan.fc.type == 2 && wlan.fc.protected == 1 && wlan.ra == $STA_L0_MAC && wlan.ta == $L0_MAC && wlan.sa == $UPSTREAM_MAC" "$WORK/mlo-bridge-data.pcap")
L1_REMOTE_DOWN=$(link_frame_count "wlan.fc.type == 2 && wlan.fc.protected == 1 && wlan.ra == $STA_L1_MAC && wlan.ta == $L1_MAC && wlan.sa == $UPSTREAM_MAC" "$WORK/mlo-bridge-data.pcap")
printf 'bridged remote-source downlink frames: link0=%s link1=%s source=%s\n' \
    "$L0_REMOTE_DOWN" "$L1_REMOTE_DOWN" "$UPSTREAM_MAC"
if [ "$L0_REMOTE_DOWN" -eq 0 ] || [ "$L1_REMOTE_DOWN" -eq 0 ]; then
    echo "remote Ethernet source was not preserved as Address 3 on both MLO links" >&2
    tshark -r "$WORK/mlo-bridge-data.pcap" \
        -Y 'wlan.fc.type == 2 && wlan.fc.protected == 1 && wlan.fc.fromds == 1' \
        -T fields -e radiotap.channel.freq -e wlan.ra -e wlan.ta -e wlan.sa \
        2>/dev/null | sort | uniq -c >&2
    exit 1
fi

echo "PASS: SAE/CCMP-128 MLD per-station AP_VLAN $MLD_VIF carries bidirectional direct and bridged data on links 0+1"

if [ "$RUN_LEGACY" != 1 ]; then
    exit 0
fi

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
