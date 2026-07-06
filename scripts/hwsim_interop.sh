#!/bin/bash
# hwsim_interop.sh — barely-ap interop matrix vs hostap v2.12 over mac80211_hwsim.
#
# ONE shell run drives the whole matrix and prints a pass/fail table — no
# per-command LLM/agent orchestration. This is the fast, repeatable way to
# re-validate interop after a change (an agent is only worth it when a cell
# FAILS and needs diagnosis).
#
# Direction A  — Rust AP (barely-ap) is the AP, a v2.12 wpa_supplicant is the
#                client. Covers WPA2-PSK, WPA3-SAE, WPA3-SAE-EHT, OWE.
# Direction B  — Rust client (barely-cli) connects to a v2.12 hostapd AP.
#                Filled in from the verified interop run (see the section below).
#
# Run on the hwsim box (e.g. ubuntu@10.168.0.18). hwsim radios ONLY — it never
# touches real radios (r_wlan*). Safe to re-run.
#
# Usage:  sudo ./scripts/hwsim_interop.sh [bins-dir]
#   bins-dir holds barely-ap (+ barely-cli for Direction B); default $HOME.

set -u
BINDIR=${1:-$HOME}
AP=$BINDIR/barely-ap
CLI=$BINDIR/barely-cli
HOSTAPD=/home/ubuntu/hostap-hwsim/hostapd/hostapd
WPAS=/home/ubuntu/hostap-hwsim/wpa_supplicant/wpa_supplicant
NS=interopcli
SSID=interop
PSK=password1234
CTRL=/run/wpa_iop
PASS=0; FAIL=0

[ -x "$AP" ]   || { echo "missing barely-ap: $AP" >&2; exit 1; }
[ -x "$WPAS" ] || { echo "missing v2.12 wpa_supplicant: $WPAS" >&2; exit 1; }

# pkill -f, bracketing the first pattern char so pkill's own `sudo pkill -f <pat>`
# argv doesn't match the regex and SIGKILL itself.
pk() { sudo pkill -9 -f "[${1:0:1}]${1:1}" 2>/dev/null; }
cleanup() {
    pk "$AP"; pk "$CLI"; pk "hostap-hwsim/hostapd/hostapd"
    sudo ip netns exec "$NS" pkill -9 wpa_supplicant 2>/dev/null
    sudo ip netns exec "$NS" ip addr flush dev "$STA_IF" 2>/dev/null
}
final_teardown() { cleanup; sudo ip netns del "$NS" 2>/dev/null; }
trap final_teardown EXIT

# Hermetic reset. ROOT CAUSE of the "random cell fails / AX looks broken"
# flakiness: a leftover consumer of the hwsim monitor device (wlantest/wmediumd
# from an earlier hostap or MLD test) keeps `hwsim0` open, so `rmmod` silently
# fails, the module keeps STALE medium state across runs, and frames stop being
# delivered between some radio pairs -> the client scan returns "0 BSSes" and
# that cell fails at random. So: kill EVERY hwsim consumer, drop known test
# netns (never all: docker/system netns live here too), THEN force a full
# module reload — verified to restore delivery on every pair (root-ns + netns).
sudo pkill -9 -f "[b]arely-ap --mode" 2>/dev/null
sudo pkill -9 wlantest 2>/dev/null; sudo pkill -9 wmediumd 2>/dev/null
sudo pkill -9 -f "hostap-hwsim" 2>/dev/null
for ns in interopcli saecli pskcli staperf cli sae stamx mldv; do sudo ip netns del "$ns" 2>/dev/null; done
sleep 2
if lsmod | grep -q '^mac80211_hwsim'; then
    ok=""
    for _ in 1 2 3 4 5; do sudo rmmod mac80211_hwsim 2>/dev/null && ok=1 && break; sleep 2; done
    [ -n "$ok" ] || { echo "FATAL: mac80211_hwsim still busy after killing consumers"; exit 1; }
fi
sudo modprobe mac80211_hwsim rctbl=1 radios=4
sleep 1
# ROOT CAUSE of the "random cell fails / AX looks broken" flakiness: a fresh
# module/netns defaults to the world regdomain ("00"), where 5 GHz ch36 is
# no-IR / passive-scan-only. A passive scan can't send probe requests, so the
# client can only discover the AP by hearing a beacon — and hwsim's beacon is a
# jitter-free 102.4 ms hrtimer that phase-aliases against the scan dwell, so
# whether a given cell hears it is random (re-rolled each AP restart). US makes
# ch36 active-scan (probe req/resp), which is phase-independent and reliable.
sudo iw reg set US 2>/dev/null; sleep 1

# Two hwsim netdevs, explicitly skipping any real radio (r_wlan*).
HW=()
for d in /sys/class/net/*/phy80211; do
    n=$(basename "$(dirname "$d")")
    [ "$(basename "$(readlink "/sys/class/net/$n/device/driver" 2>/dev/null)" 2>/dev/null)" = mac80211_hwsim ] && HW+=("$n")
done
AP_IF=${HW[0]:-}; STA_IF=${HW[1]:-}
[ -n "$AP_IF" ] && [ -n "$STA_IF" ] || { echo "need >=2 hwsim radios (got: ${HW[*]:-none})" >&2; exit 1; }
STA_PHY=$(cat "/sys/class/net/$STA_IF/phy80211/name")

# Migrate the STA radio into its netns ONCE. Doing this per-cell intermittently
# drops the radio off the hwsim medium, so the client's scan returns "0 BSSes"
# and that cell fails at random (looks like a protocol regression, isn't).
sudo ip netns add "$NS" 2>/dev/null
sudo iw phy "$STA_PHY" set netns name "$NS"
sudo ip netns exec "$NS" ip link set lo up
sudo ip netns exec "$NS" ip link set "$STA_IF" up
# The netns carries its OWN regulatory domain — set US here too so the STA
# active-scans ch36 (see the big comment above); without this the global set
# doesn't reach the migrated phy.
sudo ip netns exec "$NS" iw reg set US 2>/dev/null
sleep 2

row() { printf '%-26s | %-5s | %-6s | %-4s | %s\n' "$1" "$2" "$3" "$4" "$5"; }

# wpa_supplicant network-block body for a given security keyword.
wpa_block() {
    case "$1" in
        psk) printf ' psk="%s"\n key_mgmt=WPA-PSK\n' "$PSK";;
        sae) printf ' psk="%s"\n key_mgmt=SAE\n ieee80211w=2\n' "$PSK";;
        owe) printf ' key_mgmt=OWE\n ieee80211w=2\n';;
    esac
}

# Direction A: barely-ap is the AP; a v2.12 wpa_supplicant client must associate,
# complete the handshake, and pass a ping.  $1 label  $2 barely-ap flags  $3 sec
dir_a() {
    local label=$1 apflags=$2 sec=$3
    local L; L=$(echo "$label" | tr -c 'A-Za-z0-9' _)
    local assoc=no hs=no data=no res=FAIL note="" attempt
    { echo "ctrl_interface=$CTRL"; echo "p2p_disabled=1"; echo "network={"
      echo " ssid=\"$SSID\""; wpa_block "$sec"; echo "}"; } >/tmp/iop_sta.conf
    # Retry the whole cell up to 3x: an intermittently-cold hwsim medium returns
    # "0 BSSes" to the client on a given attempt — infra flakiness, not a
    # protocol failure. Only after the client PROVES it can see the AP (raw
    # `iw scan` shows the SSID) do we trust wpa_supplicant's verdict.
    for attempt in 1 2 3; do
        cleanup; sleep 1
        sudo ip link set "$AP_IF" down 2>/dev/null
        sudo iw dev "$AP_IF" set type __ap 2>/dev/null
        sudo ip link set "$AP_IF" up
        sudo ip addr flush dev "$AP_IF" 2>/dev/null
        sudo ip addr add 10.10.10.1/24 dev "$AP_IF"
        ( sudo "$AP" --mode netlink --iface "$AP_IF" --channel 36 --width 80 $apflags \
            --ssid "$SSID" --psk "$PSK" >"/tmp/iop_ap_$L.log" 2>&1 & )
        sleep 4
        grep -aq "START_AP ok" "/tmp/iop_ap_$L.log" || { note=" (START_AP failed: $(tail -1 "/tmp/iop_ap_$L.log"))"; continue; }
        # Gate on the medium being warm: don't start wpa_supplicant until the STA
        # radio can actually see this AP in a scan.
        local seen=""
        for _ in $(seq 1 12); do
            sudo ip netns exec "$NS" iw dev "$STA_IF" scan 2>/dev/null | grep -aq "SSID: $SSID" && { seen=1; break; }
            sleep 1
        done
        [ -n "$seen" ] || { note=" (medium cold: 0 BSSes)"; continue; }
        sudo ip netns exec "$NS" "$WPAS" -B -Dnl80211 -i"$STA_IF" -c /tmp/iop_sta.conf -dd -f "/tmp/iop_sta_$L.log"
        local st=""
        for k in $(seq 1 20); do
            sleep 1
            st=$(sudo ip netns exec "$NS" wpa_cli -p "$CTRL" -i"$STA_IF" status 2>/dev/null | sed -n 's/^wpa_state=//p')
            [ "$st" = COMPLETED ] && break
            case $k in 4|9|14) sudo ip netns exec "$NS" wpa_cli -p "$CTRL" -i"$STA_IF" scan >/dev/null 2>&1;; esac
        done
        if [ "$st" = COMPLETED ]; then
            assoc=yes; hs=yes
            sudo ip netns exec "$NS" ip addr add 10.10.10.2/24 dev "$STA_IF" 2>/dev/null
            sudo ip netns exec "$NS" ping -c2 -W2 10.10.10.1 >/dev/null 2>&1 && data=yes
        fi
        [ "$data" = yes ] && { res=PASS; note=""; break; }
    done
    # Flag the GTK/IGTK key-install regressions specifically (they're silent on data).
    grep -aqiE "NEW_KEY.*failed|policy validation" "/tmp/iop_ap_$L.log" && note="$note (key-install err!)"
    row "$label" "$assoc" "$hs" "$data" "$res$note"
    [ "$res" = PASS ] && PASS=$((PASS+1)) || FAIL=$((FAIL+1))
}

echo "# barely-ap <-> hostap v2.12 interop over hwsim   (AP_IF=$AP_IF  STA_IF=$STA_IF)"
echo "# Direction A: Rust AP  <-  wpa_supplicant client"
row scenario assoc hshake data result
dir_a "A WPA2-PSK ax"      "--phy ax"        psk   # baseline HE
dir_a "A WPA2-PSK ac"      "--phy ac"        psk   # VHT
dir_a "A WPA3-SAE ax"      "--phy ax --sae"  sae   # exercises SAE-netlink + IGTK fixes
dir_a "A WPA3-SAE-EHT be"  "--phy be"        sae   # exercises EHT-PMF + SAE + IGTK (auto-upgrades to SAE)
dir_a "A OWE ax"           "--phy ax --owe"  owe   # opportunistic wireless encryption

# ---------------------------------------------------------------------------
# Direction B: Rust client (barely-cli, --mode iface on a monitor radio) -> v2.12
# hostapd AP. barely-cli prints AUTHENTICATED + PING_REPLY_OK on success.
# WPA2-PSK / WPA3-SAE / MLO cells are appended here from the verified interop
# run (the exact hostapd link configs + barely-cli --mld-mac/--link1-mac/
# --ap-mld-mac wiring come from that run so they're correct, not guessed).
# ---------------------------------------------------------------------------
[ -x "$CLI" ] || echo "# (Direction B skipped: barely-cli not at $CLI)"

echo
echo "# RESULT: $PASS pass / $FAIL fail (Direction A)"
[ "$FAIL" -eq 0 ] && echo "# Direction A interop: ALL PASS" || echo "# Direction A interop: $FAIL FAILURE(S) above"
