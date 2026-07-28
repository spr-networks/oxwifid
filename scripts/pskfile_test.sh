#!/bin/bash
# =============================================================================
# HOW THIS E2E TEST RUNS  (read before touching it)
# =============================================================================
# WHAT it proves: a real barely-ap AP with a reference AP-style wpa_psk_file authenticates
# clients by the right credential — MAC-specific entry, wildcard onboarding, the
# wildcard *fallback*, and rejects a wrong password — over real mac80211_hwsim.
#
# WHERE it runs: on the hwsim box (ubuntu@10.168.0.18), NOT your laptop. The Rust
# binary is Linux/aarch64 — build it with docker and copy it over:
#   docker run --rm -v "$PWD":/src:ro -v /tmp/blin:/out -e CARGO_TARGET_DIR=/tmp/t \
#     -w /src rust:1-bookworm bash -c \
#     'cargo build --release --bin barely-ap && cp /tmp/t/release/barely-ap /out/'
#   # /tmp/iopbin/barely-ap on the box is root-owned; stage then sudo cp:
#   scp /tmp/blin/barely-ap box:/tmp/barely-ap-new
#   ssh box 'sudo cp /tmp/barely-ap-new /tmp/iopbin/barely-ap; sudo chmod +x /tmp/iopbin/barely-ap'
#
# HOW to run it (detached so a flaky SSH can't kill it mid-run):
#   scp scripts/pskfile_test.sh box:/tmp/pskfile_test.sh
#   ssh box 'sudo rm -f /tmp/pskfile_result.txt;
#            ( sudo setsid bash /tmp/pskfile_test.sh </dev/null >/tmp/pskfile.out 2>&1 & )'
#   # then poll for the result file:
#   ssh box 'until grep -q DONE /tmp/pskfile_result.txt 2>/dev/null; do sleep 5; done;
#            cat /tmp/pskfile_result.txt'
#
# GOTCHAS that WILL bite you (all learned the hard way):
#  * hwsim medium contamination from leftover test processes
#    process keeps the module from cleanly reloading -> stale medium state ->
#    clients see "0 BSSes" on random cells. This script's reset kills them all
#    before `modprobe -r`. If scans come back empty, THAT is why.
#  * `pkill -9` does NOT deauth -> the AP keeps the station's pinned PMK, so a
#    2nd connect on the same MAC with a different password can be misjudged. Each
#    sub-test here restarts the AP fresh to avoid stale station state.
#  * Restarting the AP on the SAME interface can leave it not-actually-beaconing
#    to the client for a beat (interface churn). If a *fresh* AP won't connect,
#    it's the medium/interface, not the psk logic.
#  * The DETERMINISTIC version of these checks is `tests/psk_file.rs` (in-process,
#    no hwsim) — run THAT first (`cargo test --test psk_file`); it isolates the
#    credential-matching logic from every hwsim gremlin above. This script is the
#    on-the-wire confirmation, not the primary test.
# =============================================================================
#
# E2E: barely-ap wpa_psk_file (wildcard + per-MAC) + per_sta_vif. Each sub-test
# restarts the AP fresh (no stale station state) and drives one wpa_supplicant
# connect. Writes /tmp/pskfile_result.txt. Run: sudo setsid bash pskfile_test.sh &
B=/tmp/iopbin/barely-ap; NS=pskcli; R=/tmp/pskfile_result.txt
WPAS=${WPAS:?set WPAS to the wpa_supplicant binary}
rm -f "$R"; : > "$R"
pkill -9 -f "[b]arely-ap --mode" 2>/dev/null; pkill -9 wlantest 2>/dev/null
pkill -9 wmediumd 2>/dev/null; pkill -9 -x wpa_supplicant 2>/dev/null
for n in $NS interopcli saecli probe probe2; do ip netns del "$n" 2>/dev/null; done
sleep 1; modprobe -r mac80211_hwsim 2>/dev/null; sleep 1; modprobe mac80211_hwsim rctbl=1 radios=4; sleep 2
iw reg set US 2>/dev/null; sleep 1
mapfile -t HW < <(for n in $(ls /sys/class/net|grep ^wlan); do [ "$(basename "$(readlink /sys/class/net/$n/device/driver 2>/dev/null)")" = mac80211_hwsim ] && echo "$n"; done)
AP=${HW[0]}; STA=${HW[1]}
STAMAC=$(cat "/sys/class/net/$STA/address")
echo "AP=$AP STA=$STA STAMAC=$STAMAC" >> "$R"
# STA into a netns once
ip netns add "$NS"; iw phy "$(cat /sys/class/net/$STA/phy80211/name)" set netns name "$NS"
ip netns exec "$NS" iw reg set US 2>/dev/null; ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip link set "$STA" up; sleep 1

# Start the AP ONCE with the full wpa_psk_file (wildcard + this STA's MAC entry).
printf '00:00:00:00:00:00 onboardpass\n%s devicepass\n' "$STAMAC" > /tmp/pskfile
cat > /tmp/ap.json <<EOF
{ "ssid": "psktest", "passphrase": "defaultpass", "key_mgmt": "psk",
  "band": 5, "channel": 36, "width": 80, "phy": "ax", "mode": "netlink",
  "iface": "$AP", "per_sta_vif": true, "wpa_psk_file": "/tmp/pskfile" }
EOF
ip link set "$AP" down; iw dev "$AP" set type __ap; ip link set "$AP" up
ip addr flush dev "$AP" 2>/dev/null; ip addr add 10.10.10.1/24 dev "$AP" 2>/dev/null
setsid "$B" --config /tmp/ap.json </dev/null >/tmp/pskfile_ap.log 2>&1 &
sleep 4; grep -aqE "START_AP.*ok" /tmp/pskfile_ap.log && echo "AP: START_AP ok" >> "$R" || { echo "AP FAILED" >> "$R"; exit 1; }

run() { # $1 label  $2 (unused)  $3 client-password  $4 expect(PASS|FAIL)
  # AP stays up; each connect is a real-time reconnect (>250ms apart), so the
  # AP's re-auth session reset clears any pinned PMK before the candidate trial.
  ip netns exec "$NS" pkill -9 wpa_supplicant 2>/dev/null; sleep 2
  printf 'ctrl_interface=/run/wpa_p\nnetwork={\n ssid="psktest"\n psk="%s"\n key_mgmt=WPA-PSK\n}\n' "$3" > /tmp/sta.conf
  ip netns exec "$NS" "$WPAS" -B -Dnl80211 -i"$STA" -c /tmp/sta.conf >/dev/null 2>&1
  local st=""
  for k in $(seq 1 15); do sleep 1
    st=$(ip netns exec "$NS" wpa_cli -p /run/wpa_p -i"$STA" status 2>/dev/null | sed -n 's/^wpa_state=//p')
    [ "$st" = COMPLETED ] && break
    case $k in 3|7|11) ip netns exec "$NS" wpa_cli -p /run/wpa_p -i"$STA" scan >/dev/null 2>&1;; esac
  done
  local got=FAIL; [ "$st" = COMPLETED ] && got=PASS
  local v=WRONG; [ "$got" = "$4" ] && v=OK
  echo "  [$v] $1: pw=$3 -> $got (expected $4)" >> "$R"
}

# 1) pure wildcard onboarding: STA's MAC is NOT in the file, uses the wildcard pw
run "wildcard-onboard"  "00:00:00:00:00:00 onboardpass"                       onboardpass PASS
# 2) MAC-specific: file has the STA's MAC with its own pw
run "mac-specific"      "00:00:00:00:00:00 onboardpass"$'\n'"$STAMAC devicepass" devicepass PASS
# 3) wildcard fallback: STA has a MAC entry but connects with the wildcard pw
run "wildcard-fallback" "00:00:00:00:00:00 onboardpass"$'\n'"$STAMAC devicepass" onboardpass PASS
# 4) wrong password rejected
run "wrong-password"    "00:00:00:00:00:00 onboardpass"$'\n'"$STAMAC devicepass" totallywrong FAIL

echo "DONE" >> "$R"
pkill -9 -f "[b]arely-ap --mode" 2>/dev/null; ip netns del "$NS" 2>/dev/null
