#!/bin/bash
# Rust barely-cli -> a reference AP on two dedicated mac80211_hwsim radios.
#
# This deliberately refuses non-hwsim interfaces and never unloads a module,
# kills a system-wide daemon, changes a physical interface, or uses a netns.
# The interface defaults match the extra virtual radios on the SPR test box.
# The reference binaries must be supplied explicitly by the test environment.
set -euo pipefail

# The full matrix is commonly launched from one privileged hwsim runner. Avoid
# re-entering sudo for every command in that case (and its hostname/DNS delay).
if [ "$EUID" -eq 0 ]; then
  sudo() { "$@"; }
fi

SEC=${1:-wpa2}
DATA_MODE=${2:-synthetic}
CIPHER=${3:-ccmp-128}
AP_IF=${AP_IF:-wlan1}
STA_IF=${STA_IF:-wlan2}
REFERENCE_AP=${REFERENCE_AP:?set REFERENCE_AP to the reference AP binary}
REFERENCE_AP_CLI=${REFERENCE_AP_CLI:?set REFERENCE_AP_CLI to its control client}
CLIENT=${CLIENT:-/tmp/barely-cli}
CLIENT_CONFIG=${CLIENT_CONFIG:-/tmp/interop-config.json}
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
MON_IF=rustclimon
ACK_IF=rustcliack
AP_MAC=02:00:00:00:00:00
STA_MAC=02:00:00:00:ab:cd
FIREWALL_COMMENT="rust-client-hwsim-$$"
REFERENCE_AP_PID=
CLIENT_PID=
REFERENCE_AP_CONFIG=
GENERATED_REFERENCE_AP_CONFIG=
STA_PHY=
STATE_OK=0
TAP_OK=0
RECONNECT_OK=0
REKEY_OK=0
STATE_CLEAN_OK=0

iw_cmd() {
  if command -v iw >/dev/null 2>&1; then
    sudo iw "$@"
  else
    sudo docker exec superapi iw "$@"
  fi
}

require_hwsim() {
  local iface=$1
  local driver
  driver=$(readlink -f "/sys/class/net/${iface}/device/driver" 2>/dev/null || true)
  case "$driver" in
    */mac80211_hwsim) ;;
    *)
      echo "REFUSING: ${iface} is not a mac80211_hwsim interface (${driver:-unknown})" >&2
      exit 2
      ;;
  esac
}

delete_firewall_rule() {
  local handle
  handle=$(sudo nft -a list chain inet filter INPUT 2>/dev/null |
    awk -v marker="$FIREWALL_COMMENT" '$0 ~ marker { for (i=1; i<=NF; i++) if ($i == "handle") print $(i+1) }' |
    head -1)
  if [ -n "$handle" ]; then
    sudo nft delete rule inet filter INPUT handle "$handle" 2>/dev/null || true
  fi
}

cleanup() {
  if [ -n "$REFERENCE_AP_PID" ]; then
    sudo kill "$REFERENCE_AP_PID" 2>/dev/null || true
    wait "$REFERENCE_AP_PID" 2>/dev/null || true
  fi
  # When this script already runs as root, `sudo` is the shell wrapper above.
  # A backgrounded wrapper can leave its reference AP child orphaned after the
  # wrapper PID exits, contaminating the next matrix cell. Match only this
  # scenario's config path and reap that child as well.
  if [ -n "$REFERENCE_AP_CONFIG" ]; then
    sudo pkill -9 -f -- "$REFERENCE_AP_CONFIG" 2>/dev/null || true
  fi
  if [ -n "$GENERATED_REFERENCE_AP_CONFIG" ]; then
    sudo rm -f "$GENERATED_REFERENCE_AP_CONFIG"
  fi
  if [ -n "$CLIENT_PID" ]; then
    sudo kill "$CLIENT_PID" 2>/dev/null || true
    wait "$CLIENT_PID" 2>/dev/null || true
  fi
  delete_firewall_rule
  sudo ip addr flush dev "$AP_IF" 2>/dev/null || true
  iw_cmd dev "$MON_IF" del 2>/dev/null || true
  iw_cmd dev "$ACK_IF" del 2>/dev/null || true
  if [ -n "$STA_PHY" ] && [ ! -e "/sys/class/net/$STA_IF" ]; then
    iw_cmd phy "$STA_PHY" interface add "$STA_IF" type managed 2>/dev/null || true
  fi
  if [ -e "/sys/class/net/$STA_IF" ]; then
    sudo ip link set "$STA_IF" down 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

require_hwsim "$AP_IF"
require_hwsim "$STA_IF"
[ -x "$REFERENCE_AP" ] || { echo "missing reference AP binary: $REFERENCE_AP" >&2; exit 2; }
[ -x "$REFERENCE_AP_CLI" ] || { echo "missing reference AP control client: $REFERENCE_AP_CLI" >&2; exit 2; }

case "$SEC" in
  wpa2)
    REFERENCE_AP_CONFIG="$SCRIPT_DIR/reference-ap-client-wpa2.conf"
    CLIENT_FLAGS=()
    ;;
  wpa3)
    REFERENCE_AP_CONFIG="$SCRIPT_DIR/reference-ap-client-sae.conf"
    CLIENT_FLAGS=(--sae)
    ;;
  owe)
    REFERENCE_AP_CONFIG="$SCRIPT_DIR/reference-ap-client-owe.conf"
    CLIENT_FLAGS=(--owe)
    ;;
  *)
    echo "usage: $0 <wpa2|wpa3|owe> <synthetic|tap|reconnect|rekey|reject> [ccmp-128|gcmp-128|ccmp-256|gcmp-256]" >&2
    exit 2
    ;;
esac

case "$CIPHER" in
  ccmp-128) REFERENCE_AP_CIPHER=CCMP ;;
  gcmp-128) REFERENCE_AP_CIPHER=GCMP ;;
  ccmp-256) REFERENCE_AP_CIPHER=CCMP-256 ;;
  gcmp-256) REFERENCE_AP_CIPHER=GCMP-256 ;;
  *)
    echo "unknown pairwise cipher $CIPHER" >&2
    exit 2
    ;;
esac
if [ "$CIPHER" != ccmp-128 ]; then
  if [ "$SEC" != wpa2 ]; then
    echo "$CIPHER reverse interop currently requires wpa2" >&2
    exit 2
  fi
  GENERATED_REFERENCE_AP_CONFIG="/tmp/reference-ap-client-${SEC}-${CIPHER}-$$.conf"
  {
    sed "s/^rsn_pairwise=.*/rsn_pairwise=$REFERENCE_AP_CIPHER/" "$REFERENCE_AP_CONFIG"
    # Keep multicast on the separately negotiated 128-bit CCMP GTK. Without
    # the reference AP implicitly promotes the group cipher alongside pairwise,
    # which is a different RSNE and key-distribution scenario.
    echo "group_cipher=CCMP"
  } >"$GENERATED_REFERENCE_AP_CONFIG"
  REFERENCE_AP_CONFIG=$GENERATED_REFERENCE_AP_CONFIG
fi
CLIENT_FLAGS+=(--cipher "$CIPHER")

sudo rm -f "/tmp/reference-ap-client-${SEC}.log" "/tmp/reference-ap-client-${SEC}-restart.log" \
  "/tmp/barely-client-${SEC}.log" "/tmp/barely-client-${SEC}-ping.log" \
  "/tmp/barely-client-${SEC}-reconnect-ping.log" "/tmp/barely-client-${SEC}-rekey-ping.log"

STA_PHY=$(basename "$(readlink -f "/sys/class/net/$STA_IF/phy80211")")
sudo rfkill unblock all 2>/dev/null || true
sudo ip link set "$STA_IF" down
iw_cmd dev "$STA_IF" del
iw_cmd phy "$STA_PHY" interface add "$ACK_IF" type managed
sudo ip link set "$ACK_IF" address "$STA_MAC"
sudo ip link set "$ACK_IF" down
sudo ip link set "$ACK_IF" up
sleep 1
iw_cmd phy "$STA_PHY" interface add "$MON_IF" type monitor
sudo ip link set "$MON_IF" up

if [ "$EUID" -eq 0 ]; then
  "$REFERENCE_AP" "$REFERENCE_AP_CONFIG" >"/tmp/reference-ap-client-${SEC}.log" 2>&1 &
else
  sudo "$REFERENCE_AP" "$REFERENCE_AP_CONFIG" >"/tmp/reference-ap-client-${SEC}.log" 2>&1 &
fi
REFERENCE_AP_PID=$!
sleep 2
sudo ip addr replace 10.10.10.1/24 dev "$AP_IF"

# SPR's input policy is intentionally restrictive. Permit only this isolated
# hwsim ICMP target for the duration of the data-plane check.
sudo nft insert rule inet filter INPUT iifname "$AP_IF" ip daddr 10.10.10.1 \
  ip protocol icmp accept comment "$FIREWALL_COMMENT"

set +e
if [ "$DATA_MODE" = tap ] || [ "$DATA_MODE" = reconnect ] || [ "$DATA_MODE" = rekey ]; then
  sudo rm -f "/tmp/rust-client-status-${SEC}"
  CLIENT_TIMEOUT=20
  [ "$DATA_MODE" = reconnect ] && CLIENT_TIMEOUT=45
  if [ "$EUID" -eq 0 ]; then
    env RUSTAP_CLIENT_DEBUG=1 timeout "$CLIENT_TIMEOUT" "$CLIENT" --config "$CLIENT_CONFIG" --mode iface \
      --iface "$MON_IF" --channel 1 --mac "$STA_MAC" --tap rusttap0 \
      --state-file "/tmp/rust-client-status-${SEC}" \
      "${CLIENT_FLAGS[@]}" >"/tmp/barely-client-${SEC}.log" 2>&1 &
  else
    sudo env RUSTAP_CLIENT_DEBUG=1 timeout "$CLIENT_TIMEOUT" "$CLIENT" --config "$CLIENT_CONFIG" --mode iface \
      --iface "$MON_IF" --channel 1 --mac "$STA_MAC" --tap rusttap0 \
      --state-file "/tmp/rust-client-status-${SEC}" \
      "${CLIENT_FLAGS[@]}" >"/tmp/barely-client-${SEC}.log" 2>&1 &
  fi
  CLIENT_PID=$!
  for _ in $(seq 1 50); do
    [ -e "/tmp/rust-client-status-${SEC}" ] && [ -e /sys/class/net/rusttap0 ] && break
    sleep 0.1
  done
  if [ -e "/tmp/rust-client-status-${SEC}" ] && [ -e /sys/class/net/rusttap0 ]; then
    if sudo grep -Eq '^CONNECTED [0-9]+$' "/tmp/rust-client-status-${SEC}"; then
      STATE_OK=1
    fi
    if sudo python3 "$SCRIPT_DIR/tap_ping.py" rusttap0 \
      --src-mac "$STA_MAC" --dst-mac "$AP_MAC" \
      >"/tmp/barely-client-${SEC}-ping.log" 2>&1; then
      TAP_OK=1
    fi
  fi

  if [ "$DATA_MODE" = reconnect ] && [ "$TAP_OK" -eq 1 ]; then
    sudo kill "$REFERENCE_AP_PID" 2>/dev/null || true
    wait "$REFERENCE_AP_PID" 2>/dev/null || true
    REFERENCE_AP_PID=
    for _ in $(seq 1 250); do
      [ ! -e "/tmp/rust-client-status-${SEC}" ] && break
      sleep 0.1
    done
    if [ "$EUID" -eq 0 ]; then
      "$REFERENCE_AP" "$REFERENCE_AP_CONFIG" >"/tmp/reference-ap-client-${SEC}-restart.log" 2>&1 &
    else
      sudo "$REFERENCE_AP" "$REFERENCE_AP_CONFIG" >"/tmp/reference-ap-client-${SEC}-restart.log" 2>&1 &
    fi
    REFERENCE_AP_PID=$!
    for _ in $(seq 1 150); do
      AUTH_COUNT=$(grep -c "AUTHENTICATED tap=" "/tmp/barely-client-${SEC}.log" 2>/dev/null)
      [ "$AUTH_COUNT" -ge 2 ] && [ -e "/tmp/rust-client-status-${SEC}" ] && break
      sleep 0.1
    done
    if sudo python3 "$SCRIPT_DIR/tap_ping.py" rusttap0 \
      --src-mac "$STA_MAC" --dst-mac "$AP_MAC" \
      >"/tmp/barely-client-${SEC}-reconnect-ping.log" 2>&1; then
      RECONNECT_OK=1
    fi
  fi

  if [ "$DATA_MODE" = rekey ] && [ "$TAP_OK" -eq 1 ]; then
    # Every test AP rotates its GTK after two seconds. Keep the client alive
    # across multiple rotations, then prove protected data still round-trips.
    sleep 5
    if sudo python3 "$SCRIPT_DIR/tap_ping.py" rusttap0 \
      --src-mac "$STA_MAC" --dst-mac "$AP_MAC" \
      >"/tmp/barely-client-${SEC}-rekey-ping.log" 2>&1 &&
      ! grep -q "group key handshake failed" "/tmp/reference-ap-client-${SEC}.log" &&
      sudo "$REFERENCE_AP_CLI" -p /tmp/reference-ap-client-ctrl -i "$AP_IF" sta "$STA_MAC" |
        grep -q 'flags=.*\[AUTHORIZED\]'; then
      REKEY_OK=1
    fi
  fi

  sudo kill "$CLIENT_PID" 2>/dev/null || true
  wait "$CLIENT_PID"
  CLIENT_RC=$?
  CLIENT_PID=
  [ ! -e "/tmp/rust-client-status-${SEC}" ] && STATE_CLEAN_OK=1
  [ "$STATE_OK" -eq 1 ] && echo "STATE_FILE_OK" >>"/tmp/barely-client-${SEC}.log"
  [ "$STATE_CLEAN_OK" -eq 1 ] && echo "STATE_FILE_CLEAN_OK" >>"/tmp/barely-client-${SEC}.log"
  [ "$TAP_OK" -eq 1 ] && echo "TAP_PING_REPLY_OK" >>"/tmp/barely-client-${SEC}.log"
  [ "$RECONNECT_OK" -eq 1 ] &&
    echo "RECONNECT_TAP_PING_REPLY_OK" >>"/tmp/barely-client-${SEC}.log"
  [ "$REKEY_OK" -eq 1 ] && echo "GROUP_REKEY_DATA_OK" >>"/tmp/barely-client-${SEC}.log"
else
  RUN_TIMEOUT=18
  [ "$DATA_MODE" = reject ] && RUN_TIMEOUT=7
  sudo timeout "$RUN_TIMEOUT" "$CLIENT" --config "$CLIENT_CONFIG" --mode iface \
    --iface "$MON_IF" --channel 1 --mac "$STA_MAC" --ping --gw-mac "$AP_MAC" \
    "${CLIENT_FLAGS[@]}" >"/tmp/barely-client-${SEC}.log" 2>&1
  CLIENT_RC=$?
fi
set -e

grep -E "AUTHENTICATED|PING_REPLY_OK|DISCONNECTED|TAP_PING_REPLY_OK" \
  "/tmp/barely-client-${SEC}.log" || true
if [ "$DATA_MODE" = reject ]; then
  if grep -q "AUTHENTICATED" "/tmp/barely-client-${SEC}.log"; then
    echo "FAIL: Rust client authenticated with a wrong credential ($SEC)" >&2
    exit 1
  fi
  echo "PASS: Rust client rejected wrong $SEC credential"
  exit 0
fi
if ! grep -q "AUTHENTICATED" "/tmp/barely-client-${SEC}.log"; then
  echo "FAIL: Rust client did not authenticate ($SEC)" >&2
  tail -80 "/tmp/barely-client-${SEC}.log" >&2
  tail -80 "/tmp/reference-ap-client-${SEC}.log" >&2
  exit 1
fi
if ! grep -q "PING_REPLY_OK" "/tmp/barely-client-${SEC}.log"; then
  echo "FAIL: encrypted data-plane ping did not return ($SEC, client rc=$CLIENT_RC)" >&2
  tail -80 "/tmp/barely-client-${SEC}.log" >&2
  tail -80 "/tmp/reference-ap-client-${SEC}.log" >&2
  exit 1
fi
if { [ "$DATA_MODE" = tap ] || [ "$DATA_MODE" = reconnect ] || [ "$DATA_MODE" = rekey ]; } &&
  ! grep -q "STATE_FILE_OK" "/tmp/barely-client-${SEC}.log"; then
  echo "FAIL: SPR connected-state file was not valid ($SEC)" >&2
  exit 1
fi
if { [ "$DATA_MODE" = tap ] || [ "$DATA_MODE" = reconnect ] || [ "$DATA_MODE" = rekey ]; } &&
  ! grep -q "STATE_FILE_CLEAN_OK" "/tmp/barely-client-${SEC}.log"; then
  echo "FAIL: SPR connected-state file survived client shutdown ($SEC)" >&2
  exit 1
fi
if [ "$DATA_MODE" = rekey ] &&
  ! grep -q "GROUP_REKEY_DATA_OK" "/tmp/barely-client-${SEC}.log"; then
  echo "FAIL: encrypted traffic failed after reference AP GTK rotation ($SEC)" >&2
  tail -100 "/tmp/barely-client-${SEC}.log" >&2
  tail -100 "/tmp/reference-ap-client-${SEC}.log" >&2
  exit 1
fi
if [ "$DATA_MODE" = reconnect ] &&
  ! grep -q "RECONNECT_TAP_PING_REPLY_OK" "/tmp/barely-client-${SEC}.log"; then
  echo "FAIL: Rust client did not recover data after AP restart ($SEC)" >&2
  tail -100 "/tmp/barely-client-${SEC}.log" >&2
  tail -80 "/tmp/reference-ap-client-${SEC}-restart.log" >&2
  exit 1
fi
echo "PASS: Rust client -> reference AP $SEC authentication and encrypted ping"
