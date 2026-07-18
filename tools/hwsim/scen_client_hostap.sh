#!/bin/bash
# Rust barely-cli -> real hostapd on two dedicated mac80211_hwsim radios.
#
# This deliberately refuses non-hwsim interfaces and never unloads a module,
# kills a system-wide daemon, changes a physical interface, or uses a netns.
# The defaults match the extra virtual radios on the SPR test box; override
# AP_IF/STA_IF when predictable interface names differ.
set -euo pipefail

SEC=${1:-wpa2}
DATA_MODE=${2:-synthetic}
AP_IF=${AP_IF:-wlan1}
STA_IF=${STA_IF:-wlan2}
HOSTAPD=${HOSTAPD:-/home/ubuntu/hostap-hwsim/hostapd/hostapd}
HOSTAPD_CLI=${HOSTAPD_CLI:-/home/ubuntu/hostap-hwsim/hostapd/hostapd_cli}
CLIENT=${CLIENT:-/tmp/barely-cli}
CLIENT_CONFIG=${CLIENT_CONFIG:-/tmp/interop-config.json}
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
MON_IF=rustclimon
ACK_IF=rustcliack
AP_MAC=02:00:00:00:00:00
STA_MAC=02:00:00:00:ab:cd
FIREWALL_COMMENT="rust-client-hwsim-$$"
HOSTAPD_PID=
CLIENT_PID=
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
  if [ -n "$HOSTAPD_PID" ]; then
    sudo kill "$HOSTAPD_PID" 2>/dev/null || true
    wait "$HOSTAPD_PID" 2>/dev/null || true
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

case "$SEC" in
  wpa2)
    HOSTAP_CONFIG="$SCRIPT_DIR/hostap-client-wpa2.conf"
    CLIENT_FLAGS=()
    ;;
  wpa3)
    HOSTAP_CONFIG="$SCRIPT_DIR/hostap-client-sae.conf"
    CLIENT_FLAGS=(--sae)
    ;;
  owe)
    HOSTAP_CONFIG="$SCRIPT_DIR/hostap-client-owe.conf"
    CLIENT_FLAGS=(--owe)
    ;;
  *)
    echo "usage: $0 <wpa2|wpa3|owe>" >&2
    exit 2
    ;;
esac

STA_PHY=$(basename "$(readlink -f "/sys/class/net/$STA_IF/phy80211")")
sudo ip link set "$STA_IF" down
iw_cmd dev "$STA_IF" del
iw_cmd phy "$STA_PHY" interface add "$ACK_IF" type ibss
sudo ip link set "$ACK_IF" address "$STA_MAC"
sudo ip link set "$ACK_IF" down
iw_cmd dev "$ACK_IF" set type ibss
sudo ip link set "$ACK_IF" up
iw_cmd dev "$ACK_IF" ibss join rust-client-ack 2412 fixed-freq 02:ca:fe:00:00:01
iw_cmd phy "$STA_PHY" interface add "$MON_IF" type monitor
sudo ip link set "$MON_IF" up

sudo "$HOSTAPD" "$HOSTAP_CONFIG" >"/tmp/hostap-client-${SEC}.log" 2>&1 &
HOSTAPD_PID=$!
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
  sudo env RUSTAP_CLIENT_DEBUG=1 timeout "$CLIENT_TIMEOUT" "$CLIENT" --config "$CLIENT_CONFIG" --mode iface \
    --iface "$MON_IF" --channel 1 --mac "$STA_MAC" --tap rusttap0 \
    --state-file "/tmp/rust-client-status-${SEC}" \
    "${CLIENT_FLAGS[@]}" >"/tmp/barely-client-${SEC}.log" 2>&1 &
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
    sudo kill "$HOSTAPD_PID" 2>/dev/null || true
    wait "$HOSTAPD_PID" 2>/dev/null || true
    HOSTAPD_PID=
    for _ in $(seq 1 250); do
      [ ! -e "/tmp/rust-client-status-${SEC}" ] && break
      sleep 0.1
    done
    sudo "$HOSTAPD" "$HOSTAP_CONFIG" >"/tmp/hostap-client-${SEC}-restart.log" 2>&1 &
    HOSTAPD_PID=$!
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
      ! grep -q "group key handshake failed" "/tmp/hostap-client-${SEC}.log" &&
      sudo "$HOSTAPD_CLI" -p /tmp/hostap-client-ctrl -i "$AP_IF" sta "$STA_MAC" |
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
  tail -80 "/tmp/hostap-client-${SEC}.log" >&2
  exit 1
fi
if ! grep -q "PING_REPLY_OK" "/tmp/barely-client-${SEC}.log"; then
  echo "FAIL: encrypted data-plane ping did not return ($SEC, client rc=$CLIENT_RC)" >&2
  tail -80 "/tmp/barely-client-${SEC}.log" >&2
  tail -80 "/tmp/hostap-client-${SEC}.log" >&2
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
  echo "FAIL: encrypted traffic failed after hostapd GTK rotation ($SEC)" >&2
  tail -100 "/tmp/barely-client-${SEC}.log" >&2
  tail -100 "/tmp/hostap-client-${SEC}.log" >&2
  exit 1
fi
if [ "$DATA_MODE" = reconnect ] &&
  ! grep -q "RECONNECT_TAP_PING_REPLY_OK" "/tmp/barely-client-${SEC}.log"; then
  echo "FAIL: Rust client did not recover data after AP restart ($SEC)" >&2
  tail -100 "/tmp/barely-client-${SEC}.log" >&2
  tail -80 "/tmp/hostap-client-${SEC}-restart.log" >&2
  exit 1
fi
echo "PASS: Rust client -> hostapd $SEC authentication and encrypted ping"
