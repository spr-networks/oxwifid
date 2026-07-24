#!/bin/bash
# Complete Linux mac80211_hwsim E2E matrix.
#
# This is the audit/release entry point: one command resets hwsim, runs both
# protocol directions plus DBDC, prints a single 28-cell summary, and exits nonzero when
# any cell fails. Individual scenario scripts remain useful only for debugging.
#
# Usage:
#   scripts/hwsim_e2e.sh [bins-dir]
#   sudo scripts/hwsim_e2e.sh [bins-dir]
#
# bins-dir must contain release builds of barely-ap and barely-cli. It defaults
# to target/release under the repository root.

set -uo pipefail

if [ "$EUID" -ne 0 ]; then
    SUDO_ENV=()
    for name in WPAS REFERENCE_AP REFERENCE_AP_CLI CLIENT_CONFIG WRONG_CONFIG RUN_LOG_DIR AP_IF STA_IF; do
        if [ -n "${!name:-}" ]; then
            SUDO_ENV+=("$name=${!name}")
        fi
    done
    exec sudo -n env "${SUDO_ENV[@]}" bash "$0" "$@"
fi

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BINDIR=${1:-"$ROOT/target/release"}
AP_MATRIX="$ROOT/scripts/hwsim_interop.sh"
CLIENT_CELL="$ROOT/tools/hwsim/scen_client_reference_ap.sh"
DBDC_CELL="$ROOT/scripts/hwsim_dbdc.sh"
CLIENT_CONFIG=${CLIENT_CONFIG:-"$ROOT/tests/interop-config.json"}
WRONG_CONFIG=${WRONG_CONFIG:-"$ROOT/tools/hwsim/client-wrong-password.json"}
RUN_LOG_DIR=${RUN_LOG_DIR:-"/tmp/barely-hwsim-e2e-$$"}
CLIENT_AP_IF=${AP_IF:-wlan1}
CLIENT_STA_IF=${STA_IF:-wlan2}
PASS=0
FAIL=0

mkdir -p "$RUN_LOG_DIR"
trap 'echo; echo "# Complete Linux hwsim E2E: ABORTED"; exit 130' INT TERM HUP

for binary in barely-ap barely-cli; do
    if [ ! -x "$BINDIR/$binary" ]; then
        echo "FATAL: missing executable $BINDIR/$binary" >&2
        exit 2
    fi
done
for path in "$AP_MATRIX" "$CLIENT_CELL" "$DBDC_CELL" "$CLIENT_CONFIG" "$WRONG_CONFIG"; do
    if [ ! -e "$path" ]; then
        echo "FATAL: missing E2E input $path" >&2
        exit 2
    fi
done

print_cell() {
    printf '%-38s | %s\n' "$1" "$2"
}

wait_for_hwsim_interface() {
    local iface=$1
    local driver=""
    local _
    for _ in $(seq 1 100); do
        driver=$(readlink -f "/sys/class/net/$iface/device/driver" 2>/dev/null || true)
        [ "${driver##*/}" = mac80211_hwsim ] && return 0
        sleep 0.1
    done
    echo "FATAL: hwsim interface $iface did not become ready after namespace teardown" >&2
    return 1
}

run_client_cell() {
    local security=$1
    local mode=$2
    local cipher=${3:-ccmp-128}
    local config=$CLIENT_CONFIG
    local label="B reference AP -> Rust client: $security/$mode/$cipher"
    local log="$RUN_LOG_DIR/client-${security}-${mode}-${cipher}.log"

    [ "$mode" = reject ] && config=$WRONG_CONFIG

    echo
    echo "## $label"
    if AP_IF="$CLIENT_AP_IF" STA_IF="$CLIENT_STA_IF" \
        CLIENT="$BINDIR/barely-cli" CLIENT_CONFIG="$config" \
        bash "$CLIENT_CELL" "$security" "$mode" "$cipher" 2>&1 | tee "$log"; then
        PASS=$((PASS + 1))
        print_cell "$label" PASS
    else
        FAIL=$((FAIL + 1))
        print_cell "$label" FAIL
    fi
}

echo "# barely-ap complete Linux hwsim E2E"
echo "# binaries: $BINDIR"
echo "# logs:     $RUN_LOG_DIR"

# Direction A is already a ten-cell autorunner. Preserve its detailed output
# and import its exact pass/fail counts into this aggregate result.
AP_LOG="$RUN_LOG_DIR/rust-ap-matrix.log"
echo
echo "## Direction A: Rust AP -> wpa_supplicant (10 cells)"
bash "$AP_MATRIX" "$BINDIR" 2>&1 | tee "$AP_LOG"
AP_RC=${PIPESTATUS[0]}
AP_RESULT=$(sed -n 's/^# RESULT: \([0-9][0-9]*\) pass \/ \([0-9][0-9]*\) fail (Direction A)$/\1 \2/p' "$AP_LOG" | tail -1)
if [ -n "$AP_RESULT" ]; then
    read -r AP_PASS AP_FAIL <<<"$AP_RESULT"
else
    AP_PASS=0
    AP_FAIL=10
fi
PASS=$((PASS + AP_PASS))
FAIL=$((FAIL + AP_FAIL))
if [ "$AP_RC" -ne 0 ] && [ "$AP_FAIL" -eq 0 ]; then
    # A fatal error after a nominal table must still fail the aggregate run.
    FAIL=$((FAIL + 1))
fi

echo
echo "## DBDC: one Rust AP process -> two SAE stations"
DBDC_LOG="$RUN_LOG_DIR/dbdc.log"
if WPAS="$WPAS" RUN_LOG_DIR="$RUN_LOG_DIR/dbdc-state" \
    bash "$DBDC_CELL" "$BINDIR" 2>&1 | tee "$DBDC_LOG"; then
    PASS=$((PASS + 1))
    print_cell "DBDC simultaneous 2.4/5 GHz SAE" PASS
else
    FAIL=$((FAIL + 1))
    print_cell "DBDC simultaneous 2.4/5 GHz SAE" FAIL
fi

# Direction B covers authentication, encrypted data, externally visible state,
# AP restart recovery, group-key rotation, and credential rejection.
wait_for_hwsim_interface "$CLIENT_AP_IF" || exit 2
wait_for_hwsim_interface "$CLIENT_STA_IF" || exit 2
for mode in synthetic tap reconnect rekey; do
    for security in wpa2 wpa3 owe; do
        run_client_cell "$security" "$mode" ccmp-128
    done
done
# Reverse-direction cipher coverage: the Rust client itself performs the
# userspace authenticated encryption against the reference AP and mac80211.
for cipher in gcmp-128 ccmp-256 gcmp-256; do
    run_client_cell wpa2 synthetic "$cipher"
done
for security in wpa2 wpa3; do
    run_client_cell "$security" reject ccmp-128
done

TOTAL=$((PASS + FAIL))
echo
echo "# RESULT: $PASS pass / $FAIL fail ($TOTAL cells)"
echo "# Detailed logs: $RUN_LOG_DIR"
if [ "$FAIL" -eq 0 ] && [ "$TOTAL" -eq 28 ]; then
    echo "# Complete Linux hwsim E2E: ALL PASS"
    exit 0
fi
echo "# Complete Linux hwsim E2E: FAILURE"
exit 1
