#!/usr/bin/env bash
# Unit test for scripts/real-cloud-evidence.sh. Runs the real script with
# stub ip/wg/tcpdump/bpftool (and id/setsid/timeout/sysctl/uname so it also runs
# on non-Linux hosts) first on PATH, in the same style as the sibling
# scripts/test-*-logic.sh suites. Each case is named for the operator harm it
# prevents: wrong or missing evidence that would be mistaken for proof.
# shellcheck disable=SC2016  # stub bodies are literal scripts
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/scripts/real-cloud-evidence.sh"
WORK="$(mktemp -d)"
trap 'pkill -f "$WORK/bin/tcpdump" 2>/dev/null || true; rm -rf "$WORK"' EXIT
BIN="$WORK/bin"
mkdir -p "$BIN"

stub() { printf '#!/usr/bin/env bash\n%s\n' "$2" >"$BIN/$1"; chmod +x "$BIN/$1"; }

stub id 'echo 0'
stub setsid 'exec "$@"'
stub timeout 'shift; exec "$@"'
stub uname 'echo 6.8.0-stub'
stub sysctl 'echo "$1 = 1"'
stub bpftool 'echo "[]"'
stub ip '
echo "ip $*" >>"$STUB_LOG"
d4="[{\"dev\":\"eth0\"}]" rg="[{\"dev\":\"eth1\"}]"
case "$*" in
  "link show geneve0") exit 0 ;;
  "-s -j link show geneve0") echo "[{\"stats64\":{\"rx\":{\"packets\":1},\"tx\":{\"packets\":1}}}]" ;;
  "-j route show default") echo "${STUB_DEFAULT4-$d4}" ;;
  "-6 -j route show default") echo "${STUB_DEFAULT6-[]}" ;;
  "-j route get "*) echo "${STUB_ROUTE_GET-$rg}" ;;
  *) exit 1 ;;
esac'
stub wg '
case "$*" in
  "show interfaces") echo "${STUB_WG_IFACES-wg0}" ;;
  "show "*" endpoints") echo "${STUB_WG_ENDPOINTS-peerkey	203.0.113.9:51820}" ;;
  *) echo "wg-out" ;;
esac'
stub tcpdump '
echo "tcpdump $*" >>"$STUB_LOG"
iface="" out=""
while [ "$#" -gt 0 ]; do
  case "$1" in -i) iface="$2"; shift ;; -w) out="$2"; shift ;; esac
  shift
done
[ "$iface" != "${STUB_TCPDUMP_FAIL_IFACE:-}" ] || { echo "stub: no such device" >&2; exit 1; }
echo pkt >"$out"
trap "exit 0" INT TERM
while :; do sleep 1; done'

mkdir -p "$WORK/pidfake"
PASS=0
FAIL=0
n=0

# run_case <label> <expected-exit> <expected-stderr-substring> -- args...
# Env for the stubs comes from the caller's exported STUB_* variables.
run_case() {
  local label="$1" expect="$2" msg="$3" status=0 out
  shift 4
  n=$((n + 1))
  export STUB_LOG="$WORK/log-$n"
  : >"$STUB_LOG"
  out="$(PATH="$BIN:$PATH" bash "$SCRIPT" "$@" 2>&1)" || status=$?
  if [ "$status" = "$expect" ] && { [ -z "$msg" ] || printf '%s' "$out" | grep -qF -- "$msg"; }; then
    echo "PASS: $label"
    PASS=$((PASS + 1))
  else
    echo "FAIL: $label (exit $status, expected $expect, wanted '$msg'): $out"
    FAIL=$((FAIL + 1))
  fi
  LAST_LOG="$STUB_LOG"
}

expect_true() { # expect_true <label> <command...>
  local label="$1"
  shift
  if "$@"; then echo "PASS: $label"; PASS=$((PASS + 1)); else echo "FAIL: $label"; FAIL=$((FAIL + 1)); fi
}

reset_env() { unset STUB_DEFAULT4 STUB_DEFAULT6 STUB_ROUTE_GET STUB_WG_IFACES STUB_WG_ENDPOINTS STUB_TCPDUMP_FAIL_IFACE; }

reset_env
mkdir -p "$WORK/pin"
touch "$WORK/pin/FLOW_TABLE"
export BEEP_PIN_DIR="$WORK/pin"

# An empty route list ([]) made `jq -er '.[0].dev // empty'` succeed with no
# output in the original form; the snapshot then ran sysctl for an empty iface
# name and recorded junk as rp_filter evidence.
export STUB_DEFAULT4='[]' STUB_DEFAULT6='[]' STUB_WG_IFACES=""
run_case "no default route (empty route list) dies instead of recording an empty-iface rp_filter" 1 "no default-route interface" -- before "$WORK/d1"
reset_env

# Default route through wg0 made NIC == wg iface: two tcpdumps wrote one
# file and the "only WireGuard crosses the NIC" proof was invalid.
export STUB_ROUTE_GET='[{"dev":"wg0"}]'
run_case "underlay NIC resolving to the wg iface dies before any capture" 1 "underlay NIC resolved to the wireguard iface" -- pcap-start "$WORK/d2"
expect_true "no tcpdump started when NIC == wg" test "$(grep -c '^tcpdump' "$LAST_LOG" || true)" = 0
reset_env

# Multi-NIC node: default route is eth0 but the peer endpoint is reached via
# eth1; capturing eth0 would show an empty, misleading underlay pcap.
run_case "underlay pcap follows the route to the wg endpoint, not the default route" 0 "" -- pcap-start "$WORK/d3"
expect_true "underlay capture runs on the endpoint-route NIC (eth1)" grep -q 'tcpdump.* -i eth1 ' "$LAST_LOG"
expect_true "route lookup used the wg peer endpoint address" grep -q 'ip -j route get 203.0.113.9' "$LAST_LOG"
expect_true "underlay pcap has its own name, distinct from the wg pcap" test -e "$WORK/d3/eth1-underlay.pcap" -a -e "$WORK/d3/wg0.pcap"
run_case "pcap-stop after a normal pcap-start succeeds" 0 "" -- pcap-stop "$WORK/d3"
reset_env

# Non-wg node: no default-route lookup, no NIC capture.
export STUB_WG_IFACES="" STUB_DEFAULT4='[]'
run_case "non-wg node starts only geneve.pcap and needs no default route" 0 "" -- pcap-start "$WORK/d4"
expect_true "only one tcpdump on a non-wg node" test "$(grep -c '^tcpdump' "$LAST_LOG")" = 1
run_case "pcap-stop on non-wg node succeeds" 0 "" -- pcap-stop "$WORK/d4"
reset_env

# A stale pid file from a crashed run must not block a fresh capture.
mkdir -p "$WORK/d5"
sleep 0 &
dead=$!
wait "$dead"
echo "$dead" >"$WORK/d5/tcpdump.pid"
export STUB_WG_IFACES=""
run_case "stale (dead) pid in tcpdump.pid does not block a new pcap-start" 0 "" -- pcap-start "$WORK/d5"
run_case "pcap-stop cleanup d5" 0 "" -- pcap-stop "$WORK/d5"
reset_env

# A live pid means a capture is already running; starting another would
# clobber its pcap.
mkdir -p "$WORK/d6"
sleep 30 &
live=$!
echo "$live" >"$WORK/d6/tcpdump.pid"
export STUB_WG_IFACES=""
run_case "live pid in tcpdump.pid refuses a second pcap-start" 1 "pcap already started" -- pcap-start "$WORK/d6"
kill "$live" 2>/dev/null || true
wait "$live" 2>/dev/null || true
reset_env

# Second capture failing must not leave the first tcpdump running forever.
export STUB_TCPDUMP_FAIL_IFACE=wg0
run_case "failed wg capture reports the tcpdump error" 1 "tcpdump exited at start" -- pcap-start "$WORK/d7"
sleep 1
orphans=0
while read -r p; do kill -0 "$p" 2>/dev/null && orphans=1; done <"$WORK/d7/tcpdump.pid"
expect_true "a start failure kills the already-started tcpdumps (no orphans)" test "$orphans" = 0
reset_env

# pcap-stop on a dir that never ran pcap-start / lost pcaps.txt.
mkdir -p "$WORK/d8"
echo 999999 >"$WORK/d8/tcpdump.pid"
run_case "pcap-stop without pcaps.txt gives a clear message, not a raw bash error" 1 "pcaps.txt missing" -- pcap-stop "$WORK/d8"

echo "---"
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
