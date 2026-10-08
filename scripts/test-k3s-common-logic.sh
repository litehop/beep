#!/usr/bin/env bash
# Unit test for the pure-shell helpers in scripts/k3s-common.sh that the k3s
# rigs rely on to fail loud rather than hang or false-PASS: bounded_run /
# kill_tree (a wedged limactl/ssh call must become rc 124 and leave no stray
# process behind), host_port (a malformed URL authority makes curl fail in
# a way the negative-isolation checks would misread), and the evidence dump's
# helper scoping. Sources the real file, mirroring
# scripts/test-controller-rss-logic.sh. No VM, kubectl or network needed.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT_DIR="$REPO/scripts"
# shellcheck source=k3s-common.sh
. "$SCRIPT_DIR/k3s-common.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0

expect_eq() {
  local label="$1" expect="$2" got="$3"
  if [ "$expect" = "$got" ]; then
    echo "PASS: $label"
    PASS=$((PASS + 1))
  else
    echo "FAIL: $label (expected '$expect', got '$got')"
    FAIL=$((FAIL + 1))
  fi
}

alive_count() { # alive_count <pidfile> -- how many pids listed in the file are still running
  local n=0 p
  while read -r p; do
    [ -n "$p" ] || continue
    if kill -0 "$p" 2>/dev/null; then n=$((n + 1)); fi
  done < "$1"
  echo "$n"
}

rc=0
start=$SECONDS
bounded_run 1 sleep 30 || rc=$?
elapsed=$((SECONDS - start))
expect_eq "a command outliving its limit returns 124 so the gate fails loud instead of hanging" 124 "$rc"
[ "$elapsed" -lt 10 ] && took_short=yes || took_short=no
expect_eq "the timed-out command is cut off near the limit, not waited out (took ${elapsed}s)" yes "$took_short"

rc=0
bounded_run 5 true || rc=$?
expect_eq "a successful command passes through rc 0" 0 "$rc"

rc=0
bounded_run 5 bash -c 'exit 3' || rc=$?
expect_eq "a failing command's own rc passes through, not collapsed to 124 or 1" 3 "$rc"

rc=0
out="$(bounded_run 5 echo hello)" || rc=$?
expect_eq "the command's stdout reaches the caller (map dumps are read from it)" hello "$out"

: > "$WORK/children.pids"
rc=0
bounded_run 1 bash -c "sleep 300 & echo \$! >> '$WORK/children.pids'; wait" || rc=$?
expect_eq "nested-child case still times out with 124" 124 "$rc"
expect_eq "a wedged grandchild (the real limactl/ssh case) is killed with its parent, not orphaned" 0 "$(alive_count "$WORK/children.pids")"

# A process that keeps forking would escape a pgrep snapshot taken before
# its newest children exist; every spawned pid must be dead afterwards.
: > "$WORK/forkloop.pids"
rc=0
bounded_run 1 bash -c "echo \$\$ >> '$WORK/forkloop.pids'; while :; do sleep 300 & echo \$! >> '$WORK/forkloop.pids'; sleep 0.01; done" || rc=$?
expect_eq "a fork-looping command times out with 124" 124 "$rc"
sleep 1
expect_eq "no child of a fork-looping command survives the kill (snapshot race)" 0 "$(alive_count "$WORK/forkloop.pids")"
[ "$(wc -l < "$WORK/forkloop.pids")" -gt 1 ] && spawned=yes || spawned=no
expect_eq "the fork loop genuinely spawned children, so the check above is not vacuous" yes "$spawned"

expect_eq "v6 literal is bracketed so it is a valid URL authority" "[fd00:beef:98::3]:8080" "$(host_port fd00:beef:98::3 8080)"
expect_eq "v4 literal is left bare" "10.0.0.5:8080" "$(host_port 10.0.0.5 8080)"
expect_eq "hostname is left bare" "node-a.example:8080" "$(host_port node-a.example 8080)"
expect_eq "v4-mapped v6 is bracketed like any v6 literal" "[::ffff:10.0.0.5]:8080" "$(host_port ::ffff:10.0.0.5 8080)"
expect_eq "an already-bracketed v6 is not double-bracketed" "[fd00:beef:98::3]:8080" "$(host_port '[fd00:beef:98::3]' 8080)"
expect_eq "empty port yields the RemoteAddr prefix form used for client-address matching" "[fd00:beef:98::14]:" "$(host_port fd00:beef:98::14 '')"

rc=0
out="$(k3s_ev 1 "wedged-call" sleep 30)" || rc=$?
expect_eq "a timed-out evidence call does not abort the dump" 0 "$rc"
case "$out" in
  *"EVIDENCE TIMEOUT: 'wedged-call'"*) timeout_line=yes ;;
  *) timeout_line=no ;;
esac
expect_eq "a timed-out evidence call prints the loud EVIDENCE TIMEOUT line" yes "$timeout_line"

limactl() { echo "stub-limactl $*"; }
kube() { echo "stub-kube $*"; }
CONTROLLER_SELECTOR="app=x"
k3s_dump_evidence vm-a vm-b /pin >/dev/null
declare -F ev >/dev/null && leaked=yes || leaked=no
expect_eq "k3s_dump_evidence does not leak an 'ev' helper into the caller's global scope" no "$leaked"

echo "---"
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
