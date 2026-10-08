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

alive_count() { # alive_count <pidfile> -- how many pids listed in the file are still running (an unreaped zombie is dead)
  local n=0 p st
  while read -r p; do
    [ -n "$p" ] || continue
    st="$(ps -o stat= -p "$p" 2>/dev/null || true)"
    case "$st" in "" | Z*) ;; *) n=$((n + 1)) ;; esac
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
# shellcheck disable=SC2034 # read by k3s_dump_evidence
CONTROLLER_SELECTOR="app=x"
k3s_dump_evidence vm-a vm-b /pin >/dev/null
declare -F ev >/dev/null && leaked=yes || leaked=no
expect_eq "k3s_dump_evidence does not leak an 'ev' helper into the caller's global scope" no "$leaked"

V4="10.0.0.5"
V6="fd00:beef:98::3"
decide() { k3s_reinstall_decision "$@"; }
expect_eq "no k3s installed: nothing to wipe, fresh install proceeds" keep "$(decide 0 1 0 0 '')"
expect_eq "installed but kubectl failed (apiserver down) never wipes a healthy v6-only cluster" unreadable "$(decide 0 1 1 0 '')"
expect_eq "installed and kubectl answered empty never wipes, even when asked for v6-only" unreadable "$(decide 0 1 1 1 '')"
expect_eq "unreadable also guards the dual-stack request" unreadable "$(decide 1 0 1 1 '')"
expect_eq "unreadable also guards the plain request" unreadable "$(decide 0 0 1 0 '')"
expect_eq "a failed read is unreadable even if stale output looks like an address" unreadable "$(decide 0 1 1 0 "$V6")"
expect_eq "a non-address answer is unreadable, not a shape" unreadable "$(decide 0 1 1 1 'garbage')"
expect_eq "v6-only requested on a v6-only cluster is a no-op" keep "$(decide 0 1 1 1 "$V6")"
expect_eq "v6-only requested on a dual-stack cluster reinstalls (shape is immutable)" reinstall "$(decide 0 1 1 1 "$V4 $V6")"
expect_eq "v6-only requested on a v4 cluster reinstalls" reinstall "$(decide 0 1 1 1 "$V4")"
expect_eq "dual-stack requested on a dual-stack cluster is a no-op" keep "$(decide 1 0 1 1 "$V4 $V6")"
expect_eq "dual-stack requested on a v4 cluster reinstalls" reinstall "$(decide 1 0 1 1 "$V4")"
expect_eq "dual-stack requested on a v6-only cluster reinstalls" reinstall "$(decide 1 0 1 1 "$V6")"
expect_eq "plain call keeps a v4 cluster" keep "$(decide 0 0 1 1 "$V4")"
expect_eq "plain call keeps a dual-stack cluster (never silently reverts it)" keep "$(decide 0 0 1 1 "$V4 $V6")"
expect_eq "plain call cannot use a v6-only cluster (agent joins over v4) so reinstalls" reinstall "$(decide 0 0 1 1 "$V6")"

expect_eq "kubectl exit 0 with error text containing dots and a port must not look like a v4 shape and wipe a v6-only request" unreadable "$(decide 0 1 1 1 'error: 127.0.0.1:6443')"
expect_eq "error text with dots and colons must not wipe a dual-stack request" unreadable "$(decide 1 0 1 1 'Unable to connect to the server: dial tcp 127.0.0.1:6443: connect: connection refused')"
expect_eq "a bare host:port is not an IP literal, so never a shape" unreadable "$(decide 0 0 1 1 '10.0.0.5:6443')"
expect_eq "garbage mixed with one valid IP is unreadable, not a shape taken from the valid token" unreadable "$(decide 0 1 1 1 "garbage $V6")"
expect_eq "a v4 plus an unparsable token is unreadable even when dual-stack would otherwise reinstall" unreadable "$(decide 1 0 1 1 "$V4 error:")"
expect_eq "an out-of-range octet is not v4" unreadable "$(decide 0 1 1 1 '999.1.1.1')"
expect_eq "a three-octet token is not v4" unreadable "$(decide 0 1 1 1 '1.2.3')"
expect_eq "a leading-zero octet is not a canonical v4" unreadable "$(decide 0 1 1 1 '10.01.0.5')"
expect_eq "a v6 with a zone or brackets is not a bare InternalIP literal" unreadable "$(decide 0 1 1 1 '[fd00:beef:98::3]')"
expect_eq "a lone colon is not a v6" unreadable "$(decide 0 1 1 1 ':')"
expect_eq "':::' is not a v6" unreadable "$(decide 0 1 1 1 'fd00:::3')"
expect_eq "two '::' is not a v6" unreadable "$(decide 0 1 1 1 'fd00::beef::3')"
expect_eq "a v6 group longer than 4 hex digits is invalid" unreadable "$(decide 0 1 1 1 'fd000::3')"
expect_eq "seven groups without '::' is not a full v6" unreadable "$(decide 0 1 1 1 '1:2:3:4:5:6:7')"
expect_eq "full 8-group v6 parses" keep "$(decide 0 1 1 1 '1:2:3:4:5:6:7:8')"
expect_eq "compressed loopback ::1 parses as v6" keep "$(decide 0 1 1 1 '::1')"
expect_eq "v4-mapped v6 parses as v6" keep "$(decide 0 1 1 1 '::ffff:10.0.0.5')"
expect_eq "a v6 whose embedded v4 is bad is invalid" unreadable "$(decide 0 1 1 1 '::ffff:10.0.0.999')"
expect_eq "a newline-separated pair (jsonpath multi-value) still parses both families" keep "$(decide 1 0 1 1 "$V4"$'\n'"$V6")"

expect_eq "a transient partial list that reads reinstall once then keep must not wipe" unreadable "$(k3s_confirm_reinstall reinstall keep)"
expect_eq "a transient failed second read after a reinstall decision must not wipe" unreadable "$(k3s_confirm_reinstall reinstall unreadable)"
expect_eq "two consecutive reinstall reads are a stable wrong shape and do wipe" reinstall "$(k3s_confirm_reinstall reinstall reinstall)"
expect_eq "two agreeing keep reads stay keep" keep "$(k3s_confirm_reinstall keep keep)"
expect_eq "two agreeing unreadable reads stay unreadable (fail loud)" unreadable "$(k3s_confirm_reinstall unreadable unreadable)"
expect_eq "keep then reinstall (cluster changing under us) does not wipe" unreadable "$(k3s_confirm_reinstall keep reinstall)"

rc=0
msg="$(k3s_bring_up_cluster a b c iptables 1 1 2>&1)" || rc=$?
expect_eq "dual-stack + v6-only together is rejected instead of v6-only silently winning" 1 "$rc"
case "$msg" in *"mutually exclusive"*) said=yes ;; *) said=no ;; esac
expect_eq "the rejection says why" yes "$said"

echo "---"
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
