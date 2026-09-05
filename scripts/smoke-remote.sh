#!/usr/bin/env bash
# VM-side half of scripts/servicelb/smoke.sh. Copied into the Lima VM and
# run there as root by smoke.sh -- not meant to be invoked directly by a
# human. Builds a self-contained veth-pair + netns fixture so the whole
# client->VIP->backend round trip happens on ONE VM (the original
# hand-verification in PR #1557 used a second physical Lima VM as the
# client; a reproducible harness can't depend on a peer machine being
# available). Owns geneve0 and the smoke-veth0/smoke-client fixture
# exclusively for its duration -- do not run this alongside a real
# servicelb deployment on the same VM.
set -euo pipefail

# RFC 5737 documentation ranges: deliberately disjoint from any real subnet
# a given VM's CNI/pod network happens to be using.
VIP_IP="203.0.113.1"
CLIENT_IP="203.0.113.2"
VIP_PORT="19100"
POD_IP="198.51.100.53"
TARGET_PORT="18080"
# A second Service port on the SAME Pod (multi-port Service, e.g. 80->8080
# alongside 443->8443) -- proves the backend's TARGET_PORTS lookup resolves
# each front independently instead of collapsing both onto whichever
# target port was written last (the bug this fixture guards against: a
# pod-IP-only key can't tell these two fronts apart at all).
VIP_PORT2="19101"
TARGET_PORT2="18081"
PIN_DIR="/sys/fs/bpf/servicelb-smoke"
BIN="/tmp/u7s-servicelb-smoke"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MEMORY_SCRIPT="$SCRIPT_DIR/sample-ebpf-memory.sh"
MEMORY_OUT_DIR="/tmp/servicelb-ebpf-memory"
LOADER_LOG="/tmp/servicelb-smoke-loader.log"
BACKEND_LOG="/tmp/servicelb-smoke-backend.log"
BACKEND_LOG2="/tmp/servicelb-smoke-backend2.log"
RESPONSE_FILE="/tmp/servicelb-smoke-response.http"
RESPONSE_FILE2="/tmp/servicelb-smoke-response2.http"
RPFILTER_SAVE_FILE="/tmp/servicelb-smoke-rpfilter-all.saved"
# Restart-preservation fixture: reuses the first VIP:PORT ->
# backend pair above, held open across a loader restart instead of a plain
# request/response, so the SECOND chunk's return leg depends on the
# FWD_FLOW/REV_FLOW conntrack entries the FIRST chunk's forward leg wrote
# BEFORE the restart -- exactly the state a DaemonSet rollout/eviction/OOM
# kill must not silently drop.
RESTART_CHUNK1="restart-preservation-chunk-1"
RESTART_CHUNK2="restart-preservation-chunk-2"
RESTART_FIFO="/tmp/servicelb-smoke-restart-fifo"
RESTART_SIGNAL_FIFO="/tmp/servicelb-smoke-restart-signal"
RESTART_BACKEND_LOG="/tmp/servicelb-smoke-restart-backend.log"
RESTART_CLIENT_OUT="/tmp/servicelb-smoke-restart-client.out"
RESTART_LOADER_LOG="/tmp/servicelb-smoke-loader-restart.log"

cmd="${1:-}"

# Releases the backend's blocking read on the signal fifo (the
# restart-preservation fixture's writer subshell parks there). Opened `<>`
# (read-write), not `>` (write-only): a write-only open blocks until a
# reader is present, which on the success path is already gone by the time
# this runs again -- read-write mode never needs a peer to proceed.
#
# Registered as this script's OWN exit trap (below), not just called from
# cleanup(): `exit` in bash -- even with no trap at all -- blocks waiting
# for every background job this shell started, DISOWNED OR NOT, before the
# process actually terminates (confirmed live: a disowned reader still
# blocked on this exact fifo wedged a bare `exit 1` indefinitely, no trap
# involved). The reader must already be unblocked by the time `exit` runs,
# not just by the time cleanup() gets around to it.
release_restart_signal() {
  { exec {sigfd}<>"$RESTART_SIGNAL_FIFO"; } 2>/dev/null && printf '\n' >&"$sigfd" 2>/dev/null || true
}

cleanup() {
  # Backstop for a `run` invocation that got SIGKILLed rather than exiting
  # normally (its own EXIT trap below never fires for that): without this,
  # a `-9`'d run leaves its reader subshell orphaned and permanently
  # blocked, since nothing else will ever write to this fifo.
  release_restart_signal
  pkill -f "$BIN" 2>/dev/null || true
  pkill -f "nc -l -N ${POD_IP} ${TARGET_PORT}" 2>/dev/null || true
  pkill -f "nc -l -N ${POD_IP} ${TARGET_PORT2}" 2>/dev/null || true
  pkill -f "nc ${VIP_IP} ${VIP_PORT}" 2>/dev/null || true
  rm -rf "$PIN_DIR"
  # Delete the veth (destroys both ends, wherever each lives) BEFORE the
  # netns: deleting the netns first can orphan smoke-veth1's namespace --
  # the veth peer keeps it alive with its bind-mount name already gone,
  # leaving an unreachable, unnamed namespace behind (seen empirically).
  ip link del smoke-veth0 2>/dev/null || true
  ip netns del smoke-client 2>/dev/null || true
  ip link del geneve0 2>/dev/null || true
  ip addr del "${POD_IP}/32" dev lo 2>/dev/null || true
  if [ -f "$RPFILTER_SAVE_FILE" ]; then
    sysctl -w net.ipv4.conf.all.rp_filter="$(cat "$RPFILTER_SAVE_FILE")" >/dev/null 2>&1 || true
    rm -f "$RPFILTER_SAVE_FILE"
  fi
}

case "$cmd" in
  cleanup)
    cleanup
    exit 0
    ;;
  run)
    ;;
  *)
    echo "usage: $0 {run|cleanup}" >&2
    exit 1
    ;;
esac

trap release_restart_signal EXIT

command -v bpftool >/dev/null || {
  echo "FAIL: bpftool not found in the VM (install linux-tools-\$(uname -r))" >&2
  exit 1
}

# Idempotent: clear any leftover fixture from a prior interrupted run before
# creating a fresh one.
cleanup >/dev/null 2>&1 || true

echo "==> creating geneve0 external (collect-metadata) device"
ip link add geneve0 type geneve external
ip link set geneve0 up

echo "==> creating smoke-veth0/smoke-veth1 + smoke-client netns (stands in for a real client machine)"
ip link add smoke-veth0 type veth peer name smoke-veth1
ip netns add smoke-client
ip link set smoke-veth1 netns smoke-client
ip addr add "${VIP_IP}/24" dev smoke-veth0
ip link set smoke-veth0 up
ip netns exec smoke-client ip addr add "${CLIENT_IP}/24" dev smoke-veth1
ip netns exec smoke-client ip link set smoke-veth1 up
ip netns exec smoke-client ip link set lo up
ip addr add "${POD_IP}/32" dev lo

# Empirically required for this fixture (kfree_skb tracepoint pinpointed
# `ip_rcv_finish_core`, reason IP_RPFILTER): the forward-decap program
# re-delivers the DNAT'd packet locally via `lo` (the pod_ip alias above)
# while it physically arrived on geneve0 -- Linux's loose (2) reverse-path
# filter still drops that mismatch for a source reachable only via a
# different device (smoke-veth0). A real deployment routes the decap'd
# packet to an actual Pod veth instead of a loopback alias and does not
# appear to need this (PR #1557's real 2-node run never touched rp_filter);
# saved/restored so this harness never leaves the VM's global rp_filter
# permanently weakened.
if [ ! -f "$RPFILTER_SAVE_FILE" ]; then
  sysctl -n net.ipv4.conf.all.rp_filter > "$RPFILTER_SAVE_FILE"
fi
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
sysctl -w net.ipv4.conf.geneve0.rp_filter=0 >/dev/null

# Both the initial load and the restart-preservation phase below need this
# same load-then-wait sequence -- pulled out so the restart run can't drift
# from the exact fixture args/timeout the initial VERIFIER-ACCEPT gate uses.
start_loader() {
  local log="$1"
  nohup "$BIN" \
    --uplink-iface smoke-veth0 --geneve-iface geneve0 --pin-dir "$PIN_DIR" \
    --fixture "${VIP_IP}:${VIP_PORT}:tcp:${VIP_IP}:${POD_IP}:${TARGET_PORT}" \
    --fixture "${VIP_IP}:${VIP_PORT2}:tcp:${VIP_IP}:${POD_IP}:${TARGET_PORT2}" \
    >"$log" 2>&1 &
  disown
}

wait_for_attach() {
  local log="$1"
  for _ in $(seq 1 20); do
    grep -q "all 3 hooks attached" "$log" 2>/dev/null && return 0
    if ! pgrep -f "$BIN" >/dev/null; then
      echo "FAIL: loader exited before attaching (verifier rejection or load error):" >&2
      cat "$log" >&2
      exit 1
    fi
    sleep 0.5
  done
  grep -q "all 3 hooks attached" "$log" || {
    echo "FAIL: loader never reported all 3 hooks attached within 10s:" >&2
    cat "$log" >&2
    exit 1
  }
}

echo "==> loading servicelb-ebpf -- this is the verifier-accept gate"
# Two --fixture entries sharing one Pod IP but different VIP/target ports:
# the multi-port-Service scenario TARGET_PORTS' front-tuple keying exists
# to disambiguate.
start_loader "$LOADER_LOG"
wait_for_attach "$LOADER_LOG"
echo "VERIFIER-ACCEPT: PASS"
cat "$LOADER_LOG"

echo "==> sampling eBPF map memory + loader RSS (before round trip)"
# A monitoring gap (e.g. jq missing on this node) must never fail the
# VERIFIER-ACCEPT/ROUND-TRIP fixture it's observing -- same contract
# sample-ebpf-memory.sh's own header documents for its per-tick sampling.
bash "$MEMORY_SCRIPT" once --pin-dir "$PIN_DIR" --out-dir "$MEMORY_OUT_DIR" || echo "WARN: eBPF memory sampling failed -- continuing (monitoring gap, not a smoke-test failure)" >&2

# Independent, kernel-truth confirmation (not just the loader's own log):
# a verifier rejection never reaches this state at all, since program.load()
# above would have returned Err and aborted the loader before this point.
loaded=$(bpftool prog list | grep -cE 'name (uplink_ingress|geneve_ingress|uplink_egress_return)')
[ "$loaded" -eq 3 ] || {
  echo "FAIL: expected 3 sched_cls programs loaded, bpftool sees $loaded" >&2
  exit 1
}

echo "==> starting backend responders on ${POD_IP}:${TARGET_PORT} and ${POD_IP}:${TARGET_PORT2}"
# Distinct bodies, not just "both connections succeed": the bug this
# fixture guards against is the backend DNAT-ing BOTH VIP ports to
# whichever target port a pod-IP-only key last happened to remember, which
# a same-body response would not catch.
printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK' > "$RESPONSE_FILE"
printf 'HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nOK2' > "$RESPONSE_FILE2"
nohup nc -l -N "$POD_IP" "$TARGET_PORT" < "$RESPONSE_FILE" >"$BACKEND_LOG" 2>&1 &
disown
nohup nc -l -N "$POD_IP" "$TARGET_PORT2" < "$RESPONSE_FILE2" >"$BACKEND_LOG2" 2>&1 &
disown
sleep 0.5

echo "==> driving one client -> VIP -> backend round trip"
body=$(ip netns exec smoke-client curl -sS -m 5 "http://${VIP_IP}:${VIP_PORT}/")
[ "$body" = "OK" ] || {
  echo "FAIL: expected response body 'OK', got: $body" >&2
  exit 1
}
echo "ROUND-TRIP: PASS (client ${CLIENT_IP} -> VIP ${VIP_IP}:${VIP_PORT} -> backend ${POD_IP}:${TARGET_PORT} -> response 'OK')"

echo "==> driving a second round trip through the SAME Pod's other Service port"
body2=$(ip netns exec smoke-client curl -sS -m 5 "http://${VIP_IP}:${VIP_PORT2}/")
[ "$body2" = "OK2" ] || {
  echo "FAIL: expected response body 'OK2' from the second Service port, got: $body2 -- a pod-IP-only backend key would DNAT this to the FIRST port's target instead" >&2
  exit 1
}
echo "MULTI-PORT ROUND-TRIP: PASS (client ${CLIENT_IP} -> VIP ${VIP_IP}:${VIP_PORT2} -> backend ${POD_IP}:${TARGET_PORT2} -> response 'OK2', distinct from the first Service port's target)"

# bpftool exits nonzero AND still prints a JSON error object to stdout for a
# missing pin (`{"error": "..."}`) -- piping that straight into `jq length`
# would report 1 (one key), a false-positive "entry" that would silently
# defeat every check below. Only trust jq's count once bpftool itself
# reports success.
map_entry_count() {
  local json
  json=$(bpftool map dump pinned "$1" --json 2>/dev/null) || { echo ""; return; }
  jq 'length' <<<"$json" 2>/dev/null || echo ""
}

echo "==> establishing a flow to hold open across a loader restart (a DaemonSet rollout/eviction/OOM kill must not silently drop an established connection)"
# The backend sends chunk 1, then blocks on a single `read` from a second
# fifo instead of polling a marker file -- chunk 2 only goes out once THIS
# script has independently confirmed (via bpftool, kernel truth rather than
# nc's own stdio buffering) that the restart completed, so there's no
# guessed delay to race against. A busy-poll loop here was found to spin up
# a fresh `sleep` subprocess every 100ms for the whole test's duration,
# racing this script's own foreground bpftool/jq pipelines for SIGCHLD and
# intermittently wedging bash in `wait()` (reproduced live: parked
# indefinitely with `do_wait` as the sole wchan and no runnable children) --
# a single blocking read has no such steady-state forking.
# No further forward-direction traffic occurs while it waits (client has
# nothing to ACK until chunk 2 arrives), so the restart can only be masked
# by FWD_FLOW/REV_FLOW surviving it, not by a fresh forward packet
# re-populating them.
rm -f "$RESTART_FIFO" "$RESTART_SIGNAL_FIFO"
mkfifo "$RESTART_FIFO" "$RESTART_SIGNAL_FIFO"
nohup nc -l -N "$POD_IP" "$TARGET_PORT" < "$RESTART_FIFO" >"$RESTART_BACKEND_LOG" 2>&1 &
disown
( printf '%s' "$RESTART_CHUNK1"; read -r _ < "$RESTART_SIGNAL_FIFO"; printf '%s' "$RESTART_CHUNK2" ) > "$RESTART_FIFO" &
disown

ip netns exec smoke-client bash -c "timeout 30 nc ${VIP_IP} ${VIP_PORT} > ${RESTART_CLIENT_OUT}" &
restart_client_pid=$!
disown

for _ in $(seq 1 30); do
  fwd_before=$(map_entry_count "$PIN_DIR/FWD_FLOW")
  [ -n "$fwd_before" ] && [ "$fwd_before" -gt 0 ] && break
  sleep 0.2
done
rev_before=$(map_entry_count "$PIN_DIR/REV_FLOW")
[ -n "$fwd_before" ] && [ "$fwd_before" -gt 0 ] || {
  echo "FAIL: FWD_FLOW (pinned at $PIN_DIR/FWD_FLOW) never gained an entry for the restart-preservation flow within 6s" >&2
  exit 1
}
[ -n "$rev_before" ] && [ "$rev_before" -gt 0 ] || {
  echo "FAIL: REV_FLOW (pinned at $PIN_DIR/REV_FLOW) has no entries before the restart -- expected the flow just established above to have populated it" >&2
  exit 1
}
echo "conntrack before restart: FWD_FLOW=$fwd_before entries, REV_FLOW=$rev_before entries"

echo "==> restarting the loader against the same --pin-dir (simulates a DaemonSet image rollout/eviction/OOM kill)"
pkill -f "$BIN" 2>/dev/null || true
for _ in $(seq 1 20); do
  pgrep -f "$BIN" >/dev/null || break
  sleep 0.2
done
pgrep -f "$BIN" >/dev/null && {
  echo "FAIL: old loader process did not exit before the restart" >&2
  exit 1
}

start_loader "$RESTART_LOADER_LOG"
wait_for_attach "$RESTART_LOADER_LOG"
echo "RESTART VERIFIER-ACCEPT: PASS"

fwd_after=$(map_entry_count "$PIN_DIR/FWD_FLOW")
rev_after=$(map_entry_count "$PIN_DIR/REV_FLOW")
# Non-decreasing, not exact equality: `try_uplink_ingress` re-inserts on
# EVERY matching packet, so a delayed TCP ACK (or any other legitimate
# forward-direction traffic) landing during the restart window can add or
# refresh an entry -- observed live, harmlessly, on a correctly-fixed
# loader. What must never happen is entries LOST, especially a reset to
# zero, which is exactly what an unpinned restart does.
[ "$fwd_after" -ge "$fwd_before" ] && [ "$rev_after" -ge "$rev_before" ] || {
  echo "FAIL: conntrack entries did not survive the loader restart -- FWD_FLOW ${fwd_before}->${fwd_after}, REV_FLOW ${rev_before}->${rev_after}. A restart must reuse the pinned maps, not swap in an empty set that silently drops every established flow." >&2
  exit 1
}
echo "RESTART MAP PRESERVATION: PASS (FWD_FLOW=$fwd_after entries, REV_FLOW=$rev_after entries, unchanged across the restart)"

# Only now does the backend send chunk 2 -- strictly after the restart is
# confirmed complete, so the second chunk's return leg genuinely exercises
# the NEW loader instance's programs, not a lucky timing window.
release_restart_signal

wait "$restart_client_pid" || true
restart_body="$(cat "$RESTART_CLIENT_OUT" 2>/dev/null || true)"
[ "$restart_body" = "${RESTART_CHUNK1}${RESTART_CHUNK2}" ] || {
  echo "FAIL: the flow held open across the loader restart stopped routing -- expected '${RESTART_CHUNK1}${RESTART_CHUNK2}', got '$restart_body'. Lost conntrack means the return leg is dropped/misrouted, even though the connection never closed." >&2
  exit 1
}
echo "RESTART FLOW CONTINUITY: PASS (client received both chunks across the loader restart: '$restart_body')"

echo "==> sampling eBPF map memory + loader RSS (after round trip, before cleanup)"
bash "$MEMORY_SCRIPT" once --pin-dir "$PIN_DIR" --out-dir "$MEMORY_OUT_DIR" || echo "WARN: eBPF memory sampling failed -- continuing (monitoring gap, not a smoke-test failure)" >&2

echo "==> ebpf-map-memory.csv:"
cat "$MEMORY_OUT_DIR/ebpf-map-memory.csv" 2>/dev/null || echo "  (not captured -- see WARN above)"
echo "==> loader-rss.csv:"
cat "$MEMORY_OUT_DIR/loader-rss.csv" 2>/dev/null || echo "  (not captured -- see WARN above)"
