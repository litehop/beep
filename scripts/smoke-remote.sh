#!/usr/bin/env bash
# VM-side half of scripts/smoke.sh. Copied into the Lima VM and
# run there as root by smoke.sh -- not meant to be invoked directly by a
# human. Builds a self-contained veth-pair + netns fixture so the whole
# client->VIP->backend round trip happens on ONE VM (the original
# hand-verification used a second physical Lima VM as the client; a
# reproducible harness can't depend on a peer machine being available).
# Owns geneve0 and the smoke-veth0/smoke-client fixture
# exclusively for its duration -- do not run this alongside a real
# beep deployment on the same VM.
set -euo pipefail

# RFC 5737 documentation ranges: deliberately disjoint from any real subnet
# a given VM's CNI/pod network happens to be using.
VIP_IP="203.0.113.1"
CLIENT_IP="203.0.113.2"
VIP_PORT="19100"
POD_IP="198.51.100.53"
# Covers POD_IP (TEST-NET-2) while staying disjoint from VIP_IP/CLIENT_IP
# (TEST-NET-3) -- exercises the vip-outside-pod-cidr startup check against a
# legitimate config, which must load, not reject.
POD_CIDR="198.51.100.0/24"
TARGET_PORT="18080"
# A second Service port on the SAME Pod (multi-port Service, e.g. 80->8080
# alongside 443->8443) -- proves the backend's TARGET_PORTS lookup resolves
# each front independently instead of collapsing both onto whichever
# target port was written last (the bug this fixture guards against: a
# pod-IP-only key can't tell these two fronts apart at all).
VIP_PORT2="19101"
TARGET_PORT2="18081"
# A third front for the anti-flush (FWD_PENDING-churn-vs-FLOW_TABLE-survival)
# demonstration below: UDP, so a burst never needs a real handshake, and
# `FLOOD_BACKEND_NODE_IP` is deliberately an address nothing on this VM
# answers to -- the encap'd packet has nowhere to complete a round trip, so
# every flood packet MUST mint into FWD_PENDING and can never be promoted
# into FLOW_TABLE (admission control's only mint site is the forward path;
# promotion requires an observed return leg, which this front can never
# produce).
VIP_PORT3="19102"
TARGET_PORT3="18082"
FLOOD_BACKEND_NODE_IP="203.0.113.250"
# A SECOND configured uplink -- proves the multi-symmetric-uplink design
# (docs/decisions/servicelb-multi-symmetric-uplink.md): a node admitting
# client traffic on N uplinks must return each flow via the SAME uplink it
# arrived on. TEST-NET-1, deliberately disjoint from the first uplink's
# TEST-NET-3 subnet above and from POD_CIDR's TEST-NET-2 -- a genuinely
# separate physical path, not just a second cable on the same wire.
# `backend_node_ip` for this uplink's fixture is still VIP_IP (this node's
# own self-loop identity, unaffected by which uplink admitted the packet).
UPLINK2_IFACE="smoke-veth2"
UPLINK2_PEER_IFACE="smoke-veth3"
UPLINK2_NETNS="smoke-client2"
UPLINK2_VIP_IP="192.0.2.1"
UPLINK2_CLIENT_IP="192.0.2.2"
UPLINK2_VIP_PORT="19103"
UPLINK2_TARGET_PORT="18083"
UPLINK2_BACKEND_LOG="/tmp/beep-smoke-backend-uplink2.log"
UPLINK2_RESPONSE_FILE="/tmp/beep-smoke-response-uplink2.http"
PIN_DIR="/sys/fs/bpf/beep-smoke"
BIN="/tmp/beep-smoke"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=verifier-accept-check.sh
. "$SCRIPT_DIR/verifier-accept-check.sh"
MEMORY_SCRIPT="$SCRIPT_DIR/sample-ebpf-memory.sh"
MEMORY_OUT_DIR="/tmp/beep-ebpf-memory"
LOADER_LOG="/tmp/beep-smoke-loader.log"
BACKEND_LOG="/tmp/beep-smoke-backend.log"
BACKEND_LOG2="/tmp/beep-smoke-backend2.log"
RESPONSE_FILE="/tmp/beep-smoke-response.http"
RESPONSE_FILE2="/tmp/beep-smoke-response2.http"
RPFILTER_SAVE_FILE="/tmp/beep-smoke-rpfilter-all.saved"
# Restart-preservation fixture: reuses the first VIP:PORT ->
# backend pair above, held open across a loader restart instead of a plain
# request/response, so the SECOND chunk's return leg depends on the
# FLOW_TABLE conntrack entries (both forward- and reverse-tagged) the FIRST
# chunk's forward leg (and its own return leg's promotion) wrote BEFORE the
# restart -- exactly the state a DaemonSet rollout/eviction/OOM kill must
# not silently drop.
RESTART_CHUNK1="restart-preservation-chunk-1"
RESTART_CHUNK2="restart-preservation-chunk-2"
RESTART_FIFO="/tmp/beep-smoke-restart-fifo"
RESTART_SIGNAL_FIFO="/tmp/beep-smoke-restart-signal"
RESTART_BACKEND_LOG="/tmp/beep-smoke-restart-backend.log"
RESTART_CLIENT_OUT="/tmp/beep-smoke-restart-client.out"
RESTART_LOADER_LOG="/tmp/beep-smoke-loader-restart.log"

# Selective conntrack eviction fixture: a front OF ITS OWN,
# not reused from the round trips above, so the eviction assertions below
# aren't confounded by conntrack rows those other flows already wrote for
# POD_IP. `EVICT_FRONT_POD_IP` is mutated across this section's own loader
# restarts (evicted-pod -> replacement pod -> the same pod IP reused) --
# `start_loader` below reads it at call time, not at definition time.
EVICT_VIP_PORT="19104"
EVICT_TARGET_PORT="18084"
EVICT_FRONT_POD_IP="$POD_IP"
EVICT_RESPONSE_FILE="/tmp/beep-smoke-response-evict.http"
EVICT_BACKEND_LOG="/tmp/beep-smoke-backend-evict.log"
REPLACEMENT_POD_IP="198.51.100.60"
REPLACEMENT_RESPONSE_FILE="/tmp/beep-smoke-response-replacement.http"
REPLACEMENT_BACKEND_LOG="/tmp/beep-smoke-backend-replacement.log"
REUSE_RESPONSE_FILE="/tmp/beep-smoke-response-reuse.http"
REUSE_BACKEND_LOG="/tmp/beep-smoke-backend-reuse.log"
EVICT_LOADER_LOG_REPLACEMENT="/tmp/beep-smoke-loader-evict-replacement.log"
EVICT_LOADER_LOG_REUSE="/tmp/beep-smoke-loader-evict-reuse.log"

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
  pkill -f "nc -l -N ${POD_IP} ${UPLINK2_TARGET_PORT}" 2>/dev/null || true
  pkill -f "nc -l -N ${POD_IP} ${EVICT_TARGET_PORT}" 2>/dev/null || true
  pkill -f "nc -l -N ${REPLACEMENT_POD_IP} ${EVICT_TARGET_PORT}" 2>/dev/null || true
  pkill -f "nc ${VIP_IP} ${VIP_PORT}" 2>/dev/null || true
  rm -rf "$PIN_DIR"
  # Delete the veth (destroys both ends, wherever each lives) BEFORE the
  # netns: deleting the netns first can orphan smoke-veth1's namespace --
  # the veth peer keeps it alive with its bind-mount name already gone,
  # leaving an unreachable, unnamed namespace behind (seen empirically).
  ip link del smoke-veth0 2>/dev/null || true
  ip netns del smoke-client 2>/dev/null || true
  ip link del "$UPLINK2_IFACE" 2>/dev/null || true
  ip netns del "$UPLINK2_NETNS" 2>/dev/null || true
  ip link del geneve0 2>/dev/null || true
  ip addr del "${POD_IP}/32" dev lo 2>/dev/null || true
  ip addr del "${REPLACEMENT_POD_IP}/32" dev lo 2>/dev/null || true
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
# The eviction test's "replacement pod" phase below re-points a front at
# this address -- added up front alongside POD_IP so both aliases exist for
# the whole run, not just from the point they're first used.
ip addr add "${REPLACEMENT_POD_IP}/32" dev lo

echo "==> creating $UPLINK2_IFACE/$UPLINK2_PEER_IFACE + $UPLINK2_NETNS netns (second uplink, stands in for e.g. a WireGuard mesh alongside the public NIC above)"
ip link add "$UPLINK2_IFACE" type veth peer name "$UPLINK2_PEER_IFACE"
ip netns add "$UPLINK2_NETNS"
ip link set "$UPLINK2_PEER_IFACE" netns "$UPLINK2_NETNS"
ip addr add "${UPLINK2_VIP_IP}/24" dev "$UPLINK2_IFACE"
ip link set "$UPLINK2_IFACE" up
ip netns exec "$UPLINK2_NETNS" ip addr add "${UPLINK2_CLIENT_IP}/24" dev "$UPLINK2_PEER_IFACE"
ip netns exec "$UPLINK2_NETNS" ip link set "$UPLINK2_PEER_IFACE" up
ip netns exec "$UPLINK2_NETNS" ip link set lo up

# Required here AND on a real deployment (empirically confirmed against a
# single-node k3s cluster): the decapped inner packet's source is the
# external client, never reachable back out an address-less `geneve0`, so
# the kernel's reverse-path filter drops it by construction -- this
# fixture's `ip_rcv_finish_core`/IP_RPFILTER kfree_skb just makes that same
# drop visible locally via the `lo` (pod_ip alias) re-delivery. The shipped
# DaemonSet now sets this itself at startup (`beep::disable_rp_filter`,
# `deploy/README.md`'s REVISIT note); this harness still saves/restores it
# around its own run so it never leaves the VM's global rp_filter
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
    --uplink-iface smoke-veth0 --uplink-iface "$UPLINK2_IFACE" --geneve-iface geneve0 \
    --pin-dir "$PIN_DIR" \
    --pod-cidr "$POD_CIDR" --node-ip "$VIP_IP" \
    --fixture "${VIP_IP}:${VIP_PORT}:tcp:${VIP_IP}:${POD_IP}:${TARGET_PORT}" \
    --fixture "${VIP_IP}:${VIP_PORT2}:tcp:${VIP_IP}:${POD_IP}:${TARGET_PORT2}" \
    --fixture "${VIP_IP}:${VIP_PORT3}:udp:${FLOOD_BACKEND_NODE_IP}:${POD_IP}:${TARGET_PORT3}" \
    --fixture "${UPLINK2_VIP_IP}:${UPLINK2_VIP_PORT}:tcp:${VIP_IP}:${POD_IP}:${UPLINK2_TARGET_PORT}" \
    --fixture "${VIP_IP}:${EVICT_VIP_PORT}:tcp:${VIP_IP}:${EVICT_FRONT_POD_IP}:${EVICT_TARGET_PORT}" \
    >"$log" 2>&1 &
  # Not `local`: wait_for_attach (called right after, every time) reads
  # this. `kill -0 "$loader_pid"`, not `pgrep -f "$BIN"`: pgrep matches on
  # cmdline, which only becomes "$BIN" once execve() replaces the forked
  # shell's image -- on a contended runner that hasn't happened yet by
  # wait_for_attach's first, zero-delay iteration, so pgrep sees no match
  # and misreports a live loader as "exited" (root cause of nondeterministic
  # CI failures: two real GH Actions runs failed here ~15-26ms after launch
  # with an empty loader log, i.e. before the loader had even started, not
  # a verifier reject). kill -0 checks the PID directly, valid from fork()
  # onward regardless of exec() progress.
  loader_pid=$!
  disown
}

wait_for_attach() {
  local log="$1"
  for _ in $(seq 1 20); do
    grep -q "all 3 hooks attached" "$log" 2>/dev/null && return 0
    if ! kill -0 "$loader_pid" 2>/dev/null; then
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

# Stops the running loader and waits for it to actually exit before a
# restart starts a second instance against the same --pin-dir -- two
# concurrent instances would both attach_to_link-swap the same pinned links,
# racing each other instead of cleanly simulating a single rollout/eviction/
# OOM-kill restart.
stop_loader() {
  pkill -f "$BIN" 2>/dev/null || true
  for _ in $(seq 1 20); do
    pgrep -f "$BIN" >/dev/null || break
    sleep 0.2
  done
  pgrep -f "$BIN" >/dev/null && {
    echo "FAIL: old loader process did not exit before the restart" >&2
    exit 1
  }
  return 0
}

echo "==> loading beep-ebpf -- this is the verifier-accept gate"
# Two --fixture entries sharing one Pod IP but different VIP/target ports:
# the multi-port-Service scenario TARGET_PORTS' front-tuple keying exists
# to disambiguate.
start_loader "$LOADER_LOG"
wait_for_attach "$LOADER_LOG"

# Independent, kernel-truth confirmation (not just the loader's own log):
# a verifier rejection never reaches this state at all, since program.load()
# above would have returned Err and aborted the loader before this point.
# The `|| true` matters: grep -c exits nonzero when it counts zero matches,
# and under `pipefail` that would trip `set -e` on this assignment itself,
# exiting before the check below ever runs -- silently skipping the FAIL
# diagnostic on exactly the failure this check exists to report.
loaded=$(bpftool prog list | grep -cE 'name (uplink_ingress|geneve_ingress|uplink_egress_return)' || true)
# verifier_accept_check (scripts/verifier-accept-check.sh) dumps the loader
# log + samples eBPF map memory BEFORE deciding pass/fail, so a kernel-truth
# divergence caught below still gets both diagnostics instead of losing them.
verifier_accept_check "$loaded" "$LOADER_LOG" "$MEMORY_SCRIPT" "$PIN_DIR" "$MEMORY_OUT_DIR" || exit 1

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

echo "==> starting a backend responder for the second uplink's front on ${POD_IP}:${UPLINK2_TARGET_PORT}"
printf 'HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nOK3' > "$UPLINK2_RESPONSE_FILE"
nohup nc -l -N "$POD_IP" "$UPLINK2_TARGET_PORT" < "$UPLINK2_RESPONSE_FILE" >"$UPLINK2_BACKEND_LOG" 2>&1 &
disown
sleep 0.5

echo "==> driving a round trip through the SECOND configured uplink ($UPLINK2_IFACE)"
# The whole point of this check: if try_geneve_decap_return's redirect used
# the wrong ifindex (e.g. always the FIRST uplink's, a regression to the old
# single-uplink CONFIG.get(0) read), this response would be redirected out
# smoke-veth0 instead of $UPLINK2_IFACE -- landing on smoke-client's netns,
# which has no route to $UPLINK2_CLIENT_IP's subnet, not on $UPLINK2_NETNS.
# The client here would then simply time out rather than see a wrong body,
# so a plain success/failure check on THIS specific netns is enough to prove
# symmetric per-uplink return, with no extra ifindex introspection needed.
body3=$(ip netns exec "$UPLINK2_NETNS" curl -sS -m 5 "http://${UPLINK2_VIP_IP}:${UPLINK2_VIP_PORT}/")
[ "$body3" = "OK3" ] || {
  echo "FAIL: expected response body 'OK3' via the second uplink ($UPLINK2_IFACE), got: $body3 -- either this uplink was never admitted (UPLINK_CONFIG miss), or its return leg redirected out the wrong uplink's ifindex" >&2
  exit 1
}
echo "SECOND-UPLINK ROUND-TRIP: PASS (client ${UPLINK2_CLIENT_IP} via ${UPLINK2_IFACE} -> VIP ${UPLINK2_VIP_IP}:${UPLINK2_VIP_PORT} -> backend ${POD_IP}:${UPLINK2_TARGET_PORT} -> response 'OK3', returned via the SAME uplink it arrived on)"

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

# Same fallback-on-missing-pin caution as map_entry_count above.
map_json() {
  bpftool map dump pinned "$1" --json 2>/dev/null || echo "[]"
}

# `beep_common::wire_ip_v6`'s embedding: a jq array-literal of the "0xXX"
# hex-string tokens bpftool's --json dump uses for each byte (NOT plain
# integers -- confirmed against a live dump). Natural (non-reversed) octet
# order at bytes 12..16 -- the SAME convention POD_TARGETS' key,
# FWD_PENDING/FLOW_TABLE's Forward-tagged VALUE (`ForwardFlowValue.backend.
# pod_ip`), and FLOW_TABLE's Reverse/PortMemo-tagged KEY (`other_ip`) all
# use, unlike NODE_ALLOW's host-native REVERSED form (a different map, not
# touched by this eviction sweep).
pod_ip_v6_json_bytes() {
  local IFS=.
  local octets=($1)
  printf '["0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0xff","0xff","0x%02x","0x%02x","0x%02x","0x%02x"]' \
    "${octets[0]}" "${octets[1]}" "${octets[2]}" "${octets[3]}"
}

# True (jq -e exit 0) if POD_TARGETS still has an entry for pod IP $1.
pod_targets_has_pod() {
  local want
  want=$(pod_ip_v6_json_bytes "$1")
  map_json "$PIN_DIR/POD_TARGETS" | jq -e --argjson want "$want" 'any(.[]; .key == $want)' >/dev/null
}

# True if FWD_PENDING still has a row whose value's backend pod_ip (bytes
# 16..32 of `ForwardFlowValue`) is pod IP $1 -- FWD_PENDING's key never
# carries pod identity at all, only the value does.
fwd_pending_has_pod() {
  local want
  want=$(pod_ip_v6_json_bytes "$1")
  map_json "$PIN_DIR/FWD_PENDING" | jq -e --argjson want "$want" 'any(.[]; .value[16:32] == $want)' >/dev/null
}

# True if FLOW_TABLE still has a row decoding to pod IP $1 for ANY of its
# three roles: Forward-tagged (key[37] == "0x00") rows match on the VALUE's
# pod_ip (bytes 16..32, same layout as FWD_PENDING above); Reverse- and
# PortMemo-tagged rows (key[37] != "0x00") match on the KEY's own bytes
# 16..32 instead (`decode_tcp_flow_key`'s `other_ip`) -- both share the
# identical key-based match, so one clause covers both tags.
flow_table_has_pod() {
  local want
  want=$(pod_ip_v6_json_bytes "$1")
  map_json "$PIN_DIR/FLOW_TABLE" | jq -e --argjson want "$want" '
    any(.[];
      (.key[37] == "0x00" and .value[16:32] == $want) or
      (.key[37] != "0x00" and .key[16:32] == $want)
    )
  ' >/dev/null
}

echo "==> demonstrating the anti-flush property: a burst of new-flow-only packets must never evict an established FLOW_TABLE entry"
# The three round trips above (two fronts on the first uplink, one on the
# second) already promoted their flows into FLOW_TABLE (forward-tagged) and
# wrote their reverse-tagged counterparts. Flood a FOURTH, never-returning
# front (VIP_PORT3, see its definition above for why the flood can never
# produce a return leg, and therefore never reaches FLOW_TABLE at all --
# FLOOD_BACKEND_NODE_IP answers to nothing) from many distinct client
# source ports -- a stand-in for an off-path spoofed-source flood -- and
# confirm FLOW_TABLE's established entries survive untouched while
# FWD_PENDING absorbs the churn.
flow_before=$(map_entry_count "$PIN_DIR/FLOW_TABLE")
pending_before=$(map_entry_count "$PIN_DIR/FWD_PENDING")
[ -n "$flow_before" ] && [ "$flow_before" -ge 6 ] || {
  echo "FAIL: expected at least 6 FLOW_TABLE entries before the flood (forward+reverse tags for the three round trips above), got '$flow_before'" >&2
  exit 1
}
echo "before flood: FLOW_TABLE=$flow_before entries, FWD_PENDING=$pending_before entries"

FLOOD_COUNT=200
ip netns exec smoke-client bash -c "
  for i in \$(seq 1 $FLOOD_COUNT); do
    printf 'flood' | nc -u -q0 '$VIP_IP' '$VIP_PORT3' 2>/dev/null
  done
  true
"

flow_after=$(map_entry_count "$PIN_DIR/FLOW_TABLE")
pending_after=$(map_entry_count "$PIN_DIR/FWD_PENDING")
echo "after flood: FLOW_TABLE=$flow_after entries, FWD_PENDING=$pending_after entries"

[ -n "$pending_after" ] && [ "$pending_after" -gt "$pending_before" ] || {
  echo "FAIL: FWD_PENDING gained no entries from the $FLOOD_COUNT-packet flood ($pending_before -> $pending_after) -- the flood fixture itself never reached admission control, so this run proves nothing about the anti-flush property" >&2
  exit 1
}
[ "$flow_after" = "$flow_before" ] || {
  echo "FAIL: FLOW_TABLE entry count changed ($flow_before -> $flow_after) after a burst of $FLOOD_COUNT new-flow-only UDP packets that never received a return leg -- admission control must confine an unpromoted flood to FWD_PENDING and must never let it touch an established flow's FLOW_TABLE entry" >&2
  exit 1
}
echo "ANTI-FLUSH: PASS (FLOW_TABLE unchanged at $flow_after entries across a $FLOOD_COUNT-packet forward-only flood that grew FWD_PENDING from $pending_before to $pending_after)"

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
# by FLOW_TABLE surviving it, not by a fresh forward packet re-populating it.
#
# Baseline captured BEFORE the fixture below starts, not a bare ">0" gate
# after: FLOW_TABLE already holds the three earlier round trips' forward-
# and reverse-tagged entries, so this flow's own arrival must be seen as an
# INCREASE of (at least) 2 -- one forward-tagged entry from its return-leg
# promotion, one reverse-tagged entry from the backend's forward-decap --
# over that pre-existing count. Capturing it any later races the fixture:
# on a fast local VM the handshake below can complete (and both tags land)
# before this script gets back around to reading FLOW_TABLE, which would
# silently fold the very entries this check is waiting for into the
# "baseline" and make the +2 threshold unreachable.
flow_baseline=$(map_entry_count "$PIN_DIR/FLOW_TABLE")
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
  fwd_before=$(map_entry_count "$PIN_DIR/FLOW_TABLE")
  [ -n "$fwd_before" ] && [ "$fwd_before" -ge "$((flow_baseline + 2))" ] && break
  sleep 0.2
done
[ -n "$fwd_before" ] && [ "$fwd_before" -ge "$((flow_baseline + 2))" ] || {
  echo "FAIL: FLOW_TABLE (pinned at $PIN_DIR/FLOW_TABLE) never gained both a forward- and reverse-tagged entry for the restart-preservation flow within 6s (baseline $flow_baseline, saw $fwd_before) -- its handshake's return leg should have promoted the forward entry, and the backend's decap should have written the reverse entry, well before this timeout" >&2
  exit 1
}
echo "conntrack before restart: FLOW_TABLE=$fwd_before entries (baseline $flow_baseline)"

echo "==> restarting the loader against the same --pin-dir (simulates a DaemonSet image rollout/eviction/OOM kill)"
stop_loader
start_loader "$RESTART_LOADER_LOG"
wait_for_attach "$RESTART_LOADER_LOG"
echo "RESTART VERIFIER-ACCEPT: PASS"

fwd_after=$(map_entry_count "$PIN_DIR/FLOW_TABLE")
# Non-decreasing, not exact equality: an already-established flow's forward
# packets (e.g. a delayed TCP ACK) skip the FLOW_TABLE forward-tagged write
# entirely (admission control only writes it via return-leg promotion), but
# other legitimate traffic landing during the restart window can still mint
# a fresh entry for an unrelated flow -- observed live, harmlessly, on a
# correctly-fixed loader. What must never happen is entries LOST, especially
# a reset to zero, which is exactly what an unpinned restart does.
[ "$fwd_after" -ge "$fwd_before" ] || {
  echo "FAIL: conntrack entries did not survive the loader restart -- FLOW_TABLE ${fwd_before}->${fwd_after}. A restart must reuse the pinned maps, not swap in an empty set that silently drops every established flow." >&2
  exit 1
}
echo "RESTART MAP PRESERVATION: PASS (FLOW_TABLE=$fwd_after entries, unchanged or grown across the restart)"

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

echo "==> selective conntrack eviction: establishing a flow on a DEDICATED front to evict"
# A front of its own (EVICT_VIP_PORT/EVICT_TARGET_PORT), not reused from the
# round trips above, so this section's before/after assertions aren't
# confounded by conntrack rows those other flows already wrote for POD_IP.
printf 'HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nEVICT1' > "$EVICT_RESPONSE_FILE"
nohup nc -l -N "$POD_IP" "$EVICT_TARGET_PORT" < "$EVICT_RESPONSE_FILE" >"$EVICT_BACKEND_LOG" 2>&1 &
disown
sleep 0.5
evict_body=$(ip netns exec smoke-client curl -sS -m 5 "http://${VIP_IP}:${EVICT_VIP_PORT}/")
[ "$evict_body" = "EVICT1" ] || {
  echo "FAIL: expected response body 'EVICT1' from the dedicated eviction-test front, got: $evict_body" >&2
  exit 1
}
echo "EVICTION-FIXTURE ROUND-TRIP: PASS (established FWD_PENDING/promoted FLOW_TABLE forward+reverse state for pod ${POD_IP})"

echo "==> running the hidden 'beep evict-pod' one-shot for pod ${POD_IP}"
"$BIN" evict-pod --pin-dir "$PIN_DIR" "$POD_IP" || {
  echo "FAIL: 'beep evict-pod ${POD_IP}' exited nonzero" >&2
  exit 1
}

pod_targets_has_pod "$POD_IP" && {
  echo "FAIL: POD_TARGETS still contains an entry for evicted pod ${POD_IP}" >&2
  exit 1
}
echo "EVICTION ASSERTION 1/2 (POD_TARGETS): PASS (no entry for evicted pod ${POD_IP})"

fwd_pending_has_pod "$POD_IP" && {
  echo "FAIL: FWD_PENDING still has a row for evicted pod ${POD_IP} -- a departed pod's pre-promotion forward entry survived the sweep and could still be promoted into FLOW_TABLE by a later packet" >&2
  exit 1
}
flow_table_has_pod "$POD_IP" && {
  echo "FAIL: FLOW_TABLE still has a row (Forward-tagged value or Reverse/PortMemo-tagged key) for evicted pod ${POD_IP} -- the sweep left stale conntrack state that could misroute a future flow reusing this pod IP" >&2
  exit 1
}
echo "EVICTION ASSERTION 2/2 (FWD_PENDING + FLOW_TABLE): PASS (zero rows decode to evicted pod ${POD_IP} across all three roles: Forward/Reverse/PortMemo)"

echo "==> restarting the loader with a REPLACEMENT pod at the same front and confirming the sweep didn't wedge it"
EVICT_FRONT_POD_IP="$REPLACEMENT_POD_IP"
stop_loader
start_loader "$EVICT_LOADER_LOG_REPLACEMENT"
wait_for_attach "$EVICT_LOADER_LOG_REPLACEMENT"
printf 'HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nREPLACEMENT' > "$REPLACEMENT_RESPONSE_FILE"
nohup nc -l -N "$REPLACEMENT_POD_IP" "$EVICT_TARGET_PORT" < "$REPLACEMENT_RESPONSE_FILE" >"$REPLACEMENT_BACKEND_LOG" 2>&1 &
disown
sleep 0.5
replacement_body=$(ip netns exec smoke-client curl -sS -m 5 "http://${VIP_IP}:${EVICT_VIP_PORT}/")
[ "$replacement_body" = "REPLACEMENT" ] || {
  echo "FAIL: expected response body 'REPLACEMENT' after re-pointing the front at a new backend pod, got: $replacement_body -- the eviction sweep must not wedge the front against a replacement endpoint" >&2
  exit 1
}
echo "REPLACEMENT-POD ROUND-TRIP: PASS (front now correctly reaches the replacement pod ${REPLACEMENT_POD_IP})"

echo "==> restarting the loader again, reusing the ORIGINAL (evicted) pod IP, and confirming the fresh flow isn't a resurrected stale one"
EVICT_FRONT_POD_IP="$POD_IP"
stop_loader
start_loader "$EVICT_LOADER_LOG_REUSE"
wait_for_attach "$EVICT_LOADER_LOG_REUSE"
printf 'HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nREUSE' > "$REUSE_RESPONSE_FILE"
nohup nc -l -N "$POD_IP" "$EVICT_TARGET_PORT" < "$REUSE_RESPONSE_FILE" >"$REUSE_BACKEND_LOG" 2>&1 &
disown
sleep 0.5
reuse_body=$(ip netns exec smoke-client curl -sS -m 5 "http://${VIP_IP}:${EVICT_VIP_PORT}/")
[ "$reuse_body" = "REUSE" ] || {
  echo "FAIL: expected response body 'REUSE' from the reused pod IP, got: $reuse_body" >&2
  exit 1
}
flow_table_has_pod "$POD_IP" || {
  echo "FAIL: FLOW_TABLE has no row decoding to pod ${POD_IP} after the reused-IP round trip succeeded -- the flow can't have actually routed through beep-ebpf's conntrack path, so this isn't proving anything about pod-IP reuse" >&2
  exit 1
}
echo "POD-IP-REUSE ROUND-TRIP: PASS (fresh flow through reused pod IP ${POD_IP} routes correctly; provably NOT a resurrected stale entry, since the EVICTION ASSERTION above already proved zero rows for this pod survived before this new flow was ever established)"

echo "==> anti-spoof negative test: removing this fixture's own NODE_ALLOW entry and confirming geneve_ingress now DROPS its (unchanged) outer tunnel source"
# This fixture is a self-loop (VIP_IP is also this node's own address, and
# `--node-ip $VIP_IP` seeded NODE_ALLOW with it), so every Geneve packet
# geneve_ingress decaps here genuinely arrives with outer source == VIP_IP.
# Deleting VIP_IP's NODE_ALLOW entry directly (bpftool, not a loader
# restart) changes ONLY the peer-attestation gate under test -- a restart
# with a different --node-ip would ALSO re-prune POD_TARGETS (scoped to
# node_ip too), confounding which gate caused a subsequent drop.
#
# NODE_ALLOW's key is `[u8; 16]` (widened for dual-stack), holding the
# host-native (`u32::from(Ipv4Addr)`, not `wire_ip` --
# `beep_common::DesiredEntries::node_allow`'s doc comment) value wrapped in
# `ipv4_mapped_v6`: a `::ffff:0:0/96`-prefixed IPv6 address (10 zero bytes,
# then `0xff 0xff`) with the host-native u32 copied verbatim into the last 4
# bytes. On this little-endian target that u32 serializes to an IP's own
# octets in REVERSE (LSB-first) order -- e.g. 203.0.113.1 -> trailing bytes
# [1, 113, 0, 203]. bpftool's `key` argument takes exactly that raw
# in-memory 16-byte sequence.
node_allow_key_bytes() {
  local IFS=.
  local octets=($1)
  echo "0 0 0 0 0 0 0 0 0 0 255 255 ${octets[3]} ${octets[2]} ${octets[1]} ${octets[0]}"
}
VIP_NODE_ALLOW_KEY=$(node_allow_key_bytes "$VIP_IP")
bpftool map delete pinned "$PIN_DIR/NODE_ALLOW" key $VIP_NODE_ALLOW_KEY || {
  echo "FAIL: could not delete VIP_IP's NODE_ALLOW entry (key bytes: $VIP_NODE_ALLOW_KEY) -- either bpftool's key syntax is wrong or NODE_ALLOW never contained this fixture's own outer tunnel source in the first place" >&2
  exit 1
}

spoof_rc=0
spoof_body=$(ip netns exec smoke-client curl -sS -m 3 "http://${VIP_IP}:${VIP_PORT}/" 2>/dev/null) || spoof_rc=$?
[ "$spoof_rc" -ne 0 ] && [ "$spoof_body" != "OK" ] || {
  echo "FAIL: client round trip through VIP ${VIP_IP}:${VIP_PORT} unexpectedly SUCCEEDED (body '$spoof_body', curl rc $spoof_rc) after this fixture's real outer tunnel source (${VIP_IP}) was removed from NODE_ALLOW -- geneve_ingress must drop a decap whose outer source (tkey.remote_ipv4) has no NODE_ALLOW entry, not decap and deliver it" >&2
  exit 1
}
echo "ANTI-SPOOF: PASS (round trip through VIP ${VIP_IP}:${VIP_PORT} correctly dropped once its own NODE_ALLOW entry was removed -- curl rc=$spoof_rc)"

echo "==> sampling eBPF map memory + loader RSS (after round trip, before cleanup)"
bash "$MEMORY_SCRIPT" once --pin-dir "$PIN_DIR" --out-dir "$MEMORY_OUT_DIR" || echo "WARN: eBPF memory sampling failed -- continuing (monitoring gap, not a smoke-test failure)" >&2

echo "==> ebpf-map-memory.csv:"
cat "$MEMORY_OUT_DIR/ebpf-map-memory.csv" 2>/dev/null || echo "  (not captured -- see WARN above)"
echo "==> loader-rss.csv:"
cat "$MEMORY_OUT_DIR/loader-rss.csv" 2>/dev/null || echo "  (not captured -- see WARN above)"
