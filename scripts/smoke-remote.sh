#!/usr/bin/env bash
# VM-side half of scripts/smoke.sh. Copied into the Lima VM and
# run there as root by smoke.sh -- not meant to be invoked directly by a
# human. Builds a self-contained veth-pair + netns fixture so the whole
# client->front->backend round trip happens on ONE VM (the original
# hand-verification used a second physical Lima VM as the client; a
# reproducible harness can't depend on a peer machine being available).
# Owns geneve0 and the smoke-veth0/smoke-client fixture
# exclusively for its duration -- do not run this alongside a real
# beep deployment on the same VM.
#
# tcpdump is required: the full-size wire assertions (forward Geneve option
# bytes, 1588-byte frames) and the count-0 silence capture are only checkable on
# the wire, and a silently skipped assertion is not a pass. Without tcpdump the
# run FAILS. Set BEEP_SMOKE_ALLOW_NO_TCPDUMP=1 on a local dev host to skip
# those assertions (loudly) and check only payload integrity / client behaviour.
set -euo pipefail

# Succeeds when tcpdump is usable; with the opt-out set, returns 1 after a
# WARN so the caller skips its wire assertion. Otherwise exits non-zero.
have_tcpdump() { # <what is skipped>
  command -v tcpdump >/dev/null && return 0
  if [ "${BEEP_SMOKE_ALLOW_NO_TCPDUMP:-0}" = "1" ]; then
    echo "WARN: tcpdump not installed and BEEP_SMOKE_ALLOW_NO_TCPDUMP=1 -- $1 SKIPPED" >&2
    return 1
  fi
  echo "FAIL: tcpdump not installed -- $1 cannot run; install tcpdump (or set BEEP_SMOKE_ALLOW_NO_TCPDUMP=1 on a dev host to skip)" >&2
  exit 1
}

# tcpdump only captures from the moment it prints "listening on" (its socket
# is open and the filter attached) to stderr; a fixed sleep after launching it
# loses the race on a slow guest and yields an empty capture. Blocks until
# every named stderr log has that line.
wait_tcpdump_listening() { # <stderr-log>...
  local log i
  for log in "$@"; do
    for ((i = 0; i < 100; i++)); do
      grep -q "listening on" "$log" 2>/dev/null && continue 2
      sleep 0.1
    done
    echo "FAIL: tcpdump never reported 'listening on' within 10s (log ${log}) -- the wire capture cannot be trusted" >&2
    cat "$log" >&2 || true
    exit 1
  done
}

# RFC 5737 documentation ranges: deliberately disjoint from any real subnet
# a given VM's CNI/pod network happens to be using.
FRONT_IP="203.0.113.1"
CLIENT_IP="203.0.113.2"
FRONT_PORT="19100"
POD_IP="198.51.100.53"
# Covers POD_IP (TEST-NET-2) while staying disjoint from FRONT_IP/CLIENT_IP
# (TEST-NET-3) -- exercises the front-outside-pod-cidr startup check against a
# legitimate config, which must load, not reject.
POD_CIDR="198.51.100.0/24"
TARGET_PORT="18080"
# A second Service port on the SAME Pod (multi-port Service, e.g. 80->8080
# alongside 443->8443) -- proves the backend's FRONT_ENDPOINTS lookup resolves
# each front independently instead of collapsing both onto whichever
# target port was written last (the bug this fixture guards against: a
# pod-IP-only key can't tell these two fronts apart at all).
FRONT_PORT2="19101"
TARGET_PORT2="18081"
# A third front for the anti-flush (FWD_PENDING-churn-vs-FLOW_TABLE-survival)
# demonstration below: UDP, so a burst never needs a real handshake, and
# `FLOOD_BACKEND_NODE_IP` is deliberately an address nothing on this VM
# answers to -- the encap'd packet has nowhere to complete a round trip, so
# every flood packet MUST mint into FWD_PENDING and can never be promoted
# into FLOW_TABLE (admission control's only mint site is the forward path;
# promotion requires an observed return leg, which this front can never
# produce).
FRONT_PORT3="19102"
TARGET_PORT3="18082"
FLOOD_BACKEND_NODE_IP="203.0.113.250"
# A SECOND configured uplink -- proves the multi-symmetric-uplink design
# (docs/decisions/servicelb-multi-symmetric-uplink.md): a node admitting
# client traffic on N uplinks must return each flow via the SAME uplink it
# arrived on. TEST-NET-1, deliberately disjoint from the first uplink's
# TEST-NET-3 subnet above and from POD_CIDR's TEST-NET-2 -- a genuinely
# separate physical path, not just a second cable on the same wire.
# `backend_node_ip` for this uplink's fixture is still FRONT_IP (this node's
# own self-loop identity, unaffected by which uplink admitted the packet).
UPLINK2_IFACE="smoke-veth2"
UPLINK2_PEER_IFACE="smoke-veth3"
UPLINK2_NETNS="smoke-client2"
UPLINK2_FRONT_IP="192.0.2.1"
UPLINK2_CLIENT_IP="192.0.2.2"
UPLINK2_FRONT_PORT="19103"
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
# Restart-preservation fixture: reuses the first FRONT_IP:PORT ->
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
EVICT_FRONT_PORT="19104"
EVICT_TARGET_PORT="18084"
EVICT_FRONT_POD_IP="$POD_IP"
# Cold-neighbor-cache fixture: its own front so the control's half-open flow
# can't pollute any other section's listener.
COLD_FRONT_PORT="19105"
COLD_TARGET_PORT="18085"
# Two fronts onto ONE pod:targetPort, driven from one fixed client source
# port: the second flow collides on the backend's reverse key, so the ingress
# remaps its source port and persists the decision as a port_memo entry.
REMAP_FRONT_PORT_A="19106"
REMAP_FRONT_PORT_B="19107"
REMAP_TARGET_PORT="18086"
REMAP_CLIENT_PORT="40000"
# Pin-steering legs beyond the v4 established flow: a v6 front (v4 outer
# tunnel, as the dual-stack rigs run) re-pointed from POD6_A to POD6_B, and a
# UDP front whose only flow stays FWD_PENDING (its original backend node
# answers to nothing) when the front is re-pointed at this node. Both
# variables are read by `start_loader` at call time.
FRONT_IP6="2001:db8:5::1"
CLIENT_IP6="2001:db8:5::2"
POD6_A="2001:db8:6::53"
POD6_B="2001:db8:6::60"
PIN6_FRONT_PORT="19108"
PIN6_TARGET_PORT="18087"
# A second front on POD6_A keeps it in POD_TARGETS across the re-point (the
# v4 pod is kept by other fronts), so only the pin decides where a packet lands.
PIN6_KEEP_FRONT_PORT="19110"
PIN6_FRONT_POD_IP="$POD6_A"
PEND_FRONT_PORT="19109"
PEND_TARGET_PORT="18088"
PEND_CLIENT_PORT="41000"
PEND_BACKEND_NODE_IP="$FLOOD_BACKEND_NODE_IP"
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
  pkill -f "nc -l -N ${POD_IP} ${COLD_TARGET_PORT}" 2>/dev/null || true
  pkill -f "nc -l -N ${POD_IP} ${REMAP_TARGET_PORT}" 2>/dev/null || true
  pkill -f "nc -6 -l -N ${POD6_A} ${PIN6_TARGET_PORT}" 2>/dev/null || true
  pkill -f "nc -6 -l -N ${POD6_B} ${PIN6_TARGET_PORT}" 2>/dev/null || true
  pkill -f "nc -u -l ${POD_IP} ${PEND_TARGET_PORT}" 2>/dev/null || true
  pkill -f "nc ${FRONT_IP} ${FRONT_PORT}" 2>/dev/null || true
  pkill -f "tcpdump -nn -l -vv -i smoke-veth1" 2>/dev/null || true
  rm -rf "$PIN_DIR"
  rm -f /tmp/beep-smoke-response-remap-*.http /tmp/beep-smoke-response-pin6.http
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
  ip -6 addr del "${POD6_A}/128" dev lo 2>/dev/null || true
  ip -6 addr del "${POD6_B}/128" dev lo 2>/dev/null || true
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
  echo "FAIL: bpftool not found in the VM (install bpftool; Debian: bpftool, Ubuntu: linux-tools-\$(uname -r))" >&2
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
ip addr add "${FRONT_IP}/24" dev smoke-veth0
ip link set smoke-veth0 up
ip netns exec smoke-client ip addr add "${CLIENT_IP}/24" dev smoke-veth1
ip netns exec smoke-client ip link set smoke-veth1 up
ip netns exec smoke-client ip link set lo up
ip addr add "${POD_IP}/32" dev lo
# The eviction test's "replacement pod" phase below re-points a front at
# this address -- added up front alongside POD_IP so both aliases exist for
# the whole run, not just from the point they're first used.
ip addr add "${REPLACEMENT_POD_IP}/32" dev lo
ip -6 addr add "${POD6_A}/128" dev lo nodad
ip -6 addr add "${POD6_B}/128" dev lo nodad
ip addr add "${FRONT_IP6}/64" dev smoke-veth0 nodad
ip netns exec smoke-client ip addr add "${CLIENT_IP6}/64" dev smoke-veth1 nodad

echo "==> creating $UPLINK2_IFACE/$UPLINK2_PEER_IFACE + $UPLINK2_NETNS netns (second uplink, stands in for e.g. a WireGuard mesh alongside the public NIC above)"
ip link add "$UPLINK2_IFACE" type veth peer name "$UPLINK2_PEER_IFACE"
ip netns add "$UPLINK2_NETNS"
ip link set "$UPLINK2_PEER_IFACE" netns "$UPLINK2_NETNS"
ip addr add "${UPLINK2_FRONT_IP}/24" dev "$UPLINK2_IFACE"
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
    --pod-cidr "$POD_CIDR" --node-ip "$FRONT_IP" \
    --fixture "${FRONT_IP}:${FRONT_PORT}:tcp:${FRONT_IP}:${POD_IP}:${TARGET_PORT}" \
    --fixture "${FRONT_IP}:${FRONT_PORT2}:tcp:${FRONT_IP}:${POD_IP}:${TARGET_PORT2}" \
    --fixture "${FRONT_IP}:${FRONT_PORT3}:udp:${FLOOD_BACKEND_NODE_IP}:${POD_IP}:${TARGET_PORT3}" \
    --fixture "${UPLINK2_FRONT_IP}:${UPLINK2_FRONT_PORT}:tcp:${FRONT_IP}:${POD_IP}:${UPLINK2_TARGET_PORT}" \
    --fixture "${FRONT_IP}:${EVICT_FRONT_PORT}:tcp:${FRONT_IP}:${EVICT_FRONT_POD_IP}:${EVICT_TARGET_PORT}" \
    --fixture "${FRONT_IP}:${COLD_FRONT_PORT}:tcp:${FRONT_IP}:${POD_IP}:${COLD_TARGET_PORT}" \
    --fixture "${FRONT_IP}:${REMAP_FRONT_PORT_A}:tcp:${FRONT_IP}:${POD_IP}:${REMAP_TARGET_PORT}" \
    --fixture "${FRONT_IP}:${REMAP_FRONT_PORT_B}:tcp:${FRONT_IP}:${POD_IP}:${REMAP_TARGET_PORT}" \
    --fixture "[${FRONT_IP6}]:${PIN6_FRONT_PORT}:tcp:${FRONT_IP}:[${PIN6_FRONT_POD_IP}]:${PIN6_TARGET_PORT}" \
    --fixture "[${FRONT_IP6}]:${PIN6_KEEP_FRONT_PORT}:tcp:${FRONT_IP}:[${POD6_A}]:${PIN6_TARGET_PORT}" \
    --fixture "${FRONT_IP}:${PEND_FRONT_PORT}:udp:${PEND_BACKEND_NODE_IP}:${POD_IP}:${PEND_TARGET_PORT}" \
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
#
# Targets $loader_pid, not `pkill -f "$BIN"`: a cmdline match also hits any
# process whose arguments merely contain the binary's path as a prefix --
# e.g. the restart fixture's client, whose `> /tmp/beep-smoke-restart-client.out`
# redirect is part of its `bash -c` cmdline -- killing it mid-flow.
stop_loader() {
  kill "$loader_pid" 2>/dev/null || true
  for _ in $(seq 1 20); do
    kill -0 "$loader_pid" 2>/dev/null || break
    sleep 0.2
  done
  kill -0 "$loader_pid" 2>/dev/null && {
    echo "FAIL: old loader process did not exit before the restart" >&2
    exit 1
  }
  return 0
}

echo "==> loading beep-ebpf -- this is the verifier-accept gate"
# Two --fixture entries sharing one Pod IP but different front/target ports:
# the multi-port-Service scenario FRONT_ENDPOINTS' front-tuple keying exists
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
# fixture guards against is the backend DNAT-ing BOTH front ports to
# whichever target port a pod-IP-only key last happened to remember, which
# a same-body response would not catch.
printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK' > "$RESPONSE_FILE"
printf 'HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nOK2' > "$RESPONSE_FILE2"
nohup nc -l -N "$POD_IP" "$TARGET_PORT" < "$RESPONSE_FILE" >"$BACKEND_LOG" 2>&1 &
disown
nohup nc -l -N "$POD_IP" "$TARGET_PORT2" < "$RESPONSE_FILE2" >"$BACKEND_LOG2" 2>&1 &
disown
sleep 0.5

echo "==> driving one client -> front -> backend round trip"
body=$(ip netns exec smoke-client curl -sS -m 5 "http://${FRONT_IP}:${FRONT_PORT}/")
[ "$body" = "OK" ] || {
  echo "FAIL: expected response body 'OK', got: $body" >&2
  exit 1
}
echo "ROUND-TRIP: PASS (client ${CLIENT_IP} -> front ${FRONT_IP}:${FRONT_PORT} -> backend ${POD_IP}:${TARGET_PORT} -> response 'OK')"

echo "==> driving a second round trip through the SAME Pod's other Service port"
body2=$(ip netns exec smoke-client curl -sS -m 5 "http://${FRONT_IP}:${FRONT_PORT2}/")
[ "$body2" = "OK2" ] || {
  echo "FAIL: expected response body 'OK2' from the second Service port, got: $body2 -- a pod-IP-only backend key would DNAT this to the FIRST port's target instead" >&2
  exit 1
}
echo "MULTI-PORT ROUND-TRIP: PASS (client ${CLIENT_IP} -> front ${FRONT_IP}:${FRONT_PORT2} -> backend ${POD_IP}:${TARGET_PORT2} -> response 'OK2', distinct from the first Service port's target)"

# Drives one POST with a 256 KiB body and a 256 KiB reply through a front and
# checks, on the wire at the Geneve underlay (`lo`, since the backend node is
# this node): the forward option is the 24-byte pod-id TLV carrying the target
# port; a full-size (1500-byte inner) packet crossed in BOTH directions, so the
# 24-byte options fit; and neither payload was corrupted.
#   $1 label  $2 nc family flag  $3 pod ip  $4 backend port  $5 front url
#   $6 pod ip as 32 hex chars (v4 pods v4-mapped)  $7 target port as 4 hex chars (wire order)
FULL_PAYLOAD="/tmp/beep-smoke-full-payload.bin"
FULL_REPLY="/tmp/beep-smoke-full-reply.bin"
FULL_REQUEST_SEEN="/tmp/beep-smoke-full-request.bin"
FULL_GOT="/tmp/beep-smoke-full-got.bin"
FULL_FRAME_BYTES=1588 # 14 outer eth + 20 IP + 8 UDP + 8 Geneve + 24 option + 14 inner eth + 1500 inner IP
full_size_leg() {
  local label="$1" ncflag="$2" pod="$3" port="$4" url="$5" pod_hex="$6" port_hex="$7"
  local cap_opt=/tmp/beep-smoke-cap-opt.txt cap_fwd=/tmp/beep-smoke-cap-fwd.txt cap_ret=/tmp/beep-smoke-cap-ret.txt
  rm -f "$cap_opt" "$cap_fwd" "$cap_ret" "$FULL_REQUEST_SEEN" "$FULL_GOT"
  nohup bash -c "{ sleep 2; printf 'HTTP/1.1 200 OK\r\nContent-Length: 262144\r\nConnection: close\r\n\r\n'; cat ${FULL_REPLY}; } | nc ${ncflag} -l -N ${pod} ${port} >${FULL_REQUEST_SEEN} 2>/dev/null" >/dev/null 2>&1 &
  disown
  local wire=0
  if have_tcpdump "${label} wire assertions (option bytes, ${FULL_FRAME_BYTES}-byte frames)"; then
    wire=1
    rm -f "$cap_opt.err" "$cap_fwd.err" "$cap_ret.err"
    timeout 30 tcpdump -nn -l -U -i lo -c 1 -xx 'udp dst port 6081 and udp[14:1] = 100' >"$cap_opt" 2>"$cap_opt.err" &
    local opt_pid=$!
    timeout 30 tcpdump -nn -l -U -i lo -c 1 "udp dst port 6081 and udp[14:1] = 100 and len = ${FULL_FRAME_BYTES}" >"$cap_fwd" 2>"$cap_fwd.err" &
    local fwd_pid=$!
    timeout 30 tcpdump -nn -l -U -i lo -c 1 "udp dst port 6081 and udp[14:1] = 200 and len = ${FULL_FRAME_BYTES}" >"$cap_ret" 2>"$cap_ret.err" &
    local ret_pid=$!
    wait_tcpdump_listening "$cap_opt.err" "$cap_fwd.err" "$cap_ret.err"
  fi
  ip netns exec smoke-client curl -sS -g -m 30 -H 'Expect:' --data-binary "@${FULL_PAYLOAD}" -o "$FULL_GOT" "$url" || {
    echo "FAIL: ${label} full-size round trip did not complete" >&2
    exit 1
  }
  [ "$wire" -eq 0 ] || wait "$opt_pid" "$fwd_pid" "$ret_pid" || true
  cmp -s "$FULL_GOT" "$FULL_REPLY" || {
    echo "FAIL: ${label} reply body differs from the 256 KiB sent by the backend" >&2
    exit 1
  }
  tail -c 262144 "$FULL_REQUEST_SEEN" | cmp -s - "$FULL_PAYLOAD" || {
    echo "FAIL: ${label} request body the backend received differs from the 256 KiB the client sent" >&2
    exit 1
  }
  if [ "$wire" -eq 0 ]; then
    echo "FULL-SIZE ${label}: PARTIAL (BEEP_SMOKE_ALLOW_NO_TCPDUMP=1: wire-option/frame-size assertions SKIPPED; payload integrity PASS, 256 KiB each way)"
    return 0
  fi
  # Geneve header (8 bytes at frame offset 42: opt-len 6 words, Transparent
  # Ethernet Bridging, VNI 100) then the option: class ffff, type 01, 5 data
  # words, pod ip, target port, 2 pad bytes.
  local hex want
  hex=$(sed -n 's/^[[:space:]]*0x[0-9a-f]*:[[:space:]]*//p' "$cap_opt" | tr -d ' \n')
  want="0600655800006400ffff0105${pod_hex}${port_hex}0000"
  [ "${hex:84:64}" = "$want" ] || {
    echo "FAIL: ${label} forward Geneve header+option on the wire is '${hex:84:64}', expected '${want}' -- the forward option must be 24 bytes and carry the target port so decap needs no front lookup" >&2
    exit 1
  }
  [ -s "$cap_fwd" ] || {
    echo "FAIL: ${label} no forward-leg Geneve frame of exactly ${FULL_FRAME_BYTES} bytes seen on lo -- a full-size (1500-byte inner) packet with the 24-byte option never crossed" >&2
    exit 1
  }
  [ -s "$cap_ret" ] || {
    echo "FAIL: ${label} no return-leg Geneve frame of exactly ${FULL_FRAME_BYTES} bytes seen on lo" >&2
    exit 1
  }
  echo "FULL-SIZE ${label}: PASS (forward option on the wire = 24 B carrying port ${port_hex}; ${FULL_FRAME_BYTES}-byte Geneve frames crossed both directions; 256 KiB each way intact)"
}

echo "==> full-size packets: single-segment skbs so TCP emits 1500-byte packets instead of GSO aggregates"
head -c 262144 /dev/urandom > "$FULL_PAYLOAD"
head -c 262144 /dev/urandom > "$FULL_REPLY"
ip link set smoke-veth0 gso_max_size 1500
ip netns exec smoke-client ip link set smoke-veth1 gso_max_size 1500
full_size_leg "v4" "-4" "$POD_IP" "$TARGET_PORT" "http://${FRONT_IP}:${FRONT_PORT}/" \
  "00000000000000000000ffffc6336435" "$(printf '%04x' "$TARGET_PORT")"
full_size_leg "v6" "-6" "$POD6_A" "$PIN6_TARGET_PORT" "http://[${FRONT_IP6}]:${PIN6_FRONT_PORT}/" \
  "20010db8000600000000000000000053" "$(printf '%04x' "$PIN6_TARGET_PORT")"
ip link set smoke-veth0 gso_max_size 65536
ip netns exec smoke-client ip link set smoke-veth1 gso_max_size 65536

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
body3=$(ip netns exec "$UPLINK2_NETNS" curl -sS -m 5 "http://${UPLINK2_FRONT_IP}:${UPLINK2_FRONT_PORT}/")
[ "$body3" = "OK3" ] || {
  echo "FAIL: expected response body 'OK3' via the second uplink ($UPLINK2_IFACE), got: $body3 -- either this uplink was never admitted (UPLINK_CONFIG miss), or its return leg redirected out the wrong uplink's ifindex" >&2
  exit 1
}
echo "SECOND-UPLINK ROUND-TRIP: PASS (client ${UPLINK2_CLIENT_IP} via ${UPLINK2_IFACE} -> front ${UPLINK2_FRONT_IP}:${UPLINK2_FRONT_PORT} -> backend ${POD_IP}:${UPLINK2_TARGET_PORT} -> response 'OK3', returned via the SAME uplink it arrived on)"

echo "==> cold neighbor cache: the return leg's bpf_redirect_neigh must resolve a client the host has NO neighbour entry for"
# The client's own SYN normally warms the host's neighbour cache (the client
# ARPs for FRONT_IP, the host learns the client from the request), which is
# why the plain round trips above can't exercise resolution at all. A
# permanent client-side entry for the host removes that ARP, so nothing but
# the return leg itself can populate the host's entry for CLIENT_IP.
COLD_RESPONSE_FILE="/tmp/beep-smoke-response-cold.http"
COLD_BACKEND_LOG="/tmp/beep-smoke-backend-cold.log"
host_mac=$(cat /sys/class/net/smoke-veth0/address)
ip netns exec smoke-client ip neigh replace "$FRONT_IP" lladdr "$host_mac" dev smoke-veth1 nud permanent
printf 'HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nCOLD' > "$COLD_RESPONSE_FILE"

host_neigh() { ip -4 neigh show "$CLIENT_IP" dev smoke-veth0; }
flush_host_neigh_and_assert_absent() {
  ip neigh del "$CLIENT_IP" dev smoke-veth0 2>/dev/null || true
  local entry
  entry=$(host_neigh)
  [ -z "$entry" ] || {
    echo "FAIL: host still has a neighbour entry for ${CLIENT_IP} after flush ('$entry') -- the cold-cache premise does not hold" >&2
    exit 1
  }
}

echo "==> control: client answers no ARP (arp off), so a cold return leg CANNOT resolve -- the round trip must fail"
ip netns exec smoke-client ip link set smoke-veth1 arp off
nohup nc -l -N "$POD_IP" "$COLD_TARGET_PORT" < "$COLD_RESPONSE_FILE" >"$COLD_BACKEND_LOG" 2>&1 &
cold_nc_pid=$!
disown
sleep 0.5
flush_host_neigh_and_assert_absent
if control_body=$(ip netns exec smoke-client curl -sS -m 3 "http://${FRONT_IP}:${COLD_FRONT_PORT}/" 2>&1); then
  echo "FAIL: cold-neighbor control succeeded ('$control_body') although the client could never answer ARP -- the return leg is NOT depending on neighbour resolution, so the variant below proves nothing" >&2
  exit 1
fi
control_entry=$(host_neigh)
case "$control_entry" in
  *lladdr*) echo "FAIL: control resolved ${CLIENT_IP} ('$control_entry') despite arp off on the client" >&2; exit 1 ;;
  *INCOMPLETE*|*FAILED*) ;;
  *) echo "FAIL: control left host neighbour for ${CLIENT_IP} '${control_entry:-absent}', expected INCOMPLETE|FAILED -- the return leg never attempted resolution, so the control's failure is not about ARP" >&2; exit 1 ;;
esac
echo "COLD-NEIGHBOR CONTROL: PASS (unresolvable client => round trip failed and host neighbour is '${control_entry:-absent}' -- success below can only come from real resolution)"
kill "$cold_nc_pid" 2>/dev/null || true
ip netns exec smoke-client ip link set smoke-veth1 arp on

echo "==> cold-cache round trip: flush the host's entry for ${CLIENT_IP}, then drive the flow"
nohup nc -l -N "$POD_IP" "$COLD_TARGET_PORT" < "$COLD_RESPONSE_FILE" >"$COLD_BACKEND_LOG" 2>&1 &
cold_nc_pid=$!
disown
sleep 0.5
flush_host_neigh_and_assert_absent
cold_body=$(ip netns exec smoke-client curl -sS -m 8 "http://${FRONT_IP}:${COLD_FRONT_PORT}/") || {
  echo "FAIL: round trip with a cold host neighbour cache did not complete -- bpf_redirect_neigh failed to resolve ${CLIENT_IP} on the return leg" >&2
  exit 1
}
[ "$cold_body" = "COLD" ] || {
  echo "FAIL: expected body 'COLD' on the cold-cache round trip, got: $cold_body" >&2
  exit 1
}
cold_entry=$(host_neigh)
case "$cold_entry" in
  *lladdr*) ;;
  *) echo "FAIL: reply was delivered but the host's neighbour for ${CLIENT_IP} is '${cold_entry:-absent}', not resolved (no lladdr)" >&2; exit 1 ;;
esac
kill "$cold_nc_pid" 2>/dev/null || true
ip netns exec smoke-client ip neigh del "$FRONT_IP" dev smoke-veth1 2>/dev/null || true
echo "COLD-NEIGHBOR ROUND-TRIP: PASS (neighbour for ${CLIENT_IP} absent before the flow, '${cold_entry}' after; response 'COLD' delivered)"

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

echo "==> port remap: a second front onto the same pod:targetPort from the same client source port must round-trip AND persist a zero-tailed port_memo entry"
remap_started=$SECONDS
# Fixed client port 40000 to front A then front B: both flows decap to the same
# reverse key (client, 40000, pod, target), so front B's flow is remapped and
# its decision memoized under key tag 02. The memo's value is 2 bytes of a 40
# byte slot; the other 38 must be zero rather than eBPF stack residue.
#
# Flow A must still hold its row when B arrives, and a cleanly closed
# connection's rows are reclaimed. So A's pod-side listener is frozen
# (SIGSTOP) after accepting: the client's FIN is acknowledged by the kernel
# but the pod never closes, leaving A half-closed with its row alive. Flow
# B's body arrives after a pause so its memo can be read while B is live,
# then B closes cleanly and its memo must be reclaimed.
nohup nc -l -d "$POD_IP" "$REMAP_TARGET_PORT" >/dev/null 2>&1 &
remap_srv_a=$!
disown
sleep 0.5
{ printf 'GET / HTTP/1.0\r\nHost: beep\r\n\r\n'; sleep 10; } \
  | timeout 3 ip netns exec smoke-client nc -p "$REMAP_CLIENT_PORT" "$FRONT_IP" "$REMAP_FRONT_PORT_A" >/dev/null 2>&1 &
remap_cli_a=$!
sleep 1
kill -STOP "$remap_srv_a"
wait "$remap_cli_a" || true
# The killed client's socket lingers on the fixed source port and curl's
# explicit bind() cannot reuse it (rc 45, EADDRINUSE). Destroy it if the
# kernel allows, else wait it out.
ip netns exec smoke-client ss -K -tan sport = ":${REMAP_CLIENT_PORT}" >/dev/null 2>&1 || true
if [ -n "$(ip netns exec smoke-client ss -Htan sport = ":${REMAP_CLIENT_PORT}")" ]; then
  echo "WARN: ss -K did not free client port ${REMAP_CLIENT_PORT} (kernel likely lacks CONFIG_INET_DIAG_DESTROY); waiting out the lingering socket (up to 70s)" >&2
fi
for _ in $(seq 1 70); do
  [ -z "$(ip netns exec smoke-client ss -Htan sport = ":${REMAP_CLIENT_PORT}")" ] && break
  sleep 1
done
{ printf 'HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\n'; sleep 8; printf 'REMAPB'; } \
  | nohup nc -l "$POD_IP" "$REMAP_TARGET_PORT" >/dev/null 2>&1 &
disown
sleep 0.5
remap_rc_file=/tmp/beep-smoke-remap-rc-B
rm -f "$remap_rc_file"
( rc=0; ip netns exec smoke-client curl -sS -m 30 --local-port "$REMAP_CLIENT_PORT" \
    "http://${FRONT_IP}:${REMAP_FRONT_PORT_B}/" > /tmp/beep-smoke-remap-body-B 2> /tmp/beep-smoke-remap-err-B || rc=$?
  echo "$rc" > "$remap_rc_file" ) &
remap_pid=$!
sleep 2.5
remap_memos=$(map_json "$PIN_DIR/FLOW_TABLE" | jq -c '[.[] | select(.key[37] == "0x02")]')
echo "port_memo entries while flow B is live (key tag 02): $remap_memos"
[ "$(jq 'length' <<<"$remap_memos")" -ge 1 ] || {
  echo "FAIL: no port_memo (key tag 02) FLOW_TABLE entry after two fronts onto ${POD_IP}:${REMAP_TARGET_PORT} from client port ${REMAP_CLIENT_PORT} -- the remap path was never exercised, so the zero-tail check proves nothing" >&2
  exit 1
}
jq -e 'all(.[]; (.value | length) == 40 and all(.value[2:40][]; . == "0x00"))' <<<"$remap_memos" >/dev/null || {
  echo "FAIL: a port_memo value has non-zero bytes in 2..40 (or is not 40 bytes) -- the FlowValue constructor leaks eBPF stack into the map" >&2
  exit 1
}
wait "$remap_pid"
[ "$(cat "$remap_rc_file")" = "0" ] || {
  echo "FAIL: remap round trip via front ${FRONT_IP}:${REMAP_FRONT_PORT_B} (client port ${REMAP_CLIENT_PORT}) did not complete: $(cat /tmp/beep-smoke-remap-err-B)" >&2
  map_json "$PIN_DIR/FLOW_TABLE" | jq -c '.[]' >&2 || true
  exit 1
}
[ "$(cat /tmp/beep-smoke-remap-body-B)" = "REMAPB" ] || {
  echo "FAIL: expected body 'REMAPB' via front ${REMAP_FRONT_PORT_B}, got: $(cat /tmp/beep-smoke-remap-body-B)" >&2
  exit 1
}
sleep 1
remap_memos_left=$(map_json "$PIN_DIR/FLOW_TABLE" | jq -c '[.[] | select(.key[37] == "0x02")] | length')
[ "$remap_memos_left" = "0" ] || {
  echo "FAIL: ${remap_memos_left} port_memo row(s) left after the remapped connection closed cleanly (FIN both ways) -- a closed connection must release its memo" >&2
  map_json "$PIN_DIR/FLOW_TABLE" | jq -c '.[]' >&2 || true
  exit 1
}
kill -9 "$remap_srv_a" 2>/dev/null || true
echo "PORT-REMAP: PASS in $((SECONDS - remap_started))s (both fronts round-tripped from client port ${REMAP_CLIENT_PORT}; port_memo value bytes 2..40 are zero; the memo was reclaimed on clean close)"

echo "==> demonstrating the anti-flush property: a burst of new-flow-only packets must never evict an established FLOW_TABLE entry"
# The three round trips above (two fronts on the first uplink, one on the
# second) already promoted their flows into FLOW_TABLE (forward-tagged) and
# wrote their reverse-tagged counterparts. Flood a FOURTH, never-returning
# front (FRONT_PORT3, see its definition above for why the flood can never
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
    printf 'flood' | nc -u -q0 '$FRONT_IP' '$FRONT_PORT3' 2>/dev/null
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

ip netns exec smoke-client bash -c "timeout 30 nc ${FRONT_IP} ${FRONT_PORT} > ${RESTART_CLIENT_OUT}" &
# Not disowned: `wait` on a disowned pid returns 0 immediately without
# waiting, which would read the body below before chunk 2 has been delivered.
restart_client_pid=$!

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
kill -0 "$restart_client_pid" 2>/dev/null && {
  echo "FAIL: restart client (pid $restart_client_pid) still running after wait -- the body below would be read before the flow finished" >&2
  exit 1
}
restart_body="$(cat "$RESTART_CLIENT_OUT" 2>/dev/null || true)"
[ "$restart_body" = "${RESTART_CHUNK1}${RESTART_CHUNK2}" ] || {
  echo "FAIL: the flow held open across the loader restart stopped routing -- expected '${RESTART_CHUNK1}${RESTART_CHUNK2}', got '$restart_body'. Lost conntrack means the return leg is dropped/misrouted, even though the connection never closed." >&2
  exit 1
}
echo "RESTART FLOW CONTINUITY: PASS (client received both chunks across the loader restart: '$restart_body')"

echo "==> cap-change restart: an established front flow must survive a loader restart that recreates the front maps (changed --max-fronts), with nothing repopulating them before attach"
# Ingress passes a FRONT_META miss to the host, so a recreated-empty front map
# resets every established front flow until a controller reconciles. A
# fixture-less loader never repopulates the maps, so only the loader's own
# snapshot/restore can keep the flow alive. Data is sent AFTER the restart:
# the forward leg is the one that looks the front up.
CAPCHG_PING_BEFORE="capchg-ping-before"
CAPCHG_PING_AFTER="capchg-ping-after"
CAPCHG_CLIENT_FIFO="/tmp/beep-smoke-capchg-client-fifo"
CAPCHG_BACKEND_LOG="/tmp/beep-smoke-capchg-backend.log"
CAPCHG_LOADER_LOG="/tmp/beep-smoke-loader-capchg.log"
rm -f "$CAPCHG_CLIENT_FIFO" "$CAPCHG_BACKEND_LOG"
mkfifo "$CAPCHG_CLIENT_FIFO"
nohup nc -l -N "$POD_IP" "$TARGET_PORT" < <(sleep 40) >"$CAPCHG_BACKEND_LOG" 2>&1 &
disown
for _ in $(seq 1 30); do
  ss -ltnH "sport = :${TARGET_PORT}" | grep -q . && break
  sleep 0.1
done
( printf '%s' "$CAPCHG_PING_BEFORE"; read -r _ < "$RESTART_SIGNAL_FIFO"; printf '%s' "$CAPCHG_PING_AFTER"; sleep 10 ) > "$CAPCHG_CLIENT_FIFO" &
disown
ip netns exec smoke-client bash -c "timeout 35 nc ${FRONT_IP} ${FRONT_PORT} < ${CAPCHG_CLIENT_FIFO} > /dev/null" &
capchg_client_pid=$!
disown

capchg_backend_has() { grep -q "$1" "$CAPCHG_BACKEND_LOG" 2>/dev/null; }
for _ in $(seq 1 30); do
  capchg_backend_has "$CAPCHG_PING_BEFORE" && break
  sleep 0.2
done
capchg_backend_has "$CAPCHG_PING_BEFORE" || {
  echo "FAIL: the cap-change flow never reached the backend before the restart (backend log: $(cat "$CAPCHG_BACKEND_LOG" 2>/dev/null))" >&2
  exit 1
}
capchg_fronts_before=$(map_entry_count "$PIN_DIR/FRONT_META")

stop_loader
nohup "$BIN" \
  --uplink-iface smoke-veth0 --uplink-iface "$UPLINK2_IFACE" --geneve-iface geneve0 \
  --pin-dir "$PIN_DIR" \
  --pod-cidr "$POD_CIDR" --node-ip "$FRONT_IP" \
  --max-fronts 512 \
  >"$CAPCHG_LOADER_LOG" 2>&1 &
loader_pid=$!
disown
wait_for_attach "$CAPCHG_LOADER_LOG"

capchg_fronts_after=$(map_entry_count "$PIN_DIR/FRONT_META")
[ "$capchg_fronts_after" = "$capchg_fronts_before" ] && [ "$capchg_fronts_after" -gt 0 ] || {
  echo "FAIL: FRONT_META held $capchg_fronts_before fronts before a recreating restart and $capchg_fronts_after after, with no fixture to refill it -- established front flows would pass to the host until a controller reconciles. Loader log:" >&2
  cat "$CAPCHG_LOADER_LOG" >&2
  exit 1
}
release_restart_signal
for _ in $(seq 1 30); do
  capchg_backend_has "$CAPCHG_PING_AFTER" && break
  sleep 0.2
done
capchg_backend_has "$CAPCHG_PING_AFTER" || {
  echo "FAIL: the established flow broke across a cap-change loader restart -- data sent after it never reached the backend (backend log: $(cat "$CAPCHG_BACKEND_LOG" 2>/dev/null)). Loader log:" >&2
  cat "$CAPCHG_LOADER_LOG" >&2
  exit 1
}
echo "CAP-CHANGE RESTART FLOW CONTINUITY: PASS (FRONT_META kept $capchg_fronts_after fronts across a recreating restart; the held flow still delivered '$CAPCHG_PING_AFTER')"
kill "$capchg_client_pid" 2>/dev/null || true

echo "==> crash-safe migration: a loader that dies after unpinning the old front maps and before restoring them must not lose the entries"
# The fault hook aborts after the new maps exist and before the restore. Without
# the _migrating pin the next start finds matching, empty maps and keeps them.
CRASH_LOADER_LOG="/tmp/beep-smoke-loader-crash.log"
CRASH_RECOVER_LOG="/tmp/beep-smoke-loader-crash-recover.log"
stop_loader
crash_fronts_before=$(map_entry_count "$PIN_DIR/FRONT_META")
[ "$crash_fronts_before" -gt 0 ] || {
  echo "FAIL: FRONT_META is empty before the crash-safe migration stage; nothing to protect" >&2
  exit 1
}
if timeout 30 env BEEP_FAULT_ABORT_BEFORE_RESTORE=1 "$BIN" \
  --uplink-iface smoke-veth0 --uplink-iface "$UPLINK2_IFACE" --geneve-iface geneve0 \
  --pin-dir "$PIN_DIR" \
  --pod-cidr "$POD_CIDR" --node-ip "$FRONT_IP" \
  --max-fronts 1024 \
  >"$CRASH_LOADER_LOG" 2>&1; then
  echo "FAIL: the loader survived the injected pre-restore fault. Loader log:" >&2
  cat "$CRASH_LOADER_LOG" >&2
  exit 1
fi
grep -q "BEEP_FAULT_ABORT_BEFORE_RESTORE" "$CRASH_LOADER_LOG" || {
  echo "FAIL: the loader exited without hitting the injected fault (timeout or another error). Loader log:" >&2
  cat "$CRASH_LOADER_LOG" >&2
  exit 1
}
[ -e "$PIN_DIR/FRONT_META_migrating" ] || {
  echo "FAIL: no FRONT_META_migrating pin after the crash; the old entries are only in the dead loader's memory" >&2
  exit 1
}
nohup "$BIN" \
  --uplink-iface smoke-veth0 --uplink-iface "$UPLINK2_IFACE" --geneve-iface geneve0 \
  --pin-dir "$PIN_DIR" \
  --pod-cidr "$POD_CIDR" --node-ip "$FRONT_IP" \
  --max-fronts 1024 \
  >"$CRASH_RECOVER_LOG" 2>&1 &
loader_pid=$!
disown
wait_for_attach "$CRASH_RECOVER_LOG"
crash_fronts_after=$(map_entry_count "$PIN_DIR/FRONT_META")
[ "$crash_fronts_after" = "$crash_fronts_before" ] || {
  echo "FAIL: FRONT_META held $crash_fronts_before fronts before the crashed migration and $crash_fronts_after after the recovery restart. Loader log:" >&2
  cat "$CRASH_RECOVER_LOG" >&2
  exit 1
}
[ ! -e "$PIN_DIR/FRONT_META_migrating" ] && [ ! -e "$PIN_DIR/FRONT_ENDPOINTS_migrating" ] || {
  echo "FAIL: a _migrating pin outlived a successful restore" >&2
  exit 1
}
echo "CRASH-SAFE MIGRATION: PASS (FRONT_META recovered $crash_fronts_after fronts after a loader crash between unpin and restore)"

echo "==> restarting the loader with the standard fixtures and default caps (migrates back, refills fixtures)"
stop_loader
start_loader "$LOADER_LOG.capchg-restore"
wait_for_attach "$LOADER_LOG.capchg-restore"

echo "==> selective conntrack eviction: establishing a flow on a DEDICATED front to evict"
# A front of its own (EVICT_FRONT_PORT/EVICT_TARGET_PORT), not reused from the
# round trips above, so this section's before/after assertions aren't
# confounded by conntrack rows those other flows already wrote for POD_IP.
printf 'HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nEVICT1' > "$EVICT_RESPONSE_FILE"
nohup nc -l -N "$POD_IP" "$EVICT_TARGET_PORT" < "$EVICT_RESPONSE_FILE" >"$EVICT_BACKEND_LOG" 2>&1 &
disown
sleep 0.5
evict_body=$(ip netns exec smoke-client curl -sS -m 5 "http://${FRONT_IP}:${EVICT_FRONT_PORT}/")
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
replacement_body=$(ip netns exec smoke-client curl -sS -m 5 "http://${FRONT_IP}:${EVICT_FRONT_PORT}/")
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
reuse_body=$(ip netns exec smoke-client curl -sS -m 5 "http://${FRONT_IP}:${EVICT_FRONT_PORT}/")
[ "$reuse_body" = "REUSE" ] || {
  echo "FAIL: expected response body 'REUSE' from the reused pod IP, got: $reuse_body" >&2
  exit 1
}
flow_table_has_pod "$POD_IP" || {
  echo "FAIL: FLOW_TABLE has no row decoding to pod ${POD_IP} after the reused-IP round trip succeeded -- the flow can't have actually routed through beep-ebpf's conntrack path, so this isn't proving anything about pod-IP reuse" >&2
  exit 1
}
echo "POD-IP-REUSE ROUND-TRIP: PASS (fresh flow through reused pod IP ${POD_IP} routes correctly; provably NOT a resurrected stale entry, since the EVICTION ASSERTION above already proved zero rows for this pod survived before this new flow was ever established)"

echo "==> pin steering: a flow held open while its front is re-pointed at another pod must keep reaching the pod that holds its state"
PIN_STEER_FIFO="/tmp/beep-smoke-pin-steer-fifo"
PIN_DRAIN_FIFO="/tmp/beep-smoke-pin-drain-fifo"
PIN_STEER_BACKEND_IN="/tmp/beep-smoke-pin-steer-backend.in"
PIN_STEER_MSG="PINMSG"
PIN_DRAIN_MSG="PINDRAIN"
PIN_DRAIN2_FIFO="/tmp/beep-smoke-pin-drain2-fifo"
PIN_DRAIN2_MSG="PINSWAP2"
rm -f "$PIN_STEER_FIFO" "$PIN_DRAIN_FIFO" "$PIN_DRAIN2_FIFO" "$PIN_STEER_BACKEND_IN"
mkfifo "$PIN_STEER_FIFO" "$PIN_DRAIN_FIFO" "$PIN_DRAIN2_FIFO"
pin_flows_before=$(map_entry_count "$PIN_DIR/FLOW_TABLE")
nohup bash -c "sleep 60 | nc -l -N ${POD_IP} ${EVICT_TARGET_PORT} >${PIN_STEER_BACKEND_IN} 2>&1" >/dev/null 2>&1 &
disown
sleep 0.5
nohup ip netns exec smoke-client bash -c "( read -r _ < ${PIN_STEER_FIFO}; printf '%s' ${PIN_STEER_MSG}; read -r _ < ${PIN_DRAIN_FIFO}; printf '%s' ${PIN_DRAIN_MSG}; read -r _ < ${PIN_DRAIN2_FIFO}; printf '%s' ${PIN_DRAIN2_MSG} ) | timeout 60 nc ${FRONT_IP} ${EVICT_FRONT_PORT} >/dev/null 2>&1" >/dev/null 2>&1 &
disown
for _ in $(seq 1 30); do
  pin_flows_now=$(map_entry_count "$PIN_DIR/FLOW_TABLE")
  [ -n "$pin_flows_now" ] && [ "$pin_flows_now" -ge "$((pin_flows_before + 2))" ] && break
  sleep 0.2
done
[ -n "$pin_flows_now" ] && [ "$pin_flows_now" -ge "$((pin_flows_before + 2))" ] || {
  echo "FAIL: pin-steering flow never established in FLOW_TABLE (before $pin_flows_before, saw $pin_flows_now)" >&2
  exit 1
}
pin_want=$(pod_ip_v6_json_bytes "$POD_IP")
echo "FLOW_TABLE forward entries pinned to ${POD_IP} (bpftool):"
map_json "$PIN_DIR/FLOW_TABLE" | jq -c --argjson want "$pin_want" '.[] | select(.key[37] == "0x00" and .value[16:32] == $want)' | tail -n 2

PIN6_FIFO="/tmp/beep-smoke-pin6-fifo"
PIN6_BACKEND_IN="/tmp/beep-smoke-pin6-backend.in"
PIN6_MSG="PIN6MSG"
PEND_BACKEND_OUT="/tmp/beep-smoke-pend-backend.out"
rm -f "$PIN6_FIFO" "$PIN6_BACKEND_IN" "$PEND_BACKEND_OUT"
mkfifo "$PIN6_FIFO"
pin6_flows_before=$(map_entry_count "$PIN_DIR/FLOW_TABLE")
nohup bash -c "sleep 60 | nc -6 -l -N ${POD6_A} ${PIN6_TARGET_PORT} >${PIN6_BACKEND_IN} 2>&1" >/dev/null 2>&1 &
disown
sleep 0.5
nohup ip netns exec smoke-client bash -c "( read -r _ < ${PIN6_FIFO}; printf '%s' ${PIN6_MSG} ) | timeout 60 nc -6 ${FRONT_IP6} ${PIN6_FRONT_PORT} >/dev/null 2>&1" >/dev/null 2>&1 &
disown
for _ in $(seq 1 30); do
  pin6_flows_now=$(map_entry_count "$PIN_DIR/FLOW_TABLE")
  [ -n "$pin6_flows_now" ] && [ "$pin6_flows_now" -ge "$((pin6_flows_before + 2))" ] && break
  sleep 0.2
done
[ -n "$pin6_flows_now" ] && [ "$pin6_flows_now" -ge "$((pin6_flows_before + 2))" ] || {
  echo "FAIL: v6 pin-steering flow never established in FLOW_TABLE (before $pin6_flows_before, saw $pin6_flows_now)" >&2
  exit 1
}

# One packet of a flow that can never be promoted: its backend node answers to
# nothing, so the flow stays FWD_PENDING-only.
pend_before=$(map_entry_count "$PIN_DIR/FWD_PENDING")
printf 'PENDPKT1' | ip netns exec smoke-client nc -u -q0 -p "$PEND_CLIENT_PORT" "$FRONT_IP" "$PEND_FRONT_PORT" 2>/dev/null || true
sleep 0.5
pend_after=$(map_entry_count "$PIN_DIR/FWD_PENDING")
[ -n "$pend_after" ] && [ "$pend_after" -gt "$pend_before" ] || {
  echo "FAIL: the pending-pin flow's first packet minted no FWD_PENDING entry ($pend_before -> $pend_after) -- the leg below would not exercise the pending branch" >&2
  exit 1
}

forward_rows_for_bytes() {
  map_json "$PIN_DIR/FLOW_TABLE" | jq --argjson want "$1" '[.[] | select(.key[37] == "0x00" and .value[16:32] == $want)] | length'
}
pin6_want='["0x20","0x01","0x0d","0xb8","0x00","0x06","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x53"]'
pin_v4_rows_before=$(forward_rows_for_bytes "$pin_want")
pin6_rows_before=$(forward_rows_for_bytes "$pin6_want")
echo "FLOW_TABLE forward rows pinned to ${POD6_A} (bpftool):"
map_json "$PIN_DIR/FLOW_TABLE" | jq -c --argjson want "$pin6_want" '.[] | select(.key[37] == "0x00" and .value[16:32] == $want)' | tail -n 2
[ "$pin6_rows_before" -ge 1 ] || {
  echo "FAIL: no forward-tagged FLOW_TABLE row pinned to ${POD6_A} -- the v6 flow's pin was never stored, so the v6 leg below proves nothing" >&2
  exit 1
}

EVICT_FRONT_POD_IP="$REPLACEMENT_POD_IP"
PIN6_FRONT_POD_IP="$POD6_B"
PEND_BACKEND_NODE_IP="$FRONT_IP"
stop_loader
start_loader "$EVICT_LOADER_LOG_REPLACEMENT"
wait_for_attach "$EVICT_LOADER_LOG_REPLACEMENT"
pin_v4_rows_after=$(forward_rows_for_bytes "$pin_want")
pin6_rows_after=$(forward_rows_for_bytes "$pin6_want")
echo "RESTART-EVICTION (log only): forward rows pinned to old pod ${POD_IP} ${pin_v4_rows_before} -> ${pin_v4_rows_after}; to old pod ${POD6_A} ${pin6_rows_before} -> ${pin6_rows_after}"
printf '\n' 1<>"$PIN_STEER_FIFO"
for _ in $(seq 1 25); do
  grep -q "$PIN_STEER_MSG" "$PIN_STEER_BACKEND_IN" 2>/dev/null && break
  sleep 0.2
done
grep -q "$PIN_STEER_MSG" "$PIN_STEER_BACKEND_IN" 2>/dev/null || {
  echo "FAIL: after the front was re-pointed at ${REPLACEMENT_POD_IP}, a packet of the established flow did not reach its pinned pod ${POD_IP} (backend received: '$(cat "$PIN_STEER_BACKEND_IN" 2>/dev/null)'). Ingress re-resolved the front instead of following the pin, so a live connection would land on a pod with no state for it." >&2
  exit 1
}
echo "PIN-STEERING (established): PASS (flow kept pod ${POD_IP} after its front was re-pointed at ${REPLACEMENT_POD_IP})"
printf 'HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nREPLACEMENT' > "$REPLACEMENT_RESPONSE_FILE"
nohup nc -l -N "$REPLACEMENT_POD_IP" "$EVICT_TARGET_PORT" < "$REPLACEMENT_RESPONSE_FILE" >"$REPLACEMENT_BACKEND_LOG" 2>&1 &
disown
sleep 0.5
pin_new_body=$(ip netns exec smoke-client curl -sS -m 5 "http://${FRONT_IP}:${EVICT_FRONT_PORT}/")
[ "$pin_new_body" = "REPLACEMENT" ] || {
  echo "FAIL: a NEW flow after the re-point must reach ${REPLACEMENT_POD_IP}, got: $pin_new_body" >&2
  exit 1
}
echo "PIN-STEERING (new flow): PASS (a fresh flow followed the new endpoint ${REPLACEMENT_POD_IP})"

printf '\n' 1<>"$PIN6_FIFO"
for _ in $(seq 1 25); do
  grep -q "$PIN6_MSG" "$PIN6_BACKEND_IN" 2>/dev/null && break
  sleep 0.2
done
grep -q "$PIN6_MSG" "$PIN6_BACKEND_IN" 2>/dev/null || {
  echo "FAIL: after the v6 front was re-pointed at ${POD6_B}, a packet of the established v6 flow did not reach its pinned pod ${POD6_A} (backend received: '$(cat "$PIN6_BACKEND_IN" 2>/dev/null)'). The v6 ingress path re-resolved the front instead of following the pin." >&2
  exit 1
}
echo "PIN-STEERING (v6 established): PASS (v6 flow kept pod ${POD6_A} after its front was re-pointed at ${POD6_B})"
pkill -P "$(pgrep -f "sleep 60 \| nc -6 -l -N ${POD6_A} ${PIN6_TARGET_PORT}" | head -n1)" 2>/dev/null || true
pkill -f "sleep 60 \| nc -6 -l -N ${POD6_A} ${PIN6_TARGET_PORT}" 2>/dev/null || true
pkill -f "timeout 60 nc -6 ${FRONT_IP6} ${PIN6_FRONT_PORT}" 2>/dev/null || true
printf 'HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nREPLACEMENT6' > /tmp/beep-smoke-response-pin6.http
nohup nc -6 -l -N "$POD6_B" "$PIN6_TARGET_PORT" < /tmp/beep-smoke-response-pin6.http >/dev/null 2>&1 &
disown
sleep 0.5
pin6_new_body=$(ip netns exec smoke-client curl -sS -g -m 5 "http://[${FRONT_IP6}]:${PIN6_FRONT_PORT}/")
[ "$pin6_new_body" = "REPLACEMENT6" ] || {
  echo "FAIL: a NEW v6 flow after the re-point must reach ${POD6_B}, got: $pin6_new_body -- without this the v6 pin check above could pass because the front was never re-pointed" >&2
  exit 1
}
echo "PIN-STEERING (v6 new flow): PASS (a fresh v6 flow followed the new endpoint ${POD6_B})"

nohup nc -u -l "$POD_IP" "$PEND_TARGET_PORT" >"$PEND_BACKEND_OUT" 2>&1 &
disown
sleep 0.5
printf 'PENDPKT2' | ip netns exec smoke-client nc -u -q0 -p "$PEND_CLIENT_PORT" "$FRONT_IP" "$PEND_FRONT_PORT" 2>/dev/null || true
sleep 1
! grep -q PENDPKT2 "$PEND_BACKEND_OUT" || {
  echo "FAIL: after the front was re-pointed at this node, a later packet of a still-FWD_PENDING flow reached the NEW endpoint instead of its pending-pinned backend node ${FLOOD_BACKEND_NODE_IP}. Re-resolving a pre-promotion flow could move it to a backend the first packet never reached." >&2
  exit 1
}
printf 'NEWFLOW' | ip netns exec smoke-client nc -u -q0 -p "$((PEND_CLIENT_PORT + 1))" "$FRONT_IP" "$PEND_FRONT_PORT" 2>/dev/null || true
sleep 1
grep -q NEWFLOW "$PEND_BACKEND_OUT" || {
  echo "FAIL: a NEW flow to the re-pointed UDP front never reached the new endpoint (backend saw: '$(cat "$PEND_BACKEND_OUT" 2>/dev/null)') -- without this the pending-pin check above could pass because the front was never re-pointed" >&2
  exit 1
}
echo "PIN-STEERING (pending): PASS (a still-FWD_PENDING flow kept its original backend node after the re-point; a fresh flow reached the new endpoint)"

# Drain: the front's ready count drops to 0 (rolling update) while the pinned
# flow is still open. It must keep forwarding; only a NEW connection is silently dropped.
# Exercises the dataplane path directly: next generation, count 0, the previous
# generation's rows left in FRONT_ENDPOINTS. The controller does not yet write
# count 0 (it deletes FRONT_META for an empty set).
DRAIN_FRONT_KEY="0 0 0 0 0 0 0 0 0 0 255 255 $(echo "${FRONT_IP}" | tr . ' ') $((EVICT_FRONT_PORT >> 8)) $((EVICT_FRONT_PORT & 255)) 6 0"
drain_front_to_next_generation() {
  local gen_bytes gen
  gen_bytes=($(bpftool -j map lookup pinned "$PIN_DIR/FRONT_META" key $DRAIN_FRONT_KEY | jq -r '.value[0:4][]'))
  gen=$((gen_bytes[0] | gen_bytes[1] << 8 | gen_bytes[2] << 16 | gen_bytes[3] << 24))
  gen=$(((gen + 1) & 0xffffffff))
  bpftool map update pinned "$PIN_DIR/FRONT_META" key $DRAIN_FRONT_KEY value $((gen & 255)) $(((gen >> 8) & 255)) $(((gen >> 16) & 255)) $(((gen >> 24) & 255)) 0 0 0 0 0 0 0 0 || {
    echo "FAIL: could not zero the ready count of front ${FRONT_IP}:${EVICT_FRONT_PORT}" >&2
    exit 1
  }
}
drain_front_to_next_generation
printf '\n' 1<>"$PIN_DRAIN_FIFO"
for _ in $(seq 1 25); do
  grep -q "$PIN_DRAIN_MSG" "$PIN_STEER_BACKEND_IN" 2>/dev/null && break
  sleep 0.2
done
grep -q "$PIN_DRAIN_MSG" "$PIN_STEER_BACKEND_IN" 2>/dev/null || {
  echo "FAIL: after the front's ready count dropped to 0, a packet of the established flow did not reach its pinned pod ${POD_IP} (backend received: '$(cat "$PIN_STEER_BACKEND_IN" 2>/dev/null)'). A draining front must keep forwarding pinned flows; resetting them breaks live connections during a rolling update." >&2
  exit 1
}
echo "PIN-DRAIN (established): PASS (pinned flow kept forwarding with the front at count 0)"
drain_rc=0
ip netns exec smoke-client curl -sS -m 2 "http://${FRONT_IP}:${EVICT_FRONT_PORT}/" >/dev/null 2>&1 || drain_rc=$?
[ "$drain_rc" -eq 28 ] || {
  echo "FAIL: a NEW connection to the count-0 front must be silently dropped (curl rc 28), got rc=$drain_rc (7 = RST, 0/1/52 = reached a backend or the host)" >&2
  exit 1
}
echo "PIN-DRAIN (new flow): PASS (new connection timed out, rc=28)"
# A second swap at count 0: the controller deletes every non-live generation,
# so no endpoint row of the pinned flow's front survives. The backend must
# still deliver, because the target port travels in the Geneve option.
drain_front_to_next_generation
printf '\n' 1<>"$PIN_DRAIN2_FIFO"
for _ in $(seq 1 25); do
  grep -q "$PIN_DRAIN2_MSG" "$PIN_STEER_BACKEND_IN" 2>/dev/null && break
  sleep 0.2
done
grep -q "$PIN_DRAIN2_MSG" "$PIN_STEER_BACKEND_IN" 2>/dev/null || {
  echo "FAIL: after a second swap at count 0 left no endpoint rows for the front, a packet of the pinned flow did not reach ${POD_IP} (backend received: '$(cat "$PIN_STEER_BACKEND_IN" 2>/dev/null)'). Decap must take the target port from the forward Geneve option, not look the front up." >&2
  exit 1
}
echo "PIN-DRAIN (second swap): PASS (pinned flow kept forwarding with no endpoint rows left for its front)"
EVICT_FRONT_POD_IP="$POD_IP"
PIN6_FRONT_POD_IP="$POD6_A"
PEND_BACKEND_NODE_IP="$FLOOD_BACKEND_NODE_IP"
stop_loader
start_loader "$EVICT_LOADER_LOG_REUSE"
wait_for_attach "$EVICT_LOADER_LOG_REUSE"
pkill -f "nc -l -N ${POD_IP} ${EVICT_TARGET_PORT}" 2>/dev/null || true
rm -f "$PIN_STEER_FIFO" "$PIN_DRAIN_FIFO" "$PIN_DRAIN2_FIFO" "$PIN_STEER_BACKEND_IN" "$PIN6_FIFO" "$PIN6_BACKEND_IN" "$PEND_BACKEND_OUT"

echo "==> non-LB node egress: with this node's own address in POD_TARGETS (a hostNetwork backend), a fresh outbound connection from it must still leave the uplink"
# A hostNetwork backend's pod IP IS the node's address, so POD_TARGETS holds
# it; the node's own SSH/kubelet/apiserver connections then pass the hook-3
# source gate yet never have a Reverse FLOW_TABLE entry. Inserted directly
# (bpftool) rather than via --fixture so no other phase's state changes.
NODE_EGRESS_PORT="19200"
NODE_EGRESS_OUT="/tmp/beep-smoke-node-egress.out"
NODE_EGRESS_KEY="0 0 0 0 0 0 0 0 0 0 255 255 $(echo "${FRONT_IP}" | tr . ' ')"
bpftool map update pinned "$PIN_DIR/POD_TARGETS" key $NODE_EGRESS_KEY value 1 || {
  echo "FAIL: could not insert node address ${FRONT_IP} into POD_TARGETS (key bytes: $NODE_EGRESS_KEY)" >&2
  exit 1
}
rm -f "$NODE_EGRESS_OUT"
nohup ip netns exec smoke-client timeout 6 nc -l -N "$CLIENT_IP" "$NODE_EGRESS_PORT" >"$NODE_EGRESS_OUT" 2>&1 &
disown
sleep 0.5
echo "node-egress-payload" | nc -s "$FRONT_IP" -w 3 "$CLIENT_IP" "$NODE_EGRESS_PORT" >/dev/null 2>&1 || true
sleep 0.5
bpftool map delete pinned "$PIN_DIR/POD_TARGETS" key $NODE_EGRESS_KEY || true
grep -q "node-egress-payload" "$NODE_EGRESS_OUT" || {
  echo "FAIL: a fresh connection from the node's own address ${FRONT_IP} (present in POD_TARGETS like a hostNetwork backend) never reached ${CLIENT_IP}:${NODE_EGRESS_PORT} -- hook 3 must pass anything that is not a FLOW_TABLE reverse hit, otherwise the node's own SSH/kubelet egress dies on a hostNetwork-backend node" >&2
  exit 1
}
echo "NODE-EGRESS: PASS (fresh connection from ${FRONT_IP}, a POD_TARGETS member, passed hook 3 with no FLOW_TABLE reverse entry)"

echo "==> count-0 drop: an owned front with no ready backends must silently drop new flows (no RST, no ICMP, never the host stack)"
# Each owned front gets a FRONT_META row with count 0 (inserted directly, like
# the node-egress phase above) AND a live host listener on the same address:port.
# A pass-through would connect (TCP) or land in the UDP listener's file, and a
# reject would RST / send ICMP; only a silent drop leaves the client timing out
# with nothing on the wire and nothing delivered to the host.
FRONT_IP6_KEY="32 1 13 184 0 5 0 0 0 0 0 0 0 0 0 1"
FRONT_IP4_KEY="0 0 0 0 0 0 0 0 0 0 255 255 $(echo "${FRONT_IP}" | tr . ' ')"
DROP_TCP4_PORT=19300
DROP_UDP4_PORT=19301
DROP_TCP6_PORT=19302
DROP_UDP6_PORT=19303
CONTROL_TCP4_PORT=19304
CONTROL_TCP6_PORT=19305
DROP_CAPTURE="/tmp/beep-smoke-drop-capture.txt"
DROP_UDP4_RX="/tmp/beep-smoke-drop-udp4-rx.txt"
DROP_UDP6_RX="/tmp/beep-smoke-drop-udp6-rx.txt"
DROP_PROBE_SECS=2

set_front_count_zero() { # <key-ip-bytes> <port> <proto-number>
  bpftool map update pinned "$PIN_DIR/FRONT_META" key $1 $(($2 >> 8)) $(($2 & 255)) $3 0 value 0 0 0 0 0 0 0 0 0 0 0 0 || {
    echo "FAIL: could not insert a count-0 FRONT_META row (key ip bytes '$1', port $2)" >&2
    exit 1
  }
}
host_listener() { # <tcp|udp> <4|6> <addr> <port> [rx-file]
  if [ "$1" = tcp ]; then
    nohup timeout 40 bash -c "printf HOSTPASS | nc -$2 -l -N $3 $4" >/dev/null 2>&1 &
  else
    nohup timeout 40 nc -$2 -u -l "$3" "$4" >"$5" 2>/dev/null &
  fi
  disown
}
: >"$DROP_UDP4_RX"
: >"$DROP_UDP6_RX"
set_front_count_zero "$FRONT_IP4_KEY" "$DROP_TCP4_PORT" 6
set_front_count_zero "$FRONT_IP4_KEY" "$DROP_UDP4_PORT" 17
set_front_count_zero "$FRONT_IP6_KEY" "$DROP_TCP6_PORT" 6
set_front_count_zero "$FRONT_IP6_KEY" "$DROP_UDP6_PORT" 17
host_listener tcp 4 "$FRONT_IP" "$DROP_TCP4_PORT"
host_listener udp 4 "$FRONT_IP" "$DROP_UDP4_PORT" "$DROP_UDP4_RX"
host_listener tcp 6 "$FRONT_IP6" "$DROP_TCP6_PORT"
host_listener udp 6 "$FRONT_IP6" "$DROP_UDP6_PORT" "$DROP_UDP6_RX"
host_listener tcp 4 "$FRONT_IP" "$CONTROL_TCP4_PORT"
host_listener tcp 6 "$FRONT_IP6" "$CONTROL_TCP6_PORT"
sleep 1

DROP_CAPTURE_PID=""
if have_tcpdump "on-the-wire silence capture (client-side behaviour is still asserted)"; then
  ip netns exec smoke-client tcpdump -nn -l -vv -i smoke-veth1 >"$DROP_CAPTURE" 2>&1 &
  DROP_CAPTURE_PID=$!
  wait_tcpdump_listening "$DROP_CAPTURE"
fi

assert_tcp_dropped() { # <label> <curl-url> [curl-extra-arg]
  local rc=0
  ip netns exec smoke-client curl -sS -m "$DROP_PROBE_SECS" ${3:-} "$2" >/dev/null 2>&1 || rc=$?
  [ "$rc" -eq 28 ] || {
    echo "FAIL: $1: expected the client to time out (curl rc 28) against a silently dropped count-0 front, got rc=$rc (rc 7 = beep answered with a RST; rc 0/1/52 = the packet passed to the host listener)" >&2
    exit 1
  }
  echo "DROP-TCP ($1): PASS (curl rc=28, timed out with no answer)"
}
assert_udp_dropped() { # <label> <addr> <port> <host-listener-rx-file>
  local out rc=0
  out=$(ip netns exec smoke-client timeout $((DROP_PROBE_SECS + 4)) bash -c 'exec 3<>"/dev/udp/$0/$1"; printf probe >&3; read -r -t "$2" -u 3 _' "$2" "$3" "$DROP_PROBE_SECS" 2>&1) || rc=$?
  case "$out" in
    *"Connection refused"*)
      echo "FAIL: $1: the UDP probe to the count-0 front ${2}:${3} got an ICMP port unreachable; a drop must be silent" >&2
      exit 1
      ;;
  esac
  [ "$rc" -gt 128 ] || {
    echo "FAIL: $1: expected the UDP probe to time out silently (read rc > 128), got rc=$rc, output '$out'" >&2
    exit 1
  }
  [ ! -s "$4" ] || {
    echo "FAIL: $1: the datagram reached the host listener on ${2}:${3}; a count-0 front must drop it before the host stack" >&2
    exit 1
  }
  echo "DROP-UDP ($1): PASS (read timed out, no ICMP, nothing reached the host listener)"
}
assert_tcp_dropped "v4" "http://${FRONT_IP}:${DROP_TCP4_PORT}/"
assert_udp_dropped "v4" "$FRONT_IP" "$DROP_UDP4_PORT" "$DROP_UDP4_RX"
assert_tcp_dropped "v6" "http://[${FRONT_IP6}]:${DROP_TCP6_PORT}/" -g
assert_udp_dropped "v6" "$FRONT_IP6" "$DROP_UDP6_PORT" "$DROP_UDP6_RX"

control4=$(ip netns exec smoke-client nc -w 3 "$FRONT_IP" "$CONTROL_TCP4_PORT" </dev/null 2>&1 || true)
control6=$(ip netns exec smoke-client nc -6 -w 3 "$FRONT_IP6" "$CONTROL_TCP6_PORT" </dev/null 2>&1 || true)
[ "$control4" = "HOSTPASS" ] && [ "$control6" = "HOSTPASS" ] || {
  echo "FAIL: a front beep does not own (no FRONT_META row) must still pass to the host stack; v4 got '$control4', v6 got '$control6', expected HOSTPASS" >&2
  exit 1
}
echo "DROP-CONTROL: PASS (non-owned fronts on v4 and v6 still reach the host listener)"

if [ -n "$DROP_CAPTURE_PID" ]; then
  sleep 0.5
  kill "$DROP_CAPTURE_PID" 2>/dev/null || true
  wait "$DROP_CAPTURE_PID" 2>/dev/null || true
  # The probes must be visible (else a dead capture would pass vacuously);
  # nothing from the node on the count-0 ports (the control ports legitimately
  # answer) may be a RST, a SYN-ACK or an ICMP(v6) unreachable. The client's
  # own packets are not judged.
  # Counted per family: retries from one family must not satisfy the other's bar.
  syn4_count=$(grep -cF "> ${FRONT_IP}.${DROP_TCP4_PORT}: Flags [S]," "$DROP_CAPTURE" || true)
  syn6_count=$(grep -cF "> ${FRONT_IP6}.${DROP_TCP6_PORT}: Flags [S]," "$DROP_CAPTURE" || true)
  if [ "$syn4_count" -lt 1 ] || [ "$syn6_count" -lt 1 ]; then
    echo "FAIL: capture saw $syn4_count v4 and $syn6_count v6 client SYN(s), expected at least 1 of each: the capture is not seeing the probes of every family" >&2
    cat "$DROP_CAPTURE" >&2
    exit 1
  fi
  replies=$(grep -E "Flags \[(R|S\.)|unreachable" "$DROP_CAPTURE" | grep -E "1930[0-3]" || true)
  if [ -n "$replies" ]; then
    echo "FAIL: the node answered a count-0 front on the wire; a silent drop must leave no RST, SYN-ACK or unreachable:" >&2
    echo "$replies" >&2
    cat "$DROP_CAPTURE" >&2
    exit 1
  fi
  echo "DROP-WIRE: PASS (client saw $syn4_count v4 + $syn6_count v6 SYN(s) and no RST, SYN-ACK or unreachable from the node)"
fi
pkill -f "nc -[46] -l -N ${FRONT_IP}" 2>/dev/null || true
if [ -n "$DROP_CAPTURE_PID" ]; then
  echo "DROP: PASS (owned count-0 fronts silently drop TCP and UDP on v4+v6; non-owned fronts still pass to the host)"
else
  echo "DROP: PARTIAL (BEEP_SMOKE_ALLOW_NO_TCPDUMP=1: DROP-WIRE capture SKIPPED; client-side drop and host-pass control PASS)"
fi

echo "==> anti-spoof negative test: removing this fixture's own NODE_ALLOW entry and confirming geneve_ingress now DROPS its (unchanged) outer tunnel source"
# This fixture is a self-loop (FRONT_IP is also this node's own address, and
# `--node-ip $FRONT_IP` seeded NODE_ALLOW with it), so every Geneve packet
# geneve_ingress decaps here genuinely arrives with outer source == FRONT_IP.
# Deleting FRONT_IP's NODE_ALLOW entry directly (bpftool, not a loader
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
FRONT_NODE_ALLOW_KEY=$(node_allow_key_bytes "$FRONT_IP")
bpftool map delete pinned "$PIN_DIR/NODE_ALLOW" key $FRONT_NODE_ALLOW_KEY || {
  echo "FAIL: could not delete FRONT_IP's NODE_ALLOW entry (key bytes: $FRONT_NODE_ALLOW_KEY) -- either bpftool's key syntax is wrong or NODE_ALLOW never contained this fixture's own outer tunnel source in the first place" >&2
  exit 1
}

spoof_rc=0
spoof_body=$(ip netns exec smoke-client curl -sS -m 3 "http://${FRONT_IP}:${FRONT_PORT}/" 2>/dev/null) || spoof_rc=$?
[ "$spoof_rc" -ne 0 ] && [ "$spoof_body" != "OK" ] || {
  echo "FAIL: client round trip through front ${FRONT_IP}:${FRONT_PORT} unexpectedly SUCCEEDED (body '$spoof_body', curl rc $spoof_rc) after this fixture's real outer tunnel source (${FRONT_IP}) was removed from NODE_ALLOW -- geneve_ingress must drop a decap whose outer source (tkey.remote_ipv4) has no NODE_ALLOW entry, not decap and deliver it" >&2
  exit 1
}
echo "ANTI-SPOOF: PASS (round trip through front ${FRONT_IP}:${FRONT_PORT} correctly dropped once its own NODE_ALLOW entry was removed -- curl rc=$spoof_rc)"

echo "==> sampling eBPF map memory + loader RSS (after round trip, before cleanup)"
bash "$MEMORY_SCRIPT" once --pin-dir "$PIN_DIR" --out-dir "$MEMORY_OUT_DIR" || echo "WARN: eBPF memory sampling failed -- continuing (monitoring gap, not a smoke-test failure)" >&2

echo "==> ebpf-map-memory.csv:"
cat "$MEMORY_OUT_DIR/ebpf-map-memory.csv" 2>/dev/null || echo "  (not captured -- see WARN above)"
echo "==> loader-rss.csv:"
cat "$MEMORY_OUT_DIR/loader-rss.csv" 2>/dev/null || echo "  (not captured -- see WARN above)"
