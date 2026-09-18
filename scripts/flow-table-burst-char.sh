#!/usr/bin/env bash
# Characterizes the safe concurrent reverse-flow burst size before a
# dual-role node's ungated reverse writes start LRU-evicting an established
# forward entry from the shared FLOW_TABLE (see its doc comment in
# ebpf/src/main.rs for the accepted availability-only tradeoff this bounds).
#
# Reuses scripts/smoke.sh's build+copy+verifier-accept path (cross-build,
# copy the loader to the VM, load it once, confirm the round trip works,
# tear down) rather than re-implementing cargo zigbuild/limactl copy/limactl
# shell -- this script only adds its OWN fixture on top, using the binary
# smoke.sh already placed at /tmp/beep-smoke on the VM.
#
# Methodology: establish a handful of real forward round trips (some
# pre-established FLOW_TABLE forward-tagged entries), then drive
# GEOMETRICALLY-increasing concurrent reverse-role UDP bursts through a
# second front whose node-ip points back at this same node (so each packet's
# decap+DNAT step writes an unconditional reverse-tagged FLOW_TABLE entry,
# exactly the ungated write path the accepted tradeoff describes -- no
# listener or return leg required, see the reverse-role front below).
# `bpftool map dump --json`'s raw key bytes let us count entries by
# direction tag (offset 37, beep_common::FlowDirection: 0x00 Forward, 0x01
# Reverse) without needing BTF-based field names.
#
# HARD cap: the burst-sweep loop (not the whole script) must not run past
# WALL_CAP_SECS. It stops at the first observed forward-entry eviction OR
# the cap, whichever comes first -- it deliberately never drives a burst to
# completion past that.
#
# Usage: scripts/flow-table-burst-char.sh [--vm <lima-vm-name>]
set -euo pipefail

VM="beep-smoke"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vm) VM="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REMOTE_SCRIPT_LOCAL="$(mktemp /tmp/flow-table-burst-remote.XXXXXX)"

echo "==> [1/3] reusing scripts/smoke.sh's build+copy+verifier-accept path on $VM"
bash "$SCRIPT_DIR/smoke.sh" --vm "$VM"

cat >"$REMOTE_SCRIPT_LOCAL" <<'REMOTE_EOF'
#!/usr/bin/env bash
set -euo pipefail

# RFC 5737 documentation ranges, disjoint from smoke-remote.sh's own fixture
# addresses/ifnames so both can coexist (this script tears its own down
# before and after every run regardless).
VIP_IP="203.0.113.211"
CLIENT_IP="203.0.113.212"
POD_IP="198.51.100.213"
FWD_PORT="19400"
FWD_TARGET_PORT="18380"
REV_PORT="19401"
REV_TARGET_PORT="18381"
NUM_FORWARD=8
PIN_DIR="/sys/fs/bpf/flow-table-burst-char"
BIN="/tmp/beep-smoke"
LOADER_LOG="/tmp/flow-table-burst-loader.log"
WALL_CAP_SECS=90

cmd="${1:-}"

cleanup() {
  pkill -f "$BIN --uplink-iface fbveth0" 2>/dev/null || true
  pkill -f "nc -l -N ${POD_IP} ${FWD_TARGET_PORT}" 2>/dev/null || true
  rm -rf "$PIN_DIR"
  ip link del fbveth0 2>/dev/null || true
  ip netns del fbclient 2>/dev/null || true
  ip link del geneve0 2>/dev/null || true
  ip addr del "${POD_IP}/32" dev lo 2>/dev/null || true
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

command -v bpftool >/dev/null || { echo "FAIL: bpftool not found in the VM" >&2; exit 1; }
command -v jq >/dev/null || { echo "FAIL: jq not found in the VM" >&2; exit 1; }

cleanup >/dev/null 2>&1 || true

echo "==> fixture: geneve0 + fbveth0/fbclient netns"
ip link add geneve0 type geneve external
ip link set geneve0 up
ip link add fbveth0 type veth peer name fbveth1
ip netns add fbclient
ip link set fbveth1 netns fbclient
ip addr add "${VIP_IP}/24" dev fbveth0
ip link set fbveth0 up
ip netns exec fbclient ip addr add "${CLIENT_IP}/24" dev fbveth1
ip netns exec fbclient ip link set fbveth1 up
ip netns exec fbclient ip link set lo up
ip addr add "${POD_IP}/32" dev lo
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
sysctl -w net.ipv4.conf.geneve0.rp_filter=0 >/dev/null

echo "==> loading beep-ebpf: forward-establishing front ${VIP_IP}:${FWD_PORT}/tcp, reverse-role burst front ${VIP_IP}:${REV_PORT}/udp (both node-ip=self, so both round trip through this node's own decap step)"
nohup "$BIN" --uplink-iface fbveth0 --geneve-iface geneve0 --pin-dir "$PIN_DIR" \
  --pod-cidr "198.51.100.0/24" --node-ip "$VIP_IP" \
  --fixture "${VIP_IP}:${FWD_PORT}:tcp:${VIP_IP}:${POD_IP}:${FWD_TARGET_PORT}" \
  --fixture "${VIP_IP}:${REV_PORT}:udp:${VIP_IP}:${POD_IP}:${REV_TARGET_PORT}" \
  >"$LOADER_LOG" 2>&1 &
loader_pid=$!
disown

for _ in $(seq 1 20); do
  grep -q "all 3 hooks attached" "$LOADER_LOG" 2>/dev/null && break
  kill -0 "$loader_pid" 2>/dev/null || {
    echo "FAIL: loader exited before attaching (verifier rejection or load error):" >&2
    cat "$LOADER_LOG" >&2
    exit 1
  }
  sleep 0.5
done
grep -q "all 3 hooks attached" "$LOADER_LOG" || {
  echo "FAIL: loader never reported all 3 hooks attached within 10s" >&2
  exit 1
}
echo "VERIFIER-ACCEPT: PASS"

echo "==> establishing $NUM_FORWARD real forward round trips (some pre-established FLOW_TABLE forward entries, the eviction target)"
printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK' >/tmp/flow-table-burst-resp.http
for i in $(seq 1 "$NUM_FORWARD"); do
  nohup nc -l -N "$POD_IP" "$FWD_TARGET_PORT" </tmp/flow-table-burst-resp.http >"/tmp/flow-table-burst-backend-$i.log" 2>&1 &
  disown
  sleep 0.1
  ip netns exec fbclient curl -sS -m 5 "http://${VIP_IP}:${FWD_PORT}/" >/dev/null || echo "WARN: forward round trip $i failed" >&2
done

map_dump() {
  bpftool map dump pinned "$PIN_DIR/FLOW_TABLE" --json 2>/dev/null
}
# `.key[37]`: beep_common::FLOW_KEY_LEN's last byte is the FlowDirection tag
# (Forward=0, Reverse=1) appended after encode_tcp_flow_key's 37 bytes --
# confirmed against a live bpftool dump, not assumed from the struct alone.
count_tagged() {
  jq --arg t "$2" '[.[] | select(.key[37] == $t)] | length' <<<"$1"
}

baseline_json=$(map_dump)
fwd_baseline=$(count_tagged "$baseline_json" "0x00")
rev_baseline=$(count_tagged "$baseline_json" "0x01")
echo "baseline: FLOW_TABLE forward-tagged=$fwd_baseline reverse-tagged=$rev_baseline (from $NUM_FORWARD attempted round trips)"
[ "$fwd_baseline" -ge 1 ] || {
  echo "FAIL: no forward-tagged FLOW_TABLE entry got established -- nothing to characterize eviction against" >&2
  exit 1
}

# Each iteration opens its own UDP socket (a fresh kernel-assigned ephemeral
# source port = a distinct FlowKey) and sends one packet with no listener on
# the decap target -- the reverse-tagged write happens at decap+DNAT time,
# before delivery, so it needs neither a listener nor a return leg (verified
# live: a 5-packet burst against an unbound target port wrote 5 distinct
# reverse-tagged entries). Runs inside ONE `bash -c` (no per-packet fork) so
# the sweep's own loop overhead stays negligible against the 90s cap.
send_burst() {
  local count="$1"
  ip netns exec fbclient bash -c "
    for ((i=0; i<${count}; i++)); do
      exec {fd}<>\"/dev/udp/${VIP_IP}/${REV_PORT}\" 2>/dev/null || continue
      printf x >&\$fd 2>/dev/null || true
      exec {fd}>&- 2>/dev/null || true
    done
  "
}

echo "==> geometric reverse-role burst sweep (hard cap: ${WALL_CAP_SECS}s wall clock; stops at first forward-entry eviction or the cap, never runs a level to completion past either)"
LEVELS=(512 1024 2048 4096 8192 16384 32768 65536 131072 262144 524288 1048576)
sweep_start=$(date +%s)
cumulative=0
first_eviction_level=""
for lvl in "${LEVELS[@]}"; do
  elapsed=$(($(date +%s) - sweep_start))
  if [ "$elapsed" -ge "$WALL_CAP_SECS" ]; then
    echo "CAP: ${WALL_CAP_SECS}s wall-clock reached before burst level $lvl -- stopping sweep"
    break
  fi
  delta=$((lvl - cumulative))
  send_burst "$delta"
  cumulative="$lvl"
  json=$(map_dump)
  fwd_now=$(count_tagged "$json" "0x00")
  total_now=$(jq 'length' <<<"$json")
  echo "burst_cumulative=$cumulative forward_entries=$fwd_now (baseline=$fwd_baseline) total_entries=$total_now"
  if [ "$fwd_now" -lt "$fwd_baseline" ]; then
    first_eviction_level="$cumulative"
    echo "FIRST FORWARD-ENTRY EVICTION observed at cumulative burst size $cumulative (forward entries $fwd_baseline -> $fwd_now)"
    break
  fi
done
sweep_elapsed=$(($(date +%s) - sweep_start))
echo "sweep wall-clock elapsed: ${sweep_elapsed}s (cap ${WALL_CAP_SECS}s)"

if [ -n "$first_eviction_level" ]; then
  echo "RESULT: first forward-entry eviction observed at $first_eviction_level concurrent reverse-role flows"
else
  echo "RESULT: no forward-entry eviction observed up to $cumulative concurrent reverse-role flows within the ${WALL_CAP_SECS}s cap"
fi
REMOTE_EOF

cleanup_remote() {
  limactl shell "$VM" -- sudo bash /tmp/flow-table-burst-remote.sh cleanup >/dev/null 2>&1 || true
}
cleanup_local() {
  rm -f "$REMOTE_SCRIPT_LOCAL"
}
trap 'cleanup_remote; cleanup_local' EXIT

echo "==> [2/3] copying the characterization fixture to $VM"
limactl copy "$REMOTE_SCRIPT_LOCAL" "$VM":/tmp/flow-table-burst-remote.sh
limactl shell "$VM" -- bash -c 'chmod +x /tmp/flow-table-burst-remote.sh'

echo "==> [3/3] running the geometric burst sweep (in-VM)"
limactl shell "$VM" -- sudo bash /tmp/flow-table-burst-remote.sh run
