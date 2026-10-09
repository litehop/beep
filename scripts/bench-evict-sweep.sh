#!/usr/bin/env bash
# Times `beep evict-pod` (the conntrack eviction sweep) over bpftool-populated
# FWD_PENDING/FLOW_TABLE maps. Run as root on a Linux host/VM where a loader is
# already running against --pin-dir (e.g. scripts/smoke-remote.sh's fixture,
# paused before cleanup) and bpftool is installed. Destructive to the pinned
# maps' contents.
#
# Usage: scripts/bench-evict-sweep.sh --bin <beep> --pin-dir <dir>
#          [--pods 100] [--departed 20] [--pending 8000] [--flows 60000]
#
# Rows are spread round-robin over --pods pod IPs (10.244.1.1..); the first
# --departed pods are swept in ONE `beep evict-pod` call. FLOW_TABLE rows are
# split evenly across Forward (pod in VALUE), Reverse and PortMemo (pod in KEY).
set -euo pipefail

BIN="" PIN_DIR="" PODS=100 DEPARTED=20 PENDING=8000 FLOWS=60000
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin) BIN="$2"; shift 2 ;;
    --pin-dir) PIN_DIR="$2"; shift 2 ;;
    --pods) PODS="$2"; shift 2 ;;
    --departed) DEPARTED="$2"; shift 2 ;;
    --pending) PENDING="$2"; shift 2 ;;
    --flows) FLOWS="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done
[[ -n "$BIN" && -n "$PIN_DIR" ]] || { echo "--bin and --pin-dir are required" >&2; exit 1; }
(( PODS <= 254 && DEPARTED <= PODS )) || { echo "need departed <= pods <= 254" >&2; exit 1; }

# v4-mapped-v6 (::ffff:a.b.c.d) as space-separated hex bytes.
mapped() { printf '00 00 00 00 00 00 00 00 00 00 ff ff %02x %02x %02x %02x' "$@"; }
# 2-byte native-endian port as hex bytes (little-endian host).
port() { printf '%02x %02x' $(($1 & 255)) $(($1 >> 8 & 255)); }
zeros() { local n=$1 out=""; while ((n-- > 0)); do out+="00 "; done; printf '%s' "$out"; }
size() { bpftool map show pinned "$PIN_DIR/$1" --json | jq -r ".$2"; }

CLIENT=$(mapped 203 0 113 2)
FRONT=$(mapped 203 0 113 1)
pod() { mapped 10 244 1 $(($1 % PODS + 1)); }

PEND_VSZ=$(size FWD_PENDING bytes_value)
FLOW_VSZ=$(size FLOW_TABLE bytes_value)
# ForwardFlowValue = backend_node_ip[16] | pod_ip[16] | ingress_ifindex u32
fwd_value() { echo "$(mapped 192 0 2 9) $(pod "$1") 01 00 00 00 $(zeros $(($2 - 36)))"; }

for m in FWD_PENDING FLOW_TABLE; do
  bpftool map show pinned "$PIN_DIR/$m" >/dev/null
done

batch=$(mktemp)
trap 'rm -f "$batch"' EXIT

for ((i = 0; i < PENDING; i++)); do
  echo "map update pinned $PIN_DIR/FWD_PENDING key hex $CLIENT $FRONT $(port $((i % 65536))) $(port 80) 06 value hex $(fwd_value "$i" "$PEND_VSZ")"
done >"$batch"
bpftool batch file "$batch"

third=$((FLOWS / 3))
for ((i = 0; i < third; i++)); do
  # Forward: key other_ip is the front; pod identity in the value.
  echo "map update pinned $PIN_DIR/FLOW_TABLE key hex $CLIENT $FRONT $(port $((i % 65536))) $(port 80) 06 00 value hex $(fwd_value "$i" "$FLOW_VSZ")"
  # Reverse / PortMemo: pod identity in the key.
  for tag in 01 02; do
    echo "map update pinned $PIN_DIR/FLOW_TABLE key hex $CLIENT $(pod "$i") $(port $((i % 65536))) $(port 8080) 06 $tag value hex $(zeros "$FLOW_VSZ")"
  done
done >"$batch"
bpftool batch file "$batch"

count() { bpftool map dump pinned "$PIN_DIR/$1" --json | jq 'length'; }
echo "before: FWD_PENDING=$(count FWD_PENDING) FLOW_TABLE=$(count FLOW_TABLE)"

ips=()
for ((p = 1; p <= DEPARTED; p++)); do ips+=("10.244.1.$p"); done
start=$(date +%s%N)
"$BIN" evict-pod --pin-dir "$PIN_DIR" "${ips[@]}"
end=$(date +%s%N)

echo "after:  FWD_PENDING=$(count FWD_PENDING) FLOW_TABLE=$(count FLOW_TABLE)"
echo "sweep of $DEPARTED pod(s) in one evict-pod call: $(((end - start) / 1000000)) ms"
