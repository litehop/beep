#!/usr/bin/env bash
# CI assertion for scripts/sample-ebpf-memory.sh's
# ebpf-map-memory.csv. Its own script (not inlined in
# .github/workflows/ci.yaml) so scripts/test-sample-ebpf-memory-logic.sh
# can exercise the REAL assertion logic against constructed CSVs instead of a
# copied-out fragment that could silently drift from what CI actually runs.
#
# Expects a CSV produced by a SINGLE `sample-ebpf-memory.sh once` call into a
# fresh --out-dir (see .github/workflows/ci.yaml's memory-smoke job):
# every data row must belong to exactly one tick. Do not point this at a CSV
# accumulated across multiple ticks/calls -- there is no per-tick boundary
# marker in the CSV to isolate "the latest tick" from an older one, and a
# mismatched map count across ticks (see PR #1568's review, which found this
# exact ambiguity silently blending a stale row into the sum) is the
# ambiguity a fresh single-tick file avoids by construction rather than by
# parsing around it.
#
# Asserts the discovered map set is EXACTLY the 9 known beep maps, not
# just a byte-count ceiling: a partial-discovery regression (e.g. only 8 of 9
# maps found) still sums to a smaller, still-passing total -- this is the
# gate this script exists to close. Also asserts their summed bytes_memlock
# is > 0 and under a gross-regression ceiling of 6 MiB.
#
# Tripwires at 1.15x of an expected USAGE, not of a cap:
#   * FRONT_META / FRONT_ENDPOINTS are BPF_F_NO_PREALLOC, so their footprint is
#     a bucket array that is allocated up front (16 B x next_pow2(max_entries))
#     plus a ~1 KiB header, plus a per-entry cost for the entries actually
#     present (~96 B META, ~128 B ENDPOINTS: element header + key + value, each
#     rounded to 8). The entry counts are passed in (count them from the pins
#     with `bpftool map dump pinned <pin> -j | jq length`), so a regression in
#     max_entries or per-entry cost trips the per-map check even though both are
#     far under any cap.
#   * Everything else preallocates for its full max_entries regardless of use;
#     FLOW_TABLE (16384 entries, ~2.25 MiB) is the largest share. Their summed
#     footprint is EXPECTED_PREALLOCATED_BYTES below; the total check is 1.15x
#     of that plus the two front maps' expected usage.
set -euo pipefail

usage="usage: $0 <ebpf-map-memory.csv> --front-meta-entries N --front-endpoints-entries N"
csv="${1:?$usage}"
shift
front_meta_entries=""
front_endpoints_entries=""
while [ $# -gt 0 ]; do
  case "$1" in
    --front-meta-entries) front_meta_entries="${2:?$usage}"; shift 2 ;;
    --front-endpoints-entries) front_endpoints_entries="${2:?$usage}"; shift 2 ;;
    *) echo "FAIL: unknown argument $1 ($usage)" >&2; exit 1 ;;
  esac
done
[ -f "$csv" ] || { echo "FAIL: $csv not found" >&2; exit 1; }
case "$front_meta_entries$front_endpoints_entries" in
  ''|*[!0-9]*) echo "FAIL: --front-meta-entries and --front-endpoints-entries must be integers ($usage)" >&2; exit 1 ;;
esac
[ -n "$front_meta_entries" ] && [ -n "$front_endpoints_entries" ] || { echo "FAIL: $usage" >&2; exit 1; }

# Summed bytes_memlock of the seven non-front maps (all preallocate their full
# max_entries, so it is a function of their default caps and the kernel's
# per-element overhead, which differs between the kernel-smoke legs). Refresh by
# summing the `bytes_memlock` column of every row except FRONT_META and
# FRONT_ENDPOINTS in a CI memory-smoke CSV; this is the highest value seen
# across the memory-smoke runs and a local 6.12 VM reads ~2.67 MB.
EXPECTED_PREALLOCATED_BYTES=2828056
FRONT_HEADER_BYTES=1024
FRONT_META_ENTRY_BYTES=96
FRONT_ENDPOINTS_ENTRY_BYTES=128
TRIPWIRE_PERCENT=115

next_pow2() {
  local n=$1 p=1
  while [ "$p" -lt "$n" ]; do p=$((p * 2)); done
  echo "$p"
}

names=()
while IFS= read -r name; do
  names+=("$name")
done < <(awk -F, 'NR>1 {print $3}' "$csv")
total=$(awk -F, 'NR>1 { sum += $6 } END { print sum+0 }' "$csv")
echo "discovered maps (${#names[@]}): ${names[*]:-none}"
echo "total bytes_memlock: $total"

expected=(CONFIG FWD_PENDING FLOW_TABLE FRONT_ENDPOINTS FRONT_META FRONT_MISSES POD_TARGETS NODE_ALLOW UPLINK_CONFIG)
actual_sorted="$(printf '%s\n' "${names[@]}" | sort -u)"
expected_sorted="$(printf '%s\n' "${expected[@]}" | sort -u)"

[ "${#names[@]}" -eq "${#expected[@]}" ] || {
  echo "FAIL: expected ${#expected[@]} maps, discovered ${#names[@]} -- map discovery broken?" >&2
  exit 1
}
[ "$actual_sorted" = "$expected_sorted" ] || {
  echo "FAIL: discovered map names don't match the known beep map set" >&2
  echo "  expected: ${expected[*]}" >&2
  echo "  actual:   ${names[*]}" >&2
  exit 1
}
[ "$total" -gt 0 ] || { echo "FAIL: total bytes_memlock is 0 despite ${#expected[@]} maps discovered -- bpftool map show broken?" >&2; exit 1; }
limit=$((6 * 1024 * 1024))
[ "$total" -lt "$limit" ] || { echo "FAIL: total bytes_memlock ($total) >= 6 MiB gross-regression ceiling" >&2; exit 1; }

# Per-map usage check for the two no-prealloc front maps.
expected_total=$EXPECTED_PREALLOCATED_BYTES
for spec in "FRONT_META:$front_meta_entries:$FRONT_META_ENTRY_BYTES" "FRONT_ENDPOINTS:$front_endpoints_entries:$FRONT_ENDPOINTS_ENTRY_BYTES"; do
  IFS=: read -r map entries per_entry <<<"$spec"
  max_entries=$(awk -F, -v m="$map" 'NR>1 && $3==m {print $5}' "$csv")
  actual=$(awk -F, -v m="$map" 'NR>1 && $3==m {print $6}' "$csv")
  expected_bytes=$(( 16 * $(next_pow2 "$max_entries") + FRONT_HEADER_BYTES + entries * per_entry ))
  map_limit=$(( expected_bytes * TRIPWIRE_PERCENT / 100 ))
  echo "$map: max_entries=$max_entries entries=$entries expected~$expected_bytes tripwire=$map_limit actual=$actual"
  [ "$actual" -le "$map_limit" ] || {
    echo "FAIL: $map bytes_memlock ($actual) exceeds ${TRIPWIRE_PERCENT}% of the expected usage ($expected_bytes = 16 x next_pow2($max_entries) bucket floor + header + $entries x $per_entry B)" >&2
    exit 1
  }
  expected_total=$((expected_total + expected_bytes))
done

total_limit=$(( expected_total * TRIPWIRE_PERCENT / 100 ))
echo "expected total ~$expected_total, tripwire $total_limit"
[ "$total" -le "$total_limit" ] || { echo "FAIL: total bytes_memlock ($total) exceeds ${TRIPWIRE_PERCENT}% of the expected footprint ($expected_total)" >&2; exit 1; }

echo "PASS: exactly ${#expected[@]} known beep maps discovered, total bytes_memlock=$total is within ${TRIPWIRE_PERCENT}% of the expected usage and under the gross-regression ceiling"
