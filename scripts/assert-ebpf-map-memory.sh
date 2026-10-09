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
# is > 0 and under a gross-regression ceiling (not a tight bound, just a
# tripwire for an accidental max_entries blow-up). The ceiling is 6 MiB, an
# INTERIM value: the measured footprint is 4,185,352 bytes (CI run
# 37885413497), so 6 MiB is ~1.5x, pending the FRONT_ENDPOINTS sizing
# decision; the long-term value is re-derived at ~2x the measured footprint.
# LRU_HASH conntrack maps (FWD_PENDING/FLOW_TABLE) preallocate for their
# full max_entries capacity regardless of active-flow count; FLOW_TABLE
# (16384 entries, ~2.25 MiB) is the largest share.
set -euo pipefail

csv="${1:?usage: $0 <ebpf-map-memory.csv>}"
[ -f "$csv" ] || { echo "FAIL: $csv not found" >&2; exit 1; }

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

echo "PASS: exactly ${#expected[@]} known beep maps discovered, total bytes_memlock=$total is within the gross-regression ceiling"
