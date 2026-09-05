#!/usr/bin/env bash
# CI assertion for scripts/servicelb/sample-ebpf-memory.sh's
# ebpf-map-memory.csv. Its own script (not inlined in
# .github/workflows/test.yaml) so scripts/servicelb/test-sample-ebpf-memory-logic.sh
# can exercise the REAL assertion logic against constructed CSVs instead of a
# copied-out fragment that could silently drift from what CI actually runs.
#
# Expects a CSV produced by a SINGLE `sample-ebpf-memory.sh once` call into a
# fresh --out-dir (see .github/workflows/test.yaml's ebpf-memory-smoke job):
# every data row must belong to exactly one tick. Do not point this at a CSV
# accumulated across multiple ticks/calls -- there is no per-tick boundary
# marker in the CSV to isolate "the latest tick" from an older one, and a
# mismatched map count across ticks (see PR #1568's review, which found this
# exact ambiguity silently blending a stale row into the sum) is the
# ambiguity a fresh single-tick file avoids by construction rather than by
# parsing around it.
#
# Asserts the discovered map set is EXACTLY the 5 known servicelb maps, not
# just a byte-count ceiling: a partial-discovery regression (e.g. only 4 of 5
# maps found) still sums to a smaller, still-passing total -- this is the
# gate this script exists to close. Also asserts their summed bytes_memlock
# is > 0 and under a gross-regression ceiling (not a tight bound, just a
# tripwire for an accidental max_entries blow-up). The ceiling is 4 MiB:
# LRU_HASH conntrack maps (FWD_FLOW/REV_FLOW/etc) preallocate for their full
# max_entries capacity regardless of active-flow count, and pa0ze's Phase-3
# 8192-entry sizing (#1567) measures ~1.82 MiB (1,909,072 bytes) preallocated
# per node -- 4 MiB leaves ~2.1x headroom over that real, constant footprint.
set -euo pipefail

csv="${1:?usage: $0 <ebpf-map-memory.csv>}"
[ -f "$csv" ] || { echo "FAIL: $csv not found" >&2; exit 1; }

mapfile -t names < <(awk -F, 'NR>1 {print $3}' "$csv")
total=$(awk -F, 'NR>1 { sum += $6 } END { print sum+0 }' "$csv")
echo "discovered maps (${#names[@]}): ${names[*]:-none}"
echo "total bytes_memlock: $total"

expected=(CONFIG FWD_FLOW TARGET_PORTS REV_FLOW VIP_MAP)
actual_sorted="$(printf '%s\n' "${names[@]}" | sort -u)"
expected_sorted="$(printf '%s\n' "${expected[@]}" | sort -u)"

[ "${#names[@]}" -eq "${#expected[@]}" ] || {
  echo "FAIL: expected ${#expected[@]} maps, discovered ${#names[@]} -- map discovery broken?" >&2
  exit 1
}
[ "$actual_sorted" = "$expected_sorted" ] || {
  echo "FAIL: discovered map names don't match the known servicelb map set" >&2
  echo "  expected: ${expected[*]}" >&2
  echo "  actual:   ${names[*]}" >&2
  exit 1
}
[ "$total" -gt 0 ] || { echo "FAIL: total bytes_memlock is 0 despite ${#expected[@]} maps discovered -- bpftool map show broken?" >&2; exit 1; }
limit=$((4 * 1024 * 1024))
[ "$total" -lt "$limit" ] || { echo "FAIL: total bytes_memlock ($total) >= 4 MiB gross-regression ceiling" >&2; exit 1; }

echo "PASS: exactly ${#expected[@]} known servicelb maps discovered, total bytes_memlock=$total is within the gross-regression ceiling"
