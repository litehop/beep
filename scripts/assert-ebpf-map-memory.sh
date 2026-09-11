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
# Asserts the discovered map set is EXACTLY the 7 known beep maps, not
# just a byte-count ceiling: a partial-discovery regression (e.g. only 6 of 7
# maps found) still sums to a smaller, still-passing total -- this is the
# gate this script exists to close. Also asserts their summed bytes_memlock
# is > 0 and under a gross-regression ceiling (not a tight bound, just a
# tripwire for an accidental max_entries blow-up). The ceiling is 4 MiB:
# LRU_HASH conntrack maps (FWD_PENDING/FLOW_TABLE) preallocate for their
# full max_entries capacity regardless of active-flow count. FLOW_TABLE
# merged the former separate FWD_MAIN+REV_FLOW maps into one 16384-entry
# table, measured at ~1.88 MiB (1,966,976 bytes) preallocated per node;
# FWD_PENDING adds a smaller tier on top (2048 entries by default, ~+240
# KiB) -- 4 MiB still leaves comfortable headroom over that real,
# near-constant footprint.
set -euo pipefail

csv="${1:?usage: $0 <ebpf-map-memory.csv>}"
[ -f "$csv" ] || { echo "FAIL: $csv not found" >&2; exit 1; }

mapfile -t names < <(awk -F, 'NR>1 {print $3}' "$csv")
total=$(awk -F, 'NR>1 { sum += $6 } END { print sum+0 }' "$csv")
echo "discovered maps (${#names[@]}): ${names[*]:-none}"
echo "total bytes_memlock: $total"

expected=(CONFIG FWD_PENDING FLOW_TABLE TARGET_PORTS VIP_MAP POD_TARGETS EGRESS_DROPS)
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
limit=$((4 * 1024 * 1024))
[ "$total" -lt "$limit" ] || { echo "FAIL: total bytes_memlock ($total) >= 4 MiB gross-regression ceiling" >&2; exit 1; }

echo "PASS: exactly ${#expected[@]} known beep maps discovered, total bytes_memlock=$total is within the gross-regression ceiling"
