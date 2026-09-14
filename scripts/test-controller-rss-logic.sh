#!/usr/bin/env bash
# Unit test for scripts/controller-rss.sh -- the shared beep-controller RSS
# ceiling logic scripts/smoke-k3s-controller.sh and
# scripts/memory-smoke-controller.sh both call. Exercises the real functions
# directly (sourced, not copied), mirroring
# scripts/test-sample-ebpf-memory-logic.sh's own approach.
#
# Covers the one failure mode this whole family of scripts exists to catch:
# a regression that inflates beep-controller's RSS must FAIL the ceiling
# check, not silently pass -- verified here with a simulated overshoot on
# both the baseline and growth assertions, not just the passing case.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=controller-rss.sh
. "$REPO/scripts/controller-rss.sh"

PASS=0
FAIL=0

expect_status() {
  local label="$1" expect="$2" got="$3"
  if [ "$expect" = "$got" ]; then
    echo "PASS: $label"
    PASS=$((PASS + 1))
  else
    echo "FAIL: $label (expected exit $expect, got $got)"
    FAIL=$((FAIL + 1))
  fi
}

status=0
assert_controller_rss_baseline "$CONTROLLER_RSS_BASELINE_CEILING_KB" "at-ceiling" >/dev/null 2>&1 || status=$?
expect_status "baseline exactly at the ceiling still passes (inclusive bound)" 0 "$status"

status=0
assert_controller_rss_baseline "$((CONTROLLER_RSS_BASELINE_CEILING_KB + 1))" "over-ceiling" >/dev/null 2>&1 || status=$?
expect_status "baseline one kB over the ceiling fails -- a real regression must not slip through by rounding" 1 "$status"

status=0
assert_controller_rss_growth 6948 7004 "small-growth" >/dev/null 2>&1 || status=$?
expect_status "a small, measured-scale growth (6948->7004 kB) passes" 0 "$status"

status=0
# Simulated regression: a leak that adds far more than one Service+backend
# Pod's worth of growth should reconcile should ever retain.
regressed_peak=$((6948 + CONTROLLER_RSS_GROWTH_CEILING_KB + 1))
assert_controller_rss_growth 6948 "$regressed_peak" "simulated-leak" >/dev/null 2>&1 || status=$?
expect_status "a simulated per-reconcile leak exceeding the growth ceiling fails -- this is the exact case this gate exists to catch" 1 "$status"

status=0
assert_controller_rss_baseline "" "process-not-found" >/dev/null 2>&1 || status=$?
expect_status "an empty RSS reading (process not found) fails rather than silently passing" 1 "$status"

status=0
assert_controller_rss_growth 6948 "" "process-vanished-mid-run" >/dev/null 2>&1 || status=$?
expect_status "a missing peak reading fails rather than computing a bogus delta" 1 "$status"

echo "---"
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
