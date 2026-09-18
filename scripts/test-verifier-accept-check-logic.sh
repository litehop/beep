#!/usr/bin/env bash
# Unit test for scripts/verifier-accept-check.sh -- the VERIFIER-ACCEPT
# confirmation scripts/smoke-remote.sh sources. Exercises the real function
# directly (sourced, not copied), mirroring
# scripts/test-controller-rss-logic.sh's own approach.
#
# Covers a real regression: reordering the bpftool kernel-truth check ahead
# of the loader-log + eBPF-memory-sample emission meant the FAIL branch
# exited before either diagnostic ever printed -- losing the exact
# diagnostic surface needed to debug a kernel-truth/loader divergence. A
# synthetic <3-loaded count drives that FAIL branch here without a VM.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=verifier-accept-check.sh
. "$REPO/scripts/verifier-accept-check.sh"

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

expect_contains() {
  local label="$1" haystack="$2" needle="$3"
  case "$haystack" in
    *"$needle"*)
      echo "PASS: $label"
      PASS=$((PASS + 1))
      ;;
    *)
      echo "FAIL: $label -- expected output to contain '$needle'"
      FAIL=$((FAIL + 1))
      ;;
  esac
}

expect_not_contains() {
  local label="$1" haystack="$2" needle="$3"
  case "$haystack" in
    *"$needle"*)
      echo "FAIL: $label -- output unexpectedly contained '$needle'"
      FAIL=$((FAIL + 1))
      ;;
    *)
      echo "PASS: $label"
      PASS=$((PASS + 1))
      ;;
  esac
}

TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_TEST"' EXIT

LOG="$TMPDIR_TEST/loader.log"
echo "loader-log-marker: all 3 hooks attached" > "$LOG"

# Stub memory sampler: stands in for sample-ebpf-memory.sh (which needs
# bpftool + real pinned maps, unavailable outside a loaded eBPF program) --
# just proves the real script's invocation point was reached.
MEMORY_SCRIPT="$TMPDIR_TEST/stub-memory.sh"
cat > "$MEMORY_SCRIPT" <<'STUB'
#!/usr/bin/env bash
echo "memory-sample-marker: sampled $*"
STUB
chmod +x "$MEMORY_SCRIPT"

# ===========================================================================
# 1. PASS case: loaded == 3 -- both diagnostics print, function returns 0.
# ===========================================================================
status=0
out_pass="$(verifier_accept_check 3 "$LOG" "$MEMORY_SCRIPT" "/tmp/pin-dir" "/tmp/mem-out" 2>&1)" || status=$?
expect_status "loaded==3 returns 0" 0 "$status"
expect_contains "loaded==3 output includes the loader log" "$out_pass" "loader-log-marker: all 3 hooks attached"
expect_contains "loaded==3 output includes the memory sample" "$out_pass" "memory-sample-marker: sampled once"
expect_contains "loaded==3 output includes VERIFIER-ACCEPT: PASS" "$out_pass" "VERIFIER-ACCEPT: PASS"

# ===========================================================================
# 2. FAIL case (the regression this test exists to catch): loaded < 3 --
#    the function must still return nonzero AND still have emitted the
#    loader log + memory sample BEFORE reporting FAIL. Before this fix,
#    smoke-remote.sh ran the bpftool check first and exited on failure
#    before either diagnostic printed -- reverting the fix reproduces that:
#    this assertion goes red.
# ===========================================================================
status=0
out_fail="$(verifier_accept_check 2 "$LOG" "$MEMORY_SCRIPT" "/tmp/pin-dir" "/tmp/mem-out" 2>&1)" || status=$?
expect_status "loaded==2 (synthetic FAIL) returns nonzero" 1 "$status"
expect_contains "FAIL path still emits the loader log -- the diagnostic surface a kernel-truth divergence needs most" "$out_fail" "loader-log-marker: all 3 hooks attached"
expect_contains "FAIL path still emits the memory sample -- same diagnostic-loss bug, other half" "$out_fail" "memory-sample-marker: sampled once"
expect_contains "FAIL path reports the bpftool count mismatch" "$out_fail" "FAIL: expected 3 sched_cls programs loaded, bpftool sees 2"
expect_not_contains "FAIL path never claims VERIFIER-ACCEPT: PASS" "$out_fail" "VERIFIER-ACCEPT: PASS"

echo "---"
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
