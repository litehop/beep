#!/usr/bin/env bash
# Asserts the canonical eBPF quality gate stays consistent across the places
# it is enforced, so an edit to one never silently drifts from the others.
#
# Source of truth: .github/workflows/ci.yaml's fmt/lint-matrix/test-matrix/
# memory-smoke jobs. By decision
# (not a shared script) those five commands are copied in full into
# .claude/settings.json's PreToolUse Bash hook and .githooks/pre-push, and
# .claude/agents/worker.md carries the macOS-host subset (fmt + beep-common
# tests) a worker runs locally. If you change the gate, change it in all of
# them together -- this test is why. It also fails if the pre-migration u7s
# `--workspace` gate form creeps back into either enforced gate.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

PASS=0; FAIL=0
assert() { # $1 label, $2 ok(1/0)
  if [ "$2" = 1 ]; then echo "PASS: $1"; PASS=$((PASS + 1)); else echo "FAIL: $1"; FAIL=$((FAIL + 1)); fi
}
has() { grep -Fq -- "$2" "$1"; } # $1 file, $2 literal substring

SETTINGS=.claude/settings.json
PREPUSH=.githooks/pre-push
WORKER=.claude/agents/worker.md

# The canonical 5 commands, in the order CI runs them across its jobs.
C1='cargo fmt --check'
C2='cargo clippy --tests -- -D warnings'
C3='cargo test -p beep-common'
C4='cargo clippy --release --target bpfel-unknown-none -Z build-std=core -- -D warnings'
C5='cargo build --release'

# The full gate must appear in both the push-time hook and pre-push.
for f in "$SETTINGS" "$PREPUSH"; do
  for c in "$C1" "$C2" "$C3" "$C4" "$C5"; do
    assert "$f carries canonical command: $c" "$(has "$f" "$c" && echo 1 || echo 0)"
  done
  assert "$f has no --workspace gate form (u7s regression)" \
    "$(grep -Fq -- '--workspace' "$f" && echo 0 || echo 1)"
done

# worker.md runs the macOS-host subset locally (Linux-only steps are
# CI-enforced, not listed as local commands). Its subset must match verbatim.
assert "worker.md carries canonical macOS-subset command: $C1" "$(has "$WORKER" "$C1" && echo 1 || echo 0)"
assert "worker.md carries canonical macOS-subset command: $C3" "$(has "$WORKER" "$C3" && echo 1 || echo 0)"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -gt 0 ] && exit 1
exit 0
