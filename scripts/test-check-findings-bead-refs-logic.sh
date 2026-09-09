#!/usr/bin/env bash
# Unit test for scripts/check-findings-bead-refs.sh's Bead: header guard.
#
# Exercises the REAL script as a subprocess against disposable sandbox git
# repos (same technique as test-check-bead-id-refs-logic.sh), not a
# reimplementation of its regex or diff-filter -- a reimplementation would
# keep passing even if the real script regressed.
#
# Regression this guards: findings are deleted from the working tree on
# bead close (see "Findings lifecycle" in the workflow docs); the Bead:
# header is the only way to trace a since-deleted finding back to the
# commit/bead that introduced it. A finding without it is unretrievable
# git bloat the moment it's removed, so the gate must actually block it.
#
# Fixtures below use a non-bead-ID-shaped `Bead: fixture-1` value, not a
# real bead-ID-shaped string, so this file doesn't need excluding from
# scripts/check-bead-id-refs.sh's own sweep -- the gate under test only
# validates the `^Bead: ` prefix, never the ID's shape, so this is a
# faithful fixture, not a weakened one.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/scripts/check-findings-bead-refs.sh"

PASS=0
FAIL=0

assert() {
  local label="$1" ok="$2"
  if [ "$ok" = "1" ]; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label"
    FAIL=$(( FAIL + 1 ))
  fi
}

# Fresh sandbox git repo at $1. The gate reads `git diff --cached`, so
# scenarios stage changes without committing -- mirroring a real pre-commit.
new_sandbox() {
  local dir="$1"
  git init -q -b main "$dir"
  git -C "$dir" config user.email test@example.com
  git -C "$dir" config user.name "Test"
}

# Runs the real gate inside sandbox $1. Returns the gate's exit code without
# tripping this script's `set -e`.
run_gate() {
  local dir="$1"
  set +e
  (cd "$dir" && bash "$SCRIPT") >"$dir/.gate-out" 2>&1
  local rc=$?
  set -e
  echo "$rc"
}

SANDBOX_ROOT=$(mktemp -d)
trap 'rm -rf "$SANDBOX_ROOT"' EXIT

# ---------------------------------------------------------------------------
# 1. Staged ai/findings/*.md WITH a Bead: header in its first 5 lines ->
#    passes. This is the common case a worker hits on every finding commit;
#    it must not be blocked.
# ---------------------------------------------------------------------------
S1="$SANDBOX_ROOT/1-with-bead"
new_sandbox "$S1"
mkdir -p "$S1/ai/findings"
printf 'Notes\nBead: fixture-1\n\nSome finding body.\n' > "$S1/ai/findings/2026-08-27-fixture-1-test.md"
git -C "$S1" add ai/findings/2026-08-27-fixture-1-test.md
RC1=$(run_gate "$S1")
assert "staged finding with Bead: header in first 5 lines passes" \
  "$([ "$RC1" -eq 0 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 2. Staged ai/findings/*.md with NO Bead: line anywhere -> fails, and names
#    the offending file. This is the exact gap the pre-commit hook exists
#    to close: a finding with no bead reference can never be traced back
#    after it's deleted on bead close.
# ---------------------------------------------------------------------------
S2="$SANDBOX_ROOT/2-no-bead"
new_sandbox "$S2"
mkdir -p "$S2/ai/findings"
printf 'Just prose, no bead reference at all.\n' > "$S2/ai/findings/2026-08-27-no-bead-test.md"
git -C "$S2" add ai/findings/2026-08-27-no-bead-test.md
RC2=$(run_gate "$S2")
assert "staged finding with no Bead: header fails" \
  "$([ "$RC2" -ne 0 ] && echo 1 || echo 0)"
assert "no-Bead failure names the offending file" \
  "$(grep -qF 'ai/findings/2026-08-27-no-bead-test.md' "$S2/.gate-out" && echo 1 || echo 0)"
assert "no-Bead failure states what's missing" \
  "$(grep -qF 'Bead: <bead-id>' "$S2/.gate-out" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3. ai/findings/legacy/*.md is exempt even with no Bead: header -- the
#    legacy pile predates the convention and is out of scope until its
#    migration bead processes it. The gate must not block unrelated work
#    that happens to touch legacy/.
# ---------------------------------------------------------------------------
S3="$SANDBOX_ROOT/3-legacy-exempt"
new_sandbox "$S3"
mkdir -p "$S3/ai/findings/legacy"
printf 'Pre-convention finding, no header.\n' > "$S3/ai/findings/legacy/old-finding.md"
git -C "$S3" add ai/findings/legacy/old-finding.md
RC3=$(run_gate "$S3")
assert "legacy/ findings are exempt from the Bead: header requirement" \
  "$([ "$RC3" -eq 0 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 4. Renamed-in finding with no Bead: header -> fails. --diff-filter=AMR
#    (not just AM) is what makes this case caught: a pure `git mv` reports
#    status R, and an AM-only filter would silently skip it.
# ---------------------------------------------------------------------------
S4="$SANDBOX_ROOT/4-rename"
new_sandbox "$S4"
mkdir -p "$S4/misc"
printf 'Just prose, no bead reference at all.\n' > "$S4/misc/draft.md"
git -C "$S4" add misc/draft.md
git -C "$S4" commit -q -m old
mkdir -p "$S4/ai/findings"
git -C "$S4" mv misc/draft.md ai/findings/2026-08-27-renamed-in.md
RC4=$(run_gate "$S4")
assert "renamed-in finding with no Bead: header is caught (AMR, not just AM)" \
  "$([ "$RC4" -ne 0 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
