#!/usr/bin/env bash
# Unit test for scripts/check-findings-closed-bead-refs.sh.
#
# Exercises the REAL script as a subprocess against disposable sandbox git
# repos (same technique as test-check-findings-bead-refs-logic.sh), not a
# reimplementation of its jq query or grep filter -- a reimplementation
# would keep passing even if the real script regressed.
#
# Regression this guards: findings are deleted from the working tree on
# bead close, but nothing enforced that step -- six closed-bead findings
# accumulated within one day of the convention shipping. This gate is the
# backstop; if it silently passed a closed-bead reference, the exact
# accumulation it exists to stop would restart unnoticed.
#
# Fixtures use non-bead-ID-shaped `Bead: fixture-*` values (not
# `mayor-XXXXX`), same rationale as test-check-findings-bead-refs-logic.sh's
# fixtures: this file's synthetic IDs must not trip
# scripts/check-bead-id-refs.sh's own mayor-XXXXX sweep, and the gate under
# test never validates an ID's shape, only whether it appears "closed" in
# the JSONL export -- so this is a faithful fixture, not a weakened one.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/scripts/check-findings-closed-bead-refs.sh"

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

# Fresh sandbox git repo at $1. The gate reads `git ls-files`, so scenarios
# only need to stage (not commit) findings files.
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
# 1. Finding references a bead the export records as "open" -> passes. The
#    common case a worker hits on every finding commit; it must not block
#    routine PRs for beads that are still live.
# ---------------------------------------------------------------------------
S1="$SANDBOX_ROOT/1-open-bead"
new_sandbox "$S1"
mkdir -p "$S1/.beads" "$S1/ai/findings"
printf '{"id":"fixture-open-1","status":"open"}\n' > "$S1/.beads/issues.jsonl"
printf 'Bead: fixture-open-1\n\nSome finding body.\n' > "$S1/ai/findings/2026-08-27-fixture-open-1-test.md"
git -C "$S1" add ai/findings/2026-08-27-fixture-open-1-test.md .beads/issues.jsonl
RC1=$(run_gate "$S1")
assert "finding referencing an open bead passes" \
  "$([ "$RC1" -eq 0 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 2. Finding references a bead the export records as "closed" -> fails and
#    names the offending file and bead. This IS the bug this gate exists to
#    close: without it, a closed bead's finding sits in the tree forever.
# ---------------------------------------------------------------------------
S2="$SANDBOX_ROOT/2-closed-bead"
new_sandbox "$S2"
mkdir -p "$S2/.beads" "$S2/ai/findings"
printf '{"id":"fixture-closed-1","status":"closed"}\n' > "$S2/.beads/issues.jsonl"
printf 'Bead: fixture-closed-1\n\nSome finding body.\n' > "$S2/ai/findings/2026-08-27-fixture-closed-1-test.md"
git -C "$S2" add ai/findings/2026-08-27-fixture-closed-1-test.md .beads/issues.jsonl
RC2=$(run_gate "$S2")
assert "finding referencing a closed bead fails" \
  "$([ "$RC2" -ne 0 ] && echo 1 || echo 0)"
assert "closed-bead failure names the offending file" \
  "$(grep -qF 'ai/findings/2026-08-27-fixture-closed-1-test.md' "$S2/.gate-out" && echo 1 || echo 0)"
assert "closed-bead failure names the bead id" \
  "$(grep -qF 'fixture-closed-1' "$S2/.gate-out" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3. ai/findings/legacy/*.md is exempt even when it references a closed
#    bead -- the legacy pile predates the convention and is out of scope
#    until its own migration bead processes it.
# ---------------------------------------------------------------------------
S3="$SANDBOX_ROOT/3-legacy-exempt"
new_sandbox "$S3"
mkdir -p "$S3/.beads" "$S3/ai/findings/legacy"
printf '{"id":"fixture-closed-2","status":"closed"}\n' > "$S3/.beads/issues.jsonl"
printf 'Bead: fixture-closed-2\n\nPre-convention finding.\n' > "$S3/ai/findings/legacy/old-finding.md"
git -C "$S3" add ai/findings/legacy/old-finding.md .beads/issues.jsonl
RC3=$(run_gate "$S3")
assert "legacy/ findings are exempt even when they cite a closed bead" \
  "$([ "$RC3" -eq 0 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 4. Finding's bead ID does not appear in the export at all -> passes.
#    Absence of a positive "closed" signal must not be treated as evidence
#    of closure -- otherwise every finding for a bead the export hasn't
#    caught up to yet (the export only refreshes at session-wrap commits)
#    would false-positive and block unrelated PRs.
# ---------------------------------------------------------------------------
S4="$SANDBOX_ROOT/4-unknown-bead"
new_sandbox "$S4"
mkdir -p "$S4/.beads" "$S4/ai/findings"
printf '{"id":"fixture-open-1","status":"open"}\n' > "$S4/.beads/issues.jsonl"
printf 'Bead: fixture-not-in-export\n\nSome finding body.\n' > "$S4/ai/findings/2026-08-27-fixture-unknown-test.md"
git -C "$S4" add ai/findings/2026-08-27-fixture-unknown-test.md .beads/issues.jsonl
RC4=$(run_gate "$S4")
assert "finding whose bead is absent from the export passes (no positive closed signal)" \
  "$([ "$RC4" -eq 0 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 5. Non-legacy finding with no Bead: header -> fails. A file this gate
#    can't attribute to a bead is a file it can't clear as safe either;
#    silently skipping it would be the same false-assurance failure mode
#    as a vacuous "can't determine, so pass" result.
# ---------------------------------------------------------------------------
S5="$SANDBOX_ROOT/5-no-header"
new_sandbox "$S5"
mkdir -p "$S5/.beads" "$S5/ai/findings"
printf '{"id":"fixture-open-1","status":"open"}\n' > "$S5/.beads/issues.jsonl"
printf 'Just prose, no bead reference at all.\n' > "$S5/ai/findings/2026-08-27-fixture-no-header-test.md"
git -C "$S5" add ai/findings/2026-08-27-fixture-no-header-test.md .beads/issues.jsonl
RC5=$(run_gate "$S5")
assert "non-legacy finding with no Bead: header fails" \
  "$([ "$RC5" -ne 0 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 6. .beads/issues.jsonl missing entirely -> hard failure, not a silent
#    pass. This is the exact vacuous-check trap this suite already shipped
#    once (an unguarded tool probe under `set -euo pipefail` that aborted
#    silently and looked like a clean run): a missing bead-state source
#    must be loud, because a check that passes when it cannot determine
#    bead state is worse than no check at all.
# ---------------------------------------------------------------------------
S6="$SANDBOX_ROOT/6-missing-export"
new_sandbox "$S6"
mkdir -p "$S6/ai/findings"
printf 'Bead: fixture-open-1\n\nSome finding body.\n' > "$S6/ai/findings/2026-08-27-fixture-missing-export-test.md"
git -C "$S6" add ai/findings/2026-08-27-fixture-missing-export-test.md
RC6=$(run_gate "$S6")
assert "missing .beads/issues.jsonl is a hard failure, not a silent pass" \
  "$([ "$RC6" -ne 0 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 7. .beads/issues.jsonl exists but is empty (0 bytes, no records) and a
#    finding cites a bead that IS actually closed -> hard failure, not a
#    silent pass. This is the vacuous-pass hole that scenario 4 (absent
#    bead ID = no signal) opened a back door to: an empty export produces
#    the exact same jq "no match" result as a bead merely not being in a
#    populated export, so without a record-count check, this scenario
#    would false-pass a genuinely closed bead's finding -- the very bug
#    this whole check exists to catch.
# ---------------------------------------------------------------------------
S7="$SANDBOX_ROOT/7-empty-export"
new_sandbox "$S7"
mkdir -p "$S7/.beads" "$S7/ai/findings"
: > "$S7/.beads/issues.jsonl"
printf 'Bead: fixture-closed-3\n\nSome finding body.\n' > "$S7/ai/findings/2026-08-27-fixture-empty-export-test.md"
git -C "$S7" add ai/findings/2026-08-27-fixture-empty-export-test.md .beads/issues.jsonl
RC7=$(run_gate "$S7")
assert "empty .beads/issues.jsonl is a hard failure, even though it would otherwise pass a closed bead's finding" \
  "$([ "$RC7" -ne 0 ] && echo 1 || echo 0)"
assert "empty-export failure names the unusable export, not just a generic error" \
  "$(grep -qF 'no bead records' "$S7/.gate-out" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 8. .beads/issues.jsonl exists and is non-empty but is not valid JSON ->
#    hard failure (set -e/pipefail already forces this) with THIS script's
#    own clear message identifying the export as malformed, not a bare jq
#    parse-error dump. An operator hitting a raw jq error in CI would have
#    to go read this script to work out what happened; a clear ERROR line
#    is the same posture already used for the missing-file and missing-jq
#    cases above.
# ---------------------------------------------------------------------------
S8="$SANDBOX_ROOT/8-malformed-export"
new_sandbox "$S8"
mkdir -p "$S8/.beads" "$S8/ai/findings"
printf '{"id": "fixture-open-1", "status": }\n' > "$S8/.beads/issues.jsonl"
printf 'Bead: fixture-open-1\n\nSome finding body.\n' > "$S8/ai/findings/2026-08-27-fixture-malformed-export-test.md"
git -C "$S8" add ai/findings/2026-08-27-fixture-malformed-export-test.md .beads/issues.jsonl
RC8=$(run_gate "$S8")
assert "malformed .beads/issues.jsonl is a hard failure" \
  "$([ "$RC8" -ne 0 ] && echo 1 || echo 0)"
assert "malformed-export failure states the export is invalid, not a bare jq error" \
  "$(grep -qF 'not valid JSONL' "$S8/.gate-out" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 9. Finding's `Bead:` header carries a trailing parenthetical (e.g. a note
#    naming a related bead) and the bead IS closed -> still fails. A whole-
#    line slurp would mangle the header into a compound string that never
#    matches any live record, silently passing a finding this check exists
#    to catch -- the same bug class fixed on the advisory side in
#    scripts/worktree-hygiene.sh.
# ---------------------------------------------------------------------------
S9="$SANDBOX_ROOT/9-trailing-parenthetical"
new_sandbox "$S9"
mkdir -p "$S9/.beads" "$S9/ai/findings"
printf '{"id":"fixture-closed-9","status":"closed"}\n' > "$S9/.beads/issues.jsonl"
printf 'Bead: fixture-closed-9 (see also fixture-other)\n\nSome finding body.\n' > "$S9/ai/findings/2026-08-27-fixture-trailing-test.md"
git -C "$S9" add ai/findings/2026-08-27-fixture-trailing-test.md .beads/issues.jsonl
RC9=$(run_gate "$S9")
assert "finding whose Bead: header has a trailing parenthetical still fails when the bead is closed" \
  "$([ "$RC9" -ne 0 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
