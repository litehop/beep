#!/usr/bin/env bash
# Unit test for scripts/worktree-hygiene.sh's pure functions.
#
# Exercises the REAL script as a subprocess via its `__call <fn> [args...]`
# entry point (same "real script, not a reimplementation" technique the
# sibling scripts/test-*-logic.sh suites use) -- a reimplementation of the
# branch-guard logic or patch-id check would keep passing even if the real
# logic regressed.
#
# Covers the three areas the extraction from mayor-bootstrap.md is
# load-bearing for:
#   1. STEP C's in-flight guard (checked_out_branches / is_checked_out) --
#      the mechanism that keeps a worker mid-dispatch from having its
#      branch force-deleted out from under it.
#   2. STEP C's patch-id merge check (is_unmerged_by_patch_id) -- the only
#      thing that distinguishes "safe to delete" from "would silently
#      destroy unmerged work," including the squash-merge case
#      `git branch --merged` would misjudge.
#   3. STEP D's gone-upstream match (gone_upstream_branches) -- must only
#      match branches whose upstream is actually `[gone]`, not ones with no
#      upstream configured at all (e.g. `investigation/*`).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/scripts/worktree-hygiene.sh"

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

call() {  # runs the real script's __call entry point, capturing stdout
  bash "$SCRIPT" __call "$@"
}

new_sandbox() {
  local dir="$1"
  git init -q -b main "$dir"
  git -C "$dir" config user.email test@example.com
  git -C "$dir" config user.name "Test"
}

SANDBOX_ROOT=$(mktemp -d)
trap 'rm -rf "$SANDBOX_ROOT"' EXIT

# ---------------------------------------------------------------------------
# 2. STEP C -- in-flight guard.
# ---------------------------------------------------------------------------

PORCELAIN='worktree /repo
HEAD abc123
branch refs/heads/main

worktree /worktrees/agent-live
HEAD def456
branch refs/heads/worker/agent-live'

CHECKED_OUT=$(call checked_out_branches "$PORCELAIN")
assert "checked_out_branches extracts every worktree's checked-out branch" \
  "$(printf '%s\n' "$CHECKED_OUT" | grep -qxF 'worker/agent-live' && printf '%s\n' "$CHECKED_OUT" | grep -qxF 'main' && echo 1 || echo 0)"

RC=0
call is_checked_out 'worker/agent-live' "$CHECKED_OUT" || RC=$?
assert "a branch checked out in a live worktree is guarded as in-flight (must not be force-deleted)" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call is_checked_out 'worker/agent-gone' "$CHECKED_OUT" || RC=$?
assert "a branch NOT checked out in any worktree is not guarded by the in-flight check" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3. STEP C -- patch-id merge check. Runs real git (not synthetic text)
#    against a disposable sandbox repo with a real `origin` remote, since
#    patch-id comparison genuinely needs two commit graphs.
# ---------------------------------------------------------------------------

BARE="$SANDBOX_ROOT/origin.git"
git init -q --bare "$BARE"

S="$SANDBOX_ROOT/patchid-repo"
new_sandbox "$S"
printf 'line one\n' > "$S/file.txt"
git -C "$S" add -A
git -C "$S" commit -q -m initial
git -C "$S" remote add origin "$BARE"
git -C "$S" push -q origin main

# Genuinely unmerged: a worker branch with a commit `origin/main` has never
# seen at all.
git -C "$S" branch worker/agent-unmerged main
git -C "$S" checkout -q worker/agent-unmerged
printf 'line one\nunmerged addition\n' > "$S/file.txt"
git -C "$S" commit -q -am 'unmerged work'
git -C "$S" checkout -q main

RC=0
WORKTREE_HYGIENE_REPO_ROOT="$S" call is_unmerged_by_patch_id worker/agent-unmerged >/dev/null 2>&1 || RC=$?
assert "a branch with commits origin/main has never seen at all is flagged unmerged (skip deletion)" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

# Genuinely merged: a branch that is a literal ancestor of origin/main (its
# commit was pushed straight to main) -- `git cherry` reports no output at
# all, since every commit in the branch is already reachable from upstream.
git -C "$S" branch worker/agent-ff-merged main
printf 'line one\nff merged addition\n' > "$S/file.txt"
git -C "$S" commit -q -am 'ff-mergeable work'
git -C "$S" push -q origin main
RC=0
WORKTREE_HYGIENE_REPO_ROOT="$S" call is_unmerged_by_patch_id worker/agent-ff-merged >/dev/null 2>&1 || RC=$?
assert "a branch whose commits are already an ancestor of origin/main is NOT flagged unmerged (safe to delete)" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# The squash-merge case mayor-bootstrap.md's design specifically calls out:
# origin/main gains a NEW commit with the same net patch as the branch's
# commit (a different SHA, as a real squash-merge produces) --
# `git branch --merged` would call this branch unmerged (its commit SHA
# isn't an ancestor), but `git cherry` detects the patch-id match and still
# produces output (a `-`-prefixed line) -- so this branch is ALSO guarded
# as "has output, skip" under the loop body's literal semantics, same as
# the genuinely-unmerged case above (the loop is a conservative backstop,
# not the primary merge-cleanup path -- that's the merge/dashboard script's
# job once a PR is confirmed merged).
git -C "$S" checkout -q -b worker/agent-squashed main
printf 'line one\nsquash payload\n' > "$S/file.txt"
git -C "$S" commit -q -am 'squash payload'
git -C "$S" checkout -q main
printf 'line one\nsquash payload\n' > "$S/file.txt"
git -C "$S" commit -q -am 'squash payload (squash-merged onto main under a new SHA)'
git -C "$S" push -q origin main
RC=0
WORKTREE_HYGIENE_REPO_ROOT="$S" call is_unmerged_by_patch_id worker/agent-squashed >/dev/null 2>&1 || RC=$?
assert "a squash-merged branch (same patch, different SHA) still produces cherry output and is guarded, matching mayor-bootstrap.md's literal 'any output -> skip' rule" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3b. STEP C -- open-PR guard. Observed 2026-08-28: PR #1433's
#    commits reached main via a DIFFERENT PR (#1435) while #1433 itself was
#    still open -- patch-id alone would call #1433's branch safe to delete,
#    but deleting it would auto-close the still-open PR and destroy its
#    review state. This must be judged on PR state, not patch-id.
# ---------------------------------------------------------------------------
OPEN_PRS='worker/agent-has-open-pr
worker/agent-other-open-pr'

RC=0
call has_open_pr 'worker/agent-has-open-pr' "$OPEN_PRS" || RC=$?
assert "a branch with an open PR is guarded, even though its commits might already be merged elsewhere by patch-id" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call has_open_pr 'worker/agent-no-pr' "$OPEN_PRS" || RC=$?
assert "a branch with no open PR is not guarded by the open-PR check" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3c. STEP C -- live-worktree-directory guard. Observed
#    2026-08-28: a worker switched its worktree to a scratch branch
#    mid-dispatch, leaving worker/agent-<id> checked out nowhere --
#    is_checked_out alone is blind to this since it only sees what's
#    checked out RIGHT NOW, not which worktree directories still exist.
# ---------------------------------------------------------------------------
LIVE_AGENT_DIR="$SANDBOX_ROOT/live-agent-worktrees/ai/worktrees/agent-live123"
mkdir -p "$LIVE_AGENT_DIR"

RC=0
call has_live_worktree_dir 'worker/agent-live123' "$SANDBOX_ROOT/live-agent-worktrees" || RC=$?
assert "a worker/agent-<id> branch with a live worktree directory is guarded, regardless of what that worktree currently has checked out" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call has_live_worktree_dir 'worker/agent-gone456' "$SANDBOX_ROOT/live-agent-worktrees" || RC=$?
assert "a worker/agent-<id> branch with no matching worktree directory is not guarded by this check" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

RC=0
call has_live_worktree_dir 'main' "$SANDBOX_ROOT/live-agent-worktrees" || RC=$?
assert "a non-worker/agent-* branch name (e.g. main) never matches this check, even if a coincidentally-named directory existed" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3d. STEP C -- --live-agents guard. THE only reliable liveness signal for
#    an in-process worker sub-agent (a sub-agent cannot call ListAgents on
#    itself, and `claude agents --json` doesn't enumerate in-process
#    subagents -- both confirmed directly). Fires FIRST and unconditionally,
#    ahead of every other STEP C guard, since it's the only one that isn't
#    itself derivable from stale git/filesystem state.
# ---------------------------------------------------------------------------

RC=0
call is_live_agent_branch 'worker/agent-abc123' 'xyz999,abc123,def456' || RC=$?
assert "a worker/agent-<id> branch whose id is ANY entry in a comma-separated --live-agents list is protected" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call is_live_agent_branch 'worker/agent-gone999' 'abc123,def456' || RC=$?
assert "a worker/agent-<id> branch whose id is NOT in --live-agents is not protected by this guard -- a genuinely stale branch must still be reapable" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

RC=0
call is_live_agent_branch 'worker/agent-abc123' '' || RC=$?
assert "an empty --live-agents set protects nothing -- an unknown agent must never be assumed live" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

RC=0
call is_live_agent_branch 'main' 'main' || RC=$?
assert "a non-worker/agent-* branch name never matches, even if it coincidentally equals a --live-agents entry" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3e. Whitespace-tolerant --live-agents membership match. A comma-space-
#    joined list (e.g. "a, b, c") must protect EVERY id, not just the
#    first -- without normalization, the naive ",${live_agents}," substring
#    match leaves a leading space on every id after the first, so only the
#    first id in the list ever matches and every subsequent live worker is
#    left unprotected/reapable.
# ---------------------------------------------------------------------------

RC=0
call agent_id_is_live 'abc123' 'abc123, def456, ghi789' || RC=$?
assert "sanity: a comma-space-joined --live-agents list protects the FIRST id" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call agent_id_is_live 'def456' 'abc123, def456, ghi789' || RC=$?
assert "...and it protects the MIDDLE id too -- fails without normalization, since \", \" leaves the id as \" def456\", which never equals the bare \"def456\" the substring match searches for" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call agent_id_is_live 'ghi789' 'abc123, def456, ghi789' || RC=$?
assert "...and it protects the LAST id too, proving every id in a comma-space-joined list is protected, not just the first" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call is_live_agent_branch 'worker/agent-def456' 'abc123, def456, ghi789' || RC=$?
assert "the same whitespace tolerance holds at the STEP C/D branch-guard level (is_live_agent_branch) -- this is what actually protects a live worker's branch from force-delete" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

# End-to-end: a worker branch that is ALREADY MERGED (ff-mergeable, so
# is_unmerged_by_patch_id says false), has no open PR, and no live worktree
# directory -- by every OTHER STEP C guard this branch is indistinguishable
# from a genuinely stale, safe-to-delete one. Only --live-agents membership
# can save it, proving the guard fires "unconditionally, regardless of dir
# existence or merge state" (the exact original bug: a ListAgents-confirmed-
# live worker's branch was force-deleted anyway because every OTHER signal
# said "safe").
BARE_LIVE="$SANDBOX_ROOT/origin-live.git"
git init -q --bare "$BARE_LIVE"

L="$SANDBOX_ROOT/step-c-live-agent-repo"
new_sandbox "$L"
printf 'line one\n' > "$L/file.txt"
git -C "$L" add -A
git -C "$L" commit -q -m initial
git -C "$L" remote add origin "$BARE_LIVE"
git -C "$L" push -q origin main

git -C "$L" branch worker/agent-liveagent456 main
printf 'line one\nmore work on main\n' > "$L/file.txt"
git -C "$L" commit -q -am 'advance main'
git -C "$L" push -q origin main

STUB_GH_NO_OPEN_PRS="$SANDBOX_ROOT/stub-gh-no-open-prs"
mkdir -p "$STUB_GH_NO_OPEN_PRS"
cat > "$STUB_GH_NO_OPEN_PRS/gh" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$STUB_GH_NO_OPEN_PRS/gh"

LIVE_AGENTS="liveagent456" WORKTREE_HYGIENE_REPO_ROOT="$L" PATH="$STUB_GH_NO_OPEN_PRS:$PATH" \
  call step_c_stale_worker_branches >/dev/null 2>&1
assert "STEP C protects a worker/agent-<id> branch whose id IS in --live-agents even though it's already merged, has no open PR, and no live worktree directory -- every other guard alone would have called it safe to delete" \
  "$(git -C "$L" branch --list worker/agent-liveagent456 | grep -q worker/agent-liveagent456 && echo 1 || echo 0)"

LIVE_AGENTS="" WORKTREE_HYGIENE_REPO_ROOT="$L" PATH="$STUB_GH_NO_OPEN_PRS:$PATH" \
  call step_c_stale_worker_branches >/dev/null 2>&1
assert "...the SAME branch, with no matching --live-agents entry, is force-deleted -- proving the guard (not some accident of the other checks) is what protected it above" \
  "$(! git -C "$L" branch --list worker/agent-liveagent456 | grep -q worker/agent-liveagent456 && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 4. STEP D -- gone-upstream match.
# ---------------------------------------------------------------------------

FOR_EACH_REF='main [ahead 1]
worker/agent-done [gone]
investigation/scratch
worker/agent-active [behind 2]'

GONE=$(call gone_upstream_branches "$FOR_EACH_REF")
assert "a branch with a [gone] upstream is matched for deletion" \
  "$(printf '%s\n' "$GONE" | grep -qxF 'worker/agent-done' && echo 1 || echo 0)"
assert "a branch with no upstream configured at all (no track field) is NOT matched (only [gone] counts, not merely absent)" \
  "$(! printf '%s\n' "$GONE" | grep -qxF 'investigation/scratch' && echo 1 || echo 0)"
assert "a branch that is merely behind (not gone) is NOT matched" \
  "$(! printf '%s\n' "$GONE" | grep -qxF 'worker/agent-active' && echo 1 || echo 0)"
assert "a branch that is ahead (not gone) is NOT matched" \
  "$(! printf '%s\n' "$GONE" | grep -qxF 'main' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 4b. STEP D -- checked-out guard, exercised end-to-end (not via a
#    reimplemented text check) against a disposable sandbox repo with a real
#    worktree, since the bug is a genuine `git branch -d` refusal, not a
#    text-matching mistake. Regression: observed 2026-09-06 twice (PRs
#    #1595, #1599) -- a worker branch's upstream goes `[gone]` the instant
#    the merge queue deletes its remote head, which can race ahead of the
#    tick that reaps its worktree. Unlike STEP C, STEP D had no
#    is_checked_out guard, so `git branch -d` on that still-checked-out
#    branch made git refuse, and this script's `set -e` turned that refusal
#    into a whole-run abort (skipping STEP E) on what is actually a benign,
#    self-resolving race.
# ---------------------------------------------------------------------------

BARE_D="$SANDBOX_ROOT/origin-d.git"
git init -q --bare "$BARE_D"

D="$SANDBOX_ROOT/step-d-repo"
new_sandbox "$D"
printf 'line one\n' > "$D/file.txt"
git -C "$D" add -A
git -C "$D" commit -q -m initial
git -C "$D" remote add origin "$BARE_D"
git -C "$D" push -q origin main

# A branch checked out in a second worktree, then merged and its remote
# head deleted -- exactly the merge-queue race: local upstream tracking
# still points at origin/worker/agent-gone, but that ref is gone.
git -C "$D" branch worker/agent-gone main
git -C "$D" push -q -u origin worker/agent-gone
git -C "$D" worktree add -q "$SANDBOX_ROOT/step-d-worktree" worker/agent-gone
git -C "$D" push -q origin --delete worker/agent-gone
git -C "$D" fetch -q --prune origin

RC=0
WORKTREE_HYGIENE_REPO_ROOT="$D" call step_d_gone_upstream_branches >/dev/null 2>&1 || RC=$?
assert "STEP D does not abort the whole hygiene tick (skipping STEP E) when a gone-upstream branch is still checked out in a live worktree" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"
assert "...and the branch itself survives -- skipped for the tick's reap, not force-deleted out from under the live worktree" \
  "$(git -C "$D" branch --list worker/agent-gone | grep -q worker/agent-gone && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 4c. STEP D -- --live-agents guard, exercised end-to-end against a
#    gone-upstream branch that is NOT checked out anywhere (unlike 4b
#    above, which covers the is_checked_out guard specifically) -- by
#    STEP D's only OTHER guard this branch is fully reapable via `-d`.
#    Only --live-agents membership can save it.
# ---------------------------------------------------------------------------

BARE_D2="$SANDBOX_ROOT/origin-d2.git"
git init -q --bare "$BARE_D2"

D2="$SANDBOX_ROOT/step-d-live-agent-repo"
new_sandbox "$D2"
printf 'line one\n' > "$D2/file.txt"
git -C "$D2" add -A
git -C "$D2" commit -q -m initial
git -C "$D2" remote add origin "$BARE_D2"
git -C "$D2" push -q origin main

git -C "$D2" branch worker/agent-liveagent789 main
git -C "$D2" push -q -u origin worker/agent-liveagent789
git -C "$D2" push -q origin --delete worker/agent-liveagent789
git -C "$D2" fetch -q --prune origin

LIVE_AGENTS="liveagent789" WORKTREE_HYGIENE_REPO_ROOT="$D2" call step_d_gone_upstream_branches >/dev/null 2>&1
assert "STEP D protects a gone-upstream worker/agent-<id> branch whose id IS in --live-agents, even though it's not checked out anywhere (STEP D's only other guard)" \
  "$(git -C "$D2" branch --list worker/agent-liveagent789 | grep -q worker/agent-liveagent789 && echo 1 || echo 0)"

LIVE_AGENTS="" WORKTREE_HYGIENE_REPO_ROOT="$D2" call step_d_gone_upstream_branches >/dev/null 2>&1
assert "...the SAME branch, with no matching --live-agents entry, is deleted -- proving the guard is what saved it above" \
  "$(! git -C "$D2" branch --list worker/agent-liveagent789 | grep -q worker/agent-liveagent789 && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 5. run_cmd dry-run gate -- the mechanism that keeps THIS test suite (and
#    any manual dry-run) from ever killing a real process or deleting a
#    real branch.
# ---------------------------------------------------------------------------

MARKER="$SANDBOX_ROOT/marker"
OUT=$(DRY_RUN=1 call run_cmd touch "$MARKER")
assert "DRY_RUN=1 logs the command instead of running it" \
  "$(printf '%s' "$OUT" | grep -q 'would run: touch' && echo 1 || echo 0)"
assert "...and the gated command genuinely did not execute" \
  "$([ ! -e "$MARKER" ] && echo 1 || echo 0)"

call run_cmd touch "$MARKER" >/dev/null
assert "without DRY_RUN, run_cmd executes the real command" \
  "$([ -e "$MARKER" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 6. STEP E -- findings-enforcement drift backstop. Only the two pure
#    functions are covered here (bead-id extraction and staleness
#    classification, which together fully capture the branching logic);
#    step_e_stale_findings() itself isn't, since it calls live `bd show`
#    against this repo's real, mutable bead state -- referencing a real
#    bead ID here would make the test's outcome depend on that bead's
#    status at whatever moment CI happens to run, silently flipping
#    PASS/FAIL as unrelated bead lifecycle events occur elsewhere. This was
#    instead verified manually against real live bd state during
#    development (a scratch ai/findings/*.md staged against a genuinely
#    closed bead, a genuinely open bead, and a nonexistent bead ID all
#    produced the expected warn/silent split) -- the same "exercise the
#    real thing, not a synthetic stand-in" principle this suite follows
#    elsewhere, just not automatable here without a disposable bd database.
# ---------------------------------------------------------------------------

# Fixture suffixes below are intentionally 2 chars, one below the real
# generator's 3-5 char range (see check-bead-id-refs.sh), so these
# synthetic bead-ID-shaped strings don't trip that guard's rot check --
# they're placeholders for the parser test, not references to real beads.
FINDING_CLOSED="$SANDBOX_ROOT/finding-closed.md"
printf 'Bead: mayor-fx\n\nBody text.\n' > "$FINDING_CLOSED"
assert "bead_id_from_finding extracts the bead id from a well-formed header" \
  "$([ "$(call bead_id_from_finding "$FINDING_CLOSED")" = "mayor-fx" ] && echo 1 || echo 0)"

FINDING_NO_HEADER="$SANDBOX_ROOT/finding-no-header.md"
printf 'Just prose, no bead reference.\n' > "$FINDING_NO_HEADER"
assert "bead_id_from_finding returns empty for a file with no Bead: header (must not be treated as a match for any bead)" \
  "$([ -z "$(call bead_id_from_finding "$FINDING_NO_HEADER")" ] && echo 1 || echo 0)"

# Regression: a header with trailing descriptive text (e.g. a parenthetical
# naming related beads) used to be slurped whole, whitespace stripped, into
# one mangled compound token that matches no live bd record -- so a real,
# still-open finding got flagged stale and recommended for deletion. The
# parser must stop at the first bead-ID token and ignore everything after.
FINDING_TRAILING="$SANDBOX_ROOT/finding-trailing.md"
printf 'Bead: mayor-tp (decision-prep for mayor-ab Phase 3 / mayor-cd)\n\nBody text.\n' > "$FINDING_TRAILING"
EXTRACTED_TRAILING=$(call bead_id_from_finding "$FINDING_TRAILING")
assert "bead_id_from_finding stops at the bead-ID token instead of slurping trailing text (incl. other mayor-* mentions) into a mangled string that would never match any live bead" \
  "$([ "$EXTRACTED_TRAILING" = "mayor-tp" ] && echo 1 || echo 0)"

# Feeding the correctly-extracted id's status through is_stale_bead_status
# as "open" proves the fix, not a coincidental match, is what keeps a live
# finding with a trailing-parenthetical header from being flagged stale.
RC=0
call is_stale_bead_status "open" || RC=$?
assert "a trailing-parenthetical header for an open bead ($EXTRACTED_TRAILING) is NOT flagged stale once the id is extracted correctly" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

RC=0
call is_stale_bead_status "closed" || RC=$?
assert "is_stale_bead_status flags a closed bead as stale (the case check-findings-closed-bead-refs.sh already catches via the export)" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call is_stale_bead_status "" || RC=$?
assert "is_stale_bead_status flags an empty (no live bd record) status as stale -- the pruned-bead hole the export-based CI check cannot see" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call is_stale_bead_status "open" || RC=$?
assert "is_stale_bead_status does NOT flag an open bead -- must not warn on every routine in-flight finding" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

RC=0
call is_stale_bead_status "in_progress" || RC=$?
assert "is_stale_bead_status does NOT flag an in_progress bead" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 7. main()'s fail-safe refusal without --live-agents. STEP C/D are
#    destructive (branch delete); dir-existence and merge-state checks
#    alone already proved insufficient to tell a live worker apart from a
#    stale one, so a missing flag must abort the whole run rather than
#    guess "assume none live" or "assume all live". This permanently
#    forecloses the reap-a-live-worker bug class via mis-invocation.
#    Invokes the real script directly (not via __call, which bypasses
#    main()'s own argv parsing and this exact gate) with no args at all --
#    safe because the refusal fires before any step runs, so no real git
#    state is ever touched.
# ---------------------------------------------------------------------------

FAILSAFE_RC=0
FAILSAFE_OUT=$(bash "$SCRIPT" 2>&1) || FAILSAFE_RC=$?
assert "worktree-hygiene refuses to run at all when --live-agents is omitted, exiting non-zero instead of silently defaulting" \
  "$([ "$FAILSAFE_RC" -eq 2 ] && echo 1 || echo 0)"
assert "...and the refusal is explained on stderr naming the missing flag, not a silent no-op" \
  "$(printf '%s' "$FAILSAFE_OUT" | grep -q -- '--live-agents' && echo 1 || echo 0)"
assert "...and no destructive-step log output appears at all -- STEP B/C/D/E never even started" \
  "$(! printf '%s' "$FAILSAFE_OUT" | grep -qE '\[hygiene\]|worktree prune' && echo 1 || echo 0)"

# Same fail-safe, but for a PRESENT --live-agents flag whose VALUE is empty
# or whitespace-only -- the flag TOKEN appearing in argv is not enough on
# its own; without checking the value too, `--live-agents ""` (e.g. a
# ListAgents call that returned zero running agents, mis-joined into an
# empty string instead of omitting the flag) would sail past a
# presence-only check and run the destructive steps with an effectively
# empty live set, reaping any genuinely live worker.
FAILSAFE_EMPTY_RC=0
FAILSAFE_EMPTY_OUT=$(bash "$SCRIPT" --live-agents "" 2>&1) || FAILSAFE_EMPTY_RC=$?
assert "worktree-hygiene refuses to run when --live-agents is present but its value is the empty string, exiting non-zero rather than treating it as a valid (if empty) live set" \
  "$([ "$FAILSAFE_EMPTY_RC" -eq 2 ] && echo 1 || echo 0)"
assert "...and no destructive-step log output appears at all for the empty-value case either" \
  "$(! printf '%s' "$FAILSAFE_EMPTY_OUT" | grep -qE '\[hygiene\]|worktree prune' && echo 1 || echo 0)"

FAILSAFE_WS_RC=0
FAILSAFE_WS_OUT=$(bash "$SCRIPT" --live-agents "   " 2>&1) || FAILSAFE_WS_RC=$?
assert "worktree-hygiene also refuses to run when --live-agents is whitespace-only -- a value that is non-empty as a raw string but carries no actual agent id must not bypass the fail-safe" \
  "$([ "$FAILSAFE_WS_RC" -eq 2 ] && echo 1 || echo 0)"
assert "...and no destructive-step log output appears at all for the whitespace-only case either" \
  "$(! printf '%s' "$FAILSAFE_WS_OUT" | grep -qE '\[hygiene\]|worktree prune' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 8. main()'s --no-live-workers flag -- the affirmative alternative to
#    --live-agents for the idle state, so a hygiene cron tick with zero
#    running workers doesn't have to fake a placeholder --live-agents id
#    just to get past the fail-safe guard above (which previously made
#    every zero-worker tick exit non-zero even on a verifiably clean repo).
# ---------------------------------------------------------------------------

STUB_GH_EMPTY="$SANDBOX_ROOT/stub-gh-empty"
mkdir -p "$STUB_GH_EMPTY"
cat > "$STUB_GH_EMPTY/gh" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$STUB_GH_EMPTY/gh"

NLW_REPO="$SANDBOX_ROOT/no-live-workers-repo"
new_sandbox "$NLW_REPO"
printf 'line one\n' > "$NLW_REPO/file.txt"
git -C "$NLW_REPO" add -A
git -C "$NLW_REPO" commit -q -m initial

NLW_RC=0
NLW_OUT=$(DRY_RUN=1 WORKTREE_HYGIENE_REPO_ROOT="$NLW_REPO" PATH="$STUB_GH_EMPTY:$PATH" bash "$SCRIPT" --no-live-workers 2>&1) || NLW_RC=$?
assert "worktree-hygiene --no-live-workers runs STEP B/C/D/E (not the fail-safe refusal) on a verifiably clean zero-worker tree, exiting 0 instead of crying wolf on every idle cron tick" \
  "$([ "$NLW_RC" -eq 0 ] && echo 1 || echo 0)"
assert "...proven by dry-run step output actually appearing, not just a bare exit 0 that could equally mean 'refused before running anything'" \
  "$(printf '%s' "$NLW_OUT" | grep -q -- '\[dry-run\] would run' && echo 1 || echo 0)"

# A bare empty --live-agents value must still refuse even now that
# --no-live-workers exists -- an omitted/empty --live-agents is
# indistinguishable from "the caller forgot the flag", and only the
# affirmative --no-live-workers flag above may waive the fail-safe.
NLW_STILL_EMPTY_RC=0
DRY_RUN=1 WORKTREE_HYGIENE_REPO_ROOT="$NLW_REPO" PATH="$STUB_GH_EMPTY:$PATH" bash "$SCRIPT" --live-agents "" >/dev/null 2>&1 || NLW_STILL_EMPTY_RC=$?
assert "worktree-hygiene still refuses to run on a bare empty --live-agents value now that --no-live-workers exists as the only valid zero-workers path" \
  "$([ "$NLW_STILL_EMPTY_RC" -eq 2 ] && echo 1 || echo 0)"

# Passing BOTH flags is a usage error, not "one wins" -- there is no way to
# tell which of two contradictory affirmative claims about the live-agent
# set the caller meant, and silently picking one risks reaping a live
# worker's branch if --live-agents was the intended (correct) flag.
NLW_BOTH_RC=0
NLW_BOTH_OUT=$(DRY_RUN=1 WORKTREE_HYGIENE_REPO_ROOT="$NLW_REPO" PATH="$STUB_GH_EMPTY:$PATH" bash "$SCRIPT" --live-agents "someagent" --no-live-workers 2>&1) || NLW_BOTH_RC=$?
assert "worktree-hygiene refuses to run when both --live-agents and --no-live-workers are passed together" \
  "$([ "$NLW_BOTH_RC" -eq 2 ] && echo 1 || echo 0)"
assert "...and the mutual-exclusion refusal names both flags on stderr, distinct from the missing-flag refusal message" \
  "$(printf '%s' "$NLW_BOTH_OUT" | grep -q -- 'mutually exclusive' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
