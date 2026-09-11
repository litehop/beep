#!/usr/bin/env bash
# Worktree hygiene loop body -- see the bootstrap doc's worktree-hygiene
# section for WHEN this runs (60m cron) and WHY it's auto-run instead of
# approval-gated. This file is the WHAT: the mechanical STEP B-E body,
# extracted out of that doc so a routine hygiene tick no longer costs an
# orchestrator model turn parsing `git` output by hand.
#
# --live-agents <comma-separated-agent-ids>: the mayor's own ListAgents-
# derived set of currently running worker/agent-* subagents. main() refuses
# to run at all without EITHER this or --no-live-workers below (see main()):
# dir-existence and merge-state checks alone already proved insufficient to
# tell a live worker's branch/worktree apart from a genuinely stale one, and
# STEP C/D are destructive (branch delete).
#
# --no-live-workers: an affirmative alternative to --live-agents for the
# idle state -- the caller has confirmed via ListAgents that ZERO
# worker/agent-* subagents are running, so STEP C/D run with an empty
# live-protection set. Mutually exclusive with --live-agents (passing both
# is a usage error). Deliberately distinct from an empty/omitted
# --live-agents value, which still refuses to run (see main()).
#
# STEP B: `git worktree prune -v` -- safe by definition, only removes
#   metadata for worktrees whose directories are already gone.
# STEP C: delete stale `worker/agent-*` branches, guarded so an in-flight
#   worker's branch (its agent-id is in --live-agents; checked out in some
#   worktree; or with a live worktree directory even if currently checked
#   out elsewhere), any branch unmerged by patch-id (catches squash-merges
#   too, which `git branch --merged` would miss), and any branch with an
#   open PR (patch-id alone can't see this: a PR's commits can reach main
#   via a DIFFERENT PR while the original stays open, and force-deleting
#   that branch auto-closes it, destroying review state) are never touched.
#   The --live-agents check fires first and unconditionally -- regardless
#   of dir existence or merge state -- since it's the only signal that
#   isn't itself derivable from stale git/filesystem state.
# STEP D: delete non-worker branches whose tracked upstream is gone, via
#   `-d` (refuses anything unmerged -- an extra safety net on top of D's
#   own scope, which never matches branches with no upstream at all), guarded
#   by the same --live-agents and in-flight checks STEP C uses so a branch
#   still checked out in a live worktree is skipped rather than erroring the
#   whole run when git refuses to delete it.
# STEP E: warn (never delete) about tracked ai/findings/*.md files whose
#   `Bead:` header is closed or absent from LIVE bd state -- the drift
#   backstop for check-findings-closed-bead-refs.sh's CI-side check, which
#   can only see the git-tracked bd export and so misses a bead closed
#   since the export's last commit, or pruned after closing.
#
# Exit codes: 0 = clean tick, nothing found. Non-zero = an anomaly for the
# mayor to look at: either a `git fetch`/`branch` failure in STEP B-D,
# surfaced via this script's own `set -e` with git's own exit code, or STEP
# E printing at least one `[hygiene] stale-finding: ...` line (tracked via
# an explicit count, not left to fall out of `set -e` incidentally) -- a
# non-zero exit is always accompanied by a message naming the anomaly, never
# silent. A missing/empty --live-agents flag with no --no-live-workers
# fallback (or passing both together) exits 2 before any step runs (see
# main()).
#
# DRY_RUN=1 turns every destructive command (git branch -D/-d) into a
# logged no-op via run_cmd() -- same idiom the sibling merge/dashboard
# script uses for its own dry-run gate -- so this script's test suite
# (scripts/test-worktree-hygiene-logic.sh) never deletes a real branch.
#
# Testability: `worktree-hygiene.sh __call <fn> [args...]` invokes a single
# function from this file and exits, the same convention used across
# scripts/ for exercising real logic (not a reimplementation) from tests.
set -euo pipefail

REPO_ROOT="${WORKTREE_HYGIENE_REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

run_cmd() {
  if [ "${DRY_RUN:-0}" = "1" ]; then
    echo "[dry-run] would run: $*"
  else
    "$@"
  fi
}

# ---------------------------------------------------------------------------
# --live-agents liveness guard, shared by STEP C/D. The mayor's own
# ListAgents call is the ONLY reliable signal that an in-process worker
# sub-agent is still running: a sub-agent cannot call ListAgents on itself,
# and `claude agents --json` doesn't enumerate in-process subagents (both
# confirmed directly). main() REFUSES to run any destructive step at all
# without --live-agents (see below) -- dir-existence and merge-state alone
# already proved insufficient to tell a live worker's branch/worktree apart
# from a genuinely stale one.
# ---------------------------------------------------------------------------
# Overridable via an inherited env var (not a CLI flag) purely so the test
# suite can drive individual STEP functions through `__call` -- which
# bypasses main()'s --live-agents argv parsing entirely -- without needing
# the whole main() pipeline just to exercise one step. Real invocations
# always go through main(), which unconditionally overwrites this from
# --live-agents, so a stray inherited env var can never substitute for the
# flag or defeat main()'s fail-safe refusal below.
LIVE_AGENTS="${LIVE_AGENTS:-}"

# Strips whitespace around each comma-separated token (and drops empty
# tokens from e.g. a trailing comma or a whitespace-only input), so
# "a, b, c" / "a,b,c" / " a ,b, c " all normalize to the same "a,b,c" --
# without this, a comma-space-joined --live-agents value leaves a leading
# space on every id after the first, which then never matches the exact
# ",${agent_id}," substring check below and under-protects every live
# worker but the first in the list.
normalize_live_agents() {
  local live_agents="$1"
  local out="" tok
  while IFS= read -r tok; do
    tok="${tok#"${tok%%[![:space:]]*}"}"
    tok="${tok%"${tok##*[![:space:]]}"}"
    [ -n "$tok" ] || continue
    out="${out:+${out},}${tok}"
  done <<< "$(printf '%s' "$live_agents" | tr ',' '\n')"
  printf '%s' "$out"
}

# True (exit 0) iff `agent_id` is present in the comma-separated
# --live-agents set. Empty `live_agents` (including whitespace-only, once
# normalized) never matches anything.
agent_id_is_live() {
  local agent_id="$1" live_agents="$2"
  [ -n "$agent_id" ] || return 1
  live_agents="$(normalize_live_agents "$live_agents")"
  [ -n "$live_agents" ] || return 1
  case ",${live_agents}," in
    *",${agent_id},"*) return 0 ;;
    *) return 1 ;;
  esac
}

# True (exit 0) iff `branch` is a worker/agent-<id> branch whose <id> is
# live per agent_id_is_live -- PROTECTS that branch/worktree from STEP
# C/D's delete unconditionally, regardless of dir existence or merge state.
# A non-worker/agent-* branch never matches, even if it coincidentally
# equals a --live-agents entry -- the same "name-shape gate before value
# comparison" discipline has_live_worktree_dir already uses below.
is_live_agent_branch() {
  local branch="$1" live_agents="$2"
  local agent_id="${branch#worker/agent-}"
  [ "$agent_id" != "$branch" ] || return 1
  agent_id_is_live "$agent_id" "$live_agents"
}

# ---------------------------------------------------------------------------
# STEP B -- worktree metadata.
# ---------------------------------------------------------------------------
step_b_prune_worktrees() {
  run_cmd git -C "$REPO_ROOT" worktree prune -v
}

# ---------------------------------------------------------------------------
# STEP C -- stale worker branches, in-flight-safe.
# ---------------------------------------------------------------------------

# Branches currently checked out in ANY worktree (the `branch
# refs/heads/<name>` lines of `git worktree list --porcelain`) -- these are
# in-flight workers (or the mayor's own checkout) and must never be
# force-deleted, including ones with no upstream pushed yet.
checked_out_branches() {
  printf '%s' "$1" | awk '/^branch refs\/heads\// {sub("refs/heads/","",$2); print $2}'
}

# True (exit 0) iff `branch` is in the given newline-separated
# checked_out_branches set -- the in-flight guard.
is_checked_out() {
  local branch="$1" checked_out="$2"
  printf '%s\n' "$checked_out" | grep -qxF "$branch"
}

# True (exit 0) iff `branch` has commits not yet reflected (by patch-id) in
# origin/main -- still unmerged, even via a squash-merge that `git branch
# --merged` would miss. Exercises real git rather than synthetic text
# because patch-id comparison genuinely needs two commit graphs; the test
# suite runs this against a disposable sandbox git repo.
is_unmerged_by_patch_id() {
  local branch="$1"
  [ -n "$(git -C "$REPO_ROOT" cherry origin/main "$branch" 2>/dev/null)" ]
}

# True (exit 0) iff `branch` appears in the given newline-separated list of
# open PRs' head branch names. Observed 2026-08-28: PR #1433's commits
# reached main via a different PR (#1435) while #1433 itself was still
# open -- is_unmerged_by_patch_id alone would call #1433's branch "safe to
# delete" since its patch-id is already in origin/main, but deleting a
# branch with an open PR makes GitHub auto-close that PR, destroying its
# review state and any unresolved threads. patch-id cannot see this; only
# a PR-state check can.
has_open_pr() {
  local branch="$1" open_pr_branches="$2"
  printf '%s\n' "$open_pr_branches" | grep -qxF "$branch"
}

# True (exit 0) iff `branch` is `worker/agent-<id>` and a live worktree
# directory ai/worktrees/agent-<id> exists, regardless of which branch that
# worktree currently has checked out. Observed 2026-08-28: a worker
# switched its worktree to a scratch branch mid-dispatch to build a
# throwaway PR, leaving worker/agent-<id> checked out nowhere -- the
# in-flight guard (is_checked_out) alone is blind to this, since it only
# protects a branch that's CURRENTLY checked out somewhere. The worktree
# directory name encodes the agent id directly, so this is a plain
# name-to-directory lookup rather than a snapshot of what's checked out
# right now.
has_live_worktree_dir() {
  local branch="$1" repo_root="$2"
  local agent_id="${branch#worker/agent-}"
  [ "$agent_id" != "$branch" ] && [ -d "$repo_root/ai/worktrees/agent-$agent_id" ]
}

step_c_stale_worker_branches() {
  run_cmd git -C "$REPO_ROOT" fetch origin main
  local porcelain checked_out branch open_pr_branches
  porcelain=$(git -C "$REPO_ROOT" worktree list --porcelain)
  checked_out=$(checked_out_branches "$porcelain")
  # Fetched once up front (not per-branch) to keep this to a single `gh`
  # call regardless of how many worker/agent-* branches exist. A `gh`
  # failure here aborts the whole tick via this script's own `set -e`
  # (see file header) rather than silently deleting branches without the
  # PR check that motivated this guard in the first place.
  open_pr_branches=$(gh pr list -R litehop/beep --state open --json headRefName --jq '.[].headRefName')
  while IFS= read -r branch; do
    [ -n "$branch" ] || continue
    case "$branch" in
      worker/agent-*) ;;
      *) continue ;;
    esac
    is_live_agent_branch "$branch" "$LIVE_AGENTS" && continue
    is_checked_out "$branch" "$checked_out" && continue
    is_unmerged_by_patch_id "$branch" && continue
    has_open_pr "$branch" "$open_pr_branches" && continue
    has_live_worktree_dir "$branch" "$REPO_ROOT" && continue
    run_cmd git -C "$REPO_ROOT" branch -D "$branch"
  done < <(git -C "$REPO_ROOT" for-each-ref --format='%(refname:short)' refs/heads/)
}

# ---------------------------------------------------------------------------
# STEP D -- non-worker branches with a gone upstream.
# ---------------------------------------------------------------------------

# Extracts branch names whose tracked upstream is `[gone]` from
# `git for-each-ref --format='%(refname:short) %(upstream:track)'` output.
# Pure text processing, so the test suite can feed synthetic for-each-ref
# lines without needing a real stale-upstream branch on disk.
gone_upstream_branches() {
  printf '%s' "$1" | awk '$2 == "[gone]" {print $1}'
}

step_d_gone_upstream_branches() {
  local refs branch checked_out
  refs=$(git -C "$REPO_ROOT" for-each-ref --format='%(refname:short) %(upstream:track)' refs/heads/)
  checked_out=$(checked_out_branches "$(git -C "$REPO_ROOT" worktree list --porcelain)")
  while IFS= read -r branch; do
    [ -n "$branch" ] || continue
    # A merged worker branch's upstream goes [gone] the instant the merge
    # queue deletes its remote head, which can race ahead of the tick that
    # reaps its worktree. `git branch -d` refuses to delete a branch checked
    # out in ANY live worktree regardless of merge state, and that refusal
    # would otherwise abort this whole run via `set -e` (see file header) --
    # leave it for the tick's reap (or the next hygiene run once the
    # worktree is gone) instead of erroring on a benign, self-resolving race.
    is_live_agent_branch "$branch" "$LIVE_AGENTS" && continue
    is_checked_out "$branch" "$checked_out" && continue
    run_cmd git -C "$REPO_ROOT" branch -d "$branch"
  done < <(gone_upstream_branches "$refs")
}

# ---------------------------------------------------------------------------
# STEP E -- findings-enforcement drift backstop.
#
# CI's check-findings-closed-bead-refs.sh reads .beads/issues.jsonl, the
# git-tracked bd export, which only refreshes at session-wrap commits and
# loses a bead entirely once it closes AND is later `bd prune`-d -- two
# documented holes on that check's own bead. This step reads LIVE bd
# state instead (bd IS available in the mayor's own environment, unlike
# CI's), closing both: a bead closed since the export was last committed,
# and a bead pruned after closing, which the export-based check can only
# treat as "no signal" since it can't tell "pruned" apart from "not
# exported yet". Live bd has no such staleness excuse, so this step
# treats "no live record at all" as ALSO stale, unlike the CI check.
#
# WARN-ONLY, not auto-delete: unlike STEP B-D (worktree metadata pruning,
# branch deletion -- neither of which touch the tracked tree or need a
# commit), deleting a findings/*.md file requires committing that
# deletion. An unattended cron sweep committing tree changes on its own is
# a materially bigger action than anything else in this loop, so this step
# reports loudly and leaves the delete-and-commit to a human or a
# follow-up workflow.
# ---------------------------------------------------------------------------

# Bead ID from a findings file's `Bead: <id>` header (first 5 lines), or
# empty if absent. Extracts only the leading bead-ID token, stopping before
# any trailing descriptive text (e.g. a parenthetical naming related beads)
# -- the old whitespace-stripped whole-line slurp mangled such a header into
# a compound string that would never match any live bd record, making this
# step warn to delete a finding that's actually still open. Matches both
# `mayor-*` (the u7s-monorepo prefix this script was imported with) and
# `beep-*` (this project's own prefix) -- a regex recognizing only the
# mayor prefix silently skipped every beep-* finding, making this whole
# step a no-op here.
#
# The final pipeline is guarded with `|| true`: under this script's
# `set -euo pipefail`, an unmatched grep (no Bead: header, or one this
# regex doesn't recognize) makes the pipeline itself exit non-zero, and the
# caller's bare `bead_id=$(bead_id_from_finding ...)` assignment then trips
# errexit and kills the whole run with no anomaly printed -- "no bead id
# found" is an expected, non-error outcome here, not a script failure.
bead_id_from_finding() {
  local f="$1" bead_line
  bead_line=$(head -n 5 "$f" | grep -m1 -E '^Bead: ' || true)
  printf '%s' "$bead_line" | grep -oE '(mayor|beep)-[a-z0-9.]+' | head -1 || true
}

# True (exit 0) iff a bead in the given live-bd status is stale enough to
# warn about: closed, or an empty status (bd has no live record at all --
# pruned after closing, or a bad reference; either way there's nothing left
# to cross-reference).
is_stale_bead_status() {
  local status="$1"
  [ "$status" = "closed" ] || [ -z "$status" ]
}

# Returns non-zero iff it printed at least one `[hygiene]` anomaly line --
# the explicit anomaly count main() relies on for its own exit status, so a
# clean tick (nothing stale) exits 0 and a reported anomaly is always
# accompanied by the message explaining it, never a silent non-zero exit.
step_e_stale_findings() {
  local findings f bead_id status stale_count=0
  findings=$(git -C "$REPO_ROOT" ls-files 'ai/findings/*.md' | grep -v '^ai/findings/legacy/') || true
  [ -n "$findings" ] || return 0

  while IFS= read -r f; do
    [ -n "$f" ] || continue
    bead_id=$(bead_id_from_finding "$REPO_ROOT/$f")
    [ -n "$bead_id" ] || continue
    status=$(bd -C "$REPO_ROOT" show "$bead_id" --json 2>/dev/null | jq -r '.[0]?.status // empty') || true
    if is_stale_bead_status "$status"; then
      stale_count=$(( stale_count + 1 ))
      if [ -z "$status" ]; then
        echo "[hygiene] stale-finding: $f references $bead_id, which bd has no live record of (pruned, or a bad reference) -- delete it, git history is the archive"
      else
        echo "[hygiene] stale-finding: $f references $bead_id, which is closed -- delete it, git history is the archive"
      fi
    fi
  done <<< "$findings"

  [ "$stale_count" -eq 0 ]
}

main() {
  local live_agents_provided=0 no_live_workers=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --live-agents)
        LIVE_AGENTS="${2:-}"
        live_agents_provided=1
        shift 2
        ;;
      --no-live-workers)
        no_live_workers=1
        shift
        ;;
      *)
        shift
        ;;
    esac
  done

  # Mutually exclusive: each flag is a different affirmative claim about
  # the live-agent set (a specific non-empty set vs. affirmatively empty),
  # and passing both leaves no way to tell which one the caller meant.
  if [ "$live_agents_provided" -eq 1 ] && [ "$no_live_workers" -eq 1 ]; then
    echo "worktree-hygiene: refusing to run -- --live-agents and --no-live-workers are mutually exclusive. Pass --live-agents <ids> when ListAgents shows running workers, or --no-live-workers when it shows zero -- never both." >&2
    exit 2
  fi

  if [ "$no_live_workers" -eq 1 ]; then
    # Affirmative idle-state declaration: run STEP C/D with an empty
    # live-protection set. This does NOT lower the staleness bar: STEP C's
    # merge-state and open-PR guards apply regardless of LIVE_AGENTS'
    # contents (see the file header), so a branch with an open, unmerged
    # PR is still preserved by STEP C even with zero live workers. STEP D
    # needs no such guard -- its scope (branches with a literally `[gone]`
    # tracked upstream) already excludes any branch an open PR keeps alive.
    LIVE_AGENTS=""
  # Fail-safe, not a default: STEP C/D are destructive (branch delete), and
  # dir-existence/merge-state alone already proved insufficient to
  # distinguish a live worker from a stale one (the bug this script exists
  # to close). Refusing outright on a missing flag -- rather than guessing
  # "assume none are live" or "assume all are live" -- permanently
  # forecloses the reap-a-live-worker bug class via mis-invocation, at the
  # cost of a no-op tick until the caller is fixed. Checking
  # normalize_live_agents' output (not just the raw flag/argv presence)
  # also closes an empty/whitespace-only value -- `--live-agents ""` or
  # `--live-agents "   "` -- which would otherwise sail past a
  # presence-only check and run the destructive steps with an effectively
  # empty live set. That case is indistinguishable from "forgot the flag"
  # and must still refuse -- --no-live-workers above is the only way to
  # affirmatively declare zero live workers.
  elif [ "$live_agents_provided" -ne 1 ] || [ -z "$(normalize_live_agents "$LIVE_AGENTS")" ]; then
    echo "worktree-hygiene: refusing to run -- --live-agents <comma-separated-agent-ids> (non-empty after trimming whitespace) or --no-live-workers is required. Without one there is no way to tell a live worker's branch/worktree apart from a stale one, and STEP C/D are destructive." >&2
    exit 2
  fi

  step_b_prune_worktrees
  step_c_stale_worker_branches
  step_d_gone_upstream_branches
  step_e_stale_findings
}

if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  if [ "${1:-}" = "__call" ]; then
    shift
    "$@"
  else
    main "$@"
  fi
fi
