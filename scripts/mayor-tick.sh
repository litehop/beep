#!/usr/bin/env bash
# Deterministic merge-PR pipeline + dashboard.md refresh for the mayor method.
#
# Replaces the mayor's per-turn model-driven work for the old 5m merge-PR
# loop and 10m dashboard-refresh loop. Session-log analysis
# (session 534747a7) showed those two loops firing on a tight cadence doing
# fully deterministic work -- queue drain, PR verdict parse, gh pr merge,
# post-merge cleanup, dashboard bookkeeping -- none of which needs a model
# turn. This script does that work; the mayor only wakes up when the exit
# code says there's a judgment call left.
#
# Split point: this script does `ls
# .claude/review-queue`, `gh pr list --json`, review-verdict parse, `gh pr
# merge` on gated CLEAN/BEHIND PRs, post-merge `git pull`/prune/worktree/branch
# cleanup, a self-heal reconciliation pass for any open worker PR the
# SubagentStop hook never queued at all, and the deterministic
# slices of ai/dashboard.md. The mayor still does: dispatching
# critical-reviewer for undrained queue entries (this script cannot invoke a
# Claude subagent), cluster-shape decisions on new `bd ready` beads, and
# investigating anything below couldn't gate cleanly.
#
# Exit code taxonomy (OR-able -- if multiple signals fire, the HIGHEST wins):
#   0  = noop, nothing for the mayor to do this tick.
#   10 = new dispatchable beads in `bd ready` -- mayor picks cluster shape
#        and dispatches workers.
#   20 = a merge/gate exception (CLEAN/BEHIND PR with no qualifying review,
#        or a needs-changes/needs-discussion verdict) OR undrained
#        review-queue entries (PR or non-PR) -- mayor investigates or
#        dispatches critical-reviewer.
#   30 = a worker worktree/branch with no PR at all -- mayor investigates.
#
# --live-agents <comma-separated-agent-ids>: the mayor's own ListAgents-
# derived set of currently running worker/agent-* subagents, fed in so
# check_worktree_anomalies (exit 30) can tell a genuinely stalled dispatch
# apart from one that's still actively running (see is_live_agent_branch).
# If omitted, LIVE_AGENTS stays empty and every no-PR worker branch reports
# as stale -- conservative-by-default for a NON-destructive reporting
# script, unlike worktree-hygiene.sh's hard fail-safe refusal.
#
# State file: .claude/mayor-tick-state.json (path overridable via
# MAYOR_TICK_STATE_FILE for tests). Written on every run; this is what the
# mayor reads to decide follow-up action without re-deriving any of it.
#
# MAYOR_TICK_DRY_RUN=1 turns every side-effecting external command (gh pr
# merge, git worktree remove, git branch -D, rm of a queue file, git pull/
# prune) into a logged no-op -- see run_cmd(). Used by this script's own
# test suite (scripts/test-mayor-tick-logic.sh) so tests never touch a real
# PR, worktree, or branch.
#
# Testability: `mayor-tick.sh __call <fn> [args...]` invokes a single
# function from this file and exits -- lets the test suite exercise the
# REAL pure functions (verdict parsing, timestamp comparison, exit-code
# selection, state-JSON construction) as a subprocess, the same convention
# scripts/test-check-bead-id-refs-logic.sh and siblings use, without
# needing network access or a live gh/bd session.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QUEUE_DIR="${MAYOR_TICK_QUEUE_DIR:-$REPO_ROOT/.claude/review-queue}"
STATE_FILE="${MAYOR_TICK_STATE_FILE:-$REPO_ROOT/.claude/mayor-tick-state.json}"
DASHBOARD_FILE="${MAYOR_TICK_DASHBOARD_FILE:-$REPO_ROOT/ai/dashboard.md}"
# Computed once per invocation (not per-call-site) so the state file's
# .timestamp and the dashboard's repo-state "As of" stamp are always the
# SAME instant -- two independent `date -u` calls a few pipeline steps
# apart could otherwise disagree by the seconds it takes refresh_dashboard
# to run, undermining the "authoritative freshness indicator" this exists
# to provide.
TICK_TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ---------------------------------------------------------------------------
# Side-effect gate. Every destructive/external-state-changing command in
# this script goes through here so MAYOR_TICK_DRY_RUN=1 can turn the whole
# pipeline into a dry preview (used by tests and available to an operator
# who wants to see what a tick would do before it does it).
# ---------------------------------------------------------------------------
run_cmd() {
  if [ "${MAYOR_TICK_DRY_RUN:-0}" = "1" ]; then
    echo "[dry-run] would run: $*"
  else
    "$@"
  fi
}

# ---------------------------------------------------------------------------
# Pure helpers (unit-tested directly via `__call`).
# ---------------------------------------------------------------------------

# The SubagentStop hook (scripts/critical-reviewer-dispatch.sh) stamps
# `queued_at` as `%Y-%m-%dT%H-%M-%SZ` (dashes, not colons -- filesystem-safe
# for a filename). GitHub's review `submittedAt` is standard ISO-8601 with
# colons. Normalize the hook's format to GitHub's so a plain string compare
# orders them correctly.
normalize_queued_at() {
  printf '%s' "$1" | sed -E 's/^([0-9]{4}-[0-9]{2}-[0-9]{2})T([0-9]{2})-([0-9]{2})-([0-9]{2})Z$/\1T\2:\3:\4Z/'
}

# True (exit 0) iff a string matches the SubagentStop hook's exact
# `queued_at` format. Used to fail CLOSED (not-drained) on a missing or
# malformed frontmatter field instead of silently treating it as
# already-drained: an empty queued_at compares as less than any non-empty
# submitted_at, so without this check a broken queue file would get rm'd
# on the next tick regardless of whether a review actually answers it.
is_valid_queued_at() {
  [[ "$1" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}-[0-9]{2}-[0-9]{2}Z$ ]]
}

# True (exit 0) iff a critical-reviewer review was submitted AFTER this
# queue entry was queued -- i.e. the queue entry is drained and its file
# can be removed. False (exit 1) for a missing/malformed queued_at
# (fail-closed -- see is_valid_queued_at), "no review yet" (empty
# submitted_at), or "review predates this queue entry" (a stale review
# from a prior round must not mask an unreviewed re-queue).
queue_is_drained() {
  local queued_at="$1" submitted_at="$2"
  is_valid_queued_at "$queued_at" || return 1
  [ -z "$submitted_at" ] && return 1
  local norm
  norm=$(normalize_queued_at "$queued_at")
  [[ "$submitted_at" > "$norm" ]]
}

# Backstop for the pending_reviews dispatch marker (see
# queue_entry_dispatch_suppressed below): once a marker is this old, treat
# the earlier presumed dispatch as dead -- a crashed/stuck reviewer, or the
# mayor never actually acted on the prior pending_reviews listing -- and
# surface the entry again rather than trusting the marker forever.
QUEUE_DISPATCH_MARKER_MAX_AGE_SECONDS=$((15 * 60))

# Path to the on-disk marker recording "this script already surfaced this
# queue entry in pending_reviews". Lives in its own subdirectory, never
# touched by the SubagentStop hook, so this script is the sole reader AND
# writer -- keyed on the queue file's basename, which is unique per active
# entry (pr_already_queued's no-double-queue invariant already relies on
# this).
dispatch_marker_path() {
  printf '%s/.dispatched/%s.marker' "$QUEUE_DIR" "$(basename "$1")"
}

# Epoch seconds recorded in a queue entry's dispatch marker, or empty if
# none exists (or it's unreadable). Empty is the FIRST-SIGHTING case and
# must be treated as immediately dispatchable, never as in-flight.
read_dispatch_marker() {
  local marker_file
  marker_file=$(dispatch_marker_path "$1")
  # No matching-branch `if` returns 0, unlike `[ -f ... ] && cat ...`, whose
  # short-circuit on a missing marker (the routine first-sighting case)
  # would return 1 and abort the whole script under `set -e` at the caller.
  if [ -f "$marker_file" ]; then
    cat "$marker_file" 2>/dev/null
  fi
}

# True (exit 0) iff a not-yet-drained review-queue entry must be SUPPRESSED
# from pending_reviews this tick because a dispatch was already recorded
# for it recently. The discriminator is dispatch STATE (does a marker
# exist and is it fresh), not the queue entry's own age: dispatch happens
# ONLY via pending_reviews (see the mayor's own bootstrap doc), so a
# brand-new entry with no marker yet must surface on its very FIRST
# sighting. An age-only gate has this exactly backwards -- a fresh entry's
# age is always near zero, which an age gate would misread as "already
# handled", delaying every entry's first dispatch by a full tick. False
# (surface it) on a missing marker (first sighting) OR a marker older than
# the backstop -- fails toward surfacing, matching queue_is_drained's
# neighbors, never toward a permanent hide.
queue_entry_dispatch_suppressed() {
  local marker_epoch="$1" now_epoch="$2"
  [ -z "$marker_epoch" ] && return 1
  [ $(( now_epoch - marker_epoch )) -lt "$QUEUE_DISPATCH_MARKER_MAX_AGE_SECONDS" ]
}

# Comma-separated worker/agent-<id> ids the mayor's own ListAgents call
# reports as currently running, fed in via --live-agents (see main()) --
# THE only reliable liveness signal for an in-process worker sub-agent: a
# sub-agent cannot call ListAgents on itself, and `claude agents --json`
# doesn't enumerate in-process subagents (both confirmed directly). This
# replaces a prior wall-clock/commit-epoch window entirely -- for a worker
# that hasn't committed yet, "age since last commit" measured the BASE
# commit's time, not the worker's own dispatch time, so age was the wrong
# signal at any window size. Empty (the flag omitted) means "no live agents
# known" -- see is_live_agent_branch's fail-toward-surfacing default.
LIVE_AGENTS=""

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
# normalized) never matches anything -- an unknown liveness state must
# never be read as "assume live", which is exactly the failure mode that
# let the old wall-clock window misclassify a genuinely live worker as
# stale well within its own working window.
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
# live per agent_id_is_live -- a worker worktree with no PR yet whose agent
# is confirmed still running must be reported informationally without
# escalating the tick's exit code (exit 30 firing on every routine dispatch
# trains the mayor to ignore it, so a genuinely stalled dispatch goes
# unnoticed). A non-worker/agent-* branch name never matches, even if it
# coincidentally equals a --live-agents entry -- the same "name-shape gate
# before value comparison" discipline worktree-hygiene.sh's
# has_live_worktree_dir already uses for its own agent-id extraction.
is_live_agent_branch() {
  local branch="$1" live_agents="$2"
  local agent_id="${branch#worker/agent-}"
  [ "$agent_id" != "$branch" ] || return 1
  agent_id_is_live "$agent_id" "$live_agents"
}

# Extracts the value after "**Verdict**:" from a critical-reviewer findings
# body. Only LGTM / LGTM-with-suggestions satisfy the merge gate; anything
# else (needs-changes, needs-discussion, or no match at all -> empty) does
# not, even though the `## critical-reviewer findings` header is present.
parse_verdict() {
  printf '%s\n' "$1" | grep -oE '\*\*Verdict\*\*:[[:space:]]*[A-Za-z-]+' | head -1 \
    | sed -E 's/^\*\*Verdict\*\*:[[:space:]]*//'
}

# True (exit 0) iff a verdict string blocks the merge gate -- needs-changes
# or needs-discussion. An empty/unrecognized verdict is NOT blocking here
# (it's a malformed body, not a confirmed blocking signal); shared by the
# stale-blocking-verdict reconcile check below.
verdict_is_blocking() {
  case "$1" in
    needs-changes|needs-discussion) return 0 ;;
    *) return 1 ;;
  esac
}

# Given a JSON array of GitHub PR reviews (the `reviews` field from `gh pr
# view --json reviews`), returns the latest (by submittedAt) review object
# whose body starts with the critical-reviewer marker, as compact JSON --
# or empty if none qualify. Resolving by time, not mere marker presence, is
# what stops an older superseded LGTM from masking a newer needs-changes
# verdict (a real incident hit this exact gap at the PR-verdict layer; see
# git history, not a citation here that would rot once that PR closes).
#
# DISMISSED reviews are excluded before the latest-by-time pick: once a
# needs-changes verdict becomes a native REQUEST_CHANGES review, dismissing
# it clears GitHub's own merge block but the review body's text still reads
# needs-changes -- without this filter the text-parse gate below would keep
# refusing the PR even after the operator dismissed it, a deadlock neither
# gate could release.
latest_reviewer_review() {
  printf '%s' "$1" | jq -c \
    '[.[] | select(.body | startswith("## critical-reviewer findings")) | select(.state != "DISMISSED")] | sort_by(.submittedAt) | last // empty'
}

# True (exit 0) iff a PR's merge-queue/check state makes it eligible for
# the review-verdict gate at all. CLEAN and BEHIND both qualify -- queuing
# a BEHIND PR is the merge queue's job to rebase, not the mayor's, so it
# must not be silently skipped forever; anything else (DIRTY, BLOCKED,
# UNKNOWN, ...) does not. Checks must be genuinely complete and non-failing
# regardless of merge state. A draft PR is excluded via its own isDraft
# field rather than folded into the mss case above -- GitHub has been
# observed reporting mergeStateStatus=CLEAN for a draft PR (a deliberate
# mayor hold), and `gh pr merge` unconditionally rejects a draft with a
# GraphQL error that would otherwise abort the whole tick under `set -e`.
pr_gate_eligible() {
  local mss="$1" pending="$2" failed="$3" is_draft="${4:-false}"
  [ "$is_draft" = "true" ] && return 1
  case "$mss" in
    CLEAN|BEHIND) ;;
    *) return 1 ;;
  esac
  [ "${pending:-0}" -eq 0 ] || return 1
  [ "${failed:-0}" -eq 0 ] || return 1
  return 0
}

# Highest-signal-wins exit code selection: non-zero exit codes are OR-able
# -- the highest set signal wins if multiple fire. 30 (worktree/hygiene)
# outranks 20 (gate/queue exception) outranks 10 (new
# dispatchable work) -- a worktree anomaly is the kind of thing that can
# make a merge decision wrong, so it must not be masked by a same-tick
# routine bd-ready signal.
compute_exit_code() {
  local bd_ready="$1" exceptions="$2" worktree="$3"
  local code=0
  [ "$bd_ready" -gt 0 ] && [ "$code" -lt 10 ] && code=10
  [ "$exceptions" -gt 0 ] && [ "$code" -lt 20 ] && code=20
  [ "$worktree" -gt 0 ] && [ "$code" -lt 30 ] && code=30
  printf '%s' "$code"
}

# Reads one `key: value` field from a review-queue file's YAML frontmatter
# (the block between the first two `---` lines).
frontmatter_field() {
  local file="$1" field="$2"
  awk -v f="$field" '
    /^---[[:space:]]*$/ { c++; next }
    c==1 && $0 ~ "^"f":" { sub("^"f":[[:space:]]*",""); print; exit }
  ' "$file"
}

# Pure dtype-routing decision behind process_review_queue's case statement:
# given one queue entry's frontmatter (file/dtype/dref), decides which state
# bucket it belongs in -- "pr" (payload is the extracted PR number, empty if
# dref didn't end in one), "non-pr" (payload is the JSON object for
# pending_non_pr_reviews), or "warning" (payload is the JSON object for
# queue_warnings, covering any dtype -- missing or unrecognized -- this
# script doesn't know how to drain; see the queue_warnings comment on why
# that must surface for the mayor instead of silently vanishing). Extracted
# from process_review_queue so dtype routing is directly testable without a
# gh network call or global-array mutation. Output is "<bucket>\t<payload>"
# on one line.
route_deliverable() {
  local file="$1" dtype="$2" dref="$3"
  case "$dtype" in
    pr)
      printf 'pr\t%s' "$(printf '%s' "$dref" | grep -oE '[0-9]+$' || true)"
      ;;
    findings|bead-close|bead-supersede)
      printf 'non-pr\t%s' "$(jq -nc --arg file "$file" --arg dtype "$dtype" --arg dref "$dref" '{file:$file, deliverable_type:$dtype, deliverable_ref:$dref}')"
      ;;
    *)
      printf 'warning\t%s' "$(jq -nc --arg file "$file" --arg dtype "$dtype" --arg reason "unrecognized-deliverable-type" '{file:$file, deliverable_type:$dtype, reason:$reason}')"
      ;;
  esac
}

# True (exit 0) iff an active review-queue file's deliverable_ref names this
# exact PR URL -- the no-double-queue guard: a PR already tracked by an
# (undrained) queue file must not also get a reconciliation-synthesized
# duplicate pending_reviews entry. `processed/` is not checked -- that
# archive directory was deleted; a drained file's audit trail is git
# history plus the review on the PR itself, not an archive directory.
pr_already_queued() {
  local url="$1" f dref
  for f in "$QUEUE_DIR"/*.md; do
    [ -e "$f" ] || continue
    dref=$(frontmatter_field "$f" deliverable_ref)
    [ "$dref" = "$url" ] && return 0
  done
  return 1
}

# True (exit 0) iff any commit's committedDate in the given JSON array of
# commits (the `commits` field from `gh pr view --json commits`) is newer
# than `cutoff` -- the discriminator the stale-blocking-verdict reconcile
# check uses between "fixed but never re-reviewed" (queue a re-review) and
# "reviewed, nothing has changed since" (nothing new for a reviewer to look
# at). Compares real ISO-8601 timestamps, never array position or count.
has_commit_after() {
  local commits_json="$1" cutoff="$2"
  printf '%s' "$commits_json" | jq -e --arg cutoff "$cutoff" \
    'any(.[]; .committedDate > $cutoff)' >/dev/null 2>&1
}

json_array() {  # plain strings -> JSON array of strings
  if [ "$#" -eq 0 ]; then printf '[]'; return; fi
  printf '%s\n' "$@" | jq -R . | jq -s -c .
}

json_number_array() {  # plain integers -> JSON array of numbers
  if [ "$#" -eq 0 ]; then printf '[]'; return; fi
  printf '%s\n' "$@" | jq -R 'tonumber' | jq -s -c .
}

json_raw_array() {  # pre-built JSON object strings -> JSON array
  if [ "$#" -eq 0 ]; then printf '[]'; return; fi
  printf '%s\n' "$@" | jq -s -c .
}

# Writes the state file the mayor reads to decide follow-up action. Kept as
# a pure function of its arguments (no reliance on this script's own global
# arrays) so the test suite can call it directly with synthetic data and
# validate the JSON shape without running the rest of the pipeline.
write_state() {
  local exit_code="$1" queue_files_json="$2" pending_reviews_json="$3" \
    merged_prs_json="$4" bd_ready_json="$5" worktree_anomalies_json="$6" \
    gate_exceptions_json="$7" pending_non_pr_json="${8:-[]}" \
    queue_warnings_json="${9:-[]}"
  jq -n \
    --arg ts "$TICK_TIMESTAMP" \
    --argjson exit_code "$exit_code" \
    --argjson queue_files "$queue_files_json" \
    --argjson pending_reviews "$pending_reviews_json" \
    --argjson merged_prs "$merged_prs_json" \
    --argjson bd_ready_ids "$bd_ready_json" \
    --argjson worktree_anomalies "$worktree_anomalies_json" \
    --argjson gate_exceptions "$gate_exceptions_json" \
    --argjson pending_non_pr_reviews "$pending_non_pr_json" \
    --argjson queue_warnings "$queue_warnings_json" \
    '{timestamp:$ts, exit_code:$exit_code, queue_files:$queue_files,
      pending_reviews:$pending_reviews, merged_prs:$merged_prs,
      bd_ready_ids:$bd_ready_ids, worktree_anomalies:$worktree_anomalies,
      gate_exceptions:$gate_exceptions,
      pending_non_pr_reviews:$pending_non_pr_reviews,
      queue_warnings:$queue_warnings}' \
    > "$STATE_FILE"
}

# ---------------------------------------------------------------------------
# Dashboard splice. ai/dashboard.md has judgment sections the mayor writes
# by hand (IN PROGRESS, DECISION POINT, WAVE plans) and deterministic
# sections this script owns, delimited by sentinel comments. Only the text
# between a BEGIN/END pair is ever touched.
# ---------------------------------------------------------------------------

# Actual dashboard-file mutations, isolated into their own tiny functions
# so run_cmd's dry-run gate (echo instead of exec) covers them exactly like
# every gh/git/rm call in this script -- a raw shell redirection (`mv`,
# `>>`) can't be passed through run_cmd's "$@" directly, so the mutation
# itself has to live behind a named command run_cmd CAN gate.
_dashboard_replace_from_tmp() {  # $1 = awk-computed tmp file to move into place
  mv "$1" "$DASHBOARD_FILE"
}
_dashboard_append_section() {  # $1 = fully-formed "## heading\n<sentinel>\n...\n" text
  printf '%s' "$1" >> "$DASHBOARD_FILE"
}

# $1=sentinel id  $2=ERE matching an existing "## ..." heading line (for
# first-run migration onto a pre-existing freeform section)  $3=heading text
# to use if no such heading exists yet (genuinely new dashboard)  $4=body.
splice_dashboard_section() {
  local id="$1" heading_re="$2" heading_text="$3" content="$4"
  local begin="<!-- BEGIN AUTO: ${id} -->"
  local end="<!-- END AUTO: ${id} -->"

  # $content is frequently multi-line (2+ worktrees, 2+ open PRs, ...).
  # BSD awk (macOS's /usr/bin/awk) rejects an embedded newline in a -v
  # scalar with "newline in string", killing the whole tick before the
  # state file is written. Route the body through a temp file and
  # getline it inside awk's BEGIN block instead of passing it via -v.
  local body_tmp
  body_tmp="$(mktemp "${DASHBOARD_FILE}.body.XXXXXX")"
  printf '%s\n' "$content" > "$body_tmp"

  if grep -qF "$begin" "$DASHBOARD_FILE"; then
    awk -v b="$begin" -v e="$end" -v bodyfile="$body_tmp" '
      BEGIN {
        n=0
        while ((getline line < bodyfile) > 0) { body = (n==0 ? line : body "\n" line); n++ }
      }
      $0==b {print; print body; skip=1; next}
      $0==e {print; skip=0; next}
      skip {next}
      {print}
    ' "$DASHBOARD_FILE" > "${DASHBOARD_FILE}.tmp"
    run_cmd _dashboard_replace_from_tmp "${DASHBOARD_FILE}.tmp"
    rm -f "${DASHBOARD_FILE}.tmp"  # no-op if already mv'd; cleans up a dry-run's leftover
    rm -f "$body_tmp"
    return
  fi

  if grep -qE "$heading_re" "$DASHBOARD_FILE"; then
    # First run against a dashboard that already has this section as
    # freeform prose (pre-mayor-tick.sh): replace everything from that
    # heading up to (not including) the next "## " heading or EOF with the
    # sentinel-wrapped body, so the section becomes script-owned in place
    # instead of duplicating a second copy of the heading at the file end.
    awk -v re="$heading_re" -v b="$begin" -v e="$end" -v bodyfile="$body_tmp" '
      BEGIN {
        done=0; n=0
        while ((getline line < bodyfile) > 0) { body = (n==0 ? line : body "\n" line); n++ }
      }
      !done && $0 ~ re { print; print b; print body; print e; done=1; skip=1; next }
      skip && /^## / { skip=0 }
      skip { next }
      { print }
    ' "$DASHBOARD_FILE" > "${DASHBOARD_FILE}.tmp"
    run_cmd _dashboard_replace_from_tmp "${DASHBOARD_FILE}.tmp"
    rm -f "${DASHBOARD_FILE}.tmp"
  else
    run_cmd _dashboard_append_section "$(printf '\n## %s\n%s\n%s\n%s\n' "$heading_text" "$begin" "$content" "$end")"
  fi
  rm -f "$body_tmp"
}

dashboard_open_prs() {
  local json count
  json=$(gh pr list --state open --json number,title,headRefName,mergeStateStatus 2>/dev/null || echo '[]')
  count=$(printf '%s' "$json" | jq 'length' 2>/dev/null || echo 0)
  if [ "$count" -eq 0 ]; then
    printf 'None open.'
    return
  fi
  printf '%s' "$json" | jq -r '.[] | "- #\(.number) \(.title) (`\(.headRefName)`, \(.mergeStateStatus))"'
}

dashboard_worktrees() {
  local out="" path branch
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    [ "$path" = "$REPO_ROOT" ] && continue
    branch=$(git -C "$path" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')
    out="${out}${out:+$'\n'}- \`$path\` (\`$branch\`)"
  done < <(git -C "$REPO_ROOT" worktree list --porcelain | awk '/^worktree / {print $2}')
  if [ -z "$out" ]; then
    printf 'None (no active worker worktrees).'
  else
    printf '%s' "$out"
  fi
}

dashboard_cron_loops() {
  printf '15m mayor tick (`scripts/mayor-tick.sh`) · 60m reread posture · 60m worktree hygiene'
}

dashboard_repo_state() {
  local branch sha dirty counts ahead behind sync
  branch=$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')
  sha=$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo '?')
  if [ -n "$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null)" ]; then dirty="dirty"; else dirty="clean"; fi
  git -C "$REPO_ROOT" fetch -q origin main 2>/dev/null || true
  counts=$(git -C "$REPO_ROOT" rev-list --left-right --count HEAD...origin/main 2>/dev/null || echo "0 0")
  ahead=$(printf '%s' "$counts" | awk '{print $1}')
  behind=$(printf '%s' "$counts" | awk '{print $2}')
  if [ "${ahead:-0}" = "0" ] && [ "${behind:-0}" = "0" ]; then
    sync="up to date with origin/main"
  else
    sync="${ahead:-0} ahead / ${behind:-0} behind origin/main"
  fi
  printf 'As of %s (last tick) — Branch `%s` @ `%s`, %s, %s.' "$TICK_TIMESTAMP" "$branch" "$sha" "$dirty" "$sync"
}

dashboard_review_queue() {
  local count
  count=$(find "$QUEUE_DIR" -maxdepth 1 -name '*.md' -type f 2>/dev/null | wc -l | tr -d ' ')
  printf '%s pending review-queue entries.' "$count"
}

refresh_dashboard() {
  [ -f "$DASHBOARD_FILE" ] || return 0
  splice_dashboard_section "open-prs" '^## .*Open PRs' '🔎 Open PRs' "$(dashboard_open_prs)"
  splice_dashboard_section "worktrees" '^## .*Worktrees' '🌲 Worktrees / hygiene' "$(dashboard_worktrees)"
  splice_dashboard_section "cron-loops" '^## .*Cron loops' '🔁 Cron loops' "$(dashboard_cron_loops)"
  splice_dashboard_section "repo-state" '^## Repo state' 'Repo state' "$(dashboard_repo_state)"
  splice_dashboard_section "review-queue" '^## .*Review queue' '📋 Review queue' "$(dashboard_review_queue)"
}

# ---------------------------------------------------------------------------
# Pipeline steps. Populate the globals main() reads to compute the exit
# code and write the state file.
# ---------------------------------------------------------------------------

QUEUE_FILES_REMAINING=()
PENDING_REVIEW_PRS=()
PENDING_NON_PR_REVIEWS=()
QUEUE_WARNINGS=()
GATE_EXCEPTIONS=()
MERGED_PRS=()
BD_READY_IDS=()
WORKTREE_ANOMALIES=()
WORKTREE_STALE_COUNT=0  # subset of WORKTREE_ANOMALIES old enough to escalate the exit code

# Step 0: drain the review queue. This is NOT reviewer dispatch (this
# script cannot invoke a Claude subagent) -- it only confirms whether a
# queue entry's deliverable already got reviewed since it was queued, and
# if so removes the queue file (rm, not mv-to-processed/ -- the audit
# trail is git history plus the review posted on the PR itself, both
# durable and both outside .claude/). Anything still undrained stays
# queued for the mayor to dispatch critical-reviewer against.
#
# Only `pr` deliverables get an automated drain check: `gh pr view` gives
# an unambiguous per-review submittedAt to compare against queued_at.
# `findings`/`bead-close`/`bead-supersede` deliverables post to bd notes
# instead (see .claude/agents/critical-reviewer.md's "Output & posting"),
# and bd's CLI exposes no per-note timestamp; a bead-supersede ref can also
# legitimately resolve to either of two beads. Self-confirming those risks
# a false "drained" against the wrong bead's unrelated update, so they are
# always surfaced in PENDING_NON_PR_REVIEWS for the mayor to confirm by
# hand instead of silently sitting undrained with no visibility.
process_review_queue() {
  local f dtype dref queued_at prnum submitted_at reviews_json latest route bucket payload marker_epoch
  for f in "$QUEUE_DIR"/*.md; do
    [ -e "$f" ] || continue
    dtype=$(frontmatter_field "$f" deliverable_type)
    dref=$(frontmatter_field "$f" deliverable_ref)
    queued_at=$(frontmatter_field "$f" queued_at)
    if ! is_valid_queued_at "$queued_at"; then
      QUEUE_WARNINGS+=("$(jq -nc --arg file "$f" --arg reason "missing-or-malformed-queued_at" '{file:$file, reason:$reason}')")
    fi
    route=$(route_deliverable "$f" "$dtype" "$dref")
    bucket="${route%%$'\t'*}"
    payload="${route#*$'\t'}"
    case "$bucket" in
      pr)
        prnum="$payload"
        if [ -n "$prnum" ]; then
          reviews_json=$(gh pr view "$prnum" --json reviews --jq '.reviews' 2>/dev/null || echo '[]')
          latest=$(latest_reviewer_review "$reviews_json")
          submitted_at=$(printf '%s' "$latest" | jq -r '.submittedAt // empty' 2>/dev/null || true)
          if queue_is_drained "$queued_at" "$submitted_at"; then
            run_cmd rm -f "$f"
            run_cmd rm -f "$(dispatch_marker_path "$f")"
            continue
          fi
          # Still undrained: surface it UNLESS a dispatch was already
          # recorded for it recently. The discriminator is dispatch STATE
          # (a marker), not the entry's own age -- dispatch happens ONLY
          # via pending_reviews (see the mayor's own bootstrap doc), so a
          # brand-new entry with no marker yet must surface immediately, on
          # its very first sighting. Re-surfacing a marked-and-fresh entry
          # risks the mayor dispatching a second reviewer for a PR already
          # being reviewed.
          marker_epoch=$(read_dispatch_marker "$f")
          if ! queue_entry_dispatch_suppressed "$marker_epoch" "$(date -u +%s)"; then
            surface_pending_review "$prnum" "$f"
          fi
        fi
        ;;
      non-pr)
        PENDING_NON_PR_REVIEWS+=("$payload")
        ;;
      warning)
        # An unrecognized (or missing) deliverable_type: never auto-drained,
        # so it must surface here -- not silently leave all four
        # newly-documented state fields empty while still forcing exit 20
        # via queue_files. See mayor-bootstrap.md's queue_warnings bullet.
        QUEUE_WARNINGS+=("$payload")
        ;;
    esac
    QUEUE_FILES_REMAINING+=("$f")
  done
}

# Step 1-2: PR gate + merge. Only worker/agent-* branches are considered --
# operator/* branches never get a queued review in the first place (the
# SubagentStop hook that feeds the queue never fires for the mayor's own
# top-level turn), so gating them here would just wedge them forever.
gate_and_merge_prs() {
  local prs_json n pr mss pending failed is_draft reviews_json latest body verdict
  prs_json=$(gh pr list --state open --json number,headRefName,mergeStateStatus,statusCheckRollup,isDraft 2>/dev/null || echo '[]')
  for n in $(printf '%s' "$prs_json" | jq -r '.[] | select(.headRefName | startswith("worker/agent-")) | .number' 2>/dev/null || true); do
    pr=$(printf '%s' "$prs_json" | jq -c --argjson n "$n" '.[] | select(.number==$n)')
    mss=$(printf '%s' "$pr" | jq -r '.mergeStateStatus')
    pending=$(printf '%s' "$pr" | jq '[.statusCheckRollup[]? | select(.status!=null and .status!="COMPLETED")] | length')
    failed=$(printf '%s' "$pr" | jq '[.statusCheckRollup[]? | select(.conclusion!=null and (.conclusion=="FAILURE" or .conclusion=="CANCELLED" or .conclusion=="TIMED_OUT" or .conclusion=="ACTION_REQUIRED"))] | length')
    is_draft=$(printf '%s' "$pr" | jq -r '.isDraft')
    pr_gate_eligible "$mss" "$pending" "$failed" "$is_draft" || continue

    reviews_json=$(gh pr view "$n" --json reviews --jq '.reviews' 2>/dev/null || echo '[]')
    latest=$(latest_reviewer_review "$reviews_json")
    if [ -z "$latest" ] || [ "$latest" = "null" ]; then
      GATE_EXCEPTIONS+=("$(jq -nc --argjson pr "$n" '{pr:$pr, reason:"no-qualifying-review"}')")
      continue
    fi
    body=$(printf '%s' "$latest" | jq -r '.body')
    verdict=$(parse_verdict "$body")
    case "$verdict" in
      LGTM|LGTM-with-suggestions)
        run_cmd gh pr merge "$n"
        ;;
      *)
        GATE_EXCEPTIONS+=("$(jq -nc --argjson pr "$n" --arg verdict "$verdict" '{pr:$pr, verdict:$verdict, reason:"verdict-not-lgtm"}')")
        ;;
    esac
  done
}

# Step 3: post-merge cleanup. Driven off the actually-existing worker
# worktrees (bounded, small) rather than a "since last tick" timestamp
# window -- self-healing across a missed tick and needs no continuity with
# the previous state file.
cleanup_merged_worktrees() {
  local path branch pr_state st num did_pull=0
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    [ "$path" = "$REPO_ROOT" ] && continue
    branch=$(git -C "$path" rev-parse --abbrev-ref HEAD 2>/dev/null || true)
    case "$branch" in
      worker/agent-*) ;;
      *) continue ;;
    esac
    pr_state=$(gh pr list --head "$branch" --state all --json number,state --jq '.[0] // empty' 2>/dev/null || true)
    [ -z "$pr_state" ] && continue
    st=$(printf '%s' "$pr_state" | jq -r '.state')
    num=$(printf '%s' "$pr_state" | jq -r '.number')
    if [ "$st" = "MERGED" ]; then
      if [ "$did_pull" -eq 0 ]; then
        # Explicit fetch+merge of ONLY main, not a bare `pull --ff-only`:
        # the wildcard fetch refspec populates FETCH_HEAD with every
        # updated branch during a multi-PR merge cascade, and a bare pull
        # then tries to fast-forward to all of FETCH_HEAD at once ("Cannot
        # fast-forward to multiple branches", exit 128).
        run_cmd git -C "$REPO_ROOT" fetch origin main
        run_cmd git -C "$REPO_ROOT" merge --ff-only origin/main
        run_cmd git -C "$REPO_ROOT" remote prune origin
        did_pull=1
      fi
      run_cmd git worktree remove "$path"
      run_cmd git branch -D "$branch"
      MERGED_PRS+=("$num")
    fi
  done < <(git -C "$REPO_ROOT" worktree list --porcelain | awk '/^worktree / {print $2}')
}

# Step 4: new dispatchable work. `bd ready` already excludes in_progress,
# blocked, deferred, and hooked issues (its own documented semantics), so
# no extra label-based "held" filter is needed on top of it -- decisions
# and epics are excluded here because they need mayor judgment on shape,
# not a worker dispatch.
check_bd_ready() {
  local out id
  out=$(bd ready --json --exclude-type decision,epic 2>/dev/null || echo '[]')
  while IFS= read -r id; do
    [ -n "$id" ] && BD_READY_IDS+=("$id")
  done < <(printf '%s' "$out" | jq -r '.[].id' 2>/dev/null || true)
}

# Step 5: worktree anomalies. Narrow on purpose -- host-process orphans,
# worktree-metadata pruning, and stale-branch deletion already belong to
# the (operator-kept, not scriptified here) 60m worktree-hygiene loop. This
# only flags a live worker worktree/branch with NO PR at all, which that
# loop's checks don't cover: it means a dispatch stalled before ever
# opening one -- UNLESS the branch's agent-id is in --live-agents
# (is_live_agent_branch), in which case it's reported here for visibility
# but excluded from WORKTREE_STALE_COUNT, so it never escalates the tick's
# exit code. If --live-agents was never passed, LIVE_AGENTS is empty and
# every no-PR branch reports as genuinely stale (no-pr-for-branch) --
# conservative-by-default, matching this script's existing
# fail-toward-surfacing bias elsewhere (e.g. is_valid_queued_at), rather
# than silently assuming an unknown worker is fine.
check_worktree_anomalies() {
  local path branch count
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    [ "$path" = "$REPO_ROOT" ] && continue
    branch=$(git -C "$path" rev-parse --abbrev-ref HEAD 2>/dev/null || true)
    case "$branch" in
      worker/agent-*) ;;
      *) continue ;;
    esac
    count=$(gh pr list --head "$branch" --state all --json number --jq 'length' 2>/dev/null || echo 0)
    if [ "${count:-0}" -eq 0 ]; then
      if is_live_agent_branch "$branch" "$LIVE_AGENTS"; then
        WORKTREE_ANOMALIES+=("$(jq -nc --arg path "$path" --arg branch "$branch" '{path:$path, branch:$branch, reason:"no-pr-for-branch-in-flight"}')")
      else
        WORKTREE_ANOMALIES+=("$(jq -nc --arg path "$path" --arg branch "$branch" '{path:$path, branch:$branch, reason:"no-pr-for-branch"}')")
        WORKTREE_STALE_COUNT=$(( WORKTREE_STALE_COUNT + 1 ))
      fi
    fi
  done < <(git -C "$REPO_ROOT" worktree list --porcelain | awk '/^worktree / {print $2}')
}

# Generic file write, isolated into its own tiny function like the
# dashboard replace/append helpers, purely so run_cmd's dry-run gate can
# cover a raw file write the same as every other side effect in this
# script. Shared by the reconcile stale-blocking-verdict write and the
# dispatch-marker stamp below.
_write_file_contents() {  # $1=path $2=contents
  printf '%s' "$2" > "$1"
}

# Atomic create-if-absent write (shell noclobber semantics): fails without
# touching the file if it already exists. Used for the reconcile
# stale-blocking-verdict write below so two overlapping mayor-tick.sh runs
# racing on the SAME PR (this script runs on a 15m cron AND can be invoked
# inline on a task notification, so overlap is real, not hypothetical)
# can't both write a duplicate queue file -- paired with a deterministic
# (not wall-clock) filename, both racing processes compute the SAME path
# and only the first writer wins.
_write_file_contents_if_absent() {  # $1=path $2=contents
  ( set -C; printf '%s' "$2" > "$1" ) 2>/dev/null
}

# Records that this tick surfaced `prnum` (backed by `queue_file`) into
# pending_reviews, by stamping a fresh dispatch marker -- so subsequent
# ticks treat it as already-dispatched (queue_entry_dispatch_suppressed)
# instead of re-surfacing it every tick. Shared by process_review_queue's
# per-file loop and reconcile's stale-blocking-verdict branch, which also
# creates a queue file that process_review_queue will examine on the VERY
# NEXT tick -- without stamping here too, that next tick would see no
# marker yet and surface the same PR again immediately, defeating the
# purpose of the marker.
surface_pending_review() {
  local prnum="$1" queue_file="$2" marker_file
  PENDING_REVIEW_PRS+=("$prnum")
  marker_file=$(dispatch_marker_path "$queue_file")
  run_cmd mkdir -p "$(dirname "$marker_file")"
  run_cmd _write_file_contents "$marker_file" "$(date -u +%s)"
}

# Step 6: self-heal reconciliation. Compensating layer for the
# SubagentStop hook missing a fire entirely (a push landing on a non-
# worker/agent-* head, upstream anthropics/claude-code#27755, or the hook
# exiting with an error) -- without this, an open worker PR with no queue
# entry AND no review sits invisible to the mayor until a manual audit
# catches it. Runs after process_review_queue so pr_already_queued sees
# this tick's queue state. Logged with the "mayor-tick reconcile:" prefix
# (distinct from process_review_queue's hook-fed path) so an audit can tell
# script-detected self-heal from hook-queued.
#
# Also covers a narrower gap: a PR that already has a review, but that
# review is a stale BLOCKING verdict (needs-changes/needs-discussion) and
# commits landed on the head branch after it was submitted -- fixed, but
# never re-reviewed, because the hook only fires from a worker's own
# SubagentStop and this fix can land any other way (a direct push, or a
# hook miss). A real queue file (not just an in-memory pending_reviews
# entry) is written for this case specifically: writing it means
# pr_already_queued's existing no-double-queue guard also covers THIS
# branch on every subsequent tick, so a re-review that comes back blocking
# again does not requeue every tick forever -- it only requeues once a
# genuinely NEW commit lands after that re-review's own submittedAt.
#
# That queue file's name is derived from the PR number + the review's own
# submittedAt, not wall-clock time: this script runs on a 15m cron AND can
# be invoked inline on a task notification, so two overlapping runs
# reconciling the SAME PR is real, not hypothetical. Both racing processes
# observe the identical latest review and so compute the identical name;
# the noclobber write below (_write_file_contents_if_absent) then lets only
# the first one through instead of both writing distinct duplicate files.
reconcile_missing_queue_entries() {
  local prs_json n url is_draft reviews_json latest verdict body submitted_at commits_json queued_at qfile
  prs_json=$(gh pr list --state open --json number,url,headRefName,isDraft --jq \
    '[.[] | select(.headRefName | startswith("worker/agent-"))]' 2>/dev/null || echo '[]')

  for n in $(printf '%s' "$prs_json" | jq -r '.[].number' 2>/dev/null || true); do
    url=$(printf '%s' "$prs_json" | jq -r --argjson n "$n" '.[] | select(.number==$n) | .url')
    is_draft=$(printf '%s' "$prs_json" | jq -r --argjson n "$n" '.[] | select(.number==$n) | .isDraft')
    # Same exclusion as pr_gate_eligible's isDraft check above: a
    # deliberately-held draft must not get nagged into pending_reviews
    # every tick just because it lacks a queue entry or review yet.
    [ "$is_draft" = "true" ] && continue

    pr_already_queued "$url" && continue

    reviews_json=$(gh pr view "$n" --json reviews --jq '.reviews' 2>/dev/null || echo '[]')
    latest=$(latest_reviewer_review "$reviews_json")
    if [ -z "$latest" ] || [ "$latest" = "null" ]; then
      echo "mayor-tick reconcile: PR #$n ($url) has no review-queue entry and no critical-reviewer review -- synthesizing pending_reviews entry" >&2
      PENDING_REVIEW_PRS+=("$n")
      continue
    fi

    body=$(printf '%s' "$latest" | jq -r '.body')
    verdict=$(parse_verdict "$body")
    verdict_is_blocking "$verdict" || continue  # LGTM/LGTM-with-suggestions -- nothing to self-heal

    submitted_at=$(printf '%s' "$latest" | jq -r '.submittedAt // empty')
    commits_json=$(gh pr view "$n" --json commits --jq '.commits' 2>/dev/null || echo '[]')
    has_commit_after "$commits_json" "$submitted_at" || continue  # blocking verdict but nothing changed since -- nothing for a reviewer to look at yet

    queued_at=$(date -u +%Y-%m-%dT%H-%M-%SZ)
    qfile="$QUEUE_DIR/mayor-tick-reconcile-pr${n}-$(printf '%s' "$submitted_at" | tr ':' '-').md"
    if run_cmd _write_file_contents_if_absent "$qfile" "$(printf -- '---\ndeliverable_type: pr\ndeliverable_ref: %s\nqueued_at: %s\n---\nmayor-tick reconcile: stale %s verdict (submitted %s) with commits landed after -- re-review needed\n' "$url" "$queued_at" "$verdict" "$submitted_at")"; then
      echo "mayor-tick reconcile: PR #$n ($url) has a stale $verdict verdict (submitted $submitted_at) with commits landed after -- queuing re-review" >&2
      surface_pending_review "$n" "$qfile"
    else
      echo "mayor-tick reconcile: PR #$n ($url) stale-verdict queue file already exists (concurrent mayor-tick run) -- not duplicating" >&2
    fi
  done
}

main() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --live-agents)
        LIVE_AGENTS="${2:-}"
        shift 2
        ;;
      *)
        shift
        ;;
    esac
  done

  process_review_queue
  reconcile_missing_queue_entries
  gate_and_merge_prs
  cleanup_merged_worktrees
  check_bd_ready
  check_worktree_anomalies
  refresh_dashboard

  local bd_ready_count=${#BD_READY_IDS[@]}
  # PENDING_REVIEW_PRS is included here (not just QUEUE_FILES_REMAINING)
  # because reconcile_missing_queue_entries can append to it for a PR with
  # NO backing queue file at all -- without counting it directly, a
  # self-healed entry would leave exit_code at 0 (noop) and the mayor would
  # never read pending_reviews to dispatch it, defeating self-heal outright.
  local exception_count=$(( ${#GATE_EXCEPTIONS[@]} + ${#QUEUE_FILES_REMAINING[@]} + ${#PENDING_REVIEW_PRS[@]} ))
  # Not ${#WORKTREE_ANOMALIES[@]}: that count includes in-flight dispatches
  # reported for visibility only (see check_worktree_anomalies) -- only the
  # stale subset should escalate the exit code.
  local worktree_count=$WORKTREE_STALE_COUNT
  local exit_code
  exit_code=$(compute_exit_code "$bd_ready_count" "$exception_count" "$worktree_count")

  # "${ARR[@]+"${ARR[@]}"}", not the bare "${ARR[@]}", at every call site
  # below: macOS ships bash 3.2 as /bin/bash (this script's own shebang
  # target), and 3.2's `set -u` treats a *zero-element* array's `[@]`
  # word-expansion as an unbound variable -- confirmed empirically, this
  # script errors out of main() entirely on a routine all-clear tick on any
  # unmodified macOS install. `${#ARR[@]}` (length, used above) is
  # unaffected; only the word-expansion form needs the guard.
  write_state "$exit_code" \
    "$(json_array "${QUEUE_FILES_REMAINING[@]+"${QUEUE_FILES_REMAINING[@]}"}")" \
    "$(json_number_array "${PENDING_REVIEW_PRS[@]+"${PENDING_REVIEW_PRS[@]}"}")" \
    "$(json_number_array "${MERGED_PRS[@]+"${MERGED_PRS[@]}"}")" \
    "$(json_array "${BD_READY_IDS[@]+"${BD_READY_IDS[@]}"}")" \
    "$(json_raw_array "${WORKTREE_ANOMALIES[@]+"${WORKTREE_ANOMALIES[@]}"}")" \
    "$(json_raw_array "${GATE_EXCEPTIONS[@]+"${GATE_EXCEPTIONS[@]}"}")" \
    "$(json_raw_array "${PENDING_NON_PR_REVIEWS[@]+"${PENDING_NON_PR_REVIEWS[@]}"}")" \
    "$(json_raw_array "${QUEUE_WARNINGS[@]+"${QUEUE_WARNINGS[@]}"}")"

  echo "mayor-tick: exit_code=$exit_code state=$STATE_FILE"
  exit "$exit_code"
}

if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  if [ "${1:-}" = "__call" ]; then
    shift
    "$@"
  else
    main "$@"
  fi
fi
