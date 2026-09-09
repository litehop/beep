#!/usr/bin/env bash
# SubagentStop hook: detects reviewable deliverables in a subagent's final
# message and queues a review request under .claude/review-queue/.
#
# Design shape (2026-08-18): dumb-but-certain queueing, NOT auto-dispatch.
#   - The hook DEFINITELY fires (writes file) once a deliverable is seen.
#   - Mayor picks up the queue file on next turn and invokes
#     `.claude/agents/critical-reviewer.md` to actually review.
#   - Chose queueing over inline `claude -p` because upstream
#     anthropics/claude-code#27755 reports SubagentStop hooks configured via
#     settings.json are unreliable, and blocking the parent loop for a full
#     reviewer run (up to 600s hook timeout) would stall session throughput.
#
# Never spawn a reviewer synchronously from here. Never edit files outside
# .claude/review-queue/.
#
# Retention policy (2026-08-27): decisions.tsv rotates via simple counter
# rotation (.tsv -> .1 -> .2, oldest generation discarded)
# once it reaches ~1 MiB, so a long-running mayor session cannot grow it
# unbounded. Both "queued" and "skip" entries rotate together -- skips are
# already the majority of lines and untangling the two isn't worth the
# complexity. Queued (auditable) entries survive at least two rotations
# before being dropped, since nothing is discarded until it ages past the
# .2 generation.
#
# Empty-agent_type filter (2026-08-27): a SubagentStop payload with an
# empty (not missing) agent_type is a spurious harness event per upstream
# anthropics/claude-code#27755 (closed not-planned) -- confirmed by a
# 2026-08-27 investigation into a ~32-33s empty-agent_type firing cadence
# with no backing transcript, invisible in the mayor's own turn loop. Every
# genuine deliverable-bearing payload populates agent_type, so this case
# never carries a reviewable message; exit before mkdir/log/anything else.
#
# Branch-lookup PR fallback (2026-08-27): a worker resumed via SendMessage
# after a needs-changes fix typically reports "New commit <sha> on PR #<N>"
# instead of the full PR URL the primary regex below matches, so the hook
# used to skip these with no-deliverable and the mayor had to notice the
# gap manually. If nothing else matches for a worker payload, ask GitHub
# for an open PR on that worker's own branch before giving up.

set -euo pipefail

INPUT=$(cat)

# Hook I/O contract (per code.claude.com/docs/en/hooks.md, verified 2026-08-18):
#   stdin JSON has: session_id, transcript_path, cwd, hook_event_name,
#   agent_id, agent_type, last_assistant_message.
AGENT_ID=$(printf '%s' "$INPUT" | jq -r '.agent_id // "unknown"')
AGENT_TYPE=$(printf '%s' "$INPUT" | jq -r '.agent_type // "unknown"')
CWD=$(printf '%s' "$INPUT" | jq -r '.cwd // empty')
MSG=$(printf '%s' "$INPUT" | jq -r '.last_assistant_message // empty')
SESSION_ID=$(printf '%s' "$INPUT" | jq -r '.session_id // "unknown"')

# See "Empty-agent_type filter" above. This is a literal empty string, not
# the "unknown" fallback above (which only fires for a missing/null field).
[ -z "$AGENT_TYPE" ] && exit 0

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(pwd)}"
QUEUE_DIR="$PROJECT_DIR/.claude/review-queue"
LOG_DIR="$QUEUE_DIR/log"

mkdir -p "$LOG_DIR"

DECISIONS_LOG="$LOG_DIR/decisions.tsv"
DECISIONS_LOG_MAX_BYTES=$((1024 * 1024)) # 1 MiB; see retention policy above.

# Counter rotation: decisions.tsv -> .1 -> .2, oldest (.2) discarded. Runs
# before every append so the live file never grows past
# DECISIONS_LOG_MAX_BYTES.
rotate_decisions_log() {
  [ -f "$DECISIONS_LOG" ] || return 0
  local size
  size=$(wc -c < "$DECISIONS_LOG" | tr -d ' ')
  [ "${size:-0}" -ge "$DECISIONS_LOG_MAX_BYTES" ] || return 0
  rm -f "$DECISIONS_LOG.2"
  [ -f "$DECISIONS_LOG.1" ] && mv "$DECISIONS_LOG.1" "$DECISIONS_LOG.2"
  mv "$DECISIONS_LOG" "$DECISIONS_LOG.1"
}

DECISIONS_LOG_LOCK_DIR="$DECISIONS_LOG.lock.d"
DECISIONS_LOG_LOCK_PID_FILE="$DECISIONS_LOG_LOCK_DIR/pid"
# Tunable so ops can adjust without patching the guts. 5s is generous for a
# critical section that's a handful of syscalls.
STALE_LOCK_TIMEOUT_SEC="${STALE_LOCK_TIMEOUT_SEC:-5}"

# `mkdir` is atomic on every POSIX filesystem, so it doubles as a lock
# primitive without an extra binary -- unlike `flock`, which ships on Linux
# but not on a stock macOS install (this hook runs on both). Bounded retry:
# a holder that crashed mid-critical-section (the critical section is a
# handful of syscalls, so this should never legitimately take
# STALE_LOCK_TIMEOUT_SEC) has its lock stolen rather than wedging every
# future hook fire forever.
#
# Liveness check (PR #1416 follow-on): a genuinely slow hook fire that's
# still alive past the timeout must NOT get evicted -- that would
# reintroduce the exact unlocked-race the lock exists to prevent. The
# holder's PID is written into the lockdir at acquire time; a steal only
# proceeds if `kill -0` confirms that PID is no longer running. A missing
# PID file (holder crashed between mkdir and the PID write, a window of a
# few bash builtins) is treated as no-liveness-info -- steal, matching the
# original crashed-holder rationale above.
acquire_decisions_lock() {
  local attempts=0 max_attempts=$((STALE_LOCK_TIMEOUT_SEC * 10)) holder_pid
  until mkdir "$DECISIONS_LOG_LOCK_DIR" 2>/dev/null; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge "$max_attempts" ]; then
      holder_pid=$(cat "$DECISIONS_LOG_LOCK_PID_FILE" 2>/dev/null || true)
      if [ -n "$holder_pid" ] && kill -0 "$holder_pid" 2>/dev/null; then
        : # holder still alive past the timeout -- do not steal, keep waiting
      else
        rm -rf "$DECISIONS_LOG_LOCK_DIR" 2>/dev/null || true
      fi
      attempts=0
    fi
    sleep 0.1
  done
  printf '%s' "$$" > "$DECISIONS_LOG_LOCK_PID_FILE"
}

release_decisions_lock() {
  rm -f "$DECISIONS_LOG_LOCK_PID_FILE"
  rmdir "$DECISIONS_LOG_LOCK_DIR" 2>/dev/null || true
}

# Concurrent subagents can hit SubagentStop within the same second (multiple
# workers finishing in one session against the same CLAUDE_PROJECT_DIR).
# Without serializing read-size -> rotate -> append as one critical section,
# overlapping invocations race the file renames: one process's in-flight
# `mv decisions.tsv decisions.tsv.1` can be clobbered by another's, silently
# discarding an entry the retention policy above promises survives two
# rotations (confirmed by critical-reviewer with 5 overlapping invocations
# against a >1 MiB file).
log_decision() {
  local line="$1"
  acquire_decisions_lock
  rotate_decisions_log
  printf '%s\n' "$line" >> "$DECISIONS_LOG"
  release_decisions_lock
}

TS=$(date -u +"%Y-%m-%dT%H-%M-%SZ")

# Detect reviewable deliverables. Empty MSG → nothing to review.
[ -z "$MSG" ] && exit 0

# A dispatched critical-reviewer's own completion report necessarily mentions
# the PR/deliverable it just reviewed (e.g. "I posted findings on PR #<N>:
# <url>"). Without this check that echo is indistinguishable from a worker
# having just opened a fresh PR, so the hook would re-queue a review of the
# review that was JUST completed -- and draining that queue entry would
# produce another critical-reviewer completion mentioning the same URL,
# re-queuing again unboundedly. Skip before running deliverable detection at
# all; there is nothing to discard, so no reason to regex the message first.
if [ "$AGENT_TYPE" = "critical-reviewer" ]; then
  log_decision "$(printf '%s\t%s\tskip\tself-review-echo\tagent_type=%s' \
    "$TS" "$AGENT_ID" "$AGENT_TYPE")"
  exit 0
fi

DELIVERABLE_TYPE=""
DELIVERABLE_REF=""
DECISION_LABEL="queued"

# 1. PR opened. Repo slug is github.com/litehop/beep
PR_URL=$(printf '%s' "$MSG" | grep -oE 'https?://github\.com/litehop/beep/pull/[0-9]+' | head -1 || true)
if [ -n "$PR_URL" ]; then
  DELIVERABLE_TYPE="pr"
  DELIVERABLE_REF="$PR_URL"
  DECISION_LABEL="queued-via-url"
fi

# 2. Findings doc. Look for absolute paths to ai/findings/*.md that the worker
#    wrote inside its worktree.
if [ -z "$DELIVERABLE_TYPE" ]; then
  FINDINGS_PATH=$(printf '%s' "$MSG" | grep -oE '/[^ )"'"'"']+/ai/findings/[^ )"'"'"']+\.md' | head -1 || true)
  if [ -n "$FINDINGS_PATH" ] && [ -f "$FINDINGS_PATH" ]; then
    DELIVERABLE_TYPE="findings"
    DELIVERABLE_REF="$FINDINGS_PATH"
  fi
fi

# 3. Bead close. The worker reports `bd close mayor-XXXXX -r "..."` in output.
if [ -z "$DELIVERABLE_TYPE" ]; then
  BEAD_ID=$(printf '%s' "$MSG" | grep -oE 'bd close (mayor-[a-z0-9]+)' | head -1 | awk '{print $3}' || true)
  if [ -n "$BEAD_ID" ]; then
    DELIVERABLE_TYPE="bead-close"
    DELIVERABLE_REF="$BEAD_ID"
  fi
fi

# 4. Bead supersede. Both `bd supersede` and `bd relate --type supersedes`
#    are seen historically — accept either.
if [ -z "$DELIVERABLE_TYPE" ]; then
  SUPERSEDE=$(printf '%s' "$MSG" | grep -oE '(bd supersede|bd relate --type supersedes)[^\n]*mayor-[a-z0-9]+' | head -1 || true)
  if [ -n "$SUPERSEDE" ]; then
    DELIVERABLE_TYPE="bead-supersede"
    DELIVERABLE_REF="$SUPERSEDE"
  fi
fi

# 5. Resumed worker fallback. See "Branch-lookup PR fallback" in the header.
if [ -z "$DELIVERABLE_TYPE" ] && [ "$AGENT_TYPE" = "worker" ] && [ "$AGENT_ID" != "unknown" ]; then
  # `&& GH_RC=0 || GH_RC=$?`, not two statements: under `set -e`, a failing
  # command substitution trips the shell on the assignment line itself,
  # before a separate `GH_RC=$?` line would ever run -- exiting the whole
  # hook non-zero on a `gh` failure instead of reaching the handling below.
  GH_OUT=$(gh pr list --head "worker/agent-$AGENT_ID" --json url --limit 1 --jq '.[0].url // ""' 2>&1) && GH_RC=0 || GH_RC=$?
  if [ "$GH_RC" -ne 0 ]; then
    # An auth/network failure looks identical to "genuinely no PR yet"
    # unless logged separately -- exactly the silent-failure mode this
    # fallback exists to avoid. tr collapses any embedded tab/newline from
    # gh's error text so it can't split into extra TSV rows/columns.
    GH_ERR_ONELINE=$(printf '%s' "$GH_OUT" | tr '\t\n' '  ')
    log_decision "$(printf '%s\t%s\tskip\tbranch-lookup-failed\tagent_type=%s;rc=%s;err=%s' \
      "$TS" "$AGENT_ID" "$AGENT_TYPE" "$GH_RC" "$GH_ERR_ONELINE")"
    exit 0
  elif [ -n "$GH_OUT" ]; then
    DELIVERABLE_TYPE="pr"
    DELIVERABLE_REF="$GH_OUT"
    DECISION_LABEL="queued-via-branch-lookup"
  fi
fi

# No reviewable deliverable → skip. Log the reason so a future audit can tell
# "hook fired but had nothing to do" from "hook never fired" (upstream #27755).
if [ -z "$DELIVERABLE_TYPE" ]; then
  log_decision "$(printf '%s\t%s\tskip\tno-deliverable\tagent_type=%s' \
    "$TS" "$AGENT_ID" "$AGENT_TYPE")"
  exit 0
fi

# Retention policy (2026-08-21): only "queued" decisions get a raw JSONL
# payload logged. Skips (the vast majority of SubagentStop events — every
# non-deliverable-producing subagent stop) are already cheaply covered by
# the one-liner above; giving every one of them a full-payload file too is
# what grew log/ past 4000 files with no bound. The raw payload is still
# useful for queued events specifically, to debug the wire format if a
# future Claude Code release changes the JSON schema (upstream #27755).
printf '%s\n' "$INPUT" > "$LOG_DIR/$TS-$AGENT_ID.jsonl"

# Write the review-request queue file. Mayor sees it on next turn.
QUEUE_FILE="$QUEUE_DIR/$TS-$AGENT_ID.md"

{
  printf -- '---\n'
  printf 'deliverable_type: %s\n' "$DELIVERABLE_TYPE"
  printf 'deliverable_ref: %s\n' "$DELIVERABLE_REF"
  printf 'agent_id: %s\n' "$AGENT_ID"
  printf 'agent_type: %s\n' "$AGENT_TYPE"
  printf 'session_id: %s\n' "$SESSION_ID"
  printf 'queued_at: %s\n' "$TS"
  printf -- '---\n\n'
  printf '# Review request\n\n'
  printf 'Invoke `.claude/agents/critical-reviewer.md` with this deliverable.\n\n'
  printf '## Subagent final message\n\n'
  printf '```\n%s\n```\n' "$MSG"
} > "$QUEUE_FILE"

log_decision "$(printf '%s\t%s\t%s\t%s\t%s' \
  "$TS" "$AGENT_ID" "$DECISION_LABEL" "$DELIVERABLE_TYPE" "$DELIVERABLE_REF")"

exit 0
