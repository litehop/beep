#!/usr/bin/env bash
# SubagentStop hook: blocks a critical-reviewer from stopping on a PR
# deliverable until its review is posted on the PR's current head.
#
# Blocking: per https://code.claude.com/docs/en/hooks.md (SubagentStop), exit
# code 2 prevents the subagent from stopping and stderr is fed back to it.
# Every allow path exits 0. Payload fields read: `agent_type`,
# `agent_transcript_path`, `stop_hook_active`. `last_assistant_message` is
# unusable: that is the very message being judged.
#
# PR number: the first line of the subagent's own transcript (JSONL) is the
# prompt it was dispatched with. Only an anchored deliverable counts: a prompt
# line starting `Review PR ` / `Re-review PR ` followed by a pull URL or `#N`,
# or a queue-entry line `deliverable_ref: <pull URL>`. Citations elsewhere
# (decoys) are ignored. No anchored PR = pass through, never guess.
#
# "Posted" = a non-DISMISSED review whose body starts with the `## critical-
# reviewer findings` marker (the merge gate's own key) on commit == headRefOid.
# Marker rather than author login so the operator-token COMMENT fallback also
# counts; a review on an older head does not.
#
# Bounded: `stop_hook_active` true (already blocked once) or any `gh`/parse
# failure allows the stop, with a loud stderr warning unless a posted review
# was verified.
set -uo pipefail

INPUT=$(cat)
field() { printf '%s' "$INPUT" | jq -r "$1" 2>/dev/null; }

[ "$(field '.agent_type // ""')" = "critical-reviewer" ] || exit 0

TRANSCRIPT=$(field '.agent_transcript_path // ""')
if [ ! -r "$TRANSCRIPT" ]; then
  echo "hook-reviewer-posted: WARNING: no readable agent_transcript_path; cannot find PR, allowing stop" >&2
  exit 0
fi
PROMPT=$(head -n 1 "$TRANSCRIPT" | jq -r '.message.content | if type == "string" then . else map(.text? // "") | join("\n") end' 2>/dev/null || true)
ANCHOR='^(Re-review|Review) PR (https://github\.com/litehop/beep/pull/|#)?[0-9]+|^deliverable_ref: https://github\.com/litehop/beep/pull/[0-9]+'
PR=$(printf '%s\n' "$PROMPT" | grep -m1 -oE "$ANCHOR" | grep -oE '[0-9]+$' || true)
if [ -z "$PR" ]; then
  echo "hook-reviewer-posted: no anchored 'Review PR <N>' / deliverable_ref in the dispatch prompt; not enforcing" >&2
  exit 0
fi

warn() {
  echo "hook-reviewer-posted: WARNING: allowing critical-reviewer stop on PR #$PR WITHOUT a verified posted review: $1" >&2
  exit 0
}

if ! VIEW=$(gh pr view "$PR" --json headRefOid,reviews 2>&1); then
  warn "gh pr view failed: $VIEW"
fi
POSTED=$(printf '%s' "$VIEW" | jq -r '
  .headRefOid as $head
  | [.reviews[]? | select((.body // "") | startswith("## critical-reviewer findings"))
      | select(.state != "DISMISSED")
      | select(.commit.oid == $head)] | length' 2>&1) || warn "unparseable gh output: $POSTED"

[ "$POSTED" -gt 0 ] 2>/dev/null && exit 0

[ "$(field '.stop_hook_active // false')" = "true" ] && warn "already blocked once (stop_hook_active)"

HEAD_OID=$(printf '%s' "$VIEW" | jq -r '.headRefOid')
echo "No critical-reviewer review is posted on the current head of PR #$PR. Post via \`scripts/gh-app-review.sh $PR\` with the payload's commit_id pinned to $HEAD_OID (on non-zero exit, retry once as COMMENT via \`gh api repos/litehop/beep/pulls/$PR/reviews -X POST --input -\`). Your final message must begin with the review URL, or the exact errors from both attempts." >&2
exit 2
