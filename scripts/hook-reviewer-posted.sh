#!/usr/bin/env bash
# SubagentStop hook: blocks a critical-reviewer from stopping on a PR
# deliverable until its review is posted on the PR's current head.
#
# PR number source: the first line of the subagent's own transcript
# (payload `agent_transcript_path`, JSONL) is the prompt the reviewer was
# dispatched with; the first `litehop/beep/pull/<N>` URL in it (else the
# first `PR #<N>`) is the PR. `last_assistant_message` is unusable: that is
# the very message being judged. No PR in the prompt = non-PR deliverable =
# pass through.
#
# "Posted" = a review whose body starts with the `## critical-reviewer
# findings` marker (the merge gate's own key) on commit == headRefOid. Marker
# rather than author login so the documented operator-token COMMENT fallback
# also counts; a review on an older head does not.
#
# Bounded: `stop_hook_active` true (already blocked once) or any `gh`/parse
# failure allows the stop with a loud stderr warning.
set -uo pipefail

INPUT=$(cat)
field() { printf '%s' "$INPUT" | jq -r "$1" 2>/dev/null; }

[ "$(field '.agent_type // ""')" = "critical-reviewer" ] || exit 0

TRANSCRIPT=$(field '.agent_transcript_path // ""')
if [ ! -r "$TRANSCRIPT" ]; then
  echo "hook-reviewer-posted: WARNING: no readable agent_transcript_path; cannot find PR, allowing stop" >&2
  exit 0
fi
PROMPT=$(head -n 1 "$TRANSCRIPT")
PR=$(printf '%s' "$PROMPT" | grep -oE 'litehop/beep/pull/[0-9]+' | head -1 | grep -oE '[0-9]+$' || true)
[ -n "$PR" ] || PR=$(printf '%s' "$PROMPT" | grep -oE 'PR #[0-9]+' | head -1 | grep -oE '[0-9]+$' || true)
[ -n "$PR" ] || exit 0

warn() {
  echo "hook-reviewer-posted: WARNING: allowing critical-reviewer stop on PR #$PR WITHOUT a verified posted review: $1" >&2
  exit 0
}

[ "$(field '.stop_hook_active // false')" = "true" ] && warn "already blocked once (stop_hook_active)"

if ! VIEW=$(gh pr view "$PR" --json headRefOid,reviews 2>&1); then
  warn "gh pr view failed: $VIEW"
fi
POSTED=$(printf '%s' "$VIEW" | jq -r '
  .headRefOid as $head
  | [.reviews[]? | select((.body // "") | startswith("## critical-reviewer findings"))
      | select(.commit.oid == $head)] | length' 2>&1) || warn "unparseable gh output: $POSTED"

[ "$POSTED" -gt 0 ] 2>/dev/null && exit 0

jq -n --arg pr "$PR" '{decision: "block", reason:
  ("No critical-reviewer review is posted on the current head of PR #" + $pr + ". Build the payload and pipe it into `scripts/gh-app-review.sh " + $pr + "` (on non-zero exit, retry once as COMMENT via `gh api repos/litehop/beep/pulls/" + $pr + "/reviews -X POST --input -`). Your final message must begin with the review URL, or the exact errors from both attempts.")}'
exit 0
