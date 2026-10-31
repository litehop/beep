#!/usr/bin/env bash
# Unit test for scripts/hook-reviewer-posted.sh. Runs the REAL hook with a
# stub `gh` shadowed on PATH and a fabricated agent transcript.
#
# Each case names what breaks for the mayor if it regresses: a reviewer that
# returns a verdict without posting costs a re-prompt and a delayed merge, and
# an unbounded or over-eager hook would hold unrelated subagents (or the
# reviewer, during a GitHub outage) open.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
HOOK="${HOOK:-$REPO/scripts/hook-reviewer-posted.sh}"

PASS=0
FAIL=0
assert() {
  if [ "$2" = "1" ]; then echo "PASS: $1"; PASS=$(( PASS + 1 )); else echo "FAIL: $1"; FAIL=$(( FAIL + 1 )); fi
}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"
cat > "$WORK/bin/gh" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "$GH_LOG"
if [ "${GH_FAIL:-0}" = "1" ]; then echo "HTTP 502" >&2; exit 1; fi
printf '%s' "$GH_JSON"
EOF
chmod +x "$WORK/bin/gh"
export GH_LOG="$WORK/gh.log" GH_JSON="" GH_FAIL=0
export PATH="$WORK/bin:$PATH"

MARK='## critical-reviewer findings — pr — beep-x'
json_with_review() {  # $1 = commit the review sits on
  jq -nc --arg c "$1" --arg m "$MARK" \
    '{headRefOid:"bbbb", reviews:[{body:"unrelated", commit:{oid:"bbbb"}}, {body:($m+"\n**Verdict**: LGTM"), commit:{oid:$c}}]}'
}
NO_REVIEW='{"headRefOid":"bbbb","reviews":[{"body":"human nit","commit":{"oid":"bbbb"}}]}'

transcript() {  # $1 = prompt text
  jq -nc --arg t "$1" '{type:"user", message:{role:"user", content:$t}}' > "$WORK/t.jsonl"
  echo '{"type":"assistant"}' >> "$WORK/t.jsonl"
}

run_hook() {  # $1=agent_type $2=stop_hook_active; sets OUT, ERR, RC
  local payload
  payload=$(jq -nc --arg a "$1" --argjson s "$2" --arg t "$WORK/t.jsonl" \
    '{agent_type:$a, stop_hook_active:$s, agent_transcript_path:$t, last_assistant_message:"verdict: LGTM"}')
  : > "$GH_LOG"
  RC=0
  OUT=$(printf '%s' "$payload" | bash "$HOOK" 2>"$WORK/err") || RC=$?
  ERR=$(cat "$WORK/err")
}
blocks() { [ "$RC" -eq 2 ] && [ -z "$OUT" ]; }

transcript "Review PR https://github.com/litehop/beep/pull/77 (bead beep-x)"

GH_JSON="$NO_REVIEW"; run_hook critical-reviewer false
assert "blocks via exit 2 (the only code that keeps a subagent from stopping) when no review is posted" "$(blocks && echo 1 || echo 0)"
assert "block reason on stderr names the posting script, --body-file and head so the reviewer knows the fix" "$(printf '%s' "$ERR" | grep -q 'scripts/gh-app-review.sh 77.*--body-file.*bbbb' && echo 1 || echo 0)"
assert "block reason does not tell the reviewer to use the Write tool, which it is disallowed from using" "$(printf '%s' "$ERR" | grep -q 'Write tool' && echo 0 || echo 1)"
assert "block reason teaches no operator-token fallback (gh api / stdin) that contradicts the reviewer's no-fallback rule" "$(printf '%s' "$ERR" | grep -qE 'gh api|--input' && echo 0 || echo 1)"
assert "queried the PR number from the dispatch prompt" "$(grep -q 'pr view 77' "$GH_LOG" && echo 1 || echo 0)"

GH_JSON=$(json_with_review bbbb); run_hook critical-reviewer false
assert "allows the stop once a review is posted on the current head" "$([ "$RC" -eq 0 ] && [ -z "$OUT" ] && echo 1 || echo 0)"

GH_JSON=$(json_with_review aaaa); run_hook critical-reviewer false
assert "blocks when the only review is on an older head (stale review is not a verdict on this code)" "$(blocks && echo 1 || echo 0)"

GH_JSON="$NO_REVIEW"; run_hook critical-reviewer true
assert "allows the stop when already blocked once, so the reviewer cannot loop forever" "$([ "$RC" -eq 0 ] && [ -z "$OUT" ] && echo 1 || echo 0)"
assert "stop_hook_active allow is loud on stderr when no review was verified" "$(printf '%s' "$ERR" | grep -q 'WITHOUT a verified' && echo 1 || echo 0)"
assert "stop_hook_active still queries gh once, so a posted review is detected" "$([ "$(wc -l < "$GH_LOG")" -eq 1 ] && echo 1 || echo 0)"

GH_JSON=$(json_with_review bbbb); run_hook critical-reviewer true
assert "stop_hook_active with a verified posted review allows silently (no false 'without review' warning)" "$([ "$RC" -eq 0 ] && [ -z "$ERR" ] && echo 1 || echo 0)"

GH_JSON=$(json_with_review bbbb | jq -c '.reviews[1].state="DISMISSED"'); run_hook critical-reviewer false
assert "a DISMISSED review does not count as posted (operator withdrew it; the gate ignores it too)" "$(blocks && echo 1 || echo 0)"

GH_FAIL=1 GH_JSON="" run_hook critical-reviewer false
assert "allows the stop when gh fails, so a GitHub outage cannot hold the reviewer open" "$([ "$RC" -eq 0 ] && [ -z "$OUT" ] && echo 1 || echo 0)"
assert "gh-failure allow is loud on stderr" "$(printf '%s' "$ERR" | grep -q 'WARNING' && echo 1 || echo 0)"

GH_JSON="$NO_REVIEW"; run_hook worker false
assert "passes non-reviewer subagents through without calling gh" "$([ "$RC" -eq 0 ] && [ -z "$OUT" ] && [ ! -s "$GH_LOG" ] && echo 1 || echo 0)"

transcript "Review findings doc /x/ai/findings/foo.md"
GH_JSON="$NO_REVIEW"; run_hook critical-reviewer false
assert "passes non-PR deliverables through (nothing to post on a PR)" "$([ "$RC" -eq 0 ] && [ -z "$OUT" ] && [ ! -s "$GH_LOG" ] && echo 1 || echo 0)"

transcript "Re-review PR #88 after fixes"
GH_JSON="$NO_REVIEW"; run_hook critical-reviewer false
assert "accepts the anchored 'Re-review PR #N' form" "$(blocks && grep -q 'pr view 88' "$GH_LOG" && echo 1 || echo 0)"

transcript "$(printf 'Context: regression of #231, see https://github.com/litehop/beep/pull/231\nReview PR https://github.com/litehop/beep/pull/99 now')"
GH_JSON="$NO_REVIEW"; run_hook critical-reviewer false
assert "decoy PR cited before the anchor is ignored: the anchored PR is checked (else enforcement lands on the wrong PR)" "$(blocks && grep -q 'pr view 99' "$GH_LOG" && ! grep -q 'pr view 231' "$GH_LOG" && echo 1 || echo 0)"

transcript "Fix follows https://github.com/litehop/beep/pull/231 and #232; please look at the findings"
GH_JSON="$NO_REVIEW"; run_hook critical-reviewer false
assert "decoy-only prompt passes through without calling gh (never guess a PR)" "$([ "$RC" -eq 0 ] && [ ! -s "$GH_LOG" ] && printf '%s' "$ERR" | grep -q 'not enforcing' && echo 1 || echo 0)"

transcript "$(printf 'deliverable_type: pr\ndeliverable_ref: https://github.com/litehop/beep/pull/55\n\n## Subagent final message\nsee https://github.com/litehop/beep/pull/231')"
GH_JSON="$NO_REVIEW"; run_hook critical-reviewer false
assert "queue-entry deliverable_ref is honoured over later citations" "$(blocks && grep -q 'pr view 55' "$GH_LOG" && echo 1 || echo 0)"

transcript "$(printf 'deliverable_type: findings\ndeliverable_ref: /x/ai/findings/foo.md\n\n## Subagent final message\nReview PR #123 was done earlier')"
GH_JSON="$NO_REVIEW"; run_hook critical-reviewer false
assert "non-PR deliverable_ref passes through; a 'Review PR' line in the embedded final message must not anchor enforcement on an unrelated PR" "$([ "$RC" -eq 0 ] && [ ! -s "$GH_LOG" ] && echo 1 || echo 0)"

transcript "Review https://github.com/litehop/beep/pull/101 (bead beep-x)"
GH_JSON="$NO_REVIEW"; run_hook critical-reviewer false
assert "accepts 'Review <pull URL>' without the word PR (dispatch phrasing varies; a miss silently disables enforcement)" "$(blocks && grep -q 'pr view 101' "$GH_LOG" && echo 1 || echo 0)"

transcript "Re-review https://github.com/litehop/beep/pull/102"
GH_JSON="$NO_REVIEW"; run_hook critical-reviewer false
assert "accepts 'Re-review <pull URL>' without the word PR" "$(blocks && grep -q 'pr view 102' "$GH_LOG" && echo 1 || echo 0)"

transcript "Review #231 conventions in the dispatch docs"
GH_JSON="$NO_REVIEW"; run_hook critical-reviewer false
assert "'Review #N' without PR is not an anchor (prose citing an issue must not trigger enforcement)" "$([ "$RC" -eq 0 ] && [ ! -s "$GH_LOG" ] && echo 1 || echo 0)"

transcript "Review PR https://github.com/litehop/beep/pull/66"
GH_JSON="$NO_REVIEW"
PAYLOAD=$(jq -nc --arg t "$WORK/t.jsonl" '{session_id:"s1", transcript_path:"/x/main.jsonl", cwd:"/x", permission_mode:"default", hook_event_name:"SubagentStop", stop_hook_active:false, agent_id:"agent-1", agent_type:"critical-reviewer", agent_transcript_path:$t, last_assistant_message:"LGTM", stop_reason:"end_turn"}')
: > "$GH_LOG"; RC=0
printf '%s' "$PAYLOAD" | bash "$HOOK" >/dev/null 2>&1 || RC=$?
assert "a payload shaped exactly like the documented SubagentStop JSON is enforced (field-name regression guard)" "$([ "$RC" -eq 2 ] && grep -q 'pr view 66' "$GH_LOG" && echo 1 || echo 0)"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
