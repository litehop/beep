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
blocks() { [ "$RC" -eq 0 ] && [ "$(printf '%s' "$OUT" | jq -r '.decision' 2>/dev/null)" = "block" ]; }

transcript "Review PR https://github.com/litehop/beep/pull/77 (bead beep-x)"

GH_JSON="$NO_REVIEW"; run_hook critical-reviewer false
assert "blocks a reviewer stop when no review is posted (the skipped-posting bug)" "$(blocks && echo 1 || echo 0)"
assert "block reason names the posting script so the reviewer knows the fix" "$(printf '%s' "$OUT" | grep -q 'scripts/gh-app-review.sh 77' && echo 1 || echo 0)"
assert "queried the PR number from the dispatch prompt" "$(grep -q 'pr view 77' "$GH_LOG" && echo 1 || echo 0)"

GH_JSON=$(json_with_review bbbb); run_hook critical-reviewer false
assert "allows the stop once a review is posted on the current head" "$([ "$RC" -eq 0 ] && [ -z "$OUT" ] && echo 1 || echo 0)"

GH_JSON=$(json_with_review aaaa); run_hook critical-reviewer false
assert "blocks when the only review is on an older head (stale review is not a verdict on this code)" "$(blocks && echo 1 || echo 0)"

GH_JSON="$NO_REVIEW"; run_hook critical-reviewer true
assert "allows the stop when already blocked once, so the reviewer cannot loop forever" "$([ "$RC" -eq 0 ] && [ -z "$OUT" ] && echo 1 || echo 0)"
assert "stop_hook_active allow is loud on stderr" "$(printf '%s' "$ERR" | grep -q 'WARNING' && echo 1 || echo 0)"

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
assert "falls back to 'PR #N' when the prompt carries no URL" "$(blocks && grep -q 'pr view 88' "$GH_LOG" && echo 1 || echo 0)"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
