#!/usr/bin/env bash
# Test harness for scripts/guard-mayor-checkout.sh.
# Builds a throwaway "mayor" repo with a linked worktree under ai/worktrees/
# and feeds the hook synthetic PreToolUse Bash inputs.
#
# Invoke: bash scripts/test-guard-mayor-checkout-logic.sh [hook-path]
set -euo pipefail

HOOK="${1:-$(git rev-parse --show-toplevel)/scripts/guard-mayor-checkout.sh}"
FAILURES=0

SANDBOX=$(mktemp -d)
trap 'rm -rf "$SANDBOX"' EXIT
MAYOR=$(cd "$SANDBOX" && mkdir mayor && cd mayor && pwd -P)
git -C "$MAYOR" init -q -b main
git -C "$MAYOR" -c user.name=t -c user.email=t@t commit -q --allow-empty -m init
mkdir -p "$MAYOR/ai/worktrees"
WT="$MAYOR/ai/worktrees/w1"
git -C "$MAYOR" worktree add -q "$WT" -b w1

# run_hook <agent_id|""> <cwd> <command> -> sets RC
run_hook() {
  local input
  input=$(jq -n --arg id "$1" --arg cwd "$2" --arg cmd "$3" \
    '{cwd:$cwd, tool_input:{command:$cmd}} + (if $id == "" then {} else {agent_id:$id, agent_type:"critical-reviewer"} end)')
  RC=0
  ERR=$(bash "$HOOK" <<< "$input" 2>&1 >/dev/null) || RC=$?
}

expect() { # $1 label, $2 expected rc (0 allow / 2 block)
  if [ "$RC" -eq "$2" ]; then
    printf 'ok: %s\n' "$1"
  else
    printf 'FAIL: %s (rc=%s, expected %s)\n' "$1" "$RC" "$2" >&2
    FAILURES=$((FAILURES + 1))
  fi
}

run_hook agent-1 "$MAYOR" "git checkout FETCH_HEAD"
expect "subagent checkout in mayor checkout is blocked (the incident: detached mayor HEAD)" 2
case "$ERR" in
  *"gh pr diff"*"worktree add"*) printf 'ok: block message names the safe alternatives\n' ;;
  *) printf 'FAIL: block message lacks gh pr diff / worktree add guidance: %s\n' "$ERR" >&2; FAILURES=$((FAILURES + 1)) ;;
esac

run_hook agent-1 "$WT" "git -C $MAYOR reset --hard origin/main"
expect "git -C <mayor> reset from elsewhere is blocked" 2

run_hook agent-1 "$MAYOR" "git fetch origin main && git switch main"
expect "switch chained after a harmless fetch is still blocked" 2

run_hook agent-1 "$WT" "cd $MAYOR && git pull --ff-only"
expect "cd <mayor> && git pull is blocked" 2

run_hook agent-1 "$MAYOR" "bash -c 'git checkout main'"
expect "bash -c wrapper does not bypass the guard" 2

run_hook agent-1 "$MAYOR" "GIT_TERMINAL_PROMPT=0 git -c advice.detachedHead=false checkout x"
expect "env prefix and -c option do not bypass the guard" 2

run_hook agent-1 "$WT" "git checkout -b scratch"
expect "same command inside an ai/worktrees/ worktree is allowed (workers need it)" 0

run_hook agent-1 "$MAYOR" "git -C $WT checkout -b scratch2"
expect "git -C <linked worktree> from the mayor cwd is allowed" 0

run_hook agent-1 "$MAYOR" "git worktree add $SANDBOX/scratch main"
expect "creating a scratch worktree from the mayor checkout is allowed" 0

for ro in "git status" "git log --oneline -3" "git diff HEAD~0" "git fetch origin" "git rev-parse HEAD" "git branch --show-current"; do
  run_hook agent-1 "$MAYOR" "$ro"
  expect "read-only '$ro' in mayor checkout is allowed" 0
done

run_hook agent-1 "$MAYOR" "gh pr comment 1 --body 'run git checkout main'"
expect "git checkout mentioned inside a comment body is not a git invocation" 0

run_hook agent-1 "$MAYOR" "gh pr comment 1 --body \"ok; git checkout x && git reset --hard | done\""
expect "separators inside quotes do not split (reviewers' comments must not be blocked)" 0

run_hook agent-1 "$MAYOR" "gh pr comment 1 --body \"say \\\"hi; there\\\"\" ; git checkout x"
expect "a real command after a quoted argument is still checked (quote tracking must not swallow the rest)" 2

run_hook agent-1 "$MAYOR" "echo \"\$(git checkout x)\""
expect "command substitution inside double quotes still runs git and is blocked" 2

run_hook agent-1 "$MAYOR" "echo \"\`git reset --hard\`\""
expect "backtick substitution inside double quotes is blocked" 2

for ro in "git stash list" "git stash show -p" "git restore --staged f" "git restore -S f"; do
  run_hook agent-1 "$MAYOR" "$ro"
  expect "read-only '$ro' in mayor checkout is allowed (does not touch HEAD or worktree)" 0
done

for rw in "git stash" "git stash pop" "git stash push" "git restore f" "git restore --staged --worktree f" "git restore -SW f"; do
  run_hook agent-1 "$MAYOR" "$rw"
  expect "'$rw' in mayor checkout is still blocked (rewrites the mayor's working tree)" 2
done

run_hook agent-1 "$WT" "cd - && git reset --hard"
expect "cd - leaves an unknown dir, so a following reset fails closed (could land in the mayor checkout)" 2

run_hook agent-1 "$WT" "cd \$MAYOR_DIR && git checkout main"
expect "cd to an unexpanded variable fails closed" 2

run_hook agent-1 "$WT" "cd - && git status"
expect "read-only git after cd - is still allowed" 0

HOME="$MAYOR" run_hook agent-1 "$WT" "cd && git reset --hard"
expect "bare cd goes to HOME (the mayor checkout here) and is blocked" 2

run_hook "" "$MAYOR" "git checkout main"
expect "mayor session (no agent_id) can still move its own HEAD" 0

if [ "$FAILURES" -eq 0 ]; then
  printf '\nall tests passed\n'
else
  printf '\n%d test(s) failed\n' "$FAILURES" >&2
  exit 1
fi
