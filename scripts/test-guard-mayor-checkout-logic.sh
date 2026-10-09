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

run_hook agent-1 "$MAYOR" "echo \$'\\'' ; git checkout x ; echo \$'\\''"
expect "ANSI-C \$'..' quoting cannot desync the splitter into hiding a real checkout" 2

run_hook agent-1 "$MAYOR" "echo \"a ; git checkout x"
expect "unbalanced quote falls back to unconditional split (fail closed)" 2

run_hook agent-1 "$MAYOR" "git restore --staged --work f"
expect "git accepts unambiguous long-option prefixes, so --work must not pass as read-only restore" 2

run_hook agent-1 "$MAYOR" "git restore --staged --source=HEAD f"
expect "restore allowlist: any flag besides --staged/-S is blocked" 2

run_hook agent-1 "$MAYOR" "git restore --staged -- f"
expect "restore --staged with -- separator stays read-only" 0

run_hook agent-1 "$MAYOR" "git stash list --output=f"
expect "stash allowlist: --output writes files, so unlisted flags are blocked" 2

run_hook agent-1 "$WT" "cd \"\$(echo $MAYOR)\" && git checkout x"
expect "cd to a command-substituted dir is unknown, so a following checkout fails closed" 2

run_hook agent-1 "$WT" "cd \`echo $MAYOR\` && git checkout x"
expect "cd to a backtick-substituted dir is unknown, so a following checkout fails closed" 2

run_hook agent-1 "$MAYOR" "git ls-files | xargs git checkout --"
expect "xargs-wrapped git checkout is blocked (rewrites the mayor's tree)" 2

run_hook agent-1 "$MAYOR" "git ls-files | xargs -I{} git status {}"
expect "xargs-wrapped read-only git stays allowed" 0

run_hook agent-1 "$MAYOR" "ls | xargs echo"
expect "xargs without git stays allowed" 0

run_hook agent-1 "$WT" "pushd $MAYOR && git checkout x"
expect "pushd <mayor> then checkout is blocked like cd" 2

run_hook agent-1 "$WT" "pushd $MAYOR && git status"
expect "read-only git after pushd <mayor> stays allowed" 0

run_hook agent-1 "$WT" "popd && git checkout x"
expect "popd leaves an unknown dir, so a following checkout fails closed" 2

run_hook agent-1 "$WT" "pushd && git checkout x"
expect "pushd with no operand swaps to an unknown dir, so checkout fails closed" 2

for cdform in "cd -P" "cd -L" "cd --" "cd -P --" "builtin cd" "command cd"; do
  run_hook agent-1 "$WT" "$cdform $MAYOR && git checkout x"
  expect "'$cdform <mayor>' then checkout is blocked (cd flags must not hide the target)" 2
done

run_hook agent-1 "$MAYOR" "cd -P $WT && git checkout -b y"
expect "cd -P into a linked worktree keeps the checkout allowed" 0

run_hook agent-1 "$WT" "GIT_DIR=$MAYOR/.git GIT_WORK_TREE=$MAYOR git checkout x"
expect "GIT_DIR/GIT_WORK_TREE env redirects the target to the mayor, so checkout is blocked" 2

run_hook agent-1 "$WT" "env GIT_DIR=$MAYOR/.git git reset --hard"
expect "env GIT_DIR=... git reset is blocked" 2

run_hook agent-1 "$WT" "GIT_DIR=$MAYOR/.git git status"
expect "read-only git with GIT_DIR stays allowed" 0

run_hook agent-1 "$WT" "git --git-dir=$MAYOR/.git --work-tree=$MAYOR checkout x"
expect "--git-dir=/--work-tree= redirect to the mayor is blocked" 2

run_hook agent-1 "$WT" "git --git-dir $MAYOR/.git --work-tree $MAYOR checkout x"
expect "space-separated --git-dir/--work-tree redirect is blocked" 2

run_hook agent-1 "$WT" "git --git-dir=$MAYOR/.git log -1"
expect "read-only git with --git-dir stays allowed" 0

run_hook agent-1 "$MAYOR" "git -c alias.co=checkout co x"
expect "-c alias.co=checkout hides the real subcommand, so it is resolved and blocked" 2

run_hook agent-1 "$MAYOR" "git -c alias.sw='switch -f' sw main"
expect "alias with arguments resolves to its first word and is blocked" 2

run_hook agent-1 "$MAYOR" "git -c alias.x='!rm -rf .' x"
expect "shell alias fails closed in the mayor checkout" 2

run_hook agent-1 "$MAYOR" "git -c alias.l=log l"
expect "alias to read-only log stays allowed" 0

run_hook agent-1 "$WT" "git -c alias.co=checkout co -b z"
expect "alias checkout in a linked worktree stays allowed" 0

run_hook agent-1 "$MAYOR" "echo \"\$(echo hi; git checkout x)\""
expect "separator inside quoted \$(...) must not hide a checkout" 2

run_hook agent-1 "$MAYOR" "echo \"\`echo hi; git checkout x\`\""
expect "separator inside quoted backticks must not hide a checkout" 2

run_hook agent-1 "$MAYOR" "echo \"\$(echo hi) ; git checkout x is text\""
expect "text after a closed substitution is quoted again (no false positive)" 0

run_hook agent-1 "$MAYOR" "echo \"\$(echo hi)\" ; git checkout x"
expect "a real command after a closed quoted substitution is still checked" 2

run_hook agent-1 "$MAYOR" "echo \"\$(git status; git log)\""
expect "read-only git inside quoted substitution stays allowed" 0

for q in "'EOF'" '"EOF"' "\\EOF"; do
  run_hook agent-1 "$MAYOR" $'gh pr comment 1 --body "$(cat <<'"$q"$'\ngit checkout main\ngit reset --hard; it\'s fine\nEOF\n)"'
  expect "quoted heredoc <<$q body is data, so prose mentioning git checkout in a PR comment is allowed" 0
done

run_hook agent-1 "$MAYOR" $'gh pr comment 1 --body "$(cat <<-\'EOF\'\n\tgit checkout main\n\tEOF\n)"'
expect "<<-'EOF' with tab-indented terminator is a quoted heredoc too" 0

run_hook agent-1 "$MAYOR" $'cat <<\'EOF\'\ngit checkout x\nEOF\ngit checkout y'
expect "a real checkout after the heredoc terminator is still blocked (stripping must not swallow the rest)" 2

run_hook agent-1 "$MAYOR" $'cat <<EOF\n$(git checkout x)\nEOF'
expect "unquoted heredoc expands \$(...), so a checkout inside it runs and is blocked" 2

run_hook agent-1 "$MAYOR" $'cat <<EOF\n`git reset --hard`\nEOF'
expect "unquoted heredoc expands backticks, so a reset inside it is blocked" 2

run_hook agent-1 "$MAYOR" $'cat <<EOF\ngit checkout x is just text\nEOF'
expect "unquoted heredoc plain text is data, not a git invocation" 0

run_hook agent-1 "$MAYOR" $'cat <<EOF\n$(echo hi\ngit checkout x\n)\nEOF'
expect "multi-line substitution inside an unquoted heredoc is scanned" 2

run_hook agent-1 "$MAYOR" $'cat <<EOF\n\\$(git checkout x)\nEOF'
expect "escaped \\\$( in an unquoted heredoc is literal text" 0

run_hook agent-1 "$MAYOR" $'cat <<\'EOF\'\ngit checkout x'
expect "heredoc without a terminator is not stripped (fail closed)" 2

run_hook agent-1 "$MAYOR" $'echo $((1<<2))\ngit checkout x\n2'
expect "<< inside \$((...)) is a shift, so a matching later line must not hide a checkout" 2

run_hook agent-1 "$MAYOR" $'echo $(( (x) <<EOF ))\ngit checkout x\nEOF'
expect "spaced/nested arithmetic with a word-shaped shift operand does not open a heredoc either" 2

run_hook agent-1 "$MAYOR" $'echo $((1<<2))\ngit status\n2'
expect "plain arithmetic with a read-only git line stays allowed" 0

run_hook agent-1 "$MAYOR" $'echo $((1<<2)); cat <<EOF\ngit checkout x is text\nEOF'
expect "a real heredoc after arithmetic on the same line is still stripped" 0

run_hook agent-1 "$MAYOR" $'(( x = 1<<EOF ))\ngit checkout x\nEOF'
expect "<< inside a bare (( ... )) command is a shift, so it must not hide a checkout" 2

run_hook agent-1 "$MAYOR" $'echo $[1<<EOF]\ngit checkout x\nEOF'
expect "<< inside legacy \$[ ... ] arithmetic is a shift, so it must not hide a checkout" 2

run_hook agent-1 "$MAYOR" $'(( x = 1<<2 )); cat <<EOF\ngit checkout x is text\nEOF'
expect "a real heredoc after a bare (( )) on the same line is still stripped" 0

run_hook agent-1 "$MAYOR" $'echo $[1<<2]; cat <<EOF\ngit checkout x is text\nEOF'
expect "a real heredoc after \$[ ] on the same line is still stripped" 0

run_hook agent-1 "$MAYOR" $'if true; then git checkout x; fi'
expect "if/then compound does not hide a checkout" 2

run_hook agent-1 "$MAYOR" "if git checkout x; then echo; fi"
expect "if <move> is a command position" 2

run_hook agent-1 "$MAYOR" "for f in a; do git checkout x; done"
expect "for/do compound does not hide a checkout" 2

run_hook agent-1 "$MAYOR" "false || { git checkout x; }"
expect "brace group does not hide a checkout" 2

run_hook agent-1 "$MAYOR" "! git checkout x"
expect "negation prefix does not hide a checkout" 2

run_hook agent-1 "$MAYOR" "\\git checkout x"
expect "backslash-escaped git (alias bypass spelling) is still git" 2

run_hook agent-1 "$MAYOR" $'git \\\ncheckout x'
expect "backslash-newline between git and subcommand is a line continuation" 2

run_hook agent-1 "$WT" $'git fetch origin main && git checkout -B w1 origin/main'
expect "worker fetch + checkout -B in own worktree stays allowed" 0

run_hook agent-1 "$WT" "git push origin HEAD:worker/x"
expect "push HEAD:branch stays allowed" 0

run_hook agent-1 "$MAYOR" "git commit -m \"fix: a; b \$(date)\""
expect "commit with ; and \$() in message stays allowed" 0

run_hook agent-1 "$MAYOR" "gh pr create --title t --body \"\$(cat body.md)\""
expect "gh pr create --body \"\$(cat file)\" stays allowed" 0

run_hook agent-1 "$MAYOR" "if true; then git status; fi"
expect "read-only git inside if/then stays allowed" 0

run_hook "" "$MAYOR" "git checkout main"
expect "mayor session (no agent_id) can still move its own HEAD" 0

if [ "$FAILURES" -eq 0 ]; then
  printf '\nall tests passed\n'
else
  printf '\n%d test(s) failed\n' "$FAILURES" >&2
  exit 1
fi
