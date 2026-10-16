#!/usr/bin/env bash
# Asserts the guard hooks in .claude/settings.json fail closed. A PreToolUse
# hook only blocks on exit 2; any other failure (bash exit 127 for a missing
# script, an unset CLAUDE_PROJECT_DIR) silently skips the guard.
#
# Invoke: bash scripts/test-settings-guard-hooks-logic.sh
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
SETTINGS="$ROOT/.claude/settings.json"
FAILURES=0

# hook_cmd <script-basename> -> the hook command that references that script
hook_cmd() {
  jq -r --arg s "$1" \
    '[.hooks.PreToolUse[].hooks[].command | select(contains($s))] | first // empty' "$SETTINGS"
}

# run <cmd> <stdin> <project-dir|UNSET> -> sets RC
run() {
  RC=0
  if [ "$3" = UNSET ]; then
    printf '%s' "$2" | env -u CLAUDE_PROJECT_DIR sh -c "$1" >/dev/null 2>&1 || RC=$?
  else
    printf '%s' "$2" | CLAUDE_PROJECT_DIR="$3" sh -c "$1" >/dev/null 2>&1 || RC=$?
  fi
}

expect() { # $1 label, $2 expected rc
  if [ "$RC" -eq "$2" ]; then
    printf 'ok: %s\n' "$1"
  else
    printf 'FAIL: %s (rc=%s, expected %s)\n' "$1" "$RC" "$2" >&2
    FAILURES=$((FAILURES + 1))
  fi
}

EMPTY_DIR=$(mktemp -d)
trap 'rm -rf "$EMPTY_DIR"' EXIT

BASH_INPUT=$(jq -n --arg cwd "$ROOT" '{cwd:$cwd, tool_input:{command:"echo hi"}}')
EDIT_INPUT=$(jq -n --arg f "$ROOT/README.md" '{tool_input:{file_path:$f}}')

check() { # $1 script basename, $2 stdin for the healthy case, $3 what breaks
  local cmd
  cmd=$(hook_cmd "$1")
  if [ -z "$cmd" ]; then
    printf 'FAIL: no hook in settings.json references %s\n' "$1" >&2
    FAILURES=$((FAILURES + 1))
    return
  fi
  run "$cmd" "$2" UNSET
  expect "$1 hook with CLAUDE_PROJECT_DIR unset must block: $3" 2
  run "$cmd" "$2" ""
  expect "$1 hook with CLAUDE_PROJECT_DIR empty must block: $3" 2
  run "$cmd" "$2" "$EMPTY_DIR"
  expect "$1 hook with script missing must block: $3" 2
  run "$cmd" "$2" "$ROOT"
  expect "$1 hook against the real repo must allow a harmless input: a false block stalls every agent" 0
}

# run in the repo so the boundary hook sees the worktree as its git root
cd "$ROOT"
check guard-mayor-checkout.sh "$BASH_INPUT" "guard silently skipped, so agents can move the mayor checkout HEAD"
check assert-worktree-boundary.sh "$EDIT_INPUT" "boundary silently skipped, so edits can leak into the wrong checkout"

if [ "$FAILURES" -gt 0 ]; then
  printf '%s failure(s)\n' "$FAILURES" >&2
  exit 1
fi
echo "all passed"
