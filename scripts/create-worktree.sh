#!/usr/bin/env bash
# WorktreeCreate hook. Creates worker worktrees at ai/worktrees/ instead
# of the default .claude/worktrees/, and copies gitignored config files.
set -euo pipefail

INPUT=$(cat)

# Harness provides: cwd (repo root), name (agent ID used as worktree name)
BASE_PATH=$(printf '%s' "$INPUT" | jq -r '.cwd')
WORKTREE_NAME=$(printf '%s' "$INPUT" | jq -r '.name')
BRANCH_NAME="worker/$WORKTREE_NAME"

if [ -z "$BASE_PATH" ] || [ "$BASE_PATH" = "null" ] || [ -z "$WORKTREE_NAME" ] || [ "$WORKTREE_NAME" = "null" ]; then
  printf 'create-worktree: missing cwd or name. INPUT=%s\n' "$INPUT" >&2
  exit 1
fi

WORKTREE_DIR="$BASE_PATH/ai/worktrees/$WORKTREE_NAME"

mkdir -p "$BASE_PATH/ai/worktrees"

git -C "$BASE_PATH" worktree add "$WORKTREE_DIR" -b "$BRANCH_NAME" HEAD

# Sync .claude/settings.json so workers inherit the project's permission allowlist
mkdir -p "$WORKTREE_DIR/.claude"
cp -f "$BASE_PATH/.claude/settings.json" "$WORKTREE_DIR/.claude/settings.json"

printf '%s\n' "$WORKTREE_DIR"
