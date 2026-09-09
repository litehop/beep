#!/usr/bin/env bash
# PreToolUse hook for Edit|Write. Blocks edits outside the current worktree.
#
# Two cases:
#   Worker session  — git root is the worktree dir; allow only files under it.
#   Mayor session   — git root is the main checkout; additionally block edits
#                     into ai/worktrees/ to prevent leaking into worker trees.
#
# Detection: in a linked worktree, --absolute-git-dir points into
# .git/worktrees/<name>, so it differs from --git-common-dir (.git).
# In the main checkout they are identical.
set -euo pipefail

INPUT=$(cat)
FILE_PATH=$(printf '%s' "$INPUT" | jq -r '.tool_input.file_path // empty')

[ -z "$FILE_PATH" ] && exit 0

# Make absolute before any dirname/basename work
if [[ "$FILE_PATH" != /* ]]; then
  FILE_PATH="$(pwd)/$FILE_PATH"
fi

GIT_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || true)
if [ -z "$GIT_ROOT" ]; then
  printf 'WORKTREE GUARD: Not in a git repository. Edit blocked.\n' >&2
  exit 2
fi

NORM_ROOT=$(cd "$GIT_ROOT" && pwd -P)

# Normalize the file path: resolve the parent dir (must exist; new files
# may not exist yet but their parent must), then reattach the basename.
PARENT_DIR=$(dirname "$FILE_PATH")
if RESOLVED_PARENT=$(cd "$PARENT_DIR" 2>/dev/null && pwd -P); then
  NORM_FILE="$RESOLVED_PARENT/$(basename "$FILE_PATH")"
else
  # Parent doesn't exist — definitely not a valid edit target in our tree
  printf 'WORKTREE GUARD: Parent directory "%s" does not exist. Edit blocked.\n' \
    "$PARENT_DIR" >&2
  exit 2
fi

# Block edits outside this session's git root entirely.
if [[ "$NORM_FILE" != "$NORM_ROOT"/* ]] && [[ "$NORM_FILE" != "$NORM_ROOT" ]]; then
  printf 'WORKTREE GUARD: Edit target "%s" is outside git root "%s".\nThis looks like a path-resolution leak. Edit blocked.\n' \
    "$FILE_PATH" "$GIT_ROOT" >&2
  exit 2
fi

# In the main checkout (not a linked worktree), block edits into worker trees.
# Run git from RESOLVED_PARENT (the file's directory) so that linked worktrees
# are correctly detected even when the shell's cwd is the main checkout.
ABS_GIT_DIR=$(git -C "$RESOLVED_PARENT" rev-parse --absolute-git-dir 2>/dev/null || true)
COMMON_GIT_DIR=$(git -C "$RESOLVED_PARENT" rev-parse --git-common-dir 2>/dev/null || true)
# Normalize common dir (may be relative in older git)
if [[ "$COMMON_GIT_DIR" != /* ]]; then
  COMMON_GIT_DIR="$(cd "$RESOLVED_PARENT" && pwd -P)/$COMMON_GIT_DIR"
fi
COMMON_GIT_DIR=$(cd "$COMMON_GIT_DIR" && pwd -P)

if [[ "$ABS_GIT_DIR" == "$COMMON_GIT_DIR" ]]; then
  # This is the main checkout. Block edits into any linked worktree.
  WORKTREE_DIR="$NORM_ROOT/ai/worktrees"
  if [[ "$NORM_FILE" == "$WORKTREE_DIR"/* ]]; then
    printf 'WORKTREE GUARD: Mayor session must not edit worker worktree at "%s".\nEdit blocked.\n' \
      "$FILE_PATH" >&2
    exit 2
  fi
fi

exit 0
