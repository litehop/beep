#!/usr/bin/env bash
# PreToolUse hook for Bash. Blocks SUBAGENTS from running HEAD-moving or
# working-tree-rewriting git commands in the main (non-linked) checkout.
#
# Subagent detection: the hook's stdin JSON carries agent_id only when the
# tool call comes from a subagent; the mayor's own session has none and is
# never blocked here.
#
# "Main checkout" = the effective repo's --absolute-git-dir equals its
# --git-common-dir (same detection as assert-worktree-boundary.sh). Linked
# worktrees (ai/worktrees/*, scratch worktrees) are therefore always allowed.
#
# Effective directory: the hook's cwd, updated by `cd <dir>` segments and
# overridden per-command by `git -C <dir>`. Best effort on shell syntax:
# command-position `git` (optionally behind env/command/sudo/exec/time or
# `bash -c '...'`) in `;`/`&&`/`||`/`|`/newline-separated segments.
set -euo pipefail

INPUT=$(cat)
AGENT_ID=$(printf '%s' "$INPUT" | jq -r '.agent_id // empty')
[ -z "$AGENT_ID" ] && exit 0

CMD=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty')
[ -z "$CMD" ] && exit 0
CWD=$(printf '%s' "$INPUT" | jq -r '.cwd // empty')
[ -z "$CWD" ] && CWD=$(pwd)

BLOCKED_SUBCMDS=" checkout switch reset pull merge rebase stash restore cherry-pick revert "

is_main_checkout() {
  local dir="$1" abs common
  [ -d "$dir" ] || return 1
  abs=$(git -C "$dir" rev-parse --absolute-git-dir 2>/dev/null) || return 1
  common=$(git -C "$dir" rev-parse --git-common-dir 2>/dev/null) || return 1
  [[ "$common" == /* ]] || common="$dir/$common"
  common=$(cd "$common" 2>/dev/null && pwd -P) || return 1
  abs=$(cd "$abs" 2>/dev/null && pwd -P) || return 1
  [ "$abs" = "$common" ]
}

resolve_dir() { # $1 base, $2 path
  case "$2" in
    /*) printf '%s' "$2" ;;
    "~"*) printf '%s' "$HOME${2#\~}" ;;
    *) printf '%s/%s' "$1" "$2" ;;
  esac
}

strip_quotes() {
  local s="$1"
  s="${s#[\"\']}"
  s="${s%[\"\']}"
  printf '%s' "$s"
}

block() { # $1 subcommand, $2 dir
  local top
  top=$(git -C "$2" rev-parse --show-toplevel 2>/dev/null || printf '%s' "$2")
  # shellcheck disable=SC2016
  printf 'MAYOR CHECKOUT GUARD: subagents must not run `git %s` in the main checkout (%s); it moves HEAD or rewrites the working tree the mayor depends on.\nInstead: read PRs via `gh pr diff <n>` / `gh pr view <n>`, or create a scratch worktree (`git worktree add <path> <ref>`) and run git there with `git -C <path> ...`.\n' \
    "$1" "$top" >&2
  exit 2
}

check_cmdline() { # $1 command line, $2 starting dir
  local line="$1" dir="$2" seg
  line=${line//&&/$'\n'}
  line=${line//||/$'\n'}
  line=${line//;/$'\n'}
  line=${line//|/$'\n'}
  line=${line//\(/$'\n'}
  line=${line//\)/$'\n'}
  line=${line//\`/$'\n'}
  while IFS= read -r seg; do
    check_segment "$seg" "$dir"
    dir="$SEG_DIR"
  done <<< "$line"
}

SEG_DIR=""
check_segment() { # $1 segment, $2 dir; sets SEG_DIR (dir after any `cd`)
  local -a t
  local dir="$2" i=0 n tok gdir sub
  SEG_DIR="$dir"
  set -f
  read -ra t <<< "$1" || true
  set +f
  n=${#t[@]}
  [ "$n" -gt 0 ] || return 0
  tok=$(strip_quotes "${t[0]}")
  while [ "$i" -lt "$n" ]; do
    tok=$(strip_quotes "${t[$i]}")
    case "$tok" in
      [A-Za-z_]*=*|env|command|sudo|exec|time|nohup) i=$((i + 1)) ;;
      *) break ;;
    esac
  done
  [ "$i" -lt "$n" ] || return 0
  tok=$(strip_quotes "${t[$i]}")
  case "${tok##*/}" in
    cd)
      if [ $((i + 1)) -lt "$n" ]; then
        SEG_DIR=$(resolve_dir "$dir" "$(strip_quotes "${t[$((i + 1))]}")")
      fi
      return 0
      ;;
    bash|sh|zsh)
      if [ $((i + 1)) -lt "$n" ] && [ "${t[$((i + 1))]}" = "-c" ] && [ $((i + 2)) -lt "$n" ]; then
        local rest="${t[*]:$((i + 2))}"
        rest="${rest#[\"\']}"
        rest="${rest%[\"\']}"
        check_cmdline "$rest" "$dir"
        SEG_DIR="$dir"
      fi
      return 0
      ;;
    git) ;;
    *) return 0 ;;
  esac

  gdir="$dir"
  i=$((i + 1))
  while [ "$i" -lt "$n" ]; do
    tok=$(strip_quotes "${t[$i]}")
    case "$tok" in
      -C)
        i=$((i + 1))
        [ "$i" -lt "$n" ] && gdir=$(resolve_dir "$gdir" "$(strip_quotes "${t[$i]}")")
        ;;
      -c|--git-dir|--work-tree|--namespace|--exec-path) i=$((i + 1)) ;;
      -*) ;;
      *) break ;;
    esac
    i=$((i + 1))
  done
  [ "$i" -lt "$n" ] || return 0
  sub=$(strip_quotes "${t[$i]}")
  case "$BLOCKED_SUBCMDS" in
    *" $sub "*)
      if is_main_checkout "$gdir"; then block "$sub" "$gdir"; fi
      ;;
  esac
  return 0
}

check_cmdline "$CMD" "$CWD"
exit 0
