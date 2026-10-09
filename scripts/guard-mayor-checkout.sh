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
# Effective directory: the hook's cwd, updated by `cd`/`pushd <dir>` segments
# (flags and `builtin cd` handled; `popd` and `pushd` without a dir make it
# unknown) and overridden per-command by `git -C <dir>`. Best effort on shell
# syntax: command-position `git` (optionally behind env/command/builtin/sudo/
# exec/time, `xargs ... git`, or `bash -c '...'`) in `;`/`&&`/`||`/`|`/newline-
# separated segments; substitutions inside double quotes are scanned as code.
# Backslash-newline is joined; heredoc bodies are data (quoted delimiter: not
# scanned; unquoted: only $(...)/backtick substitutions scanned); leading
# if/then/else/elif/do/while/until/{/!/backslash are skipped to reach `git`.
#
# Fail closed: GIT_DIR=/GIT_WORK_TREE= prefixes, --git-dir/--work-tree, and
# `-c alias.X=...` (when X is invoked) make the target unknown, so a
# HEAD-moving subcommand is blocked.
#
# Accepted residuals (accidental-move threat model, not an adversary):
# - aliases or GIT_DIR/GIT_WORK_TREE set earlier (git config, `export`, a
#   previous segment) rather than on the invocation
# - xargs/find -exec/parallel wrapping a shell (`xargs sh -c 'git ...'`);
#   only `xargs ... git <sub>` is scanned
# - eval, sourced scripts, functions, variables expanded into the command,
#   and heredoc bodies fed to a shell (`bash <<EOF`)
# - a second heredoc on one line, `<<` inside quotes mistaken for a heredoc,
#   `case` arms (`x) git checkout y ;;`), and partial escapes (`g\it`)
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

UNKNOWN_DIR="?"

resolve_dir() { # $1 base, $2 path
  case "$2" in
    -|*'$'*|*'`'*) printf '%s' "$UNKNOWN_DIR" ;;
    "") printf '%s' "$1" ;;
    /*) printf '%s' "$2" ;;
    "~"*) printf '%s' "$HOME${2#\~}" ;;
    *)
      if [ "$1" = "$UNKNOWN_DIR" ]; then
        printf '%s' "$UNKNOWN_DIR"
      else
        printf '%s/%s' "$1" "$2"
      fi
      ;;
  esac
}

strip_quotes() {
  local s="$1"
  s="${s#[\"\']}"
  s="${s%[\"\']}"
  printf '%s' "$s"
}

is_read_only() { # $1 subcommand, rest: its args
  local sub="$1" a
  shift
  case "$sub" in
    stash)
      a=$(strip_quotes "${1:-}")
      [ "$a" = list ] || [ "$a" = show ] || return 1
      shift
      for a in "$@"; do
        case "$(strip_quotes "$a")" in
          -p | --patch | --stat | --oneline | --name-only | --name-status) ;;
          -*) return 1 ;;
        esac
      done
      ;;
    restore)
      local staged=1
      for a in "$@"; do
        a=$(strip_quotes "$a")
        case "$a" in
          --) break ;;
          --staged | -S) staged=0 ;;
          -*) return 1 ;;
        esac
      done
      return "$staged"
      ;;
    *) return 1 ;;
  esac
}

block() { # $1 subcommand, $2 dir
  local top
  top=$(git -C "$2" rev-parse --show-toplevel 2>/dev/null || printf '%s' "$2")
  # shellcheck disable=SC2016
  printf 'MAYOR CHECKOUT GUARD: subagents must not run `git %s` in the main checkout (%s); it moves HEAD or rewrites the working tree the mayor depends on.\nInstead: read PRs via `gh pr diff <n>` / `gh pr view <n>`, or create a scratch worktree (`git worktree add <path> <ref>`) and run git there with `git -C <path> ...`.\n' \
    "$1" "$top" >&2
  exit 2
}

split_segments() { # $1 command line, $2 "raw" to ignore quoting -> newline-separated segments
  local s="$1" raw="${2:-}" out="" c q="" bt=0 bt_quoted=0 pd=0 i=0 n=${#1}
  local -a sub_pd=()
  # ANSI-C quoting ($'..') has escape rules this tracker does not model.
  case "$s" in *"\$'"*) raw=raw ;; esac
  while [ "$i" -lt "$n" ]; do
    c=${s:i:1}
    if [ "$c" = "\\" ] && [ "$q" != "'" ] && [ -z "$raw" ]; then
      out+="$c${s:i+1:1}"
      i=$((i + 2))
      continue
    fi
    if [ -n "$q" ]; then
      # Inside "...", a substitution's body is code again: leave quote mode
      # until it closes so its separators split, then resume the quote.
      if [ "$q" = '"' ] && [ "$c" = '$' ] && [ "${s:i+1:1}" = "(" ]; then
        out+=$'$\n'
        sub_pd+=("$pd")
        pd=$((pd + 1))
        q=""
        i=$((i + 2))
        continue
      fi
      if [ "$q" = '"' ] && [ "$c" = '`' ]; then
        out+=$'$\n'
        bt=1
        bt_quoted=1
        q=""
        i=$((i + 1))
        continue
      fi
      out+="$c"
      [ "$c" = "$q" ] && q=""
    else
      case "$c" in
        \'|\") [ -z "$raw" ] && q="$c"; out+="$c" ;;
        '`')
          if [ "$bt" -eq 0 ]; then out+=$'$\n'; else out+=$'\n'; fi
          bt=$((1 - bt))
          if [ "$bt" -eq 0 ] && [ "$bt_quoted" -eq 1 ]; then
            bt_quoted=0
            q='"'
          fi
          ;;
        '(') pd=$((pd + 1)); out+=$'\n' ;;
        ')')
          [ "$pd" -gt 0 ] && pd=$((pd - 1))
          out+=$'\n'
          if [ "${#sub_pd[@]}" -gt 0 ] && [ "${sub_pd[${#sub_pd[@]}-1]}" -eq "$pd" ]; then
            unset 'sub_pd[${#sub_pd[@]}-1]'
            q='"'
          fi
          ;;
        ';' | '|' | '&') out+=$'\n' ;;
        *) out+="$c" ;;
      esac
    fi
    i=$((i + 1))
  done
  if [ -n "$q" ] && [ -z "$raw" ]; then
    split_segments "$s" raw
    return
  fi
  printf '%s' "$out"
}

HEREDOC_RE='(^|[^<])<<(-?)[[:space:]]*([\"'"'"']?)([A-Za-z0-9_.-]+)'
TAB=$'\t'

# Only $(...) and `...` inside an unquoted heredoc body run as code.
extract_substs() { # $1 heredoc body -> its substitutions, one per line
  local s="$1" out="" c i=0 n=${#1} d=0 bt=0
  while [ "$i" -lt "$n" ]; do
    c=${s:i:1}
    if [ "$c" = "\\" ]; then
      [ "$d" -gt 0 ] || [ "$bt" -eq 1 ] && out+="$c${s:i+1:1}"
      i=$((i + 2))
      continue
    fi
    if [ "$d" -eq 0 ] && [ "$bt" -eq 0 ]; then
      if [ "$c" = '$' ] && [ "${s:i+1:1}" = "(" ]; then
        d=1
        out+='$('
        i=$((i + 1))
      elif [ "$c" = '`' ]; then
        bt=1
        out+="$c"
      fi
    else
      out+="$c"
      if [ "$bt" -eq 1 ]; then
        if [ "$c" = '`' ]; then bt=0; out+=$'\n'; fi
      elif [ "$c" = "(" ]; then
        d=$((d + 1))
      elif [ "$c" = ")" ]; then
        d=$((d - 1))
        [ "$d" -eq 0 ] && out+=$'\n'
      fi
    fi
    i=$((i + 1))
  done
  printf '%s' "$out"
}

# Heredoc bodies are data: drop quoted ones, keep only substitutions of
# unquoted ones. A heredoc with no terminator line is left in place.
strip_heredocs() { # $1 command line
  local out="" line check delim="" dash="" quoted="" body=""
  while IFS= read -r line || [ -n "$line" ]; do
    if [ -n "$delim" ]; then
      check="$line"
      [ "$dash" = "-" ] && check=${line#"${line%%[!$TAB]*}"}
      if [ "$check" = "$delim" ]; then
        [ -n "$quoted" ] || out+=$(extract_substs "$body")$'\n'
        delim=""
        body=""
      else
        body+="$line"$'\n'
      fi
      continue
    fi
    out+="$line"$'\n'
    if [[ $line =~ $HEREDOC_RE ]]; then
      dash="${BASH_REMATCH[2]}"
      quoted="${BASH_REMATCH[3]}"
      delim="${BASH_REMATCH[4]}"
    fi
  done <<< "$1"
  [ -z "$delim" ] || out+="$body"
  printf '%s' "$out"
}

check_cmdline() { # $1 command line, $2 starting dir
  local line dir="$2" seg cmd
  cmd=$(strip_heredocs "$1")
  cmd="${cmd//\\$'\n'/}"
  line=$(split_segments "$cmd")
  while IFS= read -r seg; do
    check_segment "$seg" "$dir"
    dir="$SEG_DIR"
  done <<< "$line"
}

SEG_DIR=""
check_segment() { # $1 segment, $2 dir; sets SEG_DIR (dir after any `cd`)
  local -a t
  local dir="$2" i=0 n tok gdir sub gunk=0 j alias_name="" alias_val=""
  SEG_DIR="$dir"
  set -f
  read -ra t <<< "$1" || true
  set +f
  n=${#t[@]}
  [ "$n" -gt 0 ] || return 0
  tok=$(strip_quotes "${t[0]}")
  while [ "$i" -lt "$n" ]; do
    tok=$(strip_quotes "${t[$i]}")
    tok="${tok#\\}"
    case "$tok" in
      GIT_DIR=*|GIT_WORK_TREE=*) gunk=1; i=$((i + 1)) ;;
      [A-Za-z_]*=*|env|command|builtin|sudo|exec|time|nohup) i=$((i + 1)) ;;
      if|then|else|elif|do|while|until|'{'|'!') i=$((i + 1)) ;;
      *) break ;;
    esac
  done
  [ "$i" -lt "$n" ] || return 0
  tok=$(strip_quotes "${t[$i]}")
  tok="${tok#\\}"
  if [ "${tok##*/}" = xargs ]; then
    j=$((i + 1))
    while [ "$j" -lt "$n" ] && [ "$(strip_quotes "${t[$j]}")" != git ]; do j=$((j + 1)); done
    [ "$j" -lt "$n" ] || return 0
    i=$j
    tok=git
  fi
  case "${tok##*/}" in
    cd|pushd)
      j=$((i + 1))
      while [ "$j" -lt "$n" ]; do
        tok=$(strip_quotes "${t[$j]}")
        case "$tok" in
          --) j=$((j + 1)); break ;;
          -) break ;;
          -*) j=$((j + 1)) ;;
          *) break ;;
        esac
      done
      if [ "$j" -lt "$n" ]; then
        tok=$(strip_quotes "${t[$j]}")
        case "$tok" in
          +*) SEG_DIR="$UNKNOWN_DIR" ;;
          *) SEG_DIR=$(resolve_dir "$dir" "$tok") ;;
        esac
      elif [ "${t[$i]}" = pushd ]; then
        SEG_DIR="$UNKNOWN_DIR"
      else
        SEG_DIR="$HOME"
      fi
      return 0
      ;;
    popd)
      SEG_DIR="$UNKNOWN_DIR"
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
      -c)
        i=$((i + 1))
        if [ "$i" -lt "$n" ]; then
          tok=$(strip_quotes "${t[$i]}")
          case "$tok" in
            [Aa][Ll][Ii][Aa][Ss].*=*)
              tok="${tok#*.}"
              alias_name="${tok%%=*}"
              alias_val=$(strip_quotes "${tok#*=}")
              ;;
          esac
        fi
        ;;
      --git-dir|--work-tree) i=$((i + 1)); gunk=1 ;;
      --git-dir=*|--work-tree=*) gunk=1 ;;
      --namespace|--exec-path) i=$((i + 1)) ;;
      -*) ;;
      *) break ;;
    esac
    i=$((i + 1))
  done
  [ "$i" -lt "$n" ] || return 0
  [ "$gunk" -eq 0 ] || gdir="$UNKNOWN_DIR"
  sub=$(strip_quotes "${t[$i]}")
  case "$alias_val" in
    '!'*)
      # A quoted shell-alias body spans tokens, so the invoked name is unreliable.
      if [ "$gdir" = "$UNKNOWN_DIR" ] || is_main_checkout "$gdir"; then block "alias" "$gdir"; fi
      return 0
      ;;
  esac
  [ -n "$alias_name" ] && [ "$sub" = "$alias_name" ] && sub="${alias_val%% *}"
  case "$BLOCKED_SUBCMDS" in
    *" $sub "*)
      if is_read_only "$sub" "${t[@]:$((i + 1))}"; then return 0; fi
      if [ "$gdir" = "$UNKNOWN_DIR" ] || is_main_checkout "$gdir"; then block "$sub" "$gdir"; fi
      ;;
  esac
  return 0
}

check_cmdline "$CMD" "$CWD"
exit 0
