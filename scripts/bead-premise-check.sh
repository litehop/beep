#!/usr/bin/env bash
# scripts/bead-premise-check.sh <bead-id>
#
# Replaces the mayor's per-dispatch model turn spent "grep to confirm the
# bead's target is still broken/missing (not already landed)" -- purely
# deterministic once you have the bead's own text, so it doesn't need a
# model call at all.
#
# Reads the bead via `bd show <id> --json`, best-effort extracts a target
# pattern its description/design/acceptance criteria cite (a file path, a
# symbol/type name, or a fenced code snippet), and checks whether that
# pattern is still present in the tracked tree. A bare code-span symbol or
# fenced snippet is assumed to be cited AS EVIDENCE OF THE BUG -- so
# presence means the bug is still there and absence means it's already
# been fixed. A cited file path is weaker evidence in the other direction
# only: its ABSENCE is a confident "still broken" (the bead expects it to
# exist and it doesn't), but its mere PRESENCE proves nothing on its own --
# see extract_path_candidates()'s doc comment for why.
#
# Multiple candidates are tried in priority order (most to least specific);
# a real reviewed false positive (a NetworkPolicy-protocol-defaulting bug
# report) is exactly why two separate fallbacks exist. First: its first
# backtick span, `crates/apiserver/src/handlers/
# defaults.rs`, is an existing file the fix added a function TO -- it
# exists whether or not the fix landed, so a bare path match never decides
# "still-broken" on its own (see extract_path_candidates()). Second: its
# first bug-description symbol, `NetworkPolicyPort.protocol`, is API
# terminology the fix's OWN doc comment also uses to describe what it now
# does -- presence there can't distinguish "not fixed" from "fixed, and
# said so in a comment". The bead's own "Fix:" section names what the
# remedy actually adds (`default_networkpolicy`) with the OPPOSITE
# polarity (presence = fixed) and is checked ahead of bug-description
# symbols for exactly that reason (see extract_fix_section_candidate()).
#
# Prints one of the following to stdout and exits with the matching code:
#   still-broken      (0) -- a confident signal says the bug remains;
#                            dispatch as planned.
#   no-longer-broken  (1) -- a confident signal says it's already fixed;
#                            close as verified-duplicate instead of
#                            dispatching.
#   cannot-verify      (2) -- no candidate produced a confident signal, or
#                            `bd show` failed; a human/mayor call is still
#                            needed. Preferred over guessing: see another
#                            reviewed false positive (an install-script
#                            restart-ordering bug report), whose only
#                            backtick spans are short (`enable`, `start`)
#                            or unstructured (`journalctl`) -- none
#                            specific enough to trust either way.
#
# Testability: `bead-premise-check.sh __call <fn> [args...]` invokes a
# single function from this file, the same convention used by other
# scripts/ tools (see scripts/test-check-bead-id-refs-logic.sh for the
# pattern this mirrors). The pure classification step is split into
# classify_from_json() so the test suite can feed synthetic `bd show --json`
# output and a sandbox git tree, with no live `bd` session or network call.
set -euo pipefail

REPO_ROOT="${BEAD_PREMISE_CHECK_REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

# ---------------------------------------------------------------------------
# Pure helpers (unit-tested directly via `__call`).
# ---------------------------------------------------------------------------

# Every backtick-quoted markdown code span in `text`, in order of
# appearance, with the backticks stripped -- the convention this repo's
# beads already use for file paths, symbols, and commands (see any bead
# body via `bd show`).
extract_backtick_spans() {
  printf '%s' "$1" | grep -oE '`[^`]+`' | sed -E 's/^`(.*)`$/\1/' || true
}

# Path-shaped candidates: backtick spans containing `/`. These are the
# LEAST reliable signal for "is the bug still present" when the path
# exists, because a bead's fix almost never deletes the file it modifies
# -- a bug of the shape "add function X to existing file Y" leaves Y
# existing before AND after the fix. A cited path's ABSENCE is still a
# confident signal (see classify_from_json), so this bucket is checked
# first for that half of the question only.
extract_path_candidates() {
  local text="$1" spans
  spans=$(extract_backtick_spans "$text")
  printf '%s\n' "$spans" | grep -E '/' || true
}

# True (exit 0) iff a bare (non-path) code-span candidate is specific
# enough to trust as a real symbol/type/convention reference rather than a
# short common word that will coincidentally match all over the tree.
# Reproduced false positive (critical-review findings on two real closed
# beads): without this filter, a single backtick span like `enable` (from
# "`systemctl enable --now UNIT`" / "`enable` + `start`") is treated as
# the target pattern and matches unrelated occurrences tree-wide,
# misclassifying an already-fixed bead as still-broken.
is_restricted_symbol_candidate() {
  local s="$1"
  case "$s" in
    *' '*) return 1 ;;   # multi-word prose-in-backticks (e.g. `git commit`), not a symbol
    */*) return 1 ;;     # path-shaped -- handled by extract_path_candidates instead
  esac
  [ "${#s}" -ge 8 ] || return 1
  case "$s" in
    *_*) return 0 ;;      # snake_case, e.g. `default_networkpolicy`
  esac
  # CamelCase/mixedCase: a lowercase letter immediately followed by an
  # uppercase one, e.g. `NetworkPolicyPort`. Plain grep -E (not a GNU-only
  # extension) since macOS ships BSD grep as /bin/grep.
  printf '%s' "$s" | grep -qE '[a-z][A-Z]'
}

# Bare-symbol candidates passing is_restricted_symbol_candidate, in order
# of appearance.
extract_symbol_candidates() {
  local text="$1" spans line
  spans=$(extract_backtick_spans "$text")
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    is_restricted_symbol_candidate "$line" && printf '%s\n' "$line"
  done <<< "$spans"
  return 0
}

# The first non-blank, whitespace-trimmed line of the bead's first fenced
# (```) code block, if any -- often the exact broken snippet a bead quotes
# verbatim. Only leading/trailing whitespace is trimmed (not internal
# runs), so indentation-sensitive snippets still match byte-for-byte
# against source.
extract_fenced_code_pattern() {
  local text="$1" block
  block=$(printf '%s\n' "$text" | awk '/^```/ { c++; next } c==1 { print }')
  [ -z "$block" ] && { printf ''; return; }
  printf '%s\n' "$block" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' | awk 'NF { print; exit }'
}

# True (exit 0) iff `path` is a file tracked in the repo at HEAD-equivalent
# working-tree state.
path_exists_in_tree() {
  local path="$1"
  git -C "$REPO_ROOT" ls-files --error-unmatch -- "$path" >/dev/null 2>&1
}

# True (exit 0) iff `pattern` appears in tracked file CONTENT anywhere in
# the tree. Excludes `.beads/` -- without that exclusion, every pattern
# extracted from a bead's own text would trivially match, because
# `.beads/issues.jsonl` stores that same text, making the check always
# report still-broken regardless of what the actual code looks like.
content_present_in_tree() {
  local pattern="$1"
  git -C "$REPO_ROOT" grep -qF -e "$pattern" -- . ':!.beads' 2>/dev/null
}

# This repo's beads consistently label the prescribed remedy with a
# "Fix:"/"FIX:" line starting its own paragraph. Everything from that
# marker onward describes the FIX, not the bug -- so a symbol named there
# has INVERTED polarity from a bug-description symbol: its presence means
# the fix landed, not that the bug remains. Anchored to a line start
# (optional leading whitespace/markdown emphasis only) so "prefix:"/
# "suffix:" never false-trigger.
extract_fix_section_text() {
  printf '%s\n' "$1" | sed -n -E '/^[[:space:]]*\*{0,2}[Ff][Ii][Xx]\*{0,2}:/,$p'
}

# The first restricted symbol candidate named in the bead's Fix section, if
# any. Empirical case (a reviewed false positive on a real closed bead):
# the bug-description text reuses the exact Kubernetes API terminology
# (`NetworkPolicyPort.protocol`) that the shipped fix's own doc comment
# also uses to describe what it now does -- checking that phrase's
# presence can never distinguish "not fixed yet" from "fixed, and the doc
# comment says so". The Fix section's own named symbol
# (`default_networkpolicy`, the function it says to add) doesn't have that
# problem: it names something that either exists (fixed) or doesn't
# (still broken), by construction of how "Fix: add X" is phrased.
extract_fix_section_candidate() {
  local text="$1" fix_text
  fix_text=$(extract_fix_section_text "$text")
  [ -z "$fix_text" ] && { printf ''; return; }
  extract_symbol_candidates "$fix_text" | head -1
}

# Classifies a single `bd show <id> --json` result (a one-element array).
# Split out from main() so tests can feed synthetic JSON against a sandbox
# git tree, without a live `bd` session or network access -- the same
# "exercise the real logic, not a reimplementation" technique the sibling
# scripts/test-*-logic.sh suites use.
#
# Tries candidates most-to-least specific, stopping at the first CONFIDENT
# signal (see the header comment for why a path's mere existence is never
# confident on its own): first path candidate absent -> still-broken; the
# Fix section's own symbol candidate, INVERTED (present -> no-longer-
# broken, absent -> still-broken); else a bug-description symbol
# candidate's presence/absence -> still-broken / no-longer-broken; else
# the first fenced-code-block line's presence/absence; else cannot-verify.
#
# Prints still-broken / no-longer-broken / cannot-verify and returns
# 0 / 1 / 2 respectively.
classify_from_json() {
  local json="$1" text first_path fix_symbol first_symbol fenced

  text=$(printf '%s' "$json" | jq -r '
    [.[0].description, .[0].design, .[0].acceptance_criteria]
    | map(select(. != null)) | join("\n")')

  first_path=$(extract_path_candidates "$text" | head -1)
  if [ -n "$first_path" ] && ! path_exists_in_tree "$first_path"; then
    printf 'still-broken\n'
    return 0
  fi

  fix_symbol=$(extract_fix_section_candidate "$text")
  if [ -n "$fix_symbol" ]; then
    if content_present_in_tree "$fix_symbol"; then
      printf 'no-longer-broken\n'
      return 1
    fi
    printf 'still-broken\n'
    return 0
  fi

  first_symbol=$(extract_symbol_candidates "$text" | head -1)
  if [ -n "$first_symbol" ]; then
    if content_present_in_tree "$first_symbol"; then
      printf 'still-broken\n'
      return 0
    fi
    printf 'no-longer-broken\n'
    return 1
  fi

  fenced=$(extract_fenced_code_pattern "$text")
  if [ -n "$fenced" ]; then
    if content_present_in_tree "$fenced"; then
      printf 'still-broken\n'
      return 0
    fi
    printf 'no-longer-broken\n'
    return 1
  fi

  printf 'cannot-verify\n'
  return 2
}

main() {
  local bead_id="${1:-}"
  if [ -z "$bead_id" ]; then
    echo "usage: bead-premise-check.sh <bead-id>" >&2
    printf 'cannot-verify\n'
    exit 2
  fi

  local json rc=0
  json=$(bd show "$bead_id" --json 2>/dev/null) || json=''
  if [ -z "$json" ] || [ "$json" = "null" ]; then
    printf 'cannot-verify\n'
    exit 2
  fi

  classify_from_json "$json" || rc=$?
  exit "$rc"
}

if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  if [ "${1:-}" = "__call" ]; then
    shift
    "$@"
  else
    main "$@"
  fi
fi
