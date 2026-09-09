#!/usr/bin/env bash
# SessionStart / PreCompact hook wrapper around `bd prime`.
#
# `bd prime`'s default output embeds the FULL BODY of every persistent
# memory (~300KB / ~248 memories as of 2026-08-27), and that transcript
# recurs on every SessionStart, every PreCompact, and gets cache-re-read on
# most turns in between -- measured at ~$50/day at the operator's usage
# pattern. bd's own customization point (.beads/PRIME.md) is a STATIC
# override with no templating (verified empirically: a `{{ .Key }}` probe
# passed through byte-for-byte instead of interpolating), so it can't
# express a dynamic index over a changing memory bank. This script builds
# the slim form itself: bd's workflow header + command reference verbatim,
# but the "Persistent Memories" section reduced to a one-line
# `- <key>: <snippet>` index instead of full bodies. Full bodies stay one
# `bd recall <key>` away -- see CLAUDE.md "Memory access pattern".
set -euo pipefail

# Truncation length for the index snippet. Tuned so ~248 memories + bd's
# header/command-reference boilerplate lands near a ~31KB target while
# leaving headroom for bank growth under a 50KB ceiling.
DESC_LEN="${BD_PRIME_SLIM_DESC_LEN:-70}"

MEMORY_HEADER_MARKER='## Persistent Memories ('
FOOTER_MARKER='# 🚨 SESSION CLOSE PROTOCOL'

# Reformats a `bd prime --export` transcript ($1) and a `bd memories --json`
# dump ($2) into the slim index form. Split out from main() so tests can
# feed fixtures instead of depending on live bd state.
render_slim_prime() {
  local export_file="$1" memories_json="$2"
  local full header footer count

  full="$(cat "$export_file")"

  if [[ "$full" != *"$MEMORY_HEADER_MARKER"* ]] || [[ "$full" != *"$FOOTER_MARKER"* ]]; then
    # bd's default template shape changed underneath us. Slimming blind
    # would either no-op (ship the 300KB body) or truncate the command
    # reference. Fail loud instead: pass the real output through untouched
    # and say why on stderr, rather than silently producing either failure.
    printf 'bd-prime-slim: expected marker not found in `bd prime --export`; passing through unmodified\n' >&2
    printf '%s\n' "$full"
    return
  fi

  # bash 3.2 (stock on macOS) is catastrophically slow at `${var#*pattern}`
  # / `${var%%pattern*}` on a ~300KB string when the match is near the far
  # end (measured: ~40s for the footer split alone, vs single-digit ms in
  # awk) -- bash 5 does the same expansion in milliseconds, but operators
  # can't be assumed to be on bash 5. awk finds the marker LINE and slices
  # around it in place, so both splits run in ms regardless of bash version.
  #
  # header: takes the FIRST marker occurrence. Safe because the header
  # marker structurally precedes every memory body in bd's template -- a
  # memory body containing that literal string can only appear AFTER it.
  #
  # footer: must take the LAST marker occurrence, not the first. A memory
  # body can legitimately quote the footer marker string (e.g. a memory
  # ABOUT the session-close protocol) and bd renders bodies verbatim with
  # no indent, so a body's copy of the marker lands at column 1, same as
  # the real one -- column-position alone can't disambiguate them. The
  # real footer is always the LAST occurrence because it's the template's
  # trailing section, rendered only after every memory body.
  header="$(awk -v marker="$MEMORY_HEADER_MARKER" 'index($0, marker) > 0 {exit} {print}' "$export_file")"
  footer_line="$(awk -v marker="$FOOTER_MARKER" 'index($0, marker) > 0 {n=NR} END{print n+0}' "$export_file")"
  footer="$(awk -v n="$footer_line" 'NR>=n' "$export_file")"
  # `bd memories --json` mixes in a non-memory `schema_version` metadata key
  # (numeric value) alongside the actual string-bodied memories -- filter it
  # out or jq's gsub/slicing below aborts on a non-string .value.
  count="$(jq '[to_entries[] | select(.value | type == "string")] | length' "$memories_json")"

  # `$(...)` strips header's trailing blank line(s) before the marker (they
  # were pure newlines); force exactly one back so the heading below isn't
  # glued directly to the preceding prose.
  printf '%s\n\n' "$header"
  printf '## Persistent Memories (%s) — INDEX ONLY\n\n' "$count"
  printf 'Full bodies are pulled on demand, not preloaded: `bd memories <keyword>` returns the complete entry. See CLAUDE.md "Memory access pattern". Do NOT run a bare `bd memories` to dump the whole bank into a turn -- that defeats the point of this index.\n\n'
  jq -r --argjson n "$DESC_LEN" '
    to_entries
    | map(select(.value | type == "string"))
    | sort_by(.key)
    | .[]
    | "- \(.key): \(.value | gsub("\\s+"; " ") | if length > $n then .[0:$n] + "..." else . end)"
  ' "$memories_json"
  printf '\n'
  printf '%s\n' "$footer"
}

main() {
  # Not `local`: the EXIT trap below runs after main() returns, and a
  # function-local var is unset by then under `set -u`.
  export_file="$(mktemp)"
  memories_json="$(mktemp)"
  trap 'rm -f "$export_file" "$memories_json"' EXIT

  bd prime --export > "$export_file"
  bd memories --json > "$memories_json"

  render_slim_prime "$export_file" "$memories_json"
}

# Allow the test suite to source this file (for render_slim_prime) without
# triggering a live `bd prime --export` call.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
