#!/usr/bin/env bash
# Fails if a bead-ID-shaped reference (mayor-XXXXX or beep-XXXXX) appears in
# tracked source.
#
# Bead IDs rot: a comment citing one reads fine the day it's written, but once
# that bead closes it's an unexplained token nobody can resolve. Historical
# context belongs in git/PR history, not a live token in source.
#
# Scope note (beep): beep's own crate/VM/binary names -- beep-ebpf,
# beep-common, beep-smoke, beep-node-a, beep-node-b, beep-wg2node,
# beep-ethingress2node, beep-client -- are `beep-[a-z0-9]{3,5}`-shaped too.
# The word-anchored regex below (see the regex note further down) already
# rules out beep-common/beep-node-a/beep-wg2node/beep-ethingress2node/
# beep-client: their alnum run continues past 5 chars, so no 3-5 char slice
# of it sits at a word boundary. beep-ebpf ("ebpf") and beep-smoke/-node-a
# ("smoke"/"node", up to the next hyphen) still coincide exactly with a real
# bead-ID's length; BEEP_NAME_ALLOWED_TOKENS below filters those back out,
# so only a real `beep-` bead ID (e.g. beep-xxx) trips this guard.
#
# Exclusions:
#   .beads/  -- bd's own JSONL export legitimately contains bead IDs.
#   ai/      -- findings/decisions docs legitimately cite the bead they came from.
#   docs/    -- same.
#   .github/ -- workflow configs may reference bead IDs in commit-adjacent context.
#   .gitignore -- the script name "mayor-tick" it references matches
#     mayor-[a-z0-9]{3,5} by coincidence: a permanent script name, not a
#     rotting bead ID.
#   scripts/mayor-tick.sh, scripts/test-mayor-tick-logic.sh -- their own
#     "mayor-tick" name matches the regex. A blanket whole-file skip once masked
#     THREE real, since-closed bead-ID refs in u7s, so MAYOR_TICK_ALLOWED_TOKENS
#     below re-scans them match-by-match and tolerates only known-safe tokens.
#   scripts/test-critical-reviewer-hook.sh -- its "mayor-abc12" fixture is
#     synthetic test input; CRITICAL_REVIEWER_HOOK_ALLOWED_TOKENS re-scans it.
#   scripts/test-check-bead-id-refs-logic.sh -- this guard's own regression
#     test; its fixtures are synthetic bead-ID-shaped strings that must trip
#     the regex to prove it works.
#   scripts/check-bead-id-refs.sh -- this file spells out the trip strings.
#
# Bead IDs are `mayor-` + a 3-5 char alphanumeric suffix (bd's ID generator;
# see .beads/issues.jsonl for the observed range), optionally followed by a
# dotted sub-ID suffix (e.g. `mayor-a1b2.6`). A fixed `{5}` here would silently
# skip most real IDs -- most are 3 or 4 characters, not 5.
#
# The suffix is followed by a `(?![a-z0-9])` negative lookahead so the match
# only catches a genuine 3-5 char bead-ID suffix, not a prefix of a longer
# word -- e.g. beep-servicelb's "servicelb" run is 9 alnum chars, so no 3-5
# char slice of it sits at a word boundary and the token is left alone.
# `git grep -E` (POSIX ERE) has no lookahead or \b support here, so the
# sweeps below use `git grep -P` (PCRE) instead -- via pcre_grep(), which
# fails loud (see below) if this git build lacks PCRE support, rather than
# letting the sweep go dark.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# `git grep -P` exits 1 for "no match" (expected, not an error) but a higher
# code (e.g. 128) for a real failure -- most notably a git built without PCRE
# support, which every sweep below depends on for the lookahead. The naive
# `git grep -P ... 2>/dev/null || true` pattern this replaced could not tell
# those apart: it swallowed a PCRE-unsupported fatal into an empty result,
# so the guard printed "bead-id-refs: ok" and passed silently instead of
# catching bead-ID refs, on any git build without PCRE. Route every `-P`
# sweep through this helper so that failure surfaces instead.
pcre_grep() {
  local stderr_file rc output
  stderr_file=$(mktemp)
  if output=$(git grep "$@" 2>"$stderr_file"); then
    rc=0
  else
    rc=$?
  fi
  if [ "$rc" -ge 2 ]; then
    echo "bead-id-refs: 'git grep -P' failed (exit $rc) -- this guard requires a git build with PCRE support (git grep --perl-regexp)." >&2
    cat "$stderr_file" >&2
    rm -f "$stderr_file"
    exit 1
  fi
  rm -f "$stderr_file"
  printf '%s' "$output"
}

matches=$(pcre_grep -n -P 'mayor-[a-z0-9]{3,5}(?![a-z0-9])(\.[0-9]+)?' -- . \
  ':!.beads' ':!ai' ':!docs' ':!.github' \
  ':!scripts/test-critical-reviewer-hook.sh' \
  ':!scripts/test-check-bead-id-refs-logic.sh' \
  ':!scripts/check-bead-id-refs.sh' \
  ':!scripts/mayor-tick.sh' ':!scripts/test-mayor-tick-logic.sh' \
  ':!.gitignore')

# scripts/mayor-tick.sh + scripts/test-mayor-tick-logic.sh are skipped above
# (their own name matches the regex), but that must not silently swallow a real
# bead-ID reference in their body content -- re-scan the two files
# match-by-match (not whole-file) and tolerate only the exact known-safe tokens.
MAYOR_TICK_ALLOWED_TOKENS='mayor-(tick|owned|abcd|efgh|aaaa|bbbb|cccc|dddd|abc[1-4])$'
mayor_tick_raw=$(pcre_grep -n -oP 'mayor-[a-z0-9]{3,5}(?![a-z0-9])(\.[0-9]+)?' -- \
  scripts/mayor-tick.sh scripts/test-mayor-tick-logic.sh)
if [ -n "$mayor_tick_raw" ]; then
  mayor_tick_matches=$(printf '%s' "$mayor_tick_raw" | grep -vE ":${MAYOR_TICK_ALLOWED_TOKENS}" || true)
else
  mayor_tick_matches=""
fi
if [ -n "$mayor_tick_matches" ]; then
  matches="${matches:+$matches
}$mayor_tick_matches"
fi

# scripts/test-critical-reviewer-hook.sh is skipped above (its "mayor-abc12"
# fixture is synthetic test input); re-scan match-by-match and tolerate only
# the fixture token.
CRITICAL_REVIEWER_HOOK_ALLOWED_TOKENS='mayor-abc12$'
critical_reviewer_hook_raw=$(pcre_grep -n -oP 'mayor-[a-z0-9]{3,5}(?![a-z0-9])(\.[0-9]+)?' -- \
  scripts/test-critical-reviewer-hook.sh)
if [ -n "$critical_reviewer_hook_raw" ]; then
  critical_reviewer_hook_matches=$(printf '%s' "$critical_reviewer_hook_raw" | grep -vE ":${CRITICAL_REVIEWER_HOOK_ALLOWED_TOKENS}" || true)
else
  critical_reviewer_hook_matches=""
fi
if [ -n "$critical_reviewer_hook_matches" ]; then
  matches="${matches:+$matches
}$critical_reviewer_hook_matches"
fi

# beep's own native `beep-` bead IDs rot the same way `mayor-` ones do. Sweep
# the whole tree for the shape (same base exclusions as the mayor- sweep,
# plus this guard and its own regression test -- both spell out `beep-`
# example tokens to prove the guard works, same reason they're excluded from
# the mayor- sweep above), then filter out beep's fixed crate/VM/binary
# names via the SAME allowlist-then-rescan pattern as
# MAYOR_TICK_ALLOWED_TOKENS above, so only a real bead ID (e.g. beep-xxx,
# beep-yyy) survives to trip this arm.
BEEP_NAME_ALLOWED_TOKENS='beep-(ebpf|smoke|node)$'
beep_raw=$(pcre_grep -n -oP 'beep-[a-z0-9]{3,5}(?![a-z0-9])(\.[0-9]+)?' -- . \
  ':!.beads' ':!ai' ':!docs' ':!.github' \
  ':!scripts/check-bead-id-refs.sh' \
  ':!scripts/test-check-bead-id-refs-logic.sh')
if [ -n "$beep_raw" ]; then
  beep_matches=$(printf '%s' "$beep_raw" | grep -vE ":${BEEP_NAME_ALLOWED_TOKENS}" || true)
else
  beep_matches=""
fi
if [ -n "$beep_matches" ]; then
  matches="${matches:+$matches
}$beep_matches"
fi

if [ -n "$matches" ]; then
  echo "bead-id-refs: found bead-ID reference(s) that will rot once the bead closes:" >&2
  echo "$matches" >&2
  echo "Strip the mayor-XXXXX/beep-XXXXX token -- the context lives in git/PR history instead." >&2
  exit 1
fi

echo "bead-id-refs: ok"
