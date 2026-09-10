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
# beep-ethingress2node -- are `beep-[a-z0-9]{3,5}`-shaped too (the regex's
# 3-5 char cap truncates beep-common/beep-node-a/beep-wg2node/
# beep-ethingress2node to beep-commo/beep-node/beep-wg2no/beep-ethin), so
# a naive `beep-` arm would false-positive on ~100 non-bead tokens across
# tracked source. BEEP_NAME_ALLOWED_TOKENS below filters exactly those known
# fixed names back out, so only a real `beep-` bead ID (e.g. beep-htf) trips
# this guard.
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
#   scripts/check-doc-budget.sh, scripts/test-worktree-hygiene-logic.sh -- cite
#     the ai/prompts/mayor-{bootstrap,dispatch-template}.md doc filenames;
#     "mayor-boots"/"mayor-dispa" match by coincidence. MAYOR_DOC_FILENAME_ALLOWED_TOKENS
#     re-scans these match-by-match.
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

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

matches=$(git grep -n -E 'mayor-[a-z0-9]{3,5}(\.[0-9]+)?' -- . \
  ':!.beads' ':!ai' ':!docs' ':!.github' \
  ':!scripts/test-critical-reviewer-hook.sh' \
  ':!scripts/test-check-bead-id-refs-logic.sh' \
  ':!scripts/check-bead-id-refs.sh' \
  ':!scripts/mayor-tick.sh' ':!scripts/test-mayor-tick-logic.sh' \
  ':!scripts/check-doc-budget.sh' \
  ':!scripts/test-worktree-hygiene-logic.sh' \
  ':!.gitignore' \
  2>/dev/null || true)

# scripts/mayor-tick.sh + scripts/test-mayor-tick-logic.sh are skipped above
# (their own name matches the regex), but that must not silently swallow a real
# bead-ID reference in their body content -- re-scan the two files
# match-by-match (not whole-file) and tolerate only the exact known-safe tokens.
MAYOR_TICK_ALLOWED_TOKENS='mayor-(tick|owned|abcd|efgh|aaaa|bbbb|cccc|dddd|abc[1-4]|boots)$'
mayor_tick_matches=$(git grep -n -oE 'mayor-[a-z0-9]{3,5}(\.[0-9]+)?' -- \
  scripts/mayor-tick.sh scripts/test-mayor-tick-logic.sh 2>/dev/null \
  | grep -vE ":${MAYOR_TICK_ALLOWED_TOKENS}" || true)
if [ -n "$mayor_tick_matches" ]; then
  matches="${matches:+$matches
}$mayor_tick_matches"
fi

# scripts/check-doc-budget.sh + scripts/test-worktree-hygiene-logic.sh are
# skipped above (they cite the ai/prompts/mayor-*.md doc filenames); re-scan
# match-by-match and tolerate only the two known doc-filename fragments.
MAYOR_DOC_FILENAME_ALLOWED_TOKENS='mayor-(dispa|boots)$'
mayor_doc_filename_matches=$(git grep -n -oE 'mayor-[a-z0-9]{3,5}(\.[0-9]+)?' -- \
  scripts/check-doc-budget.sh \
  scripts/test-worktree-hygiene-logic.sh 2>/dev/null \
  | grep -vE ":${MAYOR_DOC_FILENAME_ALLOWED_TOKENS}" || true)
if [ -n "$mayor_doc_filename_matches" ]; then
  matches="${matches:+$matches
}$mayor_doc_filename_matches"
fi

# scripts/test-critical-reviewer-hook.sh is skipped above (its "mayor-abc12"
# fixture is synthetic test input); re-scan match-by-match and tolerate only
# the fixture token.
CRITICAL_REVIEWER_HOOK_ALLOWED_TOKENS='mayor-abc12$'
critical_reviewer_hook_matches=$(git grep -n -oE 'mayor-[a-z0-9]{3,5}(\.[0-9]+)?' -- \
  scripts/test-critical-reviewer-hook.sh 2>/dev/null \
  | grep -vE ":${CRITICAL_REVIEWER_HOOK_ALLOWED_TOKENS}" || true)
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
# MAYOR_TICK_ALLOWED_TOKENS above, so only a real bead ID (e.g. beep-htf,
# beep-vph) survives to trip this arm.
BEEP_NAME_ALLOWED_TOKENS='beep-(ebpf|commo|smoke|node|wg2no|ethin)$'
beep_matches=$(git grep -n -oE 'beep-[a-z0-9]{3,5}(\.[0-9]+)?' -- . \
  ':!.beads' ':!ai' ':!docs' ':!.github' \
  ':!scripts/check-bead-id-refs.sh' \
  ':!scripts/test-check-bead-id-refs-logic.sh' \
  2>/dev/null | grep -vE ":${BEEP_NAME_ALLOWED_TOKENS}" || true)
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
