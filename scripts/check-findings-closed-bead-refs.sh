#!/usr/bin/env bash
# Fails if a tracked, non-legacy ai/findings/*.md file references a bead
# that .beads/issues.jsonl (bd's own git-tracked JSONL export) records as
# closed.
#
# Findings are meant to be deleted from the working tree in their bead's
# close commit, with git history as the archive (see "Findings lifecycle"
# in the workflow docs). Nothing previously enforced that step, so this is
# the backstop: a tracked finding whose bead has already closed is exactly
# the drift that step exists to prevent.
#
# Companion to check-findings-bead-refs.sh, which guarantees every non-
# legacy finding HAS a `Bead: <id>` header in its first 5 lines. This
# script assumes that invariant and treats a missing header as a hard
# failure rather than silently skipping the file -- a file this script
# can't attribute to a bead is a file it can't clear either.
#
# Bead-state source: `bd` reads a local Dolt DB that CI never materializes
# (no `bd` binary on the runner, no DB import step in the job this check
# runs in). Rather than probe for `bd` and fall back to a silent pass when
# it's missing -- the exact shape of a prior bug in this script suite, an
# unguarded tool probe under `set -euo pipefail` that aborted the whole
# file silently and looked like a clean run -- this script never invokes
# `bd` at all. It reads .beads/issues.jsonl directly: the JSONL export bd
# itself writes and this repo already tracks in git, so CI sees the exact
# same file a local checkout does, with no extra install step. A bead ID
# absent from that export is NOT treated as closed: absence is "no
# signal", not "safe to assume open" or "safe to assume closed" -- only an
# explicit "status":"closed" record fails a file. The export is refreshed
# at session-wrap commits rather than on every close, so enforcement is
# eventual (the next commit that updates the export after a close) rather
# than immediate -- an accepted tradeoff for never depending on a tool CI
# cannot run, against never enforcing this at all.
#
# Absent-bead-means-no-signal only holds if the export itself is usable.
# An empty, record-free, or syntactically invalid .beads/issues.jsonl would
# otherwise produce the exact same "no match" result as a genuinely absent
# bead ID -- silently passing every finding, including ones citing beads
# that really are closed. So file existence alone is not enough: the
# record-count and parse-validity checks below establish the export is
# usable BEFORE any per-bead absence is allowed to mean "no signal".
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

ISSUES_FILE=".beads/issues.jsonl"
if [ ! -f "$ISSUES_FILE" ]; then
  echo "ERROR: $ISSUES_FILE not found -- cannot determine bead state, refusing to pass" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq not found -- cannot read $ISSUES_FILE, refusing to pass" >&2
  exit 1
fi

if ! record_count=$(jq -s 'length' "$ISSUES_FILE" 2>&1); then
  echo "ERROR: $ISSUES_FILE is not valid JSONL -- cannot determine bead state, refusing to pass" >&2
  echo "$record_count" >&2
  exit 1
fi

if [ "$record_count" -eq 0 ]; then
  echo "ERROR: $ISSUES_FILE contains no bead records -- cannot determine bead state, refusing to pass" >&2
  exit 1
fi

findings=$(git ls-files 'ai/findings/*.md' | grep -v '^ai/findings/legacy/' || true)

fail=0
for f in $findings; do
  # Extract only the leading bead-ID token, stopping before any trailing
  # descriptive text (e.g. a parenthetical naming related beads). A
  # whitespace-stripped whole-line slurp would mangle such a header into a
  # single compound string that jq below would never match against a real
  # record -- silently passing a finding for a bead that IS closed, exactly
  # what this script exists to catch.
  bead_line=$(head -n 5 "$f" | grep -m1 -E '^Bead: ' || true)
  bead_id=$(printf '%s' "$bead_line" | sed -E 's/^Bead: *//' | awk '{print $1}')
  if [ -z "$bead_id" ]; then
    echo "ERROR: $f has no 'Bead: <bead-id>' header -- cannot verify its bead isn't closed" >&2
    fail=1
    continue
  fi

  status=$(jq -r --arg id "$bead_id" 'select(.id == $id) | .status' "$ISSUES_FILE" | tail -n1)
  if [ "$status" = "closed" ]; then
    echo "ERROR: $f references $bead_id, which is closed -- delete the finding (git history is the archive)" >&2
    fail=1
  fi
done

exit "$fail"
