#!/usr/bin/env bash
# Fails if a staged new/modified ai/findings/*.md (root only, not legacy/)
# lacks a `Bead: <bead-id>` reference in its first 5 lines.
#
# Findings are deleted from the working tree when their bead closes (see
# "Findings lifecycle" in the workflow docs); the Bead: header is what lets
# a future reader find the commit that introduced a since-deleted finding
# via bead notes. Without it, a finding is unretrievable git bloat the
# moment it's removed.
#
# --diff-filter=AMR covers renames as well as adds/modifies: a plain
# `git mv` of an existing findings file into ai/findings/ without adding a
# Bead: header must not bypass the check.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

new_findings=$(git diff --cached --name-only --diff-filter=AMR -- 'ai/findings/*.md' | grep -v '^ai/findings/legacy/' || true)

fail=0
for f in $new_findings; do
  if ! head -n 5 "$f" | grep -qE '^Bead: '; then
    echo "ERROR: $f missing 'Bead: <bead-id>' reference in first 5 lines" >&2
    fail=1
  fi
done

exit "$fail"
