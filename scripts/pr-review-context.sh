#!/usr/bin/env bash
# Bundles the PR context a review dispatch needs -- metadata + a diff-only
# view -- into one call, replacing ad hoc `git show <sha> -- <file>`
# (whole-file dumps) plus separate `gh pr view`/`gh pr checks` calls, none
# of which need model judgment to construct -- only the result does.
# `gh pr diff` already returns the changed hunks, not whole files, so this
# wrapper does no git plumbing of its own.
#
# Usage: scripts/pr-review-context.sh <pr-number>
set -euo pipefail

PR="${1:?usage: pr-review-context.sh <pr-number>}"

gh pr view "$PR" \
  --json number,title,body,state,url,baseRefName,headRefName,mergeable,files \
  --jq '"=== PR #\(.number): \(.title) ===\nState: \(.state)  Mergeable: \(.mergeable)\nBase: \(.baseRefName)  Head: \(.headRefName)\nURL: \(.url)\n\n--- Body ---\n\(.body)\n\n--- Changed files (\(.files | length)) ---\n" + ([.files[] | "\(.path)  +\(.additions) -\(.deletions)"] | join("\n"))'

echo
echo "--- Diff ---"
gh pr diff "$PR"
