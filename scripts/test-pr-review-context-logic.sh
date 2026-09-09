#!/usr/bin/env bash
# Unit test for scripts/pr-review-context.sh.
#
# Stubs `gh` on PATH (same PATH-shadow technique other scripts/test-*.sh
# files use for gh/curl): a canned `pr view --json ...` response with the
# real `--jq` filter argument re-applied via jq for deterministic output,
# and a canned `pr diff` response. No network access, so this runs on the
# CI runner.
#
# Assertions, each named for what breaks if it regresses:
#   1. Metadata (title, state, base/head, changed files with +/- counts)
#      reaches stdout -- the whole point of the wrapper is bundling this
#      into one call instead of a separate `gh pr view`/`gh pr checks`.
#   2. The diff section actually comes from `gh pr diff` (pre-filtered
#      hunks), not from re-implemented git plumbing.
#   3. The script never shells out to `git show` -- the exact whole-file-dump
#      anti-pattern this wrapper replaces; a future edit that reintroduces
#      it must fail this test.
#   4. A missing PR-number argument exits non-zero with stderr and never
#      invokes `gh` at all.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/scripts/pr-review-context.sh"

PASS=0
FAIL=0

assert() {
  local label="$1" ok="$2"
  if [ "$ok" = "1" ]; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label"
    FAIL=$(( FAIL + 1 ))
  fi
}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# --- 3. static guard: the script must never call `git show` -----------------
# The audit's anti-pattern was `git show <sha> -- <file>` whole-file dumps;
# `gh pr diff` already returns pre-filtered hunks, so nothing here should
# ever need git plumbing of its own. Strip comment lines first -- the
# rationale comment above legitimately names "git show" in prose.
assert "the script never invokes \`git show\` (the whole-file-dump anti-pattern this wrapper replaces)" \
  "$(! grep -vE '^\s*#' "$SCRIPT" | grep -q 'git show' && echo 1 || echo 0)"

# --- gh stub on PATH ----------------------------------------------------------
STUBDIR="$WORK/stubbin"
mkdir -p "$STUBDIR"
export GH_CALLED_LOG="$WORK/gh-called.log"
cat > "$STUBDIR/gh" <<'STUBEOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$GH_CALLED_LOG"
if [ "$1" = "pr" ] && [ "$2" = "view" ]; then
  base='{"number":482,"title":"fix: guard the merge path","body":"Fixes a thing.","state":"OPEN","url":"https://github.com/example/repo/pull/482","baseRefName":"main","headRefName":"worker/agent-x","mergeable":"MERGEABLE","files":[{"path":"src/foo.rs","additions":10,"deletions":2},{"path":"src/bar.rs","additions":3,"deletions":0}]}'
  jq_filter=""
  prev=""
  for a in "$@"; do
    [ "$prev" = "--jq" ] && jq_filter="$a"
    prev="$a"
  done
  if [ -n "$jq_filter" ]; then
    printf '%s' "$base" | jq -r "$jq_filter"
  else
    printf '%s' "$base"
  fi
elif [ "$1" = "pr" ] && [ "$2" = "diff" ]; then
  printf 'diff --git a/src/foo.rs b/src/foo.rs\n+added line\n-removed line\n'
else
  echo "unexpected gh invocation: $*" >&2
  exit 1
fi
STUBEOF
chmod +x "$STUBDIR/gh"

run_wrapper() {
  RUN_OUT=$(PATH="$STUBDIR:$PATH" "$SCRIPT" "$@" 2>"$WORK/stderr") && RUN_RC=0 || RUN_RC=$?
  RUN_ERR=$(cat "$WORK/stderr" 2>/dev/null || echo "")
}

# ---------------------------------------------------------------------------
# Happy path.
# ---------------------------------------------------------------------------
rm -f "$GH_CALLED_LOG"
run_wrapper "482"
assert "happy path exits 0" \
  "$([ "$RUN_RC" -eq 0 ] && echo 1 || echo 0)"

# --- 1. metadata bundled in one call ------------------------------------------
assert "PR title, state, base/head, and body reach stdout" \
  "$(printf '%s' "$RUN_OUT" | grep -qF 'PR #482: fix: guard the merge path' \
     && printf '%s' "$RUN_OUT" | grep -qF 'State: OPEN' \
     && printf '%s' "$RUN_OUT" | grep -qF 'Base: main  Head: worker/agent-x' \
     && printf '%s' "$RUN_OUT" | grep -qF 'Fixes a thing.' \
     && echo 1 || echo 0)"
assert "changed files list includes both files with their +/- counts" \
  "$(printf '%s' "$RUN_OUT" | grep -qF 'src/foo.rs  +10 -2' \
     && printf '%s' "$RUN_OUT" | grep -qF 'src/bar.rs  +3 -0' \
     && echo 1 || echo 0)"

# --- 2. diff comes from \`gh pr diff\`, not re-implemented git plumbing -------
assert "the diff section is exactly gh pr diff's (pre-filtered hunks) output" \
  "$(printf '%s' "$RUN_OUT" | grep -qF -- '--- Diff ---' \
     && printf '%s' "$RUN_OUT" | grep -qF '+added line' \
     && echo 1 || echo 0)"
assert "...fetched via \`gh pr diff\`, confirmed by the stub's own call log" \
  "$(grep -qE '^pr diff 482$' "$GH_CALLED_LOG" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 4. Missing PR-number argument.
# ---------------------------------------------------------------------------
rm -f "$GH_CALLED_LOG"
RUN_OUT=$(PATH="$STUBDIR:$PATH" "$SCRIPT" 2>"$WORK/stderr") && RUN_RC=0 || RUN_RC=$?
RUN_ERR=$(cat "$WORK/stderr" 2>/dev/null || echo "")
assert "a missing PR-number argument exits non-zero with stderr output" \
  "$([ "$RUN_RC" -ne 0 ] && [ -n "$RUN_ERR" ] && echo 1 || echo 0)"
assert "...and never invokes gh at all -- a malformed call must not turn into a request against a garbage PR number" \
  "$([ ! -e "$GH_CALLED_LOG" ] && echo 1 || echo 0)"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
