#!/usr/bin/env bash
# Unit test for scripts/gh-app-review.sh's composition and secret-hygiene.
#
# Exercises the REAL gh-app-review.sh as a subprocess (copied into a scratch
# dir alongside a stub gh-app-token.sh, since the wrapper locates its sibling
# by its own dirname rather than PATH) with `curl` shadowed earlier on PATH
# by a stub that records exactly what it was given and returns canned JSON --
# the same PATH-shadow technique test-gh-app-token-logic.sh uses for curl.
#
# Assertions, each named for what breaks if it regresses:
#   1. Happy path exits 0 and the (stubbed) GitHub API response reaches
#      stdout unchanged.
#   2. The token never appears in curl's argv. This is the one this whole
#      wrapper exists for: if a future edit reverts to
#      `curl -H "Authorization: token $TOKEN"` on the command line, the
#      token becomes visible to `ps` for as long as curl runs.
#   3. ...yet the header IS delivered, via the stdin-fed curl config --
#      proves (2) isn't passing because the request silently lost auth.
#   4. Content-Type is explicit application/json, not curl's
#      data-binary default of form-urlencoded, which GitHub's REST API does
#      not accept for a review payload.
#   5. The review payload piped to the wrapper's stdin reaches curl's request
#      body byte-for-byte.
#   6. A missing PR-number argument exits non-zero with stderr and empty
#      stdout, and curl is never invoked.
#   7. A failing token mint (gh-app-token.sh non-zero) aborts the wrapper
#      before curl ever runs, with empty stdout. A mutation self-check
#      proves this isn't just documenting today's behavior: with `set -e`
#      removed, the same failing stub still lets curl fire with an empty
#      Authorization token -- the plan's Step 5 mint-failure fallback exists
#      precisely because a caller cannot assume this any other way.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/scripts/gh-app-review.sh"

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

# --- scratch dir holding a copy of the REAL wrapper + a stub sibling -------
# gh-app-review.sh resolves gh-app-token.sh by its own dirname, not PATH, so
# the stub has to sit next to a copy of the script under test.
SCRATCH="$WORK/scratch"
mkdir -p "$SCRATCH"
cp "$SCRIPT" "$SCRATCH/gh-app-review.sh"
chmod +x "$SCRATCH/gh-app-review.sh"

export STUB_TOKEN="stub-app-review-token-not-a-real-credential"
cat > "$SCRATCH/gh-app-token.sh" <<'STUBEOF'
#!/usr/bin/env bash
if [ -n "${STUB_TOKEN_FAIL:-}" ]; then
  echo "stub gh-app-token: forced failure for test" >&2
  exit 1
fi
printf '%s\n' "$STUB_TOKEN"
STUBEOF
chmod +x "$SCRATCH/gh-app-token.sh"

# --- curl stub on PATH -------------------------------------------------------
# Records argv (to prove the token isn't there) and the piped stdin config
# (to prove the header and body ARE there via the intended channel), then
# returns canned JSON so the wrapper's stdout pass-through can be checked.
STUBDIR="$WORK/stubbin"
mkdir -p "$STUBDIR"
export CANNED_RESPONSE='{"id":555,"user":{"login":"litehop-reviewer"},"state":"CHANGES_REQUESTED"}'
export CURL_ARGV_CAPTURE="$WORK/curl-argv"
export CURL_STDIN_CAPTURE="$WORK/curl-stdin"
export CURL_BODY_CAPTURE="$WORK/curl-body"
export CURL_CALLED_MARKER="$WORK/curl-called"
cat > "$STUBDIR/curl" <<'STUBEOF'
#!/usr/bin/env bash
touch "$CURL_CALLED_MARKER"
printf '%s\n' "$@" > "$CURL_ARGV_CAPTURE"
CFG=$(cat)
printf '%s' "$CFG" > "$CURL_STDIN_CAPTURE"
BODYPATH=$(printf '%s\n' "$CFG" | sed -n 's/^data-binary = "@\(.*\)"$/\1/p')
if [ -n "$BODYPATH" ] && [ -r "$BODYPATH" ]; then
  cp "$BODYPATH" "$CURL_BODY_CAPTURE"
fi
printf '%s\n' "$CANNED_RESPONSE"
STUBEOF
chmod +x "$STUBDIR/curl"

PAYLOAD='{"body":"## critical-reviewer findings\n\n**Verdict**: needs-changes","event":"REQUEST_CHANGES"}'

# Runs the scratch copy of the wrapper with $1 as the PR number and $2 (or
# PAYLOAD) piped to stdin, curl stubbed via PATH. Sets RUN_OUT/RUN_ERR/RUN_RC.
run_wrapper() {
  local pr="$1" payload="${2:-$PAYLOAD}"
  RUN_OUT=$(printf '%s' "$payload" | PATH="$STUBDIR:$PATH" "$SCRATCH/gh-app-review.sh" "$pr" 2>"$WORK/stderr") \
    && RUN_RC=0 || RUN_RC=$?
  RUN_ERR=$(cat "$WORK/stderr" 2>/dev/null || echo "")
}

# ---------------------------------------------------------------------------
# Happy path, reused by assertions 1-5.
# ---------------------------------------------------------------------------
rm -f "$CURL_ARGV_CAPTURE" "$CURL_STDIN_CAPTURE" "$CURL_BODY_CAPTURE" "$CURL_CALLED_MARKER"
run_wrapper "482"
assert "happy path exits 0" \
  "$([ "$RUN_RC" -eq 0 ] && echo 1 || echo 0)"

# --- 1. stdout pass-through --------------------------------------------------
assert "the (stubbed) GitHub API response reaches the wrapper's stdout unchanged" \
  "$([ "$RUN_OUT" = "$CANNED_RESPONSE" ] && echo 1 || echo 0)"

# --- 2. token never in argv ---------------------------------------------------
assert "the token never appears in curl's argv -- the whole reason this wrapper exists is so \`ps\` cannot observe it while curl runs" \
  "$(! grep -qF "$STUB_TOKEN" "$CURL_ARGV_CAPTURE" && echo 1 || echo 0)"

# --- 3. token IS delivered via stdin config -----------------------------------
assert "...but the Authorization header IS delivered, via curl's stdin-fed config -- proves (2) passing isn't because auth silently went missing" \
  "$(grep -qF "Authorization: token $STUB_TOKEN" "$CURL_STDIN_CAPTURE" && echo 1 || echo 0)"

# --- 4. Content-Type is explicit application/json -----------------------------
assert "Content-Type is explicitly application/json, not curl's data-binary default of form-urlencoded, which GitHub's reviews endpoint rejects" \
  "$(grep -qF 'Content-Type: application/json' "$CURL_STDIN_CAPTURE" && echo 1 || echo 0)"

# --- 5. body round-trips byte for byte -----------------------------------------
assert "the review payload piped to the wrapper's stdin reaches curl's request body byte-for-byte" \
  "$([ "$(cat "$CURL_BODY_CAPTURE" 2>/dev/null)" = "$PAYLOAD" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 6. Missing PR-number argument.
# ---------------------------------------------------------------------------
rm -f "$CURL_CALLED_MARKER"
RUN_OUT=$(printf '%s' "$PAYLOAD" | PATH="$STUBDIR:$PATH" "$SCRATCH/gh-app-review.sh" 2>"$WORK/stderr") \
  && RUN_RC=0 || RUN_RC=$?
RUN_ERR=$(cat "$WORK/stderr" 2>/dev/null || echo "")
assert "a missing PR-number argument exits non-zero with stderr output" \
  "$([ "$RUN_RC" -ne 0 ] && [ -n "$RUN_ERR" ] && echo 1 || echo 0)"
assert "...with empty stdout, and curl is never invoked -- a malformed PR number must not turn into a request against a garbage URL" \
  "$([ -z "$RUN_OUT" ] && [ ! -e "$CURL_CALLED_MARKER" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 7. Token-mint failure must abort before curl runs.
# ---------------------------------------------------------------------------
rm -f "$CURL_CALLED_MARKER"
RUN_OUT=$(printf '%s' "$PAYLOAD" | PATH="$STUBDIR:$PATH" STUB_TOKEN_FAIL=1 "$SCRATCH/gh-app-review.sh" "482" 2>"$WORK/stderr") \
  && RUN_RC=0 || RUN_RC=$?
RUN_ERR=$(cat "$WORK/stderr" 2>/dev/null || echo "")
assert "a failing token mint aborts the wrapper (non-zero exit, empty stdout) before curl ever runs" \
  "$([ "$RUN_RC" -ne 0 ] && [ -z "$RUN_OUT" ] && [ ! -e "$CURL_CALLED_MARKER" ] && echo 1 || echo 0)"

# --- mutation self-check (CLAUDE.md rule 14) ---------------------------------
# Without `set -e`, TOKEN=$(gh-app-token.sh) swallows the stub's failure and
# curl fires anyway with an empty Authorization token -- silently posting an
# unauthenticated request instead of aborting. Proves assertion 7 above would
# actually catch a reverted `set -euo pipefail` line, not just document it.
MUTATED="$WORK/gh-app-review-mutated.sh"
sed 's/^set -euo pipefail$/set +e/' "$SCRATCH/gh-app-review.sh" > "$MUTATED"
if diff -q "$SCRATCH/gh-app-review.sh" "$MUTATED" >/dev/null 2>&1; then
  assert "mutation self-check: the set -euo pipefail line exists to mutate (if this fails, it was reshaped and this suite no longer exercises it)" 0
else
  chmod +x "$MUTATED"
  cp "$SCRATCH/gh-app-token.sh" "$WORK/gh-app-token.sh"
  chmod +x "$WORK/gh-app-token.sh"
  rm -f "$CURL_CALLED_MARKER"
  RUN_OUT=$(printf '%s' "$PAYLOAD" | PATH="$STUBDIR:$PATH" STUB_TOKEN_FAIL=1 "$MUTATED" "482" 2>/dev/null) \
    && RUN_RC=0 || RUN_RC=$?
  assert "mutation self-check: with set -euo pipefail removed, a failing token mint wrongly lets curl fire anyway -- proving assertion 7 would fail if that guard were ever reverted" \
    "$([ -e "$CURL_CALLED_MARKER" ] && echo 1 || echo 0)"
fi

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
