#!/usr/bin/env bash
# Unit test for scripts/gh-app-token.sh's JWT-minting and fail-loud guards.
#
# CI has no real litehop-reviewer App key, so this test generates a
# throwaway RSA key with openssl genrsa and shadows curl with a stub earlier
# on PATH that captures the Authorization header GitHub would have received
# and returns canned installation/access-token JSON -- exercising the REAL
# script as a subprocess, not a reimplementation of its JWT-building logic.
# This is the same PATH-shadow-a-binary technique scripts/test-critical-
# reviewer-hook.sh already uses for `gh` (the plan's cited precedent,
# test-check-doc-budget-logic.sh, does no curl/binary stubbing at all -- it
# exercises git directly, so this file establishes the pattern for curl
# rather than following an existing one).
#
# Five assertions, each named for what breaks if it regresses:
#   1. The minted JWT verifies against the throwaway key's public half.
#   2. base64url encoding contains no '+', '/', or '='.
#   3. exp - iat <= 600 and iat < now (GitHub's 10-minute JWT cap).
#   4. A missing APP_ID or unreadable key file exits non-zero with stderr
#      output AND EMPTY STDOUT. A mutation self-check proves this actually
#      matters: with the ${VAR:?} guard softened to a silent default, the
#      same stubbed backend (which never validates the JWT's issuer) happily
#      returns a token anyway -- exactly the silent-empty-token bug that
#      would make GH_TOKEN="" fall back to the operator's own gh credentials.
#   4b. The same non-zero/empty-stdout guarantee holds against realistic
#      malformed mint-response bodies too (missing .token, null, empty
#      string), not just a bad local precondition -- proven against the
#      curl stub's overridable response body, not assumed.
#   5. stdout is exactly one line, the token -- the caller does
#      GH_TOKEN=$(scripts/gh-app-token.sh), so any stray diagnostic line on
#      stdout poisons the token.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/scripts/gh-app-token.sh"

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

# --- Throwaway RSA key, never the real App's --------------------------------
KEY="$WORK/throwaway.pem"
PUB="$WORK/throwaway.pub.pem"
openssl genrsa -out "$KEY" 2048 >/dev/null 2>&1
openssl rsa -in "$KEY" -pubout -out "$PUB" >/dev/null 2>&1

# --- curl stub ---------------------------------------------------------------
# Captures the Authorization header curl was given and returns canned JSON
# depending on which of the script's two calls this is (GET installation
# lookup vs POST access-token mint, distinguished by -X POST). Never
# validates the JWT it receives -- that asymmetry is what the assertion-4
# mutation self-check below relies on to prove the ${VAR:?} guards, not this
# stub, are what stop a silently-empty issuer from still yielding a token.
#
# The real script sends Authorization via a stdin-fed `-K -` config file
# (never as a `-H` argv, so it never shows up in `ps`), so this stub reads
# the header out of its own stdin rather than out of "$@" -- AUTH_CAPTURE
# and STUB_TOKEN are exported (not heredoc-interpolated) so the stub, a
# separate process, can read them at runtime without fighting heredoc
# quoting rules to embed a literal '"' in the generated script text.
# STUB_TOKEN_BODY lets a caller override the POST response body (default
# unset -> the normal {"token":...} shape) to exercise malformed-response
# handling.
export STUB_TOKEN="test-stub-token-not-a-real-credential"
STUBDIR="$WORK/stubbin"
mkdir -p "$STUBDIR"
export AUTH_CAPTURE="$WORK/last-auth-header"
cat > "$STUBDIR/curl" <<'STUBEOF'
#!/usr/bin/env bash
method="GET"
prev=""
for arg in "$@"; do
  if [ "$prev" = "-X" ]; then method="$arg"; fi
  prev="$arg"
done
while IFS= read -r line; do
  case "$line" in
    'header = "Authorization: '*)
      hdr="${line#header = \"}"
      hdr="${hdr%\"}"
      printf '%s' "$hdr" > "$AUTH_CAPTURE"
      ;;
  esac
done
if [ "$method" = "POST" ]; then
  if [ -n "${STUB_TOKEN_BODY:-}" ]; then
    printf '%s\n' "$STUB_TOKEN_BODY"
  else
    printf '{"token":"%s"}\n' "$STUB_TOKEN"
  fi
else
  printf '{"id":999123}\n'
fi
STUBEOF
chmod +x "$STUBDIR/curl"

# Runs $3 (default: the real script) with BEEP_REVIEWER_APP_ID=$1 (unset
# entirely if empty) and BEEP_REVIEWER_APP_KEY=$2, curl shadowed by the stub
# above. Always overrides both vars explicitly (never relies on inherited
# ambient BEEP_REVIEWER_APP_ID/KEY, which this very test's own operator
# environment may have set) so results are deterministic regardless of the
# host running it. Sets RUN_OUT/RUN_ERR/RUN_RC.
run_script() {
  local app_id="$1" key_path="$2" script="${3:-$SCRIPT}"
  if [ -z "$app_id" ]; then
    RUN_OUT=$(env -u BEEP_REVIEWER_APP_ID BEEP_REVIEWER_APP_KEY="$key_path" \
      PATH="$STUBDIR:$PATH" bash "$script" 2>"$WORK/stderr") && RUN_RC=0 || RUN_RC=$?
  else
    RUN_OUT=$(BEEP_REVIEWER_APP_ID="$app_id" BEEP_REVIEWER_APP_KEY="$key_path" \
      PATH="$STUBDIR:$PATH" bash "$script" 2>"$WORK/stderr") && RUN_RC=0 || RUN_RC=$?
  fi
  RUN_ERR=$(cat "$WORK/stderr" 2>/dev/null || echo "")
}

# base64url (possibly unpadded) -> raw bytes on stdout.
b64url_decode() {
  local s="$1" slash="/"
  # Substituting a literal "/" via ${s//_/\/} keeps the backslash on bash
  # 3.2 (macOS's system bash) instead of escaping the delimiter -- routing
  # the replacement through a variable sidesteps that quirk on every bash.
  s="${s//-/+}"; s="${s//_/$slash}"
  case $(( ${#s} % 4 )) in
    2) s="${s}==" ;;
    3) s="${s}=" ;;
  esac
  printf '%s' "$s" | openssl base64 -A -d
}

# ---------------------------------------------------------------------------
# Happy path run, reused by assertions 1, 2, 3, 5.
# ---------------------------------------------------------------------------
rm -f "$AUTH_CAPTURE"
run_script "424242" "$KEY"
assert "happy path (valid app id + readable key) mints and prints a token" \
  "$([ "$RUN_RC" -eq 0 ] && echo 1 || echo 0)"

CAPTURED_HEADER=$(cat "$AUTH_CAPTURE" 2>/dev/null || echo "")
JWT="${CAPTURED_HEADER#Authorization: Bearer }"
JWT_HEADER_B64="${JWT%%.*}"
JWT_REST="${JWT#*.}"
JWT_PAYLOAD_B64="${JWT_REST%%.*}"
JWT_SIG_B64="${JWT_REST##*.}"

# --- 1. signature verifies against the throwaway public key -----------------
b64url_decode "$JWT_SIG_B64" > "$WORK/sig.bin"
printf '%s.%s' "$JWT_HEADER_B64" "$JWT_PAYLOAD_B64" > "$WORK/signing-input"
VERIFY_OK=0
openssl dgst -sha256 -verify "$PUB" -signature "$WORK/sig.bin" "$WORK/signing-input" \
  >/dev/null 2>&1 && VERIFY_OK=1
assert "the minted JWT's signature verifies against the throwaway key's public half (fails if the signing input or encoding regresses)" \
  "$VERIFY_OK"

# --- 2. base64url has no +, /, = --------------------------------------------
NO_PLUS_SLASH_EQ=1
case "$JWT_HEADER_B64$JWT_PAYLOAD_B64$JWT_SIG_B64" in
  *[+/=]*) NO_PLUS_SLASH_EQ=0 ;;
esac
assert "the JWT's base64url segments contain none of '+', '/', '=' (a plain-base64 regression yields an opaque GitHub 401 that is very hard to diagnose in production)" \
  "$NO_PLUS_SLASH_EQ"

# --- 3. exp - iat <= 600 and iat < now --------------------------------------
PAYLOAD_JSON=$(b64url_decode "$JWT_PAYLOAD_B64")
IAT=$(printf '%s' "$PAYLOAD_JSON" | jq -r '.iat')
EXP=$(printf '%s' "$PAYLOAD_JSON" | jq -r '.exp')
NOW=$(date +%s)
assert "exp - iat stays within GitHub's 10-minute JWT cap (<= 600s) -- GitHub rejects a longer-lived JWT outright" \
  "$([ $(( EXP - IAT )) -le 600 ] && echo 1 || echo 0)"
assert "iat is backdated to before now, tolerating clock skew -- without this the failure is intermittent and clock-dependent" \
  "$([ "$IAT" -lt "$NOW" ] && echo 1 || echo 0)"

# --- 5. stdout is exactly one line, the token -------------------------------
LINE_COUNT=$(printf '%s\n' "$RUN_OUT" | wc -l | tr -d ' ')
assert "stdout is exactly one line -- the caller does GH_TOKEN=\$(scripts/gh-app-token.sh), so a stray diagnostic line would poison the token" \
  "$([ "$LINE_COUNT" = "1" ] && echo 1 || echo 0)"
assert "...and that one line is exactly the token the (stubbed) GitHub API returned" \
  "$([ "$RUN_OUT" = "$STUB_TOKEN" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 4. Missing APP_ID / unreadable key -> non-zero exit, stderr output, EMPTY
#    stdout. This is the important one: a silently-empty token here would
#    make GH_TOKEN="" fall back to the operator's own gh credentials, and the
#    review would still post -- so nothing would look wrong.
# ---------------------------------------------------------------------------
run_script "" "$KEY"
assert "missing BEEP_REVIEWER_APP_ID exits non-zero instead of proceeding with an empty issuer" \
  "$([ "$RUN_RC" -ne 0 ] && echo 1 || echo 0)"
assert "...with stderr output naming the problem" \
  "$([ -n "$RUN_ERR" ] && echo 1 || echo 0)"
assert "...and, critically, EMPTY stdout -- never a token that would let GH_TOKEN=\"\$(...)\" silently fall back to the operator's own gh credentials" \
  "$([ -z "$RUN_OUT" ] && echo 1 || echo 0)"

run_script "424242" "$WORK/does-not-exist.pem"
assert "an unreadable key file exits non-zero instead of feeding garbage into openssl dgst -sign" \
  "$([ "$RUN_RC" -ne 0 ] && echo 1 || echo 0)"
assert "...with stderr output naming the problem" \
  "$([ -n "$RUN_ERR" ] && echo 1 || echo 0)"
assert "...and, critically, EMPTY stdout" \
  "$([ -z "$RUN_OUT" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 4b. Realistic malformed mint-response shapes. Assertion 4 above only
#    proves the ${VAR:?} guards fire on a bad LOCAL precondition; it never
#    exercises what happens if GitHub's own access-token endpoint returns a
#    200 whose body carries no usable token -- a missing key, an explicit
#    null, or an empty string, all shapes a real API edge case could
#    plausibly produce. Each must still exit non-zero with empty stdout,
#    same as assertion 4, or GH_TOKEN="$(...)" silently falls back to the
#    operator's own gh credentials with no visible error.
# ---------------------------------------------------------------------------
for MALFORMED_BODY in '{}' '{"token":null}' '{"token":""}'; do
  STUB_TOKEN_BODY="$MALFORMED_BODY" run_script "424242" "$KEY"
  assert "a mint response body of $MALFORMED_BODY exits non-zero instead of yielding an unusable token" \
    "$([ "$RUN_RC" -ne 0 ] && echo 1 || echo 0)"
  assert "...and, critically, EMPTY stdout for body $MALFORMED_BODY" \
    "$([ -z "$RUN_OUT" ] && echo 1 || echo 0)"
done

# ---------------------------------------------------------------------------
# Mutation self-check (CLAUDE.md rule 14): prove the two assertions above
# would actually catch a reverted guard, not just document today's behavior.
# With ${VAR:?msg} softened to ${VAR:-} (silent empty default instead of
# abort), the SAME stubbed curl backend -- which never validates the JWT's
# issuer -- happily returns a token anyway.
# ---------------------------------------------------------------------------
MUTATED="$WORK/gh-app-token-mutated.sh"
sed -E 's/\$\{(BEEP_REVIEWER_APP_(ID|KEY)):\?[^}]*\}/${\1:-}/' "$SCRIPT" > "$MUTATED"
if diff -q "$SCRIPT" "$MUTATED" >/dev/null 2>&1; then
  assert "mutation self-check: the \${VAR:?} guards exist in the script to mutate (if this fails, they were reshaped and this suite no longer exercises them)" 0
else
  run_script "" "$KEY" "$MUTATED"
  assert "mutation self-check: with the \${BEEP_REVIEWER_APP_ID:?} guard softened to a silent default, a missing APP_ID wrongly still yields a token -- proving the assertion-4 checks above would fail if this guard were ever reverted, silently reintroducing the self-review-fallback bug" \
    "$([ "$RUN_RC" -eq 0 ] && [ -n "$RUN_OUT" ] && echo 1 || echo 0)"
fi

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
