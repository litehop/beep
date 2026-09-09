#!/usr/bin/env bash
# Unit test for scripts/bd-prime-slim.sh's render_slim_prime() transform.
#
# Sources the REAL script and calls its render_slim_prime() function against
# fixture files (not live `bd` state) -- a reimplementation of the
# header/footer split or the index formatting would keep passing even if the
# real script regressed. Fixtures are small and deterministic, unlike the
# live memory bank, so the assertions below are exact-match, not "roughly
# smaller".
#
# Regression this guards: bd-prime-slim.sh replaced `bd prime`'s ~300KB
# output (full memory bodies, re-read on every SessionStart/PreCompact and
# cached across most turns in between) with an index-only form. If the marker
# strings this script splits on ever drift out of sync with bd's actual
# `bd prime --export` template, the slimming would either silently ship the
# full 300KB body again or truncate the command-reference footer -- both
# regressions this test catches without needing a live bd install.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/scripts/bd-prime-slim.sh"

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

# shellcheck source=bd-prime-slim.sh
source "$SCRIPT"

SANDBOX=$(mktemp -d)
trap 'rm -rf "$SANDBOX"' EXIT

LONG_BODY_1="This is the first memory body. It is intentionally long so the truncation logic has something real to cut, well past seventy characters of content."
LONG_BODY_2="Second memory body, also long enough to exceed the default snippet length so we can confirm it too gets truncated with a trailing ellipsis marker."

# ---------------------------------------------------------------------------
# 1. Well-formed `bd prime --export` fixture: header preserved verbatim,
#    memory bodies replaced by a truncated one-line index, footer (session
#    close protocol onward) preserved verbatim, schema_version excluded.
# ---------------------------------------------------------------------------
EXPORT_1="$SANDBOX/export-1.md"
cat > "$EXPORT_1" <<EOF
# Beads Workflow Context

> some header prose

## Persistent Memories (2)

Stored via \`bd remember\`.

### memory-one
$LONG_BODY_1

### memory-two
$LONG_BODY_2


# 🚨 SESSION CLOSE PROTOCOL 🚨

some footer prose that must survive untouched
EOF

MEM_1="$SANDBOX/memories-1.json"
cat > "$MEM_1" <<EOF
{
  "memory-one": $(printf '%s' "$LONG_BODY_1" | jq -Rs .),
  "memory-two": $(printf '%s' "$LONG_BODY_2" | jq -Rs .),
  "schema_version": 1
}
EOF

OUT_1=$(render_slim_prime "$EXPORT_1" "$MEM_1")

assert "header prose before the memories section is preserved verbatim" \
  "$(printf '%s' "$OUT_1" | grep -qF '> some header prose' && echo 1 || echo 0)"
assert "footer (session close protocol onward) is preserved verbatim" \
  "$(printf '%s' "$OUT_1" | grep -qF 'some footer prose that must survive untouched' && echo 1 || echo 0)"
assert "memory count excludes the schema_version metadata key (2, not 3)" \
  "$(printf '%s' "$OUT_1" | grep -qE '^## Persistent Memories \(2\)' && echo 1 || echo 0)"
assert "index lists memory-one as a one-line entry" \
  "$(printf '%s' "$OUT_1" | grep -qE '^- memory-one: ' && echo 1 || echo 0)"
assert "index lists memory-two as a one-line entry" \
  "$(printf '%s' "$OUT_1" | grep -qE '^- memory-two: ' && echo 1 || echo 0)"
assert "the FULL body text is NOT present -- this is the whole point of the index" \
  "$(printf '%s' "$OUT_1" | grep -qF "$LONG_BODY_1" && echo 0 || echo 1)"
assert "schema_version itself never appears as an index entry" \
  "$(printf '%s' "$OUT_1" | grep -qE '^- schema_version: ' && echo 0 || echo 1)"

# ---------------------------------------------------------------------------
# 2. DESC_LEN controls snippet length: a short cap must actually shorten the
#    rendered snippet, proving the cap is wired through to jq and not just a
#    dead variable.
# ---------------------------------------------------------------------------
OUT_SHORT=$(DESC_LEN=10 render_slim_prime "$EXPORT_1" "$MEM_1")
SNIPPET=$(printf '%s' "$OUT_SHORT" | grep -E '^- memory-one: ' | head -1)
assert "DESC_LEN=10 actually shortens the snippet (proves the cap isn't dead code)" \
  "$([ "${#SNIPPET}" -lt 40 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3. bd's default template drifts (marker missing) -> fail loud: pass the
#    real content through UNMODIFIED rather than silently corrupting it
#    (dropping the footer) or silently no-op'ing back to the full 300KB body.
# ---------------------------------------------------------------------------
EXPORT_2="$SANDBOX/export-2-no-marker.md"
printf 'some content with no recognizable bd prime markers at all\n' > "$EXPORT_2"
MEM_2="$SANDBOX/memories-2.json"
printf '{"foo": "bar"}' > "$MEM_2"

OUT_2=$(render_slim_prime "$EXPORT_2" "$MEM_2" 2>"$SANDBOX/stderr-2")
assert "marker-drift fallback passes the original content through unmodified" \
  "$(printf '%s' "$OUT_2" | grep -qF 'some content with no recognizable bd prime markers at all' && echo 1 || echo 0)"
assert "marker-drift fallback warns on stderr instead of failing silently" \
  "$(grep -qF 'marker not found' "$SANDBOX/stderr-2" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 4. SCALE regression: a synthetic ~300KB fixture with the footer marker
#    positioned near the FAR END of the string, matching the one property of
#    a real `bd prime --export` transcript that actually triggers the bug
#    this test guards against: bash 3.2 (stock on macOS) took ~40s on
#    `${var#*pattern}` to find a marker that far into a large string, vs
#    single-digit ms once render_slim_prime() switched to awk. The small
#    fixtures in scenarios 1-3 are too short to ever exercise that path --
#    this is the one that would have caught the regression before review.
# ---------------------------------------------------------------------------
EXPORT_BIG="$SANDBOX/export-big.md"
{
  printf '# Beads Workflow Context\n\n> some header prose\n\n'
  printf '## Persistent Memories (1)\n\nStored via `bd remember`.\n\n'
  printf '### padding-memory\n'
  # ~300KB of body padding between the header and the footer marker -- the
  # exact shape (large content, THEN the marker) that reproduced the bash
  # 3.2 slowdown on the real ~300KB `bd prime --export` output.
  # `|| true`: under `set -o pipefail`, `yes`'s SIGPIPE (141) when `head`
  # closes the pipe early would otherwise be reported as the pipeline's
  # exit status and abort this script under `set -e`.
  yes 'padding padding padding padding padding padding padding padding' | head -n 5000 || true
  printf '\n\n# 🚨 SESSION CLOSE PROTOCOL 🚨\n\nfooter content that must survive\n'
} > "$EXPORT_BIG"

MEM_BIG="$SANDBOX/memories-big.json"
printf '{"padding-memory": "short body", "schema_version": 1}' > "$MEM_BIG"

FIXTURE_BYTES=$(wc -c < "$EXPORT_BIG" | tr -d ' ')
assert "scale fixture is realistically sized (>=300KB, matching live bd prime --export)" \
  "$([ "$FIXTURE_BYTES" -ge 300000 ] && echo 1 || echo 0)"

START_NS=$(date +%s%N)
OUT_BIG=$(render_slim_prime "$EXPORT_BIG" "$MEM_BIG")
END_NS=$(date +%s%N)
ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))

assert "render_slim_prime() on a ~300KB fixture completes well under bd's own per-call latency (<2000ms; regressed to ~40000ms before the awk fix)" \
  "$([ "$ELAPSED_MS" -lt 2000 ] && echo 1 || echo 0)"
assert "the scale fixture's footer still survives the split, not just the timing" \
  "$(printf '%s' "$OUT_BIG" | grep -qF 'footer content that must survive' && echo 1 || echo 0)"
echo "  (render_slim_prime on ${FIXTURE_BYTES}-byte fixture: ${ELAPSED_MS}ms)"

# ---------------------------------------------------------------------------
# 5. MARKER-COLLISION regression: a memory body that itself quotes the
#    footer marker literally (e.g. a memory ABOUT the session-close
#    protocol) must not fool the footer split into firing early. Column
#    position can't disambiguate -- bd renders bodies verbatim, unindented,
#    so a body's copy of the marker lands at the same column as the real
#    one. Only "last occurrence wins" correctly picks the real footer,
#    which always renders after every memory body.
# ---------------------------------------------------------------------------
EXPORT_COLLISION="$SANDBOX/export-collision.md"
cat > "$EXPORT_COLLISION" <<EOF
# Beads Workflow Context

> some header prose

## Persistent Memories (2)

Stored via \`bd remember\`.

### about-session-close
A memory that quotes the marker verbatim:
# 🚨 SESSION CLOSE PROTOCOL 🚨
This line is memory BODY content, not the real footer -- it must not leak
the remaining memory bodies below into the slim index.

### zzz-last-memory
$LONG_BODY_2


# 🚨 SESSION CLOSE PROTOCOL 🚨

real footer prose that must survive
EOF

MEM_COLLISION="$SANDBOX/memories-collision.json"
cat > "$MEM_COLLISION" <<EOF
{
  "about-session-close": "A memory that quotes the marker verbatim:\n# 🚨 SESSION CLOSE PROTOCOL 🚨\nThis line is memory BODY content, not the real footer -- it must not leak the remaining memory bodies below into the slim index.",
  "zzz-last-memory": $(printf '%s' "$LONG_BODY_2" | jq -Rs .),
  "schema_version": 1
}
EOF

OUT_COLLISION=$(render_slim_prime "$EXPORT_COLLISION" "$MEM_COLLISION")
OUT_COLLISION_BYTES=$(printf '%s' "$OUT_COLLISION" | wc -c | tr -d ' ')

assert "a memory body quoting the footer marker does NOT trigger an early split (real footer prose still present)" \
  "$(printf '%s' "$OUT_COLLISION" | grep -qF 'real footer prose that must survive' && echo 1 || echo 0)"
assert "zzz-last-memory's full body is NOT leaked -- proves the split didn't fire at the body's fake marker" \
  "$(printf '%s' "$OUT_COLLISION" | grep -qF "$LONG_BODY_2" && echo 0 || echo 1)"
assert "zzz-last-memory still appears as a truncated index entry, same as any other memory" \
  "$(printf '%s' "$OUT_COLLISION" | grep -qE '^- zzz-last-memory: ' && echo 1 || echo 0)"
assert "marker-collision fixture stays well under the 50KB slim-output ceiling (proves no leak-driven bloat)" \
  "$([ "$OUT_COLLISION_BYTES" -lt 51200 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
