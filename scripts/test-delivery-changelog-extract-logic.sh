#!/usr/bin/env bash
# Unit test for .github/workflows/delivery.yaml's release-notes awk
# extraction (the "Create GitHub Release" step's CHANGELOG.md -> notes-file
# cut). That step only runs on a v* tag push, so CI never otherwise
# exercises it -- v0.3.0 shipped through this exact path, its GitHub Release
# body was rendered by this awk. Extracts the awk block VERBATIM out of
# delivery.yaml by line range and runs it against a fixture CHANGELOG.md, so
# an edit to the awk in delivery.yaml is what this test guards against, not
# a stale copy of it.
#
# Fixture mirrors the real CHANGELOG.md's own mixed heading style (0.3.0 is
# dated, 0.2.0/0.1.0 are not), so both of the awk's two match branches --
# `$0 == "## [" ver "]"` (exact) and `index($0, "## [" ver "] ") == 1`
# (dated prefix) -- are exercised against real-shaped input, plus a decoy
# "## [0x3y0]" section between 0.2.0 and 0.1.0 for case 4.
#
# Four cases:
#   1. Tags 0.3.0/0.2.0/0.1.0 each extract EXACTLY their own section, content
#      stopping before the next "## [" heading.
#   2. The dated heading "## [0.3.0] - <date>" still matches by prefix -- the
#      extractor keys on "## [<ver>]", not an exact-line match.
#   3. An unknown tag yields EMPTY output, so delivery.yaml's
#      --generate-notes fallback kicks in.
#   4. Literal (non-regex) version match: extracting "0.3.0" must not pull in
#      the "## [0x3y0]" decoy section. If the awk were ever rewritten to use
#      `~` regex matching instead of == / index(), "0.3.0"'s dots would act
#      as any-char wildcards and incorrectly match "0x3y0".
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
DELIVERY_YAML="$REPO/.github/workflows/delivery.yaml"

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

# --- Extract the real awk block verbatim out of delivery.yaml ---------------
START_LINE=$(grep -nF 'awk -v ver="$version"' "$DELIVERY_YAML" | head -1 | cut -d: -f1)
END_LINE=$(grep -nF 'CHANGELOG.md > "$notes"' "$DELIVERY_YAML" | head -1 | cut -d: -f1)
if [ -z "$START_LINE" ] || [ -z "$END_LINE" ]; then
  echo "FAIL: could not locate the release-notes awk block in $DELIVERY_YAML (start/end markers no longer match -- update this test alongside that change)"
  exit 1
fi
AWK_BLOCK=$(sed -n "${START_LINE},${END_LINE}p" "$DELIVERY_YAML")

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/CHANGELOG.md" <<'EOF'
# Changelog

## [0.3.0] - 2026-09-21

### Added
- Feature C line

## [0.2.0]

### Added
- Feature B line

## [0x3y0]

### Added
- DECOY content that must never appear in a 0.3.0 or 0.2.0 extraction

## [0.1.0]

### Added
- Feature A line
EOF

# Runs the REAL delivery.yaml awk block against the fixture CHANGELOG.md for
# a given version, exactly as the release step would: `version` and `notes`
# are the same shell variable names the extracted block itself references.
extract() {
  local ver="$1"
  local out="$WORK/notes-out"
  rm -f "$out"
  (
    cd "$WORK"
    version="$ver"
    notes="$out"
    eval "$AWK_BLOCK"
  )
  cat "$out" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# 1. Each real tag extracts exactly its own section.
# ---------------------------------------------------------------------------
ACTUAL_030=$(extract "0.3.0")
ACTUAL_020=$(extract "0.2.0")
ACTUAL_010=$(extract "0.1.0")

EXPECTED_030=$(cat <<'EOF'
## [0.3.0] - 2026-09-21

### Added
- Feature C line
EOF
)
EXPECTED_020=$(cat <<'EOF'
## [0.2.0]

### Added
- Feature B line
EOF
)
EXPECTED_010=$(cat <<'EOF'
## [0.1.0]

### Added
- Feature A line
EOF
)

assert "tag 0.3.0 extracts exactly its own section (stops before '## [0.2.0]')" \
  "$([ "$ACTUAL_030" = "$EXPECTED_030" ] && echo 1 || echo 0)"
assert "tag 0.2.0 extracts exactly its own section (stops before the '## [0x3y0]' decoy)" \
  "$([ "$ACTUAL_020" = "$EXPECTED_020" ] && echo 1 || echo 0)"
assert "tag 0.1.0 extracts exactly its own section (through EOF)" \
  "$([ "$ACTUAL_010" = "$EXPECTED_010" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 2. Dated heading matches by prefix, not exact-line equality.
# ---------------------------------------------------------------------------
FIRST_LINE_030=$(printf '%s\n' "$ACTUAL_030" | head -n1)
assert "dated heading '## [0.3.0] - 2026-09-21' still matches by prefix (extractor keys on '## [<ver>]', not an exact-line match)" \
  "$([ "$FIRST_LINE_030" = "## [0.3.0] - 2026-09-21" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3. Unknown tag yields empty output, so delivery.yaml falls back to
#    --generate-notes instead of shipping a Release with no body.
# ---------------------------------------------------------------------------
ACTUAL_UNKNOWN=$(extract "9.9.9")
assert "unknown tag yields EMPTY output (delivery.yaml's --generate-notes fallback path)" \
  "$([ -z "$ACTUAL_UNKNOWN" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 4. Literal, non-regex version match: "0.3.0"'s dots must not act as
#    any-char wildcards and pull in the "## [0x3y0]" decoy section.
# ---------------------------------------------------------------------------
assert "literal (non-regex) match: extracting '0.3.0' must not include the '## [0x3y0]' decoy section (dots in the version must not act as regex wildcards)" \
  "$(printf '%s' "$ACTUAL_030" | grep -qF 'DECOY' && echo 0 || echo 1)"
assert "...same for '0.2.0', the decoy's other neighbor" \
  "$(printf '%s' "$ACTUAL_020" | grep -qF 'DECOY' && echo 0 || echo 1)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
