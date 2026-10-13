#!/usr/bin/env bash
# Forced-fail test for scripts/assert-ebpf-object-stripped.sh. Runs the REAL
# script against ELF objects generated here (tiny hand-built ELF64 + objcopy
# --add-section), so no binary fixtures are committed.
#
# Each reverted-strip shape (line_info present, .rel.BTF* present, CO-RE
# relocs present, .debug_* present) must make the script fail; a clean object
# must pass. Without this, a reverted strip (~104 KB) still passes the size
# ceiling and nothing else notices.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/scripts/assert-ebpf-object-stripped.sh"

objcopy_bin=""
for candidate in llvm-objcopy objcopy; do
  command -v "$candidate" >/dev/null 2>&1 && { objcopy_bin="$candidate"; break; }
done
[ -n "$objcopy_bin" ] || { echo "FAIL: neither llvm-objcopy nor objcopy on PATH" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

PASS=0
FAIL=0
assert() {
  if [ "$2" = ok ]; then PASS=$((PASS + 1)); echo "ok: $1"; else FAIL=$((FAIL + 1)); echo "FAIL: $1" >&2; fi
}

# Empty ELF64 LE relocatable (EM_BPF): null section + .shstrtab only.
base="$tmp/base.o"
{
  printf '\x7fELF\x02\x01\x01\x00\0\0\0\0\0\0\0\0'
  printf '\x01\x00\xf7\x00\x01\x00\x00\x00'
  printf '\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
  printf '\x50\0\0\0\0\0\0\0'
  printf '\0\0\0\0\x40\x00\0\0\0\0\x40\x00\x02\x00\x01\x00'
  printf '\0.shstrtab\0\0\0\0\0\0'
  printf '%064d' 0 | tr 0 '\0'
  printf '\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
  printf '\x40\0\0\0\0\0\0\0\x0b\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
  printf '\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
} > "$base"

# 4-byte-LE helper -> escaped printf string
le32() {
  local i
  for i in 0 8 16 24; do
    printf '%b' "$(printf '\\x%02x' $(($1 >> i & 255)))"
  done
}

# .BTF.ext: 32-byte header (func_info 8 bytes, line_info $1 bytes, core_relo $2 bytes)
btf_ext() {
  local line_len=$1 core_len=$2 f=$3
  {
    printf '\x9f\xeb\x01\x00'
    le32 32
    le32 0
    le32 8
    le32 8
    le32 "$line_len"
    le32 $((8 + line_len))
    le32 "$core_len"
    head -c $((8 + line_len + core_len)) /dev/zero
  } > "$f"
}

# build <name> <line_len> <core_len> [extra objcopy args...]
build() {
  local name=$1 line_len=$2 core_len=$3
  shift 3
  head -c 16 /dev/zero > "$tmp/btf"
  btf_ext "$line_len" "$core_len" "$tmp/ext"
  "$objcopy_bin" --add-section .BTF="$tmp/btf" --add-section .BTF.ext="$tmp/ext" "$@" "$base" "$tmp/$name.o"
}

expect_fail() {
  local label=$1 obj=$2 pat=$3 out
  if out="$(bash "$SCRIPT" "$obj" 2>&1)"; then
    assert "$label (script wrongly passed)" bad
  elif printf '%s' "$out" | grep -q "$pat"; then
    assert "$label" ok
  else
    assert "$label (failed for the wrong reason: $out)" bad
  fi
}

build clean 0 0
if out="$(bash "$SCRIPT" "$tmp/clean.o" 2>&1)"; then
  assert "clean release-shaped object passes" ok
else
  assert "clean release-shaped object passes: $out" bad
fi

build line 24 0
expect_fail "line_info present is rejected (release strip reverted)" "$tmp/line.o" "line_info_len=24"

build core 0 16
expect_fail "core_relo present is rejected (rewrite would drop CO-RE relos)" "$tmp/core.o" "core_relo_len=16"

head -c 8 /dev/zero > "$tmp/rel"
build rel 0 0 --add-section .rel.BTF.ext="$tmp/rel"
expect_fail ".rel.BTF.ext present is rejected (linker-only reloc strip reverted)" "$tmp/rel.o" "BTF relocation sections"

build relb 0 0 --add-section .rel.BTF="$tmp/rel"
expect_fail ".rel.BTF present is rejected" "$tmp/relb.o" "BTF relocation sections"

build dbg 0 0 --add-section .debug_info="$tmp/rel"
expect_fail ".debug_* present is rejected" "$tmp/dbg.o" "debug_"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
