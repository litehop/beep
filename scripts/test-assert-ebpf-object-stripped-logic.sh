#!/usr/bin/env bash
# Forced-fail test for scripts/assert-ebpf-object-stripped.sh. Runs the REAL
# script against ELF64 objects assembled here in pure bash (GNU objcopy cannot
# read EM_BPF objects; no binary fixtures are committed). Needs llvm-readelf
# or readelf on PATH, like the script itself.
#
# Each reverted-strip shape (line_info present, .rel.BTF* present, CO-RE
# relocs present, .debug_* present) must make the script fail; a clean object
# must pass. Without this, a reverted strip (~104 KB) still passes the size
# ceiling and nothing else notices.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/scripts/assert-ebpf-object-stripped.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

PASS=0
FAIL=0
assert() {
  if [ "$2" = ok ]; then PASS=$((PASS + 1)); echo "ok: $1"; else FAIL=$((FAIL + 1)); echo "FAIL: $1" >&2; fi
}

# le <nbytes> <value>: little-endian integer as raw bytes
le() {
  local i
  for ((i = 0; i < $1; i++)); do
    printf '%b' "$(printf '\\x%02x' $(($2 >> (8 * i) & 255)))"
  done
}

# mkelf <out> [name=file ...]: ELF64 LE EM_BPF relocatable with those PROGBITS sections.
mkelf() {
  local out=$1 spec name file off=64 n=2 strtab='@.shstrtab@' shstr_name=1
  shift
  local -a names=() offs=() sizes=() nameoffs=()
  : > "$tmp/data"
  for spec in "$@"; do
    name=${spec%%=*}
    file=${spec#*=}
    names+=("$name")
    offs+=("$off")
    sizes+=("$(wc -c < "$file" | tr -d ' ')")
    nameoffs+=("${#strtab}")
    strtab+="$name@"
    cat "$file" >> "$tmp/data"
    off=$((off + sizes[${#sizes[@]} - 1]))
    n=$((n + 1))
  done
  local shstr_off=$off shstr_size=${#strtab} shoff
  shoff=$(((shstr_off + shstr_size + 7) / 8 * 8))
  {
    printf '\x7fELF\x02\x01\x01\x00\0\0\0\0\0\0\0\0'
    le 2 1; le 2 247; le 4 1; le 8 0; le 8 0; le 8 "$shoff"
    le 4 0; le 2 64; le 2 0; le 2 0; le 2 64; le 2 "$n"; le 2 $((n - 1))
    cat "$tmp/data"
    printf '%s' "$strtab" | tr '@' '\0'
    head -c $((shoff - shstr_off - shstr_size)) /dev/zero
    head -c 64 /dev/zero
    local i
    for ((i = 0; i < ${#names[@]}; i++)); do
      le 4 "${nameoffs[i]}"; le 4 1; le 8 0; le 8 0; le 8 "${offs[i]}"; le 8 "${sizes[i]}"
      le 4 0; le 4 0; le 8 1; le 8 0
    done
    le 4 "$shstr_name"; le 4 3; le 8 0; le 8 0; le 8 "$shstr_off"; le 8 "$shstr_size"
    le 4 0; le 4 0; le 8 1; le 8 0
  } > "$out"
}

# .BTF.ext: 32-byte header, func_info 8 bytes, then line_info/core_relo payloads.
btf_ext() {
  local line_len=$1 core_len=$2
  {
    printf '\x9f\xeb\x01\x00'
    le 4 32; le 4 0; le 4 8; le 4 8; le 4 "$line_len"; le 4 $((8 + line_len)); le 4 "$core_len"
    head -c $((8 + line_len + core_len)) /dev/zero
  }
}

head -c 16 /dev/zero > "$tmp/btf"
head -c 8 /dev/zero > "$tmp/junk"

# build <name> <line_len> <core_len> [extra name=file ...]
build() {
  local name=$1 line_len=$2 core_len=$3
  shift 3
  btf_ext "$line_len" "$core_len" > "$tmp/ext"
  mkelf "$tmp/$name.o" .BTF="$tmp/btf" .BTF.ext="$tmp/ext" "$@"
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

build rel 0 0 .rel.BTF.ext="$tmp/junk"
expect_fail ".rel.BTF.ext present is rejected (linker-only reloc strip reverted)" "$tmp/rel.o" "BTF relocation sections"

build relb 0 0 .rel.BTF="$tmp/junk"
expect_fail ".rel.BTF present is rejected" "$tmp/relb.o" "BTF relocation sections"

build dbg 0 0 .debug_info="$tmp/junk"
expect_fail ".debug_* present is rejected" "$tmp/dbg.o" "debug_"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
