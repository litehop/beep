#!/usr/bin/env bash
# CI assertion that guards build.rs's post-link DWARF strip
# (strip_dwarf_keep_btf) from a silent revert. A future edit that drops or
# breaks that step would silently reintroduce ~270KB of DWARF debug info into
# every embedded beep-ebpf object with no CI signal -- this is that signal.
#
# Checks the object passed as $1:
#   1. zero `.debug_*` sections (what the strip removes)
#   2. `.BTF` AND `.BTF.ext` both present (aya needs them at load time for
#      map + relocation info -- the strip must NOT touch these)
#   3. no `.rel.BTF` / `.rel.BTF.ext` sections, and `.BTF.ext` has
#      line_info_len == 0 and core_relo_len == 0 (release objects only: dev
#      builds keep line_info, so never pass this script a dev object)
#   4. file size under a gross-regression ceiling (post-strip ~107KB measured
#      via a real release build with dual-stack _v4/_v6 hook duplication;
#      128KB leaves headroom for legitimate growth -- the .debug_* check
#      above remains the precise guard, since a genuine DWARF revert
#      reintroduces ~270KB and is caught there regardless of this ceiling)
#
# Prefers `llvm-readelf` (matches the LLVM toolchain that produced the
# object) and falls back to GNU `readelf` (always present on any Linux dev
# image, since building C/Rust needs binutils regardless of readelf's own
# vendor) -- same PATH-then-fallback preference build.rs's
# locate_llvm_objcopy() uses for llvm-objcopy.
set -euo pipefail

object="${1:?usage: $0 <path-to-beep-ebpf-object>}"
[ -f "$object" ] || { echo "FAIL: $object not found" >&2; exit 1; }

readelf_bin=""
for candidate in llvm-readelf readelf; do
  if command -v "$candidate" >/dev/null 2>&1; then
    readelf_bin="$candidate"
    break
  fi
done
[ -n "$readelf_bin" ] || { echo "FAIL: neither llvm-readelf nor readelf found on PATH" >&2; exit 1; }

# `-SW`: one section per line (both GNU readelf and llvm-readelf support it),
# so a name is a single whitespace-delimited token -- no two-line-per-section
# GNU default format to pair up.
sections="$("$readelf_bin" -SW "$object" | sed -n 's/^ *\[[ 0-9]*\] *//p' | awk '{print $1}')"

debug_sections="$(printf '%s\n' "$sections" | grep '^\.debug' || true)"
[ -z "$debug_sections" ] || {
  echo "FAIL: $object has .debug_* sections -- build.rs's DWARF strip regressed:" >&2
  printf '%s\n' "$debug_sections" >&2
  exit 1
}

printf '%s\n' "$sections" | grep -qxF '.BTF' || {
  echo "FAIL: $object is missing .BTF -- aya needs it at load time; strip must not remove it" >&2
  exit 1
}
printf '%s\n' "$sections" | grep -qxF '.BTF.ext' || {
  echo "FAIL: $object is missing .BTF.ext -- aya needs it at load time; strip must not remove it" >&2
  exit 1
}

rel_sections="$(printf '%s\n' "$sections" | grep '^\.rela\?\.BTF' || true)"
[ -z "$rel_sections" ] || {
  echo "FAIL: $object has BTF relocation sections -- build.rs's linker-only reloc strip regressed:" >&2
  printf '%s\n' "$rel_sections" >&2
  exit 1
}

objcopy_bin=""
for candidate in llvm-objcopy objcopy; do
  if command -v "$candidate" >/dev/null 2>&1; then
    objcopy_bin="$candidate"
    break
  fi
done
[ -n "$objcopy_bin" ] || { echo "FAIL: neither llvm-objcopy nor objcopy found on PATH" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
# GNU objcopy needs an output file; llvm-objcopy accepts one too.
"$objcopy_bin" --dump-section .BTF.ext="$tmp/btf_ext" "$object" "$tmp/discard"

# .BTF.ext header (little-endian only): u16 magic 0xeB9F, u8 version, u8 flags,
# u32 hdr_len, then u32 off/len pairs for func_info (@8), line_info (@16),
# core_relo (@24; present only when hdr_len >= 32).
u32_at() {
  local b0 b1 b2 b3
  read -r b0 b1 b2 b3 < <(od -An -tu1 -j "$1" -N 4 "$tmp/btf_ext")
  echo $((b0 | b1 << 8 | b2 << 16 | b3 << 24))
}
[ "$(od -An -tx1 -N 2 "$tmp/btf_ext" | tr -d ' ')" = "9feb" ] || {
  echo "FAIL: $object .BTF.ext magic is not 0xeB9F little-endian" >&2
  exit 1
}
hdr_len="$(u32_at 4)"
[ "$hdr_len" -ge 24 ] || { echo "FAIL: $object .BTF.ext hdr_len $hdr_len too short to hold line_info" >&2; exit 1; }
line_info_len="$(u32_at 20)"
core_relo_len=0
[ "$hdr_len" -lt 32 ] || core_relo_len="$(u32_at 28)"
[ "$line_info_len" -eq 0 ] || {
  echo "FAIL: $object .BTF.ext line_info_len=$line_info_len -- release line_info strip regressed" >&2
  exit 1
}
[ "$core_relo_len" -eq 0 ] || {
  echo "FAIL: $object .BTF.ext core_relo_len=$core_relo_len -- the line_info rewrite must not carry CO-RE relocations" >&2
  exit 1
}

size="$(wc -c < "$object" | tr -d ' ')"
ceiling=$((128 * 1024))
[ "$size" -lt "$ceiling" ] || {
  echo "FAIL: $object is $size bytes, >= ${ceiling}-byte gross-regression ceiling -- DWARF strip likely regressed" >&2
  exit 1
}

echo "PASS: $object is $size bytes, no .debug_* or .rel.BTF* sections, .BTF + .BTF.ext present with no line_info/core_relo"
