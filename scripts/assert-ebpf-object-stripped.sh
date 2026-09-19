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
#   3. file size under a gross-regression ceiling (post-strip ~107KB measured
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

size="$(wc -c < "$object" | tr -d ' ')"
ceiling=$((128 * 1024))
[ "$size" -lt "$ceiling" ] || {
  echo "FAIL: $object is $size bytes, >= ${ceiling}-byte gross-regression ceiling -- DWARF strip likely regressed" >&2
  exit 1
}

echo "PASS: $object is $size bytes, no .debug_* sections, .BTF + .BTF.ext present"
