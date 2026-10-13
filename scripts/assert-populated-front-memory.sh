#!/usr/bin/env bash
# Per-entry guard for the no-prealloc front maps: scripts/assert-ebpf-map-
# memory.sh only sees ~11 smoke entries, so ~1 KB of per-entry cost sits inside
# its 1.15x slack and a doubled per-entry cost would pass. This inserts N
# synthetic rows into FRONT_META and FRONT_ENDPOINTS, re-samples memory, and
# runs the same assertion with the real entry counts, so the per-entry
# constants there are checked at a scale where they dominate. The rows are
# removed on exit (success or failure), before anything else touches the maps.
#
# Key/value sizes come from `bpftool map show` itself, so there is no second
# copy of the layouts. Keys start with 0xa5, which no real front key does (they
# start with a zeroed v4-mapped prefix or an IPv6 address), so they can never
# overwrite a live row.
#
# Usage: scripts/assert-populated-front-memory.sh <pin-dir> [<count>]
set -euo pipefail

PIN_DIR="${1:?usage: $0 <pin-dir> [<count>]}"
COUNT="${2:-1000}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"

hex_key() { # <index> <size>
  local i=$1 size=$2 out n
  out="$(printf 'a5 %02x %02x %02x' $((i & 255)) $(((i >> 8) & 255)) $(((i >> 16) & 255)))"
  for ((n = 4; n < size; n++)); do out+=" 00"; done
  echo "$out"
}

hex_zero() { # <size>
  local out="" n
  for ((n = 0; n < $1; n++)); do out+="00 "; done
  echo "$out"
}

write_batch() { # <verb: update|delete> <map> <out-file>
  local verb=$1 map=$2 out=$3 pin="$PIN_DIR/$2" key_size value_size i zero=""
  key_size=$(bpftool map show pinned "$pin" -j | jq -r .bytes_key)
  value_size=$(bpftool map show pinned "$pin" -j | jq -r .bytes_value)
  [ "$verb" = update ] && zero="$(hex_zero "$value_size")"
  : > "$out"
  for ((i = 1; i <= COUNT; i++)); do
    if [ "$verb" = update ]; then
      echo "map update pinned $pin key hex $(hex_key "$i" "$key_size") value hex $zero" >> "$out"
    else
      echo "map delete pinned $pin key hex $(hex_key "$i" "$key_size")" >> "$out"
    fi
  done
}

cleanup() {
  for map in FRONT_META FRONT_ENDPOINTS; do
    write_batch delete "$map" "$WORK/del-$map" 2>/dev/null || continue
    bpftool batch file "$WORK/del-$map" >/dev/null 2>&1 || true
  done
  rm -rf "$WORK"
}
trap cleanup EXIT

for map in FRONT_META FRONT_ENDPOINTS; do
  write_batch update "$map" "$WORK/add-$map"
  bpftool batch file "$WORK/add-$map" >/dev/null
done

bash "$SCRIPT_DIR/sample-ebpf-memory.sh" once --pin-dir "$PIN_DIR" --out-dir "$WORK/mem" >/dev/null
meta_entries=$(bpftool map dump pinned "$PIN_DIR/FRONT_META" -j | jq length)
endpoint_entries=$(bpftool map dump pinned "$PIN_DIR/FRONT_ENDPOINTS" -j | jq length)
echo "populated: FRONT_META=$meta_entries FRONT_ENDPOINTS=$endpoint_entries entries (+$COUNT synthetic each)"
bash "$SCRIPT_DIR/assert-ebpf-map-memory.sh" "$WORK/mem/ebpf-map-memory.csv" \
  --front-meta-entries "$meta_entries" \
  --front-endpoints-entries "$endpoint_entries"
