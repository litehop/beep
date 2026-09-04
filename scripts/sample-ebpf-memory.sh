#!/usr/bin/env bash
# eBPF map-memory + servicelb loader-RSS sampler.
#
# Standalone: unlike scripts/conformance/sample-run-metrics.sh, this has no
# dependency on a run-all.sh workdir/kubeconfig/VM convention -- only a
# bpffs pin-dir and (optionally) a loader binary name. That's deliberate:
# u7s-servicelb runs today inside the Tier-1 smoke fixture
# (scripts/servicelb/smoke-remote.sh, its own disjoint VM/CI job with no
# apiserver/kubelet involved) and, per Phase-4 gate-2, as a standalone
# loader against a real fleet node -- never colocated with a run-all.sh
# conformance session. This script must run unmodified in all three places.
#
# Map discovery walks the pinned tc-bpf programs under --pin-dir
# (<pin-dir>/*-prog, as attach_and_pin in crates/servicelb/src/main.rs
# names them) via `bpftool prog show pinned <path> --json`, unions their
# `map_ids` (map ids are per-boot -- never hardcode one), and reads each
# map's name/type/max_entries/bytes_memlock via `bpftool map show id <id>
# --json`. This walks only the maps the servicelb programs actually
# reference, not the host's full (and much noisier) `bpftool map show`.
#
# Two CSV outputs, header written once, appended thereafter:
#   ebpf-map-memory.csv  ts,map_id,map_name,map_type,max_entries,bytes_memlock
#                         one row per unioned map per tick.
#   loader-rss.csv        ts,pid,rss_kb
#                         one row per tick, resolved via `pgrep -f
#                         <loader-bin-name>` + `ps -o rss=`.
# ts format matches sample-run-metrics.sh: `date -u +%Y-%m-%dT%H:%M:%SZ`.
#
# Modes:
#   once  --pin-dir <dir> [--loader-bin-name <name>] [--out-dir <dir>]
#         Single snapshot (one row per CSV), then exits. Used by the
#         Tier-1 smoke fixture and its CI job, whose whole live window is
#         under a few seconds -- too short for an interval loop to show a
#         trend, so one snapshot right after attach is the actual ceiling
#         of what's observable there.
#   start --pin-dir <dir> --interval <secs> [--loader-bin-name <name>]
#         [--out-dir <dir>]
#   stop  [--out-dir <dir>]
#         Background interval loop, same pidfile/SIGTERM-then-poll idiom as
#         sample-run-metrics.sh's cmd_start/cmd_stop -- this is the tool a
#         real-node soak measurement (Phase-4 gate-2) needs, where a trend
#         actually exists. `stop` must be passed the same --out-dir as the
#         matching `start` call, since that's where the pidfile lives.
#
# A missing/dead loader process or an empty pin-dir costs one skipped row
# for that tick, never an abort -- same "skip the tick's row, don't abort"
# contract as sample-run-metrics.sh's sample_one_host_process, since a
# monitoring gap must never fail the run it's trying to observe.
set -euo pipefail

SUBCOMMAND="${1:-}"
case "$SUBCOMMAND" in
  once|start|stop) shift ;;
  *)
    echo "usage: $0 <once|start|stop> --pin-dir <dir> [--loader-bin-name <name>] [--out-dir <dir>] [--interval <secs>]" >&2
    exit 1
    ;;
esac

PIN_DIR=""
LOADER_BIN_NAME="u7s-servicelb"
OUT_DIR="$PWD/servicelb-ebpf-memory"
INTERVAL=30

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pin-dir) PIN_DIR="$2"; shift 2 ;;
    --loader-bin-name) LOADER_BIN_NAME="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [ "$SUBCOMMAND" != "stop" ] && [ -z "$PIN_DIR" ]; then
  echo "usage: $0 $SUBCOMMAND --pin-dir <dir> [...] -- missing required --pin-dir" >&2
  exit 1
fi

command -v bpftool >/dev/null || { echo "FAIL: bpftool not found on PATH" >&2; exit 1; }
command -v jq >/dev/null || { echo "FAIL: jq not found on PATH" >&2; exit 1; }

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

PIDFILE="$OUT_DIR/sample-ebpf-memory.pid"
LOGFILE="$OUT_DIR/sample-ebpf-memory.log"
MAP_CSV="$OUT_DIR/ebpf-map-memory.csv"
RSS_CSV="$OUT_DIR/loader-rss.csv"

ensure_csv_headers() {
  [ -f "$MAP_CSV" ] || echo "ts,map_id,map_name,map_type,max_entries,bytes_memlock" > "$MAP_CSV"
  [ -f "$RSS_CSV" ] || echo "ts,pid,rss_kb" > "$RSS_CSV"
}

# Unions map_ids across every pinned prog, deduping via the `seen`
# associative array (local to this call, so dedup never leaks across
# ticks). A pin-dir with no *-prog files yet (loader not started) or a
# bpftool call that fails mid-loop (prog unpinned between glob and query)
# simply yields fewer rows for this tick -- not an error.
sample_maps() {
  local ts="$1" pin_dir="$2"
  local prog json map_json id name type max_entries memlock
  local -A seen=()
  for prog in "$pin_dir"/*-prog; do
    [ -e "$prog" ] || continue
    json="$(bpftool prog show pinned "$prog" --json 2>/dev/null)" || continue
    [ -z "$json" ] && continue
    while IFS= read -r id; do
      [ -z "$id" ] && continue
      [ -n "${seen[$id]:-}" ] && continue
      seen[$id]=1
      map_json="$(bpftool map show id "$id" --json 2>/dev/null)" || continue
      [ -z "$map_json" ] && continue
      name="$(jq -r '.name // ""' <<<"$map_json")"
      type="$(jq -r '.type // ""' <<<"$map_json")"
      max_entries="$(jq -r '.max_entries // 0' <<<"$map_json")"
      memlock="$(jq -r '.bytes_memlock // 0' <<<"$map_json")"
      echo "${ts},${id},${name},${type},${max_entries},${memlock}" >> "$MAP_CSV"
    done < <(jq -r '.map_ids[]? // empty' <<<"$json")
  done
}

sample_loader_rss() {
  local ts="$1" bin_name="$2" pid rss
  pid="$(pgrep -f "$bin_name" 2>/dev/null | head -1)" || true
  [ -z "$pid" ] && return 0
  rss="$(ps -o rss= -p "$pid" 2>/dev/null | tr -d '[:space:]')" || true
  # Process died between resolve and sample -- skip this tick's row rather
  # than aborting the loop (same race sample-run-metrics.sh guards against).
  [ -z "$rss" ] && return 0
  echo "${ts},${pid},${rss}" >> "$RSS_CSV"
}

sample_tick() {
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  sample_maps "$ts" "$PIN_DIR"
  sample_loader_rss "$ts" "$LOADER_BIN_NAME"
}

sampler_loop() {
  # Never abort the whole run's monitoring over one bad tick -- see the
  # header comment's "skip the tick's row, don't abort" contract.
  set +e
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) sampler loop starting (interval=${INTERVAL}s, pin-dir=${PIN_DIR})"
  while true; do
    sample_tick
    sleep "$INTERVAL"
  done
}

cmd_once() {
  ensure_csv_headers
  sample_tick
}

cmd_start() {
  # Idempotent: replace any sampler already running for this out-dir
  # instead of accumulating duplicate background loops.
  if [ -f "$PIDFILE" ]; then
    local old_pid
    old_pid="$(cat "$PIDFILE" 2>/dev/null || true)"
    if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
      echo "sampler already running (PID $old_pid) for $OUT_DIR — stopping it first"
      cmd_stop
    fi
  fi

  ensure_csv_headers

  sampler_loop >>"$LOGFILE" 2>&1 &
  local loop_pid=$!
  disown "$loop_pid"
  echo "$loop_pid" > "$PIDFILE"
  echo "sampler started (PID $loop_pid, interval ${INTERVAL}s) — $OUT_DIR"
}

cmd_stop() {
  if [ ! -f "$PIDFILE" ]; then
    echo "no sampler pidfile at $PIDFILE — nothing to stop"
    return 0
  fi
  local pid
  pid="$(cat "$PIDFILE" 2>/dev/null || true)"
  rm -f "$PIDFILE"
  if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
    echo "sampler PID (from pidfile) already gone"
    return 0
  fi
  echo "stopping sampler (PID $pid) ..."
  kill -TERM "$pid" 2>/dev/null || true
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    kill -0 "$pid" 2>/dev/null || { echo "sampler stopped"; return 0; }
    sleep 0.5
  done
  echo "sampler PID $pid still alive 5s after SIGTERM — sending SIGKILL" >&2
  kill -9 "$pid" 2>/dev/null || true
}

case "$SUBCOMMAND" in
  once) cmd_once ;;
  start) cmd_start ;;
  stop) cmd_stop ;;
esac
