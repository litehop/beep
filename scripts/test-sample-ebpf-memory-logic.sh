#!/usr/bin/env bash
# Unit test for scripts/servicelb/sample-ebpf-memory.sh (+ its CI sibling
# scripts/servicelb/assert-ebpf-map-memory.sh).
#
# Exercises the REAL scripts as subprocesses, mirroring
# scripts/conformance/test-sample-run-metrics-logic.sh's own approach for the
# exact sibling this script mirrors: invoking the real CLI is both simpler
# and more faithful than duplicating its body into the test.
#
# Covers the failure modes PR #1568's review flagged as untested:
#
#   1. map-id union/dedup — a map pinned by two different progs (a real
#      shape: VIP_MAP/CONFIG are referenced by more than one hook) must
#      appear exactly once in the tick's CSV rows, not once per prog.
#   2. skip-on-broken-prog-pin — one prog whose pin is broken (unpinned
#      between glob and query, or a bpftool bug) must not abort the whole
#      tick; the other progs' maps still get sampled and the CSV row for the
#      just-attached loader isn't lost over one bad pin.
#   3. pidfile idempotency — `stop` on a pin-dir that was never started (no
#      pidfile) and `stop` on a stale pidfile (process already dead) are
#      both no-ops that exit 0, so a caller's teardown never has to guess
#      whether a sampler is actually running before stopping it.
#   4. CSV header-once — two `once` calls into the same --out-dir append one
#      data row each, never a second header line (a repeated snapshot must
#      stay parseable by a single-header CSV reader).
#   5. assert-ebpf-map-memory.sh — the CI gate this whole family of scripts
#      feeds: a single-tick CSV with the exact 5 known maps passes; one that
#      silently dropped a map (a "4 of 5 found" discovery regression) is
#      caught, not averaged into a smaller-but-still-passing byte sum. This
#      directly replicates PR #1568's critical-review repro (a constructed
#      5-then-4-map CSV that the OLD tick-count-inference logic silently
#      summed instead of rejecting).
#
# A stub `bpftool` on PATH stands in for the real kernel tool (unavailable
# outside Linux + a loaded eBPF program) — real `jq` is used unmodified,
# since it needs no kernel state to parse the stub's fixed JSON bodies.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$REPO/scripts/servicelb/sample-ebpf-memory.sh"
ASSERT_SCRIPT="$REPO/scripts/servicelb/assert-ebpf-map-memory.sh"

PASS=0
FAIL=0
TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_TEST"' EXIT

assert_true() {
  local label="$1" cond="$2"
  if [ "$cond" = "0" ]; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label"
    FAIL=$(( FAIL + 1 ))
  fi
}

assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label — expected '$expected', got '$actual'"
    FAIL=$(( FAIL + 1 ))
  fi
}

# ---------------------------------------------------------------------------
# Stub bpftool: `prog show pinned <path> --json` keys off the pinned file's
# basename (the real bpftool would key off actual kernel prog state; the
# pinned FILE stands in for that here, same "the file's identity is the only
# thing that matters" idiom sample-run-metrics-logic.sh's stub kubectl uses).
# `map show id <id> --json` keys off the numeric id. Any other invocation
# (including the always-broken "broken-prog" pin) fails, standing in for a
# prog unpinned between glob and query or a transient bpftool error.
# ---------------------------------------------------------------------------
STUBDIR="$TMPDIR_TEST/stubbin"
mkdir -p "$STUBDIR"
cat > "$STUBDIR/bpftool" <<'STUB'
#!/usr/bin/env bash
case "$1 $2 $3" in
  "prog show pinned")
    case "$(basename "$4")" in
      uplink_ingress-prog) echo '{"map_ids":[10,11]}' ;;
      geneve_ingress-prog) echo '{"map_ids":[11,12]}' ;;
      *) exit 1 ;;
    esac
    ;;
  "map show id")
    case "$4" in
      10) echo '{"name":"VIP_MAP","type":"hash","max_entries":16,"bytes_memlock":4096}' ;;
      11) echo '{"name":"CONFIG","type":"array","max_entries":1,"bytes_memlock":512}' ;;
      12) echo '{"name":"TARGET_PORTS","type":"hash","max_entries":32,"bytes_memlock":8192}' ;;
      *) exit 1 ;;
    esac
    ;;
  *) exit 1 ;;
esac
STUB
chmod +x "$STUBDIR/bpftool"
export PATH="$STUBDIR:$PATH"

# ===========================================================================
# 1. Map-id union/dedup: two pinned progs share map 11 — it must appear in
#    exactly one row of the tick's CSV, not two.
# ===========================================================================
PIN_DIR1="$TMPDIR_TEST/pindir1"
mkdir -p "$PIN_DIR1"
touch "$PIN_DIR1/uplink_ingress-prog" "$PIN_DIR1/geneve_ingress-prog"
OUT1="$TMPDIR_TEST/out1"
bash "$SCRIPT" once --pin-dir "$PIN_DIR1" --out-dir "$OUT1"

CSV1="$OUT1/ebpf-map-memory.csv"
ROWS1="$(awk -F, 'NR>1' "$CSV1" | wc -l | tr -d ' ')"
assert_eq "union of two progs' map_ids yields exactly 3 rows (10, 11, 12), not 4 — a naive per-prog loop with no dedup would double-count map 11" "3" "$ROWS1"

COUNT_MAP11="$(awk -F, '$2==11' "$CSV1" | wc -l | tr -d ' ')"
assert_eq "map 11 (shared by both progs) appears in exactly one row — a caller summing bytes_memlock per map would double-count it otherwise" "1" "$COUNT_MAP11"

# ===========================================================================
# 2. Skip-on-broken-prog-pin: one prog's pin is broken (bpftool fails for
#    it) — the tick must still sample the OTHER pinned prog's maps, and the
#    whole `once` invocation must still exit 0. A monitoring gap on one prog
#    must never fail the tick, let alone the smoke fixture it observes.
# ===========================================================================
PIN_DIR2="$TMPDIR_TEST/pindir2"
mkdir -p "$PIN_DIR2"
touch "$PIN_DIR2/uplink_ingress-prog" "$PIN_DIR2/broken-prog"
OUT2="$TMPDIR_TEST/out2"
set +e
bash "$SCRIPT" once --pin-dir "$PIN_DIR2" --out-dir "$OUT2"
ONCE2_EXIT=$?
set -e
assert_true "once exits 0 despite one broken pinned prog in the pin-dir" "$ONCE2_EXIT"

CSV2="$OUT2/ebpf-map-memory.csv"
GOOD_ROWS2="$(awk -F, 'NR>1' "$CSV2" | wc -l | tr -d ' ')"
assert_eq "the good prog's 2 maps (10, 11) are still sampled — one bad pin doesn't blank out the whole tick" "2" "$GOOD_ROWS2"

# ===========================================================================
# 3. Pidfile idempotency: `stop` on a pin-dir that was never started, and on
#    a stale pidfile pointing at an already-dead PID, are both no-ops.
#    run-all.sh-style callers must be able to call stop unconditionally.
# ===========================================================================
OUT3="$TMPDIR_TEST/out3"
mkdir -p "$OUT3"
set +e
STOP_OUT_MISSING="$(bash "$SCRIPT" stop --out-dir "$OUT3" 2>&1)"
STOP_EXIT_MISSING=$?
set -e
assert_true "stop on an out-dir with no pidfile at all exits 0" "$STOP_EXIT_MISSING"
case "$STOP_OUT_MISSING" in
  *"nothing to stop"*) echo "PASS: stop reports nothing-to-stop rather than a silent no-op"; PASS=$(( PASS + 1 )) ;;
  *) echo "FAIL: stop's missing-pidfile message changed — got: $STOP_OUT_MISSING"; FAIL=$(( FAIL + 1 )) ;;
esac

# A real, short-lived process stands in for a sampler loop that already died
# on its own (crash, OOM-kill, node reboot) — its pidfile is stale, not
# absent, exercising the other half of cmd_stop's guard.
( sleep 0.01 ) &
DEAD_PID=$!
wait "$DEAD_PID" 2>/dev/null || true
sleep 0.2
echo "$DEAD_PID" > "$OUT3/sample-ebpf-memory.pid"
set +e
STOP_OUT_STALE="$(bash "$SCRIPT" stop --out-dir "$OUT3" 2>&1)"
STOP_EXIT_STALE=$?
set -e
assert_true "stop on a stale pidfile (PID already dead) exits 0 — matches: $STOP_OUT_STALE" "$STOP_EXIT_STALE"
assert_true "stop removes the stale pidfile so a future start doesn't see a phantom sampler" "$( [ -f "$OUT3/sample-ebpf-memory.pid" ] && echo 1 || echo 0 )"

# ===========================================================================
# 4. CSV header-once: two `once` calls into the same --out-dir must append
#    exactly one data row each, never a second header line.
# ===========================================================================
PIN_DIR4="$TMPDIR_TEST/pindir4"
mkdir -p "$PIN_DIR4"
touch "$PIN_DIR4/uplink_ingress-prog"
OUT4="$TMPDIR_TEST/out4"
bash "$SCRIPT" once --pin-dir "$PIN_DIR4" --out-dir "$OUT4"
bash "$SCRIPT" once --pin-dir "$PIN_DIR4" --out-dir "$OUT4"

CSV4="$OUT4/ebpf-map-memory.csv"
HEADER_COUNT4="$(grep -c '^ts,map_id,map_name,map_type,max_entries,bytes_memlock$' "$CSV4")"
assert_eq "two once calls into the same out-dir write the header exactly once" "1" "$HEADER_COUNT4"
DATA_ROWS4="$(awk -F, 'NR>1' "$CSV4" | wc -l | tr -d ' ')"
assert_eq "two once calls append 2 ticks x 2 maps (uplink_ingress-prog's map_ids 10, 11) = 4 data rows" "4" "$DATA_ROWS4"

RSS_HEADER_COUNT4="$(grep -c '^ts,pid,rss_kb$' "$OUT4/loader-rss.csv")"
assert_eq "loader-rss.csv also writes its header exactly once across two once calls" "1" "$RSS_HEADER_COUNT4"

# ===========================================================================
# 5. assert-ebpf-map-memory.sh: the CI gate. A correct single-tick 5-map CSV
#    passes; a single-tick CSV missing one map (the real-world shape of "map
#    discovery silently breaks and finds 4 of 5 maps") is caught. This is
#    fix (2)'s actual mechanism: the CI job now feeds this script a FRESH,
#    single-`once`-call CSV instead of extracting "the latest tick" out of a
#    multi-tick file, so the ambiguity PR #1568's review found (a
#    constructed 5-then-4-map CSV silently summing to a plausible non-zero
#    total instead of surfacing the drop) cannot arise for the real CI input
#    shape. This block proves both that (a) it accepts what the real
#    sampler produces and (b) even the OLD ambiguous multi-tick shape, fed
#    to it anyway, is rejected rather than silently passed.
# ===========================================================================
GOOD_CSV="$TMPDIR_TEST/good.csv"
{
  echo "ts,map_id,map_name,map_type,max_entries,bytes_memlock"
  echo "2026-09-05T00:00:00Z,189,VIP_MAP,hash,16,4096"
  echo "2026-09-05T00:00:00Z,190,CONFIG,array,1,512"
  echo "2026-09-05T00:00:00Z,191,REV_FLOW,hash,64,8192"
  echo "2026-09-05T00:00:00Z,192,TARGET_PORTS,hash,32,4096"
  echo "2026-09-05T00:00:00Z,193,FWD_FLOW,hash,64,4096"
} > "$GOOD_CSV"
set +e
bash "$ASSERT_SCRIPT" "$GOOD_CSV" >/dev/null 2>&1
GOOD_EXIT=$?
set -e
assert_true "a correct single-tick CSV with all 5 known maps passes assert-ebpf-map-memory.sh" "$GOOD_EXIT"

# A single tick that dropped TARGET_PORTS — the actual shape a "4 of 5 maps
# found" discovery regression produces against the fixed CI invocation.
DROPPED_CSV="$TMPDIR_TEST/dropped.csv"
{
  echo "ts,map_id,map_name,map_type,max_entries,bytes_memlock"
  echo "2026-09-05T00:00:00Z,189,VIP_MAP,hash,16,4096"
  echo "2026-09-05T00:00:00Z,190,CONFIG,array,1,512"
  echo "2026-09-05T00:00:00Z,191,REV_FLOW,hash,64,8192"
  echo "2026-09-05T00:00:00Z,193,FWD_FLOW,hash,64,4096"
} > "$DROPPED_CSV"
set +e
DROPPED_OUT="$(bash "$ASSERT_SCRIPT" "$DROPPED_CSV" 2>&1)"
DROPPED_EXIT=$?
set -e
if [ "$DROPPED_EXIT" -ne 0 ]; then
  echo "PASS: a single-tick CSV missing one map (4 of 5) is rejected, not silently summed into a smaller passing total — matches: $DROPPED_OUT"
  PASS=$(( PASS + 1 ))
else
  echo "FAIL: a 4-of-5-map CSV must not pass — got exit 0: $DROPPED_OUT"
  FAIL=$(( FAIL + 1 ))
fi

# The reviewer's exact repro shape: one CSV holding a 5-map tick followed by
# a 4-map tick (what smoke-remote.sh's OLD two-call, single-CSV design
# produced). assert-ebpf-map-memory.sh takes no tick-index argument and
# applies no tick-selection heuristic at all — it treats every NR>1 row as
# one tick's data, so this misuse shape (9 rows, name counts that can't
# match the 5-map expected set) must still fail loudly rather than
# reproduce the old silent-blend bug.
LEGACY_5_THEN_4_CSV="$TMPDIR_TEST/legacy-5-then-4.csv"
{
  echo "ts,map_id,map_name,map_type,max_entries,bytes_memlock"
  echo "2026-09-05T00:00:00Z,189,VIP_MAP,hash,16,4096"
  echo "2026-09-05T00:00:00Z,190,CONFIG,array,1,512"
  echo "2026-09-05T00:00:00Z,191,REV_FLOW,hash,64,8192"
  echo "2026-09-05T00:00:00Z,192,TARGET_PORTS,hash,32,4096"
  echo "2026-09-05T00:00:00Z,193,FWD_FLOW,hash,64,4096"
  echo "2026-09-05T00:00:01Z,189,VIP_MAP,hash,16,4096"
  echo "2026-09-05T00:00:01Z,190,CONFIG,array,1,512"
  echo "2026-09-05T00:00:01Z,191,REV_FLOW,hash,64,8192"
  echo "2026-09-05T00:00:01Z,192,TARGET_PORTS,hash,32,4096"
} > "$LEGACY_5_THEN_4_CSV"
set +e
LEGACY_OUT="$(bash "$ASSERT_SCRIPT" "$LEGACY_5_THEN_4_CSV" 2>&1)"
LEGACY_EXIT=$?
set -e
if [ "$LEGACY_EXIT" -ne 0 ]; then
  echo "PASS: the reviewer's constructed 5-then-4-map two-tick CSV is rejected outright (no tick-selection heuristic to fool) — matches: $LEGACY_OUT"
  PASS=$(( PASS + 1 ))
else
  echo "FAIL: the legacy 5-then-4-map two-tick CSV must not silently pass — got exit 0: $LEGACY_OUT"
  FAIL=$(( FAIL + 1 ))
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
