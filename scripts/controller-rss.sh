#!/usr/bin/env bash
# Shared beep-controller userspace RSS sampling + ceiling assertion.
# Sourced (not executed) by scripts/smoke-k3s-controller.sh (Lima, remote via
# `limactl shell <vm> --`) and scripts/memory-smoke-controller.sh (CI,
# same-host) -- one measured baseline, one set of ceilings, asserted from a
# single place instead of two copies drifting.
#
# Measured directly on a live Linux run (Lima aarch64, beep-controller built
# from source, watching a real single-node k3s apiserver): ~6.8 MiB (6948 kB)
# idle baseline right after the initial Service/EndpointSlice/Node LIST+watch
# settle, ~7.0 MiB (7004 kB) after reconciling 6 Services and 5 backend Pods
# (a ~56 kB delta) -- modestly above ebpf-lb-dataplane.md's old 3-5 MiB
# estimate (a real async k8s client vs. the doc's bare-reconcile-logic
# assumption, since corrected there to the measured number), not a wild
# overshoot. Ceilings below are generous multiples of that measured
# baseline/delta, not the doc's old unvalidated estimate.
CONTROLLER_RSS_BASELINE_CEILING_KB=16384
CONTROLLER_RSS_GROWTH_CEILING_KB=4096

controller_rss() { # controller_rss [exec-prefix...] -- beep-controller RSS in kB, reached via an optional exec prefix (e.g. `limactl shell VM --`, empty for same-host); "" if the process isn't found
  local pid rss
  pid=$("$@" pgrep -f beep-controller 2>/dev/null | head -1) || true
  [ -z "$pid" ] && { echo ""; return; }
  rss=$("$@" ps -o rss= -p "$pid" 2>/dev/null | tr -d '[:space:]') || true
  echo "$rss"
}

assert_controller_rss_baseline() { # assert_controller_rss_baseline <rss_kb> <label> -- fails loud (message to stderr, returns 1) if <rss_kb> is empty or exceeds CONTROLLER_RSS_BASELINE_CEILING_KB
  local rss="$1" label="$2"
  [ -n "$rss" ] || { echo "FAIL: could not resolve beep-controller RSS on $label" >&2; return 1; }
  [ "$rss" -le "$CONTROLLER_RSS_BASELINE_CEILING_KB" ] || {
    echo "FAIL: beep-controller baseline RSS ${rss}kB on $label exceeds the ${CONTROLLER_RSS_BASELINE_CEILING_KB}kB ceiling (see this file's header for the measured baseline this ceiling is set against)" >&2
    return 1
  }
  echo "CONTROLLER-RSS-BASELINE ($label): PASS (${rss}kB, ceiling ${CONTROLLER_RSS_BASELINE_CEILING_KB}kB)"
}

assert_controller_rss_growth() { # assert_controller_rss_growth <baseline_kb> <peak_kb> <label> -- fails loud if either value is empty or the delta exceeds CONTROLLER_RSS_GROWTH_CEILING_KB
  local baseline="$1" peak="$2" label="$3" delta
  [ -n "$baseline" ] && [ -n "$peak" ] || { echo "FAIL: could not resolve beep-controller RSS on $label" >&2; return 1; }
  delta=$(( peak - baseline ))
  [ "$delta" -le "$CONTROLLER_RSS_GROWTH_CEILING_KB" ] || {
    echo "FAIL: beep-controller RSS on $label grew by ${delta}kB reconciling the fixture, exceeding the ${CONTROLLER_RSS_GROWTH_CEILING_KB}kB growth ceiling -- an unbounded per-Service/per-endpoint retained allocation would show up here first" >&2
    return 1
  }
  echo "CONTROLLER-RSS-PEAK ($label): PASS (${peak}kB, delta ${delta}kB, growth ceiling ${CONTROLLER_RSS_GROWTH_CEILING_KB}kB)"
}
