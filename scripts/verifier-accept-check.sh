#!/usr/bin/env bash
# Shared VERIFIER-ACCEPT confirmation: sourced by scripts/smoke-remote.sh and
# exercised directly by scripts/test-verifier-accept-check-logic.sh.
#
# Dumps the loader log + samples eBPF map memory UNCONDITIONALLY, before
# deciding pass/fail on bpftool's kernel-truth prog count -- a kernel-truth
# divergence (bpftool sees fewer than 3 progs) is exactly the failure this
# diagnostic surface exists for, so it must never be skipped on that path.

verifier_accept_check() { # verifier_accept_check <loaded_count> <loader_log> <memory_script> <pin_dir> <memory_out_dir>
  local loaded="$1" log="$2" memory_script="$3" pin_dir="$4" memory_out_dir="$5"
  cat "$log"
  echo "==> sampling eBPF map memory + loader RSS (before round trip)"
  # A monitoring gap (e.g. jq missing on this node) must never fail the
  # VERIFIER-ACCEPT/ROUND-TRIP fixture it's observing -- same contract
  # sample-ebpf-memory.sh's own header documents for its per-tick sampling.
  bash "$memory_script" once --pin-dir "$pin_dir" --out-dir "$memory_out_dir" || echo "WARN: eBPF memory sampling failed -- continuing (monitoring gap, not a smoke-test failure)" >&2
  [ "$loaded" -eq 3 ] || {
    echo "FAIL: expected 3 sched_cls programs loaded, bpftool sees $loaded" >&2
    return 1
  }
  echo "VERIFIER-ACCEPT: PASS"
}
