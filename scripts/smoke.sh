#!/usr/bin/env bash
# Tier-1 eBPF ServiceLB smoke harness.
#
# Run this locally before any servicelb-ebpf PR merges. It is the one gate
# that actually loads the compiled object into a live kernel verifier and
# drives real packets through it -- CI's `ebpf-build` job only proves the
# bpfel-unknown-none build COMPILES, not that the verifier ACCEPTS it at
# load time (the exact risk `ai/extended-context/ebpf-lb-dataplane.md`
# flags for "verifier rejection under churn/scale").
#
# What it does, on one already-provisioned Lima VM (default lima-node-5):
#   1. cross-builds servicelb-ebpf + u7s-servicelb on this (macOS) host via
#      nightly + bpf-linker + cargo-zigbuild, targeting the VM's aarch64
#      Linux (see crates/servicelb/README.md's "Building" section for the
#      non-cross prerequisites this reuses: nightly rust-src + bpf-linker);
#   2. copies the loader binary + scripts/servicelb/smoke-remote.sh into
#      the VM and runs it there as root;
#   3. smoke-remote.sh builds a self-contained veth-pair + netns fixture,
#      loads the 3 tc-bpf classifiers, and asserts the verifier ACCEPTED
#      them (a rejection surfaces as a loader load error, checked
#      explicitly, plus an independent `bpftool prog list` confirmation);
#   4. drives one client -> VIP -> backend TCP round trip through the real
#      Geneve encap/decap dataplane and asserts it completes.
#
# Exits non-zero on any failure. Always tears down its own fixture
# (`smoke-remote.sh cleanup`) on exit, success or failure.
#
# Usage: scripts/servicelb/smoke.sh [--vm <lima-vm-name>]
#
# Host prerequisites (same as crates/servicelb/README.md's "Building",
# plus cargo-zigbuild for the macOS-host -> Linux-VM cross build this
# harness needs since crates/servicelb cannot compile natively on macOS):
#   rustup toolchain install nightly --component rust-src
#   rustup target add aarch64-unknown-linux-gnu --toolchain nightly
#   cargo install bpf-linker cargo-zigbuild
# VM prerequisite: bpftool (already present on lima-node-5 from prior
# servicelb work; otherwise `apt-get install linux-tools-$(uname -r)`).
set -euo pipefail

VM="lima-node-5"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vm) VM="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SERVICELB_DIR="$REPO_ROOT/crates/servicelb"
REMOTE_SCRIPT="$SCRIPT_DIR/smoke-remote.sh"
MEMORY_SCRIPT="$SCRIPT_DIR/sample-ebpf-memory.sh"

for tool in cargo-zigbuild limactl; do
  command -v "$tool" >/dev/null || { echo "FAIL: $tool not found on PATH" >&2; exit 1; }
done
rustup toolchain list 2>/dev/null | grep -q '^nightly' || {
  echo "FAIL: nightly toolchain not installed (rustup toolchain install nightly --component rust-src)" >&2
  exit 1
}

echo "==> [1/4] bringing up $VM"
if ! limactl list --format '{{.Name}}\t{{.Status}}' 2>/dev/null | grep -qE "^${VM}[[:space:]]+Running"; then
  limactl start "$VM"
fi

echo "==> [2/4] cross-building servicelb-ebpf + u7s-servicelb (nightly + bpf-linker + zigbuild -> aarch64-unknown-linux-gnu)"
( cd "$SERVICELB_DIR" && cargo +nightly zigbuild --release --target aarch64-unknown-linux-gnu )
BIN="$SERVICELB_DIR/target/aarch64-unknown-linux-gnu/release/u7s-servicelb"
[ -x "$BIN" ] || { echo "FAIL: build did not produce $BIN" >&2; exit 1; }

limactl copy "$BIN" "$VM":/tmp/u7s-servicelb-smoke
limactl copy "$REMOTE_SCRIPT" "$VM":/tmp/smoke-remote.sh
limactl copy "$MEMORY_SCRIPT" "$VM":/tmp/sample-ebpf-memory.sh
limactl shell "$VM" -- bash -c 'chmod +x /tmp/u7s-servicelb-smoke /tmp/smoke-remote.sh /tmp/sample-ebpf-memory.sh'

cleanup() {
  limactl shell "$VM" -- sudo bash /tmp/smoke-remote.sh cleanup || true
}
trap cleanup EXIT

echo "==> [3/4]+[4/4] load, assert verifier-accept, drive the round trip (in-VM)"
limactl shell "$VM" -- sudo bash /tmp/smoke-remote.sh run
