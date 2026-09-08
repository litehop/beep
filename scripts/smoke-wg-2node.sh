#!/usr/bin/env bash
# Tier-1 eBPF ServiceLB cross-node harness: 2 real Lima VMs linked by a real
# WireGuard tunnel, standing in for the operator's fleet's WireGuard/
# Tailscale mesh (`ai/extended-context/ebpf-lb-dataplane.md`'s "Must work
# across four underlay scenarios ... WireGuard/Tailscale mesh"). Unlike
# scripts/servicelb/smoke.sh (one VM, a local veth pair standing in for a
# client), this drives Geneve encap/decap across TWO real kernels connected
# by a real wg0 uplink -- the scenario servicelb-ebpf's L2-header-skip fix
# (`u7s_servicelb_common::uplink_l2_header_len`) targets.
#
# CURRENT STATUS (as of this rig's introduction): the WireGuard tunnel comes
# up correctly and the L2-header-skip fix correctly parses a real L3
# WireGuard packet on the ingress node (asserted below via a live
# FWD_PENDING dump on vm-a) -- but the end-to-end round trip does NOT yet
# complete. `bpf_redirect` from the L3-only wg0 uplink to the Ethernet-type
# geneve0 device fails inside the kernel: confirmed via
# `dmesg`/`trace-cmd record -e skb:kfree_skb` showing the encapsulated SYN
# freed at `location=__bpf_redirect+0x220 reason: NOT_SPECIFIED`,
# corroborated by geneve0's `ip -s link show` TX `dropped` counter
# incrementing once per client attempt with zero corresponding RX on the
# peer. This is a NEW, distinct blocker from the two issues this rig's setup
# steps already solve (see smoke-wg-2node-remote.sh's header) -- filed
# separately for follow-up. This script's `run` therefore ends in a
# documented, non-zero "ROUND-TRIP: FAIL (known blocker)" rather than a
# false pass; every step before that is a genuine, asserted PASS.
#
# Usage: scripts/servicelb/smoke-wg-2node.sh [--vm-a <ingress-vm>] [--vm-b <backend-vm>]
# Defaults match this rig's assigned VMs: lima-node-2 (ingress, owns the VIP)
# and lima-node-4 (backend Pod + the "client" -- see remote script header on
# why a 2-node rig's client is the backend node's own root netns).
# Both VMs must be on the SAME Lima network (directly reachable over their
# real eth0/underlay) so the WireGuard handshake has a path to establish --
# WireGuard is the L3 uplink under test here, not a substitute for underlay
# reachability.
#
# Same host prerequisites as smoke.sh (nightly + rust-src + bpf-linker +
# cargo-zigbuild); VM prerequisites: bpftool (already present) plus
# `wireguard-tools` (installed automatically below via apt if missing) and
# `trace-cmd` for evidence capture on failure.
set -euo pipefail

VM_A="lima-node-2"
VM_B="lima-node-4"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vm-a) VM_A="$2"; shift 2 ;;
    --vm-b) VM_B="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SERVICELB_DIR="$REPO_ROOT/crates/servicelb"
REMOTE_SCRIPT="$SCRIPT_DIR/smoke-wg-2node-remote.sh"
BIN_NAME="u7s-servicelb-wg2node"

# RFC 5737 documentation ranges + a 10.99.0.0/24 tunnel subnet deliberately
# disjoint from either VM's real eth0/cni0 ranges.
WG_SUBNET_A="10.99.0.2"
WG_SUBNET_B="10.99.0.4"
WG_PORT="51820"
VIP_PORT="19100"
POD_IP="198.51.100.60"
TARGET_PORT="18090"

for tool in cargo-zigbuild limactl; do
  command -v "$tool" >/dev/null || { echo "FAIL: $tool not found on PATH" >&2; exit 1; }
done
rustup toolchain list 2>/dev/null | grep -q '^nightly' || {
  echo "FAIL: nightly toolchain not installed (rustup toolchain install nightly --component rust-src)" >&2
  exit 1
}

remote() { # remote <vm> <args...> -- runs smoke-wg-2node-remote.sh as root on <vm>
  local vm="$1"; shift
  limactl shell "$vm" -- sudo bash "/tmp/${BIN_NAME}-remote.sh" "$@"
}

eth0_ip() { # eth0_ip <vm> -- this VM's real underlay address (the WG endpoint)
  limactl shell "$1" -- bash -c "ip -4 -o addr show eth0 | awk '{print \$4}' | cut -d/ -f1"
}

# Retries: by the time this fires, the run above has already opened a couple
# dozen back-to-back `limactl shell` (SSH) sessions across both VMs. This
# trap's own cleanup calls were observed (repeatedly, not just once) to get
# SSH's OWN connection-level failure (exit 255, distinct from any exit code
# the remote script itself could return) immediately afterward, sometimes
# for several seconds -- while a plain `limactl shell <vm> -- echo hello` on
# the SAME VM at the SAME time succeeded, so this is specific to the
# just-finished session burst, not a general Lima/VM connectivity loss.
# Retrying with backoff clears it within a few attempts in practice; if it
# doesn't, this prints a loud warning naming the VM rather than silently
# leaving wg0/geneve0/bpf pins behind.
remote_retry() {
  local vm="$1"; shift
  local attempt
  for attempt in 1 2 3 4 5; do
    remote "$vm" "$@" && return 0
    sleep "$attempt"
  done
  echo "WARN: cleanup command '$*' did not succeed on $vm after 5 attempts -- VM may need manual teardown (see this function's comment)" >&2
  return 1
}

cleanup() {
  remote_retry "$VM_A" cleanup || true
  remote_retry "$VM_B" cleanup || true
}
trap cleanup EXIT

echo "==> [1/6] bringing up $VM_A and $VM_B"
for vm in "$VM_A" "$VM_B"; do
  if ! limactl list --format '{{.Name}}\t{{.Status}}' 2>/dev/null | grep -qE "^${vm}[[:space:]]+Running"; then
    limactl start "$vm"
  fi
  limactl shell "$vm" -- bash -c 'command -v wg >/dev/null || sudo apt-get install -y wireguard-tools' >/dev/null
done

echo "==> [2/6] cross-building servicelb-ebpf + u7s-servicelb (nightly + bpf-linker + zigbuild -> aarch64-unknown-linux-gnu)"
( cd "$SERVICELB_DIR" && cargo +nightly zigbuild --release --target aarch64-unknown-linux-gnu )
BIN="$SERVICELB_DIR/target/aarch64-unknown-linux-gnu/release/u7s-servicelb"
[ -x "$BIN" ] || { echo "FAIL: build did not produce $BIN" >&2; exit 1; }

for vm in "$VM_A" "$VM_B"; do
  limactl copy "$BIN" "$vm":"/tmp/${BIN_NAME}"
  limactl copy "$REMOTE_SCRIPT" "$vm":"/tmp/${BIN_NAME}-remote.sh"
  limactl shell "$vm" -- bash -c "chmod +x /tmp/${BIN_NAME} /tmp/${BIN_NAME}-remote.sh"
  remote "$vm" cleanup >/dev/null 2>&1 || true
done

echo "==> [3/6] establishing the real WireGuard tunnel between $VM_A and $VM_B"
IP_A="$(eth0_ip "$VM_A")"
IP_B="$(eth0_ip "$VM_B")"
[ -n "$IP_A" ] && [ -n "$IP_B" ] || {
  echo "FAIL: could not resolve eth0 addresses ($VM_A=$IP_A, $VM_B=$IP_B) -- are both VMs on the same Lima network?" >&2
  exit 1
}
# Each side's key pair is generated independently BEFORE either side's peer
# config is known -- avoids a chicken-and-egg ordering (setup-wg needs the
# PEER's pubkey as an argument, so both pubkeys must exist first).
PUBKEY_A="$(remote "$VM_A" pubkey)"
PUBKEY_B="$(remote "$VM_B" pubkey)"
remote "$VM_A" setup-wg --self-ip "$WG_SUBNET_A" --peer-ip "$WG_SUBNET_B" \
  --peer-pubkey "$PUBKEY_B" --peer-endpoint "${IP_B}:${WG_PORT}" --listen-port "$WG_PORT"
remote "$VM_B" setup-wg --self-ip "$WG_SUBNET_B" --peer-ip "$WG_SUBNET_A" \
  --peer-pubkey "$PUBKEY_A" --peer-endpoint "${IP_A}:${WG_PORT}" --listen-port "$WG_PORT"

limactl shell "$VM_A" -- ping -c 2 -W 2 "$WG_SUBNET_B" >/dev/null || {
  echo "FAIL: $VM_A cannot ping $VM_B over the WireGuard tunnel ($WG_SUBNET_B)" >&2
  exit 1
}
echo "WIREGUARD TUNNEL: PASS ($VM_A $WG_SUBNET_A <-> $VM_B $WG_SUBNET_B, over real underlay $IP_A/$IP_B)"

echo "==> [4/6] creating geneve0 on both nodes"
remote "$VM_A" setup-geneve
remote "$VM_B" setup-geneve

echo "==> [5/6] loading servicelb-ebpf on both nodes (uplink=wg0) -- this is the verifier-accept gate on a real L3 WireGuard uplink"
FIXTURE="${WG_SUBNET_A}:${VIP_PORT}:tcp:${WG_SUBNET_B}:${POD_IP}:${TARGET_PORT}"
remote "$VM_A" start-loader --fixture "$FIXTURE"
remote "$VM_B" start-loader --fixture "$FIXTURE"

remote "$VM_B" setup-backend --pod-ip "$POD_IP"
remote "$VM_B" start-backend-responder --pod-ip "$POD_IP" --port "$TARGET_PORT"

echo "==> [6/6] driving one client -> VIP -> cross-node backend round trip over the wg0 uplink"
# Client = vm-b's own root netns dialing vm-a's VIP (vm-a's own wg0 address)
# -- see smoke-wg-2node-remote.sh's header for why, with exactly 2 nodes,
# this is the topology that genuinely exercises uplink_ingress arriving on a
# real WireGuard device rather than a local loopback shortcut.
if remote "$VM_B" run-client --vip-ip "$WG_SUBNET_A" --vip-port "$VIP_PORT"; then
  echo "GATE 1 TIER-1 MECHANISM: PASS"
  exit 0
fi

echo ""
echo "==> round trip did not complete -- collecting evidence (see this script's header for the known blocker)"
echo "---- $VM_A evidence ----"
remote "$VM_A" dump-evidence
echo "---- $VM_B evidence ----"
remote "$VM_B" dump-evidence
exit 1
