#!/usr/bin/env bash
# Tier-1 eBPF beep cross-node harness: the eth0/user-v2-ingress variant of
# scripts/smoke-wg-2node.sh. That rig proves the WireGuard-AS-INGRESS path
# (client SYN arrives on wg0); this one proves the Ethernet-AS-INGRESS,
# WireGuard-AS-TRANSPORT path instead -- node-a's beep instance binds its
# uplink hooks to eth0 (confirmed below to be the real Lima user-v2 NIC
# name inside these VMs, not assumed), while the encapsulated Geneve
# packet still crosses to node-b over the real wg0 tunnel. This is the
# "eth0-in, wg0-out" multi-interface-KIND path, and it is independent of
# the (now-fixed) wg0-AS-INGRESS redirect-into-geneve0 drop: ingress here
# is Ethernet (mac_len=14), so the redirect-into-geneve0 never hits that
# L3-only-uplink code path at all.
#
# CLIENT TOPOLOGY NOTE: the bead this rig implements asked for the client
# to be the macOS host itself, reached via a Lima port-forward. That was
# investigated and found infeasible with this Lima version/network mode:
#   - Lima's automatic guest-port-forward dials the GUEST'S OWN loopback
#     address from a process (sshd) running INSIDE the guest's netns
#     (confirmed via the host-agent log: "Forwarding TCP from 0.0.0.0:PORT
#     to 127.0.0.1:PORT") -- any such packet takes the guest kernel's
#     local/loopback route and never reaches eth0's tc-ingress qdisc at
#     all, which would silently defeat the entire premise of an
#     "Ethernet ingress" test.
#   - `limactl tunnel`'s SOCKS bridge accepts the CONNECT (protocol-level
#     "request granted") for both node-a's and node-b's real eth0
#     addresses, but delivers zero bytes and produces zero packets on the
#     target's eth0 (confirmed via tcpdump) -- not currently a working
#     host<->guest bridge for this network type.
#   - A synthetic (non-VM-owned) source IP forwarded out node-b's real
#     eth0 toward node-a is dropped somewhere in Lima's virtual network
#     (confirmed via tcpdump on node-a: zero packets received for a
#     spoofed-source ping that a plain `ip route`-based forward sent) --
#     Lima's user-v2 switch does not allow off-lease source addresses to
#     transit, so a synthetic-client-identity workaround isn't available
#     either.
# Given both routes to a genuinely foreign client identity are closed,
# this rig -- like smoke-wg-2node.sh already does for the SAME reason --
# uses node-b's own root netns as the client.
#
# RESULT: the forward leg is PROVEN end-to-end on the two assigned VMs --
# eth0 ingress classification, VIP_MAP match, FWD_PENDING admission,
# Geneve encap/transport (node-a's geneve0 TX packet count exactly
# matches node-b's geneve0 RX count every run), node-b's decap+DNAT
# (writes the correct REV_FLOW entry), and nc's real listening socket on
# node-b emitting a genuine SYN-ACK (captured on `lo`; a parallel
# `trace-cmd record -e skb:kfree_skb` run across the same attempt recorded
# zero drops). The eBPF mechanism works cross-node.
#
# What fails is the RETURN leg, and it is a rig-topology limit, not a
# dataplane bug: the SYN-ACK's dst is the client's address, which in this
# 2-VM rig IS node-b's own address (node-b hosts both the backend and the
# client), so `ip route get <that address>` on node-b unconditionally
# resolves to `local ... dev lo` -- the kernel can never select the
# Geneve-transport uplink (wg0) as the SYN-ACK's egress device, regardless
# of eBPF logic or sysctls (`net.ipv4.conf.*.accept_local=1`, added below,
# clears a DIFFERENT, shallower martian-source drop on the FORWARD leg,
# but does not and cannot fix this). The SYN-ACK loops back via `lo` with
# src=pod_ip:target_port, which doesn't match curl's SYN-SENT socket
# (expecting a reply from VIP:port), so node-b's own stack RSTs it
# immediately.
#
# Same structural class as smoke-wg-2node.sh's own client-colocation
# blocker -- there it's a forward-leg martian-source drop, here it's a
# return-leg RST, but the root cause is identical: the "client" can't be
# genuinely foreign to the backend node in a 2-VM rig. Real fix needs a
# 3rd VM (client address genuinely foreign to node-b's own addresses); out
# of this rig's 2-VM scope. See this script's own dump-evidence output for
# the reproduction.
#
# Usage: scripts/smoke-eth-ingress-2node.sh [--vm-a <ingress-vm>] [--vm-b <backend-vm>]
# Defaults match this rig's assigned VMs: beep-node-a (ingress, owns the
# VIP) and beep-node-b (backend Pod + client). Both VMs must be on the
# SAME Lima network (directly reachable over their real eth0/underlay).
#
# Same host prerequisites as smoke.sh; VM prerequisites: bpftool (already
# present) plus `wireguard-tools` (installed automatically below via apt
# if missing) and `trace-cmd` for evidence capture on failure.
set -euo pipefail

VM_A="beep-node-a"
VM_B="beep-node-b"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vm-a) VM_A="$2"; shift 2 ;;
    --vm-b) VM_B="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BEEP_DIR="$REPO_ROOT"
REMOTE_SCRIPT="$SCRIPT_DIR/smoke-eth-ingress-2node-remote.sh"
BIN_NAME="beep-ethingress2node"

# RFC 5737 documentation ranges + a 10.99.0.0/24 tunnel subnet, all
# disjoint from either VM's real eth0/cni0 ranges -- same convention
# smoke-wg-2node.sh uses.
WG_SUBNET_A="10.99.0.2"
WG_SUBNET_B="10.99.0.4"
WG_PORT="51820"
VIP_PORT="19100"
POD_IP="198.51.100.60"
POD_CIDR="198.51.100.0/24"
TARGET_PORT="18090"
UPLINK_IFACE_A="eth0"

for tool in cargo-zigbuild limactl; do
  command -v "$tool" >/dev/null || { echo "FAIL: $tool not found on PATH" >&2; exit 1; }
done
rustup toolchain list 2>/dev/null | grep -q '^nightly' || {
  echo "FAIL: nightly toolchain not installed (rustup toolchain install nightly --component rust-src)" >&2
  exit 1
}

remote() { # remote <vm> <args...> -- runs smoke-eth-ingress-2node-remote.sh as root on <vm>
  local vm="$1"; shift
  limactl shell "$vm" -- sudo bash "/tmp/${BIN_NAME}-remote.sh" "$@"
}

eth0_ip() { # eth0_ip <vm> -- this VM's real underlay address
  limactl shell "$1" -- bash -c "ip -4 -o addr show eth0 | awk '{print \$4}' | cut -d/ -f1"
}

# Same retry rationale as smoke-wg-2node.sh's cleanup trap: a burst of
# back-to-back `limactl shell` sessions can leave SSH's own connection
# layer transiently unhappy right after the run finishes.
remote_retry() {
  local vm="$1"; shift
  local attempt
  for attempt in 1 2 3 4 5; do
    remote "$vm" "$@" && return 0
    sleep "$attempt"
  done
  echo "WARN: cleanup command '$*' did not succeed on $vm after 5 attempts -- VM may need manual teardown" >&2
  return 1
}

cleanup() {
  remote_retry "$VM_A" cleanup || true
  remote_retry "$VM_B" cleanup || true
}
trap cleanup EXIT

echo "==> [1/7] bringing up $VM_A and $VM_B"
for vm in "$VM_A" "$VM_B"; do
  if ! limactl list --format '{{.Name}}\t{{.Status}}' 2>/dev/null | grep -qE "^${vm}[[:space:]]+Running"; then
    limactl start "$vm"
  fi
  limactl shell "$vm" -- bash -c 'command -v wg >/dev/null || sudo apt-get install -y wireguard-tools' >/dev/null
done

echo "==> [2/7] confirming node-a's user-v2 NIC name (must not be assumed)"
IFACE_A_ACTUAL="$(limactl shell "$VM_A" -- bash -c "ip -4 -o addr show | awk '\$4 !~ /^127\\./ {print \$2; exit}'")"
[ "$IFACE_A_ACTUAL" = "$UPLINK_IFACE_A" ] || {
  echo "FAIL: expected $VM_A's user-v2 NIC to be '$UPLINK_IFACE_A', found '$IFACE_A_ACTUAL' -- update UPLINK_IFACE_A" >&2
  exit 1
}
echo "UPLINK-IFACE-NAME: PASS ($VM_A's user-v2 NIC is $UPLINK_IFACE_A)"

echo "==> [3/7] cross-building beep-ebpf + beep (nightly + bpf-linker + zigbuild -> aarch64-unknown-linux-gnu)"
( cd "$BEEP_DIR" && cargo +nightly zigbuild --release --target aarch64-unknown-linux-gnu )
BIN="$BEEP_DIR/target/aarch64-unknown-linux-gnu/release/beep"
[ -x "$BIN" ] || { echo "FAIL: build did not produce $BIN" >&2; exit 1; }

for vm in "$VM_A" "$VM_B"; do
  limactl copy "$BIN" "$vm":"/tmp/${BIN_NAME}"
  limactl copy "$REMOTE_SCRIPT" "$vm":"/tmp/${BIN_NAME}-remote.sh"
  limactl shell "$vm" -- bash -c "chmod +x /tmp/${BIN_NAME} /tmp/${BIN_NAME}-remote.sh"
  remote "$vm" cleanup >/dev/null 2>&1 || true
done

echo "==> [4/7] establishing the real WireGuard tunnel between $VM_A and $VM_B (the Geneve TRANSPORT, not the client-facing ingress)"
IP_A="$(eth0_ip "$VM_A")"
IP_B="$(eth0_ip "$VM_B")"
[ -n "$IP_A" ] && [ -n "$IP_B" ] || {
  echo "FAIL: could not resolve eth0 addresses ($VM_A=$IP_A, $VM_B=$IP_B) -- are both VMs on the same Lima network?" >&2
  exit 1
}
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

echo "==> [5/7] creating geneve0 on both nodes + verifying $VM_A's real uplink is up"
remote "$VM_A" setup-geneve
remote "$VM_B" setup-geneve
remote "$VM_A" check-uplink "$UPLINK_IFACE_A"

echo "==> [6/7] loading beep-ebpf: $VM_A uplink=$UPLINK_IFACE_A (client-facing Ethernet ingress), $VM_B uplink=wg0 (default, Geneve transport)"
FIXTURE="${IP_A}:${VIP_PORT}:tcp:${WG_SUBNET_B}:${POD_IP}:${TARGET_PORT}"
remote "$VM_A" start-loader --uplink-iface "$UPLINK_IFACE_A" --fixture "$FIXTURE" --pod-cidr "$POD_CIDR" --node-ip "$IP_A"
remote "$VM_B" start-loader --fixture "$FIXTURE" --pod-cidr "$POD_CIDR" --node-ip "$WG_SUBNET_B"

remote "$VM_B" setup-backend --pod-ip "$POD_IP"
remote "$VM_B" start-backend-responder --pod-ip "$POD_IP" --port "$TARGET_PORT"

echo "==> [7/7] driving one client -> node-a's real Ethernet VIP -> cross-node backend round trip"
# Client = vm-b's own root netns dialing vm-a's REAL eth0 address (not
# wg0) -- see this script's header for why the client can't be the macOS
# host or a synthetic address in this environment, and why it's still
# node-b (not node-a) playing the client role.
if remote "$VM_B" run-client --vip-ip "$IP_A" --vip-port "$VIP_PORT"; then
  echo "GATE 1 TIER-1 MECHANISM: PASS (eth0-ingress, wg0-transport)"
  exit 0
fi

echo ""
echo "==> round trip did not complete -- collecting evidence"
echo "---- $VM_A evidence ----"
remote "$VM_A" dump-evidence
echo "---- $VM_B evidence ----"
remote "$VM_B" dump-evidence
exit 1
