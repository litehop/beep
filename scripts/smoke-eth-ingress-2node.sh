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
# CLIENT TOPOLOGY: the client is a genuinely separate 3rd Lima VM
# (lima/beep-client.yaml, default name beep-client) on the same user-v2
# network as node-a/node-b, but non-local to both. This replaces an
# earlier version of this rig that used node-b's own root netns as the
# client -- that could only prove the FORWARD leg (client SYN -> VIP ->
# decap+DNAT -> backend), because a reply destined to node-b's own address
# resolves to `local ... dev lo` on node-b, so the kernel never selects
# the Geneve-transport uplink as egress and beep's return hook never
# fires.
#
# RESULT: with a genuinely foreign client, the full symmetric-return round
# trip is PROVEN cross-node (client -> VIP -> decap+DNAT -> backend nc ->
# un-DNAT+re-encap -> ingress node -> client, real HTTP response
# received) -- PROVIDED node-b's uplink-iface is set to the SAME real NIC
# as node-a's (both below), not left at the wg0 default. wg0 here is pure
# Geneve-transport substrate between the two nodes, not either node's
# client/return-facing device; `uplink_egress_return` only sees traffic
# actually egressing the device it's attached to, and node-b's kernel
# routes a reply to a client on the shared user-v2 subnet out its real
# NIC, not out wg0 (confirmed via tcpdump: with uplink-iface left at wg0,
# the backend's raw un-DNAT'd reply leaks out node-b's real NIC
# unencapsulated and the client never completes its handshake).
#
# Usage: scripts/smoke-eth-ingress-2node.sh [--vm-a <ingress-vm>] [--vm-b <backend-vm>] [--vm-client <client-vm>]
# Defaults match this rig's assigned VMs: beep-node-a (ingress, owns the
# VIP), beep-node-b (backend Pod), beep-client (client). All three VMs
# must be on the SAME Lima network (directly reachable over their real
# eth0/underlay).
#
# Same host prerequisites as smoke.sh; VM prerequisites: bpftool (already
# present) plus `wireguard-tools` (installed automatically below via apt
# if missing) and `trace-cmd` for evidence capture on failure. beep-client
# has no MCP server and never runs the dataplane/WG -- it's driven
# directly via `limactl shell` from this host script, not via the
# remote.sh subcommand protocol node-a/node-b use.
set -euo pipefail

VM_A="beep-node-a"
VM_B="beep-node-b"
VM_CLIENT="beep-client"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vm-a) VM_A="$2"; shift 2 ;;
    --vm-b) VM_B="$2"; shift 2 ;;
    --vm-client) VM_CLIENT="$2"; shift 2 ;;
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

echo "==> [1/7] bringing up $VM_A, $VM_B, and $VM_CLIENT"
for vm in "$VM_A" "$VM_B"; do
  if ! limactl list --format '{{.Name}}\t{{.Status}}' 2>/dev/null | grep -qE "^${vm}[[:space:]]+Running"; then
    limactl start "$vm"
  fi
  limactl shell "$vm" -- bash -c 'command -v wg >/dev/null || sudo apt-get install -y wireguard-tools' >/dev/null
done
if ! limactl list --format '{{.Name}}\t{{.Status}}' 2>/dev/null | grep -qE "^${VM_CLIENT}[[:space:]]+Running"; then
  limactl start "$VM_CLIENT"
fi

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

echo "==> [6/7] loading beep-ebpf: $VM_A and $VM_B both uplink=$UPLINK_IFACE_A (their shared real underlay NIC; wg0 is pure Geneve transport substrate on top of it, not either node's client/return-facing device)"
FIXTURE="${IP_A}:${VIP_PORT}:tcp:${WG_SUBNET_B}:${POD_IP}:${TARGET_PORT}"
remote "$VM_A" start-loader --uplink-iface "$UPLINK_IFACE_A" --fixture "$FIXTURE" --pod-cidr "$POD_CIDR" --node-ip "$IP_A"
# --uplink-iface must match $VM_A's (not the wg0 default): the backend
# node's kernel routes a reply to a client on the shared user-v2 subnet
# out its real NIC (eth0), not out wg0 (which only has a connected route
# for the 10.99.0.0/24 WG-transport subnet) -- `uplink_egress_return`
# only sees traffic actually egressing the device it's attached to, so
# leaving this at the wg0 default means the hook never fires and the raw
# backend-pod-sourced reply leaks onto the wire un-encapsulated,
# un-un-DNAT'd (confirmed via tcpdump: `198.51.100.60.PORT >
# <client>.PORT` on $VM_B's real eth0, never entering geneve0 at all).
remote "$VM_B" start-loader --uplink-iface "$UPLINK_IFACE_A" --fixture "$FIXTURE" --pod-cidr "$POD_CIDR" --node-ip "$WG_SUBNET_B"

remote "$VM_B" setup-backend --pod-ip "$POD_IP"
remote "$VM_B" start-backend-responder --pod-ip "$POD_IP" --port "$TARGET_PORT"

echo "==> [7/7] driving one client ($VM_CLIENT) -> node-a's real Ethernet VIP -> cross-node backend round trip"
# Client = the genuinely separate beep-client VM dialing vm-a's REAL eth0
# address -- driven directly via limactl, not the remote.sh subcommand
# protocol (beep-client has no /tmp/${BIN_NAME}-remote.sh copy and no MCP
# server; see this script's header). A 20s cap, not 5s: the first
# connection pays for ARP resolution of the client's MAC on $VM_B plus
# the WG tunnel's own handshake, so the first SYN(-ACK) round trip alone
# can take several seconds -- confirmed empirically, a 5s cap flakes on a
# cold rig even though the dataplane mechanism itself is correct.
set +e
CLIENT_BODY="$(limactl shell "$VM_CLIENT" -- curl -sS -m 20 "http://${IP_A}:${VIP_PORT}/" 2>&1)"
CLIENT_RC=$?
set -e
if [ "$CLIENT_RC" -eq 0 ] && [ "$CLIENT_BODY" = "OK" ]; then
  echo "ROUND-TRIP: PASS (client $VM_CLIENT -> VIP ${IP_A}:${VIP_PORT} -> cross-node backend -> response 'OK')"
  echo "GATE 1 TIER-1 MECHANISM: PASS (eth0-ingress, wg0-transport, symmetric return proven from a genuinely foreign client)"
  exit 0
fi
echo "ROUND-TRIP: FAIL (curl rc=$CLIENT_RC, body='$CLIENT_BODY')" >&2

echo ""
echo "==> round trip did not complete -- collecting evidence"
echo "---- $VM_A evidence ----"
remote "$VM_A" dump-evidence
echo "---- $VM_B evidence ----"
remote "$VM_B" dump-evidence
exit 1
