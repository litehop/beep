#!/usr/bin/env bash
# Dual-stack sibling of scripts/smoke-wg-2node.sh: proves ONE
# fixture set -- a v4 front and a v6 front on the same VIP_PORT, same
# backend node -- serves BOTH a v4 client AND a v6 client concurrently on
# the beep-node-a/beep-node-b rig, over a real WireGuard tunnel.
#
# Uses ONLY beep-node-a/beep-node-b, no 3rd client VM: the client for BOTH
# families runs in its own isolated netns on node-b (a veth pair, one end
# in node-b's default netns, the other in $CLIENT_NETNS -- see
# smoke-wg-2node-remote.sh's setup_client_netns), the same isolation
# technique scripts/smoke-remote.sh's single-VM smoke-client netns already
# uses. This sidesteps the known martian-source-drop failure mode where a
# co-located client's own address collides with pod_ip, both "local" to
# node-b, dropped at ip_rcv_finish_core: the client's address lives in a
# netns of its own, so it is never one of node-b's default-netns-local
# addresses, regardless of node-b also hosting the backend Pod.
#
# NODE_ALLOW peer-node attestation (`beep_common::peer_node_admission`)
# makes a bare loader -- no controller, no Node watch -- admit a Geneve
# decap ONLY when its outer source equals the decapsulating node's OWN
# `--node-ip`: there is no CLI knob to widen it to a genuinely different
# peer. So, exactly like the existing v4-only
# smoke-wg-2node.sh, this round trip's forward leg is caught and
# self-looped entirely on node-b (its own `--uplink-iface` is the client
# veth, not wg0): node-b is simultaneously ingress (for admission-control
# purposes) and backend for both fixtures. wg0 still carries this rig's WG
# handshake/tunnel and the loader attached to it on node-a, but the
# client's packets never physically cross it -- the same structural
# constraint every bare-loader beep-node-a/beep-node-b rig has today.
#
# The outer Geneve/underlay stays v4-only for BOTH fronts (`NODE_ALLOW`/
# `bpf_tunnel_key.remote_ipv4` module doc in ebpf/src/main.rs: "every
# fixture/smoke deployment today runs a v4-only underlay regardless of the
# inner packet's own family") -- only the VIP/pod_ip pair's own family
# varies per front. This lets one `--node-ip` (node-b's v4 wg0 address)
# correctly scope POD_TARGETS to BOTH fixtures' pod_ip (`--node-ip`'s doc
# comment in src/main.rs: matched by exact `backend_node_ip` equality).
#
# Usage: scripts/smoke-wg-2node-dualstack.sh [--vm-a <ingress-vm>] [--vm-b <backend-vm>]
# Same host/VM prerequisites as smoke-wg-2node.sh.
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
REMOTE_SCRIPT="$SCRIPT_DIR/smoke-wg-2node-remote.sh"
BIN_NAME="beep-wg2node"

# RFC 5737/3849 documentation ranges + a 10.99.0.0/24 tunnel subnet, all
# deliberately disjoint from either VM's real eth0/cni0 ranges and from
# each other.
WG_SUBNET_A="10.99.0.2"
WG_SUBNET_B="10.99.0.4"
WG_ULA_A="fd00:beef:99::2"
WG_ULA_B="fd00:beef:99::4"
WG_PORT="51820"
VIP_PORT="19100"
POD_CIDR="198.51.100.0/24"
POD_IP_V4="198.51.100.60"
POD_IP_V6="2001:db8:60::10"
TARGET_PORT_V4="18090"
TARGET_PORT_V6="18091"
# Client-netns veth on node-b: root end stays in node-b's default netns
# (where the loader's `--uplink-iface` for this fixture is attached), peer
# end is isolated in the netns the curl clients actually run in.
CLIENT_V4_ROOT="203.0.113.1"
CLIENT_V4="203.0.113.2"
CLIENT_V4_PREFIX="29"
CLIENT_V6_ROOT="fd00:beef:60::1"
CLIENT_V6="fd00:beef:60::2"
CLIENT_V6_PREFIX="64"
CLIENT_VETH="wg2ds-veth0"
CLIENT_NETNS="smoke-wg2node-client"

FIXTURE_V4="${WG_SUBNET_A}:${VIP_PORT}:tcp:${WG_SUBNET_B}:${POD_IP_V4}:${TARGET_PORT_V4}"
FIXTURE_V6="[${WG_ULA_A}]:${VIP_PORT}:tcp:${WG_SUBNET_B}:[${POD_IP_V6}]:${TARGET_PORT_V6}"

command -v limactl >/dev/null || { echo "FAIL: limactl not found on PATH" >&2; exit 1; }
command -v cargo-zigbuild >/dev/null || { echo "FAIL: cargo-zigbuild not found on PATH" >&2; exit 1; }
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

# Same retry rationale as smoke-wg-2node.sh's remote_retry: a burst of
# back-to-back `limactl shell` sessions can leave SSH transiently unhappy
# right when cleanup fires.
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

echo "==> [1/8] bringing up $VM_A and $VM_B"
for vm in "$VM_A" "$VM_B"; do
  if ! limactl list --format '{{.Name}}\t{{.Status}}' 2>/dev/null | grep -qE "^${vm}[[:space:]]+Running"; then
    limactl start "$vm"
  fi
  limactl shell "$vm" -- bash -c 'command -v wg >/dev/null || sudo apt-get install -y wireguard-tools' >/dev/null
done

echo "==> [2/8] cross-building beep-ebpf + beep (nightly + bpf-linker + zigbuild -> aarch64-unknown-linux-gnu)"
( cd "$BEEP_DIR" && cargo +nightly zigbuild --release --target aarch64-unknown-linux-gnu )
BIN="$BEEP_DIR/target/aarch64-unknown-linux-gnu/release/beep"
[ -x "$BIN" ] || { echo "FAIL: build did not produce $BIN" >&2; exit 1; }

for vm in "$VM_A" "$VM_B"; do
  limactl copy "$BIN" "$vm":"/tmp/${BIN_NAME}"
  limactl copy "$REMOTE_SCRIPT" "$vm":"/tmp/${BIN_NAME}-remote.sh"
  limactl shell "$vm" -- bash -c "chmod +x /tmp/${BIN_NAME} /tmp/${BIN_NAME}-remote.sh"
  remote "$vm" cleanup >/dev/null 2>&1 || true
done

echo "==> [3/8] establishing the dual-stack WireGuard tunnel between $VM_A and $VM_B"
IP_A="$(eth0_ip "$VM_A")"
IP_B="$(eth0_ip "$VM_B")"
[ -n "$IP_A" ] && [ -n "$IP_B" ] || {
  echo "FAIL: could not resolve eth0 addresses ($VM_A=$IP_A, $VM_B=$IP_B) -- are both VMs on the same Lima network?" >&2
  exit 1
}
# Each side's key pair is generated independently BEFORE either side's peer
# config is known.
PUBKEY_A="$(remote "$VM_A" pubkey)"
PUBKEY_B="$(remote "$VM_B" pubkey)"
# `wg set <iface> peer <pubkey> allowed-ips <list>` REPLACES that peer's
# whole allowed-ips list, so the SECOND (v6) call per node must re-list
# everything the FIRST (v4) call already granted, not just add to it.
# node-a's peer entry for node-b is additionally widened (--extra-allowed)
# to admit the client-netns's own v4/v6 addresses -- node-b relays the
# client's plain packet into the tunnel as an ordinary IP forward
# (ip_forward=1/net.ipv6.conf.all.forwarding=1, set up by setup-backend
# below), and without this widening, WireGuard's own crypto-routing source
# filter would drop that relayed, client-sourced packet on decrypt.
remote "$VM_A" setup-wg --self-ip "$WG_SUBNET_A" --peer-ip "$WG_SUBNET_B" \
  --peer-pubkey "$PUBKEY_B" --peer-endpoint "${IP_B}:${WG_PORT}" --listen-port "$WG_PORT" \
  --extra-allowed "${CLIENT_V4}/32"
remote "$VM_A" setup-wg --family 6 --self-ip "$WG_ULA_A" --peer-ip "$WG_ULA_B" \
  --peer-pubkey "$PUBKEY_B" --peer-endpoint "${IP_B}:${WG_PORT}" --listen-port "$WG_PORT" \
  --extra-allowed "${WG_SUBNET_B}/32,${CLIENT_V4}/32,${CLIENT_V6}/128"
remote "$VM_B" setup-wg --self-ip "$WG_SUBNET_B" --peer-ip "$WG_SUBNET_A" \
  --peer-pubkey "$PUBKEY_A" --peer-endpoint "${IP_A}:${WG_PORT}" --listen-port "$WG_PORT"
remote "$VM_B" setup-wg --family 6 --self-ip "$WG_ULA_B" --peer-ip "$WG_ULA_A" \
  --peer-pubkey "$PUBKEY_A" --peer-endpoint "${IP_A}:${WG_PORT}" --listen-port "$WG_PORT" \
  --extra-allowed "${WG_SUBNET_A}/32"

limactl shell "$VM_A" -- ping -c 2 -W 2 "$WG_SUBNET_B" >/dev/null || {
  echo "FAIL: $VM_A cannot ping $VM_B over the WireGuard tunnel ($WG_SUBNET_B)" >&2
  exit 1
}
limactl shell "$VM_A" -- ping -6 -c 2 -W 2 "$WG_ULA_B" >/dev/null || {
  echo "FAIL: $VM_A cannot ping6 $VM_B over the WireGuard tunnel ($WG_ULA_B)" >&2
  exit 1
}
echo "WIREGUARD TUNNEL (v4+v6): PASS ($VM_A $WG_SUBNET_A/$WG_ULA_A <-> $VM_B $WG_SUBNET_B/$WG_ULA_B, over real underlay $IP_A/$IP_B)"

echo "==> [4/8] creating geneve0 on both nodes"
remote "$VM_A" setup-geneve
remote "$VM_B" setup-geneve

echo "==> [5/8] creating node-b's dual-stack backend Pod addresses + client netns"
remote "$VM_B" setup-backend --pod-ip "$POD_IP_V4" --pod-ip-v6 "$POD_IP_V6"
remote "$VM_B" setup-client-netns \
  --v4-root "$CLIENT_V4_ROOT" --v4-client "$CLIENT_V4" --v4-prefix "$CLIENT_V4_PREFIX" \
  --v6-root "$CLIENT_V6_ROOT" --v6-client "$CLIENT_V6" --v6-prefix "$CLIENT_V6_PREFIX"

echo "==> [6/8] loading beep-ebpf on both nodes with ONE dual-stack fixture set"
remote "$VM_A" start-loader --fixture "$FIXTURE_V4" --fixture "$FIXTURE_V6" \
  --pod-cidr "$POD_CIDR" --node-ip "$WG_SUBNET_A"
# --uplink-iface = the client veth, not wg0: node-b's own uplink_ingress
# must be the hook that first sees the client's packet, so this fixture's
# encap+decap self-loops entirely on node-b (this script's header explains
# why: NODE_ALLOW only ever admits a decap sourced from the decapsulating
# node's own --node-ip).
remote "$VM_B" start-loader --uplink-iface "$CLIENT_VETH" \
  --fixture "$FIXTURE_V4" --fixture "$FIXTURE_V6" --pod-cidr "$POD_CIDR" --node-ip "$WG_SUBNET_B"

remote "$VM_B" start-backend-responder --pod-ip "$POD_IP_V4" --port "$TARGET_PORT_V4" --family 4 --body "OK4"
remote "$VM_B" start-backend-responder --pod-ip "$POD_IP_V6" --port "$TARGET_PORT_V6" --family 6 --body "OK6"

echo "==> [7/8] driving a v4 client round trip: netns $CLIENT_NETNS ($CLIENT_V4) -> VIP ${WG_SUBNET_A}:${VIP_PORT}"
set +e
V4_BODY="$(limactl shell "$VM_B" -- sudo ip netns exec "$CLIENT_NETNS" curl -sS -4 -m 20 "http://${WG_SUBNET_A}:${VIP_PORT}/" 2>&1)"
V4_RC=$?
set -e
if [ "$V4_RC" -eq 0 ] && [ "$V4_BODY" = "OK4" ]; then
  echo "ROUND-TRIP-V4: PASS (client ${CLIENT_V4} -> VIP ${WG_SUBNET_A}:${VIP_PORT} -> backend ${POD_IP_V4}:${TARGET_PORT_V4} -> response 'OK4')"
else
  echo "ROUND-TRIP-V4: FAIL (curl rc=$V4_RC, body='$V4_BODY')" >&2
fi

echo "==> [8/8] driving a v6 client round trip: netns $CLIENT_NETNS ($CLIENT_V6) -> VIP [${WG_ULA_A}]:${VIP_PORT}"
set +e
V6_BODY="$(limactl shell "$VM_B" -- sudo ip netns exec "$CLIENT_NETNS" curl -sS -6 -m 20 "http://[${WG_ULA_A}]:${VIP_PORT}/" 2>&1)"
V6_RC=$?
set -e
if [ "$V6_RC" -eq 0 ] && [ "$V6_BODY" = "OK6" ]; then
  echo "ROUND-TRIP-V6: PASS (client ${CLIENT_V6} -> VIP [${WG_ULA_A}]:${VIP_PORT} -> backend [${POD_IP_V6}]:${TARGET_PORT_V6} -> response 'OK6')"
else
  echo "ROUND-TRIP-V6: FAIL (curl rc=$V6_RC, body='$V6_BODY')" >&2
fi

if [ "$V4_RC" -eq 0 ] && [ "$V4_BODY" = "OK4" ] && [ "$V6_RC" -eq 0 ] && [ "$V6_BODY" = "OK6" ]; then
  echo "GATE DUAL-STACK VIP ROUND TRIP: PASS (v4 and v6 clients both reached the same VIP_PORT ${VIP_PORT} off one fixture set)"
  exit 0
fi

echo ""
echo "==> at least one family did not complete -- collecting evidence"
echo "---- $VM_A evidence ----"
remote "$VM_A" dump-evidence
echo "---- $VM_B evidence ----"
remote "$VM_B" dump-evidence
exit 1
