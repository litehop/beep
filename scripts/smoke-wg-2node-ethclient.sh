#!/usr/bin/env bash
# Regression rig for the try_geneve_decap_return L2-header bug: the final
# client-bound redirect must synthesize a valid L2 header when
# the egress uplink is real Ethernet, instead of carrying over the
# all-zero header geneve0's L3-only tunnel decap leaves on the packet
# (which gets eth_type_trans-classified PACKET_OTHERHOST and dropped on
# receipt at the other end).
#
# Sibling of scripts/smoke-wg-2node-dualstack.sh, with ONE deliberate
# difference: node-a's client-facing --uplink-iface is $CLIENT_VETH itself
# (wg2ds-veth0, ARPHRD_ETHER, created by smoke-wg-2node-remote.sh's
# setup-client-netns), not the ipip/ip6tnl tunnel setup-client-tunnels
# would otherwise layer on top of it. That tunnel device is ARPHRD_TUNNEL
# (no L2, no eth_type_trans check) -- precisely why the dualstack rig's
# round trip already passes without this fix and can't catch this bug.
# Skipping setup-client-tunnels here makes the veth pair itself node-a's
# uplink, so the client's own address is $CLIENT_VETH_PEER's directly
# (no tunnel-inner address layered on top).
#
# v4-only: the bug is family-agnostic (bites v4 and v6 alike per its own
# description); one family is enough to prove the redirect path. The
# --v6-* args below are supplied only because setup-client-netns's
# argument validation requires them -- never dialed.
#
# Usage: scripts/smoke-wg-2node-ethclient.sh [--vm-a <ingress-vm>] [--vm-b <backend-vm>]
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

# Same RFC 5737 documentation ranges as smoke-wg-2node-dualstack.sh.
WG_SUBNET_A="10.99.0.2"
WG_SUBNET_B="10.99.0.4"
WG_PORT="51820"
VIP_PORT="19100"
POD_IP="198.51.100.60"
POD_CIDR="198.51.100.0/24"
TARGET_PORT="18090"
# smoke-wg-2node-remote.sh's setup-client-netns hardcodes this veth pair's
# name ($CLIENT_VETH/$CLIENT_VETH_PEER) -- used directly as --uplink-iface
# below (ARPHRD_ETHER), unlike smoke-wg-2node-dualstack.sh which layers an
# L3-only ipip/ip6tnl tunnel on top of it and uplinks THAT instead.
CLIENT_UPLINK_IFACE="wg2ds-veth0"
CLIENT_ROOT="203.0.113.1"
CLIENT_ADDR="203.0.113.2"
CLIENT_PREFIX="29"
# Unused placeholders: setup-client-netns's argument validation requires
# non-empty v6 args regardless of which family this rig actually dials.
CLIENT_ROOT_V6="fd00:beef:60::1"
CLIENT_ADDR_V6="fd00:beef:60::2"
CLIENT_PREFIX_V6="64"
CLIENT_NETNS="smoke-wg2node-client"

FIXTURE="${WG_SUBNET_A}:${VIP_PORT}:tcp:${WG_SUBNET_B}:${POD_IP}:${TARGET_PORT}"

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

# Same retry rationale as smoke-wg-2node.sh's remote_retry.
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

echo "==> [3/8] establishing the WireGuard tunnel between $VM_A and $VM_B"
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

echo "==> [4/8] creating geneve0 on both nodes"
remote "$VM_A" setup-geneve
remote "$VM_B" setup-geneve

echo "==> [5/8] creating node-b's backend Pod address + return route, and node-a's client netns/veth (Ethernet, no tunnel layer)"
remote "$VM_B" setup-backend --pod-ip "$POD_IP" --return-route "${CLIENT_ADDR}/32"
remote "$VM_A" setup-client-netns \
  --v4-root "$CLIENT_ROOT" --v4-client "$CLIENT_ADDR" --v4-prefix "$CLIENT_PREFIX" \
  --v6-root "$CLIENT_ROOT_V6" --v6-client "$CLIENT_ADDR_V6" --v6-prefix "$CLIENT_PREFIX_V6"

echo "==> [6/8] loading beep-ebpf: $VM_A uplink=$CLIENT_UPLINK_IFACE (real Ethernet veth -- the L2 header this bug is about)"
remote "$VM_A" start-loader --uplink-iface "$CLIENT_UPLINK_IFACE" \
  --fixture "$FIXTURE" --pod-cidr "$POD_CIDR" --node-ip "$WG_SUBNET_A"
remote "$VM_B" start-loader --fixture "$FIXTURE" --pod-cidr "$POD_CIDR" --node-ip "$WG_SUBNET_B"

echo "==> [7/8] seeding NODE_ALLOW bidirectionally (mimics a controller's Node-watch, no bare-loader CLI knob exists)"
NODE_A_KEY="$(remote "$VM_A" dump-node-allow-key)"
NODE_B_KEY="$(remote "$VM_B" dump-node-allow-key)"
remote "$VM_B" seed-node-allow --key-hex "$NODE_A_KEY"
remote "$VM_A" seed-node-allow --key-hex "$NODE_B_KEY"

remote "$VM_B" start-backend-responder --pod-ip "$POD_IP" --port "$TARGET_PORT"

# wg0-traversal evidence: a genuine cross-node round trip must move wg0's
# own packet counters, same as smoke-wg-2node-dualstack.sh's check.
WG_A_BEFORE="$(remote "$VM_A" wg-packet-count)"
WG_B_BEFORE="$(remote "$VM_B" wg-packet-count)"

echo "==> [8/8] driving a client round trip: netns $CLIENT_NETNS ($CLIENT_ADDR) -> VIP ${WG_SUBNET_A}:${VIP_PORT} -- return leg redirects onto real Ethernet $CLIENT_UPLINK_IFACE"
set +e
BODY="$(limactl shell "$VM_A" -- sudo ip netns exec "$CLIENT_NETNS" curl -sS -4 -m 20 "http://${WG_SUBNET_A}:${VIP_PORT}/" 2>&1)"
RC=$?
set -e
if [ "$RC" -eq 0 ] && [ "$BODY" = "OK" ]; then
  echo "ROUND-TRIP: PASS (client ${CLIENT_ADDR} -> VIP ${WG_SUBNET_A}:${VIP_PORT} -> backend ${POD_IP}:${TARGET_PORT} -> response 'OK')"
else
  echo "ROUND-TRIP: FAIL (curl rc=$RC, body='$BODY')" >&2
fi

WG_A_AFTER="$(remote "$VM_A" wg-packet-count)"
WG_B_AFTER="$(remote "$VM_B" wg-packet-count)"
if [ "$WG_A_AFTER" -gt "$WG_A_BEFORE" ] && [ "$WG_B_AFTER" -gt "$WG_B_BEFORE" ]; then
  echo "WG0-TRAVERSAL: PASS ($VM_A wg0 packets $WG_A_BEFORE -> $WG_A_AFTER, $VM_B wg0 packets $WG_B_BEFORE -> $WG_B_AFTER)"
else
  echo "WG0-TRAVERSAL: FAIL ($VM_A wg0 packets $WG_A_BEFORE -> $WG_A_AFTER, $VM_B wg0 packets $WG_B_BEFORE -> $WG_B_AFTER)" >&2
fi

if [ "$RC" -eq 0 ] && [ "$BODY" = "OK" ] \
  && [ "$WG_A_AFTER" -gt "$WG_A_BEFORE" ] && [ "$WG_B_AFTER" -gt "$WG_B_BEFORE" ]; then
  echo "GATE ETH-CLIENT-EGRESS RETURN-LEG L2: PASS (client-bound redirect onto a real Ethernet uplink delivered the reply -- the L2 header try_geneve_decap_return synthesizes for it is valid)"
  exit 0
fi

echo ""
echo "==> at least one assertion above did not pass -- collecting evidence"
echo "---- $VM_A evidence ----"
remote "$VM_A" dump-evidence
echo "---- $VM_B evidence ----"
remote "$VM_B" dump-evidence
exit 1
