#!/usr/bin/env bash
# Dual-stack sibling of scripts/smoke-wg-2node.sh: proves ONE fixture set --
# a v4 front and a v6 front on the same VIP_PORT, same backend node -- serves
# BOTH a v4 client AND a v6 client concurrently on the beep-node-a/
# beep-node-b rig, over a GENUINE cross-node round trip.
#
# Uses ONLY beep-node-a/beep-node-b, no 3rd client VM. The client for BOTH
# families runs in its own isolated netns on node-a (the VIP-owning ingress
# node) -- a veth pair, one end in node-a's default netns, the other in
# $CLIENT_NETNS -- the same isolation technique scripts/smoke-remote.sh's
# single-VM smoke-client netns already uses, chosen here so this node's own
# address is never also the packet's source, which is what martian-source-
# drops a co-located client.
#
# GENUINE cross-node, not a same-node self-loop: the client dials node-a's
# VIP, node-a's own loader Geneve-encapsulates and hands off to the KERNEL's
# wg0 route to node-b (a real WireGuard-encrypted hop over the real
# underlay), node-b decaps + DNATs + delivers to its local backend, and the
# backend's reply re-encaps and crosses wg0 right back. `--vm-a`/`--vm-b`
# each attach the OTHER 3 tc-bpf hooks accordingly; see
# smoke-wg-2node-remote.sh's $IPTNL_IFACE comment for exactly which device
# node-a's client-facing uplink is and why.
#
# NODE_ALLOW peer-node attestation (`beep_common::peer_node_admission`)
# makes a bare loader -- no controller, no Node watch -- admit a Geneve
# decap ONLY when its outer source equals the decapsulating node's OWN
# `--node-ip`, with no CLI knob to widen it to a genuinely different peer.
# This script fills that gap the same way a real cluster's controller would
# (Node-watch keeping NODE_ALLOW converged with the fleet's real peer set),
# just via a direct bpftool write on the loader's own pinned NODE_ALLOW map
# instead of a running controller: `dump-node-allow-key`/`seed-node-allow`
# below copy each node's own loader-computed self-key into the OTHER
# node's NODE_ALLOW, bidirectionally (the forward leg's decap needs it on
# node-b, the return leg's decap needs it on node-a) -- a pure test-side
# fixture, no loader/dataplane code change.
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
# Client-netns veth on node-a: root end stays in node-a's default netns,
# peer end is isolated in the netns the curl clients actually run in. Pure
# transport for the ipip/ip6tnl tunnels below now, not the client's own
# dialed address -- see smoke-wg-2node-remote.sh's $IPTNL_IFACE comment.
CLIENT_TRANSPORT_V4_ROOT="203.0.113.1"
CLIENT_TRANSPORT_V4_PEER="203.0.113.2"
CLIENT_TRANSPORT_V4_PREFIX="29"
CLIENT_TRANSPORT_V6_ROOT="fd00:beef:60::1"
CLIENT_TRANSPORT_V6_PEER="fd00:beef:60::2"
CLIENT_TRANSPORT_V6_PREFIX="64"
# The client's OWN address, from the ingress node's point of view: the
# ipip/ip6tnl tunnel's inner endpoint, layered on top of the transport veth
# above. This -- not $CLIENT_TRANSPORT_V4_PEER/_V6_PEER -- is what the
# backend must observe as the request's source for a genuine
# client-IP-preservation proof.
CLIENT_TUNNEL_V4_ROOT="203.0.115.1"
CLIENT_TUNNEL_V4="203.0.115.2"
CLIENT_TUNNEL_V4_PREFIX="30"
CLIENT_TUNNEL_V6_ROOT="fd00:beef:62::1"
CLIENT_TUNNEL_V6="fd00:beef:62::2"
CLIENT_TUNNEL_V6_PREFIX="64"
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

echo "==> [1/9] bringing up $VM_A and $VM_B"
for vm in "$VM_A" "$VM_B"; do
  if ! limactl list --format '{{.Name}}\t{{.Status}}' 2>/dev/null | grep -qE "^${vm}[[:space:]]+Running"; then
    limactl start "$vm"
  fi
  limactl shell "$vm" -- bash -c 'command -v wg >/dev/null || sudo apt-get install -y wireguard-tools' >/dev/null
done

echo "==> [2/9] cross-building beep-ebpf + beep (nightly + bpf-linker + zigbuild -> aarch64-unknown-linux-gnu)"
( cd "$BEEP_DIR" && cargo +nightly zigbuild --release --target aarch64-unknown-linux-gnu )
BIN="$BEEP_DIR/target/aarch64-unknown-linux-gnu/release/beep"
[ -x "$BIN" ] || { echo "FAIL: build did not produce $BIN" >&2; exit 1; }

for vm in "$VM_A" "$VM_B"; do
  limactl copy "$BIN" "$vm":"/tmp/${BIN_NAME}"
  limactl copy "$REMOTE_SCRIPT" "$vm":"/tmp/${BIN_NAME}-remote.sh"
  limactl shell "$vm" -- bash -c "chmod +x /tmp/${BIN_NAME} /tmp/${BIN_NAME}-remote.sh"
  remote "$vm" cleanup >/dev/null 2>&1 || true
done

echo "==> [3/9] establishing the dual-stack WireGuard tunnel between $VM_A and $VM_B"
IP_A="$(eth0_ip "$VM_A")"
IP_B="$(eth0_ip "$VM_B")"
[ -n "$IP_A" ] && [ -n "$IP_B" ] || {
  echo "FAIL: could not resolve eth0 addresses ($VM_A=$IP_A, $VM_B=$IP_B) -- are both VMs on the same Lima network?" >&2
  exit 1
}
# Each side's key pair is generated independently BEFORE either side's peer
# config is known. `wg set <iface> peer <pubkey> allowed-ips <list>`
# REPLACES that peer's whole allowed-ips list, not merges into it -- since
# the v4 and v6 calls below share the SAME peer pubkey (one wg0, one
# keypair per node, regardless of family), the SECOND (v6) call per node
# must re-list the FIRST (v4) call's own allowed-ips via `--extra-allowed`,
# or it silently evicts the v4 route (confirmed empirically: `ping -c 2
# $WG_SUBNET_B` failed `sendmsg: Required key not available` -- WireGuard's
# own error for a peer whose crypto-routing entry the v6 call had just
# narrowed away -- until this re-listing was restored).
PUBKEY_A="$(remote "$VM_A" pubkey)"
PUBKEY_B="$(remote "$VM_B" pubkey)"
remote "$VM_A" setup-wg --self-ip "$WG_SUBNET_A" --peer-ip "$WG_SUBNET_B" \
  --peer-pubkey "$PUBKEY_B" --peer-endpoint "${IP_B}:${WG_PORT}" --listen-port "$WG_PORT"
remote "$VM_A" setup-wg --family 6 --self-ip "$WG_ULA_A" --peer-ip "$WG_ULA_B" \
  --peer-pubkey "$PUBKEY_B" --peer-endpoint "${IP_B}:${WG_PORT}" --listen-port "$WG_PORT" \
  --extra-allowed "${WG_SUBNET_B}/32"
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

echo "==> [4/9] creating geneve0 on both nodes"
remote "$VM_A" setup-geneve
remote "$VM_B" setup-geneve

echo "==> [5/9] creating node-b's dual-stack backend Pod addresses + return routes, and node-a's client netns/tunnels"
# Host routes (/32, /128) straight to the client's own tunnel address, not
# its wider subnet: a route's own network prefix must have zero host bits
# beyond its mask (confirmed empirically -- `.../64 dev wg0` for a /64
# subnet whose $CLIENT_TUNNEL_V6_ROOT address is `::1`, not `::`, answered
# `Error: Invalid prefix for given prefix length`), and this rig only ever
# needs to reach the one client address anyway.
remote "$VM_B" setup-backend --pod-ip "$POD_IP_V4" --pod-ip-v6 "$POD_IP_V6" \
  --return-route "${CLIENT_TUNNEL_V4}/32" \
  --return-route "${CLIENT_TUNNEL_V6}/128"
remote "$VM_A" setup-client-netns \
  --v4-root "$CLIENT_TRANSPORT_V4_ROOT" --v4-client "$CLIENT_TRANSPORT_V4_PEER" --v4-prefix "$CLIENT_TRANSPORT_V4_PREFIX" \
  --v6-root "$CLIENT_TRANSPORT_V6_ROOT" --v6-client "$CLIENT_TRANSPORT_V6_PEER" --v6-prefix "$CLIENT_TRANSPORT_V6_PREFIX"
remote "$VM_A" setup-client-tunnels \
  --v4-transport-root "$CLIENT_TRANSPORT_V4_ROOT" --v4-transport-client "$CLIENT_TRANSPORT_V4_PEER" \
  --v4-inner-root "$CLIENT_TUNNEL_V4_ROOT" --v4-inner-client "$CLIENT_TUNNEL_V4" --v4-inner-prefix "$CLIENT_TUNNEL_V4_PREFIX" \
  --v6-transport-root "$CLIENT_TRANSPORT_V6_ROOT" --v6-transport-client "$CLIENT_TRANSPORT_V6_PEER" \
  --v6-inner-root "$CLIENT_TUNNEL_V6_ROOT" --v6-inner-client "$CLIENT_TUNNEL_V6" --v6-inner-prefix "$CLIENT_TUNNEL_V6_PREFIX"

echo "==> [6/9] loading beep-ebpf on both nodes with ONE dual-stack fixture set"
# --uplink-iface (repeated): node-a's client-facing uplinks are the
# ipip/ip6tnl tunnel devices setup-client-tunnels just created, NOT the
# transport veth directly -- see smoke-wg-2node-remote.sh's $IPTNL_IFACE
# comment for why a real-Ethernet uplink would drop the return leg's reply.
remote "$VM_A" start-loader --uplink-iface wg2ds-ipc0 --uplink-iface wg2ds-ip6c0 \
  --fixture "$FIXTURE_V4" --fixture "$FIXTURE_V6" --pod-cidr "$POD_CIDR" --node-ip "$WG_SUBNET_A"
remote "$VM_B" start-loader --fixture "$FIXTURE_V4" --fixture "$FIXTURE_V6" --pod-cidr "$POD_CIDR" --node-ip "$WG_SUBNET_B"

echo "==> [7/9] seeding NODE_ALLOW bidirectionally (mimics a controller's Node-watch, no bare-loader CLI knob exists)"
# This loader run's own key was just (re)computed by start-loader above --
# each node's own key only exists AFTER its loader starts (populate_fixtures
# prunes any pre-existing NODE_ALLOW entry not matching --node-ip), so this
# must run after step 6, not before.
NODE_A_KEY="$(remote "$VM_A" dump-node-allow-key)"
NODE_B_KEY="$(remote "$VM_B" dump-node-allow-key)"
remote "$VM_B" seed-node-allow --key-hex "$NODE_A_KEY"
remote "$VM_A" seed-node-allow --key-hex "$NODE_B_KEY"

remote "$VM_B" start-backend-responder --pod-ip "$POD_IP_V4" --port "$TARGET_PORT_V4" --family 4 --body "OK4"
remote "$VM_B" start-backend-responder --pod-ip "$POD_IP_V6" --port "$TARGET_PORT_V6" --family 6 --body "OK6"

# wg0-traversal evidence: a genuine cross-node round trip must move wg0's
# own packet counters (the same-node self-loop this rig replaces never did)
# -- snapshot before, diff after each round trip below.
WG_A_BEFORE="$(remote "$VM_A" wg-packet-count)"
WG_B_BEFORE="$(remote "$VM_B" wg-packet-count)"

echo "==> [8/9] driving a v4 client round trip: netns $CLIENT_NETNS ($CLIENT_TUNNEL_V4) -> VIP ${WG_SUBNET_A}:${VIP_PORT}"
set +e
V4_BODY="$(limactl shell "$VM_A" -- sudo ip netns exec "$CLIENT_NETNS" curl -sS -4 -m 20 "http://${WG_SUBNET_A}:${VIP_PORT}/" 2>&1)"
V4_RC=$?
set -e
if [ "$V4_RC" -eq 0 ] && [ "$V4_BODY" = "OK4" ]; then
  echo "ROUND-TRIP-V4: PASS (client ${CLIENT_TUNNEL_V4} -> VIP ${WG_SUBNET_A}:${VIP_PORT} -> backend ${POD_IP_V4}:${TARGET_PORT_V4} -> response 'OK4')"
else
  echo "ROUND-TRIP-V4: FAIL (curl rc=$V4_RC, body='$V4_BODY')" >&2
fi

echo "==> [9/9] driving a v6 client round trip: netns $CLIENT_NETNS ($CLIENT_TUNNEL_V6) -> VIP [${WG_ULA_A}]:${VIP_PORT}"
set +e
V6_BODY="$(limactl shell "$VM_A" -- sudo ip netns exec "$CLIENT_NETNS" curl -sS -6 -m 20 "http://[${WG_ULA_A}]:${VIP_PORT}/" 2>&1)"
V6_RC=$?
set -e
if [ "$V6_RC" -eq 0 ] && [ "$V6_BODY" = "OK6" ]; then
  echo "ROUND-TRIP-V6: PASS (client ${CLIENT_TUNNEL_V6} -> VIP [${WG_ULA_A}]:${VIP_PORT} -> backend [${POD_IP_V6}]:${TARGET_PORT_V6} -> response 'OK6')"
else
  echo "ROUND-TRIP-V6: FAIL (curl rc=$V6_RC, body='$V6_BODY')" >&2
fi

WG_A_AFTER="$(remote "$VM_A" wg-packet-count)"
WG_B_AFTER="$(remote "$VM_B" wg-packet-count)"
if [ "$WG_A_AFTER" -gt "$WG_A_BEFORE" ] && [ "$WG_B_AFTER" -gt "$WG_B_BEFORE" ]; then
  echo "WG0-TRAVERSAL: PASS ($VM_A wg0 packets $WG_A_BEFORE -> $WG_A_AFTER, $VM_B wg0 packets $WG_B_BEFORE -> $WG_B_AFTER -- both moved, so the round trip(s) above genuinely crossed wg0 in both directions, not a same-node self-loop)"
else
  echo "WG0-TRAVERSAL: FAIL ($VM_A wg0 packets $WG_A_BEFORE -> $WG_A_AFTER, $VM_B wg0 packets $WG_B_BEFORE -> $WG_B_AFTER)" >&2
fi

# The headline claim: the backend observes the CLIENT's real source address
# (nc -v's own "Connection received on <ip> <port>" accept log), not any
# NAT'd or node-local one. This -- not just a passing curl body -- is what
# beep exists to preserve across a real Geneve encap/decap round trip.
V4_LOG="$(limactl shell "$VM_B" -- cat "/tmp/wg2node-backend-${TARGET_PORT_V4}.log" 2>/dev/null || true)"
V6_LOG="$(limactl shell "$VM_B" -- cat "/tmp/wg2node-backend-${TARGET_PORT_V6}.log" 2>/dev/null || true)"
V4_CLIENT_IP_SEEN=false
V6_CLIENT_IP_SEEN=false
echo "$V4_LOG" | grep -q "Connection received on ${CLIENT_TUNNEL_V4} " && V4_CLIENT_IP_SEEN=true
echo "$V6_LOG" | grep -q "Connection received on ${CLIENT_TUNNEL_V6} " && V6_CLIENT_IP_SEEN=true
if [ "$V4_CLIENT_IP_SEEN" = true ] && [ "$V6_CLIENT_IP_SEEN" = true ]; then
  echo "CLIENT-IP-PRESERVATION: PASS (backend on $VM_B saw the real client source -- v4 ${CLIENT_TUNNEL_V4}, v6 ${CLIENT_TUNNEL_V6} -- not a NAT'd or node-local address)"
else
  echo "CLIENT-IP-PRESERVATION: FAIL (v4 seen=$V4_CLIENT_IP_SEEN, v6 seen=$V6_CLIENT_IP_SEEN)" >&2
  echo "-- v4 backend log --" >&2
  echo "$V4_LOG" >&2
  echo "-- v6 backend log --" >&2
  echo "$V6_LOG" >&2
fi

if [ "$V4_RC" -eq 0 ] && [ "$V4_BODY" = "OK4" ] && [ "$V6_RC" -eq 0 ] && [ "$V6_BODY" = "OK6" ] \
  && [ "$WG_A_AFTER" -gt "$WG_A_BEFORE" ] && [ "$WG_B_AFTER" -gt "$WG_B_BEFORE" ] \
  && [ "$V4_CLIENT_IP_SEEN" = true ] && [ "$V6_CLIENT_IP_SEEN" = true ]; then
  echo "GATE DUAL-STACK GENUINE CROSS-NODE ROUND TRIP: PASS (v4 and v6 clients both reached the same VIP_PORT ${VIP_PORT} off one fixture set, over a real wg0 hop, with client-IP preserved end to end)"
  exit 0
fi

echo ""
echo "==> at least one assertion above did not pass -- collecting evidence"
echo "---- $VM_A evidence ----"
remote "$VM_A" dump-evidence
echo "---- $VM_B evidence ----"
remote "$VM_B" dump-evidence
exit 1
