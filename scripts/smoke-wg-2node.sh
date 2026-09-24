#!/usr/bin/env bash
# Tier-1 eBPF beep cross-node harness: 2 real Lima VMs linked by a real
# WireGuard tunnel, standing in for the operator's fleet's WireGuard/
# Tailscale mesh (`docs/design/ebpf-lb-dataplane.md`'s "Must work
# across four underlay scenarios ... WireGuard/Tailscale mesh"). Unlike
# scripts/smoke.sh (one VM, a local veth pair standing in for a
# client), this drives Geneve encap/decap across TWO real kernels connected
# by a real wg0 uplink -- the scenario beep-ebpf's L2-header-skip fix
# (`beep_common::uplink_l2_header_len`) targets.
#
# A prior redirect/verifier drop on this rig's original bpf_redirect(wg0 ->
# geneve0) path has since been fixed. That fix then exposed a second,
# downstream problem: with only 2 nodes, the "client" had to be node-b's
# own root netns, so after decap+DNAT the packet's src (node-b's own wg0
# address) collided with pod_ip (also bound on node-b's own lo) -- both
# local to node-b, so the kernel martian-dropped it at ip_rcv_finish_core.
# Real deployments never collide a client address with the backend node's
# own address; this was purely this rig's own topology.
#
# FIX: the client is now beep-client (lima/beep-client.yaml), a genuinely
# separate 3rd VM non-local to either node -- the same fix already applied
# to scripts/smoke-eth-ingress-2node.sh. beep-client never runs WireGuard
# itself (see that profile's header), so it cannot dial node-a's wg0 VIP
# directly; node-b relays the client's plain SYN into the tunnel as an
# ordinary IP forward (ip_forward=1, set up below), and node-a's WireGuard
# peer entry for node-b is widened (--extra-allowed) to admit the client's
# real source address past WireGuard's own crypto-routing source filter.
# The client's SYN therefore still arrives at node-a genuinely
# WireGuard-decrypted on wg0 -- the exact mechanism under test -- while its
# source is no longer local to node-b.
#
# SECOND FIX: the above still self-looped on node-b. node-b's own
# `--uplink-iface eth0` gave it a `uplink_ingress` classifier on the SAME
# device the client's SYN transits en route to node-a -- and LB_FRONT_MAP is
# deliberately unfiltered by node ownership (any node can be ingress for any
# VIP, so TARGET_PORTS' forward-decap lookup on the real backend node needs
# the real front's key regardless of which node "owns" that VIP) -- so
# node-b's eth0 ingress matched the in-transit SYN and Geneve-encapped it to
# itself before it ever reached node-a. The client's packet never crossed
# wg0 at all (confirmed: wg0 rx/tx counters unchanged, node-a's FLOW_TABLE
# empty). In a real WireGuard/Tailscale mesh this can't happen: every node
# has a direct peer-to-peer tunnel to every other node, so node-a's traffic
# never transits a third node as an incidental router. beep-client's lack of
# a WireGuard identity of its own is what forces this rig to relay through
# node-b at all -- so the fix keeps that relay (unavoidable with a 2-node
# mesh and a non-mesh-member client) but stops it from ALSO being a beep
# admission point: node-b no longer takes `--uplink-iface eth0` (defaults to
# wg0, its real per-node-owned uplink), so its `uplink_ingress`/
# `uplink_egress_return` hooks never see the client's raw, un-tunneled SYN
# at all -- that packet is now a plain, un-intercepted kernel IP-forward
# hop, exactly like a real intermediate router that isn't running beep. The
# backend pod's own reply is forced onto wg0 (not eth0's connected LAN
# route) via `setup-backend --return-route`, so node-b's egress-return hook
# -- now on wg0 -- still catches it and re-Geneves it back to node-a
# symmetrically. NODE_ALLOW is seeded bidirectionally right after each
# node's own loader starts (mimics a controller's Node-watch, no bare-loader
# CLI knob exists) since BOTH directions now genuinely cross wg0 with the
# real peer's address, not a self-loop. Verified genuinely cross-node below:
# wg0 rx/tx packet counters move on BOTH nodes, and node-a's FLOW_TABLE
# gains an entry it didn't have before the round trip.
#
# Usage: scripts/smoke-wg-2node.sh [--vm-a <ingress-vm>] [--vm-b <backend-vm>] [--vm-client <client-vm>] [--family 4|6]
# Defaults match this rig's assigned VMs: beep-node-a (ingress, owns the
# VIP), beep-node-b (backend Pod + the client's WireGuard relay), beep-client
# (client). All three VMs must be on the SAME Lima network (directly
# reachable over their real eth0/underlay) so the WireGuard handshake has a
# path to establish -- WireGuard is the L3 uplink under test here, not a
# substitute for underlay reachability.
#
# --family 6: proves WireGuard's tunnel carries IPv6 end-to-end between
# vm-a and vm-b, using a static ULA on each side of wg0 (Lima's own
# network hands out v6 link-local only, never anything routable -- see
# lima-ipv6-reconciled-with-u7s), THEN continues into a full v6-UNDERLAY
# beep dataplane round trip: --node-ip/the fixture's
# backend_node_ip/the VIP itself are all wg0's own v6 ULA, so the Geneve
# tunnel's outer encap/decap -- not just WireGuard's transport -- runs over
# v6 end to end. vm-client relays through vm-b exactly like the v4 rig
# below, over a second, separate v6 ULA statically assigned to vm-b's and
# vm-client's real LAN NIC (again because Lima hands out v6 link-local
# only there too).
#
# Same host prerequisites as smoke.sh (nightly + rust-src + bpf-linker +
# cargo-zigbuild); VM prerequisites: bpftool (already present) plus
# `wireguard-tools` (installed automatically below via apt if missing) and
# `trace-cmd` for evidence capture on failure. beep-client has no MCP server
# and never runs the dataplane/WG -- it's driven directly via `limactl
# shell` from this host script, not via the remote.sh subcommand protocol
# node-a/node-b use.
set -euo pipefail

VM_A="beep-node-a"
VM_B="beep-node-b"
VM_CLIENT="beep-client"
FAMILY="4"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vm-a) VM_A="$2"; shift 2 ;;
    --vm-b) VM_B="$2"; shift 2 ;;
    --vm-client) VM_CLIENT="$2"; shift 2 ;;
    --family) FAMILY="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done
[[ "$FAMILY" == "4" || "$FAMILY" == "6" ]] || {
  echo "FAIL: --family must be 4 or 6, got '$FAMILY'" >&2
  exit 1
}
# Peer attestation regression check, default-on: once the rig's
# self-loop was fixed (this script's header), a live run confirmed
# `geneve_ingress`'s peer attestation (`beep_common::peer_node_admission`)
# genuinely admits a peer-only NODE_ALLOW and genuinely drops a self-only
# one against a real cross-node packet -- there is no dataplane bug (see
# `bd memories wg-2node-rig-self-loop`), so this now runs unconditionally as
# part of the default gate rather than behind an opt-in flag.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BEEP_DIR="$REPO_ROOT"
REMOTE_SCRIPT="$SCRIPT_DIR/smoke-wg-2node-remote.sh"
BIN_NAME="beep-wg2node"

# RFC 5737 documentation ranges + a 10.99.0.0/24 tunnel subnet deliberately
# disjoint from either VM's real eth0/cni0 ranges.
WG_SUBNET_A="10.99.0.2"
WG_SUBNET_B="10.99.0.4"
# fd00:beef:99::/64 ULA, disjoint from any real prefix -- statically assigned
# since Lima's network never hands out routable v6 (no RA/DHCPv6, see this
# script's --family 6 header note).
WG_ULA_A="fd00:beef:99::2"
WG_ULA_B="fd00:beef:99::4"
WG_PORT="51820"
VIP_PORT="19100"
POD_IP="198.51.100.60"
POD_CIDR="198.51.100.0/24"
TARGET_PORT="18090"
UPLINK_IFACE_B="eth0"
# v6-underlay-only: a SEPARATE v6 ULA from WG_ULA_A/B's own
# tunnel-inner prefix, statically assigned to vm-b's and vm-client's real
# LAN NIC (eth0) so vm-client's relay-via-vm-b leg has a routable v6
# next-hop -- the same role $IP_B/$IP_CLIENT play for the v4 rig's relay
# below, needed here too since Lima's shared network never hands out a
# routable v6 address of its own (this script's --family 6 header note).
LAN_ULA_B="fd00:beef:98::4"
LAN_ULA_CLIENT="fd00:beef:98::14"
POD_IP_V6="fd00:beef:60::60"
POD_CIDR_V6="fd00:beef:60::/64"

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

STEP_TOTAL=8
[ "$FAMILY" = "6" ] && STEP_TOTAL=10
echo "==> [1/$STEP_TOTAL] bringing up $VM_A, $VM_B, and $VM_CLIENT"
for vm in "$VM_A" "$VM_B"; do
  if ! limactl list --format '{{.Name}}\t{{.Status}}' 2>/dev/null | grep -qE "^${vm}[[:space:]]+Running"; then
    limactl start "$vm"
  fi
  limactl shell "$vm" -- bash -c 'command -v wg >/dev/null || sudo apt-get install -y wireguard-tools' >/dev/null
done
if ! limactl list --format '{{.Name}}\t{{.Status}}' 2>/dev/null | grep -qE "^${VM_CLIENT}[[:space:]]+Running"; then
  limactl start "$VM_CLIENT"
fi

# --family 6 now drives a full beep dataplane round trip too (not just the
# WireGuard transport check), so both families need the cross-built binary
# on both nodes.
echo "==> [2/$STEP_TOTAL] cross-building beep-ebpf + beep (nightly + bpf-linker + zigbuild -> aarch64-unknown-linux-gnu)"
( cd "$BEEP_DIR" && cargo +nightly zigbuild --release --target aarch64-unknown-linux-gnu )
BIN="$BEEP_DIR/target/aarch64-unknown-linux-gnu/release/beep"
[ -x "$BIN" ] || { echo "FAIL: build did not produce $BIN" >&2; exit 1; }

for vm in "$VM_A" "$VM_B"; do
  limactl copy "$BIN" "$vm":"/tmp/${BIN_NAME}"
  limactl copy "$REMOTE_SCRIPT" "$vm":"/tmp/${BIN_NAME}-remote.sh"
  limactl shell "$vm" -- bash -c "chmod +x /tmp/${BIN_NAME} /tmp/${BIN_NAME}-remote.sh"
  remote "$vm" cleanup >/dev/null 2>&1 || true
done

echo "==> [3/$STEP_TOTAL] establishing the real WireGuard tunnel between $VM_A and $VM_B, plus $VM_CLIENT's relay route"
IP_A="$(eth0_ip "$VM_A")"
IP_B="$(eth0_ip "$VM_B")"
[ -n "$IP_A" ] && [ -n "$IP_B" ] || {
  echo "FAIL: could not resolve eth0 addresses ($VM_A=$IP_A, $VM_B=$IP_B) -- are both VMs on the same Lima network?" >&2
  exit 1
}
IP_CLIENT="$(eth0_ip "$VM_CLIENT")"
[ -n "$IP_CLIENT" ] || {
  echo "FAIL: could not resolve eth0 address for $VM_CLIENT -- is it on the same Lima network?" >&2
  exit 1
}
# Each side's key pair is generated independently BEFORE either side's peer
# config is known -- avoids a chicken-and-egg ordering (setup-wg needs the
# PEER's pubkey as an argument, so both pubkeys must exist first).
PUBKEY_A="$(remote "$VM_A" pubkey)"
PUBKEY_B="$(remote "$VM_B" pubkey)"
if [ "$FAMILY" = "6" ]; then
  # --extra-allowed: $VM_CLIENT relays into the v6 tunnel via $VM_B's plain
  # IP forward exactly like the v4 path below, over a SEPARATE v6 ULA on
  # their shared LAN NIC ($LAN_ULA_B/$LAN_ULA_CLIENT, assigned in step
  # [4/9]) -- $VM_A's peer entry for $VM_B must admit that address too, or
  # WireGuard's own crypto-routing source filter drops the relayed,
  # client-sourced packet on decrypt before beep ever sees it.
  remote "$VM_A" setup-wg --family 6 --self-ip "$WG_ULA_A" --peer-ip "$WG_ULA_B" \
    --peer-pubkey "$PUBKEY_B" --peer-endpoint "${IP_B}:${WG_PORT}" --listen-port "$WG_PORT" \
    --extra-allowed "${LAN_ULA_CLIENT}/128"
  remote "$VM_B" setup-wg --family 6 --self-ip "$WG_ULA_B" --peer-ip "$WG_ULA_A" \
    --peer-pubkey "$PUBKEY_A" --peer-endpoint "${IP_A}:${WG_PORT}" --listen-port "$WG_PORT"

  limactl shell "$VM_A" -- ping -6 -c 2 -W 2 "$WG_ULA_B" >/dev/null || {
    echo "FAIL: $VM_A cannot ping6 $VM_B over the WireGuard tunnel ($WG_ULA_B)" >&2
    exit 1
  }
  echo "WIREGUARD TUNNEL (v6): PASS ($VM_A $WG_ULA_A <-> $VM_B $WG_ULA_B, over real v4 underlay $IP_A/$IP_B)"

  echo "==> [4/10] giving $VM_B and $VM_CLIENT a shared v6 ULA on their real LAN NIC (Lima hands out v6 link-local only)"
  limactl shell "$VM_B" -- sudo ip -6 addr replace "${LAN_ULA_B}/64" dev eth0
  limactl shell "$VM_CLIENT" -- sudo ip -6 addr replace "${LAN_ULA_CLIENT}/64" dev eth0
  # Lima's vz shared-network backend doesn't propagate IPv6 multicast
  # between sibling VMs (confirmed empirically: tcpdump on $VM_B's eth0
  # sees ZERO packets for a neighbor solicitation $VM_CLIENT sends), so
  # NDP -- multicast-based, unlike ARP's broadcast -- can never resolve
  # either side's link-layer address on this LAN segment. A static neigh
  # entry sidesteps NDP outright; both MACs are already known, so nothing
  # is actually being discovered here that this script doesn't already have.
  MAC_B="$(limactl shell "$VM_B" -- bash -c "ip link show eth0 | awk '/link\/ether/{print \$2}'")"
  MAC_CLIENT="$(limactl shell "$VM_CLIENT" -- bash -c "ip link show eth0 | awk '/link\/ether/{print \$2}'")"
  limactl shell "$VM_B" -- sudo ip -6 neigh replace "$LAN_ULA_CLIENT" lladdr "$MAC_CLIENT" dev eth0 nud permanent
  limactl shell "$VM_CLIENT" -- sudo ip -6 neigh replace "$LAN_ULA_B" lladdr "$MAC_B" dev eth0 nud permanent

  echo "==> [5/10] creating geneve0 on both nodes"
  remote "$VM_A" setup-geneve
  remote "$VM_B" setup-geneve

  echo "==> [6/10] confirming $VM_B's real underlay NIC name (must not be assumed)"
  IFACE_B_ACTUAL="$(limactl shell "$VM_B" -- bash -c "ip -4 -o addr show eth0 | awk '{print \$2; exit}'")"
  [ "$IFACE_B_ACTUAL" = "$UPLINK_IFACE_B" ] || {
    echo "FAIL: expected $VM_B's user-v2 NIC to be '$UPLINK_IFACE_B', found '$IFACE_B_ACTUAL' -- update UPLINK_IFACE_B" >&2
    exit 1
  }
  echo "UPLINK-IFACE-NAME: PASS ($VM_B's user-v2 NIC is $UPLINK_IFACE_B)"

  # VIP, --node-ip, and the fixture's backend_node_ip are all wg0's v6 ULA,
  # so the Geneve tunnel's outer SET (set_tunnel_remote) and GET
  # (get_tunnel_key/tunnel_remote) both run their v6 arm end to end,
  # not just WireGuard's own v6-agnostic transport.
  echo "==> [7/10] loading beep-ebpf with a v6-underlay --node-ip on both nodes ($VM_B uplink=wg0 default, NOT eth0 -- see this script's header on why eth0 there self-looped)"
  FIXTURE_V6="[${WG_ULA_A}]:${VIP_PORT}:tcp:[${WG_ULA_B}]:[${POD_IP_V6}]:${TARGET_PORT}"
  remote "$VM_A" start-loader --fixture "$FIXTURE_V6" --pod-cidr "$POD_CIDR_V6" --node-ip "$WG_ULA_A"
  remote "$VM_B" start-loader --fixture "$FIXTURE_V6" --pod-cidr "$POD_CIDR_V6" --node-ip "$WG_ULA_B"

  echo "==> [8/10] seeding NODE_ALLOW bidirectionally (mimics a controller's Node-watch, no bare-loader CLI knob exists) and starting the v6 backend"
  # Each node's own key only exists AFTER its loader (re)starts above
  # (populate_fixtures prunes any pre-existing NODE_ALLOW entry not matching
  # --node-ip), and must be captured HERE, before either map holds more than
  # one entry -- dump-node-allow-key returns bpftool's first dumped entry,
  # which is only unambiguously "this node's own key" while it's the only
  # entry present.
  NODE_A_KEY="$(remote "$VM_A" dump-node-allow-key)"
  NODE_B_KEY="$(remote "$VM_B" dump-node-allow-key)"
  remote "$VM_B" seed-node-allow --key-hex "$NODE_A_KEY"
  remote "$VM_A" seed-node-allow --key-hex "$NODE_B_KEY"
  # --return-route: $VM_B's pod reply (dst=$VM_CLIENT's real LAN address)
  # would otherwise take $VM_B's connected-LAN route out eth0 -- a device
  # with no beep hook on it anymore -- leaking the un-DNAT'd reply straight
  # to the client instead of symmetrically re-Geneving it back to $VM_A.
  # Forcing it via wg0 (where $VM_B's uplink_egress_return now actually
  # lives) restores that.
  remote "$VM_B" setup-backend --pod-ip-v6 "$POD_IP_V6" --return-route "${LAN_ULA_CLIENT}/128"
  remote "$VM_B" start-backend-responder --pod-ip "$POD_IP_V6" --port "$TARGET_PORT" --family 6

  echo "==> [9/10] routing $VM_CLIENT's v6 traffic to the VIP via $VM_B's relay"
  limactl shell "$VM_CLIENT" -- sudo ip -6 route replace "${WG_ULA_A}/128" via "$LAN_ULA_B"

  # wg0-traversal + FLOW_TABLE evidence: a genuine cross-node round trip
  # must move wg0's own packet counters on BOTH nodes and leave $VM_A's
  # FLOW_TABLE holding an entry it didn't have before -- the same-node
  # self-loop this rig replaces did neither (see this script's header).
  WG_A_BEFORE="$(remote "$VM_A" wg-packet-count)"
  WG_B_BEFORE="$(remote "$VM_B" wg-packet-count)"
  FLOW_A_BEFORE="$(remote "$VM_A" flow-table-count)"
  remote "$VM_A" start-tcpdump wg0
  remote "$VM_B" start-tcpdump wg0

  echo "==> [10/10] driving one client ($VM_CLIENT) -> v6 VIP (over wg0 ingress, via $VM_B's relay) -> cross-node backend round trip"
  set +e
  CLIENT_BODY="$(limactl shell "$VM_CLIENT" -- curl -sS -m 20 "http://[${WG_ULA_A}]:${VIP_PORT}/" 2>&1)"
  CLIENT_RC=$?
  set -e
  WG_A_AFTER="$(remote "$VM_A" wg-packet-count)"
  WG_B_AFTER="$(remote "$VM_B" wg-packet-count)"
  FLOW_A_AFTER="$(remote "$VM_A" flow-table-count)"

  if [ "$CLIENT_RC" -eq 0 ] && [ "$CLIENT_BODY" = "OK" ] \
    && [ "$WG_A_AFTER" -gt "$WG_A_BEFORE" ] && [ "$WG_B_AFTER" -gt "$WG_B_BEFORE" ] \
    && [ "$FLOW_A_AFTER" -gt "$FLOW_A_BEFORE" ]; then
    echo "ROUND-TRIP (v6 underlay): PASS (client $VM_CLIENT -> VIP [${WG_ULA_A}]:${VIP_PORT} -> cross-node backend -> response 'OK')"
    echo "WG0-TRAVERSAL (v6): PASS ($VM_A wg0 packets $WG_A_BEFORE -> $WG_A_AFTER, $VM_B wg0 packets $WG_B_BEFORE -> $WG_B_AFTER -- both moved, not a same-node self-loop)"
    echo "FLOW-TABLE (v6): PASS ($VM_A FLOW_TABLE entries $FLOW_A_BEFORE -> $FLOW_A_AFTER)"
    echo "GATE: V6-UNDERLAY DATAPLANE: PASS (family-aware Geneve tunnel-key GET/SET proven end to end over a genuinely cross-node v6 underlay)"
    exit 0
  fi
  echo "ROUND-TRIP (v6 underlay): FAIL (curl rc=$CLIENT_RC, body='$CLIENT_BODY', wg0 $VM_A $WG_A_BEFORE->$WG_A_AFTER, $VM_B $WG_B_BEFORE->$WG_B_AFTER, FLOW_TABLE(a) $FLOW_A_BEFORE->$FLOW_A_AFTER)" >&2
  echo ""
  echo "==> round trip did not complete -- collecting evidence"
  echo "---- $VM_A wg0 tcpdump ----"
  remote "$VM_A" dump-tcpdump wg0
  echo "---- $VM_B wg0 tcpdump ----"
  remote "$VM_B" dump-tcpdump wg0
  echo "---- $VM_A evidence ----"
  remote "$VM_A" dump-evidence
  echo "---- $VM_B evidence ----"
  remote "$VM_B" dump-evidence
  exit 1
fi
# --extra-allowed: $VM_CLIENT never runs WireGuard itself (lima/beep-client.yaml),
# so it can't dial $VM_A's wg0 VIP directly -- $VM_B relays its plain SYN
# into the tunnel as an ordinary IP forward (ip_forward=1, set up in
# setup-backend below). Without widening $VM_A's peer entry for $VM_B past
# $WG_SUBNET_B/32, WireGuard's own crypto-routing source filter would drop
# the relayed, client-sourced packet on decrypt before beep ever sees it.
remote "$VM_A" setup-wg --self-ip "$WG_SUBNET_A" --peer-ip "$WG_SUBNET_B" \
  --peer-pubkey "$PUBKEY_B" --peer-endpoint "${IP_B}:${WG_PORT}" --listen-port "$WG_PORT" \
  --extra-allowed "${IP_CLIENT}/32"
remote "$VM_B" setup-wg --self-ip "$WG_SUBNET_B" --peer-ip "$WG_SUBNET_A" \
  --peer-pubkey "$PUBKEY_A" --peer-endpoint "${IP_A}:${WG_PORT}" --listen-port "$WG_PORT"

limactl shell "$VM_A" -- ping -c 2 -W 2 "$WG_SUBNET_B" >/dev/null || {
  echo "FAIL: $VM_A cannot ping $VM_B over the WireGuard tunnel ($WG_SUBNET_B)" >&2
  exit 1
}
echo "WIREGUARD TUNNEL: PASS ($VM_A $WG_SUBNET_A <-> $VM_B $WG_SUBNET_B, over real underlay $IP_A/$IP_B)"

# $VM_CLIENT's only path to the VIP is through $VM_B's relay -- $VM_B is
# directly reachable on the shared user-v2 subnet, but the WG-only VIP
# subnet is not, so this route is required, not incidental.
limactl shell "$VM_CLIENT" -- sudo ip route replace "${WG_SUBNET_A}/32" via "$IP_B"

echo "==> [4/8] creating geneve0 on both nodes"
remote "$VM_A" setup-geneve
remote "$VM_B" setup-geneve

echo "==> [5/8] confirming $VM_B's real underlay NIC name (must not be assumed)"
IFACE_B_ACTUAL="$(limactl shell "$VM_B" -- bash -c "ip -4 -o addr show eth0 | awk '{print \$2; exit}'")"
[ "$IFACE_B_ACTUAL" = "$UPLINK_IFACE_B" ] || {
  echo "FAIL: expected $VM_B's user-v2 NIC to be '$UPLINK_IFACE_B', found '$IFACE_B_ACTUAL' -- update UPLINK_IFACE_B" >&2
  exit 1
}
echo "UPLINK-IFACE-NAME: PASS ($VM_B's user-v2 NIC is $UPLINK_IFACE_B)"

echo "==> [6/8] loading beep-ebpf: $VM_A uplink=wg0 (the mechanism under test), $VM_B uplink=wg0 default too (NOT $UPLINK_IFACE_B -- see this script's header on why eth0 there self-looped)"
FIXTURE="${WG_SUBNET_A}:${VIP_PORT}:tcp:${WG_SUBNET_B}:${POD_IP}:${TARGET_PORT}"
remote "$VM_A" start-loader --fixture "$FIXTURE" --pod-cidr "$POD_CIDR" --node-ip "$WG_SUBNET_A"
remote "$VM_B" start-loader --fixture "$FIXTURE" --pod-cidr "$POD_CIDR" --node-ip "$WG_SUBNET_B"

echo "==> [7/8] seeding NODE_ALLOW bidirectionally (mimics a controller's Node-watch, no bare-loader CLI knob exists) and starting the backend"
# Each node's own key only exists AFTER its loader (re)starts above
# (populate_fixtures prunes any pre-existing NODE_ALLOW entry not matching
# --node-ip), and must be captured HERE, before either map holds more than
# one entry -- dump-node-allow-key returns bpftool's first dumped entry,
# which is only unambiguously "this node's own key" while it's the only
# entry present.
NODE_A_KEY="$(remote "$VM_A" dump-node-allow-key)"
NODE_B_KEY="$(remote "$VM_B" dump-node-allow-key)"
remote "$VM_B" seed-node-allow --key-hex "$NODE_A_KEY"
remote "$VM_A" seed-node-allow --key-hex "$NODE_B_KEY"
# --return-route: $VM_B's pod reply (dst=$VM_CLIENT's real LAN address)
# would otherwise take $VM_B's connected-LAN route out $UPLINK_IFACE_B -- a
# device with no beep hook on it anymore -- leaking the un-DNAT'd reply
# straight to the client instead of symmetrically re-Geneving it back to
# $VM_A. Forcing it via wg0 (where $VM_B's uplink_egress_return now
# actually lives) restores that.
remote "$VM_B" setup-backend --pod-ip "$POD_IP" --return-route "${IP_CLIENT}/32"
remote "$VM_B" start-backend-responder --pod-ip "$POD_IP" --port "$TARGET_PORT"

# wg0-traversal + FLOW_TABLE evidence: a genuine cross-node round trip must
# move wg0's own packet counters on BOTH nodes and leave $VM_A's FLOW_TABLE
# holding an entry it didn't have before -- the same-node self-loop this
# rig replaces did neither (see this script's header).
WG_A_BEFORE="$(remote "$VM_A" wg-packet-count)"
WG_B_BEFORE="$(remote "$VM_B" wg-packet-count)"
FLOW_A_BEFORE="$(remote "$VM_A" flow-table-count)"
remote "$VM_A" start-tcpdump wg0
remote "$VM_B" start-tcpdump wg0

echo "==> [8/8] driving one client ($VM_CLIENT) -> VIP (over wg0 ingress, via $VM_B's relay) -> cross-node backend round trip"
# Client = the genuinely separate beep-client VM dialing $VM_A's VIP --
# driven directly via limactl, not the remote.sh subcommand protocol
# (beep-client has no /tmp/${BIN_NAME}-remote.sh copy and no MCP server;
# see this script's header). A 20s cap, not 5s: the first connection pays
# for the relay's ARP resolution plus the WG tunnel's own handshake, so the
# first SYN(-ACK) round trip alone can take several seconds -- confirmed
# empirically on the sibling eth-ingress rig, a 5s cap flakes on a cold rig
# even though the dataplane mechanism itself is correct.
set +e
CLIENT_BODY="$(limactl shell "$VM_CLIENT" -- curl -sS -m 20 "http://${WG_SUBNET_A}:${VIP_PORT}/" 2>&1)"
CLIENT_RC=$?
set -e
WG_A_AFTER="$(remote "$VM_A" wg-packet-count)"
WG_B_AFTER="$(remote "$VM_B" wg-packet-count)"
FLOW_A_AFTER="$(remote "$VM_A" flow-table-count)"

if [ "$CLIENT_RC" -eq 0 ] && [ "$CLIENT_BODY" = "OK" ] \
  && [ "$WG_A_AFTER" -gt "$WG_A_BEFORE" ] && [ "$WG_B_AFTER" -gt "$WG_B_BEFORE" ] \
  && [ "$FLOW_A_AFTER" -gt "$FLOW_A_BEFORE" ]; then
  echo "ROUND-TRIP: PASS (client $VM_CLIENT -> VIP ${WG_SUBNET_A}:${VIP_PORT} -> cross-node backend -> response 'OK')"
  echo "WG0-TRAVERSAL: PASS ($VM_A wg0 packets $WG_A_BEFORE -> $WG_A_AFTER, $VM_B wg0 packets $WG_B_BEFORE -> $WG_B_AFTER -- both moved, not a same-node self-loop)"
  echo "FLOW-TABLE: PASS ($VM_A FLOW_TABLE entries $FLOW_A_BEFORE -> $FLOW_A_AFTER)"
  echo "GATE 1 TIER-1 MECHANISM: PASS (wg0-ingress, symmetric return proven from a genuinely foreign client, over a verified cross-node path)"

  # Isolates a genuinely peer-only NODE_ALLOW on $VM_B (self-entry
  # explicitly removed, not left alongside the peer key) and asserts the
  # two outcomes a real peer-attestation mechanism must produce. Default-on:
  # with the self-loop above fixed, a live run confirmed both assertions
  # genuinely hold against a real cross-node packet -- see this script's
  # header and `bd memories wg-2node-rig-self-loop`.
  echo ""
  echo "==> BEEP_PEER_ATTESTATION_CHECK: isolating peer-only NODE_ALLOW admission"
  PEER_CHECK_FAIL=0

  echo "----> case 1: $VM_B's NODE_ALLOW = peer-only ($VM_A's real key, self-entry removed) -- round trip must PASS"
  remote "$VM_B" delete-node-allow --key-hex "$NODE_B_KEY"
  # start-backend-responder's nc listener is one-shot (no -k) -- the
  # GATE 1 round trip above already consumed it, so it must be restarted
  # before every subsequent attempt here or a dead backend (not the
  # NODE_ALLOW state under test) would decide the outcome.
  remote "$VM_B" start-backend-responder --pod-ip "$POD_IP" --port "$TARGET_PORT"
  set +e
  PEER_BODY_1="$(limactl shell "$VM_CLIENT" -- curl -sS -m 20 "http://${WG_SUBNET_A}:${VIP_PORT}/" 2>&1)"
  PEER_RC_1=$?
  set -e
  if [ "$PEER_RC_1" -eq 0 ] && [ "$PEER_BODY_1" = "OK" ]; then
    echo "PEER-ATTESTATION (peer-only admits the real peer): PASS"
  else
    echo "PEER-ATTESTATION (peer-only admits the real peer): FAIL (curl rc=$PEER_RC_1, body='$PEER_BODY_1')"
    PEER_CHECK_FAIL=1
  fi

  echo "----> case 2: $VM_B's NODE_ALLOW = self-only (no real peer key) -- a packet from the real peer must be DROPPED"
  remote "$VM_B" delete-node-allow --key-hex "$NODE_A_KEY"
  remote "$VM_B" seed-node-allow --key-hex "$NODE_B_KEY"
  remote "$VM_B" start-backend-responder --pod-ip "$POD_IP" --port "$TARGET_PORT"
  set +e
  PEER_BODY_2="$(limactl shell "$VM_CLIENT" -- curl -sS -m 20 "http://${WG_SUBNET_A}:${VIP_PORT}/" 2>&1)"
  PEER_RC_2=$?
  set -e
  if [ "$PEER_RC_2" -ne 0 ]; then
    echo "PEER-ATTESTATION (self-only drops the real peer): PASS"
  else
    echo "PEER-ATTESTATION (self-only drops the real peer): FAIL (curl unexpectedly succeeded, body='$PEER_BODY_2')"
    PEER_CHECK_FAIL=1
  fi

  if [ "$PEER_CHECK_FAIL" -eq 1 ]; then
    echo "GATE: PEER-ATTESTATION REGRESSION: FAIL"
    echo ""
    echo "==> peer-attestation check did not pass -- collecting evidence"
    echo "---- $VM_A wg0 tcpdump ----"
    remote "$VM_A" dump-tcpdump wg0
    echo "---- $VM_B wg0 tcpdump ----"
    remote "$VM_B" dump-tcpdump wg0
    echo "---- $VM_A evidence ----"
    remote "$VM_A" dump-evidence
    echo "---- $VM_B evidence ----"
    remote "$VM_B" dump-evidence
    exit 1
  fi
  echo "GATE: PEER-ATTESTATION REGRESSION: PASS"
  exit 0
fi
echo "ROUND-TRIP: FAIL (curl rc=$CLIENT_RC, body='$CLIENT_BODY', wg0 $VM_A $WG_A_BEFORE->$WG_A_AFTER, $VM_B $WG_B_BEFORE->$WG_B_AFTER, FLOW_TABLE(a) $FLOW_A_BEFORE->$FLOW_A_AFTER)" >&2

echo ""
echo "==> round trip did not complete -- collecting evidence"
echo "---- $VM_A wg0 tcpdump ----"
remote "$VM_A" dump-tcpdump wg0
echo "---- $VM_B wg0 tcpdump ----"
remote "$VM_B" dump-tcpdump wg0
echo "---- $VM_A evidence ----"
remote "$VM_A" dump-evidence
echo "---- $VM_B evidence ----"
remote "$VM_B" dump-evidence
exit 1
