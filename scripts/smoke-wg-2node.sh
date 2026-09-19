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
# source is no longer local to node-b. The round trip now reaches a
# genuine GREEN.
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
# lima-ipv6-reconciled-with-u7s). This is a 2-node-only, beep-dataplane-free
# check: it stops after the tunnel is up and never touches vm-client,
# geneve, or the loader, since beep itself is still IPv4-only.
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

command -v limactl >/dev/null || { echo "FAIL: limactl not found on PATH" >&2; exit 1; }
if [ "$FAMILY" = "4" ]; then
  command -v cargo-zigbuild >/dev/null || { echo "FAIL: cargo-zigbuild not found on PATH" >&2; exit 1; }
  rustup toolchain list 2>/dev/null | grep -q '^nightly' || {
    echo "FAIL: nightly toolchain not installed (rustup toolchain install nightly --component rust-src)" >&2
    exit 1
  }
fi

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

if [ "$FAMILY" = "4" ]; then
  echo "==> [1/7] bringing up $VM_A, $VM_B, and $VM_CLIENT"
else
  echo "==> [1/3] bringing up $VM_A and $VM_B (--family 6: $VM_CLIENT/geneve/loader are out of scope, beep is still v4-only)"
fi
for vm in "$VM_A" "$VM_B"; do
  if ! limactl list --format '{{.Name}}\t{{.Status}}' 2>/dev/null | grep -qE "^${vm}[[:space:]]+Running"; then
    limactl start "$vm"
  fi
  limactl shell "$vm" -- bash -c 'command -v wg >/dev/null || sudo apt-get install -y wireguard-tools' >/dev/null
done
if [ "$FAMILY" = "4" ]; then
  if ! limactl list --format '{{.Name}}\t{{.Status}}' 2>/dev/null | grep -qE "^${VM_CLIENT}[[:space:]]+Running"; then
    limactl start "$VM_CLIENT"
  fi
fi

if [ "$FAMILY" = "4" ]; then
  echo "==> [2/7] cross-building beep-ebpf + beep (nightly + bpf-linker + zigbuild -> aarch64-unknown-linux-gnu)"
  ( cd "$BEEP_DIR" && cargo +nightly zigbuild --release --target aarch64-unknown-linux-gnu )
  BIN="$BEEP_DIR/target/aarch64-unknown-linux-gnu/release/beep"
  [ -x "$BIN" ] || { echo "FAIL: build did not produce $BIN" >&2; exit 1; }
else
  echo "==> [2/3] copying the remote rig script only (no beep binary needed -- the loader is never started)"
fi

for vm in "$VM_A" "$VM_B"; do
  if [ "$FAMILY" = "4" ]; then
    limactl copy "$BIN" "$vm":"/tmp/${BIN_NAME}"
    limactl copy "$REMOTE_SCRIPT" "$vm":"/tmp/${BIN_NAME}-remote.sh"
    limactl shell "$vm" -- bash -c "chmod +x /tmp/${BIN_NAME} /tmp/${BIN_NAME}-remote.sh"
  else
    limactl copy "$REMOTE_SCRIPT" "$vm":"/tmp/${BIN_NAME}-remote.sh"
    limactl shell "$vm" -- bash -c "chmod +x /tmp/${BIN_NAME}-remote.sh"
  fi
  remote "$vm" cleanup >/dev/null 2>&1 || true
done

if [ "$FAMILY" = "4" ]; then
  echo "==> [3/7] establishing the real WireGuard tunnel between $VM_A and $VM_B, plus $VM_CLIENT's relay route"
else
  echo "==> [3/3] establishing the real WireGuard tunnel between $VM_A and $VM_B, then proving it carries IPv6"
fi
IP_A="$(eth0_ip "$VM_A")"
IP_B="$(eth0_ip "$VM_B")"
[ -n "$IP_A" ] && [ -n "$IP_B" ] || {
  echo "FAIL: could not resolve eth0 addresses ($VM_A=$IP_A, $VM_B=$IP_B) -- are both VMs on the same Lima network?" >&2
  exit 1
}
if [ "$FAMILY" = "4" ]; then
  IP_CLIENT="$(eth0_ip "$VM_CLIENT")"
  [ -n "$IP_CLIENT" ] || {
    echo "FAIL: could not resolve eth0 address for $VM_CLIENT -- is it on the same Lima network?" >&2
    exit 1
  }
fi
# Each side's key pair is generated independently BEFORE either side's peer
# config is known -- avoids a chicken-and-egg ordering (setup-wg needs the
# PEER's pubkey as an argument, so both pubkeys must exist first).
PUBKEY_A="$(remote "$VM_A" pubkey)"
PUBKEY_B="$(remote "$VM_B" pubkey)"
if [ "$FAMILY" = "6" ]; then
  # No --extra-allowed here: --family 6 never involves $VM_CLIENT's relay,
  # so node-b's own /128 peer entry is all node-a needs to admit.
  remote "$VM_A" setup-wg --family 6 --self-ip "$WG_ULA_A" --peer-ip "$WG_ULA_B" \
    --peer-pubkey "$PUBKEY_B" --peer-endpoint "${IP_B}:${WG_PORT}" --listen-port "$WG_PORT"
  remote "$VM_B" setup-wg --family 6 --self-ip "$WG_ULA_B" --peer-ip "$WG_ULA_A" \
    --peer-pubkey "$PUBKEY_A" --peer-endpoint "${IP_A}:${WG_PORT}" --listen-port "$WG_PORT"

  limactl shell "$VM_A" -- ping -6 -c 2 -W 2 "$WG_ULA_B" >/dev/null || {
    echo "FAIL: $VM_A cannot ping6 $VM_B over the WireGuard tunnel ($WG_ULA_B)" >&2
    exit 1
  }
  echo "WIREGUARD TUNNEL (v6): PASS ($VM_A $WG_ULA_A <-> $VM_B $WG_ULA_B, over real v4 underlay $IP_A/$IP_B)"

  # A plain nc -6 payload delivery, independent of ping's ICMP-only proof:
  # confirms wg0 carries a genuine TCP/v6 byte stream (the 3-way handshake
  # and the server's ACKs of the payload both require the return leg to
  # carry v6 too, so a successful delivery already proves both directions).
  NC_PORT="19620"
  NC_PAYLOAD="beep-v6-payload"
  limactl shell "$VM_B" -- bash -c "rm -f /tmp/wg2node-v6-payload.log; nohup nc -l -N -6 ${WG_ULA_B} ${NC_PORT} > /tmp/wg2node-v6-payload.log 2>&1 & disown"
  sleep 0.5
  limactl shell "$VM_A" -- bash -c "printf '%s' '${NC_PAYLOAD}' | nc -6 -w 3 ${WG_ULA_B} ${NC_PORT}"
  NC_RECEIVED="$(limactl shell "$VM_B" -- cat /tmp/wg2node-v6-payload.log)"
  limactl shell "$VM_B" -- rm -f /tmp/wg2node-v6-payload.log
  [ "$NC_RECEIVED" = "$NC_PAYLOAD" ] || {
    echo "FAIL: nc -6 payload over wg0 not received intact by $VM_B (got '$NC_RECEIVED')" >&2
    exit 1
  }
  echo "WG-V6-PAYLOAD: PASS (nc -6 delivered '$NC_RECEIVED' $VM_A -> $WG_ULA_B:$NC_PORT over wg0)"
  echo "GATE: WIREGUARD-CARRIES-IPV6: PASS (transport only -- beep's own dataplane is still IPv4-only)"
  exit 0
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

echo "==> [4/7] creating geneve0 on both nodes"
remote "$VM_A" setup-geneve
remote "$VM_B" setup-geneve

echo "==> [5/7] confirming $VM_B's real underlay NIC name (must not be assumed)"
IFACE_B_ACTUAL="$(limactl shell "$VM_B" -- bash -c "ip -4 -o addr show eth0 | awk '{print \$2; exit}'")"
[ "$IFACE_B_ACTUAL" = "$UPLINK_IFACE_B" ] || {
  echo "FAIL: expected $VM_B's user-v2 NIC to be '$UPLINK_IFACE_B', found '$IFACE_B_ACTUAL' -- update UPLINK_IFACE_B" >&2
  exit 1
}
echo "UPLINK-IFACE-NAME: PASS ($VM_B's user-v2 NIC is $UPLINK_IFACE_B)"

echo "==> [6/7] loading beep-ebpf: $VM_A uplink=wg0 (the mechanism under test), $VM_B uplink=$UPLINK_IFACE_B (its return-to-client path)"
FIXTURE="${WG_SUBNET_A}:${VIP_PORT}:tcp:${WG_SUBNET_B}:${POD_IP}:${TARGET_PORT}"
remote "$VM_A" start-loader --fixture "$FIXTURE" --pod-cidr "$POD_CIDR" --node-ip "$WG_SUBNET_A"
# --uplink-iface must be $VM_B's real NIC, not the wg0 default: the backend
# pod's raw reply is un-DNAT'd and redirected straight to whatever device
# --uplink-iface names (see try_geneve_decap_return's comment in
# ebpf/src/main.rs), and the client (on the shared user-v2 subnet) is only
# reachable from $VM_B over its real NIC, never over wg0 -- left at the wg0
# default, `uplink_egress_return` never fires and the un-DNAT'd reply leaks
# out $UPLINK_IFACE_B unencapsulated.
remote "$VM_B" start-loader --uplink-iface "$UPLINK_IFACE_B" --fixture "$FIXTURE" --pod-cidr "$POD_CIDR" --node-ip "$WG_SUBNET_B"

remote "$VM_B" setup-backend --pod-ip "$POD_IP"
remote "$VM_B" start-backend-responder --pod-ip "$POD_IP" --port "$TARGET_PORT"

echo "==> [7/7] driving one client ($VM_CLIENT) -> VIP (over wg0 ingress, via $VM_B's relay) -> cross-node backend round trip"
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
if [ "$CLIENT_RC" -eq 0 ] && [ "$CLIENT_BODY" = "OK" ]; then
  echo "ROUND-TRIP: PASS (client $VM_CLIENT -> VIP ${WG_SUBNET_A}:${VIP_PORT} -> cross-node backend -> response 'OK')"
  echo "GATE 1 TIER-1 MECHANISM: PASS (wg0-ingress, symmetric return proven from a genuinely foreign client)"
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
