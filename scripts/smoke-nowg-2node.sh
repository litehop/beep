#!/usr/bin/env bash
# WireGuard-free 2-node cross-node rig: client VM -> node-a's real eth0 front
# -> Geneve over the plain user-v2 underlay (eth0 <-> eth0, no wg0 anywhere)
# -> node-b backend -> symmetric return -> client.
#
# Reuses smoke-wg-2node-remote.sh unchanged, minus its WireGuard subcommands
# (setup-wg/pubkey are never called): both loaders bind --uplink-iface eth0
# and use their own eth0 address as --node-ip, so the Geneve outer header
# runs node-a eth0 <-> node-b eth0 directly.
#
# Cross-node proof (a bare loader otherwise self-loops on one node):
#   - node-b's geneve0 rx and node-a's geneve0 rx must BOTH move during the
#     round trip (forward decap on b, return decap on a),
#   - node-b's backend log must show the real client address,
#   - no WireGuard device exists on either node and node-b's route to
#     node-a is via eth0.
# Negative control: with NODE_ALLOW seeding skipped, the same request must
# FAIL; otherwise the positive result would not be attributable to seeding
# the peer's key (peer_node_admission).
#
# Underlay-follows-FIB (stage 7b): the forward Geneve leg only sets the tunnel
# remote, so node-a's route to node-b's address picks the egress device. A GRE
# device gives a second path; flipping the route moves the outer packets to it
# with no loader restart, and flipping back returns them (control).
#
# Usage: scripts/smoke-nowg-2node.sh [--vm-a <ingress-vm>] [--vm-b <backend-vm>] [--vm-client <client-vm>]
# Same host/VM prerequisites as smoke-eth-ingress-2node.sh (minus wireguard-tools).
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
REMOTE_SCRIPT="$SCRIPT_DIR/smoke-wg-2node-remote.sh"
BIN_NAME="beep-wg2node"

FRONT_PORT="19100"
POD_IP="198.51.100.60"
POD_CIDR="198.51.100.0/24"
TARGET_PORT="18090"
UPLINK_IFACE="eth0"

for tool in cargo-zigbuild limactl; do
  command -v "$tool" >/dev/null || { echo "FAIL: $tool not found on PATH" >&2; exit 1; }
done
rustup toolchain list 2>/dev/null | grep -q '^nightly' || {
  echo "FAIL: nightly toolchain not installed (rustup toolchain install nightly --component rust-src)" >&2
  exit 1
}

remote() {
  local vm="$1"; shift
  limactl shell "$vm" -- sudo bash "/tmp/${BIN_NAME}-remote.sh" "$@"
}

vm_ip() { # real underlay address of <vm>
  limactl shell "$1" -- bash -c "ip -4 -o addr show eth0 | awk '{print \$4}' | cut -d/ -f1"
}

geneve_rx() { # rx packet count on <vm>'s geneve0
  limactl shell "$1" -- cat /sys/class/net/geneve0/statistics/rx_packets
}

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
  limactl shell "$VM_B" -- sudo ip addr del "${POD_IP}/32" dev lo 2>/dev/null || true
  for vm in "$VM_A" "$VM_B"; do
    limactl shell "$vm" -- sudo ip link del beepul0 2>/dev/null || true
  done
}
trap cleanup EXIT

curl_front() { # curl_front <max-seconds>; sets CLIENT_RC/CLIENT_BODY
  set +e
  CLIENT_BODY="$(limactl shell "$VM_CLIENT" -- curl -sS -m "$1" "http://${IP_A}:${FRONT_PORT}/" 2>&1)"
  CLIENT_RC=$?
  set -e
}

echo "==> [1/8] bringing up $VM_A, $VM_B, $VM_CLIENT"
for vm in "$VM_A" "$VM_B" "$VM_CLIENT"; do
  if ! limactl list --format '{{.Name}}\t{{.Status}}' 2>/dev/null | grep -qE "^${vm}[[:space:]]+Running"; then
    limactl start "$vm"
  fi
done

echo "==> [2/8] cross-building beep (nightly + bpf-linker + zigbuild -> aarch64-unknown-linux-gnu)"
( cd "$REPO_ROOT" && cargo +nightly zigbuild --release --target aarch64-unknown-linux-gnu )
BIN="$REPO_ROOT/target/aarch64-unknown-linux-gnu/release/beep"
[ -x "$BIN" ] || { echo "FAIL: build did not produce $BIN" >&2; exit 1; }

for vm in "$VM_A" "$VM_B"; do
  limactl copy "$BIN" "$vm":"/tmp/${BIN_NAME}"
  limactl copy "$REMOTE_SCRIPT" "$vm":"/tmp/${BIN_NAME}-remote.sh"
  limactl shell "$vm" -- bash -c "chmod +x /tmp/${BIN_NAME} /tmp/${BIN_NAME}-remote.sh"
  remote "$vm" cleanup >/dev/null 2>&1 || true
done

IP_A="$(vm_ip "$VM_A")"
IP_B="$(vm_ip "$VM_B")"
IP_CLIENT="$(vm_ip "$VM_CLIENT")"
[ -n "$IP_A" ] && [ -n "$IP_B" ] && [ -n "$IP_CLIENT" ] || {
  echo "FAIL: could not resolve eth0 addresses (a=$IP_A b=$IP_B client=$IP_CLIENT)" >&2
  exit 1
}

echo "==> [3/8] creating geneve0 on both nodes; asserting no WireGuard device and an eth0 underlay route"
remote "$VM_A" setup-geneve
remote "$VM_B" setup-geneve
for vm in "$VM_A" "$VM_B"; do
  wg_links="$(limactl shell "$vm" -- ip -o link show type wireguard)"
  [ -z "$wg_links" ] || { echo "FAIL: WireGuard device present on $vm: $wg_links" >&2; exit 1; }
done
ROUTE_B_TO_A="$(limactl shell "$VM_B" -- ip route get "$IP_A")"
case "$ROUTE_B_TO_A" in
  *"dev $UPLINK_IFACE"*) ;;
  *) echo "FAIL: $VM_B reaches $VM_A via something other than $UPLINK_IFACE: $ROUTE_B_TO_A" >&2; exit 1 ;;
esac
echo "NO-WIREGUARD: PASS (no wireguard link on either node; $VM_B -> $IP_A via $UPLINK_IFACE)"

echo "==> [4/8] loading beep on both nodes (uplink=$UPLINK_IFACE, node-ip = own eth0 address)"
FIXTURE="${IP_A}:${FRONT_PORT}:tcp:${IP_B}:${POD_IP}:${TARGET_PORT}"
remote "$VM_A" start-loader --uplink-iface "$UPLINK_IFACE" --fixture "$FIXTURE" --pod-cidr "$POD_CIDR" --node-ip "$IP_A"
remote "$VM_B" start-loader --uplink-iface "$UPLINK_IFACE" --fixture "$FIXTURE" --pod-cidr "$POD_CIDR" --node-ip "$IP_B"
remote "$VM_B" setup-backend --pod-ip "$POD_IP"
remote "$VM_B" start-backend-responder --pod-ip "$POD_IP" --port "$TARGET_PORT"

echo "==> [5/8] NEGATIVE CONTROL: NODE_ALLOW not seeded -- the round trip must FAIL"
# Attribution to NODE_ALLOW, not just "some failure": curl must time out
# (rc=28; a crashed loader/backend gives rc=7/52), both loaders must still be
# alive, and the forward Geneve packet must have reached node-b's geneve0
# (rx moved: the underlay and decap path work) without being delivered -- the
# admission drop happens in beep's hook after geneve0 has counted the packet,
# so the backend must have logged no connection from the client.
NC_RX_A_BEFORE="$(geneve_rx "$VM_A")"
NC_RX_B_BEFORE="$(geneve_rx "$VM_B")"
curl_front 8
NC_RX_A_AFTER="$(geneve_rx "$VM_A")"
NC_RX_B_AFTER="$(geneve_rx "$VM_B")"
echo "NEGATIVE-CONTROL: curl rc=$CLIENT_RC; geneve0 rx $VM_A $NC_RX_A_BEFORE -> $NC_RX_A_AFTER, $VM_B $NC_RX_B_BEFORE -> $NC_RX_B_AFTER"
if [ "$CLIENT_RC" -eq 0 ] && [ "$CLIENT_BODY" = "OK" ]; then
  echo "NEGATIVE-CONTROL: FAIL (round trip succeeded without NODE_ALLOW seeding -- the rig does not prove peer admission)" >&2
  exit 1
fi
if [ "$CLIENT_RC" -ne 28 ]; then
  echo "NEGATIVE-CONTROL: FAIL (curl rc=$CLIENT_RC, expected 28 timeout -- a refused/reset connection is not a NODE_ALLOW drop: '$CLIENT_BODY')" >&2
  exit 1
fi
for vm in "$VM_A" "$VM_B"; do
  limactl shell "$vm" -- pgrep -x "$BIN_NAME" >/dev/null || {
    echo "NEGATIVE-CONTROL: FAIL (loader not running on $vm after the unseeded attempt -- crash, not admission drop)" >&2
    exit 1
  }
done
if [ "$NC_RX_B_AFTER" -le "$NC_RX_B_BEFORE" ]; then
  echo "NEGATIVE-CONTROL: FAIL ($VM_B geneve0 rx did not move: the packet never arrived, so the timeout is not attributable to NODE_ALLOW)" >&2
  exit 1
fi
NC_BACKEND_LOG="$(limactl shell "$VM_B" -- cat "/tmp/wg2node-backend-${TARGET_PORT}.log" 2>/dev/null || true)"
if echo "$NC_BACKEND_LOG" | grep -q "Connection received on ${IP_CLIENT} "; then
  echo "NEGATIVE-CONTROL: FAIL (backend received the client connection despite no NODE_ALLOW seeding)" >&2
  exit 1
fi
echo "NEGATIVE-CONTROL: PASS (unseeded: curl timed out, loaders alive, packet reached $VM_B geneve0 but was not delivered)"

echo "==> [6/8] seeding NODE_ALLOW bidirectionally"
NODE_A_KEY="$(remote "$VM_A" dump-node-allow-key)"
NODE_B_KEY="$(remote "$VM_B" dump-node-allow-key)"
remote "$VM_B" seed-node-allow --key-hex "$NODE_A_KEY"
remote "$VM_A" seed-node-allow --key-hex "$NODE_B_KEY"
# The failed attempt above may have left a half-served backend listener.
remote "$VM_B" start-backend-responder --pod-ip "$POD_IP" --port "$TARGET_PORT"

echo "==> [7/8] seeded round trip: $VM_CLIENT ($IP_CLIENT) -> front ${IP_A}:${FRONT_PORT} -> $VM_B backend"
RX_A_BEFORE="$(geneve_rx "$VM_A")"
RX_B_BEFORE="$(geneve_rx "$VM_B")"
curl_front 20
RX_A_AFTER="$(geneve_rx "$VM_A")"
RX_B_AFTER="$(geneve_rx "$VM_B")"

OK=true
if [ "$CLIENT_RC" -eq 0 ] && [ "$CLIENT_BODY" = "OK" ]; then
  echo "ROUND-TRIP: PASS (response 'OK')"
else
  echo "ROUND-TRIP: FAIL (curl rc=$CLIENT_RC, body='$CLIENT_BODY')" >&2
  OK=false
fi

if [ "$RX_B_AFTER" -gt "$RX_B_BEFORE" ] && [ "$RX_A_AFTER" -gt "$RX_A_BEFORE" ]; then
  echo "CROSS-NODE: PASS (geneve0 rx $VM_B $RX_B_BEFORE -> $RX_B_AFTER forward decap, $VM_A $RX_A_BEFORE -> $RX_A_AFTER return decap)"
else
  echo "CROSS-NODE: FAIL (geneve0 rx $VM_B $RX_B_BEFORE -> $RX_B_AFTER, $VM_A $RX_A_BEFORE -> $RX_A_AFTER)" >&2
  OK=false
fi

BACKEND_LOG="$(limactl shell "$VM_B" -- cat "/tmp/wg2node-backend-${TARGET_PORT}.log" 2>/dev/null || true)"
if echo "$BACKEND_LOG" | grep -q "Connection received on ${IP_CLIENT} "; then
  echo "CLIENT-IP-PRESERVATION: PASS (backend on $VM_B saw client $IP_CLIENT)"
else
  echo "CLIENT-IP-PRESERVATION: FAIL (backend log: $BACKEND_LOG)" >&2
  OK=false
fi

echo "==> [7b/8] forward Geneve underlay follows the FIB: flip node-a's route to $IP_B between two paths, no loader restart"
# Path 1 is eth0. Path 2 is a GRE device bound to eth0 (so its own outer
# packets skip the override route below) -- the VMs have one NIC, and a
# second routable L3 device to the same peer is all the FIB needs to choose
# between. Outer Geneve packets (udp/6081, dst IP_B) are told apart by
# device: seen on eth0 directly = path 1; seen on $ALT_IFACE (inside GRE on
# eth0, which an eth0 'udp' filter does not match) = path 2.
ALT_IFACE="beepul0"
GENEVE_PORT="6081"
ul() { limactl shell "$1" -- sudo ip "${@:2}"; }

for pair in "$VM_A:$IP_A:$IP_B" "$VM_B:$IP_B:$IP_A"; do
  IFS=: read -r vm lip rip <<<"$pair"
  ul "$vm" tunnel add "$ALT_IFACE" mode gre local "$lip" remote "$rip" dev "$UPLINK_IFACE"
  ul "$vm" link set "$ALT_IFACE" up
  limactl shell "$vm" -- sudo sysctl -w "net.ipv4.conf.${ALT_IFACE}.rp_filter=0" >/dev/null
done

geneve_fwd_count() { # geneve_fwd_count <iface> <file>: outer forward packets seen on node-a's <iface>
  grep -c " > ${IP_B}\.${GENEVE_PORT}:" "$2" || true
}

round_trip_capturing() { # round_trip_capturing <tag>; sets CLIENT_RC/CLIENT_BODY, CAP_ETH0, CAP_ALT
  local tag="$1" f_eth f_alt
  f_eth="$(mktemp)"; f_alt="$(mktemp)"
  remote "$VM_B" start-backend-responder --pod-ip "$POD_IP" --port "$TARGET_PORT"
  limactl shell "$VM_A" -- sudo timeout 10 tcpdump -ni "$UPLINK_IFACE" -l "udp dst port $GENEVE_PORT and dst host $IP_B" >"$f_eth" 2>/dev/null &
  limactl shell "$VM_A" -- sudo timeout 10 tcpdump -ni "$ALT_IFACE" -l "udp dst port $GENEVE_PORT and dst host $IP_B" >"$f_alt" 2>/dev/null &
  sleep 3
  curl_front 8
  wait
  CAP_ETH0="$(geneve_fwd_count "$UPLINK_IFACE" "$f_eth")"
  CAP_ALT="$(geneve_fwd_count "$ALT_IFACE" "$f_alt")"
  rm -f "$f_eth" "$f_alt"
  echo "UNDERLAY[$tag]: route=$(limactl shell "$VM_A" -- ip route get "$IP_B" | head -1) curl rc=$CLIENT_RC; forward geneve pkts $VM_A $UPLINK_IFACE=$CAP_ETH0 $ALT_IFACE=$CAP_ALT"
}

underlay_expect() { # underlay_expect <tag> <eth0|alt>
  if [ "$CLIENT_RC" -ne 0 ] || [ "$CLIENT_BODY" != "OK" ]; then
    echo "UNDERLAY[$1]: FAIL (round trip broke: rc=$CLIENT_RC body='$CLIENT_BODY')" >&2; OK=false; return
  fi
  if [ "$2" = eth0 ] && [ "$CAP_ETH0" -gt 0 ] && [ "$CAP_ALT" -eq 0 ]; then
    echo "UNDERLAY[$1]: PASS (forward leg on $UPLINK_IFACE only)"
  elif [ "$2" = alt ] && [ "$CAP_ALT" -gt 0 ] && [ "$CAP_ETH0" -eq 0 ]; then
    echo "UNDERLAY[$1]: PASS (forward leg on $ALT_IFACE only)"
  else
    echo "UNDERLAY[$1]: FAIL (expected $2 only; $UPLINK_IFACE=$CAP_ETH0 $ALT_IFACE=$CAP_ALT)" >&2; OK=false
  fi
}

LOADER_PID_A="$(limactl shell "$VM_A" -- pgrep -x "$BIN_NAME")"
round_trip_capturing baseline
underlay_expect baseline eth0

ul "$VM_A" route replace "${IP_B}/32" dev "$ALT_IFACE" src "$IP_A"
round_trip_capturing flipped
underlay_expect flipped alt

ul "$VM_A" route del "${IP_B}/32" dev "$ALT_IFACE"
round_trip_capturing control
underlay_expect control eth0

if [ "$(limactl shell "$VM_A" -- pgrep -x "$BIN_NAME")" = "$LOADER_PID_A" ]; then
  echo "NO-RESTART: PASS (loader pid $LOADER_PID_A unchanged across both route changes)"
else
  echo "NO-RESTART: FAIL (loader pid changed)" >&2; OK=false
fi

echo "==> [8/8] verdict"
if [ "$OK" = true ]; then
  echo "GATE WIREGUARD-FREE 2-NODE CROSS-NODE ROUND TRIP: PASS"
  exit 0
fi
echo "---- $VM_A evidence ----"
remote "$VM_A" dump-evidence
echo "---- $VM_B evidence ----"
remote "$VM_B" dump-evidence
exit 1
