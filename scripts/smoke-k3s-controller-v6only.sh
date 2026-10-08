#!/usr/bin/env bash
# IPv6-only sibling of scripts/smoke-k3s-controller-dualstack.sh: proves the
# REAL controller (deploy/daemonset.yaml -- not a hand-rolled --fixture)
# serves a v6 front end to end on a genuinely IPv6-only k3s cluster
# (scripts/k3s-up.sh --v6-only): neither Node object carries a v4 InternalIP,
# neither k3s --node-ip is v4, and v4 Geneve egress is dropped on both nodes,
# so the underlay between them can only be v6. (eth0 keeps its DHCP v4
# address: Lima's host->guest control channel needs it, and removing it
# wedges the VM. k3s rejects a v6-only node inside a dual-stack cluster, so
# the whole cluster is v6-only, not just $VM_B.)
#
# TOPOLOGY: same as the dual-stack rig -- ingress = $VM_A's ULA, hostNetwork
# backend Pod pinned to $VM_B (its podIP is $VM_B's own v6 node address, which
# the controller admits via the hostNetwork signature), separate $VM_CLIENT.
#
# CROSS-NODE PROOF: a reply alone can't distinguish a real traversal from a
# same-node self-loop, so the gate also requires (a) geneve0 counters moving
# on both nodes, (b) Geneve-over-v6 packets captured on each node's eth0 in
# BOTH directions between the two ULAs, with the v4 UDP/6081 DROP rule's packet
# counter unchanged on both nodes since a positive-control probe moved it 0 -> 1
# (the eth0 capture sits after that drop, so only the counter proves no v4
# Geneve was attempted), and (c) a FLOW_TABLE entry for
# the client's v6 address on the ingress node.
#
# NOT COVERED: a dual-stack ingress node fronting a v6-only backend node. k3s
# rejects a v6-only node inside a dual-stack cluster, so that mix cannot be
# built on k3s; it is exercised only by the controller's unit tests and needs
# real hardware (gate 3) to run end to end.
#
# Usage: scripts/smoke-k3s-controller-v6only.sh [--vm-a <ingress-vm>] [--vm-b <backend-vm>] [--vm-client <client-vm>]
#
# Test hook: BEEP_SMOKE_MAP_DUMP_TIMEOUT=<seconds> (default 20) bounds each
# bpftool map dump; BEEP_SMOKE_EVIDENCE_TIMEOUT=<seconds> (default 20) bounds
# each call of the FAIL-path evidence dump.
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
# shellcheck source=k3s-common.sh
. "$SCRIPT_DIR/k3s-common.sh"

NAMESPACE="beep-controller-e2e-v6only"
DEPLOY_NAME="whoami-v6"
SVC_V6="whoami-v6only"
PORT_V6="8082"
TARGET_PORT="80"
BACKEND_IMAGE="docker.io/traefik/whoami:latest"
PIN_DIR="/sys/fs/bpf/beep"
KUBECONFIG_SECRET="beep-controller-kubeconfig"
V4_GENEVE_BLOCK_TAG="beep-v6only-no-v4-geneve"
CAPTURE_UNIT="beep-v6only-capture"
CAPTURE_FILE="/tmp/beep-v6only-capture.pcap"
IMAGE_TMPDIR=""
IMAGE=""

for tool in limactl jq docker cargo-zigbuild; do
  command -v "$tool" >/dev/null || { echo "FAIL: $tool not found on PATH" >&2; exit 1; }
done
rustup toolchain list 2>/dev/null | grep -q '^nightly' || {
  echo "FAIL: nightly toolchain not installed (rustup toolchain install nightly --component rust-src)" >&2
  exit 1
}
rustup component list --toolchain nightly 2>/dev/null | grep -q '^rust-src (installed)' || {
  echo "FAIL: rust-src component not installed for nightly (rustup component add rust-src --toolchain nightly)" >&2
  exit 1
}

map_dump() { # map_dump <vm> <map-name> -- raw bpftool JSON dump of a pinned map on stdout, exit 0 (a genuinely empty map prints "[]"); exit 1 with the reason on stderr if the pin is missing/unreadable, bpftool/limactl fails, or the call times out. Callers MUST treat non-zero as a gate FAIL, never as "empty".
  local vm="$1" name="$2" out_file err_file limit="${BEEP_SMOKE_MAP_DUMP_TIMEOUT:-20}" rc=0 run_rc=0
  out_file="$(mktemp)"
  err_file="$(mktemp)"
  bounded_run "$limit" limactl shell "$vm" -- sudo bpftool map dump pinned "$PIN_DIR/$name" --json 2>"$err_file" > "$out_file" || run_rc=$?
  if [ "$run_rc" -eq 124 ]; then
    echo "map_dump $vm/$name timed out after ${limit}s" >&2
    rc=1
  elif [ "$run_rc" -ne 0 ]; then
    echo "map_dump $vm/$name failed: $(tr '\n' ' ' < "$err_file")" >&2
    rc=1
  elif [ ! -s "$out_file" ]; then
    echo "map_dump $vm/$name returned no output" >&2
    rc=1
  else
    cat "$out_file"
  fi
  rm -f "$out_file" "$err_file"
  return "$rc"
}

v4_block_pkts() { # v4_block_pkts <vm> -- packet counter of the v4 UDP/6081 DROP rule on stdout; exit 1 unless exactly one such rule exists (the capture on eth0 sits after this netfilter OUTPUT drop, so only this counter sees blocked v4 Geneve attempts)
  limactl shell "$1" -- sudo bash -c "iptables -nvxL OUTPUT | awk -v tag='$V4_GENEVE_BLOCK_TAG' 'index(\$0, tag) && \$3 == \"DROP\" && /udp dpt:6081/ {n++; p=\$1} END {if (n != 1) exit 1; print p}'"
}

dump_evidence() { k3s_dump_evidence "$VM_A" "$VM_B" "$PIN_DIR"; }

cleanup() {
  kube delete namespace "$NAMESPACE" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  k3s_teardown_controller "$REPO_ROOT" "$KUBECONFIG_SECRET"
  [ -n "$IMAGE_TMPDIR" ] && rm -rf "$IMAGE_TMPDIR"
  [ -n "$IMAGE" ] && docker rmi "$IMAGE" >/dev/null 2>&1 || true
  for vm in "$VM_A" "$VM_B"; do
    limactl shell "$vm" -- sudo systemctl stop "$CAPTURE_UNIT" >/dev/null 2>&1 || true
    limactl shell "$vm" -- sudo rm -f "$CAPTURE_FILE" >/dev/null 2>&1 || true
    limactl shell "$vm" -- sudo rm -rf "$PIN_DIR" >/dev/null 2>&1 || true
    limactl shell "$vm" -- sudo ip link del geneve0 >/dev/null 2>&1 || true
    limactl shell "$vm" -- sudo bash -c "while iptables -D OUTPUT -p udp --dport 6081 -m comment --comment '$V4_GENEVE_BLOCK_TAG' -j DROP; do :; done" >/dev/null 2>&1 || true
    limactl shell "$vm" -- sudo bash -c '
      if [ -f /tmp/beep-k3s-controller-v6only-rpfilter-all.saved ]; then
        sysctl -w net.ipv4.conf.all.rp_filter="$(cat /tmp/beep-k3s-controller-v6only-rpfilter-all.saved)" >/dev/null 2>&1 || true
        rm -f /tmp/beep-k3s-controller-v6only-rpfilter-all.saved
      fi
    ' >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

echo "==> [1/12] bringing up the IPv6-ONLY k3s cluster ($VM_A server, $VM_B agent) and $VM_CLIENT"
k3s_bring_up_cluster "$VM_A" "$VM_B" "$VM_CLIENT" "iptables" "0" "1"
k3s_seed_lan_v6 "$VM_A" "$K3S_LAN_ULA_A" "$VM_B" "$K3S_LAN_ULA_B" "$VM_CLIENT" "$K3S_LAN_ULA_CLIENT"

ULA_A="$K3S_LAN_ULA_A"
ULA_B="$K3S_LAN_ULA_B"
ULA_CLIENT="$K3S_LAN_ULA_CLIENT"
NODE_A_K8S="lima-${VM_A}"
NODE_B_K8S="lima-${VM_B}"
for pair in "$NODE_A_K8S:$ULA_A" "$NODE_B_K8S:$ULA_B"; do
  node="${pair%%:*}"
  want="${pair#*:}"
  addrs="$(kube get node "$node" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')"
  [ "$addrs" = "$want" ] || {
    echo "FAIL: $node's InternalIPs are '$addrs', wanted exactly the v6 '$want' -- node is not genuinely IPv6-only" >&2
    exit 1
  }
done
for vm in "$VM_A" "$VM_B"; do
  node_ip_args="$(limactl shell "$vm" -- sudo bash -c 'grep -ho -- "--node-ip[= ][^ ]*" /etc/systemd/system/k3s*.service' | tr '\n' ' ')"
  case "$node_ip_args" in
    *--node-ip*) ;;
    *) echo "FAIL: no --node-ip found in $vm's k3s unit" >&2; exit 1 ;;
  esac
  case "$node_ip_args" in
    *.*) echo "FAIL: $vm's k3s --node-ip carries a v4 address: $node_ip_args" >&2; exit 1 ;;
  esac
done
echo "CLUSTER-UP: PASS (v6-only; $NODE_A_K8S InternalIP=$ULA_A, $NODE_B_K8S InternalIP=$ULA_B, no v4 InternalIP or v4 k3s --node-ip on either; client=$VM_CLIENT $ULA_CLIENT)"

echo "==> [2/12] creating geneve0 on both nodes (external mode -- beep sets the tunnel key itself)"
for vm in "$VM_A" "$VM_B"; do
  limactl shell "$vm" -- sudo bash -c '
    ip link show geneve0 >/dev/null 2>&1 || ip link add geneve0 type geneve external
    ip link set geneve0 up
    if [ ! -f /tmp/beep-k3s-controller-v6only-rpfilter-all.saved ]; then
      sysctl -n net.ipv4.conf.all.rp_filter > /tmp/beep-k3s-controller-v6only-rpfilter-all.saved
    fi
    sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
    sysctl -w net.ipv4.conf.geneve0.rp_filter=0 >/dev/null
  '
done

echo "==> [3/12] provisioning the controller's kubeconfig Secret (apiserver over v6: [$ULA_A]:6443)"
k3s_provision_kubeconfig_secret "$VM_A" "[$ULA_A]" "$KUBECONFIG_SECRET" 1

SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"
IMAGE="docker.io/valerauko/beep-lb:${SHA}-v6only"
echo "==> [4/12] building the commit-under-test's image ($IMAGE), deploying the controller DaemonSet, and blocking v4 Geneve on both nodes"
node_arch="$(limactl shell "$VM_A" -- uname -m)"
[ "$(limactl shell "$VM_B" -- uname -m)" = "$node_arch" ] || {
  echo "FAIL: $VM_A and $VM_B report different architectures -- this rig assumes a homogeneous node pair" >&2
  exit 1
}
case "$node_arch" in
  aarch64) rust_target="aarch64-unknown-linux-gnu.2.36"; goarch="arm64" ;;
  x86_64) rust_target="x86_64-unknown-linux-gnu.2.36"; goarch="amd64" ;;
  *) echo "FAIL: unsupported node architecture '$node_arch' (want aarch64 or x86_64)" >&2; exit 1 ;;
esac

( cd "$REPO_ROOT" && cargo +nightly zigbuild --release -p beep-controller --target "$rust_target" )
mkdir -p "$REPO_ROOT/dist/linux/$goarch"
cp "$REPO_ROOT/target/${rust_target%%.*}/release/beep-controller" "$REPO_ROOT/dist/linux/$goarch/beep-controller"

docker buildx build --platform "linux/$goarch" -t "$IMAGE" --load "$REPO_ROOT" >/dev/null

IMAGE_TMPDIR="$(mktemp -d)"
docker save "$IMAGE" -o "$IMAGE_TMPDIR/beep-lb.tar"
for vm in "$VM_A" "$VM_B"; do
  limactl copy "$IMAGE_TMPDIR/beep-lb.tar" "$vm":/tmp/beep-lb.tar
  limactl shell "$vm" -- sudo k3s ctr images import /tmp/beep-lb.tar >/dev/null
  limactl shell "$vm" -- rm -f /tmp/beep-lb.tar
done
rm -rf "$IMAGE_TMPDIR"
IMAGE_TMPDIR=""
for vm in "$VM_A" "$VM_B"; do
  limactl shell "$vm" -- sudo bash -c "while iptables -D OUTPUT -p udp --dport 6081 -m comment --comment '$V4_GENEVE_BLOCK_TAG' -j DROP 2>/dev/null; do :; done"
  limactl shell "$vm" -- sudo iptables -I OUTPUT -p udp --dport 6081 -m comment --comment "$V4_GENEVE_BLOCK_TAG" -j DROP
  blocked_pkts="$(v4_block_pkts "$vm")" || { echo "V4-GENEVE-BLOCKED: FAIL ($vm: could not read back exactly one v4 UDP/6081 DROP rule after inserting it)" >&2; exit 1; }
  echo "  $vm: v4 UDP/6081 DROP rule read back (packets so far: $blocked_pkts)"
done
echo "V4-GENEVE-BLOCKED: PASS (v4 UDP/6081 egress dropped on $VM_A and $VM_B -- rule read back from iptables on each, so a v4 tunnel remote could not carry traffic; Lima's own control channel needs eth0's v4 address, so it stays)"

if ! k3s_deploy_controller_daemonset "$REPO_ROOT" "$IMAGE"; then
  echo "CONTROLLER-DEPLOY: FAIL (see pod status/logs below -- this step is expected to PASS)" >&2
  kube -n kube-system get pods -l "$CONTROLLER_SELECTOR" -o wide >&2 || true
  dump_evidence
  exit 1
fi
echo "CONTROLLER-DEPLOY: PASS (servicelb-controller Running on both nodes, zero restarts after a 10s settle)"

for pair in "$NODE_A_K8S:$ULA_A" "$NODE_B_K8S:$ULA_B"; do
  node="${pair%%:*}"
  want="${pair#*:}"
  host_ip="$(kube -n kube-system get pods -l "$CONTROLLER_SELECTOR" --field-selector "spec.nodeName=$node" -o jsonpath='{.items[0].status.hostIP}')"
  [ "$host_ip" = "$want" ] || {
    echo "FAIL: controller pod on $node has status.hostIP='$host_ip', wanted $want -- deploy/daemonset.yaml's --node-ip=\$(NODE_IP) would not be this node's v6 address" >&2
    dump_evidence
    exit 1
  }
done
echo "CONTROLLER-NODE-IP: PASS (status.hostIP -- the DaemonSet's --node-ip -- is $ULA_A on $NODE_A_K8S and $ULA_B on $NODE_B_K8S)"

echo "==> [5/12] creating the backend Pod (hostNetwork, pinned to $NODE_B_K8S) + a SingleStack IPv6 Service"
kube create namespace "$NAMESPACE" --dry-run=client -o yaml | kube apply -f -
cat <<EOF | kube apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: $DEPLOY_NAME
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels: {app: $DEPLOY_NAME}
  template:
    metadata:
      labels: {app: $DEPLOY_NAME}
    spec:
      hostNetwork: true
      nodeName: $NODE_B_K8S
      containers:
        - name: whoami
          image: $BACKEND_IMAGE
          ports:
            - containerPort: $TARGET_PORT
---
apiVersion: v1
kind: Service
metadata:
  name: $SVC_V6
  namespace: $NAMESPACE
spec:
  type: LoadBalancer
  ipFamilyPolicy: SingleStack
  ipFamilies: [IPv6]
  selector: {app: $DEPLOY_NAME}
  ports:
    - port: $PORT_V6
      targetPort: $TARGET_PORT
      protocol: TCP
EOF

echo "==> [6/12] waiting for the Deployment and its IPv6 EndpointSlice"
kube -n "$NAMESPACE" rollout status deployment/"$DEPLOY_NAME" --timeout=60s || {
  echo "FAIL: backend Deployment never became Ready" >&2
  kube -n "$NAMESPACE" describe pods >&2 || true
  dump_evidence
  exit 1
}
ep=""
for _ in $(seq 1 30); do
  ep=$(kube -n "$NAMESPACE" get endpointslices -l kubernetes.io/service-name="$SVC_V6" \
    -o jsonpath='{.items[?(@.addressType=="IPv6")].endpoints[0].addresses[0]}' 2>/dev/null || true)
  [ -n "$ep" ] && break
  sleep 1
done
[ "$ep" = "$ULA_B" ] || {
  echo "FAIL: $SVC_V6's IPv6 EndpointSlice endpoint is '$ep', wanted the hostNetwork pod's node address $ULA_B" >&2
  dump_evidence
  exit 1
}
echo "ENDPOINTSLICE: PASS ($SVC_V6 v6 endpoint=$ep, the hostNetwork backend on $VM_B)"

echo "==> [7/12] confirming status.loadBalancer.ingress lists exactly the two v6 node addresses"
ips=""
for _ in $(seq 1 30); do
  ips=$(kube -n "$NAMESPACE" get svc "$SVC_V6" -o jsonpath='{.status.loadBalancer.ingress[*].ip}' 2>/dev/null || true)
  case " $ips " in *" $ULA_A "*) case " $ips " in *" $ULA_B "*) [ "$(wc -w <<<"$ips")" -eq 2 ] && break ;; esac ;; esac
  sleep 1
done
case " $ips " in *" $ULA_A "*) ;; *) echo "FAIL: $SVC_V6 ingress '$ips' lacks $ULA_A" >&2; dump_evidence; exit 1 ;; esac
case " $ips " in *" $ULA_B "*) ;; *) echo "FAIL: $SVC_V6 ingress '$ips' lacks $ULA_B" >&2; dump_evidence; exit 1 ;; esac
[ "$(wc -w <<<"$ips")" -eq 2 ] || { echo "FAIL: $SVC_V6 ingress '$ips' is not exactly the two v6 node addresses" >&2; dump_evidence; exit 1; }
echo "SERVICE STATUS: PASS ($SVC_V6 status.loadBalancer.ingress=$ips)"

v6_bytes() { # v6_bytes <fd00:beef:98::N> -- jq array literal of the address's 16 octets as bpftool "0xNN" strings (fd00:beef:98::<hex> ULAs only)
  local last="${1##*::}"
  printf '["0xfd","0x00","0xbe","0xef","0x00","0x98","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x%02x"]' "0x$last"
}

echo "==> [8/12] confirming the controller programmed the v6 front on $VM_A and the backend's admission on $VM_B"
# bpftool's --json dump has no BTF for these structs, so key/value are flat
# arrays of "0xNN" byte strings: FRONT_META key = front_ip[0..16) + front_port
# BE [16..18) + proto + pad; value = generation u32 LE [0..4) + count u16 +
# flags u16. FRONT_ENDPOINTS key = that same 20-byte front key + generation
# u32 LE [20..24) + slot u16 [24..26) + pad; value = backend_node_ip[0..16) +
# pod_ip[16..32). The endpoint must sit under the generation FRONT_META names.
port_hi="$(printf '0x%02x' $(( (PORT_V6 >> 8) & 0xff )))"
port_lo="$(printf '0x%02x' $(( PORT_V6 & 0xff )))"
meta_dump="$(map_dump "$VM_A" FRONT_META)" || { echo "FAIL: cannot read $VM_A FRONT_META" >&2; dump_evidence; exit 1; }
ep_dump="$(map_dump "$VM_A" FRONT_ENDPOINTS)" || { echo "FAIL: cannot read $VM_A FRONT_ENDPOINTS" >&2; dump_evidence; exit 1; }
rc=0
jq -e --argjson a "$(v6_bytes "$ULA_A")" --argjson b "$(v6_bytes "$ULA_B")" --arg hi "$port_hi" --arg lo "$port_lo" --argjson eps "$ep_dump" '
  any(.[]; (.key[0:16] == $a) and .key[16] == $hi and .key[17] == $lo
           and (. as $m | any($eps[]; (.key[0:20] == $m.key[0:20])
                and (.key[20:24] == $m.value[0:4])
                and (.key[24:26] == ["0x00","0x00"])
                and (.value[0:16] == $b) and (.value[16:32] == $b))))
' <<<"$meta_dump" >/dev/null 2>&1 || rc=$?
[ "$rc" -eq 0 ] || {
  echo "FAIL: $VM_A FRONT_META/FRONT_ENDPOINTS has no live front=[$ULA_A]:$PORT_V6 -> backend_node_ip=$ULA_B pod_ip=$ULA_B (jq rc=$rc)" >&2
  dump_evidence
  exit 1
}
dump="$(map_dump "$VM_B" POD_TARGETS)" || { echo "FAIL: cannot read $VM_B POD_TARGETS" >&2; dump_evidence; exit 1; }
rc=0
jq -e --argjson b "$(v6_bytes "$ULA_B")" 'any(.[]; .key == $b)' <<<"$dump" >/dev/null 2>&1 || rc=$?
[ "$rc" -eq 0 ] || {
  echo "FAIL: $VM_B POD_TARGETS does not admit the v6-only node's own hostNetwork pod $ULA_B (jq rc=$rc)" >&2
  dump_evidence
  exit 1
}
echo "MAP-PROGRAMMING: PASS ($VM_A FRONT_META/FRONT_ENDPOINTS [$ULA_A]:$PORT_V6 -> v6 underlay remote $ULA_B / pod $ULA_B; $VM_B POD_TARGETS admits $ULA_B)"

echo "==> positive control: one v4 UDP/6081 probe per node must move the DROP counter 0 -> 1"
# The probe is a locally generated v4 UDP/6081 datagram, so it takes the same
# netfilter OUTPUT hook as geneve0's encap: the tunnel's UDP socket transmits
# through udp_tunnel_xmit_skb -> ip_local_out -> NF_INET_LOCAL_OUT. A counter
# that stays 0 here would mean the rule is not on that path and NO-V4-GENEVE
# below could never fail.
V4_BLOCK_BASELINE_A=""
V4_BLOCK_BASELINE_B=""
for vm in "$VM_A" "$VM_B"; do
  [ "$vm" = "$VM_A" ] && peer="$VM_B" || peer="$VM_A"
  peer_ip="$(eth0_ip "$peer")"
  before="$(v4_block_pkts "$vm")" || { echo "NO-V4-GENEVE-CONTROL: FAIL ($vm: cannot read the v4 UDP/6081 DROP counter)" >&2; exit 1; }
  # the DROP verdict surfaces to sendto as EPERM; the counter below is the assertion
  limactl shell "$vm" -- sudo bash -c "echo probe > /dev/udp/$peer_ip/6081" 2>/dev/null || true
  after="$(v4_block_pkts "$vm")" || { echo "NO-V4-GENEVE-CONTROL: FAIL ($vm: cannot re-read the v4 UDP/6081 DROP counter)" >&2; exit 1; }
  if [ "$before" -ne 0 ] || [ "$after" -ne 1 ]; then
    echo "NO-V4-GENEVE-CONTROL: FAIL ($vm: DROP counter $before -> $after after one v4 UDP/6081 probe to $peer_ip; wanted 0 -> 1 -- the rule is not matching or not on the OUTPUT path, or v4 Geneve was already attempted)" >&2
    exit 1
  fi
  if [ "$vm" = "$VM_A" ]; then V4_BLOCK_BASELINE_A="$after"; else V4_BLOCK_BASELINE_B="$after"; fi
done
echo "NO-V4-GENEVE-CONTROL: PASS (one v4 UDP/6081 probe moved each node's DROP counter 0 -> 1, so the rule matches and sits on the OUTPUT path geneve0 encap traverses)"

echo "==> [9/12] snapshotting geneve0 counters and starting an eth0 Geneve capture on both nodes"
geneve_pkts() { limactl shell "$1" -- bash -c "ip -s -j link show geneve0 | jq '.[0].stats64.rx.packets + .[0].stats64.tx.packets'"; }
GENEVE_A_BEFORE="$(geneve_pkts "$VM_A")"
GENEVE_B_BEFORE="$(geneve_pkts "$VM_B")"
for vm in "$VM_A" "$VM_B"; do
  limactl shell "$vm" -- sudo systemctl stop "$CAPTURE_UNIT" >/dev/null 2>&1 || true
  limactl shell "$vm" -- sudo systemd-run --quiet --unit="$CAPTURE_UNIT" tcpdump -nn -U -i eth0 -w "$CAPTURE_FILE" 'udp port 6081'
done
sleep 2

echo "==> [10/12] driving client ($VM_CLIENT) -> [$ULA_A]:$PORT_V6 over v6"
url="http://[$ULA_A]:$PORT_V6/"
set +e
body="$(limactl shell "$VM_CLIENT" -- curl -sS -6 -m 20 "$url" 2>&1)"
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
  echo "ROUND-TRIP-V6ONLY: FAIL (curl -6 $url rc=$rc: $body)" >&2
  dump_evidence
  exit 1
fi
if ! grep -qF "RemoteAddr: [$ULA_CLIENT]:" <<<"$body"; then
  echo "ROUND-TRIP-V6ONLY: FAIL ($url did not report RemoteAddr: [$ULA_CLIENT]:* -- got: $body)" >&2
  dump_evidence
  exit 1
fi
echo "ROUND-TRIP-V6ONLY: PASS (client [$ULA_CLIENT] -> front [$ULA_A]:$PORT_V6 -> backend on $VM_B; reply returned and the backend saw the client's v6 address)"
sleep 1
for vm in "$VM_A" "$VM_B"; do
  limactl shell "$vm" -- sudo systemctl stop "$CAPTURE_UNIT"
done

echo "==> [11/12] proving cross-node traversal over the v6 underlay"
GENEVE_A_AFTER="$(geneve_pkts "$VM_A")"
GENEVE_B_AFTER="$(geneve_pkts "$VM_B")"
if [ "$GENEVE_A_AFTER" -gt "$GENEVE_A_BEFORE" ] && [ "$GENEVE_B_AFTER" -gt "$GENEVE_B_BEFORE" ]; then
  echo "GENEVE0-TRAVERSAL: PASS ($VM_A geneve0 packets $GENEVE_A_BEFORE -> $GENEVE_A_AFTER, $VM_B geneve0 packets $GENEVE_B_BEFORE -> $GENEVE_B_AFTER -- both moved)"
else
  echo "GENEVE0-TRAVERSAL: FAIL ($VM_A geneve0 packets $GENEVE_A_BEFORE -> $GENEVE_A_AFTER, $VM_B geneve0 packets $GENEVE_B_BEFORE -> $GENEVE_B_AFTER)" >&2
  dump_evidence
  exit 1
fi
cap_count() { # cap_count <vm> <tcpdump-filter> -- packets in the capture matching the filter
  limactl shell "$1" -- sudo bash -c "tcpdump -nn -r '$CAPTURE_FILE' '$2' 2>/dev/null | wc -l" | tr -d ' '
}
for vm in "$VM_A" "$VM_B"; do
  fwd="$(cap_count "$vm" "ip6 and src $ULA_A and dst $ULA_B and udp port 6081")"
  ret="$(cap_count "$vm" "ip6 and src $ULA_B and dst $ULA_A and udp port 6081")"
  if [ "$fwd" -ge 1 ] && [ "$ret" -ge 1 ]; then
    echo "  $vm eth0: Geneve/v6 $ULA_A->$ULA_B=$fwd, $ULA_B->$ULA_A=$ret"
  else
    echo "UNDERLAY-V6-TRAVERSAL: FAIL ($vm eth0 capture: $ULA_A->$ULA_B=$fwd, $ULA_B->$ULA_A=$ret; wanted both v6 directions >= 1)" >&2
    dump_evidence
    exit 1
  fi
done
echo "UNDERLAY-V6-TRAVERSAL: PASS (Geneve over v6 observed on both nodes' eth0 in both directions between $ULA_A and $ULA_B -- forward and symmetric return crossed the v6 underlay)"
for vm in "$VM_A" "$VM_B"; do
  if [ "$vm" = "$VM_A" ]; then baseline="$V4_BLOCK_BASELINE_A"; else baseline="$V4_BLOCK_BASELINE_B"; fi
  v4_attempts="$(v4_block_pkts "$vm")" || { echo "NO-V4-GENEVE: FAIL ($vm: cannot read back exactly one v4 UDP/6081 DROP rule -- v4 attempts are unknown)" >&2; dump_evidence; exit 1; }
  if ! [[ "$v4_attempts" =~ ^[0-9]+$ ]] || [ "$v4_attempts" -ne "$baseline" ]; then
    echo "NO-V4-GENEVE: FAIL ($vm's v4 UDP/6081 DROP rule counted '$v4_attempts' packets, baseline after the control probe was $baseline -- the dataplane attempted v4 Geneve on a v6-only cluster)" >&2
    dump_evidence
    exit 1
  fi
done
echo "NO-V4-GENEVE: PASS (the v4 UDP/6081 DROP rule's packet counter is unchanged from its post-control baseline on $VM_A and $VM_B after the round trip -- no v4 Geneve was ever attempted, not merely none seen past the drop)"

echo "==> [12/12] confirming a FLOW_TABLE entry for the client exists on the ingress node"
dump="$(map_dump "$VM_A" FLOW_TABLE)" || { echo "FAIL: cannot read $VM_A FLOW_TABLE" >&2; dump_evidence; exit 1; }
rc=0
jq -e --argjson c "$(v6_bytes "$ULA_CLIENT")" --argjson a "$(v6_bytes "$ULA_A")" '
  any(.[]; (.key | . as $k | [range(0; length - 15)] | any(.[]; $k[.:(. + 16)] == $c))
           and (.key | . as $k | [range(0; length - 15)] | any(.[]; $k[.:(. + 16)] == $a)))
' <<<"$dump" >/dev/null 2>&1 || rc=$?
[ "$rc" -eq 0 ] || {
  echo "FAIL: $VM_A's FLOW_TABLE has no flow between client $ULA_CLIENT and front $ULA_A after the completed round trip (jq rc=$rc)" >&2
  dump_evidence
  exit 1
}
echo "CONNTRACK: PASS ($VM_A FLOW_TABLE holds a flow keyed on client $ULA_CLIENT and front $ULA_A)"

echo ""
echo "GATE IPV6-ONLY CONTROLLER-DRIVEN ROUND-TRIP: PASS"
