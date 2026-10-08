#!/usr/bin/env bash
# Dual-stack sibling of scripts/smoke-k3s-controller.sh: proves the REAL
# controller (Node/Service/EndpointSlice watch, deploy/daemonset.yaml -- not
# a hand-rolled --fixture) correctly fronts THREE real Service objects on a
# genuinely dual-stack k3s cluster (scripts/k3s-up.sh --dual-stack):
#
#   - a PreferDualStack Service (both a v4 and a v6 front)
#   - a SingleStack IPv4 Service (v4 front only)
#   - a SingleStack IPv6 Service (v6 front only)
#
# all backed by ONE hostNetwork Pod pinned to $VM_B -- hostNetwork makes the
# Pod's own status.podIPs equal to $VM_B's real node addresses (both
# families), so EndpointSliceController naturally emits one IPv4 and one
# IPv6 EndpointSlice without needing flannel's own pod network to be
# dual-stack-capable end to end (verified live: a probe Deployment's
# status.podIPs listed both the node's v4 AND v6 address). This keeps the
# gate scoped to what this rig actually tests -- the controller's
# Service/EndpointSlice/Node reconcile + the dataplane's family-aware
# front/tunnel-key handling -- not flannel's own dual-stack CNI plumbing.
#
# TOPOLOGY: same as smoke-k3s-controller.sh -- ingress = $VM_A's own
# address(es), backend Pod on $VM_B, client is the separate $VM_CLIENT VM.
# The underlay Geneve tunnel itself stays v4 (both nodes' --node-ip primary
# family is v4; the controller's pick_underlay_ip prefers a same-family
# match), same as smoke-wg-2node-dualstack.sh's fixture -- only the
# front/pod_ip family varies per Service. A genuinely v6-only underlay is
# out of scope here; see this bead's IPv6-only-node section.
#
# LAN v6: Lima's user-v2 switch forwards v6 unicast between VMs but hands
# out no routable address of its own (no RA/DHCPv6) and drops the multicast
# NDP that would resolve neighbors automatically -- confirmed live (ping6
# full-mesh across $VM_A/$VM_B/$VM_CLIENT after static ULA + `ip -6 neigh`).
# scripts/k3s-common.sh's k3s_seed_lan_v6 assigns fd00:beef:98::3/::4/::14
# (the same prefix+suffixes smoke-wg-2node.sh's --family 6 mode already
# uses for $VM_B/$VM_CLIENT, so the two rigs never fight over addressing).
#
# Usage: scripts/smoke-k3s-controller-dualstack.sh [--vm-a <ingress-vm>] [--vm-b <backend-vm>] [--vm-client <client-vm>]
#
# Test hook: BEEP_SMOKE_MAP_DUMP_TIMEOUT=<seconds> (default 20) bounds each
# bpftool map dump; 0 forces every dump to time out, which must FAIL the gate
# at the first map check (an unreadable map is never treated as empty).
# BEEP_SMOKE_EVIDENCE_TIMEOUT=<seconds> (default 20) likewise bounds each call
# of the FAIL-path evidence dump; 0 forces every call to report EVIDENCE TIMEOUT.
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

NAMESPACE="beep-controller-e2e-dualstack"
DEPLOY_NAME="whoami-ds"
SVC_DUAL="whoami-dual"
SVC_V4="whoami-v4only"
SVC_V6="whoami-v6only"
PORT_DUAL="8080"
PORT_V4="8081"
PORT_V6="8082"
TARGET_PORT="80"
PIN_DIR="/sys/fs/bpf/beep"
# deploy/daemonset.yaml hardcodes this exact secret name (not
# parameterizable) -- must match, not a free choice.
KUBECONFIG_SECRET="beep-controller-kubeconfig"
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

map_dump() { # map_dump <vm> <map-name> -- raw bpftool JSON dump of a pinned map on stdout, exit 0 (a genuinely empty map prints "[]"); exit 1 with the reason on stderr if the pin is missing/unreadable, bpftool/limactl fails, or the call times out. Callers MUST treat non-zero as a gate FAIL, never as "empty": an absence check must not pass on a dump that never happened. Bounded to ${BEEP_SMOKE_MAP_DUMP_TIMEOUT:-20}s rather than a bare `limactl shell` call: observed live, a loaded node's SSH session can wedge indefinitely under this rig's load, which would otherwise hang the whole gate rather than failing loud (macOS has no `timeout` builtin, so this polls a backgrounded call).
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

dump_evidence() { k3s_dump_evidence "$VM_A" "$VM_B" "$PIN_DIR"; }

cleanup() {
  kube delete namespace "$NAMESPACE" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  k3s_teardown_controller "$REPO_ROOT" "$KUBECONFIG_SECRET"
  [ -n "$IMAGE_TMPDIR" ] && rm -rf "$IMAGE_TMPDIR"
  [ -n "$IMAGE" ] && docker rmi "$IMAGE" >/dev/null 2>&1 || true
  for vm in "$VM_A" "$VM_B"; do
    limactl shell "$vm" -- sudo rm -rf "$PIN_DIR" >/dev/null 2>&1 || true
    limactl shell "$vm" -- sudo ip link del geneve0 >/dev/null 2>&1 || true
    limactl shell "$vm" -- sudo bash -c '
      if [ -f /tmp/beep-k3s-controller-dualstack-rpfilter-all.saved ]; then
        sysctl -w net.ipv4.conf.all.rp_filter="$(cat /tmp/beep-k3s-controller-dualstack-rpfilter-all.saved)" >/dev/null 2>&1 || true
        rm -f /tmp/beep-k3s-controller-dualstack-rpfilter-all.saved
      fi
    ' >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

echo "==> [1/12] bringing up the DUAL-STACK k3s cluster ($VM_A server, $VM_B agent) and $VM_CLIENT"
k3s_bring_up_cluster "$VM_A" "$VM_B" "$VM_CLIENT" "iptables" "1"
k3s_seed_lan_v6 "$VM_A" "$K3S_LAN_ULA_A" "$VM_B" "$K3S_LAN_ULA_B" "$VM_CLIENT" "$K3S_LAN_ULA_CLIENT"

IP_A="$(eth0_ip "$VM_A")"
IP_B="$(eth0_ip "$VM_B")"
IP_CLIENT="$(eth0_ip "$VM_CLIENT")"
[ -n "$IP_A" ] && [ -n "$IP_B" ] && [ -n "$IP_CLIENT" ] || {
  echo "FAIL: could not resolve eth0 addresses (a=$IP_A b=$IP_B client=$IP_CLIENT)" >&2
  exit 1
}
ULA_A="$K3S_LAN_ULA_A"
ULA_B="$K3S_LAN_ULA_B"
ULA_CLIENT="$K3S_LAN_ULA_CLIENT"
NODE_A_K8S="lima-${VM_A}"
NODE_B_K8S="lima-${VM_B}"
kube get node "$NODE_A_K8S" "$NODE_B_K8S" >/dev/null || {
  echo "FAIL: expected k8s node names lima-\$VM -- $NODE_A_K8S/$NODE_B_K8S not both found" >&2
  exit 1
}
for want in "$IP_A" "$ULA_A"; do
  kube get node "$NODE_A_K8S" -o jsonpath='{.status.addresses[*].address}' | grep -q "$want" || {
    echo "FAIL: $NODE_A_K8S's Node object does not report InternalIP $want -- cluster is not genuinely dual-stack-shaped" >&2
    exit 1
  }
done
echo "CLUSTER-UP: PASS (dual-stack; $VM_A=$IP_A/$ULA_A ingress, $VM_B=$IP_B/$ULA_B backend, client=$VM_CLIENT $IP_CLIENT/$ULA_CLIENT)"

echo "==> [2/12] creating geneve0 on both nodes (external mode -- beep sets the tunnel key itself)"
for vm in "$VM_A" "$VM_B"; do
  limactl shell "$vm" -- sudo bash -c '
    ip link show geneve0 >/dev/null 2>&1 || ip link add geneve0 type geneve external
    ip link set geneve0 up
    if [ ! -f /tmp/beep-k3s-controller-dualstack-rpfilter-all.saved ]; then
      sysctl -n net.ipv4.conf.all.rp_filter > /tmp/beep-k3s-controller-dualstack-rpfilter-all.saved
    fi
    sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
    sysctl -w net.ipv4.conf.geneve0.rp_filter=0 >/dev/null
  '
done

echo "==> [3/12] provisioning the controller's kubeconfig Secret from $VM_A's own admin kubeconfig"
k3s_provision_kubeconfig_secret "$VM_A" "$IP_A" "$KUBECONFIG_SECRET" 1

SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"
IMAGE="docker.io/valerauko/beep-lb:${SHA}-dualstack"
echo "==> [4/12] building the commit-under-test's image ($IMAGE) and deploying the controller DaemonSet"
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

if ! k3s_deploy_controller_daemonset "$REPO_ROOT" "$IMAGE"; then
  echo "CONTROLLER-DEPLOY: FAIL (see pod status/logs below -- this step is expected to PASS)" >&2
  kube -n kube-system get pods -l "$CONTROLLER_SELECTOR" -o wide >&2 || true
  dump_evidence
  exit 1
fi
echo "CONTROLLER-DEPLOY: PASS (servicelb-controller Running on both nodes, zero restarts after a 10s settle)"

echo "==> [5/12] creating the backend Pod (hostNetwork, pinned to $NODE_B_K8S) + 3 Services"
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
          image: docker.io/traefik/whoami:latest
          ports:
            - containerPort: $TARGET_PORT
---
apiVersion: v1
kind: Service
metadata:
  name: $SVC_DUAL
  namespace: $NAMESPACE
spec:
  type: LoadBalancer
  ipFamilyPolicy: PreferDualStack
  selector: {app: $DEPLOY_NAME}
  ports:
    - port: $PORT_DUAL
      targetPort: $TARGET_PORT
      protocol: TCP
---
apiVersion: v1
kind: Service
metadata:
  name: $SVC_V4
  namespace: $NAMESPACE
spec:
  type: LoadBalancer
  ipFamilyPolicy: SingleStack
  ipFamilies: [IPv4]
  selector: {app: $DEPLOY_NAME}
  ports:
    - port: $PORT_V4
      targetPort: $TARGET_PORT
      protocol: TCP
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

echo "==> [6/12] waiting for the Deployment and per-family EndpointSlices"
kube -n "$NAMESPACE" rollout status deployment/"$DEPLOY_NAME" --timeout=60s || {
  echo "FAIL: backend Deployment never became Ready" >&2
  kube -n "$NAMESPACE" describe pods >&2 || true
  dump_evidence
  exit 1
}

wait_for_endpointslice_family() { # wait_for_endpointslice_family <svc> <addressType> -- polls up to 30s for an EndpointSlice of the given family
  local svc="$1" family="$2" found=""
  for _ in $(seq 1 30); do
    found=$(kube -n "$NAMESPACE" get endpointslices -l kubernetes.io/service-name="$svc" \
      -o jsonpath="{.items[?(@.addressType==\"$family\")].endpoints[0].addresses[0]}" 2>/dev/null || true)
    [ -n "$found" ] && { echo "$found"; return 0; }
    sleep 1
  done
  return 1
}

dual_v4_ep="$(wait_for_endpointslice_family "$SVC_DUAL" IPv4)" || { echo "FAIL: no IPv4 EndpointSlice for $SVC_DUAL" >&2; dump_evidence; exit 1; }
dual_v6_ep="$(wait_for_endpointslice_family "$SVC_DUAL" IPv6)" || { echo "FAIL: no IPv6 EndpointSlice for $SVC_DUAL" >&2; dump_evidence; exit 1; }
v4only_ep="$(wait_for_endpointslice_family "$SVC_V4" IPv4)" || { echo "FAIL: no IPv4 EndpointSlice for $SVC_V4" >&2; dump_evidence; exit 1; }
v6only_ep="$(wait_for_endpointslice_family "$SVC_V6" IPv6)" || { echo "FAIL: no IPv6 EndpointSlice for $SVC_V6" >&2; dump_evidence; exit 1; }
# The negative half of "each SingleStack Service gets only its own family":
# a SingleStack IPv4 Service must NEVER get an IPv6 EndpointSlice, and vice
# versa, even though the backing Pod itself is dual-stack (hostNetwork).
if kube -n "$NAMESPACE" get endpointslices -l kubernetes.io/service-name="$SVC_V4" -o jsonpath='{.items[*].addressType}' | grep -q IPv6; then
  echo "FAIL: $SVC_V4 (SingleStack IPv4) unexpectedly has an IPv6 EndpointSlice" >&2
  dump_evidence
  exit 1
fi
if kube -n "$NAMESPACE" get endpointslices -l kubernetes.io/service-name="$SVC_V6" -o jsonpath='{.items[*].addressType}' | grep -q IPv4; then
  echo "FAIL: $SVC_V6 (SingleStack IPv6) unexpectedly has an IPv4 EndpointSlice" >&2
  dump_evidence
  exit 1
fi
echo "ENDPOINTSLICE: PASS ($SVC_DUAL v4=$dual_v4_ep v6=$dual_v6_ep, $SVC_V4 v4=$v4only_ep only, $SVC_V6 v6=$v6only_ep only)"

echo "==> [7/12] confirming status.loadBalancer.ingress lists exactly the fronted families per Service"
assert_ingress() { # assert_ingress <svc> <want-count> <must-contain...> -- polls status.loadBalancer.ingress up to 30s
  local svc="$1" want_count="$2"; shift 2
  local ips="" ok=0 want
  for _ in $(seq 1 30); do
    ips=$(kube -n "$NAMESPACE" get svc "$svc" -o jsonpath='{.status.loadBalancer.ingress[*].ip}' 2>/dev/null || true)
    ok=1
    for want in "$@"; do
      case " $ips " in *" $want "*) ;; *) ok=0 ;; esac
    done
    [ "$(wc -w <<<"$ips")" -eq "$want_count" ] || ok=0
    [ "$ok" -eq 1 ] && break
    sleep 1
  done
  if [ "$ok" -ne 1 ]; then
    echo "FAIL: $svc's status.loadBalancer.ingress = '$ips', wanted exactly [$*] ($want_count entries)" >&2
    return 1
  fi
  echo "  $svc ingress: $ips"
}
assert_ingress "$SVC_DUAL" 4 "$IP_A" "$ULA_A" "$IP_B" "$ULA_B" || { dump_evidence; exit 1; }
assert_ingress "$SVC_V4" 2 "$IP_A" "$IP_B" || { dump_evidence; exit 1; }
assert_ingress "$SVC_V6" 2 "$ULA_A" "$ULA_B" || { dump_evidence; exit 1; }
echo "SERVICE STATUS: PASS (each Service's status.loadBalancer.ingress matches exactly its own spec.ipFamilies)"

echo "==> [8/12] confirming $VM_A's own dataplane front is programmed for each family it should serve, and NOT for families it shouldn't"
# bpftool's --json dump has no BTF for LbFrontKey, so `key`/`value` are each
# a flat array of "0xNN" byte strings (address order), not named
# front_ip/front_port fields. Bytes [0..16)=front_ip, [16..18)=front_port
# (beep_common::wire_port() = port.to_be(); on this LE host that store+load
# round-trip nets out to the raw bytes being the port's plain big-endian
# (network) representation, so compare against that directly). front_ip's v4
# case is stored as v4-mapped-v6 (bytes[10..12] == ff,ff -- LbFrontKey's own
# doc comment).
front_has_family() { # front_has_family <vm> <port> <family: v4|v6> [any] -- true if FRONT_META has a key at this port whose front_ip byte pattern matches the requested family AND (unless "any") FRONT_ENDPOINTS holds an entry under that front's live generation (FRONT_META value[0..4) = generation u32 LE; FRONT_ENDPOINTS key = the 20-byte front key + generation [20..24)). "any" is for absence checks: a stale or half-programmed front must still count as present.
  local vm="$1" port="$2" family="$3" mode="${4:-live}" hi lo dump ep_dump="[]"
  hi="$(printf '0x%02x' $(( (port >> 8) & 0xff )))"
  lo="$(printf '0x%02x' $(( port & 0xff )))"
  dump="$(map_dump "$vm" FRONT_META)" || { echo "FAIL: cannot read $vm FRONT_META -- front presence/absence is unknown" >&2; dump_evidence; exit 1; }
  if [ "$mode" != "any" ]; then
    ep_dump="$(map_dump "$vm" FRONT_ENDPOINTS)" || { echo "FAIL: cannot read $vm FRONT_ENDPOINTS -- front endpoint presence is unknown" >&2; dump_evidence; exit 1; }
  fi
  local rc=0
  jq -e --arg hi "$hi" --arg lo "$lo" --arg fam "$family" --arg mode "$mode" --argjson eps "$ep_dump" '
    any(.[]; . as $m | $m.key as $k |
      ($k[16] == $hi and $k[17] == $lo) and
      (if $fam == "v4" then ($k[10] == "0xff" and $k[11] == "0xff")
       else ($k[10] != "0xff" or $k[11] != "0xff") end) and
      ($mode == "any" or any($eps[]; (.key[0:20] == $k[0:20]) and (.key[20:24] == $m.value[0:4]))))
  ' <<<"$dump" >/dev/null 2>&1 || rc=$?
  # jq -e: 1 = filter false/null (a real answer); >1 = jq itself failed (unparseable dump).
  [ "$rc" -le 1 ] || { echo "FAIL: $vm FRONT_META/FRONT_ENDPOINTS dump is not parseable JSON -- front presence/absence is unknown" >&2; dump_evidence; exit 1; }
  return "$rc"
}
front_has_family "$VM_A" "$PORT_DUAL" v4 || { echo "FAIL: $VM_A FRONT_META/FRONT_ENDPOINTS has no live v4 front for $SVC_DUAL (port $PORT_DUAL)" >&2; dump_evidence; exit 1; }
front_has_family "$VM_A" "$PORT_DUAL" v6 || { echo "FAIL: $VM_A FRONT_META/FRONT_ENDPOINTS has no live v6 front for $SVC_DUAL (port $PORT_DUAL)" >&2; dump_evidence; exit 1; }
front_has_family "$VM_A" "$PORT_V4" v4 || { echo "FAIL: $VM_A FRONT_META/FRONT_ENDPOINTS has no live v4 front for $SVC_V4 (port $PORT_V4)" >&2; dump_evidence; exit 1; }
if front_has_family "$VM_A" "$PORT_V4" v6 any; then
  echo "FAIL: $VM_A FRONT_META has a v6 front for SingleStack-IPv4 $SVC_V4 (port $PORT_V4) -- should be v4-only" >&2
  dump_evidence
  exit 1
fi
front_has_family "$VM_A" "$PORT_V6" v6 || { echo "FAIL: $VM_A FRONT_META/FRONT_ENDPOINTS has no live v6 front for $SVC_V6 (port $PORT_V6)" >&2; dump_evidence; exit 1; }
if front_has_family "$VM_A" "$PORT_V6" v4 any; then
  echo "FAIL: $VM_A FRONT_META has a v4 front for SingleStack-IPv6 $SVC_V6 (port $PORT_V6) -- should be v6-only" >&2
  dump_evidence
  exit 1
fi
pod_targets_b=$(map_dump "$VM_B" POD_TARGETS | jq 'length') || { echo "FAIL: cannot read $VM_B POD_TARGETS" >&2; dump_evidence; exit 1; }
[ "$pod_targets_b" -ge 1 ] || { echo "FAIL: $VM_B's POD_TARGETS has no entries -- the backend Pod was never admitted" >&2; dump_evidence; exit 1; }
echo "MAP-PROGRAMMING: PASS ($VM_A FRONT_META has v4+v6 fronts for $SVC_DUAL, v4-only for $SVC_V4, v6-only for $SVC_V6; $VM_B POD_TARGETS=$pod_targets_b entries)"

echo "==> [9/12] snapshotting geneve0 packet counters on both nodes before the round trips"
geneve_pkts() { limactl shell "$1" -- bash -c "ip -s -j link show geneve0 | jq '.[0].stats64.rx.packets + .[0].stats64.tx.packets'"; }
GENEVE_A_BEFORE="$(geneve_pkts "$VM_A")"
GENEVE_B_BEFORE="$(geneve_pkts "$VM_B")"

echo "==> [10/12] driving client ($VM_CLIENT) -> $SVC_DUAL: v4 ($IP_A:$PORT_DUAL) and v6 ([$ULA_A]:$PORT_DUAL)"
http_url() { # http_url <addr> <port>
  echo "http://$(host_port "$1" "$2")/"
}
round_trip() { # round_trip <curl-family-flag> <dial-addr> <port> <expect-client-addr> -- returns the body on success, prints ROUND-TRIP FAIL and returns 1 otherwise
  local flag="$1" addr="$2" port="$3" expect="$4" body rc url
  url="$(http_url "$addr" "$port")"
  set +e
  body="$(limactl shell "$VM_CLIENT" -- curl -sS "$flag" -m 20 "$url" 2>&1)"
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    echo "FAIL: curl $flag $url rc=$rc" >&2
    return 1
  fi
  if ! grep -qF "RemoteAddr: $(host_port "$expect" "")" <<<"$body"; then
    echo "FAIL: $url did not report RemoteAddr: $(host_port "$expect" "")* -- got: $body" >&2
    return 1
  fi
  echo "$body"
}
round_trip -4 "$IP_A" "$PORT_DUAL" "$IP_CLIENT" >/dev/null || { echo "ROUND-TRIP-DUAL-V4: FAIL" >&2; dump_evidence; exit 1; }
echo "ROUND-TRIP-DUAL-V4: PASS (client $IP_CLIENT -> $SVC_DUAL v4 front $IP_A:$PORT_DUAL -> backend on $VM_B, client IP preserved)"
round_trip -6 "$ULA_A" "$PORT_DUAL" "$ULA_CLIENT" >/dev/null || { echo "ROUND-TRIP-DUAL-V6: FAIL" >&2; dump_evidence; exit 1; }
echo "ROUND-TRIP-DUAL-V6: PASS (client $ULA_CLIENT -> $SVC_DUAL v6 front [$ULA_A]:$PORT_DUAL -> backend on $VM_B, client IP preserved)"

echo "==> [11/12] negative checks: a v6 client must NOT reach the SingleStack-IPv4 Service (and vice versa)"
expect_refused() { # expect_refused <curl-family-flag> <dial-addr> <port> -- passes only on curl rc 7 with the connect errno "Connection refused" (from -v; the summary line says only "Couldn't connect"): the node answered with an RST because no front exists for this family (an RST proves only that no front serves it; the FRONT_META absence check in step 8 covers "beep never programmed one"). LC_ALL=C pins curl's English errno text. Any other rc (timeout 28, no route, malformed URL 3, ...) or a successful fetch means the path is broken or leaking, not correctly refused.
  local flag="$1" addr="$2" port="$3" out rc url
  url="$(http_url "$addr" "$port")"
  set +e
  out="$(limactl shell "$VM_CLIENT" -- env LC_ALL=C curl -sSv "$flag" -m 5 "$url" 2>&1)"
  rc=$?
  set -e
  if [ "$rc" -eq 7 ] && grep -qF "failed: Connection refused" <<<"$out"; then
    return 0
  fi
  echo "FAIL: curl $flag $url expected rc=7 + 'failed: Connection refused', got rc=$rc: $out" >&2
  return 1
}
round_trip -4 "$IP_A" "$PORT_V4" "$IP_CLIENT" >/dev/null || { echo "NEGATIVE-FAMILY-ISOLATION: FAIL (positive control: v4 client could not reach $SVC_V4's v4 front $IP_A:$PORT_V4)" >&2; dump_evidence; exit 1; }
round_trip -6 "$ULA_A" "$PORT_V6" "$ULA_CLIENT" >/dev/null || { echo "NEGATIVE-FAMILY-ISOLATION: FAIL (positive control: v6 client could not reach $SVC_V6's v6 front [$ULA_A]:$PORT_V6)" >&2; dump_evidence; exit 1; }
expect_refused -6 "$ULA_A" "$PORT_V4" || { echo "NEGATIVE-FAMILY-ISOLATION: FAIL (v6 client vs $SVC_V4's v4-only front)" >&2; dump_evidence; exit 1; }
expect_refused -4 "$IP_A" "$PORT_V6" || { echo "NEGATIVE-FAMILY-ISOLATION: FAIL (v4 client vs $SVC_V6's v6-only front)" >&2; dump_evidence; exit 1; }
echo "NEGATIVE-FAMILY-ISOLATION: PASS (same-family positive controls served on $SVC_V4 v4 and $SVC_V6 v6; cross-family curls refused with rc=7 Connection refused)"

GENEVE_A_AFTER="$(geneve_pkts "$VM_A")"
GENEVE_B_AFTER="$(geneve_pkts "$VM_B")"
if [ "$GENEVE_A_AFTER" -gt "$GENEVE_A_BEFORE" ] && [ "$GENEVE_B_AFTER" -gt "$GENEVE_B_BEFORE" ]; then
  echo "GENEVE0-TRAVERSAL: PASS ($VM_A geneve0 packets $GENEVE_A_BEFORE -> $GENEVE_A_AFTER, $VM_B geneve0 packets $GENEVE_B_BEFORE -> $GENEVE_B_AFTER -- both moved, so the round trips above genuinely crossed the underlay tunnel in both directions, not a same-node self-loop)"
else
  echo "GENEVE0-TRAVERSAL: FAIL ($VM_A geneve0 packets $GENEVE_A_BEFORE -> $GENEVE_A_AFTER, $VM_B geneve0 packets $GENEVE_B_BEFORE -> $GENEVE_B_AFTER)" >&2
  dump_evidence
  exit 1
fi

echo "==> [12/12] confirming a conntrack/FLOW_TABLE entry exists on the ingress node"
flow_a=$(map_dump "$VM_A" FLOW_TABLE | jq 'length') || { echo "FAIL: cannot read $VM_A FLOW_TABLE" >&2; dump_evidence; exit 1; }
[ "$flow_a" -ge 1 ] || {
  echo "FAIL: $VM_A's FLOW_TABLE has no entries ($flow_a) after completed round trips" >&2
  dump_evidence
  exit 1
}
echo "CONNTRACK: PASS ($VM_A FLOW_TABLE=$flow_a entries)"

echo ""
echo "GATE DUAL-STACK CONTROLLER-DRIVEN ROUND-TRIP: PASS"
