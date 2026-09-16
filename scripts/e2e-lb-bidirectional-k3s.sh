#!/usr/bin/env bash
# Bidirectional cross-node LB gate on the k3s-on-Lima rig
# (ai/extended-context/k3s-e2e-rig.md): TWO type=LoadBalancer Services in
# ONE cluster bring-up, with opposite node-pinning --
#   direction 1: backend Pod on node-a, dialed through node-b's own address
#   direction 2: backend Pod on node-b, dialed through node-a's own address
# scripts/smoke-k3s-controller.sh and scripts/e2e-lb-k3s.sh's upstream specs
# only ever exercise direction 2's orientation (backend on the k3s agent,
# dialed via the k3s server) -- this catches a Geneve encap/decap or
# return-path bug that only manifests in the other ingress/backend
# orientation, since node-a (k3s server, apiserver-hosting) and node-b (k3s
# agent) are not guaranteed symmetric just because the same eBPF program is
# loaded on both. Reuses scripts/k3s-up.sh's bring-up and
# deploy/{rbac,daemonset}.yaml, same as smoke-k3s-controller.sh -- does not
# re-assert RSS/FLOW_TABLE/VIP_MAP population already covered there.
#
# Each direction uses a distinct VIP port (80 vs 8081): a type=LoadBalancer
# Service's status.loadBalancer.ingress lists ALL node IPs regardless of
# which node its backend Pod is pinned to, so two Services sharing one VIP
# port would race for the same (node-ip, port) dataplane map key on
# whichever node isn't hosting either one's backend.
#
# For BOTH directions this asserts: the round trip succeeds, AND the real
# client IP survives end-to-end (beep never source-NATs the forward leg) --
# the whoami backend's own RemoteAddr report is the proof.
#
# Usage: scripts/e2e-lb-bidirectional-k3s.sh [--vm-a <ingress-vm>] [--vm-b <backend-vm>] [--vm-client <client-vm>]
# Defaults: beep-node-a (k3s server), beep-node-b (k3s agent), beep-client.
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

NAMESPACE="beep-bidirectional-e2e"
PORT_SVC_A="80"   # svc-on-node-a, dialed via node-b
PORT_SVC_B="8081" # svc-on-node-b, dialed via node-a
PIN_DIR="/sys/fs/bpf/beep"
KUBECONFIG_SECRET="beep-controller-kubeconfig"
RPFILTER_SAVE="/tmp/beep-k3s-bidirectional-rpfilter-all.saved"

for tool in limactl jq; do
  command -v "$tool" >/dev/null || { echo "FAIL: $tool not found on PATH" >&2; exit 1; }
done

kube() { # kube <args...> -- runs k3s kubectl as root on $VM_A (the only node with a local apiserver)
  limactl shell "$VM_A" -- sudo k3s kubectl "$@"
}

eth0_ip() { # eth0_ip <vm> -- this VM's real underlay address
  limactl shell "$1" -- bash -c "ip -4 -o addr show eth0 | awk '{print \$4}' | cut -d/ -f1"
}

dump_evidence() {
  for vm in "$VM_A" "$VM_B"; do
    echo "---- $vm evidence ----"
    for m in VIP_MAP TARGET_PORTS POD_TARGETS FLOW_TABLE; do
      echo "== bpftool map dump: $m =="
      limactl shell "$vm" -- sudo bpftool map dump pinned "$PIN_DIR/$m" 2>&1 || true
    done
    echo "== ip -s link (eth0, geneve0) =="
    limactl shell "$vm" -- ip -s link show eth0 2>&1 || true
    limactl shell "$vm" -- ip -s link show geneve0 2>&1 || true
    echo "== dmesg (tail) =="
    limactl shell "$vm" -- sudo dmesg 2>&1 | tail -30 || true
  done
  echo "---- controller pod logs (current + previous, i.e. pre-crash) ----"
  kube -n kube-system logs -l "$CONTROLLER_SELECTOR" --all-containers --tail=100 2>&1 || true
  kube -n kube-system logs -l "$CONTROLLER_SELECTOR" --all-containers --tail=100 --previous 2>&1 || true
}

cleanup() {
  kube delete namespace "$NAMESPACE" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  # `-f -` (stdin), not a host path: `kube` runs kubectl on $VM_A, which has
  # no access to this script's own (host-side) $REPO_ROOT.
  kube delete -f - --ignore-not-found < "$REPO_ROOT/deploy/daemonset.yaml" >/dev/null 2>&1 || true
  kube delete -f - --ignore-not-found < "$REPO_ROOT/deploy/rbac.yaml" >/dev/null 2>&1 || true
  kube delete secret "$KUBECONFIG_SECRET" -n kube-system --ignore-not-found >/dev/null 2>&1 || true
  for vm in "$VM_A" "$VM_B"; do
    limactl shell "$vm" -- sudo rm -rf "$PIN_DIR" >/dev/null 2>&1 || true
    limactl shell "$vm" -- sudo ip link del geneve0 >/dev/null 2>&1 || true
  done
  limactl shell "$VM_A" -- sudo bash -c "
    if [ -f '$RPFILTER_SAVE' ]; then
      sysctl -w net.ipv4.conf.all.rp_filter=\"\$(cat '$RPFILTER_SAVE')\" >/dev/null 2>&1 || true
      rm -f '$RPFILTER_SAVE'
    fi
  " >/dev/null 2>&1 || true
  limactl shell "$VM_B" -- sudo bash -c "
    if [ -f '$RPFILTER_SAVE' ]; then
      sysctl -w net.ipv4.conf.all.rp_filter=\"\$(cat '$RPFILTER_SAVE')\" >/dev/null 2>&1 || true
      rm -f '$RPFILTER_SAVE'
    fi
  " >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> [1/8] bringing up the k3s cluster ($VM_A server, $VM_B agent) and $VM_CLIENT"
"$SCRIPT_DIR/k3s-up.sh" --vm-a "$VM_A" --vm-b "$VM_B"
if ! limactl list --format '{{.Name}}\t{{.Status}}' 2>/dev/null | grep -qE "^${VM_CLIENT}[[:space:]]+Running"; then
  limactl start "$VM_CLIENT"
fi

IP_A="$(eth0_ip "$VM_A")"
IP_B="$(eth0_ip "$VM_B")"
IP_CLIENT="$(eth0_ip "$VM_CLIENT")"
[ -n "$IP_A" ] && [ -n "$IP_B" ] && [ -n "$IP_CLIENT" ] || {
  echo "FAIL: could not resolve eth0 addresses (a=$IP_A b=$IP_B client=$IP_CLIENT)" >&2
  exit 1
}
NODE_A_K8S="lima-${VM_A}"
NODE_B_K8S="lima-${VM_B}"
kube get node "$NODE_A_K8S" "$NODE_B_K8S" >/dev/null || {
  echo "FAIL: expected k8s node names lima-\$VM -- $NODE_A_K8S/$NODE_B_K8S not both found" >&2
  exit 1
}
echo "CLUSTER-UP: PASS ($VM_A=$IP_A/$NODE_A_K8S, $VM_B=$IP_B/$NODE_B_K8S, client=$VM_CLIENT/$IP_CLIENT)"

echo "==> [2/8] creating geneve0 on both nodes (external mode -- beep sets the tunnel key itself)"
for vm in "$VM_A" "$VM_B"; do
  limactl shell "$vm" -- sudo bash -c "
    ip link show geneve0 >/dev/null 2>&1 || ip link add geneve0 type geneve external
    ip link set geneve0 up
    # Same rp_filter workaround as smoke-k3s-controller.sh: geneve0 carries no
    # IP, so fib_validate_source never grants its loose-mode (2) exception --
    # only rp_filter=0 (both all and the interface) avoids silently
    # blackholing decapped packets. Saved/restored in cleanup().
    if [ ! -f '$RPFILTER_SAVE' ]; then
      sysctl -n net.ipv4.conf.all.rp_filter > '$RPFILTER_SAVE'
    fi
    sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
    sysctl -w net.ipv4.conf.geneve0.rp_filter=0 >/dev/null
  "
done

echo "==> [3/8] provisioning the controller's kubeconfig Secret from $VM_A's own admin kubeconfig"
limactl shell "$VM_A" -- sudo bash -c "
  sed 's#server: https://127.0.0.1:6443#server: https://${IP_A}:6443#' /etc/rancher/k3s/k3s.yaml > /tmp/beep-controller-kubeconfig
  k3s kubectl create secret generic $KUBECONFIG_SECRET -n kube-system \
    --from-file=kubeconfig=/tmp/beep-controller-kubeconfig --dry-run=client -o yaml | k3s kubectl apply -f -
  rm -f /tmp/beep-controller-kubeconfig
"

echo "==> [4/8] deploying the controller DaemonSet (deploy/rbac.yaml + deploy/daemonset.yaml)"
kube apply -f - < "$REPO_ROOT/deploy/rbac.yaml"
kube apply -f - < "$REPO_ROOT/deploy/daemonset.yaml"
controller_deploy_failed=0
if ! kube -n kube-system rollout status daemonset/servicelb-controller --timeout=90s; then
  controller_deploy_failed=1
fi
CONTROLLER_SELECTOR=$(kube -n kube-system get daemonset servicelb-controller \
  -o json | jq -r '.spec.selector.matchLabels | to_entries | map("\(.key)=\(.value)") | join(",")')
# rollout status alone can observe a container that starts fine but then
# CrashLoopBackOffs moments later (no readiness/liveness probe here) --
# settle, then require zero restarts, same as smoke-k3s-controller.sh.
sleep 10
restarts=$(kube -n kube-system get pods -l "$CONTROLLER_SELECTOR" \
  -o jsonpath='{.items[*].status.containerStatuses[0].restartCount}' 2>/dev/null || echo "")
for c in $restarts; do
  [ "$c" = "0" ] || controller_deploy_failed=1
done
if [ "$controller_deploy_failed" -ne 0 ]; then
  echo "CONTROLLER-DEPLOY: FAIL" >&2
  kube -n kube-system get pods -l "$CONTROLLER_SELECTOR" -o wide >&2 || true
  dump_evidence
  exit 1
fi
echo "CONTROLLER-DEPLOY: PASS (servicelb-controller Running on both nodes, zero restarts after a 10s settle)"

echo "==> [5/8] creating both directional Services (svc-on-node-a port $PORT_SVC_A, svc-on-node-b port $PORT_SVC_B)"
kube create namespace "$NAMESPACE" --dry-run=client -o yaml | kube apply -f -
cat <<EOF | kube apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: whoami-a
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels: {app: whoami-a}
  template:
    metadata:
      labels: {app: whoami-a}
    spec:
      nodeName: $NODE_A_K8S
      containers:
        - name: whoami
          image: docker.io/traefik/whoami:latest
          ports:
            - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: whoami-a
  namespace: $NAMESPACE
spec:
  type: LoadBalancer
  selector: {app: whoami-a}
  ports:
    - port: $PORT_SVC_A
      targetPort: 80
      protocol: TCP
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: whoami-b
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels: {app: whoami-b}
  template:
    metadata:
      labels: {app: whoami-b}
    spec:
      nodeName: $NODE_B_K8S
      containers:
        - name: whoami
          image: docker.io/traefik/whoami:latest
          ports:
            - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: whoami-b
  namespace: $NAMESPACE
spec:
  type: LoadBalancer
  selector: {app: whoami-b}
  ports:
    - port: $PORT_SVC_B
      targetPort: 80
      protocol: TCP
EOF

wait_for_service() { # wait_for_service <svc> -- blocks on EndpointSlice + status.loadBalancer.ingress listing both node IPs
  local svc="$1" ready_endpoint="" ingress_ips=""
  kube -n "$NAMESPACE" rollout status deployment/"$svc" --timeout=60s || {
    echo "FAIL: $svc's backend Deployment never became Ready" >&2
    kube -n "$NAMESPACE" describe pods -l app="$svc" >&2 || true
    dump_evidence
    exit 1
  }
  for _ in $(seq 1 30); do
    ready_endpoint=$(kube -n "$NAMESPACE" get endpointslices -l kubernetes.io/service-name="$svc" \
      -o jsonpath='{.items[0].endpoints[0].addresses[0]}' 2>/dev/null || true)
    [ -n "$ready_endpoint" ] && break
    sleep 1
  done
  [ -n "$ready_endpoint" ] || {
    echo "FAIL: no EndpointSlice address for $svc after 30s" >&2
    kube -n "$NAMESPACE" get endpointslices -o yaml >&2 || true
    exit 1
  }
  for _ in $(seq 1 30); do
    ingress_ips=$(kube -n "$NAMESPACE" get svc "$svc" -o jsonpath='{.status.loadBalancer.ingress[*].ip}' 2>/dev/null || true)
    case "$ingress_ips" in
      *"$IP_A"*"$IP_B"*|*"$IP_B"*"$IP_A"*) break ;;
    esac
    sleep 1
  done
  case "$ingress_ips" in
    *"$IP_A"*"$IP_B"*|*"$IP_B"*"$IP_A"*) ;;
    *)
      echo "FAIL: $svc's status.loadBalancer.ingress never listed both node IPs ($IP_A, $IP_B); got '$ingress_ips'" >&2
      exit 1
      ;;
  esac
  echo "SERVICE STATUS ($svc): PASS (pod_ip=$ready_endpoint, ingress=$ingress_ips)"
}

echo "==> [6/8] waiting for both Deployments, EndpointSlices, and status.loadBalancer.ingress"
wait_for_service whoami-a
wait_for_service whoami-b

assert_round_trip() { # assert_round_trip <direction-label> <dial-ip> <dial-port>
  local label="$1" vip="$2" port="$3" body rc
  set +e
  body="$(limactl shell "$VM_CLIENT" -- curl -sS -m 20 "http://${vip}:${port}/" 2>&1)"
  rc=$?
  set -e
  echo "$body"
  if [ "$rc" -ne 0 ]; then
    echo "ROUND-TRIP ($label): FAIL (curl rc=$rc dialing $vip:$port)" >&2
    dump_evidence
    exit 1
  fi
  if ! grep -q "RemoteAddr: ${IP_CLIENT}:" <<<"$body"; then
    echo "ROUND-TRIP ($label): FAIL (response did not report RemoteAddr: ${IP_CLIENT}:* -- the real client IP was not preserved at the pod, e.g. SNAT'd to a node address)" >&2
    dump_evidence
    exit 1
  fi
  echo "ROUND-TRIP ($label): PASS (client IP $IP_CLIENT preserved end-to-end via $vip:$port)"
}

echo "==> [7/8] direction 1: svc-on-node-a, dialed via node-b's ingress ($IP_B:$PORT_SVC_A)"
assert_round_trip "svc-on-node-A via node-B" "$IP_B" "$PORT_SVC_A"

echo "==> [8/8] direction 2: svc-on-node-b, dialed via node-a's ingress ($IP_A:$PORT_SVC_B)"
assert_round_trip "svc-on-node-B via node-A" "$IP_A" "$PORT_SVC_B"

echo ""
echo "GATE E2E-LB-BIDIRECTIONAL-K3S: PASS (both cross-node orientations delivered traffic with the client IP preserved)"
