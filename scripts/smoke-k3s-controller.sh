#!/usr/bin/env bash
# Tier-2 controller-driven integration gate: a real type=LoadBalancer
# Service + backend Deployment/Pod + resulting EndpointSlice on the
# k3s-on-Lima cluster (scripts/k3s-up.sh), with the beep servicelb
# controller (deploy/daemonset.yaml, docker.io/valerauko/beep-lb:latest)
# watching Service/EndpointSlice/Node and programming the dataplane maps
# from LIVE watch events -- not hand-rolled fixture args like
# scripts/smoke.sh / smoke-wg-2node.sh / smoke-eth-ingress-2node.sh.
#
# CURRENT STATUS: the AppArmor/bpffs-pin blocker this gate originally
# surfaced -- containerd's default `cri-containerd.apparmor.d` profile
# denying all bpffs writes -- is fixed via `deploy/daemonset.yaml`'s
# `appArmorProfile: Unconfined`. The controller DaemonSet still crashloops
# one step later, now during BPF_PROG_LOAD, with the kernel verifier
# rejecting a pointer-arithmetic pattern for a process lacking CAP_PERFMON
# (`add: ["BPF", "NET_ADMIN"]` isn't sufficient) -- not this gate's own bug.
# See docs/decisions/servicelb-controller-apparmor-unconfined.md for the
# AppArmor rationale. This script's `run`
# therefore ends in a documented, non-zero "CONTROLLER-DEPLOY: FAIL (known
# blocker)" rather than a false pass; every step before that (cluster
# bring-up, geneve0, the kubeconfig Secret, the DaemonSet/RBAC apply
# itself) is a genuine, asserted PASS.
#
# TOPOLOGY: ingress VIP = node-a's own address, backend Pod pinned
# (`nodeName`) to node-b -- a genuinely cross-node round trip: the backend
# node's `uplink_egress_return` hook must fire on its own client-facing NIC
# (eth0), not a tunnel device, to un-DNAT the reply straight back to the
# client. The client is the separate beep-client Lima VM, never node-a or
# node-b: a known martian-source drop is caused specifically by co-locating
# the client with the backend's own node (mirrors
# smoke-eth-ingress-2node.sh's header on why an earlier node-b-as-client
# rig could only prove the forward leg). Driving the client from a
# genuinely separate VM sidesteps that blocker entirely.
#
# KUBECONFIG: beep-kubeconfig (controller/src/main.rs's --kubeconfig) only
# parses an X.509 client-cert kubeconfig -- no in-cluster ServiceAccount
# token support yet. This gate extracts k3s's own admin kubeconfig
# (/etc/rancher/k3s/k3s.yaml) from node-a, rewrites its `server:` from
# 127.0.0.1 to node-a's real address (node-b has no local apiserver to
# reach at 127.0.0.1), and ships it to both controller pods as a Secret.
# That grants the controller cluster-admin rather than deploy/rbac.yaml's
# scoped ClusterRole -- acceptable for this gate (RBAC's own intent is
# still verified by inspection, not exercised end-to-end); tracked as a
# known gap, not a bug this bead fixes.
#
# Usage: scripts/smoke-k3s-controller.sh [--vm-a <ingress-vm>] [--vm-b <backend-vm>] [--vm-client <client-vm>]
# Defaults: beep-node-a (ingress, k3s server), beep-node-b (backend Pod,
# k3s agent), beep-client (client). All three must be on the same Lima
# network (scripts/k3s-up.sh's beep-k3s.yaml profile for the first two).
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

NAMESPACE="beep-controller-e2e"
SERVICE_NAME="whoami"
DEPLOY_NAME="whoami"
VIP_PORT="80"
PIN_DIR="/sys/fs/bpf/beep"
KUBECONFIG_SECRET="beep-controller-kubeconfig"

for tool in limactl jq; do
  command -v "$tool" >/dev/null || { echo "FAIL: $tool not found on PATH" >&2; exit 1; }
done

kube() { # kube <args...> -- runs k3s kubectl as root on $VM_A (the only node with a local apiserver)
  limactl shell "$VM_A" -- sudo k3s kubectl "$@"
}

eth0_ip() { # eth0_ip <vm> -- this VM's real underlay address
  limactl shell "$1" -- bash -c "ip -4 -o addr show eth0 | awk '{print \$4}' | cut -d/ -f1"
}

map_entry_count() { # map_entry_count <vm> <map-name> -- entries in a pinned map, "" if the pin is missing/unreadable
  local vm="$1" name="$2" json
  json=$(limactl shell "$vm" -- sudo bpftool map dump pinned "$PIN_DIR/$name" --json 2>/dev/null) || { echo ""; return; }
  jq 'length' <<<"$json" 2>/dev/null || echo ""
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
  echo "---- controller pod describe (events) ----"
  kube -n kube-system describe pods -l "$CONTROLLER_SELECTOR" 2>&1 || true
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
}
trap cleanup EXIT

echo "==> [1/9] bringing up the k3s cluster ($VM_A server, $VM_B agent) and $VM_CLIENT"
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
echo "CLUSTER-UP: PASS ($VM_A=$IP_A/$NODE_A_K8S ingress, $VM_B=$IP_B/$NODE_B_K8S backend, client=$VM_CLIENT/$IP_CLIENT)"

echo "==> [2/9] creating geneve0 on both nodes (external mode -- beep sets the tunnel key itself)"
for vm in "$VM_A" "$VM_B"; do
  limactl shell "$vm" -- sudo bash -c '
    ip link show geneve0 >/dev/null 2>&1 || ip link add geneve0 type geneve external
    ip link set geneve0 up
  '
done

echo "==> [3/9] provisioning the controller's kubeconfig Secret from $VM_A's own admin kubeconfig (see this script's header)"
limactl shell "$VM_A" -- sudo bash -c "
  sed 's#server: https://127.0.0.1:6443#server: https://${IP_A}:6443#' /etc/rancher/k3s/k3s.yaml > /tmp/beep-controller-kubeconfig
  k3s kubectl create secret generic $KUBECONFIG_SECRET -n kube-system \
    --from-file=kubeconfig=/tmp/beep-controller-kubeconfig --dry-run=client -o yaml | k3s kubectl apply -f -
  rm -f /tmp/beep-controller-kubeconfig
"

echo "==> [4/9] deploying the controller DaemonSet (deploy/rbac.yaml + deploy/daemonset.yaml)"
kube apply -f - < "$REPO_ROOT/deploy/rbac.yaml"
kube apply -f - < "$REPO_ROOT/deploy/daemonset.yaml"
controller_deploy_failed=0
if ! kube -n kube-system rollout status daemonset/servicelb-controller --timeout=90s; then
  controller_deploy_failed=1
fi
# Read the pod selector back from the DaemonSet itself, rather than
# hardcoding a copy of `deploy/daemonset.yaml`'s labels here: a hardcoded
# literal that drifts from the manifest matches zero pods, leaving
# `controller_deploy_failed` unchanged instead of failing -- a silent
# no-op, not a caught error.
CONTROLLER_SELECTOR=$(kube -n kube-system get daemonset servicelb-controller \
  -o json | jq -r '.spec.selector.matchLabels | to_entries | map("\(.key)=\(.value)") | join(",")')
# `rollout status` alone is not sufficient evidence: a container with no
# readiness/liveness probe (this one has neither) reports Ready as soon as
# it *starts*, even if it exits non-zero moments later -- `rollout status`
# can observe that brief window and report success just before the pod
# enters CrashLoopBackOff (confirmed: this exact false-positive happened
# while diagnosing the AppArmor/bpffs blocker). Settle, then require zero
# restarts.
sleep 10
restarts=$(kube -n kube-system get pods -l "$CONTROLLER_SELECTOR" \
  -o jsonpath='{.items[*].status.containerStatuses[0].restartCount}' 2>/dev/null || echo "")
for c in $restarts; do
  [ "$c" = "0" ] || controller_deploy_failed=1
done
if [ "$controller_deploy_failed" -ne 0 ]; then
  echo "CONTROLLER-DEPLOY: FAIL (known blocker -- see this script's header)" >&2
  kube -n kube-system get pods -l "$CONTROLLER_SELECTOR" -o wide >&2 || true
  dump_evidence
  exit 1
fi
echo "CONTROLLER-DEPLOY: PASS (servicelb-controller Running on both nodes, zero restarts after a 10s settle)"

echo "==> [5/9] creating the real Service + backend Deployment (Pod pinned to $NODE_B_K8S)"
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
  name: $SERVICE_NAME
  namespace: $NAMESPACE
spec:
  type: LoadBalancer
  selector: {app: $DEPLOY_NAME}
  ports:
    - port: $VIP_PORT
      targetPort: 80
      protocol: TCP
EOF

echo "==> [6/9] waiting for the Deployment, EndpointSlice, and status.loadBalancer.ingress"
kube -n "$NAMESPACE" rollout status deployment/"$DEPLOY_NAME" --timeout=60s || {
  echo "FAIL: backend Deployment never became Ready" >&2
  kube -n "$NAMESPACE" describe pods >&2 || true
  dump_evidence
  exit 1
}

ready_endpoint=""
for _ in $(seq 1 30); do
  ready_endpoint=$(kube -n "$NAMESPACE" get endpointslices -l kubernetes.io/service-name="$SERVICE_NAME" \
    -o jsonpath='{.items[0].endpoints[0].addresses[0]}' 2>/dev/null || true)
  [ -n "$ready_endpoint" ] && break
  sleep 1
done
[ -n "$ready_endpoint" ] || {
  echo "FAIL: no EndpointSlice address for $SERVICE_NAME after 30s" >&2
  kube -n "$NAMESPACE" get endpointslices -o yaml >&2 || true
  exit 1
}
echo "ENDPOINTSLICE: PASS (pod_ip=$ready_endpoint)"

ingress_ips=""
for _ in $(seq 1 30); do
  ingress_ips=$(kube -n "$NAMESPACE" get svc "$SERVICE_NAME" -o jsonpath='{.status.loadBalancer.ingress[*].ip}' 2>/dev/null || true)
  case "$ingress_ips" in
    *"$IP_A"*"$IP_B"*|*"$IP_B"*"$IP_A"*) break ;;
  esac
  sleep 1
done
case "$ingress_ips" in
  *"$IP_A"*"$IP_B"*|*"$IP_B"*"$IP_A"*) ;;
  *)
    echo "FAIL: status.loadBalancer.ingress never listed both node IPs ($IP_A, $IP_B); got '$ingress_ips'" >&2
    exit 1
    ;;
esac
echo "SERVICE STATUS: PASS (status.loadBalancer.ingress = $ingress_ips)"

echo "==> [7/9] confirming the dataplane maps are programmed"
vip_a=$(map_entry_count "$VM_A" VIP_MAP)
vip_b=$(map_entry_count "$VM_B" VIP_MAP)
pod_targets_b=$(map_entry_count "$VM_B" POD_TARGETS)
[ -n "$vip_a" ] && [ "$vip_a" -ge 1 ] || { echo "FAIL: $VM_A's VIP_MAP has no entries ($vip_a)" >&2; dump_evidence; exit 1; }
[ -n "$vip_b" ] && [ "$vip_b" -ge 1 ] || { echo "FAIL: $VM_B's VIP_MAP has no entries ($vip_b)" >&2; dump_evidence; exit 1; }
[ -n "$pod_targets_b" ] && [ "$pod_targets_b" -ge 1 ] || {
  echo "FAIL: $VM_B's POD_TARGETS has no entries ($pod_targets_b) -- the backend Pod it hosts was never admitted" >&2
  dump_evidence
  exit 1
}
echo "MAP-PROGRAMMING: PASS (VIP_MAP: $VM_A=$vip_a $VM_B=$vip_b entries, $VM_B POD_TARGETS=$pod_targets_b entries)"

echo "==> [8/9] driving client ($VM_CLIENT, $IP_CLIENT) -> VIP $IP_A:$VIP_PORT -> cross-node backend on $VM_B"
set +e
CLIENT_BODY="$(limactl shell "$VM_CLIENT" -- curl -sS -m 20 "http://${IP_A}:${VIP_PORT}/" 2>&1)"
CLIENT_RC=$?
set -e
echo "$CLIENT_BODY"
if [ "$CLIENT_RC" -ne 0 ]; then
  echo "ROUND-TRIP: FAIL (curl rc=$CLIENT_RC)" >&2
  dump_evidence
  exit 1
fi
if ! grep -q "RemoteAddr: ${IP_CLIENT}:" <<<"$CLIENT_BODY"; then
  echo "ROUND-TRIP: FAIL (response did not report RemoteAddr: ${IP_CLIENT}:* -- the real client IP was not preserved at the pod, e.g. SNAT'd to a node address)" >&2
  dump_evidence
  exit 1
fi
echo "ROUND-TRIP: PASS (symmetric return; whoami's RemoteAddr confirms the real client IP $IP_CLIENT reached the pod un-SNAT'd)"

echo "==> [9/9] confirming a conntrack/FLOW_TABLE entry exists for the flow"
flow_a=$(map_entry_count "$VM_A" FLOW_TABLE)
[ -n "$flow_a" ] && [ "$flow_a" -ge 1 ] || {
  echo "FAIL: $VM_A's FLOW_TABLE has no entries ($flow_a) after a completed round trip" >&2
  dump_evidence
  exit 1
}
echo "CONNTRACK: PASS ($VM_A FLOW_TABLE=$flow_a entries)"

echo ""
echo "GATE CONTROLLER-DRIVEN ROUND-TRIP: PASS"
