#!/usr/bin/env bash
# Per-PR CI gate for beep-controller's userspace RSS
# (.github/workflows/ci.yaml's memory-smoke job). Runs the real
# beep-controller binary against a REAL, single-node k3s apiserver -- not a
# fixture-args-only run like scripts/smoke-remote.sh drives for the
# standalone `beep` loader -- so its tokio/hyper/rustls/watch-loop weight is
# actually measured, not estimated.
#
# Single node is enough: beep-controller only watches Service/EndpointSlice/
# Node objects and writes the dataplane maps from those events; it needs no
# second node, no kubelet-scheduled backend Pod, and no dataplane round trip
# to reach steady state. A hand-created Namespace/Deployment/Service fixture
# still exercises the SAME reconcile path a real cluster would.
#
# The eBPF hooks this binary attaches (uplink_ingress/geneve_ingress/
# uplink_egress_return) are given a dedicated dummy uplink + geneve device
# (ctrl-uplink0/ctrl-geneve0) and pin dir, entirely disjoint from
# scripts/smoke-remote.sh's own smoke-veth0/geneve0/`/sys/fs/bpf/beep-smoke`
# fixture run earlier in the same job -- no real traffic needs to flow
# through them here, only a verifier-accept attach, so no veth pair/netns/
# rp_filter dance is needed either. `ip link add` retries for up to a
# minute: k3s's own flannel CNI bringing up cni0/flannel.1 and scheduling
# coredns was observed leaving the host's rtnl busy enough to fail this
# exact call with EBUSY on a real GitHub-hosted runner, well after /readyz
# already reported the API server itself healthy (ci.yaml's install step
# additionally waits for coredns Running before this script runs at all --
# this retry is defense in depth, not the primary fix).
#
# RSS ceilings/sampling: see scripts/controller-rss.sh (shared with
# scripts/smoke-k3s-controller.sh's own real-2-node data point).
#
# Requires k3s already installed and its single-node cluster Ready (see
# ci.yaml's own install step) and target/release/beep-controller already
# built. Usage: scripts/memory-smoke-controller.sh {run|cleanup}
set -euo pipefail

NAMESPACE="beep-controller-memory-smoke"
DEPLOY_NAME="whoami"
SERVICE_NAME="whoami"
PIN_DIR="/sys/fs/bpf/beep-controller-smoke"
UPLINK_IFACE="ctrl-uplink0"
GENEVE_IFACE="ctrl-geneve0"
LOG="/tmp/beep-controller-memory-smoke.log"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=controller-rss.sh
. "$SCRIPT_DIR/controller-rss.sh"
BIN="$REPO_ROOT/target/release/beep-controller"

kube() { k3s kubectl "$@"; }

dump_evidence() {
  echo "---- beep-controller log ----"
  cat "$LOG" 2>&1 || true
  echo "---- namespace/pods/svc/endpointslices ----"
  kube -n "$NAMESPACE" get pods,svc,endpointslices -o wide 2>&1 || true
}

cleanup() {
  pkill -f "$BIN" 2>/dev/null || true
  kube delete namespace "$NAMESPACE" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  rm -rf "$PIN_DIR"
  ip link del "$UPLINK_IFACE" >/dev/null 2>&1 || true
  ip link del "$GENEVE_IFACE" >/dev/null 2>&1 || true
}

case "${1:-}" in
  cleanup) cleanup; exit 0 ;;
  run) ;;
  *) echo "usage: $0 {run|cleanup}" >&2; exit 1 ;;
esac

for tool in k3s jq; do
  command -v "$tool" >/dev/null || { echo "FAIL: $tool not found on PATH" >&2; exit 1; }
done
[ -x "$BIN" ] || { echo "FAIL: $BIN not found -- build beep-controller (cargo build --release -p beep-controller) first" >&2; exit 1; }

cleanup >/dev/null 2>&1 || true

ip_link_add_retry() { # ip_link_add_retry <ip link add args...> -- retries on a transient EBUSY (see this script's header) for up to a minute, dumping kernel-side evidence if it never clears
  local i
  for i in $(seq 1 30); do
    ip link add "$@" 2>&1 && return 0
    sleep 2
  done
  echo "FAIL: \`ip link add $*\` stayed busy for 60s" >&2
  ip link show >&2 || true
  journalctl -k --since "-2 minutes" >&2 || true
  return 1
}

echo "==> [1/6] creating a dedicated dummy uplink + geneve device for beep-controller's own tc-bpf attach"
ip_link_add_retry "$UPLINK_IFACE" type dummy
ip link set "$UPLINK_IFACE" up
ip_link_add_retry "$GENEVE_IFACE" type geneve external
ip link set "$GENEVE_IFACE" up

echo "==> [2/6] resolving this single node's identity from the live k3s apiserver"
NODE_NAME=$(kube get nodes -o jsonpath='{.items[0].metadata.name}')
NODE_IP=$(kube get node "$NODE_NAME" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
POD_CIDR=$(kube get node "$NODE_NAME" -o jsonpath='{.spec.podCIDR}')
[ -n "$NODE_NAME" ] && [ -n "$NODE_IP" ] && [ -n "$POD_CIDR" ] || {
  echo "FAIL: could not resolve node identity (name='$NODE_NAME' ip='$NODE_IP' pod_cidr='$POD_CIDR')" >&2
  exit 1
}
echo "node=$NODE_NAME ip=$NODE_IP pod_cidr=$POD_CIDR"

echo "==> [3/6] starting beep-controller against the live apiserver"
nohup "$BIN" \
  --uplink-iface "$UPLINK_IFACE" --geneve-iface "$GENEVE_IFACE" --pin-dir "$PIN_DIR" \
  --pod-cidr "$POD_CIDR" --node-ip "$NODE_IP" --kubeconfig /etc/rancher/k3s/k3s.yaml \
  >"$LOG" 2>&1 &
controller_pid=$!
disown

for _ in $(seq 1 20); do
  grep -q "all 3 hooks attached" "$LOG" 2>/dev/null && break
  if ! kill -0 "$controller_pid" 2>/dev/null; then
    echo "FAIL: beep-controller exited before attaching (verifier rejection or load error)" >&2
    dump_evidence
    exit 1
  fi
  sleep 0.5
done
grep -q "all 3 hooks attached" "$LOG" || {
  echo "FAIL: beep-controller never reported all 3 hooks attached within 10s" >&2
  dump_evidence
  exit 1
}
echo "VERIFIER-ACCEPT: PASS"

echo "==> [4/6] sampling beep-controller RSS baseline (after the initial Service/EndpointSlice/Node LIST+watch settle, before any fixture exists)"
sleep 5
rss_baseline=$(controller_rss)
assert_controller_rss_baseline "$rss_baseline" "ci-runner" || { dump_evidence; exit 1; }

echo "==> [5/6] reconciling a real Service + backend Deployment"
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
    - port: 80
      targetPort: 80
      protocol: TCP
EOF

kube -n "$NAMESPACE" rollout status deployment/"$DEPLOY_NAME" --timeout=90s || {
  echo "FAIL: backend Deployment never became Ready" >&2
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
  dump_evidence
  exit 1
}

ingress_ip=""
for _ in $(seq 1 30); do
  ingress_ip=$(kube -n "$NAMESPACE" get svc "$SERVICE_NAME" -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)
  [ "$ingress_ip" = "$NODE_IP" ] && break
  sleep 1
done
[ "$ingress_ip" = "$NODE_IP" ] || {
  echo "FAIL: status.loadBalancer.ingress never resolved to this node's address ($NODE_IP); got '$ingress_ip'" >&2
  dump_evidence
  exit 1
}
echo "RECONCILE: PASS (endpoint=$ready_endpoint, status.loadBalancer.ingress=$ingress_ip)"

echo "==> [6/6] sampling beep-controller RSS after the reconcile and asserting growth stays bounded"
rss_peak=$(controller_rss)
assert_controller_rss_growth "$rss_baseline" "$rss_peak" "ci-runner" || { dump_evidence; exit 1; }

echo ""
echo "GATE MEMORY-SMOKE-CONTROLLER: PASS"
