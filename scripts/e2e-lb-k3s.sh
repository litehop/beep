#!/usr/bin/env bash
# Manual/nightly Lima-tier gate: runs upstream Kubernetes e2e LoadBalancer
# conformance specs (test/e2e/network/loadbalancer.go) against beep's own
# dataplane on the k3s-on-Lima rig, instead of a hand-rolled fixture like
# scripts/smoke-k3s-controller.sh's whoami Service. Not wired into
# .github/workflows/ci.yaml: every CI job runs on GitHub-hosted ubuntu-latest
# runners, which can't host this 3-VM Lima rig -- smoke-k3s-controller.sh
# (the closest existing analog) is absent from ci.yaml for the same reason.
#
# Focus list: the 4 ExternalTrafficPolicy:Local specs, the TCP
# type/port-mutability spec, and the 2 UDP flow-affinity specs -- 7 specs
# total (4+1+2). 6 of the 7 carry Ginkgo's Slow label (only the two UDP
# specs, loadbalancer.go:707/:841, do not) -- size
# --ginkgo-timeout/--wall-timeout for a Slow-heavy run, not a "fast
# primary" assumption.
#
# FOCUS below tolerates an inline-tag quirk in the real spec names:
# SIGDescribe()/f.WithSlow() render tags (e.g. "[Feature:LoadBalancer]
# [Slow]") BETWEEN the container text and the It text (confirmed against
# the live e2e.test binary's --ginkgo.dry-run --ginkgo.v output, e.g.
# "LoadBalancers ExternalTrafficPolicy: Local [Feature:LoadBalancer]
# [Slow] should work from pods") -- a regex with tight "Local
# (alt1|alt2|...)" adjacency and no tag tolerance matches zero specs
# against the real binary. The ".*" below skips over those inline tags.
# Validate any focus-regex change with --dry-run first.
#
# Requires the kube-proxy/flannel coexistence gap closed and the
# cross-node return-path dataplane bug fixed for a genuine green run --
# check kube-proxy/status-IP overlap before attributing a red run to a
# beep dataplane regression.
#
# Usage: scripts/e2e-lb-k3s.sh [--vm-a <ingress-vm>] [--vm-b <backend-vm>]
#          [--vm-client <client-vm>] [--focus <ginkgo-focus-regex>]
#          [--ginkgo-timeout <go-duration>] [--wall-timeout <go-duration>]
#          [--junit-dir <host-dir>] [--dry-run]
# Defaults: beep-node-a (ingress, k3s server), beep-node-b (backend, k3s
# agent), beep-client (runs e2e.test). All three must already exist on the
# same Lima network (scripts/k3s-up.sh's beep-k3s.yaml profile for the first
# two; scripts/smoke-k3s-controller.sh's beep-client.yaml for the third).
set -euo pipefail

VM_A="beep-node-a"
VM_B="beep-node-b"
VM_CLIENT="beep-client"
FOCUS='LoadBalancers ExternalTrafficPolicy: Local .*(should work for type=LoadBalancer|should work from pods|should only target nodes with endpoints|should target all nodes with endpoints)|LoadBalancers .*(should be able to change the type and ports of a TCP service|should be able to preserve UDP traffic when server pod cycles for a LoadBalancer service on (different|the same) nodes)'
GINKGO_TIMEOUT="2h"
WALL_TIMEOUT="150m"
JUNIT_DIR=""
DRY_RUN="false"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vm-a) VM_A="$2"; shift 2 ;;
    --vm-b) VM_B="$2"; shift 2 ;;
    --vm-client) VM_CLIENT="$2"; shift 2 ;;
    --focus) FOCUS="$2"; shift 2 ;;
    --ginkgo-timeout) GINKGO_TIMEOUT="$2"; shift 2 ;;
    --wall-timeout) WALL_TIMEOUT="$2"; shift 2 ;;
    --junit-dir) JUNIT_DIR="$2"; shift 2 ;;
    --dry-run) DRY_RUN="true"; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
JUNIT_DIR="${JUNIT_DIR:-$REPO_ROOT/temp/e2e-lb-k3s-junit}"

PIN_DIR="/sys/fs/bpf/beep"
KUBECONFIG_SECRET="beep-controller-kubeconfig"
CLIENT_KUBECONFIG="/tmp/e2e-lb-k3s-kubeconfig"
CLIENT_JUNIT="/tmp/e2e-lb-k3s-junit.xml"

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
  done
  echo "---- controller pod logs (current + previous, i.e. pre-crash) ----"
  kube -n kube-system logs -l "$CONTROLLER_SELECTOR" --all-containers --tail=100 2>&1 || true
  kube -n kube-system logs -l "$CONTROLLER_SELECTOR" --all-containers --tail=100 --previous 2>&1 || true
}

cleanup() {
  # e2e.test's own framework deletes its per-spec Namespaces on success; this
  # is the safety net for a Ctrl-C or a hard-timeout early exit. Both suites
  # in loadbalancer.go use framework.NewDefaultFramework("loadbalancers"/"esipp"),
  # so their generated Namespaces are named loadbalancers-<random>/esipp-<random>.
  kube get ns -o name 2>/dev/null | grep -E '^namespace/(loadbalancers|esipp)-' | sed 's#^namespace/##' \
    | while read -r ns; do kube delete namespace "$ns" --ignore-not-found --wait=false >/dev/null 2>&1 || true; done || true
  kube delete -f - --ignore-not-found < "$REPO_ROOT/deploy/daemonset.yaml" >/dev/null 2>&1 || true
  kube delete -f - --ignore-not-found < "$REPO_ROOT/deploy/rbac.yaml" >/dev/null 2>&1 || true
  kube delete secret "$KUBECONFIG_SECRET" -n kube-system --ignore-not-found >/dev/null 2>&1 || true
  limactl shell "$VM_CLIENT" -- rm -f "$CLIENT_KUBECONFIG" "$CLIENT_JUNIT" >/dev/null 2>&1 || true
  for vm in "$VM_A" "$VM_B"; do
    limactl shell "$vm" -- sudo rm -rf "$PIN_DIR" >/dev/null 2>&1 || true
    limactl shell "$vm" -- sudo ip link del geneve0 >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

echo "==> [1/7] bringing up the k3s cluster ($VM_A server, $VM_B agent) and $VM_CLIENT"
"$SCRIPT_DIR/k3s-up.sh" --vm-a "$VM_A" --vm-b "$VM_B"
if ! limactl list --format '{{.Name}}\t{{.Status}}' 2>/dev/null | grep -qE "^${VM_CLIENT}[[:space:]]+Running"; then
  limactl start "$VM_CLIENT"
fi

IP_A="$(eth0_ip "$VM_A")"
IP_B="$(eth0_ip "$VM_B")"
[ -n "$IP_A" ] && [ -n "$IP_B" ] || {
  echo "FAIL: could not resolve eth0 addresses (a=$IP_A b=$IP_B)" >&2
  exit 1
}
echo "CLUSTER-UP: PASS ($VM_A=$IP_A ingress, $VM_B=$IP_B backend, client=$VM_CLIENT)"

echo "==> [2/7] creating geneve0 on both nodes (external mode -- beep sets the tunnel key itself)"
for vm in "$VM_A" "$VM_B"; do
  limactl shell "$vm" -- sudo bash -c '
    ip link show geneve0 >/dev/null 2>&1 || ip link add geneve0 type geneve external
    ip link set geneve0 up
    # Same rp_filter workaround as scripts/smoke-k3s-controller.sh: geneve0
    # carries no IP, so fib_validate_source never grants its loose-mode (2)
    # exception -- only rp_filter=0 (both all and the interface, kernel
    # takes max(all, interface)) avoids silently blackholing decapped packets.
    sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
    sysctl -w net.ipv4.conf.geneve0.rp_filter=0 >/dev/null
  '
done

echo "==> [3/7] provisioning kubeconfigs (controller Secret on $VM_A, e2e client copy on $VM_CLIENT)"
limactl shell "$VM_A" -- sudo bash -c "
  sed 's#server: https://127.0.0.1:6443#server: https://${IP_A}:6443#' /etc/rancher/k3s/k3s.yaml > /tmp/beep-controller-kubeconfig
  k3s kubectl create secret generic $KUBECONFIG_SECRET -n kube-system \
    --from-file=kubeconfig=/tmp/beep-controller-kubeconfig --dry-run=client -o yaml | k3s kubectl apply -f -
"
limactl shell "$VM_A" -- sudo cat /tmp/beep-controller-kubeconfig \
  | limactl shell "$VM_CLIENT" -- tee "$CLIENT_KUBECONFIG" >/dev/null
limactl shell "$VM_A" -- sudo rm -f /tmp/beep-controller-kubeconfig

echo "==> [4/7] deploying the controller DaemonSet (deploy/rbac.yaml + deploy/daemonset.yaml)"
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

echo "==> [5/7] resolving the live k3s minor on $VM_A and caching e2e.test+ginkgo on $VM_CLIENT"
K3S_VER="$(limactl shell "$VM_A" -- sudo k3s --version | awk '/^k3s version/{print $3}')"
[ -n "$K3S_VER" ] || { echo "FAIL: could not resolve $VM_A's k3s version" >&2; exit 1; }
K8S_VER="${K3S_VER%%+*}" # k3s's version string is built directly on this exact upstream k8s release
echo "k3s=$K3S_VER -> kubernetes=$K8S_VER"
limactl shell "$VM_CLIENT" -- env K8S_VER="$K8S_VER" bash -c '
  set -euo pipefail
  CACHE_DIR="$HOME/.cache/e2e-lb-k3s/$K8S_VER"
  if [ -x "$CACHE_DIR/e2e.test" ] && [ -x "$CACHE_DIR/ginkgo" ]; then
    echo "cache hit: $CACHE_DIR"
    exit 0
  fi
  echo "cache miss: downloading kubernetes-test-linux-arm64.tar.gz for $K8S_VER"
  mkdir -p "$CACHE_DIR"
  curl -sfL "https://dl.k8s.io/${K8S_VER}/kubernetes-test-linux-arm64.tar.gz" \
    | tar -xz -C "$CACHE_DIR" --strip-components=3 kubernetes/test/bin/e2e.test kubernetes/test/bin/ginkgo
  chmod +x "$CACHE_DIR/e2e.test" "$CACHE_DIR/ginkgo"
'

echo "==> [6/7] running e2e.test on $VM_CLIENT (--provider=local, ginkgo-timeout=$GINKGO_TIMEOUT, wall-timeout=$WALL_TIMEOUT, dry-run=$DRY_RUN)"
mkdir -p "$JUNIT_DIR"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
LOCAL_JUNIT="$JUNIT_DIR/junit-$TS.xml"
LOCAL_LOG="$JUNIT_DIR/e2e-$TS.log"
set +e
limactl shell "$VM_CLIENT" -- env \
  K8S_VER="$K8S_VER" FOCUS="$FOCUS" GINKGO_TIMEOUT="$GINKGO_TIMEOUT" WALL_TIMEOUT="$WALL_TIMEOUT" \
  KUBECONFIG_PATH="$CLIENT_KUBECONFIG" JUNIT_PATH="$CLIENT_JUNIT" DRY_RUN="$DRY_RUN" \
  bash -c '
    set -euo pipefail
    CACHE_DIR="$HOME/.cache/e2e-lb-k3s/$K8S_VER"
    timeout "$WALL_TIMEOUT" "$CACHE_DIR/e2e.test" \
      --kubeconfig="$KUBECONFIG_PATH" \
      --provider=local \
      --ginkgo.focus="$FOCUS" \
      --ginkgo.timeout="$GINKGO_TIMEOUT" \
      --ginkgo.junit-report="$JUNIT_PATH" \
      --ginkgo.dry-run="$DRY_RUN" \
      --ginkgo.no-color \
      --ginkgo.v
  ' 2>&1 | tee "$LOCAL_LOG"
E2E_RC=${PIPESTATUS[0]}
set -e

echo "==> [7/7] collecting JUnit + log, reporting"
limactl copy "$VM_CLIENT:$CLIENT_JUNIT" "$LOCAL_JUNIT" >/dev/null 2>&1 || echo "WARN: no JUnit report retrieved from $VM_CLIENT:$CLIENT_JUNIT" >&2
echo "-- ginkgo summary --"
grep -E '^(Will run|Ran |SUCCESS!|FAIL!)' "$LOCAL_LOG" || true
echo "-- failed specs (if any) --"
grep -E '\[FAILED\]' "$LOCAL_LOG" || true
echo "JUnit: $LOCAL_JUNIT"
echo "Log:   $LOCAL_LOG"
if [ "$E2E_RC" -ne 0 ]; then
  echo "E2E-LB-K3S: FAIL (e2e.test rc=$E2E_RC -- check kube-proxy/status-IP overlap before assuming a beep dataplane regression)" >&2
  dump_evidence
  exit "$E2E_RC"
fi
echo ""
echo "GATE E2E-LB-K3S: PASS"
