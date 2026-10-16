#!/usr/bin/env bash
# Tier-2 controller-driven integration gate: a real type=LoadBalancer
# Service + backend Deployment/Pod + resulting EndpointSlice on the
# k3s-on-Lima cluster (scripts/k3s-up.sh), with the beep servicelb
# controller (deploy/daemonset.yaml) watching Service/EndpointSlice/Node and
# programming the dataplane maps from LIVE watch events -- not hand-rolled
# fixture args like scripts/smoke.sh / smoke-wg-2node.sh /
# smoke-eth-ingress-2node.sh.
#
# IMAGE: deploy/daemonset.yaml hardcodes docker.io/valerauko/beep-lb:latest,
# which resolves to the newest RELEASE (.github/workflows/delivery.yaml's
# `v*` tag push), not this checkout -- a main-branch commit only ever gets a
# `:sha` tag (github.sha, the full 40-char commit sha), and that tag never
# exists on Docker Hub yet for a commit still under test. So step [4/11]
# below cross-builds beep-controller, docker-builds+saves it as
# docker.io/valerauko/beep-lb:<git rev-parse HEAD>, and `k3s ctr images
# import`s that tarball directly into both nodes' containerd -- never
# pulled from a registry -- then overrides the DaemonSet to that tag.
#
# STATUS: the AppArmor/bpffs-pin blocker, the BPF_PROG_LOAD
# verifier/CAP_PERFMON blocker, and the cross-node return-path dataplane
# bug this gate originally surfaced are all fixed (`deploy/daemonset.yaml`'s
# `appArmorProfile: Unconfined` + `add: ["BPF", "NET_ADMIN", "PERFMON"]`;
# see docs/decisions/servicelb-controller-apparmor-unconfined.md). Every
# step -- cluster bring-up, geneve0, the
# DaemonSet/RBAC apply, the controller loading and pinning its eBPF
# programs, map programming, the cross-node round trip, and FLOW_TABLE
# promotion -- is a genuine, asserted PASS.
#
# TOPOLOGY: ingress front = node-a's own address, backend Pod pinned
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
# CONTROLLER RSS: this gate ALSO asserts beep-controller's userspace RSS
# (scripts/controller-rss.sh, shared with the per-PR CI gate below) as a
# second, real-2-node data point on top of the CI one -- the actual gate that
# runs on every PR is ci.yaml's memory-smoke job
# (scripts/memory-smoke-controller.sh), a single-node beep-controller-vs-k3s
# run that needs no Lima rig. See scripts/controller-rss.sh's header for the
# measured baseline the shared ceilings are set against.
#
# AUTH: the stock deploy/daemonset.yaml is applied unmodified, so the
# controller authenticates as its own ServiceAccount (deploy/rbac.yaml's
# scoped ClusterRole) via the projected token -- no kubeconfig anywhere. The
# gate asserts the DaemonSet carries no --kubeconfig and that every node's
# Lease keeps renewing; Service status, map programming and the round trip
# below prove the watches and patches work under that scoped RBAC.
# --client-cert-auth instead exercises deploy/README.md's documented
# client-cert opt-in (k3s_provision_client_cert_auth), with the
# ServiceAccount token unmounted so only the cert can authenticate, and stops
# after the first round trip and conntrack steps.
#
# Usage: scripts/smoke-k3s-controller.sh [--vm-a <ingress-vm>] [--vm-b <backend-vm>] [--vm-client <client-vm>] [--proxy-mode <iptables|ipvs>] [--client-cert-auth]
# Defaults: beep-node-a (ingress, k3s server), beep-node-b (backend Pod,
# k3s agent), beep-client (client). All three must be on the same Lima
# network (scripts/k3s-up.sh's beep-k3s.yaml profile for the first two).
# --keep-going runs every multi-endpoint leg and fails at the end instead of
# stopping at the first failed leg.
# --proxy-mode forwards to scripts/k3s-up.sh (default iptables) -- without
# this passthrough, this script's own k3s-up.sh invocation always defaults
# back to iptables, silently resetting a cluster an earlier `k3s-up.sh
# --proxy-mode ipvs` run had put into IPVS mode.
set -euo pipefail

VM_A="beep-node-a"
VM_B="beep-node-b"
VM_CLIENT="beep-client"
PROXY_MODE="iptables"
KEEP_GOING=0
LEG_FAILURES=0
CLIENT_CERT_AUTH=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vm-a) VM_A="$2"; shift 2 ;;
    --vm-b) VM_B="$2"; shift 2 ;;
    --vm-client) VM_CLIENT="$2"; shift 2 ;;
    --proxy-mode) PROXY_MODE="$2"; shift 2 ;;
    --keep-going) KEEP_GOING=1; shift ;;
    --client-cert-auth) CLIENT_CERT_AUTH=1; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=controller-rss.sh
. "$SCRIPT_DIR/controller-rss.sh"
# shellcheck source=k3s-common.sh
. "$SCRIPT_DIR/k3s-common.sh"

NAMESPACE="beep-controller-e2e"
SERVICE_NAME="whoami"
DEPLOY_NAME="whoami"
FRONT_PORT="80"
PIN_DIR="/sys/fs/bpf/beep"
IMAGE_TMPDIR=""
IMAGE=""

for tool in limactl jq docker cargo-zigbuild; do
  command -v "$tool" >/dev/null || { echo "FAIL: $tool not found on PATH" >&2; exit 1; }
done
rustup toolchain list 2>/dev/null | grep -q '^nightly' || {
  echo "FAIL: nightly toolchain not installed (rustup toolchain install nightly --component rust-src)" >&2
  exit 1
}
# build.rs/aya-build cross-builds beep-ebpf via `-Z build-std=core`, which
# needs rust-src regardless of the host target -- a nightly toolchain
# without it passes the check above but fails later with an obscure
# zigbuild/build.rs error.
rustup component list --toolchain nightly 2>/dev/null | grep -q '^rust-src (installed)' || {
  echo "FAIL: rust-src component not installed for nightly (rustup component add rust-src --toolchain nightly)" >&2
  exit 1
}

map_entry_count() { # map_entry_count <vm> <map-name> -- entries in a pinned map, "" if the pin is missing/unreadable
  local vm="$1" name="$2" json
  json=$(limactl shell "$vm" -- sudo bpftool map dump pinned "$PIN_DIR/$name" --json 2>/dev/null) || { echo ""; return; }
  jq 'length' <<<"$json" 2>/dev/null || echo ""
}

dump_evidence() { k3s_dump_evidence "$VM_A" "$VM_B" "$PIN_DIR"; }

cleanup() {
  kube delete namespace "$NAMESPACE" --ignore-not-found --timeout=120s >/dev/null 2>&1 || \
    echo "WARN: namespace $NAMESPACE was not deleted within 120s; it may still be terminating and can leak into the next run" >&2
  k3s_teardown_controller "$REPO_ROOT"
  k3s_teardown_client_cert_auth
  kube -n beep-leases delete lease -l app.kubernetes.io/component=node-lease --ignore-not-found >/dev/null 2>&1 || true
  [ -n "$IMAGE_TMPDIR" ] && rm -rf "$IMAGE_TMPDIR"
  # The tarball above is trap-cleaned, but the locally built+tagged image
  # itself isn't -- without this, every run of a different commit leaves
  # its sha-tagged image on the host indefinitely.
  [ -n "$IMAGE" ] && docker rmi "$IMAGE" >/dev/null 2>&1 || true
  for vm in "$VM_A" "$VM_B"; do
    limactl shell "$vm" -- sudo rm -rf "$PIN_DIR" >/dev/null 2>&1 || true
    limactl shell "$vm" -- sudo ip link del geneve0 >/dev/null 2>&1 || true
    limactl shell "$vm" -- sudo bash -c '
      if [ -f /tmp/beep-k3s-controller-rpfilter-all.saved ]; then
        sysctl -w net.ipv4.conf.all.rp_filter="$(cat /tmp/beep-k3s-controller-rpfilter-all.saved)" >/dev/null 2>&1 || true
        rm -f /tmp/beep-k3s-controller-rpfilter-all.saved
      fi
    ' >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

echo "==> [1/11] bringing up the k3s cluster ($VM_A server, $VM_B agent, proxy-mode=$PROXY_MODE) and $VM_CLIENT"
k3s_bring_up_cluster "$VM_A" "$VM_B" "$VM_CLIENT" "$PROXY_MODE"

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

echo "==> [2/11] creating geneve0 on both nodes (external mode -- beep sets the tunnel key itself)"
for vm in "$VM_A" "$VM_B"; do
  limactl shell "$vm" -- sudo bash -c '
    ip link show geneve0 >/dev/null 2>&1 || ip link add geneve0 type geneve external
    ip link set geneve0 up
    # Same rp_filter workaround every other smoke harness applies
    # (smoke-remote.sh/smoke-wg-2node-remote.sh/smoke-eth-ingress-2node-remote.sh):
    # geneve0 carries no IP address, so fib_validate_source in the kernel
    # never grants its loose-mode (2) exception for it -- an address-less
    # input device falls through to the same reverse-path drop as strict
    # mode regardless of the configured value, silently blackholing every
    # decapped forward packet before it ever reaches cni0 (confirmed live:
    # kprobe:ip_route_input_noref returns -EXDEV for the decapped packet,
    # even with rp_filter=2 on both all and geneve0). Only rp_filter=0
    # bypasses this check. The kernel takes max(all, interface), so the
    # `all` companion is required too -- an interface-only 0 is fragile
    # against a nonzero `all` (the siblings above all set both).
    # Saved (all only -- geneve0 itself is deleted in cleanup, so its
    # own value never persists to restore) and restored on exit, same
    # as smoke-remote.sh/smoke-wg-2node-remote.sh/
    # smoke-eth-ingress-2node-remote.sh, so this rig never leaves the
    # VM'"'"'s global rp_filter permanently weakened.
    if [ ! -f /tmp/beep-k3s-controller-rpfilter-all.saved ]; then
      sysctl -n net.ipv4.conf.all.rp_filter > /tmp/beep-k3s-controller-rpfilter-all.saved
    fi
    sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
    sysctl -w net.ipv4.conf.geneve0.rp_filter=0 >/dev/null
  '
done

SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"
IMAGE="docker.io/valerauko/beep-lb:${SHA}"
echo "==> [4/11] building the commit-under-test's image ($IMAGE) and deploying the controller DaemonSet (deploy/rbac.yaml + deploy/daemonset.yaml)"

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

# Same cross-build technique as scripts/smoke.sh (cargo-zigbuild, no QEMU),
# glibc-pinned the same way as .github/workflows/delivery.yaml's real
# release build, just targeting this rig's own node arch instead of both.
( cd "$REPO_ROOT" && cargo +nightly zigbuild --release -p beep-controller --target "$rust_target" )
mkdir -p "$REPO_ROOT/dist/linux/$goarch"
cp "$REPO_ROOT/target/${rust_target%%.*}/release/beep-controller" "$REPO_ROOT/dist/linux/$goarch/beep-controller"

docker buildx build --platform "linux/$goarch" -t "$IMAGE" --load "$REPO_ROOT" >/dev/null

IMAGE_TMPDIR="$(mktemp -d)"
docker save "$IMAGE" -o "$IMAGE_TMPDIR/beep-lb.tar"
for vm in "$VM_A" "$VM_B"; do
  limactl copy "$IMAGE_TMPDIR/beep-lb.tar" "$vm":/tmp/beep-lb.tar
  # Imported straight into containerd, never pulled from a registry -- the
  # whole point is testing this exact checkout, not whatever tag currently
  # resolves on Docker Hub (see this script's IMAGE header note).
  limactl shell "$vm" -- sudo k3s ctr images import /tmp/beep-lb.tar >/dev/null
  limactl shell "$vm" -- rm -f /tmp/beep-lb.tar
done
rm -rf "$IMAGE_TMPDIR"
IMAGE_TMPDIR=""

if ! k3s_deploy_controller_daemonset "$REPO_ROOT" "$IMAGE"; then
  echo "CONTROLLER-DEPLOY: FAIL (see pod status/logs below -- this step is expected to PASS, see this script's header)" >&2
  kube -n kube-system get pods -l "$CONTROLLER_SELECTOR" -o wide >&2 || true
  dump_evidence
  exit 1
fi
echo "CONTROLLER-DEPLOY: PASS (servicelb-controller Running on both nodes, zero restarts after a 10s settle)"

lease_renewals() { # lease_renewals -- "<lease> <renewTime>" per node Lease
  kube -n beep-leases get lease -l app.kubernetes.io/component=node-lease \
    -o jsonpath='{range .items[*]}{.metadata.name} {.spec.renewTime}{"\n"}{end}'
}

if [ "$CLIENT_CERT_AUTH" = 1 ]; then
  echo "==> [4a/11] switching the controller to the documented client-cert kubeconfig (deploy/README.md Authentication)"
  k3s_provision_client_cert_auth "$VM_A" "$IP_A" "$REPO_ROOT" || {
    echo "CLIENT-CERT-AUTH: FAIL (provisioning or rollout failed)" >&2
    dump_evidence
    exit 1
  }
  sleep 10
  AUTH_ARGS="$(kube -n kube-system get pods -l "$CONTROLLER_SELECTOR" -o jsonpath='{.items[*].spec.containers[0].args}')"
  AUTH_AUTOMOUNT="$(kube -n kube-system get pods -l "$CONTROLLER_SELECTOR" -o jsonpath='{.items[*].spec.automountServiceAccountToken}')"
  AUTH_LABEL="client-cert kubeconfig, ServiceAccount token unmounted"
  case "$AUTH_ARGS" in *--kubeconfig=*) ;; *) echo "CLIENT-CERT-AUTH: FAIL (pods carry no --kubeconfig arg: $AUTH_ARGS)" >&2; dump_evidence; exit 1 ;; esac
  case "$AUTH_AUTOMOUNT" in *true*) echo "CLIENT-CERT-AUTH: FAIL (ServiceAccount token still mounted: $AUTH_AUTOMOUNT)" >&2; dump_evidence; exit 1 ;; esac
else
  AUTH_ARGS="$(kube -n kube-system get pods -l "$CONTROLLER_SELECTOR" -o jsonpath='{.items[*].spec.containers[0].args}')"
  AUTH_LABEL="in-cluster ServiceAccount, no kubeconfig"
  case "$AUTH_ARGS" in *--kubeconfig*) echo "AUTH: FAIL (the stock DaemonSet must not pass --kubeconfig: $AUTH_ARGS)" >&2; dump_evidence; exit 1 ;; esac
fi
LEASES_BEFORE="$(lease_renewals)"
sleep 25
LEASES_AFTER="$(lease_renewals)"
if [ "$(wc -l <<<"$LEASES_AFTER" | tr -d ' ')" -lt 2 ] || \
   awk 'NR==FNR{b[$1]=$2;next} b[$1]==$2{bad=1} END{exit !bad}' <(printf '%s\n' "$LEASES_BEFORE") <(printf '%s\n' "$LEASES_AFTER"); then
  echo "AUTH: FAIL (a node Lease did not renew in 25s, so the controller is not talking to the API under $AUTH_LABEL)" >&2
  echo "before: $LEASES_BEFORE" >&2
  echo "after: $LEASES_AFTER" >&2
  dump_evidence
  exit 1
fi
echo "AUTH: PASS ($AUTH_LABEL; $(wc -l <<<"$LEASES_AFTER" | tr -d ' ') node Leases renewed within 25s)"

echo "==> [5/11] sampling beep-controller RSS baseline (post-deploy, before any Service/EndpointSlice reconcile load)"
rss_a_baseline=$(controller_rss limactl shell "$VM_A" --)
rss_b_baseline=$(controller_rss limactl shell "$VM_B" --)
assert_controller_rss_baseline "$rss_a_baseline" "$VM_A" || { dump_evidence; exit 1; }
assert_controller_rss_baseline "$rss_b_baseline" "$VM_B" || { dump_evidence; exit 1; }

echo "==> [6/11] creating the real Service + backend Deployment (Pod pinned to $NODE_B_K8S)"
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
    - port: $FRONT_PORT
      targetPort: 80
      protocol: TCP
EOF

echo "==> [7/11] waiting for the Deployment, EndpointSlice, and status.loadBalancer.ingress"
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

echo "==> [8/11] confirming the dataplane maps are programmed"
front_a=$(map_entry_count "$VM_A" FRONT_META)
front_b=$(map_entry_count "$VM_B" FRONT_META)
pod_targets_b=$(map_entry_count "$VM_B" POD_TARGETS)
[ -n "$front_a" ] && [ "$front_a" -ge 1 ] || { echo "FAIL: $VM_A's FRONT_META has no entries ($front_a)" >&2; dump_evidence; exit 1; }
[ -n "$front_b" ] && [ "$front_b" -ge 1 ] || { echo "FAIL: $VM_B's FRONT_META has no entries ($front_b)" >&2; dump_evidence; exit 1; }
[ -n "$pod_targets_b" ] && [ "$pod_targets_b" -ge 1 ] || {
  echo "FAIL: $VM_B's POD_TARGETS has no entries ($pod_targets_b) -- the backend Pod it hosts was never admitted" >&2
  dump_evidence
  exit 1
}
echo "MAP-PROGRAMMING: PASS (FRONT_META: $VM_A=$front_a $VM_B=$front_b entries, $VM_B POD_TARGETS=$pod_targets_b entries)"

echo "==> [9/11] sampling beep-controller RSS after real reconcile load and asserting growth stays bounded"
rss_a_peak=$(controller_rss limactl shell "$VM_A" --)
rss_b_peak=$(controller_rss limactl shell "$VM_B" --)
assert_controller_rss_growth "$rss_a_baseline" "$rss_a_peak" "$VM_A" || { dump_evidence; exit 1; }
assert_controller_rss_growth "$rss_b_baseline" "$rss_b_peak" "$VM_B" || { dump_evidence; exit 1; }

echo "==> [10/11] driving client ($VM_CLIENT, $IP_CLIENT) -> front $IP_A:$FRONT_PORT -> cross-node backend on $VM_B"
set +e
CLIENT_BODY="$(limactl shell "$VM_CLIENT" -- curl -sS -m 20 "http://${IP_A}:${FRONT_PORT}/" 2>&1)"
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

echo "==> [11/11] confirming a conntrack/FLOW_TABLE entry exists for a live flow"
k3s_hold_connection "$VM_CLIENT" "$IP_A" "$FRONT_PORT" 12 >/dev/null 2>&1 &
HOLD_PID=$!
sleep 4
flow_a=$(map_entry_count "$VM_A" FLOW_TABLE)
wait "$HOLD_PID" || true
[ -n "$flow_a" ] && [ "$flow_a" -ge 1 ] || {
  echo "FAIL: $VM_A's FLOW_TABLE has no entries ($flow_a) while a connection through it is open" >&2
  dump_evidence
  exit 1
}
echo "CONNTRACK: PASS ($VM_A FLOW_TABLE=$flow_a entries)"

if [ "$CLIENT_CERT_AUTH" = 1 ]; then
  echo ""
  echo "GATE CLIENT-CERT AUTH: PASS"
  exit 0
fi

# ---------------------------------------------------------------------------
# Multi-endpoint legs. Every Service gets its own front port (a front is keyed
# on address+port, so two Services on one port would share a front). Each leg
# asserts a property a pick-one controller or a policy-blind one cannot meet.
# ---------------------------------------------------------------------------
P_CLUSTER=81 P_PREF=82 P_LOCAL=83 P_TERM=84
N_CONNS=60

leg_fail() { # leg_fail <message> -- fatal, unless --keep-going, which runs every leg and fails at the end
  echo "$1" >&2
  LEG_FAILURES=$((LEG_FAILURES + 1))
  [ "$KEEP_GOING" = 1 ] && return 0
  dump_evidence
  exit 1
}

pod_map() { # pod_map <app> -- "<pod> <node>" per pod
  kube -n "$NAMESPACE" get pods -l "app=$1" --field-selector=status.phase=Running \
    -o jsonpath='{range .items[*]}{.metadata.name} {.spec.nodeName}{"\n"}{end}'
}

client_hits() { # client_hits <front-ip> <port> <n> -- "<count> <pod>" per distinct answering pod, "<count> FAIL" for failed connections; every request is a fresh connection
  limactl shell "$VM_CLIENT" -- bash -c "for i in \$(seq 1 $3); do curl -sS -m 5 http://$1:$2/ 2>/dev/null | sed -n 's/^Hostname: //p' | grep . || echo FAIL; done | sort | uniq -c"
}

hits_on_node() { # hits_on_node <pod-map> <hits> <node> -- connections answered by pods on <node>
  awk -v node="$3" 'NR==FNR{n[$1]=$2;next} n[$2]==node{s+=$1} END{print s+0}' <(printf '%s\n' "$1") <(printf '%s\n' "$2")
}

hits_total() { awk '$2!="FAIL"{s+=$1} END{print s+0}' <<<"$1"; }
hits_failed() { awk '$2=="FAIL"{s+=$1} END{print s+0}' <<<"$1"; }
hits_pods() { awk '$2!="FAIL"{n++} END{print n+0}' <<<"$1"; }

probe_rc() { # probe_rc <front-ip> <port> -- curl exit status of one fresh connection from the client
  local rc
  set +e
  limactl shell "$VM_CLIENT" -- curl -sS -m 5 -o /dev/null "http://$1:$2/" >/dev/null 2>&1
  rc=$?
  set -e
  echo "$rc"
}

ingress_of() { # ingress_of <svc> -- sorted, space-separated status.loadBalancer.ingress IPs
  kube -n "$NAMESPACE" get svc "$1" -o jsonpath='{.status.loadBalancer.ingress[*].ip}' | tr ' ' '\n' | sort | tr '\n' ' ' | sed 's/ $//'
}

wait_ingress() { # wait_ingress <svc> <expected sorted ips> -- polls, then echoes the last value
  local got="" _
  for _ in $(seq 1 60); do
    got="$(ingress_of "$1")"
    [ "$got" = "$2" ] && break
    sleep 1
  done
  echo "$got"
}

apply_multi() { # apply_multi <name> <port> <replicas> <etp|-> <td|-> <extra pod spec, 6-space indented, or empty> <extra container spec, 10-space indented, or empty>
  local name="$1" port="$2" replicas="$3" etp="$4" td="$5" podspec="$6" ctrspec="$7" policy=""
  [ "$etp" = "-" ] || policy="$policy
  externalTrafficPolicy: $etp"
  [ "$td" = "-" ] || policy="$policy
  trafficDistribution: $td"
  cat <<EOF | kube apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: $name
  namespace: $NAMESPACE
spec:
  replicas: $replicas
  selector:
    matchLabels: {app: $name}
  template:
    metadata:
      labels: {app: $name}
    spec:
$podspec
      containers:
        - name: whoami
          image: docker.io/traefik/whoami:latest
          ports:
            - containerPort: 80
$ctrspec
---
apiVersion: v1
kind: Service
metadata:
  name: $name
  namespace: $NAMESPACE
spec:
  type: LoadBalancer
  selector: {app: $name}$policy
  ports:
    - port: $port
      targetPort: 80
      protocol: TCP
EOF
}

SPREAD_PODSPEC="      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: kubernetes.io/hostname
          whenUnsatisfiable: DoNotSchedule
          labelSelector:
            matchLabels: {app: APP}"

spread_for() { echo "${SPREAD_PODSPEC/APP/$1}"; }

wait_ready() { # wait_ready <deployment> -- rollout done, then a settle for the EndpointSlice and the controller's reconcile
  kube -n "$NAMESPACE" rollout status "deployment/$1" --timeout=120s >/dev/null || leg_fail "LEG: FAIL ($1 never became Ready)"
  sleep 8
}

echo "==> [12] multi-endpoint legs (4 replicas spread 2+2 across $NODE_A_K8S/$NODE_B_K8S; $N_CONNS fresh connections per probe)"
apply_multi mcluster "$P_CLUSTER" 4 - - "$(spread_for mcluster)" ""
apply_multi mpref "$P_PREF" 4 - PreferSameNode "$(spread_for mpref)" ""
wait_ready mcluster
wait_ready mpref
CMAP="$(pod_map mcluster)"
PMAP="$(pod_map mpref)"
[ "$(hits_on_node "$CMAP" "$(awk '{print "1 "$1}' <<<"$CMAP")" "$NODE_A_K8S")" = 2 ] || leg_fail "LEG: FAIL (mcluster replicas not spread 2+2: $CMAP)"

# (a) Cluster, no trafficDistribution: spread over every pod, remote ones included although local ones exist.
HITS="$(client_hits "$IP_A" "$P_CLUSTER" "$N_CONNS")"
echo "$HITS"
LOCAL_N="$(hits_on_node "$CMAP" "$HITS" "$NODE_A_K8S")"
REMOTE_N="$(hits_on_node "$CMAP" "$HITS" "$NODE_B_K8S")"
[ "$(hits_failed "$HITS")" = 0 ] || leg_fail "LEG-A: FAIL (connections failed: $HITS)"
[ "$(hits_pods "$HITS")" -ge 3 ] && [ "$LOCAL_N" -ge 1 ] && [ "$REMOTE_N" -ge 1 ] || \
  leg_fail "LEG-A: FAIL (Cluster policy must spread over local AND remote pods; local=$LOCAL_N remote=$REMOTE_N distinct=$(hits_pods "$HITS"))"
echo "LEG-A cluster/uniform: PASS (via $IP_A: $LOCAL_N conns on node-a pods, $REMOTE_N on node-b pods, $(hits_pods "$HITS") of 4 pods used)"
ING="$(ingress_of mcluster)"
[ "$ING" = "$(printf '%s\n%s' "$IP_A" "$IP_B" | sort | tr '\n' ' ' | sed 's/ $//')" ] || leg_fail "LEG-A: FAIL (Cluster ingress should list both nodes, got '$ING')"

# (b) PreferSameNode: every flow stays on a pod local to the node it entered.
for pair in "$IP_A:$NODE_A_K8S:$NODE_B_K8S" "$IP_B:$NODE_B_K8S:$NODE_A_K8S"; do
  ip="${pair%%:*}"; rest="${pair#*:}"; own="${rest%%:*}"; other="${rest#*:}"
  HITS="$(client_hits "$ip" "$P_PREF" "$N_CONNS")"
  echo "$HITS"
  OWN_N="$(hits_on_node "$PMAP" "$HITS" "$own")"
  OTHER_N="$(hits_on_node "$PMAP" "$HITS" "$other")"
  [ "$(hits_failed "$HITS")" = 0 ] && [ "$OWN_N" -eq "$N_CONNS" ] && [ "$OTHER_N" = 0 ] || \
    leg_fail "LEG-B: FAIL (PreferSameNode via $ip: want all $N_CONNS on $own, got own=$OWN_N other=$OTHER_N)"
  echo "LEG-B prefer-same-node: PASS (via $ip: $OWN_N/$N_CONNS on $own pods, $OTHER_N remote)"
done

# (c) eTP=Local, pods only on node-b: node-a must not be advertised and must not serve.
apply_multi mlocal "$P_LOCAL" 2 Local - "      nodeName: $NODE_B_K8S" ""
wait_ready mlocal
LMAP="$(pod_map mlocal)"
ING="$(wait_ingress mlocal "$IP_B")"
[ "$ING" = "$IP_B" ] || leg_fail "LEG-C: FAIL (eTP=Local ingress should be only $IP_B (the node with pods), got '$ING')"
HITS="$(client_hits "$IP_B" "$P_LOCAL" 40)"
echo "$HITS"
[ "$(hits_failed "$HITS")" = 0 ] && [ "$(hits_pods "$HITS")" = 2 ] || leg_fail "LEG-C: FAIL (eTP=Local via the node with pods should spread over its 2 local pods: $HITS)"
RC_A="$(probe_rc "$IP_A" "$P_LOCAL")"
[ "$RC_A" != 0 ] || leg_fail "LEG-C: FAIL (a connection via $IP_A, which has no local pod, succeeded)"
echo "LEG-C eTP=Local: PASS (ingress=$ING; $IP_B served by both local pods; $IP_A has no local pod, connection failed rc=$RC_A)"

# (d) deleting one pod re-homes only its flows: every long-lived flow on a surviving pod continues,
# and the lost flows are exactly a subset of the victim's. Each flow is one curl connection (two URLs,
# keepalive reuse): a quick request records the serving pod, the long wait spans the delete. curl
# silently re-sends on a fresh connection when a reused one dies, so a flow only counts as surviving
# if both requests report the same client RemoteAddr (ip:port); a reconnect is a lost flow.
# The victim is the pod that actually answered the most flows (read from each flow's streamed first
# response), not one picked up front: hashing can leave any given pod flowless, and a leg whose
# victim served nothing proves nothing.
N_LONG=24
LONG_OUT="$(mktemp)"
FLOW_DIR="/tmp/beep-leg-d-flows"
limactl shell "$VM_CLIENT" -- bash -c "rm -rf $FLOW_DIR; mkdir -p $FLOW_DIR; for i in \$(seq 1 $N_LONG); do ( out=\$(curl -sS -m 50 'http://$IP_A:$P_CLUSTER/' 'http://$IP_A:$P_CLUSTER/?wait=30s' 2>/dev/null | sed -un 's/^Hostname: /H=/p;s/^RemoteAddr: /R=/p' | tee $FLOW_DIR/\$i); echo \$out ) & done; wait" >"$LONG_OUT" &
LONG_PID=$!
sleep 8
FIRST_HITS="$(limactl shell "$VM_CLIENT" -- bash -c "head -qn1 $FLOW_DIR/* | sed -n 's/^H=//p' | sort | uniq -c | sort -rn")"
echo "LEG-D first-request pods (count pod) at 8s: $(tr '\n' ';' <<<"$FIRST_HITS"); FRONT_ENDPOINTS entries: $(map_entry_count "$VM_A" FRONT_ENDPOINTS) on $VM_A, $(map_entry_count "$VM_B" FRONT_ENDPOINTS) on $VM_B"
VICTIM="$(awk 'NR==1{print $2}' <<<"$FIRST_HITS")"
[ -n "$VICTIM" ] || { leg_fail "LEG-D: FAIL (no flow had been answered 8s in; there is no victim to delete)"; VICTIM="none"; }
kube -n "$NAMESPACE" delete pod "$VICTIM" --grace-period=0 --force >/dev/null 2>&1 || leg_fail "LEG-D: FAIL (could not delete $VICTIM)"
wait "$LONG_PID" || true
# Fields are keyed (H=pod, R=client addr) and attributed to a request by the RemoteAddr count, so
# a request with no Hostname line yields FAIL instead of shifting RemoteAddr into the pod column.
FLOWS="$(awk '{
  nr = 0; h[1] = h[2] = r[1] = r[2] = ""
  for (i = 1; i <= NF; i++) {
    if ($i ~ /^H=/ && nr < 2) h[nr + 1] = substr($i, 3)
    else if ($i ~ /^R=/ && nr < 2) r[++nr] = substr($i, 3)
  }
  print (h[1] != "" && r[1] != "" ? h[1] : "FAIL"), (h[2] != "" && r[1] != "" && r[2] == r[1] ? h[2] : "FAIL")
}' "$LONG_OUT")"
rm -f "$LONG_OUT"
echo "LEG-D flows per pod before delete:"
awk '{print $1}' <<<"$FLOWS" | sort | uniq -c
echo "LEG-D flows per pod after delete:"
awk '{print $2}' <<<"$FLOWS" | sort | uniq -c
[ "$(awk 'END{print NR}' <<<"$FLOWS")" = "$N_LONG" ] && ! awk '$1=="FAIL"{f=1} END{exit !f}' <<<"$FLOWS" || \
  leg_fail "LEG-D: FAIL (not every flow established before the delete: $FLOWS)"
VICTIM_FLOWS="$(awk -v v="$VICTIM" '$1==v' <<<"$FLOWS" | wc -l | tr -d ' ')"
SURV_LOST="$(awk -v v="$VICTIM" '$1!=v && $2=="FAIL"' <<<"$FLOWS" | wc -l | tr -d ' ')"
SURV_MOVED="$(awk -v v="$VICTIM" '$1!=v && $2!="FAIL" && $2!=$1' <<<"$FLOWS" | wc -l | tr -d ' ')"
VICTIM_SERVED="$(awk -v v="$VICTIM" '$2==v' <<<"$FLOWS" | wc -l | tr -d ' ')"
LONG_OK="$(awk '$2!="FAIL"' <<<"$FLOWS" | wc -l | tr -d ' ')"
echo "LEG-D victim=$VICTIM victim_flows=$VICTIM_FLOWS survivor_flows_lost=$SURV_LOST survivor_flows_moved=$SURV_MOVED survived=$LONG_OK"
[ "$VICTIM_FLOWS" -ge 1 ] || leg_fail "LEG-D: FAIL (no long-lived flow landed on $VICTIM; the leg proves nothing: $FLOWS)"
[ "$VICTIM_SERVED" = 0 ] || leg_fail "LEG-D: FAIL (a connection was answered by the deleted pod $VICTIM)"
[ "$SURV_LOST" = 0 ] && [ "$SURV_MOVED" = 0 ] || \
  leg_fail "LEG-D: FAIL (flows on surviving pods were disturbed by deleting $VICTIM: lost=$SURV_LOST moved=$SURV_MOVED; flows (before after): $FLOWS)"
echo "LEG-D pod-delete: PASS (deleted $VICTIM: lost flows are exactly its $VICTIM_FLOWS; all $LONG_OK survivor flows continued unmoved)"
wait_ready mcluster
HITS="$(client_hits "$IP_A" "$P_CLUSTER" 40)"
[ "$(hits_failed "$HITS")" = 0 ] || leg_fail "LEG-D: FAIL (new connections failed after the delete: $HITS)"

# (f) eTP=Local, single local pod being deleted with a preStop sleep: the draining pod still serves.
TERM_PODSPEC="      nodeName: $NODE_B_K8S
      terminationGracePeriodSeconds: 45"
TERM_CTR="          lifecycle:
            preStop:
              sleep: {seconds: 30}
          readinessProbe:
            httpGet: {path: /, port: 80}
            initialDelaySeconds: 25
            periodSeconds: 2"
apply_multi mterm "$P_TERM" 1 Local - "$TERM_PODSPEC" "$TERM_CTR"
kube -n "$NAMESPACE" rollout status deployment/mterm --timeout=120s >/dev/null || leg_fail "LEG-F: FAIL (mterm never became Ready)"
sleep 8
OLD="$(pod_map mterm | awk '{print $1}')"
[ -n "$OLD" ] || leg_fail "LEG-F: FAIL (no mterm pod)"
kube -n "$NAMESPACE" delete pod "$OLD" --wait=false >/dev/null
sleep 5
HITS="$(client_hits "$IP_B" "$P_TERM" 10)"
echo "$HITS"
[ "$(hits_failed "$HITS")" = 0 ] && [ "$(hits_total "$HITS")" = 10 ] && [ "$(awk '$2==o{s+=$1} END{print s+0}' o="$OLD" <<<"$HITS")" = 10 ] || \
  leg_fail "LEG-F: FAIL (the terminating-but-serving local pod $OLD must keep serving while its replacement is not ready: $HITS)"
ING="$(ingress_of mterm)"
[ "$ING" = "$IP_B" ] || leg_fail "LEG-F: FAIL (node with the draining pod must stay listed, got '$ING')"
echo "LEG-F eTP=Local terminating fallback: PASS (10/10 connections answered by draining $OLD while no replacement was ready)"

# (e) no ready endpoints: new connections do not succeed (drop vs reject is not asserted here).
kube -n "$NAMESPACE" scale deployment/mcluster --replicas=0 >/dev/null
for _ in $(seq 1 60); do
  [ -z "$(pod_map mcluster)" ] && break
  sleep 1
done
sleep 8
for ip in "$IP_A" "$IP_B"; do
  RC="$(probe_rc "$ip" "$P_CLUSTER")"
  [ "$RC" != 0 ] || leg_fail "LEG-E: FAIL (a connection via $ip succeeded with 0 endpoints)"
done
echo "LEG-E scale-to-0: PASS (connections via both nodes do not succeed)"

# (i) colliding source ports across two fronts sharing one pod: the same client port is used for a
# connection via node-a and then via node-b, each closed before the next. The second collides on the
# backend's reverse key with whatever the first left behind, so every stale row used up one of the 16
# remap slots until new colliding connections were dropped; closed rows linger until the sweep but
# must not hold a slot. `nc -p` pins the source
# port (curl --local-port cannot rebind a port a previous connection used); the server closes first
# (HTTP/1.0), so the client side holds no TIME_WAIT and the port can be reused at once.
N_COLLIDE=24
COLLIDE_BASE=41000
flow_rows() { # flow_rows <vm> <tag> -- FLOW_TABLE rows of one role tag (00 forward, 01 reverse, 02 memo) on a node
  limactl shell "$1" -- sudo bpftool map dump pinned "$PIN_DIR/FLOW_TABLE" --json 2>/dev/null | jq --arg t "0x$2" '[.[] | select(.key[37] == $t)] | length'
}
flow_rows_b() { flow_rows "$VM_B" "$1"; }
closed_rows() { # closed_rows <vm> <tag> -- rows of one role tag whose closed flag (0x10 of the flags word at value byte 38) is set
  limactl shell "$1" -- sudo bpftool map dump pinned "$PIN_DIR/FLOW_TABLE" --json 2>/dev/null | jq --arg t "0x$2" '
    def hexb: ltrimstr("0x") | ascii_downcase | explode | map(if . > 96 then . - 87 else . - 48 end) | .[0] * 16 + .[1];
    [.[] | select(.key[37] == $t and ((((.value[38] | hexb) / 16 | floor) % 2) == 1))] | length'
}
echo "==> [12i] colliding source ports: $N_COLLIDE closed pairs through $IP_A and $IP_B (one pod), then more"
ROWS_BEFORE="$(flow_rows_b 01)"
FWD_BEFORE="$(flow_rows "$VM_A" 00)"
COLLIDE_OUT="$(limactl shell "$VM_CLIENT" -- bash -c "
ok=0; fail=0; first_fail=''
for i in \$(seq 0 $((N_COLLIDE - 1))); do
  p=\$(($COLLIDE_BASE + i))
  for ip in $IP_A $IP_B; do
    out=\$(printf 'GET / HTTP/1.0\r\nHost: beep\r\n\r\n' | timeout 6 nc -p \$p \$ip $FRONT_PORT 2>&1)
    if grep -q '^Hostname: ' <<<\"\$out\"; then
      ok=\$((ok + 1))
    else
      fail=\$((fail + 1)); [ -n \"\$first_fail\" ] || first_fail=\"pair \$i port \$p via \$ip: \$(tr '\n' ' ' <<<\"\$out\" | cut -c1-100)\"
    fi
    sleep 0.3
  done
done
echo \"ok=\$ok fail=\$fail first_fail=\$first_fail\"
")"
FWD_AFTER="$(flow_rows "$VM_A" 00)"
echo "LEG-I $COLLIDE_OUT; backend reverse rows before=$ROWS_BEFORE after=$(flow_rows_b 01) memo rows=$(flow_rows_b 02); ingress forward rows on $VM_A before=$FWD_BEFORE after=$FWD_AFTER"
case "$COLLIDE_OUT" in
  "ok=$((N_COLLIDE * 2)) fail=0 "*) ;;
  *) leg_fail "LEG-I: FAIL (colliding-port connections were refused: $COLLIDE_OUT)" ;;
esac
[ "$(flow_rows_b 02)" -le "$N_COLLIDE" ] || leg_fail "LEG-I: FAIL (more port-remap memo rows than remapped connections after $N_COLLIDE closed pairs: $(flow_rows_b 02))"
CLOSED_FWD="$(closed_rows "$VM_A" 00)"
[ "$((FWD_AFTER - FWD_BEFORE))" -le "$((N_COLLIDE + 4))" ] || leg_fail "LEG-I: FAIL ($N_COLLIDE closed connections through $VM_A left $((FWD_AFTER - FWD_BEFORE)) new forward rows)"
[ "$CLOSED_FWD" -ge "$((N_COLLIDE / 2))" ] || leg_fail "LEG-I: FAIL (only $CLOSED_FWD of $N_COLLIDE closed connections through $VM_A have their forward row marked closed)"
echo "LEG-I colliding-source-ports: PASS ($((N_COLLIDE * 2)) connections over $N_COLLIDE colliding pairs all answered although closed rows linger; $CLOSED_FWD ingress forward rows marked closed)"

# (h) ConfigMap sizing change: editing beep-config and restarting the DaemonSet resizes the front
# maps on both nodes (the pods read the new value; bpftool shows the new max_entries) while an
# established flow keeps running (FLOW_TABLE is a separate, unchanged map). Fresh connections are
# probed throughout; the failure window is reported, and every front must answer again afterwards.
# Runs before (g), which leaves the DaemonSet on OnDelete (no rollout restart).
CFG_FRONTS=1000
CFG_EPF=3
PROBE_STOP=/tmp/beep-cfg-probe-stop
PROBE_OUT="$(mktemp)"
FLOW_OUT="$(mktemp)"
map_max_entries() { # map_max_entries <vm> <map> -- the pinned map's max_entries
  limactl shell "$1" -- sudo bpftool map show pinned "$PIN_DIR/$2" --json | jq -r .max_entries
}
pod_beep_env() { # pod_beep_env <vm> -- the controller process's BEEP_* env, one per line
  limactl shell "$1" -- sudo bash -c 'tr "\0" "\n" < /proc/$(pgrep -x beep-controller | head -1)/environ | grep ^BEEP_ | sort'
}
echo "==> [13] ConfigMap sizing change (BEEP_MAX_FRONTS=$CFG_FRONTS) + DaemonSet restart: maps resized, established flow survives"
limactl shell "$VM_CLIENT" -- rm -f "$PROBE_STOP"
limactl shell "$VM_CLIENT" -- bash -c "( curl -sS -m 150 'http://$IP_A:$FRONT_PORT/' 'http://$IP_A:$FRONT_PORT/?wait=100s' 2>/dev/null | sed -n 's/^Hostname: //p;s/^RemoteAddr: //p' | tr '\n' ' '; echo )" >"$FLOW_OUT" &
FLOW_PID=$!
PROBE_PIDS=""
for ip in "$IP_A" "$IP_B"; do
  limactl shell "$VM_CLIENT" -- bash -c "while [ ! -e $PROBE_STOP ]; do t=\$(date +%s.%N); if curl -sS -m 2 -o /dev/null http://$ip:$FRONT_PORT/ 2>/dev/null; then echo \"$ip \$t ok\"; else echo \"$ip \$t fail\"; fi; sleep 0.1; done" >>"$PROBE_OUT" &
  PROBE_PIDS="$PROBE_PIDS $!"
done
sleep 5
kube -n kube-system patch configmap beep-config --type=merge \
  -p "{\"data\":{\"BEEP_MAX_FRONTS\":\"$CFG_FRONTS\",\"BEEP_ENDPOINTS_PER_FRONT\":\"$CFG_EPF\"}}" >/dev/null
RESTART_T0=$(date +%s)
kube -n kube-system rollout restart daemonset/servicelb-controller >/dev/null
kube -n kube-system rollout status daemonset/servicelb-controller --timeout=180s >/dev/null || leg_fail "LEG-H: FAIL (DaemonSet did not finish rolling out after the ConfigMap change)"
RESTART_S=$(( $(date +%s) - RESTART_T0 ))
sleep 10
limactl shell "$VM_CLIENT" -- touch "$PROBE_STOP"
# shellcheck disable=SC2086
wait $PROBE_PIDS || true
wait "$FLOW_PID" || true
for vm in "$VM_A" "$VM_B"; do
  ENV_NOW="$(pod_beep_env "$vm")"
  FM="$(map_max_entries "$vm" FRONT_META)"
  FE="$(map_max_entries "$vm" FRONT_ENDPOINTS)"
  echo "LEG-H $vm env: $(tr '\n' ' ' <<<"$ENV_NOW") FRONT_META.max_entries=$FM FRONT_ENDPOINTS.max_entries=$FE"
  [ "$(grep -Ev '_IDLE_SWEEP_SECS=|BEEP_FLOW_TABLE_MAX_ENTRIES=' <<<"$ENV_NOW")" = "$(printf 'BEEP_ENDPOINTS_PER_FRONT=%s\nBEEP_MAX_FRONTS=%s' "$CFG_EPF" "$CFG_FRONTS")" ] || leg_fail "LEG-H: FAIL ($vm controller did not pick up the ConfigMap env)"
  [ "$FM" = "$CFG_FRONTS" ] && [ "$FE" = "$((CFG_FRONTS * CFG_EPF * 2))" ] || \
    leg_fail "LEG-H: FAIL ($vm front maps not resized: FRONT_META=$FM FRONT_ENDPOINTS=$FE, want $CFG_FRONTS/$((CFG_FRONTS * CFG_EPF * 2)))"
done
read -r FLOW_POD FLOW_ADDR1 FLOW_POD2 FLOW_ADDR2 <"$FLOW_OUT" || true
echo "LEG-H established flow (pod addr / pod addr): ${FLOW_POD:-none} ${FLOW_ADDR1:-} ${FLOW_POD2:-} ${FLOW_ADDR2:-}"
{ [ -n "${FLOW_ADDR1:-}" ] && [ "${FLOW_ADDR1:-}" = "${FLOW_ADDR2:-}" ] && [ "${FLOW_POD:-}" = "${FLOW_POD2:-}" ]; } || \
  leg_fail "LEG-H: FAIL (the established flow did not survive the restart: '$(cat "$FLOW_OUT")')"
for ip in "$IP_A" "$IP_B"; do
  awk -v ip="$ip" -v restart_s="$RESTART_S" '
    $1==ip { n++; if ($3=="fail") { f++; if (!first) first=$2; last=$2 } }
    END { printf "LEG-H new connections via %s: %d probes, %d failed, failure window %.1fs (first fail to last fail), rollout took %ds\n", ip, n, f, (f ? last-first : 0), restart_s }' "$PROBE_OUT"
  awk -v ip="$ip" '$1==ip{last=$3} END{exit last!="ok"}' "$PROBE_OUT" || leg_fail "LEG-H: FAIL (new connections via $ip still failing after the restart)"
done
rm -f "$PROBE_OUT" "$FLOW_OUT"
echo "LEG-H configmap-restart: PASS (pods read the ConfigMap, maps resized, established flow survived)"

# (h2) A restore write failure must reach a real apiserver as MapRestoreFailed Events on the Node
# (default ns) and the Pod (its ns). The fault hook fails the first restore write with ENOMEM on a
# resize; removing the hook lets the retry restore from the kept parked pin.
CFG_FAULT_FRONTS=1500
echo "==> [13b] injected restore write failure (BEEP_MAX_FRONTS=$CFG_FAULT_FRONTS): MapRestoreFailed Events accepted by the apiserver"
kube delete events -A --field-selector reason=MapRestoreFailed >/dev/null 2>&1 || true
kube -n kube-system patch configmap beep-config --type=merge \
  -p "{\"data\":{\"BEEP_MAX_FRONTS\":\"$CFG_FAULT_FRONTS\"}}" >/dev/null
kube -n kube-system set env daemonset/servicelb-controller BEEP_FAULT_FAIL_RESTORE_WRITE=1 >/dev/null
restore_events() { kube get events -A --field-selector reason=MapRestoreFailed -o json; }
for _ in $(seq 1 45); do
  [ "$(restore_events | jq '[.items[].involvedObject.kind] | unique | length')" = 2 ] && break
  sleep 2
done
echo "LEG-H2 events:"
kube get events -A --field-selector reason=MapRestoreFailed
restore_events | jq -r '.items[0].message' | sed 's/^/LEG-H2 message: /'
[ "$(restore_events | jq '[.items[] | select(.involvedObject.kind == "Node" and .metadata.namespace == "default")] | length')" -ge 1 ] || \
  leg_fail "LEG-H2: FAIL (no MapRestoreFailed Event on a Node in default)"
[ "$(restore_events | jq '[.items[] | select(.involvedObject.kind == "Pod" and .metadata.namespace == "kube-system")] | length')" -ge 1 ] || \
  leg_fail "LEG-H2: FAIL (no MapRestoreFailed Event on a Pod in kube-system)"
kube -n kube-system set env daemonset/servicelb-controller BEEP_FAULT_FAIL_RESTORE_WRITE- >/dev/null
# Dropping the env restores the pre-fault pod template, so a node whose pod never restarted keeps its old sizing.
kube -n kube-system rollout restart daemonset/servicelb-controller >/dev/null
kube -n kube-system rollout status daemonset/servicelb-controller --timeout=240s >/dev/null || leg_fail "LEG-H2: FAIL (DaemonSet did not recover once the fault was removed)"
for vm in "$VM_A" "$VM_B"; do
  FM="$(map_max_entries "$vm" FRONT_META)"
  [ "$FM" = "$CFG_FAULT_FRONTS" ] || leg_fail "LEG-H2: FAIL ($vm FRONT_META.max_entries=$FM after the retry, want $CFG_FAULT_FRONTS)"
done
echo "LEG-H2 restore-failure-events: PASS (Node and Pod MapRestoreFailed Events accepted; pods recovered after the fault was removed)"

# (g) dead-node pruning: a node whose beep pod is gone must leave status.loadBalancer.ingress
# (its Lease expires and a live controller prunes it) and return when beep comes back.
# OnDelete keeps node-a's controller (the pruner) running; a nodeSelector to node-a alone makes the
# DaemonSet controller remove node-b's pod and not recreate it.
# Budget: pod termination grace (up to 30s) + lease duration 40s + prune
# interval <=15s x 2 passes (an IP is pruned only after two consecutive unmatched passes) = ~100s,
# plus slack.
LEASE_PRUNE_BUDGET=120
LEASE_RETURN_BUDGET=120
BOTH_IPS="$(printf '%s\n%s' "$IP_A" "$IP_B" | sort | tr '\n' ' ' | sed 's/ $//')"
poll_ingress() { # poll_ingress <svc> <expected> <seconds> -- echoes seconds waited, or "" on timeout
  local waited=0
  while [ "$waited" -lt "$3" ]; do
    [ "$(ingress_of "$1")" = "$2" ] && { echo "$waited"; return; }
    sleep 2
    waited=$((waited + 2))
  done
  echo ""
}
[ "$(ingress_of whoami)" = "$BOTH_IPS" ] || leg_fail "LEG-G: FAIL (precondition: whoami ingress should list both nodes before the beep pod is stopped, got '$(ingress_of whoami)')"
kube -n kube-system patch daemonset servicelb-controller --type=merge \
  -p "{\"spec\":{\"updateStrategy\":{\"type\":\"OnDelete\",\"rollingUpdate\":null},\"template\":{\"spec\":{\"nodeSelector\":{\"kubernetes.io/hostname\":\"$NODE_A_K8S\"}}}}}" >/dev/null
GONE_AFTER="$(poll_ingress whoami "$IP_A" "$LEASE_PRUNE_BUDGET")"
[ -n "$GONE_AFTER" ] || { kube -n beep-leases get lease -o yaml >&2 || true; kube -n kube-system logs -l app.kubernetes.io/name=servicelb-controller --tail=60 >&2 || true; }
[ -n "$GONE_AFTER" ] || leg_fail "LEG-G: FAIL ($IP_B still listed in whoami ingress ${LEASE_PRUNE_BUDGET}s after its beep pod was stopped: '$(ingress_of whoami)'; dead nodes are not pruned)"
echo "LEG-G dead-node prune: PASS ($IP_B left ingress ${GONE_AFTER}s after its beep pod was stopped; $IP_A stays)"
kube -n kube-system patch daemonset servicelb-controller --type=json \
  -p '[{"op":"remove","path":"/spec/template/spec/nodeSelector"}]' >/dev/null
BACK_AFTER="$(poll_ingress whoami "$BOTH_IPS" "$LEASE_RETURN_BUDGET")"
[ -n "$BACK_AFTER" ] || leg_fail "LEG-G: FAIL ($IP_B did not return to whoami ingress ${LEASE_RETURN_BUDGET}s after its beep pod came back: '$(ingress_of whoami)')"
echo "LEG-G node return: PASS ($IP_B re-listed ${BACK_AFTER}s after its beep pod came back)"

echo ""
if [ "$LEG_FAILURES" -gt 0 ]; then
  echo "GATE CONTROLLER-DRIVEN ROUND-TRIP: FAIL ($LEG_FAILURES multi-endpoint assertion(s) failed)" >&2
  exit 1
fi
echo "GATE CONTROLLER-DRIVEN ROUND-TRIP: PASS"
