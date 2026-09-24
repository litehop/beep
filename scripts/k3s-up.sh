#!/usr/bin/env bash
# Idempotently stand up k3s across beep-node-a (server) + beep-node-b (agent)
# on the lima/beep-k3s.yaml profile -- the Tier-2 k8s integration cluster the
# controller's e2e test runs on. servicelb+traefik disabled so k3s's own
# klipper-lb can't race beep for type=LoadBalancer Services; flannel
# (default VXLAN CNI) and kube-proxy are left stock.
#
# --dual-stack reconfigures the cluster's own cluster-cidr/service-cidr/
# node-ip to dual-stack (v4 primary, v6 second) -- a k3s-immutable shape that
# needs a full uninstall+reinstall to change, so this flag forces one
# whenever the live cluster isn't already shaped that way (checked via each
# node's own InternalIP list, so a repeat --dual-stack call is still a cheap
# no-op). Never silently reverts a dual-stack cluster back to single-stack
# when the flag is omitted -- extra unused v6 InternalIPs don't affect a
# single-stack-only caller's own assertions.
#
# Usage: scripts/k3s-up.sh [--vm-a <server-vm>] [--vm-b <agent-vm>] [--proxy-mode <iptables|ipvs>] [--dual-stack]
set -euo pipefail

VM_A="beep-node-a"
VM_B="beep-node-b"
PROXY_MODE="iptables"
DUAL_STACK=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vm-a) VM_A="$2"; shift 2 ;;
    --vm-b) VM_B="$2"; shift 2 ;;
    --proxy-mode) PROXY_MODE="$2"; shift 2 ;;
    --dual-stack) DUAL_STACK=1; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=k3s-common.sh
. "$SCRIPT_DIR/k3s-common.sh"

# kube-proxy's IPVS backend needs ip_vs/ip_vs_rr/nf_conntrack present on both
# nodes -- lima/beep-k3s.yaml's Ubuntu image has them, but this script
# doesn't modprobe them; caller's responsibility.
KUBE_PROXY_ARG=""
if [ "$PROXY_MODE" = "ipvs" ]; then
  KUBE_PROXY_ARG=" --kube-proxy-arg=proxy-mode=ipvs"
elif [ "$PROXY_MODE" != "iptables" ]; then
  echo "FAIL: unknown --proxy-mode '$PROXY_MODE' (want iptables or ipvs)" >&2
  exit 1
fi

LIMA_YAML="$SCRIPT_DIR/../lima/beep-k3s.yaml"

command -v jq >/dev/null || { echo "FAIL: jq not found on PATH" >&2; exit 1; }

# beep-node-a/beep-node-b are shared, by name, with the lighter smoke-wg-2node
# rig (lima/beep.yaml, 1CPU/2GiB) -- an already-provisioned directory under
# these names doesn't prove it was provisioned from THIS profile
# (lima/beep-k3s.yaml, 2CPU/4GiB). Resuming a wrong-shaped VM silently would
# make the controller e2e flaky/underpowered instead of failing loud.
REQUIRED_CPUS="$(grep -E '^cpus:' "$LIMA_YAML" | awk '{print $2}')"
REQUIRED_MEMORY="$(grep -E '^memory:' "$LIMA_YAML" | awk '{print $2}' | tr -d '"')"
[ -n "$REQUIRED_CPUS" ] && [ -n "$REQUIRED_MEMORY" ] || {
  echo "FAIL: could not read cpus/memory from $LIMA_YAML" >&2
  exit 1
}

assert_vm_shape() { # assert_vm_shape <vm> -- fails loud if a VM already provisioned under this name has different cpus/memory than lima/beep-k3s.yaml wants (e.g. it's still shaped for the lighter smoke-wg-2node rig), instead of silently resuming it
  local vm="$1" info actual_cpus actual_memory
  info="$(limactl list --json 2>/dev/null | jq -c "select(.name == \"$vm\")")"
  [ -n "$info" ] || { echo "FAIL: $vm has a lima instance directory but 'limactl list' doesn't know about it" >&2; exit 1; }
  actual_cpus="$(jq -r '.config.cpus' <<<"$info")"
  actual_memory="$(jq -r '.config.memory' <<<"$info")"
  if [ "$actual_cpus" != "$REQUIRED_CPUS" ] || [ "$actual_memory" != "$REQUIRED_MEMORY" ]; then
    echo "FAIL: $vm is already provisioned at cpus=$actual_cpus memory=$actual_memory, but this k3s rig (lima/beep-k3s.yaml) needs cpus=$REQUIRED_CPUS memory=$REQUIRED_MEMORY -- looks like the lighter smoke-wg-2node profile (lima/beep.yaml) is still provisioned under this VM name. Delete it first: limactl delete -f $vm" >&2
    exit 1
  fi
}

echo "==> [1/4] bringing up $VM_A and $VM_B (lima/beep-k3s.yaml)"
for vm in "$VM_A" "$VM_B"; do
  if [ -d "${HOME}/.lima/${vm}" ]; then
    assert_vm_shape "$vm"
    limactl start "$vm" >/dev/null
  else
    limactl start --tty=false --name="$vm" "$LIMA_YAML"
  fi
done

eth0_ip() { # eth0_ip <vm> -- this VM's underlay address, used as k3s node-ip / server URL
  limactl shell "$1" -- bash -c "ip -4 -o addr show eth0 | awk '{print \$4}' | cut -d/ -f1"
}
IP_A="$(eth0_ip "$VM_A")"
[ -n "$IP_A" ] || { echo "FAIL: could not resolve $VM_A's eth0 address" >&2; exit 1; }

NODE_IP_A="$IP_A"
NODE_IP_B_ARG=""
DUAL_STACK_CIDR_ARGS=""
if [ "$DUAL_STACK" = "1" ]; then
  echo "==> [1b/4] assigning static LAN v6 (fd00:beef:98::/64) on $VM_A/$VM_B"
  k3s_seed_lan_v6 "$VM_A" "$K3S_LAN_ULA_A" "$VM_B" "$K3S_LAN_ULA_B"
  NODE_IP_A="$IP_A,$K3S_LAN_ULA_A"
  NODE_IP_B_ARG=" --node-ip=$(eth0_ip "$VM_B"),$K3S_LAN_ULA_B"
  # cluster-cidr/service-cidr are immutable after install (flannel/apiserver
  # allocate from them at first bring-up) -- a live cluster not already
  # shaped dual-stack needs a full uninstall+reinstall, not just a restart
  # with new EXEC args, to avoid leaving stale single-stack CNI/iptables
  # state behind.
  DUAL_STACK_CIDR_ARGS=" --cluster-cidr=10.42.0.0/16,fd00:beef:42::/56 --service-cidr=10.43.0.0/16,fd00:beef:43::/112"
  already_dual_stack=0
  if limactl shell "$VM_A" -- test -x /usr/local/bin/k3s >/dev/null 2>&1; then
    addrs="$(limactl shell "$VM_A" -- sudo /usr/local/bin/k3s kubectl get node "lima-$VM_A" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null || true)"
    case "$addrs" in *:*) already_dual_stack=1 ;; esac
  fi
  if [ "$already_dual_stack" = "0" ]; then
    echo "==> $VM_A/$VM_B are not yet dual-stack-shaped -- uninstalling k3s before reinstalling with dual-stack cluster-cidr/service-cidr"
    limactl shell "$VM_B" -- sudo bash -c '[ -x /usr/local/bin/k3s-agent-uninstall.sh ] && /usr/local/bin/k3s-agent-uninstall.sh || true' >/dev/null 2>&1 || true
    limactl shell "$VM_A" -- sudo bash -c '[ -x /usr/local/bin/k3s-uninstall.sh ] && /usr/local/bin/k3s-uninstall.sh || true' >/dev/null 2>&1 || true
  fi
fi

echo "==> [2/4] installing k3s server on $VM_A (node-ip=$NODE_IP_A, --disable=servicelb,traefik, proxy-mode=$PROXY_MODE, dual-stack=$DUAL_STACK)"
limactl shell "$VM_A" -- sudo bash -c "curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC='server --disable=servicelb,traefik --node-ip=$NODE_IP_A --write-kubeconfig-mode=644$KUBE_PROXY_ARG$DUAL_STACK_CIDR_ARGS' sh -"

echo "==> waiting for $VM_A's k3s server to be ready"
limactl shell "$VM_A" -- sudo bash -c '
  for i in $(seq 1 30); do
    /usr/local/bin/k3s kubectl get --raw=/readyz >/dev/null 2>&1 && exit 0
    sleep 2
  done
  echo "FAIL: k3s server on '"$VM_A"' did not become ready" >&2
  exit 1
'

TOKEN="$(limactl shell "$VM_A" -- sudo cat /var/lib/rancher/k3s/server/node-token)"
[ -n "$TOKEN" ] || { echo "FAIL: could not read $VM_A's k3s node-token" >&2; exit 1; }

echo "==> [3/4] installing k3s agent on $VM_B (joining https://$IP_A:6443, proxy-mode=$PROXY_MODE, dual-stack=$DUAL_STACK)"
limactl shell "$VM_B" -- sudo bash -c "curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC='agent$KUBE_PROXY_ARG$NODE_IP_B_ARG' K3S_URL='https://$IP_A:6443' K3S_TOKEN='$TOKEN' sh -"

echo "==> [4/4] waiting for both nodes to report Ready"
limactl shell "$VM_A" -- sudo bash -c '
  for i in $(seq 1 60); do
    ready="$(/usr/local/bin/k3s kubectl get nodes --no-headers 2>/dev/null | awk '"'"'$2 == "Ready"'"'"' | wc -l)"
    [ "$ready" -eq 2 ] && exit 0
    sleep 2
  done
  echo "FAIL: both nodes did not become Ready" >&2
  /usr/local/bin/k3s kubectl get nodes >&2 || true
  exit 1
'

echo "==> done -- e.g. 'limactl shell $VM_A -- sudo k3s kubectl get nodes'"
