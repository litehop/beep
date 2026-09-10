#!/usr/bin/env bash
# Idempotently stand up k3s across beep-node-a (server) + beep-node-b (agent)
# on the lima/beep-k3s.yaml profile -- the Tier-2 k8s integration cluster the
# controller's e2e test runs on. servicelb+traefik disabled so k3s's own
# klipper-lb can't race beep for type=LoadBalancer Services; flannel
# (default VXLAN CNI) and kube-proxy are left stock.
#
# Usage: scripts/k3s-up.sh [--vm-a <server-vm>] [--vm-b <agent-vm>]
set -euo pipefail

VM_A="beep-node-a"
VM_B="beep-node-b"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vm-a) VM_A="$2"; shift 2 ;;
    --vm-b) VM_B="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIMA_YAML="$SCRIPT_DIR/../lima/beep-k3s.yaml"

echo "==> [1/4] bringing up $VM_A and $VM_B (lima/beep-k3s.yaml)"
for vm in "$VM_A" "$VM_B"; do
  if [ -d "${HOME}/.lima/${vm}" ]; then
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

echo "==> [2/4] installing k3s server on $VM_A (node-ip=$IP_A, --disable=servicelb,traefik)"
limactl shell "$VM_A" -- sudo bash -c "curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC='server --disable=servicelb,traefik --node-ip=$IP_A --write-kubeconfig-mode=644' sh -"

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

echo "==> [3/4] installing k3s agent on $VM_B (joining https://$IP_A:6443)"
limactl shell "$VM_B" -- sudo bash -c "curl -sfL https://get.k3s.io | K3S_URL='https://$IP_A:6443' K3S_TOKEN='$TOKEN' sh -"

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
