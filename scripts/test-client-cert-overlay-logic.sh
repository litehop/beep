#!/usr/bin/env bash
# deploy/overlays/client-cert must swap the ServiceAccount token for the
# client-cert kubeconfig by NAME, never by position: if a base edit reordered
# or appended volumes and the overlay then dropped the wrong one, the
# dataplane would lose its bpffs mount or keep the token that masks a broken
# cert path.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$SCRIPT_DIR/.."

if ! command -v kubectl >/dev/null 2>&1; then
  echo "SKIP: kubectl not found; the client-cert overlay was NOT verified" >&2
  exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail=0
ok() { echo "PASS: $1"; }
bad() { echo "FAIL: $1" >&2; fail=1; }
has() { grep -qF -- "$2" "$1"; }

check_render() { # <label> <overlay-dir>
  local label=$1 out="$TMP/out.yaml"
  kubectl kustomize "$2" >"$out"
  if has "$out" 'name: serviceaccount' || has "$out" 'serviceAccountToken' || has "$out" 'mountPath: /var/run/secrets/kubernetes.io/serviceaccount'; then
    bad "$label: the ServiceAccount volume or mount survived, so the token can mask a broken cert path"
  else
    ok "$label: ServiceAccount volume and mount are gone"
  fi
  if has "$out" '- --kubeconfig=/etc/beep-controller/kubeconfig' && has "$out" 'secretName: beep-controller-kubeconfig' && has "$out" 'mountPath: /etc/beep-controller'; then
    ok "$label: kubeconfig arg, Secret volume and mount are present"
  else
    bad "$label: kubeconfig arg, Secret volume or mount missing, so the controller has no credentials"
  fi
  if [ "$(grep -cF 'name: bpffs' "$out")" = 2 ] && has "$out" 'mountPath: /sys/fs/bpf'; then
    ok "$label: bpffs volume and mount untouched"
  else
    bad "$label: bpffs volume or mount lost, so pins would not survive restarts"
  fi
}

check_render "stock base" "$REPO/deploy/overlays/client-cert"

# Same manifests in a scratch tree, base volumes/mounts perturbed.
cp -R "$REPO/deploy" "$TMP/"
printf '        - name: extra\n          emptyDir: {}\n' >>"$TMP/deploy/base/daemonset.yaml"
check_render "volume appended to base" "$TMP/deploy/overlays/client-cert"

awk '/^        - name: bpffs$/ {print "        - name: extra0"; print "          emptyDir: {}"} {print}' \
  "$TMP/deploy/base/daemonset.yaml" >"$TMP/ds.yaml"
mv "$TMP/ds.yaml" "$TMP/deploy/base/daemonset.yaml"
check_render "volume inserted before bpffs (indices shifted)" "$TMP/deploy/overlays/client-cert"

# A manifest accidentally dropped from or added to the base would silently
# change what users apply (e.g. losing the RBAC the controller needs), and the
# overlay must ship exactly the same objects.
EXPECTED='ClusterRole/servicelb-controller
ClusterRoleBinding/servicelb-controller
ConfigMap/kube-system/beep-config
DaemonSet/kube-system/servicelb-controller
Namespace/beep-leases
Role/beep-leases/servicelb-controller-node-lease
Role/default/servicelb-controller-events
Role/kube-system/servicelb-controller-events
Role/kube-system/servicelb-controller-flow-hash-seed
RoleBinding/beep-leases/servicelb-controller-node-lease
RoleBinding/default/servicelb-controller-events
RoleBinding/kube-system/servicelb-controller-events
RoleBinding/kube-system/servicelb-controller-flow-hash-seed
ServiceAccount/kube-system/servicelb-controller'

objects() { # <kustomize-dir> -> sorted kind/[namespace/]name lines
  kubectl kustomize "$1" | awk '
    function flush() { if (kind != "") print kind "/" (ns != "" ? ns "/" : "") name; kind = ""; ns = ""; name = ""; m = 0 }
    /^---$/ { flush(); next }
    /^kind:/ { kind = $2 }
    /^[^ ]/ { m = ($0 == "metadata:") }
    m && /^  name:/ { name = $2 }
    m && /^  namespace:/ { ns = $2 }
    END { flush() }' | LC_ALL=C sort
}

for d in base overlays/client-cert; do
  if [ "$(objects "$REPO/deploy/$d")" = "$(printf '%s\n' "$EXPECTED" | LC_ALL=C sort)" ]; then
    ok "deploy/$d renders exactly the expected objects"
  else
    bad "deploy/$d renders a different object set than expected, so users would apply more or fewer manifests than intended"
  fi
done

exit "$fail"
