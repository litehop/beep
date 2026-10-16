#!/usr/bin/env bash
# deploy-overlays/client-cert must swap the ServiceAccount token for the
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

check_render "stock base" "$REPO/deploy-overlays/client-cert"

# Same manifests in a scratch tree, base volumes/mounts perturbed.
cp -R "$REPO/deploy" "$REPO/deploy-overlays" "$TMP/"
printf '        - name: extra\n          emptyDir: {}\n' >>"$TMP/deploy/daemonset.yaml"
check_render "volume appended to base" "$TMP/deploy-overlays/client-cert"

awk '/^        - name: bpffs$/ {print "        - name: extra0"; print "          emptyDir: {}"} {print}' \
  "$TMP/deploy/daemonset.yaml" >"$TMP/ds.yaml"
mv "$TMP/ds.yaml" "$TMP/deploy/daemonset.yaml"
check_render "volume inserted before bpffs (indices shifted)" "$TMP/deploy-overlays/client-cert"

exit "$fail"
