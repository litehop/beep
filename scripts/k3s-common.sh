#!/usr/bin/env bash
# Shared k3s-on-Lima bring-up/controller-deploy/teardown boilerplate, sourced
# (not executed) by scripts/smoke-k3s-controller.sh, scripts/e2e-lb-k3s.sh,
# and scripts/e2e-lb-bidirectional-k3s.sh -- same convention as
# scripts/controller-rss.sh. Every function below assumes the caller has
# already defined SCRIPT_DIR and a `kube() { limactl shell "$VM_A" -- sudo
# k3s kubectl "$@"; }` wrapper, same as all three callers do.

k3s_bring_up_cluster() { # k3s_bring_up_cluster <vm-a> <vm-b> <vm-client> -- brings up the k3s server/agent pair (scripts/k3s-up.sh) and starts the client VM if it isn't already running
  local vm_a="$1" vm_b="$2" vm_client="$3"
  "$SCRIPT_DIR/k3s-up.sh" --vm-a "$vm_a" --vm-b "$vm_b"
  if ! limactl list --format '{{.Name}}\t{{.Status}}' 2>/dev/null | grep -qE "^${vm_client}[[:space:]]+Running"; then
    limactl start "$vm_client"
  fi
}

k3s_provision_kubeconfig_secret() { # k3s_provision_kubeconfig_secret <vm-a> <ip-a> <secret-name> <rm-after: 0|1> -- extracts vm-a's own admin kubeconfig, rewrites its 127.0.0.1 server to vm-a's real address, and applies it as a Secret; rm-after=0 leaves /tmp/beep-controller-kubeconfig on vm-a for the caller to copy elsewhere (e.g. to a client VM) before removing it itself
  local vm_a="$1" ip_a="$2" secret_name="$3" rm_after="$4" rm_cmd=""
  [ "$rm_after" = "1" ] && rm_cmd='
  rm -f /tmp/beep-controller-kubeconfig'
  limactl shell "$vm_a" -- sudo bash -c "
  sed 's#server: https://127.0.0.1:6443#server: https://${ip_a}:6443#' /etc/rancher/k3s/k3s.yaml > /tmp/beep-controller-kubeconfig
  k3s kubectl create secret generic $secret_name -n kube-system \
    --from-file=kubeconfig=/tmp/beep-controller-kubeconfig --dry-run=client -o yaml | k3s kubectl apply -f -$rm_cmd
"
}

k3s_deploy_controller_daemonset() { # k3s_deploy_controller_daemonset <repo-root> -- applies deploy/{rbac,daemonset}.yaml via the caller's kube(), waits for the rollout, and requires zero container restarts after a 10s settle (rollout status alone can miss a container that starts fine then CrashLoopBackOffs moments later, since none of these have a readiness/liveness probe); sets CONTROLLER_SELECTOR as a side effect, returns 1 on any failure
  local repo_root="$1"
  kube apply -f - < "$repo_root/deploy/rbac.yaml"
  kube apply -f - < "$repo_root/deploy/daemonset.yaml"
  controller_deploy_failed=0
  if ! kube -n kube-system rollout status daemonset/servicelb-controller --timeout=90s; then
    controller_deploy_failed=1
  fi
  CONTROLLER_SELECTOR=$(kube -n kube-system get daemonset servicelb-controller \
    -o json | jq -r '.spec.selector.matchLabels | to_entries | map("\(.key)=\(.value)") | join(",")')
  sleep 10
  restarts=$(kube -n kube-system get pods -l "$CONTROLLER_SELECTOR" \
    -o jsonpath='{.items[*].status.containerStatuses[0].restartCount}' 2>/dev/null || echo "")
  for c in $restarts; do
    [ "$c" = "0" ] || controller_deploy_failed=1
  done
  return "$controller_deploy_failed"
}

k3s_teardown_controller() { # k3s_teardown_controller <repo-root> <secret-name> -- deletes the controller DaemonSet/RBAC/kubeconfig Secret via the caller's kube(); `-f -` (stdin), not a host path -- kube() runs kubectl on a remote VM with no access to this process's own $REPO_ROOT
  local repo_root="$1" secret_name="$2"
  kube delete -f - --ignore-not-found < "$repo_root/deploy/daemonset.yaml" >/dev/null 2>&1 || true
  kube delete -f - --ignore-not-found < "$repo_root/deploy/rbac.yaml" >/dev/null 2>&1 || true
  kube delete secret "$secret_name" -n kube-system --ignore-not-found >/dev/null 2>&1 || true
}
