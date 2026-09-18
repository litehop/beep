#!/usr/bin/env bash
# Shared k3s-on-Lima bring-up/controller-deploy/teardown boilerplate, sourced
# (not executed) by scripts/smoke-k3s-controller.sh, scripts/e2e-lb-k3s.sh,
# and scripts/e2e-lb-bidirectional-k3s.sh -- same convention as
# scripts/controller-rss.sh. Every function below assumes the caller has
# already defined SCRIPT_DIR and VM_A before sourcing this file (kube() runs
# kubectl against $VM_A, the only node with a local apiserver).

kube() { # kube <args...> -- runs k3s kubectl as root on $VM_A (the only node with a local apiserver)
  limactl shell "$VM_A" -- sudo k3s kubectl "$@"
}

eth0_ip() { # eth0_ip <vm> -- this VM's real underlay address
  limactl shell "$1" -- bash -c "ip -4 -o addr show eth0 | awk '{print \$4}' | cut -d/ -f1"
}

k3s_bring_up_cluster() { # k3s_bring_up_cluster <vm-a> <vm-b> <vm-client> [proxy-mode] -- brings up the k3s server/agent pair (scripts/k3s-up.sh) and starts the client VM if it isn't already running; proxy-mode forwards to k3s-up.sh --proxy-mode (default iptables, matching k3s-up.sh's own default) so a caller can drive an IPVS-mode cluster without k3s-up.sh's own default silently resetting it back to iptables on the next invocation
  local vm_a="$1" vm_b="$2" vm_client="$3" proxy_mode="${4:-iptables}"
  "$SCRIPT_DIR/k3s-up.sh" --vm-a "$vm_a" --vm-b "$vm_b" --proxy-mode "$proxy_mode"
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

k3s_deploy_controller_daemonset() { # k3s_deploy_controller_daemonset <repo-root> [image] -- applies deploy/{rbac,daemonset}.yaml via the caller's kube(), waits for the rollout, and requires zero container restarts after a 10s settle; sets CONTROLLER_SELECTOR as a side effect, returns 1 on any failure. image, if given, overrides deploy/daemonset.yaml's hardcoded docker.io/valerauko/beep-lb:latest -- e.g. scripts/smoke-k3s-controller.sh pins the commit-under-test's :sha so this gate tests that build, not whatever :latest currently resolves to.
  local repo_root="$1" image="${2:-}"
  kube apply -f - < "$repo_root/deploy/rbac.yaml"
  controller_deploy_failed=0
  if [ -n "$image" ]; then
    sed "s#docker.io/valerauko/beep-lb:latest#${image}#" "$repo_root/deploy/daemonset.yaml" | kube apply -f -
    # If deploy/daemonset.yaml's hardcoded image line ever drifts from this
    # sed's match pattern, the sed silently no-ops and the rig deploys
    # whatever :latest resolves to -- recreating the exact stale-image
    # regression this image override exists to prevent. Read the deployed
    # DaemonSet's image back (same pattern as CONTROLLER_SELECTOR below)
    # and fail loud if it isn't the override we asked for. Fold into
    # controller_deploy_failed rather than returning early: an early return
    # here would skip the CONTROLLER_SELECTOR assignment below, and the
    # caller's FAIL branch (dump_evidence) reads that under `set -u`.
    deployed_image=$(kube -n kube-system get daemonset servicelb-controller \
      -o jsonpath='{.spec.template.spec.containers[0].image}')
    if [ "$deployed_image" != "$image" ]; then
      echo "FAIL: image override did not apply -- deployed image is '$deployed_image', expected '$image' (deploy/daemonset.yaml's hardcoded image line may have drifted from k3s_deploy_controller_daemonset's sed pattern)" >&2
      controller_deploy_failed=1
    fi
  else
    kube apply -f - < "$repo_root/deploy/daemonset.yaml"
  fi
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
  return "$controller_deploy_failed"
}

k3s_teardown_controller() { # k3s_teardown_controller <repo-root> <secret-name> -- deletes the controller DaemonSet/RBAC/kubeconfig Secret via the caller's kube(); `-f -` (stdin), not a host path -- kube() runs kubectl on a remote VM with no access to this process's own $REPO_ROOT
  local repo_root="$1" secret_name="$2"
  kube delete -f - --ignore-not-found < "$repo_root/deploy/daemonset.yaml" >/dev/null 2>&1 || true
  kube delete -f - --ignore-not-found < "$repo_root/deploy/rbac.yaml" >/dev/null 2>&1 || true
  kube delete secret "$secret_name" -n kube-system --ignore-not-found >/dev/null 2>&1 || true
}

k3s_dump_evidence() { # k3s_dump_evidence <vm-a> <vm-b> <pin-dir> -- on any FAIL path: bpftool dumps of LB_FRONT_MAP/TARGET_PORTS/POD_TARGETS/FLOW_TABLE, eth0/geneve0 link stats and dmesg tail on both nodes, then the controller pod's describe (Events, e.g. scheduling/OOM/image-pull) and current+previous logs via the caller's kube() and CONTROLLER_SELECTOR
  local vm_a="$1" vm_b="$2" pin_dir="$3"
  for vm in "$vm_a" "$vm_b"; do
    echo "---- $vm evidence ----"
    for m in LB_FRONT_MAP TARGET_PORTS POD_TARGETS FLOW_TABLE; do
      echo "== bpftool map dump: $m =="
      limactl shell "$vm" -- sudo bpftool map dump pinned "$pin_dir/$m" 2>&1 || true
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
