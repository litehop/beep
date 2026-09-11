# deploy/

Manifest skeleton for the beep servicelb controller.

- `daemonset.yaml` points at `docker.io/valerauko/beep-lb:latest`, a
  dual-arch (linux/amd64 + linux/arm64) image built by the root
  `Dockerfile` and published by `.github/workflows/delivery.yaml`'s
  `image` job on every push to `main`.
- **RBAC is scoped to exactly what the design calls for:** list/watch/get on
  `Service`, `discovery.k8s.io/EndpointSlice`, and `Node` (the last needed to
  resolve an `EndpointSlice` endpoint's hosting-node IP). Nothing broader.

## Files

- `daemonset.yaml` — one controller pod per node (`hostNetwork: true`),
  `CAP_BPF` + `CAP_NET_ADMIN` only (no `privileged: true`, no CRI socket
  mount), tolerates all taints so it runs on every node including
  control-plane nodes, and mounts the host's bpffs (`/sys/fs/bpf`) so pinned
  programs/maps survive pod restarts.
- `rbac.yaml` — `ServiceAccount` + `ClusterRole` + `ClusterRoleBinding` for
  the above.

## Deployment model

Per `docs/design/ebpf-lb-dataplane.md`'s "Userspace control plane" section:
the controller runs per node (eBPF maps are local kernel memory, so a
central controller can't program them), loads and pins the tc-bpf programs
once, watches `Service`/`EndpointSlice`, writes maps on change, then idles —
the kernel does the packet forwarding.

## Kubeconfig

`beep-kubeconfig` only parses an X.509 client-cert kubeconfig file (no
in-cluster ServiceAccount token support yet), so `--kubeconfig` points at a
Secret-mounted kubeconfig, not the ServiceAccount's own projected token.
Provisioning that Secret (`beep-controller-kubeconfig` in `kube-system`) is
left to the cluster operator/deploy tooling -- not this manifest.
