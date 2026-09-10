# deploy/

Manifest skeleton for the beep servicelb controller.

- `daemonset.yaml` points at `docker.io/valerauko/beep-lb:latest`, a
  dual-arch (linux/amd64 + linux/arm64) image built by the root
  `Dockerfile` and published by `.github/workflows/ci.yaml`'s
  `controller-image` job on every push to `main`.
- **RBAC is scoped to exactly what the design calls for:** list/watch/get on
  `Service` and `discovery.k8s.io/EndpointSlice`. Nothing broader.

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

## Out of scope here

Container args/env that encode map names, pin-dir paths, or other
map-schema-dependent wiring are left for the controller-binary work — baking
them into this skeleton ahead of that would be guessing at a schema that
isn't settled yet.
