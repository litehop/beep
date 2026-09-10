# deploy/

Manifest skeleton for the beep servicelb controller. This is deployment
scaffolding only, not a runnable deployment yet:

- **No controller binary exists.** `daemonset.yaml` points at
  `PLACEHOLDER_IMAGE`; the controller's Service/EndpointSlice watch-and-
  program logic is a separate, gated piece of work.
- **The image registry is undecided.** GHCR is ruled out (IPv4-only pulls).
  Docker Hub is a candidate pending an IPv6-pull verification. Self-hosting
  or a NAT64/DNS64 gateway are the fallbacks. Swap `PLACEHOLDER_IMAGE` for a
  real reference once that lands.
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
