# deploy/

Manifest skeleton for the beep servicelb controller.

- `daemonset.yaml` points at `docker.io/valerauko/beep-lb:latest`, a
  dual-arch (linux/amd64 + linux/arm64) image built by the root
  `Dockerfile` and published by `.github/workflows/delivery.yaml`'s
  `image` job. `:latest` tracks the newest `v*` release tag (see
  `docs/decisions/versioning.md`); a push to `main` alone only publishes
  a `:<sha>` image. To run a specific version or commit, override the
  image with a local `kustomize` patch rather than editing this manifest.
- **RBAC is scoped to exactly what the design calls for:** list/watch/get on
  `Service`, `discovery.k8s.io/EndpointSlice`, and `Node` (the last needed to
  resolve an `EndpointSlice` endpoint's hosting-node IP). Nothing broader.

## Files

- `daemonset.yaml` — one controller pod per node (`hostNetwork: true`),
  `CAP_BPF` + `CAP_NET_ADMIN` only (no `privileged: true`, no CRI socket
  mount), tolerates all taints so it runs on every node including
  control-plane nodes, and mounts the host's bpffs (`/sys/fs/bpf`) so pinned
  programs/maps survive pod restarts. Requires `appArmorProfile: Unconfined`
  to pin to bpffs under containerd's default AppArmor profile — see
  `docs/decisions/servicelb-controller-apparmor-unconfined.md`.
- `rbac.yaml` — `ServiceAccount` + `ClusterRole` + `ClusterRoleBinding` for
  the above.

## Deployment model

Per `docs/design/ebpf-lb-dataplane.md`'s "Userspace control plane" section:
the controller runs per node (eBPF maps are local kernel memory, so a
central controller can't program them), loads and pins the tc-bpf programs
once, watches `Service`/`EndpointSlice`, writes maps on change, then idles —
the kernel does the packet forwarding.

Node self-prep is part of that same startup, not a separate step this
manifest or its operator needs to provide: the controller creates `geneve0`
(an address-less, external-mode Geneve device) if it doesn't already exist,
and disables the reverse-path filter on `all` and `geneve0`
(`net.ipv4.conf.{all,geneve0}.rp_filter=0`).

**rp_filter=0 is a deliberate, operator-decided tradeoff (2026-09-17), not
an oversight.** beep preserves the client's real source IP across the
Geneve tunnel — the entire point of this LB — so the decapped packet's
source address is the external client, never reachable back out an
address-less `geneve0`; the kernel's reverse-path filter drops it by
construction regardless of strict/loose mode. Cilium and Katran run the
same way, for the same reason; Calico only avoids it because it's a
routing-based LB with symmetric BGP returns, not an eBPF-redirect one. The
cost is real: this weakens anti-spoof protection node-wide (`all`), not
just on `geneve0`. REVISIT if that turns out to matter for your threat
model — the escape hatch is a routing-based/policy-routing decap
alternative that preserves symmetric RPF at a real datapath cost.

## Kubeconfig

`beep-kubeconfig` only parses an X.509 client-cert kubeconfig file (no
in-cluster ServiceAccount token support yet), so `--kubeconfig` points at a
Secret-mounted kubeconfig, not the ServiceAccount's own projected token.
Provisioning that Secret (`beep-controller-kubeconfig` in `kube-system`) is
left to the cluster operator/deploy tooling -- not this manifest.
