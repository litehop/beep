# kube-proxy / flannel coexistence

**Verdict:** beep coexists with kube-proxy in **iptables or nftables
mode**. **IPVS mode is unsupported.**

This is the durable home for the coexistence contract; the design and
decision docs below only sketch it in passing. Audience: operators
deploying beep onto an existing cluster, and agents verifying the claim.

## Why iptables/nftables coexistence works

Verified live on a k3s cluster running real kube-proxy and flannel
(2026-09-14, iptables mode). beep's tc-bpf classifiers on the uplink NIC
and kube-proxy's netfilter chains run on disjoint kernel subsystems, in a
fixed order: tc runs before netfilter on ingress, so beep's classifier
sees a packet first. `ClusterIP`/`NodePort` (east-west) traffic is never
written to beep's VIP map, so it never matches in beep's classifier and
falls through to kube-proxy's chains untouched — beep owns only
north-south `LoadBalancer` VIP:port traffic. There is no double-processing
between the two (`docs/decisions/servicelb-ebpf-geneve-dataplane.md:46`).
`geneve0` (Geneve/UDP 6081, beep's tunnel device) and `flannel.1`
(VXLAN/UDP 8472, flannel's) are separate devices with no shared routes —
beep's Geneve tunnel never touches flannel's vxlan device (`flannel.1`).
The one intended contact point: a backend node's decap hands its DNAT'd
packet to flannel's pod-CIDR routing for the last hop
(`docs/decisions/servicelb-ebpf-geneve-dataplane.md:50-53`,
`docs/design/ebpf-lb-dataplane.md:63`).

## Why IPVS mode is unsupported

**Not** the originally hypothesized failure: kube-proxy's IPVS reconciler
binds every Service VIP to the `kube-ipvs0` dummy device as a local
address, and a naive kube-ipvs0-hijack theory says a node's own VIP gets
REJECTed at that dummy device before beep ever sees it. That's refuted —
`kube-ipvs0` skips binding an IP equal to the node's own real interface
address, so a node's own VIP is never hijacked locally, and beep's
tc-ingress classifier fronts that traffic regardless of proxy mode.

The actual failure is different and comes from how beep publishes VIP
ownership. beep's controller writes every DaemonSet node's own physical IP
into the LoadBalancer Service's `status.loadBalancer.ingress[]`
(`controller/src/status.rs:75`, `ensure_node_ingress`) — one entry per
node, because beep runs as a DaemonSet and each node fronts the VIP
locally. Under IPVS mode, kube-proxy's reconciler treats every address in
that list as a Service VIP to bind onto its own `kube-ipvs0`, including
the *other* nodes' addresses it now sees via that shared status field. The
result is a reciprocal duplicate-IP conflict: each node ends up binding
every other node's real IP as a local NOARP address on a flat L2 network,
which breaks node-to-node connectivity — reproduced consistently in live
IPVS-mode testing, with node-to-node connectivity breaking and, on some
runs, a node becoming unresponsive. The iptables baseline passed both
before and after this testing; only IPVS mode exhibits the conflict.

## Deployment requirements

- kube-proxy MUST run in **iptables or nftables** mode. Do not deploy
  beep onto a cluster with `--proxy-mode ipvs` set.
- beep MUST run as a **DaemonSet on every node** (`deploy/daemonset.yaml`)
  so each node's tc-ingress intercepts its own VIP traffic locally. This
  is also *why* IPVS breaks: every node ends up publishing its own address
  into the same shared ingress list.
- The LB VIP / front-IP range MUST be disjoint from the **pod CIDR** — a
  hostNetwork Pod's IP equals its node's IP (front-IP space), so a VIP
  inside the pod CIDR can byte-collide a forward and reverse flow key.
  This is **enforced at startup by the standalone `beep` loader's
  `--fixture` path**: `vip_outside_pod_cidr` (`src/main.rs:195`) rejects a
  `--pod-cidr` that contains any configured VIP. The shipped
  `beep-controller` DaemonSet binary does not call this guard — its VIP is
  always the node's own physical address, disjoint from the pod CIDR by
  construction, so the check doesn't apply there.
- The VIP range MUST also be disjoint from the **Service CIDR**
  (ClusterIP range), or beep's classifier can shadow a ClusterIP Service's
  east-west traffic instead of falling through to kube-proxy. Same scope
  as above: the standalone loader enforces this when `--service-cidr` is
  given (`vip_outside_service_cidr`, `src/main.rs`); it's optional and, like
  `--pod-cidr`, not called by `beep-controller`.

## Verifying this (agent-facing)

**Supported (iptables) path** — the green controller-driven round trip:

```bash
scripts/k3s-up.sh --proxy-mode iptables   # default; flag can be omitted
scripts/smoke-k3s-controller.sh
```

`k3s-up.sh --proxy-mode` (default `iptables`) passes
`--kube-proxy-arg=proxy-mode=<mode>` to the k3s server and agent install. A
green run shows `smoke-k3s-controller.sh`'s full sequence passing: cluster
bring-up, the controller loading and pinning its eBPF programs, VIP map
programming from watch events, and a genuine cross-node client round trip.

**Unsupported (IPVS) observation** — `smoke-k3s-controller.sh` forwards
`--proxy-mode` to `k3s-up.sh`, so the single-command form below drives the
cluster in IPVS mode without a silent reset back to iptables:

```bash
scripts/smoke-k3s-controller.sh --proxy-mode ipvs
```

With the controller/DaemonSet running against this cluster, the
incompatibility is visible without a separate round-trip assertion: the
controller publishes every node's own IP into
`status.loadBalancer.ingress[]`, each node's kube-proxy binds the *other*
nodes' IPs onto its local `kube-ipvs0`, and node-to-node connectivity
breaks as a result — the control-plane tunnel between nodes resets, and a
node can become unresponsive. That breakage is the incompatibility itself,
not a rig bug, and it is why no clean LB round trip can be observed under
IPVS mode.

## Verifying this (human-facing)

Before deploying beep onto an existing cluster:

1. Check the running kube-proxy mode:
   ```bash
   kubectl -n kube-system get configmap kube-proxy -o yaml | grep mode
   ```
   or inspect the `kube-proxy` process's `--proxy-mode` flag directly on a
   node. If it reports `ipvs`, do not deploy beep until the cluster is
   reconfigured to `iptables` or `nftables`.
2. Confirm the LB VIP range does not overlap the cluster's pod CIDR (beep
   will refuse to start otherwise) or its Service CIDR (checked manually
   today — `kubectl cluster-info dump | grep -i cidr` or the CNI/cluster
   config).
3. Deploy `deploy/daemonset.yaml` on every node, not a subset — a partial
   rollout leaves nodes without local VIP interception.
