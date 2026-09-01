# ServiceLB uses an eBPF Geneve per-node dataplane

**Status:** Accepted
**Date:** 2026-09-01

## Context

u7s's `type=LoadBalancer` Services must work across a range of underlay
scenarios: nodes on disjoint subnets reachable only through a
WireGuard/Tailscale mesh, with one node behind NAT (the operator's own
multi-cloud fleet is one instance of this); and, at the other extreme,
every node colocated on one L2 with no encapsulated underlay at all. In
every scenario, a client packet can land on any node, must reach a backend
Pod on a *different* node, and that Pod must see the real client IP at L3,
without assuming a shared L2 or a BGP peer is available.
`ai/extended-context/cni-svclb-landscape.md` surveyed the alternatives
against this constraint.

## Decision

A per-node eBPF pipeline IS u7s's ServiceLB dataplane, not a separate
component. tc-bpf programs on each node match `LoadBalancer` VIP traffic,
consistent-hash to a ready backend, and Geneve-encapsulate the packet to
whichever node holds it, over whatever underlay connects the two nodes.
This replaces the klipper-lb-alike design (`bd show mayor-0gpqp`, closed as
superseded); mechanism detail lives in
`ai/extended-context/ebpf-lb-dataplane.md`.

## Rationale

The klipper-lb-alike (iptables DNAT, one DaemonSet per Service+protocol)
loses the real client IP on cross-node delivery: its unconditional
`POSTROUTING … MASQUERADE` rewrites the source address for traffic not
answered locally, and nothing about iptables DNAT carries the original
client address across nodes. loxilb, a real eBPF
LB, is disqualified outright: on a real 1 CPU/1GiB Lima VM it crash-loops on
`ENOMEM` from `bpf_create_map_xattr`, never reaching a running state — it
needs 2GiB to start. MetalLB, kube-vip, and purelb all require either shared
L2 (ARP) or a BGP peer for VIP announcement — neither exists in a
disjoint-subnet topology with a NAT'd node in the path. OpenELB is
CNCF-archived and dead.

## Consequences

- kube-proxy is retained unmodified for east-west traffic
  (`ClusterIP`/`NodePort`); this dataplane owns only north-south
  `LoadBalancer` external IP:port traffic, so there is no double-processing
  between the two.
- No flannel address-space collision: the VIP sits outside flannel's
  pod-CIDR and Service-CIDR, and the Geneve tunnel never touches flannel's
  vxlan device. The one contact point: backend-node decap hands its DNAT'd
  packet to flannel's pod-CIDR routing for the last hop.
- The control plane runs per node, not centrally: eBPF maps are local
  kernel memory with no remote-write API, so a single centralized
  controller cannot populate another node's maps.
- Return-path mechanism and toolchain are separate decisions: see
  `servicelb-symmetric-geneve-return.md` and `ebpf-toolchain-aya.md`.
