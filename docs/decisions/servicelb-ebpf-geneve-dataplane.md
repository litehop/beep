# ServiceLB uses an eBPF Geneve per-node dataplane

**Status:** Accepted
**Date:** 2026-09-01

## Context

u7s's `type=LoadBalancer` Services need cross-node delivery: a client packet
can land on any node, must reach a backend Pod on a *different* node, and
that Pod must see the real client IP at L3. The fleet's nodes sit on
disjoint subnets (3 Scaleway IPv6-only, 1 Linode, 1 home-NAT, mesh-connected
via Tailscale) with no shared L2 and no BGP peer available.
`docs/design/cni-svclb-landscape-2026-08-25.md` surveyed the alternatives
against this constraint.

## Decision

A per-node eBPF pipeline IS u7s's ServiceLB dataplane, not a separate
component. tc-bpf/XDP programs on each node match `LoadBalancer` VIP
traffic, consistent-hash to a ready backend, and Geneve-encapsulate the
packet to whichever node holds it, over whatever underlay connects the two
nodes (Tailscale mesh today, plain routed L3, or none). This replaces the
klipper-lb-alike design (`bd show mayor-0gpqp`, closed as superseded);
mechanism detail lives in `docs/design/ebpf-lb-dataplane.md`.

## Rationale

The klipper-lb-alike (iptables DNAT, one DaemonSet per Service+protocol)
loses the real client IP on cross-node delivery: its unconditional
`POSTROUTING … MASQUERADE` rewrites the source address for traffic not
answered locally, and nothing about iptables DNAT carries the original
client address across nodes the way Geneve encap does. loxilb, a real eBPF
LB, is disqualified outright: on a real 1 CPU/1GiB Lima VM it crash-loops on
`ENOMEM` from `bpf_create_map_xattr`, never reaching a running state — it
needs 2GiB to start. MetalLB, kube-vip, and purelb all require either shared
L2 (ARP) or a BGP peer for VIP announcement — neither exists in a
WAN/Tailscale topology with disjoint subnets. OpenELB is CNCF-archived and
dead. No existing tool satisfies cross-node delivery, real client IP, and
disjoint subnets simultaneously; only an overlay-encap dataplane the cluster
controls end to end can.

## Consequences

- kube-proxy is retained unmodified for east-west traffic
  (`ClusterIP`/`NodePort`); this dataplane owns only north-south
  `LoadBalancer` external IP:port traffic.
- The control plane runs per node, not centrally: eBPF maps are local
  kernel memory with no remote-write API, so a single centralized
  controller cannot populate another node's maps.
- Return-path mechanism and toolchain are separate decisions: see
  `servicelb-symmetric-geneve-return.md` and `ebpf-toolchain-aya.md`.
