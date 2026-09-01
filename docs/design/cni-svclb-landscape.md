---
as_of: 2026-08-25
kind: initiative-state
---

# CNI + Service LoadBalancer landscape

Pre-decision research for a real target cluster: 5 nodes, 1GB RAM/1VCPU
each — 2 on Linode, 1 behind a home NAT router, 3 on Scaleway (IPv6-only,
no IPv4 at all), mesh-connected via Tailscale. Priorities: memory footprint
(hard ceiling), then correctness (cross-node routing, source-IP
preservation, IPv4-less egress), then NetworkPolicy depth (near-zero —
`kube-network-policies` already covers this per
`docs/decisions/network-policy-engine.md`, regardless of CNI choice).

## Recommendation

| Layer | Pick | Why |
|---|---|---|
| CNI | **Flannel**, bundled default | Lightest verified footprint (~50–80MB), no forced kube-proxy replacement. See `docs/decisions/flannel-for-cni.md`. |
| Egress (Scaleway IPv4-less nodes) | **Jool + CoreDNS `dns64`**, host-level on Linode only | Measured negligible footprint; pure static routing, no CNI cooperation needed. |
| Mesh | **Tailscale** (stays) | Beats surveyed alternatives on no-exposed-IP + low footprint + route-carrying simultaneously, at zero added infra. |
| Ingress/L7 | **Traefik** (stays) | ~45MiB observed in production; not replaced by any alternative. |
| Service LB | **eBPF Geneve dataplane** — see `docs/decisions/servicelb-ebpf-geneve-dataplane.md` | Supersedes the klipper-lb-alike originally recommended here (see Service LB below); this doc's disqualifications (loxilb, MetalLB, etc.) still hold. |

Rough per-node total (Flannel + Tailscale + `kube-network-policies` +
Traefik, before kubelet/CRI-O): **~155–375MB** on the Scaleway/home-NAT
nodes — an additive shape, not a verified end-to-end figure.

**Rejected**: Cilium as CNI (higher AND unpredictable footprint — real
production reports of step-growth to multi-GB and OOM-killing kubelet;
`cilium/cilium#37935`, `#37629`, `#44310`). kube-router (unresolved
multi-GB leak, `cloudnativelabs/kube-router#795`). Patu (single-node only).

## Provider IPv6 pools are statically routed, not BGP-gated

Both Linode and Scaleway statically route an IPv6 prefix to a single
instance — no customer BGP session needed for basic reachability. This
means an LB only needs to (a) bind/respond on the node it's already routed
to (an OS-level config problem, not an announcement protocol) and (b) get
the packet to the right pod without losing source IP — a materially lower
bar than MetalLB's L2/BGP modes, neither of which fit this topology (no
shared L2 across disjoint subnets, no BGP peer).

## CNI comparison

| Candidate | Memory | Cross-node routing fix |
|---|---|---|
| **Flannel** — recommended | ~50–80MB, no official floor | Fixed via KCM's `node-ipam-controller` (`--allocate-node-cidrs`, PR #1365) — verified live, distinct auto-allocated podCIDRs, cross-node reachability both directions. |
| Calico — second choice | ~120–220MB, no policy-disabled minimal mode | `calico-ipam`, independent of KCM. |
| Cilium — not recommended | ~180–450MB, unpredictable growth (see Rejected above) | Yes, but not worth the cost. |
| kube-router — disqualified | Real multi-GB leak, unfixed | No official fix path either. |
| Patu — disqualified | N/A | Single-node only, no cross-node routing at all. |

## Service LoadBalancer

**loxilb is disqualified.** On a real 1 CPU/1GiB Lima VM (kernel 6.17), it
crash-loops indefinitely — `bpf_create_map_xattr` `ENOMEM`, never reaching
a running state. Confirmed as a genuine memory floor (needs 2GiB minimum),
not an artifact: the identical image starts stably at 2GiB and 4GiB, only
1GiB fails. Source-IP preservation and no-BGP-required both checked out
live before the disqualification — irrelevant if the process can't start.

**klipper-lb (k3s's built-in ServiceLB)**: a shell script installing
iptables DNAT rules, no persistent proxy loop — **~92KB RSS per instance**,
confirmed live. Its one defect: an unconditional `POSTROUTING …
MASQUERADE` SNATs every packet regardless of `externalTrafficPolicy`,
losing the real client IP — confirmed to affect both TCP and UDP. This is
the mechanism that made a from-scratch eBPF dataplane necessary for
cross-node delivery with real client IP preserved
(`docs/decisions/servicelb-ebpf-geneve-dataplane.md`); klipper-lb's
"install rules once, then let the kernel do all subsequent work" shape is
still the memory-discipline model that dataplane's control plane follows.

**Not recommended, none clear this topology's bar**: MetalLB and kube-vip
(L2 mode needs shared L2/ARP, ruled out for disjoint subnets; BGP mode
needs a real peer). purelb (same limitation). OpenELB (CNCF-archived,
dead).

## NAT64/DNS64 gateway (Scaleway egress)

**Jool** (kernel NAT64, stateful) — recommended. Measured on a 1 CPU/1GiB
Lima VM: idle footprint unmeasurable above noise; 500 concurrent flows
still well under 1MB. Runs as a systemd service on the Linode gateway
node, not a per-node DaemonSet. **CoreDNS `dns64`** — recommended pairing,
~0MB delta measured, config-only change, RFC 6052 resolution correctness
confirmed live. Not recommended: TAYGA (needs a second NAT44 hop), 464XLAT
(solves a different problem — no private IPv4 to translate here).

## Mesh (Tailscale alternatives)

Constraint: IPv6-only Scaleway nodes, one home-NAT node that must not
expose its own public IPv4 — any replacement needs real NAT
traversal/relay. **Keep Tailscale** — beats alternatives on all three
criteria (no exposed IP, low footprint, route-carrying) simultaneously.
headscale (self-hosted control plane, identical client) is the move if
decoupling from Tailscale Inc. specifically is the goal. Nebula has a
lower claimed footprint (~27MB vendor-claimed) but a secondary
subnet-routing story and an open relay-fallback gap
(`slackhq/nebula#204`) — worth a trial only if footprint reduction is a
priority on its own. Not recommended: plain WireGuard (no signaling/relay,
breaks on symmetric NAT), Netmaker/netbird (1–2GB minimum, exceeds the
whole per-node budget), ZeroTier (not WireGuard-based).

## Open questions

- Kilo's actual footprint has never been measured (potential Tailscale +
  CNI overlay collapse into one component).
- Nebula/ZeroTier footprint figures are single-vendor-sourced on desktop
  hardware, not this cluster's actual nodes.
- Confirm the ISP's delegated IPv6 /64 stability for the home node before
  relying on static addressing there.

## References

`ai/findings/legacy/cni-svclb-landscape-2026-08-25.md` history (git) has
the full citation-by-citation research this digest summarizes — CVE/issue
links, exact benchmark sources, and the complete disqualification
evidence, recoverable by commit if ever needed verbatim.
