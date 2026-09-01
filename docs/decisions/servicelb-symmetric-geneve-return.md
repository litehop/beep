# ServiceLB return path is symmetric through the ingress node, not DSR

**Status:** Accepted
**Date:** 2026-09-01

## Context

Once a backend Pod on a different node answers a `LoadBalancer` VIP request
(`servicelb-ebpf-geneve-dataplane.md`), the reply needs a path back to the
external client. Two mechanisms exist: Direct Server Return (DSR), where
the backend node sources the reply directly as the VIP and saves the hop
back through the ingress node, or symmetric return through the ingress
node. DSR requires the backend node to source a packet as an address it
does not own.

## Decision

The backend node never sources a packet as the VIP. It Geneve-encaps the
Pod's raw reply back to the node that actually owns the VIP (the "ingress
node"), which decaps, un-DNATs (`PodIP:TargetPort → VIP:PORT`), and sends it
to the client sourced as an address it actually owns.

## Rationale

DSR's only benefit — skipping the return hop through the ingress node —
matters for throughput-heavy, download-style traffic; u7s runs no such
workload, so the benefit is worth nothing at this scale. In exchange, DSR
would have cost:

- **Source-spoofing / cloud anti-spoof (uRPF) risk**: the backend node would
  emit a packet sourced as an address it was never assigned, and
  Linode's/Scaleway's anti-spoof filtering behavior toward that could not be
  verified either way.
- **A NAT'd-node scheduling exclusion**: any node behind a NAT has its own
  router re-mangle a reply forged as the VIP before it reaches the
  internet, so DSR would have had to exclude such nodes from hosting any
  backend for an externally-facing Service.
- **A public-VIP requirement**: DSR implicitly needs the VIP reachable
  independent of which node answers for it, i.e. a provider-pinned public
  address.

Symmetric return deletes all three: no node ever sources a packet as an
address it doesn't own.

## Consequences

- Both the ingress node and the backend node hold per-flow state for the
  life of a connection, not just the ingress node.
- Every reply takes one extra Geneve hop (backend → ingress) versus DSR.
- The VIP can be any address the ingress node owns — a provider-pinned
  public IPv6 prefix, a LAN address on a colocated cluster, or a
  WireGuard/Tailscale mesh address — never required to be public.
- Revisit DSR only if a download-heavy, high-throughput workload appears
  **and** the provider in use allows cross-node egress source-forging;
  neither holds today.
