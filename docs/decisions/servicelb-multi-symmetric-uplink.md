# beep admits client traffic on multiple symmetric uplinks, not one

**Status:** Accepted
**Date:** 2026-09-19

## Context

`--uplink-iface` today is single-valued: one ifindex and one L2 header
length (`uplink_l2_hlen`) live as scalar fields in `Config`, written once
at load and read by every uplink hook via the single-entry `CONFIG` array.
A real node needs more than one INGRESS uplink at once — e.g. `eth0`
(public, Ethernet-framed, `l2_hlen=14`) and `wg0` (WireGuard, L3-only,
`l2_hlen=0`) admitting client traffic simultaneously. The two values
cannot share one `Config` scalar (`mayor-f3ru5` already proved
`wg0`'s L3-only framing needs its own `l2_hlen`, for the single-uplink
case). This ADR widens that from one uplink to N.

## Decision

`--uplink-iface` becomes repeatable; N=1 is the unchanged, unremarkable
subset. `Config`'s `uplink_ifindex`/`uplink_l2_hlen` scalars are removed;
`CONFIG` (a 1-entry array) keeps only `geneve_ifindex`, staying
single-valued — multi-relay/egress is deferred separately. A new map,
keyed by ifindex and holding `l2_hlen`, gets one entry per configured
uplink at load.

The ingress hook looks up that map by the packet's own ingress ifindex: a
hit is simultaneously admission (this ifindex is a configured uplink) and
resolves the `l2_hlen` to parse with; a miss means an unconfigured
interface and is passed through as today. `FLOW_TABLE`'s forward-tagged
entry gains an `ingress_ifindex` field, stamped from the packet's own
ingress ifindex at admission time (free — no extra lookup). The decap-return
path's `bpf_redirect` target changes from the old `CONFIG.get(0)`
singular read to that stored `ingress_ifindex`: the reply always egresses
the SAME physical uplink the client's packet arrived on. No asymmetric
egress-uplink selection exists or is added.

## Rationale

A raw-ifindex-indexed array would need sizing to the largest ifindex the
host could assign — unbounded and sparse for a handful of configured
uplinks. A map bounded to N configured uplinks matches the sizing
discipline every other admission table in this codebase already uses
(`FLOW_TABLE`, `POD_TARGETS`, `NODE_ALLOW`), at a hash cost negligible next
to those. Symmetric return needs no new selection logic — the ingress
ifindex the flow was admitted on is already free data on that packet;
storing it removes the dataplane's last singular `CONFIG.get(0)` uplink
read.

## Consequences

- The attach loop must run per configured uplink (N tc-bpf hook sets, not
  one) — implementation, tracked by beep-eix's children.
- Deferred, explicitly out of scope: asymmetric relay/egress-interface
  selection (a separate outbound-leg decision); `NODE_ALLOW` multi-IP /
  multi-homed peer admission (beep-5ng); IPv6/dual-stack (beep-7qm) — this
  ADR's ifindex-keyed map is IPv4-only.
