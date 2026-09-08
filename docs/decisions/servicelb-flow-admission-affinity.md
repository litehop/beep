# ServiceLB flow table: two-tier admission control, stored-identity affinity

**Status:** Accepted
**Date:** 2026-09-06

## Context

`uplink_ingress` inserted into a single `FWD_FLOW` LRU map on any packet
matching a Service front, with no validation — an off-path flood of
~8192 spoofed packets evicts every established flow's forward entry in
milliseconds (`bd show mayor-aie31.11`). Separately, the forward path
re-resolved the backend set on every packet with no per-flow pin, so a
backend-set change mid-connection could move an in-flight flow to a
backend holding no state for it (`bd show mayor-aie31.21`).

## Decision

**Admission**: split `FWD_FLOW` into two LRU tiers. `FWD_PENDING`
(default 2048 entries) is the only flood-exposed tier — every new flow
lands here first. `FWD_MAIN` (default 8192 TCP/UDP, 4096 QUIC) holds
established flows, populated only by **promotion on observed
bidirectionality**: the first return packet for a pending flow promotes
it into `FWD_MAIN`. Protocol-agnostic — no QUIC DCID-MAC gate for the
MVP, matching `mayor-g3lag`'s pass-through keying. **Map sizes are
configurable by the userspace DaemonSet at load time, never hard-coded
consts.**

**Affinity**: `FWD_FLOW`'s value stores the full backend identity
(`backend_node_ip` **and** `pod_ip`), chosen once on a flow's first
packet by a deterministic hash over the ready set. Later packets follow
the stored pin. Eviction is scoped and event-driven, firing only when
the userspace controller sees an endpoint stop serving: `FWD_FLOW`
deletion is mandatory for UDP (no teardown signal); `REV_FLOW` deletes
for both protocols.

## Rationale

A spoofed flood only ever touches `FWD_PENDING`; `FWD_MAIN` is
unreachable without a real round trip through a live backend — the same
assured/unreplied split `nf_conntrack`'s `early_drop` uses. Fixed
map-size consts would force a rebuild to retune; the DaemonSet already
owns map population at load time, so sizing is a deployment concern.
Stored affinity is strict: a backend-set change disturbs only flows
pinned to a departed endpoint — at u7s's small, often single-digit
endpoint counts, per-packet re-hashing's disruption fraction is too
large to accept.

## Consequences

- `FWD_FLOW`'s value widens from a bare node IP to the full backend
  identity, carried by both tiers.
- The delivery (backend) node must independently validate the stamped
  `pod_ip` against its own local serving-set (`bd show mayor-tavxy`) —
  a lagging ingress node's stale pin is bounded only if the backend
  node rejects it.
- TCP eviction on endpoint removal is left open (`bd show mayor-dksf5`):
  without it, a pinned flow hangs until the client's retransmit timeout
  rather than getting a prompt RST.
