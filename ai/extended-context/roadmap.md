---
name: roadmap
description: Where beep stands against the operator's six-gate v1.0 plan as of 2026-10-09 -- gate table, critical path (real hardware), near-term bead sequence, settled decisions, release state, and firm principles. Read this first when picking up beep with no prior session context.
---

# Roadmap

As of 2026-10-09, beep has cleared gate 1 of the six-gate v1.0 plan, gate 2
(IPv6) is done except real-fleet validation, and the critical path is gate 3:
tests on real hardware, which only the operator can provision.

v1.0 = production-ready (operator, 2026-09-19). Order is fixed: functional
correctness first, then the perf/quality and security audits, then docs. Epic:
`beep-xfa`. Verify any status below with `bd show` / `git tag` before relying
on it; this file is a snapshot.

## Gates

| # | Gate | Status | What remains | Tracking |
| --- | --- | --- | --- | --- |
| 1 | Multi-interface | Shipped as multi-symmetric-uplink in v0.2.0 | Only deferred P4 items remain | `beep-eix` |
| 2 | Dual-stack IPv6, incl. IPv6-only nodes (no NAT64/DNS64) | Implemented; controller-driven dual-stack and IPv6-only-node round trips pass on the Lima k3s rig (#168) | IPv6-only validated cross-node on a real fleet, which depends on gate 3 | `beep-7qm` |
| 3 | Tests on actual VPS / real hardware | Not started; needs operator-provisioned nodes | Real-fleet round trip: genuinely external client IP, provider uRPF/NAT, MTU, IPv6-only, native-v6 registry pull, documented k3s+u7s real-hardware deploy | `beep-903` |
| 4 | Performance + code-quality audit | Started: `unsafe` audit done (#182); follow-ons filed | `beep-a32h`, `beep-l8xn`, `beep-noak`, `beep-9si3`; perf (measure-first) `beep-xfa.5`, `beep-7qm.15` | `beep-xfa` |
| 5 | Red-team security audit | Not started | No bead yet; file when gate 3 is underway | none |
| 6 | Documentation refinement | Not started | Last by design | none |

Also a v1.0 functional requirement: selective conntrack eviction on endpoint
removal (firm, operator 2026-09-19). Single-node eviction is smoke-proven
(`beep-03i`, batched in #179, reconcile retry in #183). OPEN P1: `beep-eto0` --
the ingress-side sweep misses remote backends, so flows to a departed remote
pod blackhole since pin-steering landed. Fix pending in PR #200 (not merged), with `beep-b6qw` (sweep on
pod-IP reuse, operator option C).

## Critical path

Gate 3 is operator-provisioned, so agents cannot advance it alone; gate 2's
real-fleet acceptance waits on it too. Until nodes exist, agent work is the
in-repo functional tail below, then gate 4.

## Near-term sequence

1. PR #200 (`beep-eto0`, `beep-b6qw`).
2. `beep-5lw` multi-endpoint selection, no longer parked. Landed: seeded flow
   hash (`.1`, #178) and ingress pin-steering + selection (`.2`, #195).
   Order: `.5` (in flight: owned front with 0 ready backends gets RST/ICMP)
   -> `.4` (target_port in a 24-byte forward Geneve option; pinned flow value
   36 -> 40 B) -> `.3` (node-local preference) -> `beep-vksr` (size
   `FRONT_ENDPOINTS`, re-derive the map-memory tripwire; blocks `.6`) ->
   `.6` controller emits all ready endpoints -> `.7` smoke -> `.8` docs.
3. Gate 4 items above.

Open for the operator: `mayor-xjy5o` (QUIC CID keying ADR, Proposed);
`beep-wtx5` (worker MCP tools; verify after a session restart).

## Settled decisions

- **Multi-endpoint (operator 2026-10-08/09):** node-local preference in v1,
  else hash over all ready endpoints; terminating endpoints excluded from new
  flows (pinned flows continue); owned front with 0 ready backends is rejected
  with RST/ICMP, a `FRONT_META` miss still passes to the host.
- **Flow-hash seed** is cluster-wide via a Secret, because external clients
  are untrusted (#190, #193).
- **Map-memory tripwire** is an interim 6 MiB (#199); `beep-vksr` re-derives
  it as low as justified.
- **Relay leg (`beep-eix`):** routing (FIB) selects egress; asymmetric return
  egress is not a goal; NATed or unreachable InternalIP between nodes is a
  cluster misconfiguration.
- **`beep-hl6`** (selective rp_filter) closed won't-do.
- **Loader:** `--pin-dir` is required; restart prunes stale rows (#198).

## Release state

Tags: `v0.1.0` (2026-09-14, single-backend delivery), `v0.2.0`
(multi-interface), `v0.3.0` (dual-stack inner services over an IPv4 Geneve
underlay; see `CHANGELOG.md`). Operator 2026-10-08: cutting a release is NOT
a priority; show progress against the gates first. Scheme and scope:
`docs/decisions/versioning.md`. The image is published to Docker Hub
(`docker.io/valerauko/beep-lb`); IPv6-native pull is unverified and tracked
under gate 3.

## Firm principles

- **Positive identification** (operator 2026-09-24): act only on packets
  positively identified as beep's own (front hit on ingress, `FLOW_TABLE` hit
  on return/egress); everything else passes untouched. Never drop on a map
  miss. Memory: `dataplane-positive-identification`.
- **IPv6-only nodes** (operator 2026-09-10): infra must work on IPv6-only
  nodes; never assume NAT64/DNS64. Applies to all infra decisions, including
  the registry pull path. Memory: `architectural-constraint-operator-2026-09-10-firm-beep`.
- **Front vs underlay addresses** are different sets and are never conflated
  (operator 2026-09-24); `NODE_ALLOW` and `Reverse.ingress_node_ip` are
  underlay concepts.
- **Dataplane fix gate** (operator 2026-10-08): every `ebpf/` bug fix needs a
  local `scripts/smoke.sh` A/B (pre-fix FAIL, post-fix PASS) on the assigned
  VM; CI evidence is not a substitute. Memory:
  `dataplane-fix-gate-operator-2026-10-08-firm`.
- **Terminology**: never "VIP"; say front address. Memory:
  `terminology-no-vip`.
