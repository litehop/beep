---
name: roadmap
description: Progress review of beep against the operator's six-gate v1.0 (production-ready) plan as of 2026-10-29 -- gates cleared, critical path, release state, settled decisions, firm principles. Read this first when picking up beep with no prior session context.
---

# Roadmap

As of 2026-10-29 (v0.6.0 is the latest release), beep's functional core is
built and verified on Lima rigs, but v1.0 is gated on tests on real
hardware, which only the operator can provision, followed by the performance
and security audits and documentation.

This is a progress review, not a tracker: detail lives in beads
(`bd show beep-xfa` is the v1.0 epic), `CHANGELOG.md` and
`docs/decisions/`. It is a snapshot; verify with `git tag` and `bd` before
relying on it.

## Where beep stands against v1.0

v1.0 = production-ready (operator, 2026-09-19). Order is fixed: functional
correctness first, then the performance/quality and security audits, then
documentation.

1. **Multi-interface: cleared.** Shipped as multi-symmetric-uplink in v0.2.0.
   Only deferred relay-leg and per-underlay Geneve extensions remain.
2. **Dual-stack IPv6, including IPv6-only nodes: implemented, not validated
   on a real fleet.** Dual-stack inner services shipped in v0.3.0 over an IPv4
   Geneve underlay and pass on the Lima k3s rig. IPv6-only validation across
   real nodes and an IPv6-native registry pull depend on gate 3; the epic
   (`beep-7qm`) stays a v1.0 blocker.
3. **Tests on real hardware: partially started, the critical path.** u7s GCP
   IPv4 runs exist, single subnet only; no Tier-2 criterion is met yet. Still
   needed: disjoint subnets/uRPF, external L4 client IP, WireGuard, dual-stack,
   MTU, IPv6-only nodes, native-v6 pull (`beep-903`). Plan:
   [real-cloud verification](../../docs/verification/real-cloud.md).
4. **Performance and code-quality audit: started.** The `unsafe` audit is
   done; perf work is measure-first.
5. **Red-team security audit: not started.** Begins once gate 3 is underway.
6. **Documentation refinement: not started.** Last by design.

Functional correctness is otherwise largely in place:

- Multi-endpoint load balancing: seeded flow hash, ingress pin-steering,
  node-local preference, `PreferSameNode`, `externalTrafficPolicy` handling
  and ClientIP session affinity (v0.5.0, v0.6.0).
- Selective conntrack eviction on endpoint removal (firm v1 requirement,
  operator 2026-09-19), idle `FLOW_TABLE` GC and closed-row TCP linger.
- Per-node Leases with lost-node ingress pruning, in-cluster ServiceAccount
  auth, and map-capacity sizing via the `beep-config` ConfigMap.

## Open strategic items

- **Real-hardware fleet** (gate 3): the only blocker agents cannot advance.
- **Operator-observability surface**: the controller's Event set, the metrics
  endpoint/port/auth, and honouring `sessionAffinityConfig.timeoutSeconds`
  are awaiting operator decisions.
- **Relay-leg rescope** (`beep-eix`): remaining multi-interface questions and
  per-underlay Geneve interfaces are deferred, low priority.
- **QUIC connection migration**: not a v1.0 blocker (operator 2026-10-13);
  4-tuple pass-through is acceptable for v1. See
  [`quic-cid-keying`](../../docs/decisions/quic-cid-keying.md) (Proposed).

## Release state

Tags: v0.1.0 (2026-09-14), v0.2.0 (2026-09-19), v0.3.0 (2026-09-21), v0.4.0
(2026-10-09), v0.5.0 (2026-10-15, multi-endpoint LB), v0.6.0 (2026-10-19,
deploy hardening, ClientIP affinity, `externalTrafficPolicy: Local`
fail-open to cluster-wide endpoints). Nothing is unreleased on `main` beyond
dependency bumps. Since the e2e rigs began deploying the commit under test,
releases are verified against the release-candidate image on every in-scope
rig (all must pass; a red rig blocks until explained); v0.6.0 was verified that
way, while v0.4.0 and v0.5.0 predate it and their e2e runs may have used a
stale image. Scheme
and scope: [`versioning`](../../docs/decisions/versioning.md). The image is
published to `docker.io/valerauko/beep-lb`; IPv6-native pull is unverified.

Support scope (operator, firm until 1.0): systemd-based Linux, kernel 6.6 or
newer, little-endian x86-64/AArch64, the latest two Kubernetes minors.
kube-proxy IPVS mode is unsupported (rigs exclude it). beep must be the
cluster's only L4 load balancer.

## Settled decisions

ADRs in `docs/decisions/`:

- [Geneve dataplane](../../docs/decisions/servicelb-ebpf-geneve-dataplane.md),
  [symmetric return](../../docs/decisions/servicelb-symmetric-geneve-return.md),
  [multi symmetric uplink](../../docs/decisions/servicelb-multi-symmetric-uplink.md)
- [Flow admission and affinity](../../docs/decisions/servicelb-flow-admission-affinity.md)
- [Geneve underlay trust model](../../docs/decisions/geneve-underlay-trust-model.md),
  [`NODE_ALLOW` startup blackout](../../docs/decisions/node-allow-startup-blackout.md)
- [rp_filter handling](../../docs/decisions/geneve-rp-filter-disable.md),
  [init container](../../docs/decisions/servicelb-rp-filter-init-container.md),
  [controller AppArmor](../../docs/decisions/servicelb-controller-apparmor-unconfined.md)
- [eBPF toolchain (aya)](../../docs/decisions/ebpf-toolchain-aya.md)

Operator decisions not in an ADR:

- Multi-endpoint: node-local preference, else hash over all ready endpoints;
  terminating endpoints are excluded from new flows (pinned flows continue).
  An owned front with no ready endpoint silently drops new flows; a front
  with no `FRONT_META` row passes to the host.
- The flow-hash seed is cluster-wide via a Secret because external clients
  are untrusted.
- Decap trusts the target port in the peer's forward Geneve option, so the
  underlay trust model is load-bearing: `NODE_ALLOW` source-IP admission is the
  boundary, assuming the underlay prevents IP spoofing; no decap port bound
  unless spoofing is observed.
- Routing (FIB) selects relay egress; asymmetric return egress is not a goal;
  a NATed or unreachable node InternalIP is a cluster misconfiguration.

## Firm principles

- **Positive identification** (2026-09-24): act only on packets positively
  identified as beep's own (front hit on ingress, `FLOW_TABLE` hit on
  return/egress); everything else passes untouched. Never drop on a map miss.
- **IPv6-only nodes** (2026-09-10): infra must work on IPv6-only nodes; never
  assume NAT64/DNS64, including the registry pull path.
- **Front vs underlay addresses** are different sets and never conflated;
  `NODE_ALLOW` and `Reverse.ingress_node_ip` are underlay concepts.
- **Dataplane fix gate** (2026-10-08): every `ebpf/` bug fix needs a local
  `scripts/smoke.sh` A/B (pre-fix FAIL, post-fix PASS) on the assigned VM; CI
  evidence is not a substitute.
- **Terminology**: say front address, never "VIP".
