---
name: roadmap
description: Settled facts and near-term trajectory for beep's ServiceLB dataplane as of 2026-09-14 -- current state, the testable-by-u7s bar, and open versioning decisions. Read this first when picking up beep with no prior session context.
---

# Roadmap

## Current state (2026-09-14)

The ServiceLB epic (`mayor-aie31`) is functionally complete: all 7 phase
beads (`mayor-g6u8s` through `mayor-g9l0f`) are closed, including Phase 7's
conformance harness. The epic bead itself stays OPEN -- it still owns a tail
of P2-P4 follow-on beads (`mayor-aie31.19` DWARF strip, `mayor-aie31.21`
affinity+eviction, `mayor-aie31.22` metrics, `mayor-aie31.4` eventual repo
split), not because the dataplane is unproven.

e2e status on the k3s-on-Lima rig (`beep-lbs`, `scripts/e2e-lb-k3s.sh`'s
7-spec upstream LoadBalancer focus list): 6 of 7 specs PASS or are explained
as non-bugs. Cross-node LB delivery is PROVEN -- upstream specs 3/4 (the
>=2-node "target nodes with endpoints" specs) PASS via Geneve, and both UDP
flow-affinity specs PASS. Specs 2/5 (the ETP:Local "should work from pods"
family) were fixed by `beep-bol` (beep-client was missing a standalone
`kubectl` binary -- a harness gap, not a dataplane bug). Spec 1 ("should
work for type=LoadBalancer") still reports FAIL, but only because Lima's
flat /24 defeats the upstream heuristic that infers masquerading from the
client's subnet -- beep's own logs show the real client IP delivered. This
is confirmed in `ebpf/src/main.rs`: the forward leg's DNAT rewrites only the
destination IP/port (VIP -> pod:targetPort) and, when a source-port
collision forces a remap, the source port -- it never touches the client's
source IP. Genuinely-external client-IP verification is deferred to
`beep-903`, which needs operator-provisioned real cloud nodes.

Controller footprint is measured, not estimated: `beep-toi` (PR #57) put
idle/loaded RSS at ~6.8-7.7 MiB and gates it in CI's memory-smoke job.
`beep-eyz`'s dhat profile (PR #63) attributes that baseline to aya's BTF
parse at load time, not to rustls/aws-lc-rs or trimmable heap -- idle
retained Rust heap is only ~128 KiB, but BTF parsing produces a TRANSIENT
~17-31 MiB peak that any DaemonSet memory limit must clear (`beep-39n`, in
flight on a separate worktree at time of writing).

Delivery: the image is published to `docker.io/valerauko/beep-lb` (`:latest`
+ `:sha` tags via `.github/workflows/delivery.yaml`, decided in `beep-vk5`)
-- Docker Hub is natively pullable over IPv6, resolving the project's
IPv6-only-registry constraint. `deploy/daemonset.yaml` pulls `:latest`.

## Near-term goal -- "testable by u7s"

Two bars gate beep being usable from the u7s monorepo it was extracted from,
and both are essentially MET:

- **Consumable**: an image u7s can pull. Met -- Docker Hub, IPv6-reachable.
- **Functional**: real LoadBalancer delivery, single-node AND cross-node,
  with the real client IP preserved. Met -- proven on the k3s-on-Lima rig
  per the e2e status above.

u7s tests beep by standing up the same kind of local VM rig beep itself
uses (Lima + k3s), not a real cloud fleet. So the remaining requirement is
that VM rig plus documentation good enough for a human AND an agent to
reproduce the test -- not production-fleet sign-off. Treat `beep-903`
(genuinely-external client IP against a real provider's uRPF/NAT/IPv6) as
DEFERRED production-hardening, off this path -- it does not block u7s
integration.

`beep-n24` (the 2-node WireGuard smoke rig's martian-source drop) is a
test-rig co-location artifact -- that rig's "client" shares an address with
the backend node's own `lo` -- not a cross-node functional gap, and should
not be treated as a v0.x blocker.

## Near-term work items

- `beep-hmj` -- bidirectional cross-node e2e: assert delivery + real client
  IP in both directions (Service on node-A dialed via node-B, and the
  reverse), to catch a return-path asymmetry a one-directional proof can't.
- `beep-39n` -- DaemonSet memory request/limit sized to clear the measured
  ~31 MiB BTF-parse peak, plus control-plane tolerations, so beep schedules
  on resource-starved and control-plane nodes.
- A u7s-facing "how to test beep on a VM rig" doc for humans and agents.
  **Gap, not covered**: `ai/extended-context/vm-operations.md` documents the
  Lima pool and the single-node dataplane smoke path (`scripts/smoke.sh`)
  well, but says nothing about the k3s-controller e2e rig
  (`scripts/k3s-up.sh`, `scripts/e2e-lb-k3s.sh`,
  `scripts/smoke-k3s-controller.sh`) that the e2e status above actually
  exercises -- that path's only documentation today is the scripts' own
  header comments. Extending `vm-operations.md` (or a sibling doc) to cover
  the k3s rig is unclaimed work.

## Versioning trajectory

Cut **v0.1.0** once the u7s-testable bar and the docs gap above are closed.
Mechanics, once decided: add semver image tags in
`.github/workflows/delivery.yaml` (today it only pushes `:latest`/`:sha`),
pin `deploy/daemonset.yaml` to `:v0.1.0` instead of `:latest`, and git-tag
the release. The eventual repo split (`mayor-aie31.4`) for an independent
release cadence is out of scope for v0.1.0.

## Open (operator to ratify)

- **Does v0.1.0 require multi-endpoint LB (`beep-5lw`), or is
  single-backend-per-Service sufficient for u7s's first integration?** The
  controller ships single-endpoint today by design (deferred from
  `mayor-9gr0n`); `beep-5lw` is the open feature bead for real N-endpoint
  selection. No versioning ADR exists yet -- write one once this is
  ratified, since it determines what v0.1.0 actually promises.
