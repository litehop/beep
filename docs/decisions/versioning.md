# Versioning: v0.x pre-1.0 semver, and what v0.1.0 covers

**Status:** Accepted
**Date:** 2026-09-14

## Context

beep is pre-alpha: it is still proving basic ServiceLB delivery, and no
external consumer depends on a stable contract yet. The near-term goal is a
u7s-pullable image good enough for that monorepo's own integration testing,
not a production-fleet guarantee. Before cutting a first tag, the project
needs a semver policy that matches its break-freely stance, and an explicit
statement of what v0.1.0 promises — single-backend-per-Service selection
(deferred from `mayor-9gr0n`) was an open question until the operator
ratified it on 2026-09-14.

## Decision

Standard semver, pre-1.0 convention: `0.MINOR.PATCH`. Any `0.x` bump may
break map layouts, CLI flags, or CRD shape without a deprecation period —
PATCH is for fixes with no such break, everything else bumps MINOR. `1.0.0`
is reserved for a contract the project is willing to hold stable; nothing in
the v0.x line implies that yet.

**v0.1.0 covers:**

- Single-backend-per-Service north-south `type=LoadBalancer` delivery.
  Multi-endpoint selection (`beep-5lw`) is explicitly deferred, not a
  v0.1.0 blocker.
- Single-node AND cross-node delivery, proven on the k3s-on-Lima VM rig
  (`scripts/e2e-lb-k3s.sh`'s 7-spec focus list: 6/7 pass or are explained
  non-bugs; the one FAIL is a Lima-subnet harness artifact, not a
  dataplane bug).
- Real client-IP preservation, code-verified in `ebpf/src/main.rs`: the
  forward leg's DNAT rewrites only the destination IP/port (and, on a
  source-port collision, the source port) — never the client's source IP.
- Controller memory footprint CI-gated (`ci.yaml`'s memory-smoke job).
- A Docker Hub image, `docker.io/valerauko/beep-lb`, natively pullable
  over IPv6.

**Explicitly deferred**, none blocking v0.1.0: multi-endpoint LB
(`beep-5lw`); real-fleet/production-network fidelity — genuinely-external
client IP against a real provider's uRPF/NAT/IPv6 (`beep-903`); the
eventual repo split for an independent release cadence (`mayor-aie31.4`).

## Cut procedure (operator step, not performed by this ADR)

1. Push git tag `v0.1.0`.
2. `.github/workflows/delivery.yaml`'s tag trigger builds and publishes
   `docker.io/valerauko/beep-lb:v0.1.0`.
3. Pin `deploy/daemonset.yaml`'s image tag to `:v0.1.0` (was `:latest`).
4. Create the GitHub release from the tag.

## Consequences

- No v0.x tag is a compatibility promise; downstream consumers (u7s) must
  expect breaking changes between MINOR versions until 1.0.
- A future ADR narrowing this scope (e.g. ratifying multi-endpoint as a
  version requirement) supersedes this one's coverage list, not its
  semver scheme.
