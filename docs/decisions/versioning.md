# Versioning: v0.x pre-1.0 semver, and what v0.1.0 covers

**Status:** Accepted
**Date:** 2026-09-14

## Context

beep is pre-alpha: it is still proving basic ServiceLB delivery, and no
external consumer depends on a stable contract yet. Before cutting a first
tag, the project needs a semver policy matching its break-freely stance,
and a statement of what v0.1.0 promises — single-backend-per-Service
selection (deferred from `mayor-9gr0n`), ratified by the operator on
2026-09-14.

## Decision

Standard semver, pre-1.0 convention: `0.MINOR.PATCH`. Any `0.x` bump may
break map layouts, CLI flags, or CRD shape without a deprecation period —
PATCH is for fixes with no such break, everything else bumps MINOR. `1.0.0`
is reserved for a contract the project is willing to hold stable.

**v0.1.0 covers:** single-backend-per-Service north-south `type=LoadBalancer`
delivery (multi-endpoint, `beep-5lw`, is explicitly deferred); single-node
AND cross-node delivery, proven on the k3s-on-Lima VM rig
(`scripts/e2e-lb-k3s.sh`'s 7-spec focus list: 6/7 pass or are explained
non-bugs); real client-IP preservation, code-verified in
`ebpf/src/main.rs` (the forward DNAT rewrites only the destination IP/port,
never the client's source IP); controller memory footprint
CI-gated; and a Docker Hub image, `docker.io/valerauko/beep-lb`, natively
pullable over IPv6.

**Explicitly deferred**, none blocking v0.1.0: multi-endpoint LB
(`beep-5lw`); real-fleet/production-network fidelity (`beep-903`); the
eventual repo split for an independent release cadence (`mayor-aie31.4`).

**Cut procedure**: push git tag `v0.1.0` → `delivery.yaml` publishes
`docker.io/valerauko/beep-lb:v0.1.0` (plus `:latest`, if it's the highest
`v*` tag) and auto-creates the GitHub release.

**`deploy/daemonset.yaml` stays on `:latest`**: a release-tag pin is
temporally impossible — the pin commit lands after the immutable tag, so
the tagged commit never carries its own pin. `:latest` now equals the
newest release; override to a version or sha via a local kustomize patch
(`deploy/README.md`).

## Rationale

u7s — the monorepo beep was extracted from — corroborates break-freely 0.x
from outside: its own tags never include a plain, un-suffixed
`v0.1.0`/`v0.2.0` GA release, only `-alpha`/`-snapshot` pre-releases
(`v0.2.0-alpha.1` since 2026-08-23) — early 0.x breaks continuously even
at u7s's scale.

Adopted from u7s's `release-tarball.yaml`: its `push: tags: ['v*']` trigger,
its "partial upload is worse than slow" concurrency comment, and its
single-workflow `gh release create`. Not adopted: tarball + `install.sh`
distribution (beep ships a container image); prerelease-suffix detection
(no snapshot/rc cadence yet).

## Consequences

- No v0.x tag is a compatibility promise; u7s must expect breaking changes
  between MINOR versions until 1.0.
- A future ADR narrowing this scope (e.g. ratifying multi-endpoint as a
  version requirement) supersedes this one's coverage list, not its
  semver scheme.
