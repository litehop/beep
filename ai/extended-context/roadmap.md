---
name: roadmap
description: Where beep stands against the operator's six-gate v1.0 plan as of 2026-10-08 -- gate table, critical path (real hardware), near-term bead sequence, release state, and firm principles. Read this first when picking up beep with no prior session context.
---

# Roadmap

As of 2026-10-08, beep has cleared gate 1 of the six-gate v1.0 plan, gate 2
(IPv6) is code-complete except IPv6-only-node validation, and the critical
path is now gate 3: tests on real hardware, which only the operator can
provision.

v1.0 = production-ready (operator, 2026-09-19). Order is fixed: functional
correctness first, then the perf/quality and security audits, then docs. Epic:
`beep-xfa`. Verify any status below with `bd show` / `git tag` before relying
on it; this file is a snapshot.

## Gates

| # | Gate | Status | What remains | Tracking |
| --- | --- | --- | --- | --- |
| 1 | Multi-interface | Shipped as multi-symmetric-uplink in v0.2.0 (repeatable `--uplink-iface`, per-uplink `l2_hlen`, return via ingress uplink) | Egress-interface selection for the relay leg was deferred out of the MVP; `beep-eix` (open, P3) still owns it. | `beep-eix` |
| 2 | Dual-stack IPv6, incl. IPv6-only nodes (no NAT64/DNS64) | Dual-stack inner + underlay implemented; controller-driven dual-stack round trip proven on the Lima k3s rig; IPv6-only dataplane gaps (e.g. peer attestation, node identity) closed | Controller-driven IPv6-only-node round trip on the rig (`.18`); `7qm.19` fix merged (#155), full-rig PASS pending, blocked by `beep-nj6` (node-b SSH wedge; likely the pre-#156 egress drop, rerun on main in progress); acceptance also needs IPv6-only validated cross-node on a real fleet, which depends on gate 3 | `beep-7qm` |
| 3 | Tests on actual VPS / real hardware | Not started; needs operator-provisioned nodes | Real-fleet round trip: genuinely external client IP, provider uRPF/NAT, MTU, IPv6-only, native-v6 registry pull, documented k3s+u7s real-hardware deploy | `beep-903` |
| 4 | Performance + code-quality audit | Not started | Includes the `unsafe` reduction audit; perf follow-ons are queued below | `beep-uqn`, `beep-xfa.5`, `beep-7qm.15`, `beep-xvw` |
| 5 | Red-team security audit | Not started | No bead yet; file when gate 3 is underway | none |
| 6 | Documentation refinement | Not started | Last by design | none |

Also a v1.0 functional requirement: selective conntrack eviction on endpoint
removal (firm, operator 2026-09-19). Done: `beep-03i` closed (PR #134, #135),
smoke-proven on a live kernel.

## Critical path

Gate 3 (real hardware) is the critical path. It is operator-provisioned, so
agents cannot advance it alone. Gate 2's IPv6-only acceptance ("validated
cross-node on real fleet") also waits on it. Until nodes exist, agent work is
the in-repo functional tail below, then gate 4 prep.

## Near-term sequence

1. `beep-xfa.1` -- consolidate `LB_FRONT_MAP` + `TARGET_PORTS` into one
   `FRONTS` map `{backend_node_ip, pod_ip, target_port, flags(IS_LOCAL)}`.
   Approved by the operator 2026-10-08. It removes the relay self-loop by
   construction, keeps `POD_TARGETS` for the decap stale-pod check, keeps
   front and underlay address sets strictly separate, and renames legacy
   `vip_*` identifiers in the same change.
2. Loader/eBPF tail: `beep-0p2` (pinned-map `max_entries` mismatch after the
   xfa.4 cap change; overlaps `mayor-cutt9`), then `beep-7qm.18`/`.19` rig
   work, then the perf beads (`beep-xfa.5` measure-first, `beep-7qm.15`,
   `beep-xvw`).
3. `beep-5lw` -- multi-endpoint backend selection. Open, parked on a design
   fork (slot renumbering vs `BackendId`), sequenced after `beep-xfa.1`
   because the consolidation reshapes the same front-to-backend maps. Its
   prerequisite `beep-03i` is done.

Closed 2026-10-08 (PRs #154, #156, #157, #158): node address roles
(`beep-xfa.3`), egress pass-on-miss (`beep-xfa.2`, P1), node-identity for
local endpoints and hostNetwork admission (`beep-xfa.6`, `beep-7qm.17`, P1),
configurable `NODE_ALLOW`/`POD_TARGETS` caps (`beep-xfa.4`).

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
