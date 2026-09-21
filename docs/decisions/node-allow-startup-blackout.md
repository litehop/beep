# NODE_ALLOW population is gated on `fronts_known`, widening the cold-start blackout

**Status:** Accepted
**Date:** 2026-09-18

## Context

`NODE_ALLOW` (PR #98, beep-bwh) is the outer-Geneve peer-attestation
allowlist that compensates for `rp_filter=0`
(`docs/decisions/geneve-rp-filter-disable.md`): it validates a decapped
packet's tunnel-source IP against the set of known peer nodes. Its
controller-side apply path (`controller/src/apply.rs`,
`controller/src/reconcile.rs`) sits alongside `VIP_MAP`/`TARGET_PORTS`
(gated on `fronts_known`, the Node LIST watch's initial-sync completion)
and `POD_TARGETS` (gated on the narrower `pod_targets_known`, this node's
own entry resolved). A reviewer on #98
(pullrequestreview-5244211971) asked which signal should gate
`NODE_ALLOW`.

## Decision

`NODE_ALLOW`'s destructive full-sync is gated on `fronts_known`, not
`pod_targets_known`.

## Rationale

`NODE_ALLOW`'s desired content is the whole known-peer-node set — it is
`VIP_MAP`/`TARGET_PORTS`-shaped (cluster-wide), not `POD_TARGETS`-shaped
(this node's own entry). Gating a destructive full-sync on
`pod_targets_known` would let a controller restart apply a partially
caught-up Node LIST as the new full `NODE_ALLOW` state, wiping
already-pinned peer entries mid-list — the exact restart-wipe bug
`fronts_known` exists to prevent for `VIP_MAP`/`TARGET_PORTS`. The
narrower signal answers "do I know my own node yet?"; `NODE_ALLOW` needs
"do I know every node yet?", which only `fronts_known` answers. Restart-
wipe safety (a correctness risk: wrongly evicting a legitimate peer) is
judged to outweigh a bounded cold-start availability window (an
availability tradeoff) — a judgment call, not a measured one.

## Consequences

- Both the forward and return Geneve legs are blacked out for longer on
  controller cold-start or node-join than pre-#98 behavior, until the
  full Node LIST sync completes — a real, deliberately accepted cost.
- **Open follow-on (beep-ur2):** narrow this by making `apply_node_allow`
  additive-only (upsert, never delete) until `fronts_known` first
  becomes true, then switching to the current destructive full-sync.
  Not decided here; needs its own design/test pass.
- **Open question (beep-ztb):** whether `NODE_ALLOW` is load-bearing or
  defense-in-depth depends on the deployment underlay's isolation and is
  unresolved; this ADR does not depend on that answer.
