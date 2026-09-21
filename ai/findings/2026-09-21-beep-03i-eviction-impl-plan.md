---
Bead: beep-03i
---

# Eviction implementation plan (beep-03i)

Bead: beep-03i
Date: 2026-09-21
Kind: findings (read-only audit + bead split; no code changed)

## Answer first

aie31.21's eviction table is written for a two-map model (`FWD_FLOW`,
`REV_FLOW`) that no longer exists in this repo -- the conntrack maps were
unified into one `FLOW_TABLE` (see "Real flow-table shape" below), so
aie31.21 is not implementable verbatim. The INTENT survives the
unification cleanly (delete forward-role pins to the departed pod, delete
reverse-role entries pointing at it, both unconditional on protocol) once
re-expressed against the real shape. File **3 beads**, in dependency
order: **(A)** move `FlowValue`/`RevFlowValue`/`PortMemoValue` into
`beep-common` so userspace can even read `FLOW_TABLE` (mechanical,
MED); **(B)** the sweep itself + controller wiring + a loader-side
trigger for testability (HIGH, the actual v1 requirement); **(C)** the
beep-smoke acceptance test (HIGH, the only thing that proves B against a
live kernel). One genuine fork is flagged below (PortMemo-tagged rows) --
not folded into any bead's mandatory scope.

## Real flow-table shape (established before anything else, per the correction)

Confirmed by reading `common/src/lib.rs` and `ebpf/src/main.rs` directly
(not inferred from aie31.21's text):

- **One physical conntrack table for the promoted/established roles**:
  `FLOW_TABLE: LruHashMap<FlowKey, FlowValue>` (`ebpf/src/main.rs:407-408`).
  Its own doc comment says it explicitly: "replacing the former separate
  `FWD_MAIN`/`REV_FLOW` maps" (`ebpf/src/main.rs:357-358`).
- **Forward vs. reverse vs. a third role are NOT distinguished by which
  map they're in -- they're distinguished by a `FlowDirection` tag byte
  appended to the key.** `FlowKey = TcpFlowKey (37 bytes) + 1 tag byte`
  (`common/src/lib.rs:90-133`, `FlowDirection::{Forward=0, Reverse=1,
  PortMemo=2}`). The value is a plain Rust union, read via the tag:
  `pub union FlowValue { forward: ForwardFlowValue, reverse: RevFlowValue,
  port_memo: PortMemoValue }` (`ebpf/src/main.rs:304-310`,
  `flow_table_get_forward`/`_reverse`/`_port_memo` at `:416-429`).
- **A separate, never-merged small map still exists for the
  PRE-promotion forward tier**: `FWD_PENDING: LruHashMap<TcpFlowKey,
  ForwardFlowValue>` (`ebpf/src/main.rs:291-293`) -- the admission-gated
  tier a flow sits in until its first observed return leg promotes it into
  `FLOW_TABLE`'s Forward-tagged rows (`ebpf/src/main.rs:1428-1441`).
  Deliberately kept separate so a flood can never evict an established
  entry (`ebpf/src/main.rs:237-254`'s doc comment) -- this is NOT part of
  the unification and is a second physical location the forward role's
  data lives in.

So today's real topology for what aie31.21 called two maps is:
**`FWD_FLOW` = `FWD_PENDING` (pre-promotion) + `FLOW_TABLE` rows tagged
`Forward` (post-promotion)`; `REV_FLOW` = `FLOW_TABLE` rows tagged
`Reverse``. A third role, `PortMemo` (added by the backend-src-port-remap
work after aie31.21 was written -- see `common/src/lib.rs:95-99`'s doc
comment), shares the same physical table as `Reverse` and is not
mentioned in aie31.21 at all.

## Map-match mechanism: does the value carry backend identity? -- YES for Forward, NO (key does instead) for Reverse/PortMemo

This differs by role, which is itself the biggest correction to aie31.21's
"symmetric FWD_FLOW/REV_FLOW delete" framing:

- **Forward role** (`FWD_PENDING` and `FLOW_TABLE`-Forward): the key is
  `(client_ip, client_port, VIP_ip, VIP_port, proto[, Forward])` --
  confirmed at the mint site, `ebpf/src/main.rs:1405-1412`
  (`encode_flow_key(client_ip_v6, client_port, vip_ip_v6, vip_port, proto,
  FlowDirection::Forward)`). **The key never carries pod identity at
  all.** Pod identity lives only in the VALUE:
  `ForwardFlowValue { backend: LbFrontBackend { backend_node_ip, pod_ip },
  ingress_ifindex }` (`common/src/lib.rs:258-275`). A sweep for "entries
  pointing at pod X" on this role must decode every candidate row's VALUE.
- **Reverse role** (`FLOW_TABLE`-Reverse) and **PortMemo role**
  (`FLOW_TABLE`-PortMemo): the key is `(client_ip, client_port, pod_ip,
  target_port, proto[, tag])` -- confirmed at both mint sites,
  `ebpf/src/main.rs:992-999` (`natural_rev_key`) and `:1006-1013`
  (`port_memo_key`), both literally passing `pod_ip_v6` as the key's
  "other" address. **Pod identity is embedded directly in the KEY's bytes
  16..32** (`beep_common::decode_tcp_flow_key`'s `other_ip` return value,
  `common/src/lib.rs:67-74`, already exists and needs no new code to
  reuse). `RevFlowValue`/`PortMemoValue` themselves carry no pod_ip field
  (`ebpf/src/main.rs:335-340`, `:351-355`) -- irrelevant for matching,
  since the key already tells you.

Consequence for the sweep implementation: it must branch by role. Forward
rows need a value read to find the departed pod; Reverse/PortMemo rows
can be matched from the key alone (decode with the existing
`decode_tcp_flow_key`, compare `other_ip`).

**Gap this surfaces (mechanical, not a design fork):** `FlowValue`,
`RevFlowValue`, and `PortMemoValue` are defined `ebpf`-crate-local
(`ebpf/src/main.rs:304-355`), not in `beep-common`, and carry no
`unsafe impl aya::Pod`. Neither `controller/` nor `beep`'s loader can open
`FLOW_TABLE` as a typed map today -- there is no userspace-reachable type
for it at all. Per this project's own rule ("any type shared between the
loader and the eBPF program lives in `beep-common`"), this is Bead A.

## aie31.21 reconciliation (each assumption -> corrected form)

| aie31.21 assumption | Reality in this repo | Corrected form |
|---|---|---|
| Two maps, `FWD_FLOW` and `REV_FLOW` | One `FLOW_TABLE` (tag-discriminated union) + a separate `FWD_PENDING` pre-promotion tier | Sweep must touch `FWD_PENDING` (all entries) + `FLOW_TABLE` (Forward- and Reverse-tagged entries only, by tag byte) |
| Deleting `REV_FLOW` and `FWD_FLOW` entries is symmetric ("delete entries pointing at pod X") | Pod identity is in the VALUE for Forward rows, in the KEY for Reverse rows | Sweep branches by tag: Forward -> filter on decoded value's `backend.pod_ip`; Reverse -> filter on decoded key's `other_ip` |
| Implicitly, only two roles exist | A third role, `PortMemo`, shares `FLOW_TABLE`'s physical storage and key shape, added after aie31.21 was written | **Flagged for operator, not decided here** (see below) |
| `FWD_FLOW`/`REV_FLOW` types are reachable wherever the eviction code needs to run | `FlowValue`/`RevFlowValue`/`PortMemoValue` are `ebpf`-crate-local, no `aya::Pod` impl, unreachable from userspace | Bead A: move to `beep-common`, gate `Pod` impls under the existing `#[cfg(feature = "user")]` convention (matches `LbFrontKey`/`LbFrontBackend`/`Config`/`UplinkConfig`, `common/src/lib.rs:277-284`) |
| "Reconciliation is a live per-key map write ... not a program reload" (unaffected by unification) | Still true; `LB_FRONT_MAP`/`POD_TARGETS` are diffed and patched live (`controller/src/apply.rs`) | No correction needed -- carries over unchanged |
| "UDP `FWD_FLOW` delete mandatory; TCP `FWD_FLOW` delete YES" | `proto` is a plain key byte on every role; the decided table gives BOTH protocols the same action | Collapses to: delete unconditionally, no protocol branch needed in the sweep at all |

## Where eviction hooks in: `controller/src/apply.rs`, not the loader's fixture path

`src/main.rs`'s own module doc says, verbatim, "Real Service/EndpointSlice
watching is Phase 5" (`src/main.rs:17`) -- **this is stale**. A real
controller crate (`controller/`, binary `beep-controller`) already exists,
already watches `Service`/`EndpointSlice`, and already does the exact
live per-key reconcile aie31.21's invariant describes
(`controller/src/apply.rs`, `controller/src/reconcile.rs`). The `beep`
binary (`src/main.rs`) is the separate, `--fixture`-driven loader/smoke
path and has no endpoint-watch of its own.

The exact seam already exists and needs no new machinery to detect "a pod
left":

- `controller/src/apply.rs:207-237` (`apply_pod_targets`) already computes
  `beep::stale_pod_targets(&existing, &live)` (`src/lib.rs:193-200`) --
  the set-difference of POD_TARGETS' old membership vs. the new desired
  one -- and deletes each stale pod IP from `POD_TARGETS`
  (`controller/src/apply.rs:214-221`). **This is the exact list of
  "departed pod IPs" the eviction sweep needs**, computed on every
  reconcile tick, already tested (`beep::stale_pod_targets` has its own
  unit tests via `src/lib.rs`'s existing style).
- `PinnedMaps` (`controller/src/apply.rs:21-58`) already opens
  `LB_FRONT_MAP`/`TARGET_PORTS`/`POD_TARGETS`/`NODE_ALLOW` from their
  bpffs pins via `open_hash_map::<K, V>` (`:38-47`). Both `FWD_PENDING`
  and `FLOW_TABLE` are already in the pinned set (`src/lib.rs:33-42`'s
  `MAP_NAMES`, entries `"FWD_PENDING"`/`"FLOW_TABLE"` at lines 40-41) --
  they just aren't opened by `controller` today. Confirmed
  `open_hash_map` needs no LRU-specific code: aya's `Map::HashMap`
  variant and `Map::LruHashMap` variant both convert into the same
  userspace `aya::maps::HashMap<MapData, K, V>` wrapper (aya 0.14.0,
  `src/maps/mod.rs`'s `impl_try_from_map!` macro, `HashMap from
  HashMap|LruHashMap`) -- the exact same `open_hash_map` helper already in
  `apply.rs:38-47` works unmodified for both new maps.
- The module doc at the top of `apply.rs` currently promises "this process
  never touches `FWD_PENDING`/`FLOW_TABLE`" (`controller/src/apply.rs:4-6`)
  -- that invariant is being deliberately narrowed (not violated) to "never
  touches them except this one targeted per-departed-pod delete," and the
  comment needs updating as part of Bead B.

**Confirmed userspace-only, no dataplane (`ebpf/`) change needed.** The
sweep is a plain iterate-and-delete over already-pinned maps from
existing userspace code, exactly the kube-proxy-style targeted pass
aie31.21 itself describes. `ebpf/src/main.rs` needs zero changes (Bead A
only moves type *definitions* out of it into `beep-common`; the maps,
hooks, and packet-path logic are untouched).

## Genuine fork flagged for the operator (not decided here)

**Should `PortMemo`-tagged `FLOW_TABLE` rows be evicted on pod removal
too?** aie31.21's decided table only names `FWD_FLOW`/`REV_FLOW`; `PortMemo`
didn't exist yet when it was written. `PortMemo` shares `Reverse`'s exact
key shape (pod IP embedded in the key, `common/src/lib.rs:95-99`'s doc
comment: "persists `resolve_backend_src_port`'s decision ... keyed on its
natural (client, real client port, pod, target port) tuple") and is
subject to the identical pod-IP-reuse hazard `REV_FLOW`'s "both protocols"
rule exists to close: a stale `PortMemo` memo for a reused pod IP could
feed a stale synthetic-port decision to an unrelated new flow through that
IP. This looks like the same rationale applies, but it is an inference,
not the decided text -- **Bead B's mandatory scope is Forward + Reverse
only** (the literal aie31.21 roles); `PortMemo` eviction is left as an
explicit, called-out follow-up in Bead B's description, not silently
included or silently skipped.

## Smoke-test strategy

`scripts/smoke.sh` never runs `beep-controller` (no live kube API in the
Lima VM) -- it only runs the `beep` loader against static `--fixture`
flags. So the controller's reconcile-triggered sweep (Bead B's primary
path) is not directly reachable from the existing harness. Bead B adds a
small loader-side trigger -- a `beep evict-pod` one-shot mode reusing the
exact same pure sweep functions the controller calls, opening the pinned
maps the same way `smoke.sh`'s existing step 5 already manipulates
`NODE_ALLOW` directly (`scripts/smoke.sh:30-33`) -- so the smoke harness
can simulate "a pod left" without a live control plane, while the
sweep *logic* under test is identical to what the real controller runs.
Bead C's acceptance test, concretely:

1. Drive one client -> VIP -> backend Pod TCP round trip (existing
   `smoke.sh` step 4 pattern) to establish a real `FWD_PENDING`/promoted
   `FLOW_TABLE` Forward + Reverse pair for that pod.
2. Run `beep evict-pod <pod-ip>` (Bead B's new trigger) against the
   pinned maps.
3. `bpftool map dump pinned <pin-dir>/POD_TARGETS` -- assert the pod's
   entry is gone.
4. `bpftool map dump pinned <pin-dir>/FWD_PENDING` and
   `.../FLOW_TABLE` -- assert no remaining row decodes to that pod (value
   `pod_ip` for Forward-tagged rows, key bytes 16..32 for Reverse-tagged
   rows).
5. Add a second fixture backend Pod IP and drive a NEW round trip through
   the same VIP -- assert it lands on the replacement pod (proves the
   sweep didn't wedge the front).
6. Re-add a fixture whose pod IP equals the ORIGINAL (evicted) pod IP
   (pod-IP reuse) and drive a fresh round trip -- assert the resulting
   `FLOW_TABLE` Reverse-tagged entry's value matches THIS flow (fresh
   `ingress_node_ip`/`vip_port`), not a resurrected stale one -- provable
   because step 4 already proved nothing stale survived to resurrect.

`cargo test -p beep-common` alone cannot exercise any of this (no live
kernel, no map dump) -- Bead C's smoke pass on `beep-smoke` is a mandatory
gate, not optional, before beep-03i can be considered landed.

## Recommended bead split

Smallest/least risky first; each depends on the previous.

### Bead A -- move `FlowValue`/`RevFlowValue`/`PortMemoValue` into `beep-common`

**Severity: MED** (blocking prerequisite; low risk in isolation, but
nothing else in this epic compiles without it).

- **Files touched:** `common/src/lib.rs` (add the three types + gated
  `Pod` impls), `ebpf/src/main.rs:304-355` (delete the local definitions,
  import from `beep_common` instead, adjust the `use` list at
  `ebpf/src/main.rs:70` and neighbors).
- **Change sketch:** cut `FlowValue`/`RevFlowValue`/`PortMemoValue`
  verbatim from `ebpf/src/main.rs:304-355` into `common/src/lib.rs`
  (near `ForwardFlowValue`, `common/src/lib.rs:258-275`); add
  `#[cfg(feature = "user")] unsafe impl aya::Pod for FlowValue {}` (and
  same for `RevFlowValue`, `PortMemoValue`), mirroring
  `common/src/lib.rs:277-284`'s existing pattern exactly. `ebpf/src/main.rs`
  re-imports all three from `beep_common` in place of its local
  definitions; no field, layout, or behavior changes.
- **Settled rule this implements:** none directly -- this is the
  "shared type lives in `beep-common`" project convention, a prerequisite
  for Beads B/C to compile at all.
- **beep-smoke acceptance:** none required (no dataplane behavior change);
  gate is `cargo fmt --check` + `cargo test -p beep-common` (host-only,
  must stay green) plus a new regression test asserting
  `size_of::<RevFlowValue>()`/`size_of::<PortMemoValue>()`/
  `size_of::<FlowValue>()` match today's ebpf-side values with no
  compiler-inserted padding gap, mirroring the existing
  `assert_eq!(core::mem::size_of::<ForwardFlowValue>(), 36)` pattern
  (`common/src/lib.rs:848`) -- this is Rule 14's regression test: if a
  future field reorder reintroduces a padding gap, this test fails before
  a live kernel round-trip ever does.

### Bead B -- selective conntrack eviction sweep + controller wiring + loader trigger

**Severity: HIGH** (this bead IS the firm v1 production-readiness
requirement; depends on Bead A).

- **Files touched:** `src/lib.rs` (new pure sweep-decision functions,
  next to `stale_pod_targets` at `:193-200`), `controller/src/apply.rs`
  (new `PinnedMaps` fields + wiring in `apply_pod_targets`/`apply`,
  module doc update at `:4-6`), `src/main.rs` (new `evict-pod` one-shot
  CLI entry point reusing the same pure functions).
- **Change sketch:**
  - `src/lib.rs`: add `pub fn stale_forward_entries<K: Copy>(entries: &[(K,
    ForwardFlowValue)], departed_pod: [u8; 16]) -> Vec<K>` (filters on
    `value.backend.pod_ip == departed_pod`; generic `K` so it serves both
    `FWD_PENDING`'s `TcpFlowKey` and `FLOW_TABLE`'s Forward-tagged
    `FlowKey` rows after the caller has already read `union.forward`) and
    `pub fn stale_reverse_keys(keys: &[FlowKey], departed_pod: [u8; 16]) ->
    Vec<FlowKey>` (filters `FlowDirection::Reverse`-tagged keys via
    `decode_tcp_flow_key`'s `other_ip`, per the "Reconciliation" table
    above). Both pure, host-testable, no kernel dependency -- unit tests
    assert a departed pod's rows are selected and an unrelated pod's rows
    are not, mirroring `stale_pod_targets`'s own test style.
  - `controller/src/apply.rs`: add `fwd_pending: AyaHashMap<MapData,
    TcpFlowKey, ForwardFlowValue>` and `flow_table: AyaHashMap<MapData,
    FlowKey, FlowValue>` fields to `PinnedMaps`, opened via the existing
    `open_hash_map` helper (`:38-47`, needs no change) in `PinnedMaps::open`
    (`:49-58`). In `apply_pod_targets` (`:207-237`), for each `stale` pod IP
    (already computed at `:214`, before the `map.remove` call, so the
    sweep runs even if the `POD_TARGETS` delete itself fails), iterate
    `fwd_pending.iter()` and `flow_table.iter()`, split `flow_table`'s rows
    by tag byte, call the two new pure functions, and `.remove()` every
    matched key -- same continue-past-failure logging convention as
    `apply_diff_ops` (`:141-177`). Update the module doc (`:4-6`) to state
    the narrowed (not removed) invariant.
  - `src/main.rs`: add an `evict-pod` CLI mode (flag or subcommand) that
    opens `POD_TARGETS`/`FWD_PENDING`/`FLOW_TABLE` from their bpffs pins
    (same `MapData::from_pin` pattern `apply.rs` already uses) given a pod
    IP argument, deletes the `POD_TARGETS` entry, and runs the same two
    pure sweep functions -- this is Bead C's only way to trigger the sweep
    without a live kube API.
- **Settled rule this implements:** aie31.21's eviction table, re-expressed
  per the "Reconciliation" section above -- unconditional-on-protocol
  delete of Forward-role rows (`FWD_PENDING` + `FLOW_TABLE` Forward-tagged)
  and Reverse-role rows (`FLOW_TABLE` Reverse-tagged) matching the departed
  pod. `PortMemo`-tagged rows are explicitly OUT of this bead's mandatory
  scope (see "Genuine fork flagged" above) -- note it in the bead body as
  a deliberate, called-out omission, not an oversight.
- **beep-smoke acceptance:** none on its own (this bead ships the
  mechanism); Bead C is the mandatory proof. This bead's own gate is
  `cargo fmt --check` + `cargo test -p beep-common` for the new pure
  functions' unit tests, plus (Linux-only, per this repo's OS split)
  `cargo test` for `controller`'s existing `apply.rs`/`reconcile.rs` suite
  staying green.

### Bead C -- beep-smoke acceptance test for selective eviction

**Severity: HIGH** (per the brief: `cargo test -p beep-common` does not
exercise this; without this bead the epic has no proof the sweep works
against a real kernel).

- **Files touched:** `scripts/smoke.sh`, `scripts/smoke-remote.sh` (or a
  sibling script following the existing `smoke.sh`/`smoke-remote.sh`
  split).
- **Change sketch:** exactly the 6-step sequence under "Smoke-test
  strategy" above -- establish a round trip, run `beep evict-pod`, assert
  via `bpftool map dump pinned <pin-dir>/{POD_TARGETS,FWD_PENDING,
  FLOW_TABLE}` that matching rows are gone, assert a replacement-pod round
  trip works, assert pod-IP reuse doesn't resurrect stale reverse-role
  state.
- **Settled rule this implements:** proves Bead B's implementation of
  aie31.21's eviction table against a live kernel, not just unit tests.
- **beep-smoke acceptance:** this bead's own deliverable IS the beep-smoke
  pass -- `bash scripts/smoke.sh --vm beep-smoke` (or `--vm <assigned VM>`)
  must exit 0 with the new eviction assertions included, run on Linux/Lima
  only per this repo's existing build-gate split.

## Dependencies

`bd dep add`: Bead B depends on Bead A (needs the moved types to compile
`controller`/`src/lib.rs` code against `FlowValue`/`RevFlowValue`). Bead C
depends on Bead B (needs the `evict-pod` trigger to exist before smoke.sh
can call it).

## Hot-zone for the mayor (parallel-drain carve-out)

- Bead A: `common/src/lib.rs`, `ebpf/src/main.rs` (lines 304-355 and the
  `use` list only -- no packet-path logic).
- Bead B: `src/lib.rs`, `src/main.rs`, `controller/src/apply.rs`. Does
  NOT touch `ebpf/` at all.
- Bead C: `scripts/smoke.sh`, `scripts/smoke-remote.sh`. Does not touch
  any Rust source.

No overlap with `beep-5lw`'s planned files (`ebpf/src/main.rs:121-138,
527-572`, `controller/src/reconcile.rs:171-225,303-353`,
`controller/src/apply.rs:38-100`) except that both epics touch
`controller/src/apply.rs` -- beep-5lw's touch is `PinnedMaps`'s
`LB_FRONT_MAP`/`TARGET_PORTS` fields (`:38-100`), this epic's Bead B touch
is new `fwd_pending`/`flow_table` fields and `apply_pod_targets`
(`:207-237`) -- same file, disjoint regions, but sequence rather than
parallelize if both land close together to avoid a merge-conflict-prone
`PinnedMaps` struct edit.
