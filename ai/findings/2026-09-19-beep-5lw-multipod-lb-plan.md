---
Bead: beep-5lw
---

# Multi-pod backend LB plan + estimates (beep-5lw)

Bead: beep-5lw
Date: 2026-09-19
Kind: findings (read-only audit, Phase 1 of audit -> operator-decides -> apply)

## Recommendation (read this first)

Add an **indexed endpoint table** (`LB_FRONT_ENDPOINTS`, replacing today's
one-value `LB_FRONT_MAP`) plus a tiny **ready-count map** (`LB_FRONT_COUNT`),
and select a backend on the first-packet miss with a **plain deterministic
hash of the flow tuple modulo the ready count** -- one extra map lookup, zero
loops, verifier-trivial. Do **not** build a Maglev permutation table: the
existing, operator-accepted ADR
(`docs/decisions/servicelb-flow-admission-affinity.md`) already commits to
"a deterministic hash over the ready set" and justifies it on beep's actual
scale ("u7s's small, often single-digit endpoint counts") -- Maglev's payoff
over plain hashing only shows up with large backend tables and needs a
controller-maintained permutation map beep does not otherwise need. Round-
robin is worse than either here: it needs a shared, cross-CPU mutable
counter on the hot path with no offsetting benefit, since per-flow stickiness
already comes from the affinity pin (mayor-aie31.21), not from the selection
algorithm.

**This selection algorithm feeds an affinity-pin mechanism that is already
implemented in this repo** (`FWD_PENDING`, `ForwardFlowValue`,
`fwd_pending_affinity_pin`, promotion into `FLOW_TABLE` --
`ebpf/src/main.rs:190-246`, `common/src/lib.rs:258-340`). beep-5lw only has
to change what feeds INTO that pin on a first-packet miss (today: the one
fixed value `LB_FRONT_MAP` holds; after: the hash-selected slot out of
`LB_FRONT_ENDPOINTS`). The eviction half of mayor-aie31.21 (scoped delete on
endpoint removal) is **not implemented anywhere in this repo today** (no
`evict`/`delete`-on-removal code exists outside passive LRU aging -- verified
by grep across `ebpf/`, `src/`, `controller/`) and stays out of this bead's
scope.

**Total estimate: ~24-34 hours (roughly 4-6 focused engineering days)**
across 6 beads, S/M/L breakdown below. Biggest open question for the
operator: accept **contiguous per-front slot renumbering** on every
endpoint add/remove (simple, matches this codebase's existing "sort
deterministically, no dedup" style) or invest now in a **global BackendId
indirection** (Cilium-style, avoids renumbering churn, costs a second
indirection hop and a controller-side ID allocator) -- see Open Questions.

A real controller (`controller/` crate, `beep-controller`) already exists in
this repo and already reconciles `Service`/`EndpointSlice` objects into
these maps -- this is not future/aspirational work. `mayor-9gr0n` (closed
2026-09-11 in the mayor tracker) is the design ancestor; the actual
implementation landed in *this* repo under beep's own bead numbering
starting with commit `f8222ae` (2026-09-10, `feat(controller): beep-
controller crate + pure reconcile fn + tests`) and continued through beads
like beep-90g. Every mayor-9gr0n/mayor-aie31.21 path reference below has
been remapped from the stale `crates/servicelb/servicelb-ebpf/...` layout to
this repo's real `ebpf/`, `src/`, `common/`, `controller/` layout.

## 1. Current state: one backend per front, cited

**The map.** `ebpf/src/main.rs:121-122`:

```rust
#[map]
static LB_FRONT_MAP: HashMap<LbFrontKey, LbFrontBackend> = HashMap::with_max_entries(4096, 0);
```

`LbFrontKey` (`common/src/lib.rs:210-217`) is the front tuple (`vip_ip:
[u8;16]`, `vip_port`, `proto`); `LbFrontBackend` (`common/src/lib.rs:224-230`)
is exactly **one** `{ backend_node_ip, pod_ip }` pair. There is no count, no
list, no array -- the value type itself has room for one backend, full stop.
(Naming note: the mayor-9gr0n/mayor-aie31.21 bead text calls these
`VIP_MAP`/`VipKey`/`VipBackend`; those names never existed in this repo --
`LB_FRONT_MAP`/`LbFrontKey`/`LbFrontBackend` are the real, current names,
confirmed against `ebpf/src/main.rs` and `common/src/lib.rs`.)

**The lookup.** `ebpf/src/main.rs:533`, inside
`try_uplink_ingress_headers` (the forward-path ingress classifier):

```rust
let backend = *unsafe { LB_FRONT_MAP.get(key) }?;
```

One `get`, one value, no selection logic of any kind. This `backend` is
what's threaded into `ForwardFlowValue` and pinned into `FWD_PENDING`
(`ebpf/src/main.rs:562-571`) -- the affinity-pin machinery downstream already
expects "the chosen backend," it just has never had more than one candidate
to choose from.

**The loader fixture.** `src/main.rs:371-406` (`fixture_key`/
`populate_fixtures`): `--fixture` is `required = true` and repeatable
(`src/main.rs:87-88`, `Vec<Fixture>`), but `fixture_key` hashes on
`(vip_ip, vip_port, proto)` alone, and `populate_fixtures` does a plain
`HashMap::insert` per fixture (`src/main.rs:390-405`). Two `--fixture` flags
naming the same VIP:port:proto with different backends do not merge or
error -- the later flag silently overwrites the earlier one in
`LB_FRONT_MAP`. There is no CLI syntax today for "these two backends are
alternatives for the same front."

**The controller.** `controller/src/reconcile.rs:303-353`
(`reconcile_service`) already collects every ready endpoint for a Service
port (`candidates`, line 319-323) and then throws all but one away:

```rust
// Decision #5 (single backend per front): today's LB_FRONT_MAP schema
// holds exactly one backend per front, so pick deterministically --
// lowest pod IP -- rather than arbitrarily ...
candidates.sort_by_key(|e| e.pod_ip);
let Some(backend) = candidates.first() else { continue; };
```

This is the exact deferred decision the bead description names ("Decision
#5 ... deferred separately"). The controller-side data (`EndpointSliceView`,
`Endpoint { pod_ip, node_ip, ready, ports }`, `controller/src/reconcile.rs:
134-140`) already carries every ready endpoint; nothing about the watch
layer needs to change, only what `reconcile_service` does with the
already-collected `candidates` list.

**What can't be represented today:** any Service with more than one ready
endpoint. `LB_FRONT_MAP` structurally has room for exactly one backend per
front; the controller structurally discards every endpoint but one before
it ever reaches the map; the loader's `--fixture` flag has no syntax for
more than one backend per front either. All three layers agree with each
other today (self-consistent single-backend design), which is exactly why
this is a schema change, not a bug fix.

## 2. Endpoint-map schema

Replace `LB_FRONT_MAP`'s single-value shape with two maps:

```rust
// beep-common
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct LbFrontEndpointKey {
    pub front: LbFrontKey, // 20 bytes, no padding (existing type, unchanged)
    pub slot: u16,         // offset 20 is already 2-aligned: no padding gap
}
```

- `LB_FRONT_COUNT: HashMap<LbFrontKey, u32>` -- ready-endpoint count for a
  front. A miss means "no such front" or "zero ready backends," identical
  in effect to today's `LB_FRONT_MAP` miss (drop/pass-through via `?`).
- `LB_FRONT_ENDPOINTS: HashMap<LbFrontEndpointKey, LbFrontBackend>` -- the
  indexed table, slots `0..ready_count-1` populated contiguously per front.
  Reuses `LbFrontBackend` unchanged (no new value type).

**Verifier/bounded-lookup trade-off.** This design needs **no loop at all**
on the hot path -- unlike `resolve_backend_src_port`'s `PROBE_LIMIT`-bounded
probe loop (`common/src/lib.rs:592-612`, a different problem: reverse-key
conflict resolution), backend selection is one hash, one integer modulo,
and one direct-key `HashMap` lookup:

1. `LB_FRONT_COUNT.get(front_key)` -> `ready_count` (miss = today's drop
   path, unchanged).
2. `slot = hash(flow_tuple) % ready_count` (guard `ready_count == 0` the
   same way a miss is guarded -- one scalar op, no loop, trivially provable
   termination).
3. `LB_FRONT_ENDPOINTS.get(LbFrontEndpointKey { front: front_key, slot })`
   -> `LbFrontBackend` (miss should not happen if the controller keeps slots
   dense, but must still be handled as "no backend," matching this file's
   existing fail-loud drop convention rather than assumed).

Net cost over today: one extra `HashMap` lookup (2 total instead of 1) on
the ingress fast path. No new loop, no new verifier risk class.

**Sizing.** `docs/design/ebpf-lb-dataplane.md`'s own sizing table
(lines 122-134) *already* budgets for exactly this split and has since
Phase 1 (`as_of: 2026-09-07`, predates beep-5lw): a "Front-IP map (<100
Services x <=2 protocols)" row at ~25 KiB *and a separate* "Endpoint map
(<1000 endpoints)" row at ~128 KiB, explicitly annotated "Full map on every
node." `LB_FRONT_COUNT` is the (cheap) front-IP-map role; `LB_FRONT_ENDPOINTS`
is the (larger) endpoint-map role. The design intent for a real endpoint
map predates this bead; it was simply never implemented -- `LB_FRONT_MAP`
stayed a single-value placeholder through Phase 2/3/5.

`assert-ebpf-map-memory.sh:45` hard-codes the exact expected map name set
(9 names today, including `LB_FRONT_MAP`) and a 4 MiB gross-regression
ceiling (`assert-ebpf-map-memory.sh:60-61`). This gate **must** be updated
(swap `LB_FRONT_MAP` for `LB_FRONT_COUNT`+`LB_FRONT_ENDPOINTS`, 10 names
total) as part of the implementation bead, and the new total should be
re-measured against the 4 MiB ceiling rather than assumed safe -- plain
`HASH` maps (unlike the `LRU_HASH` conntrack tables this ceiling's comment
walks through) may not fully preallocate `max_entries` up front, but that
should be confirmed against a live `bpftool map show`, not asserted here.

## 3. Selection algorithm: deterministic hash (not Maglev, not round-robin)

**Recommendation: plain deterministic hash of the flow 5-tuple, modulo the
ready count.** Already the accepted design per
`docs/decisions/servicelb-flow-admission-affinity.md` (Status: Accepted,
2026-09-06): *"chosen once on a flow's first packet by a deterministic
hash over the ready set. Later packets follow the stored pin."* This ADR's
own rationale (lines 43-46) is the strongest argument against Maglev at
beep's scale: *"at u7s's small, often single-digit endpoint counts,
per-packet re-hashing's disruption fraction is too large to accept"* --
which is exactly why affinity pinning (not the selection algorithm) is what
carries the consistency burden. Once a flow is pinned, the selection
algorithm is never consulted again for that flow until its specific backend
is evicted -- at which point *that* flow has to move somewhere regardless
of algorithm; no algorithm avoids that.

**Why not Maglev.** Maglev's entire value proposition is minimizing how
many *unrelated* flows get reassigned when the backend set changes, via a
large (typically >=65537-slot) per-service permutation table the control
plane builds and keeps in sync. At beep's declared scale (design doc:
"<10 nodes/<100 Services/<1000 endpoints," often single-digit endpoints per
Service) that permutation table's memory and controller-side complexity
buys almost nothing over plain `hash % N`, because affinity pinning already
absorbs the "don't disturb existing flows" requirement structurally --
Maglev and plain hashing produce identical behavior for already-pinned
flows (neither is ever asked to re-decide), and for brand-new flows during
a churn window, N is small enough that plain hashing's redistribution
fraction is not the dominant cost.

**Why not round-robin.** Round-robin needs a mutable, shared cursor
incremented on every new-flow (first-packet-miss) event. In a distributed,
per-node dataplane with no cross-node coordination (this dataplane's
explicit design constraint -- every node loads its own eBPF programs and
maps independently), that cursor is either per-node (so two nodes acting as
ingress for the same VIP diverge immediately and non-deterministically) or
needs cross-CPU/cross-node synchronization this dataplane has no mechanism
for. A hash needs no shared state and gives the same answer on any CPU, any
node, replayed identically -- a strictly stronger property for zero
additional cost.

**Concrete shape.** A pure function in `beep-common`, mirroring
`synthetic_port_seed`'s existing bit-mixing style
(`common/src/lib.rs:648-652`) rather than pulling in a hashing crate
(minimal-deps stance):

```rust
pub fn select_backend_slot(client_ip: u32, client_port: u16,
                            front_ip: u32, front_port: u16,
                            ready_count: u32) -> Option<u32> {
    if ready_count == 0 { return None; }
    let mixed = /* same rotate/xor mixing style as synthetic_port_seed */;
    Some(mixed % ready_count)
}
```

Unit-testable exactly like `resolve_backend_src_port` (host-side, no kernel
needed): fixed inputs produce a fixed slot; sweeping many flows across a
fixed `ready_count` should distribute roughly evenly (same style of test as
`common/src/lib.rs`'s existing `many_fronts_sharing_a_backend_pod_never_
produce_a_duplicate_reverse_key`).

## 4. Composition with mayor-aie31.21 (fixed, not re-litigated)

aie31.21's accepted decision (`bd show mayor-aie31.21`, operator 2026-09-07):
stored per-flow affinity, `FWD_FLOW` (now `FWD_PENDING`/`FLOW_TABLE` in this
repo's real map names) pins the **full** backend identity
(`backend_node_ip` + `pod_ip`), chosen **once** on the first-packet miss via
a deterministic hash over the ready set; later packets follow the pin.
Eviction table: UDP `FWD_FLOW` delete mandatory, TCP `FWD_FLOW` delete YES,
`REV_FLOW` delete both protocols.

**The pin mechanism is already built, in this repo, today** --
`ForwardFlowValue { backend: LbFrontBackend, ingress_ifindex: u32 }`
(`common/src/lib.rs:270-275`), `FwdPendingPin`/`fwd_pending_affinity_pin`
(`common/src/lib.rs:319-340`), wired into `try_uplink_ingress_headers`
(`ebpf/src/main.rs:555-572`): on a `FLOW_TABLE` miss, it mints exactly once
into `FWD_PENDING` and never rewrites an existing pin. This is precisely
aie31.21's "chosen once ... later packets follow the stored pin" -- it is
just currently fed by `LB_FRONT_MAP`'s single fixed value instead of a
selection among N.

**The seam is exactly line 533.** Today:

```rust
let backend = *unsafe { LB_FRONT_MAP.get(key) }?;
```

becomes (schematically):

```rust
let ready_count = unsafe { LB_FRONT_COUNT.get(key) }.copied()?;
let slot = select_backend_slot(src_ip, src_port, dst_ip, dst_port, ready_count)?;
let backend = *unsafe {
    LB_FRONT_ENDPOINTS.get(LbFrontEndpointKey { front: key, slot })
}?;
```

Everything downstream of this line (`ForwardFlowValue` construction,
`fwd_pending_affinity_pin`, promotion into `FLOW_TABLE` on the observed
return leg) is untouched. beep-5lw's entire dataplane-side surface area is
this one substitution: what feeds the pin, not how the pin itself works.

**Eviction is NOT implemented and is out of scope here.** Grepped across
`ebpf/`, `src/`, `controller/`: no selective delete-on-endpoint-removal
pass exists anywhere in this repo -- only passive LRU aging. aie31.21's
eviction half (mandatory UDP `FWD_FLOW` delete, TCP YES, `REV_FLOW` both
protocols) remains open implementation work, tracked under aie31.21 itself,
not this bead. beep-5lw's multi-endpoint selection makes that eviction work
*matter more* (a departed endpoint that was one of several is now silently
still selectable by a stale `LB_FRONT_ENDPOINTS` slot until the controller's
next reconcile removes it -- a narrower window than today's single-backend
case, not a new hazard), but does not require implementing it.

## 5. Controller programming

**A real controller exists in this repo today** -- `controller/`
(`beep-controller` crate: `main.rs`, `watch.rs`, `reconcile.rs`, `apply.rs`,
`status.rs`). `mayor-9gr0n` (closed 2026-09-11 in the mayor tracker) is the
design ancestor; git history shows the actual crate landing in *this* repo
starting `f8222ae` (2026-09-10, `feat(controller): beep-controller crate +
pure reconcile fn + tests`) and growing under beep's own bead series (e.g.
beep-90g vendoring `beep-kubeconfig`). This is live, tested code, not
aspirational -- `reconcile_service` and `diff`/`apply_ops` already have a
substantial unit-test suite (`controller/src/reconcile.rs:410+`,
`controller/src/apply.rs:341+`). Do not treat mayor-9gr0n's "controller
watches Service/EndpointSlice" as future work; it is done. What's
unfinished is specifically the pick-one step inside it.

**The change.** `reconcile_service` (`controller/src/reconcile.rs:303-353`)
already builds `candidates: Vec<&Endpoint>` from every ready endpoint
across every `EndpointSliceView` (line 309, 319-323) before discarding all
but the lowest-pod-IP one. Replace the discard with:

- Sort `candidates` deterministically (already does this, by `pod_ip`) so
  two reconciles over the same input assign the same slot to the same
  endpoint -- unchanged property, just no longer collapsed to one.
- Emit one `LbFrontEndpointKey { front: key, slot: i }` -> `LbFrontBackend`
  entry per candidate into a new `desired.lb_front_endpoints: HashMap<
  LbFrontEndpointKey, LbFrontBackend>` field on `DesiredEntries`
  (`controller/src/reconcile.rs:171-225`).
- Emit `desired.lb_front_count: HashMap<LbFrontKey, u32>` with
  `candidates.len()` for the front.

The existing `diff`/`MapOp<K, V>` machinery (`controller/src/reconcile.rs:
355-402`) is already generic over `K, V` and needs no change; `apply.rs`'s
`PinnedMaps`/`apply_ops` (`controller/src/apply.rs:38-100`) needs two new
`open_hash_map` calls (`LB_FRONT_ENDPOINTS`, `LB_FRONT_COUNT`) replacing the
one for `LB_FRONT_MAP`, following the exact pattern already used for
`TARGET_PORTS`.

**Loader-side fixture parity.** `src/main.rs`'s `--fixture` flag and
`populate_fixtures` (`src/main.rs:380-406`) is the non-controller,
smoke-test code path and needs the equivalent change: allow repeated
`--fixture` entries sharing a front to become slots 0..N-1 in
`LB_FRONT_ENDPOINTS` instead of silently overwriting each other in
`LB_FRONT_MAP`, plus write `LB_FRONT_COUNT`. `MAP_NAMES`
(`src/lib.rs:33-42`) needs `LB_FRONT_MAP` swapped for the two new names.

## 6. Proposed bead breakdown (for operator approval -- not created)

Dependency order top to bottom; no beads created per this task's scope.

1. **beep-common: endpoint-map types + selection hash (S, ~3-4h).** Add
   `LbFrontEndpointKey`, `select_backend_slot` (+ no-padding/round-trip/
   distribution unit tests mirroring the existing `resolve_backend_src_
   port` test style). No kernel dependency; runs on macOS via `cargo test
   -p beep-common`.
2. **ebpf: swap `LB_FRONT_MAP` for `LB_FRONT_COUNT`+`LB_FRONT_ENDPOINTS`,
   wire the selection call into `try_uplink_ingress_headers` (M, ~5-8h).**
   Depends on (1). Touches `ebpf/src/main.rs:121-138` (map decls) and
   `:527-572` (selection + pin). Update
   `scripts/assert-ebpf-map-memory.sh:45`'s expected name list and re-verify
   the 4 MiB ceiling against a live `bpftool map show`.
3. **loader: `--fixture`/`populate_fixtures` multi-backend support (S/M,
   ~3-5h).** Depends on (1)+(2). Touches `src/main.rs:371-406`,
   `src/lib.rs:33-42` (`MAP_NAMES`).
4. **controller: `reconcile_service` emits all ready endpoints, `apply.rs`
   wiring (M/L, ~6-10h).** Depends on (1)+(2). Touches
   `controller/src/reconcile.rs:171-225,303-353` and
   `controller/src/apply.rs:38-100`; the existing ~450-line test suite in
   both files encodes today's pick-one behavior and needs rewriting, not
   just extending -- this is the biggest single piece of work in the plan.
5. **dataplane smoke: multi-backend round trip + distribution assertion
   (M, ~3-5h).** Depends on (2)+(3)+(4). Extends `scripts/smoke.sh` (or a
   sibling script) to run 2+ backend fixtures/pods behind one VIP and
   assert traffic actually lands on more than one, not just that it round-
   trips. Linux/Lima-VM only, per this repo's build-gate split.
6. **docs: sizing table + packet-flow note reconciliation (S, ~1-2h).**
   `docs/design/ebpf-lb-dataplane.md`'s sizing table (lines 122-134)
   already anticipates this split; update it to name the real map pair and
   confirm the "(2) Ingress hashes to a ready backend" packet-flow line
   (line 55) now matches the implementation instead of describing intent
   only.

**Total: ~21-34 hours.** Suggested priority: **P2**, matching the parent
epic (`mayor-aie31`) and `mayor-aie31.21` -- a load balancer that can only
front one backend per Service is not yet doing the thing its name promises,
and this is core-correctness work, not a performance nicety.

## 7. Open questions for the operator

1. **Contiguous slot renumbering vs. BackendId indirection.** The schema in
   Section 2 renumbers `LB_FRONT_ENDPOINTS` slots 0..N-1 contiguously per
   front; removing endpoint at slot k shifts every slot after it. At
   beep's declared scale (<1000 endpoints total) this is cheap per
   reconcile tick, and only affects yet-unpinned new flows during the
   reconcile race (already-pinned flows are untouched, per Section 4). The
   alternative -- a global, controller-assigned `BackendId` table decoupled
   from any one front's slot numbering (Cilium's actual design) -- avoids
   renumbering entirely but adds a second indirection hop and a controller-
   side ID allocator/lifecycle this bead's plan does not otherwise need.
   Recommend accepting the simpler renumbering design; flag if churn proves
   to matter in practice.
2. **Same backend, multiple fronts.** A pod backing two Service ports (two
   `LbFrontKey`s) gets two independent `LB_FRONT_ENDPOINTS` entries under
   the Section 2 schema -- no dedup. Acceptable at declared scale; revisit
   if `LB_FRONT_ENDPOINTS`'s size becomes a real constraint.
3. **Weighted selection.** `Endpoint` (`controller/src/reconcile.rs:134-140`)
   carries no weight field; Section 3's hash treats every ready endpoint
   as equal-probability. Is unweighted selection sufficient for v1, or does
   `externalTrafficPolicy=Local`-style node-local preference need scoping
   now?
4. **Terminating-but-still-serving endpoints.** `Endpoint.ready` is the
   only readiness signal tracked today (`controller/src/watch.rs:161`,
   "`conditions.ready` defaults to `true`") -- there is no separate
   terminating/serving distinction. Should a *newly selected* flow (first-
   packet miss) ever be allowed to land on a terminating-but-still-serving
   endpoint, or should the ready-set for new selections exclude it while
   aie31.21's (not-yet-built) eviction still treats it as valid for
   already-pinned flows? Worth deciding before, not during, aie31.21's
   eviction implementation.
5. **`LB_FRONT_COUNT`/`LB_FRONT_ENDPOINTS` `max_entries` defaults.** Follow
   the existing `--fwd-pending-max-entries`-style DaemonSet-configurable
   pattern (`src/lib.rs:165-186`), or hard-code the design doc's <1000-
   endpoint ceiling for v1 and make it configurable later?
