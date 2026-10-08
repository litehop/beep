---
Bead: beep-5lw
---

# Multi-endpoint backend LB plan + estimates (beep-5lw)

Bead: beep-5lw
Date: 2026-09-19
As of 2026-10-08 (line numbers cite main at 0e75d0f)
Kind: findings (Phase 1 of audit -> operator-decides -> apply)

## Recommendation (read this first)

Build the multi-endpoint **shape** inside beep-xfa.1 (a per-front meta map
plus a `(front, slot)` endpoint table, exactly one endpoint per front), then
let beep-5lw add the behaviour: select a slot with a **plain deterministic
hash of the flow tuple modulo the front's ready count**, make ingress
**steer from the stored affinity pin** (it does not today -- see section 3),
and have the controller emit every ready endpoint of the front's own address
family. Keep **per-front dense slot renumbering** with backend identity
`(pod_ip, target_port)`; no new identity and no BackendId table is needed
(Q1). Do not build Maglev: the accepted ADR
(`docs/decisions/servicelb-flow-admission-affinity.md:30`) already commits to
"a deterministic hash over the ready set" at single-digit endpoint counts,
and Maglev is the later upgrade only if churn proves to matter.

**Estimate:** xfa.1 shape increment **~8-12h** on top of its consolidation;
beep-5lw remainder **~23-37h** over 6 beads. The old 21-34h total was
lower because it missed two items found on this refresh: ingress does not
steer from the pin, and decap cannot find a per-endpoint `target_port` once
a front has more than one endpoint.

Must be decided **before xfa.1**: Q2 (where `target_port` lives, and how
decap finds it) and Q1's confirmation. Everything else gates only 5lw.

## 1. Current state (main, 2026-10-08)

**Maps** (`ebpf/src/main.rs`): `LB_FRONT_MAP: HashMap<LbFrontKey,
LbFrontBackend>` (:160, 4096 entries) and `TARGET_PORTS: HashMap<LbFrontKey,
u16>` (:176, 4096) -- two maps on the same key; the file itself says "the two
never interact" (:148). `POD_TARGETS` (:210, default 128) is the per-pod
stale-pod/egress gate; `NODE_ALLOW` (:240, default 32) is the peer-underlay
allow-list. `FWD_PENDING` (:297) and `FLOW_TABLE` (:351) hold conntrack.
`MAP_NAMES` is 8 names (`src/lib.rs:36`), matching
`scripts/assert-ebpf-map-memory.sh:45`.

**Types** (`common/src/lib.rs`): `LbFrontKey` (:241) is 16-byte front
address + port + proto + pad, v4 stored v4-mapped; `LbFrontBackend` (:254) is
one `{backend_node_ip, pod_ip}`; `ForwardFlowValue` (:301) is
`{backend: LbFrontBackend, ingress_ifindex}`. Address fields still use
legacy pre-rename names (xfa.1 renames them).

**Readers.** Ingress reads `LB_FRONT_MAP` once per packet, v4 at
`ebpf/src/main.rs:611` and v6 at `:753`. Decap-forward on the backend node
reads `TARGET_PORTS` keyed by the INGRESS node's front (v4 `:951`, v6
`:1163`) -- the front rides through Geneve unrewritten -- after the
`POD_TARGETS` stale-pod check (`:915`). Return paths read neither.

**Writers.** Controller: `reconcile_service` (`controller/src/reconcile.rs:389`)
collects all ready candidates per Service port (:405-409) and keeps only the
lowest pod IP (:410-420, "Decision #5 ... placeholder"); `apply.rs:60-61`
opens the two pinned maps. Loader: `populate_fixtures` (`src/main.rs:563`)
inserts one backend per `--fixture`; a repeated front silently overwrites.
So all three layers agree on one backend per front today.

**Per-family gap (beep-39a, in flight).** A dual-stack Service's v6 front was
programmed with the v4 pod (`LB_FRONT_MAP` value `::ffff:192.168.104.14` under
a v6 key). Selection must therefore be **per front, hence per family**: a
front's endpoint set contains only endpoints whose pod address is the
front's family; the hash and count are per front and never see the other
family. beep-39a fixes this in `reconcile_service`; xfa.1 and 5lw must not
re-merge families.

**Recently landed, relevant:** #154 (node address roles: underlay vs
fronts), #157 (`Endpoint.node_addrs`, `controller/src/reconcile.rs:218`, node
identity decided against the set), #158 (configurable `NODE_ALLOW`/`POD_TARGETS`
caps; `capacity_hint` in `src/lib.rs:346`), #156 (egress pass-on-miss).

## 2. Target schema (this IS the xfa.1 schema)

Two maps replace `LB_FRONT_MAP` + `TARGET_PORTS`; `POD_TARGETS` stays.

```rust
// beep-common, all #[repr(C)], explicit padding, no layout surprises
struct FrontMeta { ready_count: u32, flags: u32 }          // flags: IS_LOCAL
struct FrontEndpointKey { front: LbFrontKey, slot: u16 }   // 22 bytes, align 2
struct FrontEndpoint { backend: LbFrontBackend, target_port: u16, _pad: u16 }
// FRONT_META: HashMap<LbFrontKey, FrontMeta>
// FRONT_ENDPOINTS: HashMap<FrontEndpointKey, FrontEndpoint>
```

- `LbFrontBackend` and `ForwardFlowValue` stay **byte-identical**: the pin
  keeps `{backend_node_ip, pod_ip}` + ifindex, so the `FLOW_TABLE` value
  size, the union readers and the beep-03i eviction sweep are untouched.
  `target_port` lives in the endpoint value, not in the pin.
- `IS_LOCAL` means "this node owns this FRONT address" only. Front and
  underlay address sets stay separate: `backend_node_ip`, `NODE_ALLOW` and
  the return-leg ingress node are underlay concepts and never derive from
  the front set.
- Map count stays 8 (two replace two), so the memory-assert name list swaps
  names but keeps its length. `FRONT_ENDPOINTS` is larger than the old map
  (key 22 B + value 36 B per row, one row per front x endpoint); size its
  default from the design doc's <1000-endpoint budget
  (`docs/design/ebpf-lb-dataplane.md:131-132` already budgets a front-IP map
  and a separate endpoint map) and re-measure against the 4 MiB ceiling
  (`assert-ebpf-map-memory.sh:61`) with a live `bpftool map show`.
- Capacity follows the existing pattern (answers the old Q5): one
  `--*-max-entries` flag per new map (replacing `--lb-front-map-*` and
  `--target-ports-*`), pinned-at-creation semantics, and `capacity_hint`
  extended to name both so an `E2BIG` is fail-loud.

**xfa.1 behaviour (count = 1):** ingress does `FRONT_META.get(front)`, then
`FRONT_ENDPOINTS.get((front, 0))`; decap does the same slot-0 lookup for
`target_port`. A meta miss or `ready_count == 0` is today's miss path. The
controller writes `ready_count = 1` and slot 0 = the existing pick.

**Apply ordering (needed even at count 1):** write the endpoint row before
raising the count; lower the count before deleting rows. A reader that sees
count > rows gets an endpoint miss and drops that packet, same as today's
fail-closed convention; it must never read a stale row as valid.

## 3. Selection and the affinity pin (the correction)

**Selection:** a pure `beep-common` fn
`select_backend_slot(client_ip: [u8;16], client_port, front: &LbFrontKey,
ready_count: u32) -> Option<u32>` using the bit-mixing style of
`synthetic_port_seed` (`common/src/lib.rs:800`), no hashing crate. 16-byte
addresses, not the old `u32` signature, because fronts are dual-stack.
Deterministic, stateless, same answer on any CPU/node; round-robin needs a
shared mutable cursor and Maglev's permutation table buys little at beep's
scale because the pin carries stability.

**Verified: the pin stores the backend, not the slot -- but ingress does not
steer from it.** `ForwardFlowValue.backend` (`common/src/lib.rs:301-304`)
holds `{backend_node_ip, pod_ip}`; no slot index exists anywhere in
conntrack. However ingress re-resolves the front on **every** packet
(`ebpf/src/main.rs:611`, `:753`) and uses that fresh `backend` for the Geneve
remote (:655, :786) and pod option (:674); `fwd_pending_affinity_pin`
(`common/src/lib.rs:458`) only guards what is *written* into `FWD_PENDING`,
and the pinned `backend` is read back only by eviction
(`src/lib.rs:229-238`) -- the decap-return path reads just `ingress_ifindex`
(`:1420`). Today that is harmless (one backend per front). With N endpoints,
any change to N or to slot order would re-steer **established** flows to a
different pod mid-connection. So 5lw must change ingress to: established
(`FLOW_TABLE` forward hit) -> use the pinned backend; pending hit -> use the
pending backend; miss -> hash to a slot and pin. The ADR's "later packets
follow the stored pin" is only true once that lands.

## 4. Composition with eviction (implemented)

Epic beep-03i is closed: on endpoint removal the controller prunes
`POD_TARGETS` and runs `evict_pod_flows` (`src/lib.rs:273`, called from
`controller/src/apply.rs:231-257`), sweeping `FWD_PENDING` and `FLOW_TABLE`
Forward/Reverse/PortMemo rows by departed `pod_ip` (`stale_forward_entries`
keys on `value.backend.pod_ip`, `src/lib.rs:229`; reverse/port-memo on the
key's pod address, :249). Smoke step "evict-pod" (`scripts/smoke.sh:30`)
proves it on a live kernel. Consequences for this plan:

- Eviction keys on pod address, so the same pod behind several fronts is
  swept in one pass; no endpoint-table coupling.
- With pin-steering (section 3), a removed endpoint's flows are deleted, the
  next packet misses, and the hash picks a surviving slot -- the intended
  re-home. Without pin-steering, eviction would be the only thing keeping
  established flows off a re-numbered slot, which it is not designed to do.
- The remaining window is between the endpoint row disappearing and the
  sweep: new flows hash only over rows that exist (count lowered first),
  so they cannot select the departed pod.

## 5. Controller

`reconcile_service` (`controller/src/reconcile.rs:389`) already has every
ready endpoint in `candidates`. 5lw replaces the pick-one with: filter to
the front's address family (beep-39a), sort by `pod_ip` (stable slots for the
same input), emit `FRONT_ENDPOINTS[(front, i)]` per candidate and
`FRONT_META[front].ready_count = len`. `diff`/`MapOp` are generic over
key/value and `lb_front_backend_eq` (:494) compares the backend part; the
endpoint-value comparison must include `target_port`. The existing tests
encode pick-one and need rewriting. The watch layer parses only the first
address per endpoint, `nodeName` and `conditions.ready`
(`controller/src/watch.rs:262-266`); it does not parse `targetRef`.

## 6. Bead breakdown

**(a) beep-xfa.1 -- shape, count = 1, behaviour-preserving (increment
~8-12h on top of the consolidation it already owns):**

1. common: `FrontMeta`, `FrontEndpointKey`, `FrontEndpoint` + layout tests
   (no padding, round-trip) (S, 2-3h).
2. ebpf: two maps, v4/v6 ingress and v4/v6 decap switched to
   meta -> slot 0 (M, 3-4h incremental).
3. controller + loader: emit meta + slot 0, two-map apply ordering, fixture
   population, `--*-max-entries` flags and `capacity_hint`, memory-assert
   names (S/M, 3-5h incremental).

**Where xfa.1 stops (scope-creep risks).** Out of xfa.1, each with the
temptation that causes the creep:

- `ready_count > 1` or any hash: tempting because the table is right there;
  xfa.1 asserts count == 1 in tests and the controller keeps the lowest-pod
  pick.
- Pin-steering at ingress: tempting while editing the same lines
  (`:611`/`:753`); it changes forward-path semantics and needs its own
  smoke (5lw).
- Carrying `target_port` in the Geneve option so decap drops its front
  lookup: tempting because xfa.1 already touches decap; it changes the wire
  option length and both ends (5lw, Q2).
- Changing `LbFrontBackend`/`ForwardFlowValue` layout (e.g. folding
  `target_port` into the pin): breaks the `FLOW_TABLE` value size and the
  03i union readers.
- Family filtering (beep-39a), weights, terminating endpoints, BackendId/UID.
- Legacy front-address renames: bound to `LbFrontKey`/`RevFlowValue`
  fields and the code the new types touch; a repo-wide rename of every test
  literal is the likeliest source of diff bloat -- split it if it exceeds
  the shape change itself.

**(b) beep-5lw -- behaviour (~23-37h):**

1. common: `select_backend_slot` + determinism/distribution tests (S, 2-3h).
2. ebpf: pin-steering at ingress, hash on miss, v4+v6 (M, 6-9h). Largest
   verifier/correctness surface; needs the established-flow stability test.
3. decap target_port per endpoint (Geneve option or slot match), v4+v6
   (M, 5-8h); only if Q2 resolves to per-endpoint.
4. controller: emit all ready endpoints per front-family, two-map diff
   ordering, rewrite pick-one tests (M/L, 6-10h).
5. smoke: 2+ pods behind one front, assert traffic lands on more than one
   and that endpoint removal re-homes only the removed pod's flows (M, 3-5h;
   Linux/Lima only).
6. docs: sizing table, packet-flow note (`ebpf-lb-dataplane.md:55`) (S, 1-2h).

Suggested priority: P2 -- a load balancer that fronts one backend per
Service is not yet doing what its name promises.

## 7. Open questions for the operator

**1. New identity needed? (Mayor analysis, verified.) No.**
- Fronts are already keyed by `LbFrontKey` (front address + port + proto).
- Backends are already identified by `(pod_ip, target_port)`: the pin stores
  `pod_ip` (section 3), eviction keys on it (section 4), and
  `FrontEndpoint` carries both. Verified differences from the mayor note:
  eviction matches `pod_ip` alone, not the pair, which is correct (a departed
  pod takes every port with it).
- `targetRef.uid` (Pod UID) exists on EndpointSlice endpoints but the
  controller does not parse it (`watch.rs:262-266`); nothing in the
  dataplane needs it. Use it only if controller-side diffing across pod-IP
  reuse proves ambiguous.
- The "renumbering vs BackendId" fork is not an identity gap. Hash-mod-N
  needs dense positions 0..N-1 and a UID cannot be an array index; Cilium's
  BackendId exists to keep positions stable. Because the pin stores the
  backend (not the slot) and, after 5lw's pin-steering, ingress follows the
  pin, renumbering re-maps only NEW flows.
- **Recommendation:** per-front slot renumbering, identity `(pod_ip,
  target_port)`, no BackendId table. Maglev is the later upgrade if churn
  matters; it also needs no new identity.
- Caveat: "renumbering only re-maps new flows" holds only after 5lw's
  pin-steering lands (section 3); until then it is false.

**2. Where does `target_port` live, and how does decap find it? (Before
xfa.1.)** Operator direction puts it in the endpoint value. At count 1 decap
reads slot 0. At N the backend node only knows the front and `pod_ip`, not
the slot, and named ports can resolve differently per pod. Options: (a)
carry `target_port` in the Geneve option beside `pod_ip` (removes decap's
front lookup entirely; recommended, 5lw); (b) require all endpoints of a
front to share one port and drop disagreeing ones (simple, loses named-port
semantics); (c) scan slots for the `pod_ip` match (a loop; avoid). xfa.1 only
needs agreement that `target_port` is in the endpoint value and decap uses
slot 0 for now.

**3. Same pod behind several fronts? (Before xfa.1; answer: no dedup.)**
Each front owns its own rows. Acceptable at the declared scale; eviction
already sweeps by pod address. Schema-neutral.

**4. Weights. (Before 5lw only.)** `Endpoint`
(`controller/src/reconcile.rs:212`) has no weight. Recommend unweighted for
v1; `FrontEndpoint._pad` can hold a weight later without a size change, so
this is not schema-affecting now.

**5. Terminating-but-serving endpoints. (Before 5lw only.)** Only
`conditions.ready` is tracked (`watch.rs:265`, defaulting to true).
Recommend excluding terminating endpoints from the selectable set; already
pinned flows are unaffected by that choice (pin-steering) and are cleaned up
by eviction when the pod goes away. No per-endpoint flag needed.

**6. `max_entries` defaults. Resolved:** follow the `--*-max-entries`
pattern (section 2) unless the memory re-measure rules a default out.
