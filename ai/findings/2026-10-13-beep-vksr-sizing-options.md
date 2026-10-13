<!-- Bead: beep-vksr -->
# FRONT_ENDPOINTS sizing options (beep-vksr)

Bead: beep-vksr. Written 2026-10-13T10:55Z against main b125573.

**Summary:** decide (1) the default endpoint capacity (recommend 2048 fronts / 16384 rows, i.e. 4 endpoints per front at 2 generations), (2) swap headroom (recommend keeping the global 2x pool, but sizing it against `N_live + N_prev` per front, not `2 x live`, because the current code keeps the previous generation resident), and (3) the memory tripwire (recommend ~5.75 MiB for that sizing, replacing the interim 6 MiB; a deterministic prealloc footprint needs only ~15% margin).

Numbers are labelled **[measured]** (CI / repo docs) or **[estimate]** (my arithmetic). I ran no VM and no new CI.

## Facts the decisions rest on

- **Every map preallocates.** All 10 maps in `ebpf/src/main.rs` are declared `with_max_entries(N, 0)`: flags 0, no `BPF_F_NO_PREALLOC`. `max_entries` is the memory cost. The loader and controller already override each of the six sized maps via `--front-meta-max-entries`, `--front-endpoints-max-entries` etc. (`src/main.rs:223-240`, `controller/src/main.rs:111-136`).
- **Per-entry cost [estimate, validated below].** Kernel hash element = 48 B header + key rounded to 8 + value rounded to 8; plus 16 B bucket (buckets round up to a power of two).
  - `FRONT_ENDPOINTS`: key 28 -> 32, value 40 -> 120 B/elem, 136 B/entry incl. bucket.
  - `FRONT_META`: key 20 -> 24, value 8 -> 80 B/elem, 96 B/entry.
  - `FLOW_TABLE` (LRU): key 38 -> 40, value 36 -> 40 -> 128 B/elem, 144 B/entry; `FWD_PENDING` the same.
- **Model check.** Model total for the current defaults = 2,359,296 (FLOW_TABLE) + 294,912 (FWD_PENDING) + 1,114,112 (FRONT_ENDPOINTS) + 393,216 (FRONT_META) = 4,161,536 B. **[measured]** total in main CI run 38385070814 (2026-10-13T10:41Z) is 4,185,688 B. The 24,152 B residual fits the small maps (POD_TARGETS, NODE_ALLOW, UPLINK_CONFIG, CONFIG, per-CPU arrays). The design doc's measured "~1.06 MiB" and "~385 KiB" for the two front maps match 1,114,112 and 393,216.
- **What memory-smoke measures.** `scripts/sample-ebpf-memory.sh once` runs `bpftool map show id <id> --json` on every map referenced by the pinned programs and records `bytes_memlock` (the kernel's per-map memory usage, which for preallocated hashes counts full `max_entries`). `scripts/assert-ebpf-map-memory.sh` sums them and checks the set is exactly 10 maps. So the measurement includes preallocation and tracks the loader defaults automatically (the smoke fixture uses defaults). It is blind to loader/controller RSS; that is gated separately in `scripts/controller-rss.sh` (baseline ceiling 16384 kB, growth ceiling 4096 kB; measured ~6.8 MiB).
- **Tripwire today:** `scripts/assert-ebpf-map-memory.sh:58-59`, `limit=$((6 * 1024 * 1024))` = 6,291,456 B, an "interim" ~1.5x of the measured 4,185,352 (now 4,185,688). Run via the `memory-smoke` job in `.github/workflows/ci.yaml` (step at ~:296-297).
- **Front-count formula.** `FRONT_META` holds one row per (node front address x Service port/proto) and every node holds the full map (`ebpf-lb-dataplane.md:131-132`). So live endpoint rows = A x E, where A = node front addresses and E = sum over Services of (ports x ready same-family endpoints). beep-5lw.6 emits all ready endpoints into every one of a Service's fronts, so each endpoint is stored once per front, not once per cluster.

## Finding that changes the bead's premise

The bead assumes only fronts mid-swap need double slots. The code keeps the previous generation resident indefinitely: `plan_front_writes` for an unchanged front deletes only generations other than `g` and `g-1` (`src/front_swap.rs:113-122`, header comment `:21`), and the next real change deletes `g-1` as its first step before writing `g+1`. So any front that has swapped at least once holds `N_live + N_prev` rows in steady state, not just during a swap. A scale-down 10 -> 2 holds 12 rows for that front. `2 x live` is therefore not an upper bound; `sum(N_live + N_prev)` is. The count-0 test (`front_swap.rs:459-477`) pins that the previous rows survive on purpose "for decap of pinned flows".

## Decision 1: default endpoint capacity (and max fronts)

Real shapes (all **[estimate]**, no field data in the repo beyond the cluster description):
- Named target (`docs/design/cni-svclb-landscape.md:8-10`): 5 nodes (the doc itemises 2+1+3 = 6), 1 GB / 1 vCPU each, IPv6-only on Scaleway. Say 6 nodes, up to 12 front addresses, ~20 LoadBalancer ports, 1-3 replicas: ~12 x 20 = 240 fronts, ~700 live rows, ~1.4k at 2 generations. Fits today's 8192 about 5x.
- u7s envelope (`ebpf-lb-dataplane.md:139-141`): <10 nodes, <100 Services, <1000 endpoints: up to 10 x 1000 = 10k live rows (dual-stack pods up to ~2x), 20k+ at 2 generations. Today's 8192 does NOT cover this once beep-5lw.6 lands.
- Upper code-comment bound (`src/lib.rs:393-395`): 100 nodes x 40 ports = 4096 fronts; at 3 replicas that is 12,288 live rows, 24,576 at 2 generations.
- k8s: Deployments are typically 2-3 replicas at small scale, HPA'd services 5-10+; one EndpointSlice holds up to 100 endpoints. `slot` is u16, so no format limit.

Totals below hold all other maps at the modelled 2,678,360 B (measured total minus modelled front maps). Total = that + META + ENDPOINTS.

| Option | fronts / rows | META | ENDPOINTS | Total eBPF map memory | Covers |
|---|---|---|---|---|---|
| 1 status quo | 4096 / 8192 | 393,216 | 1,114,112 | **4,185,688 [measured]** (3.99 MiB) | 1 endpoint/front only; named target OK |
| 2 | 2048 / 16384 | 196,608 | 2,228,224 | 5,103,192 [estimate] (4.87 MiB) | 4 endpoints x 2048 fronts x 2 gens; named target with large headroom |
| 3 | 4096 / 32768 | 393,216 | 4,456,448 | 7,528,024 [estimate] (7.18 MiB) | 4 endpoints x 4096 fronts x 2 gens; whole u7s envelope |
| 4 | 4096 / 65536 | 393,216 | 8,912,896 | 11,984,472 [estimate] (11.43 MiB) | 8 endpoints x 4096 fronts x 2 gens |

Trade-offs: on 1 GB nodes the largest delta (option 3, +3.3 MiB) is ~0.3% of RAM, so the real cost of oversizing is the operator's "as low as justified" preference and the tripwire value; the cost of undersizing is a loud `E2BIG` plus stale serving (Decision 2). Non-power-of-two row counts waste bucket memory (20,480 rows still allocate 32,768 buckets), so keep powers of two. Loader RSS also scales with rows, since `apply_fronts` reads both maps into std `HashMap`s every tick [estimate: roughly 1.5 MB at 16k rows, 3 MB at 32k, 6 MB at 64k; against a 4096 kB growth ceiling that option 4 would likely trip].

**Recommendation: option 2** as the default (small-cluster sized, documented formula `fronts x endpoints x 2`), raised by flag; option 3 if the operator wants the full u7s envelope out of the box. Replace the `2 * DEFAULT_FRONT_META_MAX_ENTRIES` coupling (`src/lib.rs:400`) with explicit constants.

Configurability: flags already exist for both maps on both binaries, so no new flag is needed to override. Open question: expose a derived knob (`--max-fronts` and `--endpoints-per-front`, computing both maps and the generation factor) instead of two raw row counts. Pre-1.0 it is free to change; raw counts keep the tripwire arithmetic obvious, a derived knob matches how operators think. Either way the `capacity_hint` text should state the formula.

## Decision 2: swap headroom, global vs per-front

How a swap works (`src/front_swap.rs:9-14, 105-155`): per front, delete every generation except `g`; write all N slots under `g+1`; single `FRONT_META` replace commits. Fronts are applied one at a time (`apply_fronts` loops plans sequentially, `:211`), in `HashSet` (random) order. Transient peak is `N_live + N_new` for the front being swapped; steady state after commit is the same pair, so concurrency adds nothing beyond `sum(N_live + N_prev)`.

When the map is full: a `PutEndpoint` returns `E2BIG`, `run_front_plan` sets `commit_blocked`, the `FRONT_META` commit is skipped and the front stays on its old generation (**fail-stale, not fail-closed, not a mix**). Rows already written under `g+1` linger until the next plan deletes them first. `apply_front_maps` (`controller/src/apply.rs:200-223`) logs per-front errors and returns one reconcile error, which retries with backoff, but a retry frees nothing net, so it keeps failing until the cap is raised (a changed cap recreates the pinned map on the next start per `capacity_hint`). A brand-new front gets no `FRONT_META` row at all: its traffic passes to the host.

Eviction interaction (beep-03i / #200, #203, #208, #209): the controller sweeps conntrack for a departed pod before writing fronts that name it, then deletes its `POD_TARGETS` row. If the following front swap fails with `E2BIG`, the stale generation still lists the departed pod; new flows hashed to it are dropped at the backend's decap (`POD_TARGETS` check), i.e. roughly 1/N of new flows to that front blackhole while the cap is exhausted. Because order is random, under pressure random fronts starve, not the least important ones. #208 keeps drained fronts at count 0, so scaled-to-zero Services keep their meta and previous rows, and their capacity use never shrinks.

| Option | Capacity rule | Pros | Cons / failure under a large rollout |
|---|---|---|---|
| A. Global 2x pool, retention unchanged | `fronts x N_max x 2` | Zero code change; reader-safe | Overflow is all-or-nothing by arrival order; the bound must be `sum(N_live+N_prev)`, so HPA flapping 1<->10 exceeds `2 x live`. Memory spent on a headroom that is permanent, not transient |
| B. Userspace admission / per-front cap | Controller clamps endpoints per front (e.g. 64) and checks `sum(N_live+N_prev)+N_new <= cap` before swapping | Makes overflow deterministic and loud before any write; bounds the worst front | Clamping silently drops endpoints (needs an event/metric); new code in controller |
| C. Drop `g-1` after commit (grace), size `live + margin` | rows = live + largest `N_new` (swaps are sequential, so margin is one front, ~100 rows) | Roughly halves capacity: option 2 needs 8192 rows (1,114,112 B) instead of 16384, saving ~1.1 MiB [estimate]; option 3 saves ~2.1 MiB | Needs a time-based grace (a reader that loaded old meta must still find `g`; a miss is one dropped packet and `FRONT_MISSES++`); count-0 case relies on previous rows (may soften if beep-5lw.4 moves `target_port` into the Geneve option). Per-front *reservation* is not expressible in a hash map; only A-with-admission (B) approximates it |

**Recommendation: A + B-lite:** keep the global pool and retention (correct and tested), size it per Decision 1, and add a pre-write capacity check that fails the reconcile before any front is touched. Revisit C only if memory pressure appears; the saving is ~1 MiB on a 1 GB node, which does not justify a race window. This is the operator's call.

## Decision 3: re-derive the tripwire

The footprint is deterministic (preallocation), so margin only has to absorb kernel/runner variance (per-CPU arrays scale with CPU count; elem header differs by kernel), not workload. The prior interim 6 MiB is 1.50x measured. The bead says "~2x measured", but 2 x 4.19 MB = 8.4 MB would raise the ceiling, contradicting the operator's "as low as justified". I used 1.15x rounded up to 0.25 MiB:

| Sizing | Expected | Tripwire (1.15x, rounded) |
|---|---|---|
| Option 1 | 4,185,688 [measured] | 4.75 MiB (4,980,736) |
| Option 2 | 5,103,192 [estimate] | **5.75 MiB (6,029,312)**, below today's 6 MiB |
| Option 3 | 7,528,024 [estimate] | 8.5 MiB (8,912,896) |
| Option 4 | 11,984,472 [estimate] | 13.25 MiB (13,893,632) |

Pick the tripwire from the chosen option; re-measure with the real memory-smoke run before fixing it (estimates carry ~0.6% model error). If Decision 2 picks C, subtract the saving above. Also stale: the CI step title says "exactly the 7 known maps" while the script asserts 10 (`.github/workflows/ci.yaml:296`), and the design doc's "~1-2 MiB" flow-map line (`ebpf-lb-dataplane.md:135`) is ~2.6 MiB measured (FLOW_TABLE 2.25 MiB + FWD_PENDING 0.28 MiB).

## Questions for the operator

1. Default capacity: option 2 (16384 rows) or option 3 (32768 rows)?
2. Headroom: A (+B-lite) or C?
3. Tripwire margin: 1.15x as proposed, or looser?
4. Knobs: keep two raw `--*-max-entries` flags, or add derived `--max-fronts` / `--endpoints-per-front`?
