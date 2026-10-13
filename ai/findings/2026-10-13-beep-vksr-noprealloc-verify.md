# Verify BPF_F_NO_PREALLOC for FRONT_META / FRONT_ENDPOINTS

Bead: beep-vksr
Date: 2026-10-13

**Answer: yes, `BPF_F_NO_PREALLOC` is viable on both maps (loads, passes the
verifier, forwards on 6.6, 6.8 and 6.12) and cuts the two maps from 1.51 MB to
~0.20 MB in the 11-fixture smoke, but memory is not free: a fixed ~196 KB
bucket floor stays (it scales with `max_entries`), a full map costs 6-8% MORE
than preallocated, and one thing must change in the loader or an upgrade
silently keeps the old preallocated maps.**

Base: main at b283f9a (includes #229). Spike branch
`spike/beep-vksr-noprealloc` (two-line flag change; draft PR #232, closed
unmerged).

## Q1 Who writes these maps?

Only userspace. In `ebpf/src/main.rs` the maps are defined at :160
(FRONT_META) and :174 (FRONT_ENDPOINTS), and every use goes through two
helpers: `FRONT_META.get_ptr` (:397) and `FRONT_ENDPOINTS.get_ptr` (:403).
The only `.insert(`/`.remove(` calls anywhere in `ebpf/src` target
FWD_PENDING and FLOW_TABLE (`git grep -nE "\.(insert|remove)\("`). The writers
are `src/front_swap.rs` (`apply_fronts`, `endpoints.insert/remove`,
`meta.insert/remove`) driven by the controller. So the dataplane never
allocates in these maps.

## Q2 Map types

Both are `BPF_MAP_TYPE_HASH` (aya `HashMap`, not LRU, not array;
`bpftool map show` reports `"type":"hash"` on all three kernels).
`BPF_F_NO_PREALLOC` is valid for them; no array alternative is needed.
Keys/values (bpftool): FRONT_META key 20 B / value 8 B; FRONT_ENDPOINTS key
28 B / value 40 B.

## Q3 aya support

- eBPF side: `HashMap::with_max_entries(max_entries, flags)` takes the flags
  directly (aya-ebpf 0.2.1 `src/maps/hash_map.rs:25`, `flags: u32`).
  `BPF_F_NO_PREALLOC` is `1` (`aya-ebpf-bindings .../bindings.rs:851`). The
  spike passes `1` in place of `0` at `ebpf/src/main.rs:160,175`.
- Loader: `loader.map_max_entries(name, size)` at `src/lib.rs:475` (fed by
  `--front-meta-max-entries` / `--front-endpoints-max-entries`) changes only
  `max_entries`; the flags in the object survive. Confirmed: the loaded map
  reports `flags 1` with max_entries 4096/8192.
- **Gotcha (verified live, beep-smoke 6.12):** aya reuses any pinned map
  without comparing flags (`aya-0.14.0 src/maps/mod.rs:885`), and
  `MapShape` (`src/lib.rs:490`) compares only type/key/value/max_entries, so
  `recreate_mismatched_pins` does not notice a flag change. Starting the
  prealloc binary and then the no-prealloc binary on the same `--pin-dir`
  left `{"flags":0,"bytes_memlock":394232}`: every already-deployed node would
  keep the preallocated maps after upgrade. `MapShape` needs a `map_flags`
  field (pre-1.0: recreate on mismatch, same as the other fields).

## Q4 Live measurement

Method: `/tmp/measure.sh` (kept out of the repo) loads the loader against a
veth + geneve0, reads `bpftool map show -j` `bytes_memlock`. (a) prealloc
binary, 11 `--fixture`s (the smoke fixture count); (b) no-prealloc, 1 fixture
(the loader refuses zero fixtures, so "empty" is 1 entry); (c) no-prealloc,
11 fixtures; (d) (b) plus 1000 synthetic entries via `bpftool map update` into
each map (1001 entries each).

| bytes_memlock | 6.8.0-146 (beep-node-a) META / ENDPOINTS | 6.12.111 (beep-smoke) META / ENDPOINTS |
|---|---|---|
| (a) prealloc, max 4096 / 8192 | 394,416 / 1,115,392 | 394,232 / 1,115,168 |
| (b) no-prealloc, 1 entry | 66,648 / 132,224 | 66,552 / 132,128 |
| (c) no-prealloc, 11 fixtures | 67,528 / 133,504 | 67,432 / 133,408 |
| (d) no-prealloc, 1001 entries | 154,648 / 260,224 | 154,552 / 260,128 |
| (e) no-prealloc, full (4096 / 8192) | 427,008 / 1,180,672 | 426,912 / 1,180,576 |

The reported number tracks real usage on both kernels:

- Marginal cost: META (154,552-66,552)/1000 = 88 B/entry; ENDPOINTS
  (260,128-132,128)/1000 = 128 B/entry. (c)-(b) = 880 B = 10 x 88, matching.
- Floor: 66.5 KB = 4096 buckets x 16 B + header; 132 KB = 8192 x 16 B + header.
  The bucket array is allocated up front (`roundup_pow_of_two(max_entries)`),
  so `max_entries` is NOT free: ~196 KB at the default caps.
- Prealloc was 96 B / 136 B per max-entry (394,232/4096, 1,115,168/8192).
  At full occupancy no-prealloc is +8.3% (META) and +5.9% (ENDPOINTS) over
  prealloc (per-element `llist_node` overhead). 6.8 and 6.12 differ by
  <=200 B.
- (e) was filled with one `bpftool batch` process (4096/8192 updates in
  13/30 ms on 6.8), then the next insert failed with E2BIG ("Argument list too
  long"). No ENOMEM occurred in a burst at the cap.
- Full smoke: `scripts/smoke.sh --vm beep-smoke` with the spike: **rc=0**,
  VERIFIER-ACCEPT, round trips, restart preservation, eviction and pin
  steering all PASS; its memory CSV shows FRONT_META 67,432 /
  FRONT_ENDPOINTS 133,408 (so the flags took effect inside the real harness).
- CI on the spike (draft PR #232, run 38393858407): all green including
  `kernel-smoke` 6.6 (guest 6.6.158), 6.12 and latest, and `memory-smoke`:
  `total bytes_memlock: 2877208` for all 10 maps (the 6 MiB ceiling in
  `scripts/assert-ebpf-map-memory.sh` is unchanged and trivially met).

**6.6.** Functionally proven by the 6.6.158 kernel-smoke leg above (loads,
verifies, forwards; no-prealloc hash is also accepted for sched_cls). For
memory accounting, kernel source at tag v6.6 (`kernel/bpf/hashtab.c:2209`,
`htab_map_mem_usage`) already has the `if (prealloc) ... else
num_entries = atomic_read(&htab->count)` split, i.e. usage-based. I did not
read a live `bytes_memlock` on 6.6 (the CI leg does not print it), so on 6.6
the usage-tracking is source-derived, not measured.

## Q5 Behavioural differences

- **Lookup cost.** Not benchmarked. Both modes run the same
  `__htab_map_lookup_elem` (v6.6 `hashtab.c:667`: hash, bucket, nulls-list
  walk); preallocation only changes element allocation. Expect no difference
  beyond cache locality (prealloc elements are one contiguous block).
- **Update path / ENOMEM.** Non-prealloc updates call `bpf_mem_cache_alloc`
  (`hashtab.c:1028`) and return `-ENOMEM` on failure (:1030). This is a NEW
  failure mode: with prealloc, replacing an existing key reuses a per-cpu
  spare element (:1005-1009) and cannot fail on memory, whereas no-prealloc
  allocates the new element before freeing the old one, so even the
  `FRONT_META` replace that is the commit point of a generation swap can
  ENOMEM. `E2BIG` (map full) still exists in both modes (:1014).
- **How failures are handled today.** `run_front_plan`
  (`src/front_swap.rs:171`) records any failed step; a failed
  `PutEndpoint` suppresses the META commit, so the front stays on its previous
  generation (fail-stale); `apply_front_maps` (`controller/src/apply.rs:206`)
  logs per front and returns an error. Both ENOMEM and E2BIG take this same
  path, so no new handling is required for safety. The pre-write capacity
  check decided earlier covers only the E2BIG case (count vs. max); it cannot
  predict ENOMEM. Two nits: the log text says "map may be at capacity"
  (`apply.rs:211`) and the hint is `capacity_hint` (`src/lib.rs`), both wrong
  for ENOMEM; and ENOMEM is transient, so the retry on the next reconcile is
  what recovers (I did not verify the controller's reconcile cadence).
  bpf_mem_alloc's per-cpu cache can also fail transiently without memcg
  pressure; I did not reproduce that (burst fill to cap was clean).
- **Verifier / prog type.** The old "tracing progs may only use preallocated
  maps" rule (`verifier.c` v5.15:11408) is gone in v6.6 (no `prealloc`
  strings in v6.6 `verifier.c`) and never applied to tc. Verified: sched_cls
  loads and forwards on 6.6, 6.8, 6.12.

## Q6 Consequences for the decided items

- **1.15x tripwire.** Define it on usage, not cap: expected =
  `bucket_floor(max_entries) + entries x per-entry`, using the measured
  88 B (META) and 128 B (ENDPOINTS) and a floor of `16 x roundup_pow2(max)`
  plus ~0.1-1 KB header. For the smoke fixture that is ~200.8 KB for the two
  maps (6.12/6.8 measured 200,840 / 201,032). A cap-based worst case would
  not trip on a real regression because actual use is far below it; a
  fixture-usage expectation will (1.15x of ~200.8 KB is a ~30 KB band; a
  per-entry growth from 88 B to ~190 B across the 11 smoke entries would stay
  inside it, so the floor term dominates and the tripwire mainly guards
  `max_entries` / bucket-floor regressions, not per-entry bloat; a 1000-entry
  usage scenario would guard per-entry cost). `bytes_memlock` also folds in
  `num_possible_cpus()` terms and varies by arch/kernel. Keep the existing total-map ceiling in
  `assert-ebpf-map-memory.sh` as the gross check; today it is 6 MiB against
  2.88 MB measured.
- **Default caps.** Entries cost nothing until used, but the bucket floor
  does: ~16 B per cap entry rounded up to a power of two. At 4096/8192 that
  is ~196 KB; 2x the caps adds only ~196 KB more. A worst-case (cap) fill
  costs 427 KB + 1.18 MB, slightly more than prealloc, so caps are a ceiling
  on memory only in the sense of "<= ~1.6 MB". A cap just above a pow2
  boundary doubles the bucket array, so choose caps at or just below a power
  of two (4096, 8192; not 5000).
- **Previous generation.** Still matters, but as usage, not as reservation:
  `plan_front_writes` keeps generation `g-1` until the next swap
  (`src/front_swap.rs:113-139`), so steady state holds up to 2 x N endpoint
  rows. Count that when computing expected usage (128 B x 2 per front-slot)
  and when sizing `--endpoints-per-front`; the E2BIG pre-write check must
  count both generations.

## Q7 Recommendation

Adopt `BPF_F_NO_PREALLOC` for FRONT_ENDPOINTS and FRONT_META, with these
conditions:

1. Add `map_flags` to `MapShape` / `map_shape_mismatches` so existing pins
   created without the flag are recreated on upgrade (verified failure mode
   above). Without this the change is a silent no-op on every upgraded node.
2. Define the tripwire per usage (above); do not size it from the caps.
3. Treat ENOMEM as a first-class cause in `apply.rs:211` and
   `capacity_hint` (same fail-stale path), so operators are not told to raise
   a cap that is not the problem.
4. Do not reuse this for FLOW_TABLE / FWD_PENDING (LRU hash: the kernel
   rejects the flag, and the dataplane writes those from tc).

Savings for a small cluster: ~1.31 MB per node today (1.51 MB -> 0.20 MB for
the smoke's 11 fronts); the remaining floor is ~196 KB at default caps. If
that floor also matters, the next-best option is loader-time sizing from the
derived `--max-fronts` / `--endpoints-per-front` flags (already how
`map_max_entries` works): the bucket array then shrinks with the cap, at the
cost of recreating the map (and a resync) to grow it. A map-of-maps resize
would remove that but adds an indirection to every packet and a swap protocol
for no gain at this scale.

Not verified: lookup latency under `BPF_PROG_TEST_RUN`; live `bytes_memlock`
on 6.6; ENOMEM under real memcg pressure.
