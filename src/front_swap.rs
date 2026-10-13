//! Generation-swap writer for `FRONT_META` + `FRONT_ENDPOINTS`.
//!
//! The dataplane reads `FRONT_META[front]` once per packet and then
//! `FRONT_ENDPOINTS[(front, meta.generation, slot)]`. `FRONT_META` is a
//! `BPF_MAP_TYPE_HASH`: replacing one element is atomic for concurrent
//! readers, so the single `FRONT_META` write is the commit point and a
//! reader sees either the old generation or the new one, never a mix.
//!
//! Per front, when (and only when) its endpoint set changes, with `g` the
//! live generation:
//!   1. delete every endpoint generation other than `g` (this includes
//!      `g-1` and any crash leftovers),
//!   2. write all slots under `g+1`,
//!   3. replace `FRONT_META[front]` with `{g+1, count, flags}`.
//!
//! At most two generations (`g`, `g+1`) of a front exist at any moment, and
//! the live one is never touched before the commit. If any step-2 write fails
//! the commit is skipped, so the old generation keeps serving. Deleting a
//! front drops `FRONT_META` first, then its endpoints; if that first delete
//! fails the endpoints are left alone.
//!
//! After a commit, `g` stays as `g-1` for a short grace (`RecentSwaps`) and
//! is then deleted: the only reader that can still want it is a packet that
//! loaded `FRONT_META` at `g` just before the commit and reads
//! `FRONT_ENDPOINTS` microseconds later. Established flows read their pin,
//! not these maps. A front with unchanged endpoints therefore produces no
//! writes except deleting every generation but the live one (and `g-1` while
//! it is within its grace), which is also what cleans up a previous process's
//! crash leftovers on startup.

use std::{
    borrow::BorrowMut,
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use aya::maps::{HashMap as AyaHashMap, MapData, MapError};
use beep_common::{FrontEndpoint, FrontEndpointKey, FrontMeta, LbFrontKey, ENDPOINT_FLAG_IS_LOCAL};

/// The endpoint set a front should have. Slot `i` is `endpoints[i]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DesiredFront {
    pub flags: u16,
    pub endpoints: Vec<FrontEndpoint>,
}

impl DesiredFront {
    /// Length of the leading run of `ENDPOINT_FLAG_IS_LOCAL` slots. The
    /// dataplane hashes over exactly that prefix, so callers must order local
    /// endpoints first.
    pub fn local_count(&self) -> u16 {
        self.endpoints
            .iter()
            .take_while(|e| e.flags & ENDPOINT_FLAG_IS_LOCAL != 0)
            .count() as u16
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrontWrite {
    DeleteEndpoint(FrontEndpointKey),
    PutEndpoint(FrontEndpointKey, FrontEndpoint),
    PutMeta(LbFrontKey, FrontMeta),
    DeleteMeta(LbFrontKey),
}

/// The ordered writes for one front. Steps must run in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrontPlan {
    pub front: LbFrontKey,
    pub steps: Vec<FrontWrite>,
}

fn endpoint_key(front: LbFrontKey, generation: u32, slot: usize) -> FrontEndpointKey {
    FrontEndpointKey {
        front,
        generation,
        slot: slot as u16,
        _pad: 0,
    }
}

/// Plans the writes that take `(current_meta, current_endpoints)` to
/// `desired`. A desired front with no endpoints is kept as `count == 0`
/// (the dataplane rejects new flows to it and lets pinned ones drain); only a
/// front absent from `desired` is deleted. With `prune_absent`, fronts (and orphan endpoints) not in `desired` are
/// removed; without it, only fronts named in `desired` are touched.
/// `keep_previous` names fronts still inside their post-swap grace, whose
/// `g-1` rows an unchanged front must not delete yet.
///
/// Plans come back ordered by net endpoint-row change (shrinking fronts
/// first), then by front key: entries freed by a scale-down are available to a
/// scale-up in the same pass, and which front starves under pressure is
/// deterministic rather than hash-random.
pub fn plan_front_writes(
    current_meta: &HashMap<LbFrontKey, FrontMeta>,
    current_endpoints: &HashMap<FrontEndpointKey, FrontEndpoint>,
    desired: &HashMap<LbFrontKey, DesiredFront>,
    prune_absent: bool,
    keep_previous: &HashSet<LbFrontKey>,
) -> Vec<FrontPlan> {
    let mut endpoints_by_front: HashMap<LbFrontKey, Vec<FrontEndpointKey>> = HashMap::new();
    for key in current_endpoints.keys() {
        endpoints_by_front.entry(key.front).or_default().push(*key);
    }

    let mut fronts: HashSet<LbFrontKey> = desired.keys().copied().collect();
    if prune_absent {
        fronts.extend(current_meta.keys().copied());
        fronts.extend(endpoints_by_front.keys().copied());
    }

    let mut plans = Vec::new();
    for front in fronts {
        let existing = endpoints_by_front
            .get(&front)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let meta = current_meta.get(&front);
        let mut steps = Vec::new();

        match desired.get(&front) {
            None => {
                if !prune_absent {
                    continue;
                }
                if meta.is_some() {
                    steps.push(FrontWrite::DeleteMeta(front));
                }
                steps.extend(existing.iter().map(|k| FrontWrite::DeleteEndpoint(*k)));
            }
            Some(want) => {
                let count = want.endpoints.len() as u16;
                let local_count = want.local_count();
                let unchanged = meta.filter(|m| {
                    m.count == count
                        && m.local_count == local_count
                        && want.endpoints.iter().enumerate().all(|(slot, ep)| {
                            current_endpoints.get(&endpoint_key(front, m.generation, slot))
                                == Some(ep)
                        })
                });
                if let Some(m) = unchanged {
                    steps.extend(
                        existing
                            .iter()
                            .filter(|k| {
                                k.generation != m.generation
                                    && !(keep_previous.contains(&front)
                                        && k.generation == m.generation.wrapping_sub(1))
                            })
                            .map(|k| FrontWrite::DeleteEndpoint(*k)),
                    );
                    if m.flags != want.flags {
                        steps.push(FrontWrite::PutMeta(
                            front,
                            FrontMeta {
                                flags: want.flags,
                                ..*m
                            },
                        ));
                    }
                } else {
                    let live = meta.map(|m| m.generation);
                    let next = live.map_or(1, |g| g.wrapping_add(1));
                    steps.extend(
                        existing
                            .iter()
                            .filter(|k| Some(k.generation) != live)
                            .map(|k| FrontWrite::DeleteEndpoint(*k)),
                    );
                    for (slot, ep) in want.endpoints.iter().enumerate() {
                        steps.push(FrontWrite::PutEndpoint(
                            endpoint_key(front, next, slot),
                            *ep,
                        ));
                    }
                    steps.push(FrontWrite::PutMeta(
                        front,
                        FrontMeta {
                            generation: next,
                            count,
                            flags: want.flags,
                            local_count,
                            _pad: 0,
                        },
                    ));
                }
            }
        }

        if !steps.is_empty() {
            plans.push(FrontPlan { front, steps });
        }
    }
    plans.sort_by_key(|p| {
        let (net, ..) = plan_effect(p, current_meta.contains_key(&p.front));
        (net, p.front.front_ip, p.front.front_port, p.front.proto)
    });
    plans
}

/// Why a front write failed. The remedies differ: `Capacity` needs a bigger
/// cap, `OutOfMemory` is the kernel failing to allocate a map element (a
/// non-preallocated map allocates per insert, even when replacing a key) and
/// clears on its own, `Other` is anything else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureKind {
    Capacity,
    OutOfMemory,
    Other,
}

impl FailureKind {
    pub fn from_errno(errno: Option<i32>) -> Self {
        match errno {
            Some(libc::E2BIG) => Self::Capacity,
            Some(libc::ENOMEM) => Self::OutOfMemory,
            _ => Self::Other,
        }
    }

    fn of(error: &MapError) -> Self {
        match error {
            MapError::SyscallError(e) => Self::from_errno(e.io_error.raw_os_error()),
            _ => Self::Other,
        }
    }
}

/// aya's syscall errors display only the syscall name; the errno is what
/// tells E2BIG from ENOMEM.
fn describe(error: &MapError) -> String {
    match error {
        MapError::SyscallError(e) => format!("`{}` failed: {}", e.call, e.io_error),
        other => format!("{other:#}"),
    }
}

/// One failed front write: what failed and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrontFailure {
    pub kind: FailureKind,
    pub message: String,
}

/// Runs one front's plan through `write`, in order. Returns one failure per
/// failed step. A failed endpoint write suppresses the `FRONT_META` commit
/// (the old generation keeps serving); a failed `FRONT_META` delete
/// suppresses the endpoint deletes behind it (they would strand a live front).
pub fn run_front_plan(
    plan: &FrontPlan,
    mut write: impl FnMut(&FrontWrite) -> Result<(), MapError>,
) -> Vec<FrontFailure> {
    let mut failures = Vec::new();
    let mut commit_blocked = false;
    for step in &plan.steps {
        if commit_blocked && matches!(step, FrontWrite::PutMeta(..)) {
            continue;
        }
        if let Err(e) = write(step) {
            let what = match step {
                FrontWrite::DeleteEndpoint(_) => "FRONT_ENDPOINTS delete",
                FrontWrite::PutEndpoint(..) => "FRONT_ENDPOINTS write",
                FrontWrite::PutMeta(..) => "FRONT_META write",
                FrontWrite::DeleteMeta(_) => "FRONT_META delete",
            };
            failures.push(FrontFailure {
                kind: FailureKind::of(&e),
                message: format!("{what} failed: {}", describe(&e)),
            });
            match step {
                FrontWrite::PutEndpoint(..) => commit_blocked = true,
                FrontWrite::DeleteMeta(_) => break,
                _ => {}
            }
        }
    }
    failures
}

/// The `max_entries` of the two pinned front maps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrontCapacity {
    pub meta: u32,
    pub endpoints: u32,
}

/// How many entries the two front maps currently hold.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FrontUsage {
    pub meta: usize,
    pub endpoints: usize,
}

impl FrontUsage {
    fn apply(&mut self, step: &FrontWrite, front_had_meta: bool) {
        match step {
            FrontWrite::PutEndpoint(..) => self.endpoints += 1,
            FrontWrite::DeleteEndpoint(_) => self.endpoints = self.endpoints.saturating_sub(1),
            FrontWrite::PutMeta(..) if !front_had_meta => self.meta += 1,
            FrontWrite::PutMeta(..) => {}
            FrontWrite::DeleteMeta(_) => self.meta = self.meta.saturating_sub(1),
        }
    }
}

/// Net and peak change in entries a plan causes, run in step order:
/// `(endpoint net, endpoint peak, meta peak)`. The peak is what must fit under
/// the cap, since a plan's deletes run before its writes.
fn plan_effect(plan: &FrontPlan, front_had_meta: bool) -> (isize, usize, usize) {
    let (mut ep, mut ep_peak, mut meta, mut meta_peak) = (0isize, 0isize, 0isize, 0isize);
    for step in &plan.steps {
        match step {
            FrontWrite::PutEndpoint(..) => ep += 1,
            FrontWrite::DeleteEndpoint(_) => ep -= 1,
            FrontWrite::PutMeta(..) if !front_had_meta => meta += 1,
            FrontWrite::PutMeta(..) => {}
            FrontWrite::DeleteMeta(_) => meta -= 1,
        }
        ep_peak = ep_peak.max(ep);
        meta_peak = meta_peak.max(meta);
    }
    (ep, ep_peak as usize, meta_peak as usize)
}

/// Checks that `plan` fits under the caps before any of it is written. A plan
/// that would run the map out of room is refused whole, instead of writing a
/// partial new generation that then fails on `E2BIG` and lingers as dead rows.
pub fn capacity_shortfall(
    plan: &FrontPlan,
    front_had_meta: bool,
    used: FrontUsage,
    cap: FrontCapacity,
) -> Option<FrontFailure> {
    let (_, ep_peak, meta_peak) = plan_effect(plan, front_had_meta);
    let (map, need, used, max) = if used.endpoints + ep_peak > cap.endpoints as usize {
        ("FRONT_ENDPOINTS", ep_peak, used.endpoints, cap.endpoints)
    } else if used.meta + meta_peak > cap.meta as usize {
        ("FRONT_META", meta_peak, used.meta, cap.meta)
    } else {
        return None;
    };
    Some(FrontFailure {
        kind: FailureKind::Capacity,
        message: format!(
            "{map} has {used} of {max} entries used, but this front's update needs {need} more; \
             nothing written"
        ),
    })
}

/// What one pass over the front maps did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FrontApply {
    /// `(front, failure)` for every failed or refused step.
    pub failures: Vec<(LbFrontKey, FrontFailure)>,
    /// Fronts whose new generation was committed: their previous generation
    /// is now `g-1` and due for deletion after the grace.
    pub swapped: Vec<LbFrontKey>,
}

/// Runs every plan through `write`. Plans are independent, so a refused or
/// failed one never stops the others. `used` is tracked across plans, so a
/// plan that frees entries (run first, see `plan_front_writes`) makes room for
/// the ones after it.
pub fn run_front_plans(
    plans: &[FrontPlan],
    current_meta: &HashMap<LbFrontKey, FrontMeta>,
    mut used: FrontUsage,
    cap: FrontCapacity,
    mut write: impl FnMut(&FrontWrite) -> Result<(), MapError>,
) -> FrontApply {
    let mut applied = FrontApply::default();
    for plan in plans {
        let live = current_meta.get(&plan.front);
        if let Some(shortfall) = capacity_shortfall(plan, live.is_some(), used, cap) {
            applied.failures.push((plan.front, shortfall));
            continue;
        }
        let mut committed = false;
        let errors = run_front_plan(plan, |step| {
            write(step)?;
            used.apply(step, live.is_some());
            if let FrontWrite::PutMeta(_, m) = step {
                committed |= live.map(|l| l.generation) != Some(m.generation);
            }
            Ok(())
        });
        if committed {
            applied.swapped.push(plan.front);
        }
        applied
            .failures
            .extend(errors.into_iter().map(|e| (plan.front, e)));
    }
    applied
}

/// Reads both pinned maps, plans, and applies. Fronts are independent, so one
/// front's failure (e.g. a full map) never stops the others.
pub fn apply_fronts<M: BorrowMut<MapData>>(
    meta: &mut AyaHashMap<M, LbFrontKey, FrontMeta>,
    endpoints: &mut AyaHashMap<M, FrontEndpointKey, FrontEndpoint>,
    capacity: FrontCapacity,
    desired: &HashMap<LbFrontKey, DesiredFront>,
    prune_absent: bool,
    keep_previous: &HashSet<LbFrontKey>,
) -> anyhow::Result<FrontApply> {
    let current_meta: HashMap<LbFrontKey, FrontMeta> = meta.iter().collect::<Result<_, _>>()?;
    let current_endpoints: HashMap<FrontEndpointKey, FrontEndpoint> =
        endpoints.iter().collect::<Result<_, _>>()?;
    let used = FrontUsage {
        meta: current_meta.len(),
        endpoints: current_endpoints.len(),
    };
    let plans = plan_front_writes(
        &current_meta,
        &current_endpoints,
        desired,
        prune_absent,
        keep_previous,
    );
    Ok(run_front_plans(
        &plans,
        &current_meta,
        used,
        capacity,
        |step| match step {
            FrontWrite::DeleteEndpoint(k) => endpoints.remove(k),
            FrontWrite::PutEndpoint(k, v) => endpoints.insert(k, v, 0),
            FrontWrite::PutMeta(k, v) => meta.insert(k, v, 0),
            FrontWrite::DeleteMeta(k) => meta.remove(k),
        },
    ))
}

/// Fronts that committed a new generation recently, so their `g-1` rows are
/// still held. The grace is far longer than the dataplane's read window (a
/// reader holding the old generation needs it for the microseconds between
/// its two lookups in one tc invocation), so deleting after it can only race
/// a packet stalled for that long.
#[derive(Debug, Default)]
pub struct RecentSwaps(HashMap<LbFrontKey, Instant>);

impl RecentSwaps {
    /// Fronts whose grace has not yet elapsed at `now`.
    pub fn held(&self, now: Instant, grace: Duration) -> HashSet<LbFrontKey> {
        self.0
            .iter()
            .filter(|(_, at)| now.saturating_duration_since(**at) < grace)
            .map(|(front, _)| *front)
            .collect()
    }

    /// Forgets expired holds and starts the grace for `swapped`.
    pub fn record(&mut self, swapped: &[LbFrontKey], now: Instant, grace: Duration) {
        self.0
            .retain(|_, at| now.saturating_duration_since(*at) < grace);
        self.0.extend(swapped.iter().map(|front| (*front, now)));
    }

    /// Whether some hold has expired, i.e. another pass would now delete
    /// that front's `g-1` rows. Nothing else triggers a pass on a quiet
    /// cluster.
    pub fn expired(&self, now: Instant, grace: Duration) -> bool {
        self.0
            .values()
            .any(|at| now.saturating_duration_since(*at) >= grace)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use beep_common::{ipv4_mapped_v6, wire_ip, wire_port, LbFrontBackend};

    fn front(last_octet: u8, port: u16) -> LbFrontKey {
        LbFrontKey {
            front_ip: ipv4_mapped_v6(wire_ip(u32::from_be_bytes([203, 0, 113, last_octet]))),
            front_port: wire_port(port),
            proto: 6,
            _pad: 0,
        }
    }

    fn endpoint(pod_octet: u8, target_port: u16) -> FrontEndpoint {
        FrontEndpoint {
            backend: LbFrontBackend {
                backend_node_ip: ipv4_mapped_v6(u32::from_be_bytes([10, 0, 0, 5])),
                pod_ip: ipv4_mapped_v6(wire_ip(u32::from_be_bytes([10, 244, 0, pod_octet]))),
            },
            target_port: wire_port(target_port),
            flags: 0,
            _pad: [0; 4],
        }
    }

    fn want(ep: FrontEndpoint) -> DesiredFront {
        DesiredFront {
            flags: 0,
            endpoints: vec![ep],
        }
    }

    /// A pair of in-memory maps plus a reader that behaves like the
    /// dataplane: one meta lookup, then one endpoint lookup.
    #[derive(Default)]
    struct Store {
        meta: HashMap<LbFrontKey, FrontMeta>,
        endpoints: HashMap<FrontEndpointKey, FrontEndpoint>,
    }

    impl Store {
        fn read(&self, front: LbFrontKey) -> Option<FrontEndpoint> {
            let m = *self.meta.get(&front)?;
            let key = beep_common::front_endpoint_key(front, m)?;
            self.endpoints.get(&key).copied()
        }

        fn plan(&self, desired: &HashMap<LbFrontKey, DesiredFront>, prune: bool) -> Vec<FrontPlan> {
            self.plan_keeping(desired, prune, &HashSet::new())
        }

        fn plan_keeping(
            &self,
            desired: &HashMap<LbFrontKey, DesiredFront>,
            prune: bool,
            keep_previous: &HashSet<LbFrontKey>,
        ) -> Vec<FrontPlan> {
            plan_front_writes(&self.meta, &self.endpoints, desired, prune, keep_previous)
        }

        fn apply_step(&mut self, step: &FrontWrite) {
            match step {
                FrontWrite::DeleteEndpoint(k) => {
                    self.endpoints.remove(k);
                }
                FrontWrite::PutEndpoint(k, v) => {
                    self.endpoints.insert(*k, *v);
                }
                FrontWrite::PutMeta(k, v) => {
                    self.meta.insert(*k, *v);
                }
                FrontWrite::DeleteMeta(k) => {
                    self.meta.remove(k);
                }
            }
        }

        /// Applies every plan, calling `observe` between every pair of
        /// steps (a concurrent reader's possible vantage points).
        fn apply_all(&mut self, plans: &[FrontPlan], mut observe: impl FnMut(&Store)) {
            for plan in plans {
                for step in &plan.steps {
                    self.apply_step(step);
                    observe(self);
                }
            }
        }
    }

    fn desired(entries: &[(LbFrontKey, DesiredFront)]) -> HashMap<LbFrontKey, DesiredFront> {
        entries.iter().cloned().collect()
    }

    #[test]
    fn a_new_front_writes_its_endpoint_before_publishing_the_meta() {
        // A reader must never find a FRONT_META pointing at an endpoint that
        // is not there yet, or the front blackholes until the write lands.
        let f = front(1, 443);
        let store = Store::default();
        let plans = store.plan(&desired(&[(f, want(endpoint(7, 8443)))]), true);

        assert_eq!(plans.len(), 1);
        let steps = &plans[0].steps;
        assert!(
            matches!(steps[0], FrontWrite::PutEndpoint(k, _) if k.generation == 1 && k.slot == 0)
        );
        assert!(matches!(steps[1], FrontWrite::PutMeta(_, m) if m.generation == 1 && m.count == 1));
        assert_eq!(steps.len(), 2);
    }

    #[test]
    fn replacing_a_backend_deletes_old_generation_then_writes_new_then_flips_meta() {
        // The documented order: delete g-1, write g+1, flip meta. Violating it
        // either exceeds two live generations or exposes a half-written set.
        let f = front(1, 443);
        let mut store = Store::default();
        let first = store.plan(&desired(&[(f, want(endpoint(7, 8443)))]), true);
        store.apply_all(&first, |_| {});
        let second = store.plan(&desired(&[(f, want(endpoint(8, 8443)))]), true);
        store.apply_all(&second, |_| {});
        let third = store.plan(&desired(&[(f, want(endpoint(9, 8443)))]), true);

        let steps = &third[0].steps;
        let pos = |pred: &dyn Fn(&FrontWrite) -> bool| steps.iter().position(pred).unwrap();
        let delete_old = pos(&|s| matches!(s, FrontWrite::DeleteEndpoint(k) if k.generation == 1));
        let put_new = pos(&|s| matches!(s, FrontWrite::PutEndpoint(k, _) if k.generation == 3));
        let flip = pos(&|s| matches!(s, FrontWrite::PutMeta(_, m) if m.generation == 3));
        assert!(
            delete_old < put_new && put_new < flip,
            "order must be delete g-1, write g+1, flip meta; got {steps:?}"
        );
        assert_eq!(flip, steps.len() - 1, "the meta flip must be the last step");
    }

    #[test]
    fn a_concurrent_reader_always_resolves_an_endpoint_during_a_backend_swap() {
        // The user-visible guarantee: no packet of an established front is
        // dropped while its backend is replaced -- at every step boundary the
        // reader finds either the old or the new endpoint, never nothing.
        let f = front(1, 443);
        let (old, new) = (endpoint(7, 8443), endpoint(8, 9443));
        let mut store = Store::default();
        let first = store.plan(&desired(&[(f, want(old))]), true);
        store.apply_all(&first, |_| {});
        let swap = store.plan(&desired(&[(f, want(new))]), true);

        let mut seen = Vec::new();
        store.apply_all(&swap, |s| seen.push(s.read(f)));

        assert!(
            seen.iter().all(|r| *r == Some(old) || *r == Some(new)),
            "reader saw a gap or a mixed state mid-swap: {seen:?}"
        );
        assert_eq!(store.read(f), Some(new));
    }

    #[test]
    fn at_most_two_generations_exist_per_front_across_many_swaps() {
        let f = front(1, 443);
        let mut store = Store::default();
        for pod in 1..=6u8 {
            let plans = store.plan(&desired(&[(f, want(endpoint(pod, 8443)))]), true);
            let mut max_gens = 0;
            store.apply_all(&plans, |s| {
                let gens: HashSet<u32> = s.endpoints.keys().map(|k| k.generation).collect();
                max_gens = max_gens.max(gens.len());
            });
            assert!(
                max_gens <= 2,
                "swap {pod} had {max_gens} live generations; unbounded generations leak map capacity"
            );
        }
    }

    #[test]
    fn an_unchanged_front_produces_no_writes() {
        // A reconcile tick that changes nothing must not mint a generation,
        // or every tick would churn the dataplane maps.
        let f = front(1, 443);
        let mut store = Store::default();
        let d = desired(&[(f, want(endpoint(7, 8443)))]);
        let first = store.plan(&d, true);
        store.apply_all(&first, |_| {});

        assert!(store.plan(&d, true).is_empty());
    }

    #[test]
    fn a_target_port_change_alone_mints_a_new_generation() {
        let f = front(1, 443);
        let mut store = Store::default();
        let first = store.plan(&desired(&[(f, want(endpoint(7, 8443)))]), true);
        store.apply_all(&first, |_| {});
        let plans = store.plan(&desired(&[(f, want(endpoint(7, 9443)))]), true);
        store.apply_all(&plans, |_| {});

        assert_eq!(store.meta[&f].generation, 2);
        assert_eq!(store.read(f), Some(endpoint(7, 9443)));
    }

    fn local(mut ep: FrontEndpoint) -> FrontEndpoint {
        ep.flags = ENDPOINT_FLAG_IS_LOCAL;
        ep
    }

    fn many(eps: Vec<FrontEndpoint>) -> DesiredFront {
        DesiredFront {
            flags: 0,
            endpoints: eps,
        }
    }

    #[test]
    fn an_endpoint_becoming_local_mints_a_generation_and_publishes_local_count() {
        // The row flag and FRONT_META.local_count together define the hash
        // domain; a pod gaining locality with no other change must still
        // republish, or the node keeps spreading over remotes.
        let f = front(1, 443);
        let mut store = Store::default();
        let first = store.plan(
            &desired(&[(f, many(vec![endpoint(7, 8443), endpoint(8, 8443)]))]),
            true,
        );
        store.apply_all(&first, |_| {});
        assert_eq!(store.meta[&f].local_count, 0);

        let after = many(vec![local(endpoint(7, 8443)), endpoint(8, 8443)]);
        let plans = store.plan(&desired(&[(f, after)]), true);
        store.apply_all(&plans, |_| {});

        assert_eq!(
            store.meta[&f].generation, 2,
            "flag change must mint a generation"
        );
        assert_eq!(store.meta[&f].local_count, 1);
        assert_eq!(store.meta[&f].count, 2);
    }

    #[test]
    fn a_local_count_mismatch_alone_republishes() {
        // Rows already carry the right flags (e.g. a previous writer left
        // local_count 0): the meta must still be corrected.
        let f = front(1, 443);
        let mut store = Store::default();
        let d = many(vec![local(endpoint(7, 8443)), endpoint(8, 8443)]);
        let first = store.plan(&desired(&[(f, d.clone())]), true);
        store.apply_all(&first, |_| {});
        store.meta.get_mut(&f).unwrap().local_count = 0;

        let plans = store.plan(&desired(&[(f, d)]), true);

        assert!(!plans.is_empty(), "stale local_count must be repaired");
    }

    #[test]
    fn a_reader_never_sees_a_count_past_the_rows_that_exist_while_scaling() {
        // Hash selection can land on any slot below `count`: at every step
        // boundary of a 1 -> 3 -> 1 scale, each such slot must resolve.
        let f = front(1, 443);
        let mut store = Store::default();
        let eps = |n: u8| (1..=n).map(|o| endpoint(o, 8443)).collect::<Vec<_>>();
        let mut seen = 0;
        for n in [1u8, 3, 1] {
            let plans = store.plan(&desired(&[(f, many(eps(n)))]), true);
            store.apply_all(&plans, |s| {
                let Some(m) = s.meta.get(&f) else { return };
                for slot in 0..m.count as usize {
                    seen += 1;
                    assert!(
                        s.endpoints
                            .contains_key(&endpoint_key(f, m.generation, slot)),
                        "slot {slot} of count {} is missing mid-scale to {n}",
                        m.count
                    );
                }
            });
        }
        assert!(seen > 0);
    }

    #[test]
    fn a_flags_only_change_republishes_meta_without_a_new_generation() {
        let f = front(1, 443);
        let mut store = Store::default();
        let first = store.plan(&desired(&[(f, want(endpoint(7, 8443)))]), true);
        store.apply_all(&first, |_| {});
        let mut flagged = want(endpoint(7, 8443));
        flagged.flags = 1;
        let plans = store.plan(&desired(&[(f, flagged)]), true);

        assert_eq!(plans[0].steps.len(), 1);
        store.apply_all(&plans, |_| {});
        assert_eq!(store.meta[&f].generation, 1);
        assert_eq!(store.meta[&f].flags, 1);
    }

    #[test]
    fn removing_a_front_drops_meta_before_its_endpoints() {
        // With the endpoints gone first, a packet could hit a live meta and
        // count an endpoint miss for a front that is being removed.
        let f = front(1, 443);
        let mut store = Store::default();
        let first = store.plan(&desired(&[(f, want(endpoint(7, 8443)))]), true);
        store.apply_all(&first, |_| {});
        let plans = store.plan(&HashMap::new(), true);

        assert!(matches!(plans[0].steps[0], FrontWrite::DeleteMeta(_)));
        let mut meta_present_without_endpoint = false;
        store.apply_all(&plans, |s| {
            if s.meta.contains_key(&f) && s.read(f).is_none() {
                meta_present_without_endpoint = true;
            }
        });
        assert!(!meta_present_without_endpoint);
        assert!(store.meta.is_empty() && store.endpoints.is_empty());
    }

    fn drained() -> DesiredFront {
        DesiredFront {
            flags: 0,
            endpoints: vec![],
        }
    }

    #[test]
    fn a_front_with_no_ready_endpoints_keeps_its_meta_at_count_zero_and_sheds_its_rows() {
        // Deleting the meta makes ingress pass the packet to the host: new
        // clients hang instead of being refused. Count 0 keeps the reject.
        // Pinned flows to a draining pod read their conntrack pin, not these
        // maps, so no endpoint row is needed once the grace is over.
        let f = front(1, 443);
        let old = endpoint(7, 8443);
        let mut store = Store::default();
        let first = store.plan(&desired(&[(f, want(old))]), true);
        store.apply_all(&first, |_| {});
        let plans = store.plan(&desired(&[(f, drained())]), true);
        store.apply_all(&plans, |_| {});

        let m = store.meta[&f];
        assert_eq!((m.generation, m.count), (2, 0));
        assert_eq!(
            store.endpoints.get(&endpoint_key(f, 1, 0)),
            Some(&old),
            "the previous generation stays for the grace"
        );

        let after_grace = store.plan(&desired(&[(f, drained())]), true);
        store.apply_all(&after_grace, |_| {});
        assert!(
            store.endpoints.is_empty(),
            "a drained front must not hold endpoint rows forever: {:?}",
            store.endpoints
        );
        assert_eq!(store.meta[&f].count, 0);
    }

    #[test]
    fn repeated_count_zero_reconciles_do_not_bump_the_generation() {
        // A bump per reconcile at count 0 would churn the dataplane maps
        // every tick for a front with nothing to publish.
        let f = front(1, 443);
        let mut store = Store::default();
        let first = store.plan(&desired(&[(f, want(endpoint(7, 8443)))]), true);
        store.apply_all(&first, |_| {});
        for _ in 0..3 {
            let plans = store.plan(&desired(&[(f, drained())]), true);
            store.apply_all(&plans, |_| {});
        }

        assert_eq!(store.meta[&f].generation, 2);
        assert!(store.plan(&desired(&[(f, drained())]), true).is_empty());
    }

    #[test]
    fn the_previous_generation_is_deleted_once_its_grace_is_over() {
        // Keeping g-1 forever doubles steady-state rows for every front that
        // ever swapped; it is only needed by a reader that loaded the old
        // meta a few microseconds before the commit.
        let f = front(1, 443);
        let mut store = Store::default();
        let first = store.plan(&desired(&[(f, want(endpoint(7, 8443)))]), true);
        store.apply_all(&first, |_| {});
        let d = desired(&[(f, want(endpoint(8, 8443)))]);
        let swap = store.plan(&d, true);
        store.apply_all(&swap, |_| {});
        assert_eq!(store.endpoints.len(), 2);

        let within_grace = store.plan_keeping(&d, true, &HashSet::from([f]));
        assert!(
            within_grace.is_empty(),
            "g-1 must survive its grace: {within_grace:?}"
        );

        let after_grace = store.plan(&d, true);
        store.apply_all(&after_grace, |_| {});
        assert_eq!(
            store.endpoints.len(),
            1,
            "steady state must hold only the live generation"
        );
        assert_eq!(store.read(f), Some(endpoint(8, 8443)));
    }

    #[test]
    fn a_reader_that_loaded_the_old_meta_before_the_commit_still_resolves_within_grace() {
        // The race the grace exists for: a packet reads FRONT_META at g, the
        // controller commits g+1, and only then does the packet read
        // FRONT_ENDPOINTS[g]. Deleting g at the commit would turn that packet
        // into a front miss.
        let f = front(1, 443);
        let (old, new) = (endpoint(7, 8443), endpoint(8, 8443));
        let mut store = Store::default();
        let first = store.plan(&desired(&[(f, want(old))]), true);
        store.apply_all(&first, |_| {});
        let stale_meta = store.meta[&f];

        let d = desired(&[(f, want(new))]);
        let swap = store.plan(&d, true);
        store.apply_all(&swap, |_| {});
        let stale_read = |s: &Store| {
            let key = beep_common::front_endpoint_key(f, stale_meta)?;
            s.endpoints.get(&key).copied()
        };
        assert_eq!(stale_read(&store), Some(old));

        let held = store.plan_keeping(&d, true, &HashSet::from([f]));
        store.apply_all(&held, |_| {});
        assert_eq!(
            stale_read(&store),
            Some(old),
            "a reconcile inside the grace must not delete g-1"
        );
    }

    #[test]
    fn a_second_swap_inside_the_grace_still_deletes_the_older_generation_first() {
        // Holding g-1 across a further swap would run three generations and
        // break the capacity bound the pre-write check relies on.
        let f = front(1, 443);
        let mut store = Store::default();
        for pod in 1..=2u8 {
            let plans = store.plan(&desired(&[(f, want(endpoint(pod, 8443)))]), true);
            store.apply_all(&plans, |_| {});
        }
        let d = desired(&[(f, want(endpoint(3, 8443)))]);
        let third = store.plan_keeping(&d, true, &HashSet::from([f]));
        let mut max_gens = 0;
        store.apply_all(&third, |s| {
            max_gens = max_gens.max(
                s.endpoints
                    .keys()
                    .map(|k| k.generation)
                    .collect::<HashSet<_>>()
                    .len(),
            );
        });
        assert!(max_gens <= 2, "{max_gens} generations at once");
    }

    #[test]
    fn a_committed_swap_is_reported_but_a_flags_only_change_is_not() {
        // The grace clock starts at a generation commit; a flags republish
        // retires nothing, and starting a hold for it would only delay GC.
        let f = front(1, 443);
        let mut store = Store::default();
        let cap = FrontCapacity {
            meta: 8,
            endpoints: 8,
        };
        let swapped = |store: &mut Store, d: &HashMap<LbFrontKey, DesiredFront>| {
            let plans = store.plan(d, true);
            let used = FrontUsage {
                meta: store.meta.len(),
                endpoints: store.endpoints.len(),
            };
            let meta = store.meta.clone();
            run_front_plans(&plans, &meta, used, cap, |step| {
                store.apply_step(step);
                Ok(())
            })
            .swapped
        };
        assert_eq!(
            swapped(&mut store, &desired(&[(f, want(endpoint(1, 8443)))])),
            [f]
        );
        assert_eq!(
            swapped(&mut store, &desired(&[(f, want(endpoint(2, 8443)))])),
            [f]
        );
        let mut flagged = want(endpoint(2, 8443));
        flagged.flags = 1;
        assert!(swapped(&mut store, &desired(&[(f, flagged)])).is_empty());
    }

    #[test]
    fn recent_swaps_hold_until_the_grace_then_ask_for_a_pass() {
        // On a quiet cluster nothing else triggers the pass that deletes g-1;
        // `expired` is what tells the controller to run one.
        let f = front(1, 443);
        let grace = Duration::from_secs(2);
        let t0 = Instant::now();
        let mut recent = RecentSwaps::default();
        recent.record(&[f], t0, grace);

        assert!(recent.held(t0 + Duration::from_secs(1), grace).contains(&f));
        assert!(!recent.expired(t0 + Duration::from_secs(1), grace));
        assert!(recent.held(t0 + grace, grace).is_empty());
        assert!(recent.expired(t0 + grace, grace));

        recent.record(&[], t0 + grace, grace);
        assert!(
            !recent.expired(t0 + grace, grace),
            "the pass that deleted g-1 settles the hold"
        );
    }

    #[test]
    fn a_service_deleted_while_drained_removes_its_meta() {
        let f = front(1, 443);
        let mut store = Store::default();
        let first = store.plan(&desired(&[(f, drained())]), true);
        store.apply_all(&first, |_| {});
        assert_eq!(
            store.meta[&f].count, 0,
            "a never-served front is still owned"
        );
        let plans = store.plan(&HashMap::new(), true);
        store.apply_all(&plans, |_| {});

        assert!(store.meta.is_empty() && store.endpoints.is_empty());
    }

    #[test]
    fn startup_cleanup_deletes_every_non_live_generation_and_orphans() {
        // A crashed predecessor can leave generations behind. A fresh process
        // has no grace to honour: keep only the live generation, and delete
        // any endpoint of a front with no meta, or capacity leaks across restarts.
        let f = front(1, 443);
        let orphan_front = front(2, 443);
        let mut store = Store::default();
        store.meta.insert(
            f,
            FrontMeta {
                generation: 5,
                count: 1,
                flags: 0,
                local_count: 0,
                _pad: 0,
            },
        );
        let ep = endpoint(7, 8443);
        for generation in [2, 3, 4, 5, 6] {
            store.endpoints.insert(endpoint_key(f, generation, 0), ep);
        }
        store
            .endpoints
            .insert(endpoint_key(orphan_front, 1, 0), endpoint(9, 8443));

        let plans = store.plan(&desired(&[(f, want(ep))]), true);
        store.apply_all(&plans, |_| {});

        let mut gens: Vec<u32> = store
            .endpoints
            .keys()
            .filter(|k| k.front == f)
            .map(|k| k.generation)
            .collect();
        gens.sort_unstable();
        assert_eq!(
            gens,
            vec![5],
            "only the live generation may survive a restart"
        );
        assert!(
            store.endpoints.keys().all(|k| k.front != orphan_front),
            "endpoints of a front with no FRONT_META are unreachable and must be deleted"
        );
        assert_eq!(
            store.meta[&f].generation, 5,
            "cleanup must not mint a generation"
        );
    }

    #[test]
    fn a_failed_endpoint_write_keeps_the_old_generation_serving() {
        // If the new generation cannot be fully written (map full), flipping
        // the meta would point live traffic at a missing endpoint.
        let f = front(1, 443);
        let mut store = Store::default();
        let (old, new) = (endpoint(7, 8443), endpoint(8, 8443));
        let first = store.plan(&desired(&[(f, want(old))]), true);
        store.apply_all(&first, |_| {});
        let plans = store.plan(&desired(&[(f, want(new))]), true);

        let failures = run_front_plan(&plans[0], |step| match step {
            FrontWrite::PutEndpoint(..) => Err(sys_error(libc::E2BIG)),
            other => {
                store.apply_step(other);
                Ok(())
            }
        });

        assert_eq!(failures.len(), 1);
        assert_eq!(store.read(f), Some(old), "old generation must keep serving");
    }

    fn sys_error(errno: i32) -> MapError {
        MapError::SyscallError(aya::sys::SyscallError {
            call: "bpf_map_update_elem",
            io_error: std::io::Error::from_raw_os_error(errno),
        })
    }

    #[test]
    fn enomem_is_reported_as_out_of_memory_not_as_a_full_map() {
        // A non-preallocated map can fail an insert with ENOMEM while far
        // from its cap; telling the operator to raise a cap that is not the
        // problem wastes the incident. Both still fail-stale.
        let f = front(1, 443);
        let mut store = Store::default();
        let (old, new) = (endpoint(7, 8443), endpoint(8, 8443));
        let first = store.plan(&desired(&[(f, want(old))]), true);
        store.apply_all(&first, |_| {});
        let plans = store.plan(&desired(&[(f, want(new))]), true);

        for (errno, kind) in [
            (libc::ENOMEM, FailureKind::OutOfMemory),
            (libc::E2BIG, FailureKind::Capacity),
            (libc::EPERM, FailureKind::Other),
        ] {
            let mut scratch = Store {
                meta: store.meta.clone(),
                endpoints: store.endpoints.clone(),
            };
            let failures = run_front_plan(&plans[0], |step| match step {
                FrontWrite::PutEndpoint(..) => Err(sys_error(errno)),
                other => {
                    scratch.apply_step(other);
                    Ok(())
                }
            });
            assert_eq!(failures.len(), 1);
            assert_eq!(failures[0].kind, kind, "errno {errno}");
            assert!(
                failures[0]
                    .message
                    .contains(&std::io::Error::from_raw_os_error(errno).to_string()),
                "the log must carry the errno text, got {:?}",
                failures[0].message
            );
            assert_eq!(scratch.read(f), Some(old), "errno {errno} must fail stale");
        }
    }

    fn two(a: u8, b: u8) -> DesiredFront {
        DesiredFront {
            flags: 0,
            endpoints: vec![endpoint(a, 8443), endpoint(b, 8443)],
        }
    }

    fn run_all(
        store: &mut Store,
        desired: &HashMap<LbFrontKey, DesiredFront>,
        cap: FrontCapacity,
    ) -> Vec<(LbFrontKey, FrontFailure)> {
        let plans = store.plan(desired, true);
        let used = FrontUsage {
            meta: store.meta.len(),
            endpoints: store.endpoints.len(),
        };
        let meta = store.meta.clone();
        run_front_plans(&plans, &meta, used, cap, |step| {
            store.apply_step(step);
            Ok(())
        })
        .failures
    }

    #[test]
    fn a_swap_that_does_not_fit_is_refused_before_any_row_is_written() {
        // Writing the new generation until E2BIG leaves partial rows behind
        // and a stale front with no explanation; the operator must instead
        // get one loud capacity failure and an untouched map.
        let f = front(1, 443);
        let mut store = Store::default();
        let cap = FrontCapacity {
            meta: 8,
            endpoints: 4,
        };
        assert!(run_all(&mut store, &desired(&[(f, two(1, 2))]), cap).is_empty());

        // 2 -> 3 endpoints needs 3 new rows next to the 2 live ones.
        let three = DesiredFront {
            flags: 0,
            endpoints: vec![endpoint(1, 8443), endpoint(2, 8443), endpoint(4, 8443)],
        };
        let failures = run_all(&mut store, &desired(&[(f, three)]), cap);

        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].0, f);
        assert_eq!(failures[0].1.kind, FailureKind::Capacity);
        assert!(
            failures[0].1.message.contains("FRONT_ENDPOINTS"),
            "{:?}",
            failures[0].1.message
        );
        assert_eq!(
            store.endpoints.len(),
            2,
            "a refused swap must not leave partial rows of the new generation"
        );
        assert_eq!(store.meta[&f].generation, 1);
    }

    #[test]
    fn a_new_front_is_refused_when_front_meta_is_full() {
        let mut store = Store::default();
        let cap = FrontCapacity {
            meta: 1,
            endpoints: 8,
        };
        let both = desired(&[
            (front(1, 443), want(endpoint(1, 8443))),
            (front(2, 443), want(endpoint(2, 8443))),
        ]);
        let failures = run_all(&mut store, &both, cap);

        assert_eq!(failures.len(), 1);
        assert!(failures[0].1.message.contains("FRONT_META"));
        assert_eq!(store.meta.len(), 1, "FRONT_META must stay within its cap");
        assert_eq!(
            store.endpoints.len(),
            1,
            "the refused front must not strand endpoint rows"
        );
    }

    #[test]
    fn removed_fronts_are_applied_first_so_their_freed_rows_fund_growing_fronts() {
        // With hash-random order a grower can hit a full map that a deletion
        // would have freed a moment later, so which Services update would
        // depend on luck. Deletions (net shrink) must run first.
        let mut store = Store::default();
        let roomy = FrontCapacity {
            meta: 32,
            endpoints: 32,
        };
        let growers: Vec<LbFrontKey> = (1..=4).map(|n| front(n, 443)).collect();
        let removed: Vec<LbFrontKey> = (11..=18).map(|n| front(n, 443)).collect();
        let start: Vec<_> = growers
            .iter()
            .chain(&removed)
            .map(|f| (*f, want(endpoint(1, 8443))))
            .collect();
        assert!(run_all(&mut store, &desired(&start), roomy).is_empty());
        assert_eq!(store.endpoints.len(), 12);

        // Cap equals the current usage: growers (2 new rows each) fit only
        // once the 8 removed fronts' rows are gone.
        let full = FrontCapacity {
            meta: 32,
            endpoints: 12,
        };
        let next: Vec<_> = growers.iter().map(|f| (*f, two(1, 2))).collect();
        let failures = run_all(&mut store, &desired(&next), full);

        assert!(failures.is_empty(), "{failures:?}");
        assert!(growers.iter().all(|g| store.meta[g].count == 2));
        assert!(store.endpoints.len() <= 12);
    }

    #[test]
    fn plan_order_is_deterministic_for_equal_effects() {
        // Which front starves under pressure must not depend on HashSet
        // iteration order, or the same shortfall hits random Services.
        let fronts: Vec<LbFrontKey> = (1..=6).map(|n| front(n, 443)).collect();
        let want_all: HashMap<_, _> = fronts
            .iter()
            .map(|f| (*f, want(endpoint(9, 8443))))
            .collect();
        let store = Store::default();
        let order: Vec<_> = store
            .plan(&want_all, true)
            .iter()
            .map(|p| p.front)
            .collect();
        let mut sorted = fronts.clone();
        sorted.sort_by_key(|f| (f.front_ip, f.front_port, f.proto));
        assert_eq!(order, sorted);
    }

    #[test]
    fn without_prune_fronts_outside_the_desired_set_are_left_alone() {
        // The loader's fixture mode must not wipe fronts a controller wrote.
        let (a, b) = (front(1, 443), front(2, 443));
        let mut store = Store::default();
        let first = store.plan(&desired(&[(b, want(endpoint(7, 8443)))]), true);
        store.apply_all(&first, |_| {});

        let plans = store.plan(&desired(&[(a, want(endpoint(8, 8443)))]), false);
        store.apply_all(&plans, |_| {});

        assert!(store.read(a).is_some());
        assert!(store.read(b).is_some());
    }
}
