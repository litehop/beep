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
//! fails the endpoints are left alone. A front with unchanged endpoints
//! produces no writes except deleting generations older than `g-1`, which is
//! also what cleans up a previous process's crash leftovers on startup.

use std::{
    borrow::BorrowMut,
    collections::{HashMap, HashSet},
};

use aya::maps::{HashMap as AyaHashMap, MapData};
use beep_common::{FrontEndpoint, FrontEndpointKey, FrontMeta, LbFrontKey};

/// The endpoint set a front should have. Slot `i` is `endpoints[i]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DesiredFront {
    pub flags: u16,
    pub endpoints: Vec<FrontEndpoint>,
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
/// `desired`. A desired front with no endpoints is treated as absent.
/// With `prune_absent`, fronts (and orphan endpoints) not in `desired` are
/// removed; without it, only fronts named in `desired` are touched.
pub fn plan_front_writes(
    current_meta: &HashMap<LbFrontKey, FrontMeta>,
    current_endpoints: &HashMap<FrontEndpointKey, FrontEndpoint>,
    desired: &HashMap<LbFrontKey, DesiredFront>,
    prune_absent: bool,
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

        match desired.get(&front).filter(|d| !d.endpoints.is_empty()) {
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
                let unchanged = meta.filter(|m| {
                    m.count == count
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
                                    && k.generation != m.generation.wrapping_sub(1)
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
                        },
                    ));
                }
            }
        }

        if !steps.is_empty() {
            plans.push(FrontPlan { front, steps });
        }
    }
    plans
}

/// Runs one front's plan through `write`, in order. Returns one message per
/// failed step. A failed endpoint write suppresses the `FRONT_META` commit
/// (the old generation keeps serving); a failed `FRONT_META` delete
/// suppresses the endpoint deletes behind it (they would strand a live front).
pub fn run_front_plan<E: std::fmt::Display>(
    plan: &FrontPlan,
    mut write: impl FnMut(&FrontWrite) -> Result<(), E>,
) -> Vec<String> {
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
            failures.push(format!("{what} failed: {e:#}"));
            match step {
                FrontWrite::PutEndpoint(..) => commit_blocked = true,
                FrontWrite::DeleteMeta(_) => break,
                _ => {}
            }
        }
    }
    failures
}

/// Reads both pinned maps, plans, and applies. Returns `(front, message)`
/// for every failed step; fronts are independent, so one front's failure
/// (e.g. a full map) never stops the others.
pub fn apply_fronts<M: BorrowMut<MapData>>(
    meta: &mut AyaHashMap<M, LbFrontKey, FrontMeta>,
    endpoints: &mut AyaHashMap<M, FrontEndpointKey, FrontEndpoint>,
    desired: &HashMap<LbFrontKey, DesiredFront>,
    prune_absent: bool,
) -> anyhow::Result<Vec<(LbFrontKey, String)>> {
    let current_meta: HashMap<LbFrontKey, FrontMeta> = meta.iter().collect::<Result<_, _>>()?;
    let current_endpoints: HashMap<FrontEndpointKey, FrontEndpoint> =
        endpoints.iter().collect::<Result<_, _>>()?;
    let mut failures = Vec::new();
    for plan in plan_front_writes(&current_meta, &current_endpoints, desired, prune_absent) {
        let errors = run_front_plan(&plan, |step| match step {
            FrontWrite::DeleteEndpoint(k) => endpoints.remove(k),
            FrontWrite::PutEndpoint(k, v) => endpoints.insert(k, v, 0),
            FrontWrite::PutMeta(k, v) => meta.insert(k, v, 0),
            FrontWrite::DeleteMeta(k) => meta.remove(k),
        });
        failures.extend(errors.into_iter().map(|e| (plan.front, e)));
    }
    Ok(failures)
}

#[cfg(test)]
mod tests {
    use super::*;
    use beep_common::{ipv4_mapped_v6, wire_ip, wire_port, LbFrontBackend};

    fn front(last_octet: u8, port: u16) -> LbFrontKey {
        LbFrontKey {
            vip_ip: ipv4_mapped_v6(wire_ip(u32::from_be_bytes([203, 0, 113, last_octet]))),
            vip_port: wire_port(port),
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
            _pad: [0; 6],
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
            plan_front_writes(&self.meta, &self.endpoints, desired, prune)
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

    #[test]
    fn startup_cleanup_deletes_generations_older_than_previous_and_orphans() {
        // A crashed predecessor can leave generations behind. Keep current
        // and g-1; delete everything else, and any endpoint of a front that
        // has no meta at all, or map capacity leaks across restarts.
        let f = front(1, 443);
        let orphan_front = front(2, 443);
        let mut store = Store::default();
        store.meta.insert(
            f,
            FrontMeta {
                generation: 5,
                count: 1,
                flags: 0,
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
            vec![4, 5],
            "only the live generation and g-1 may survive"
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
            FrontWrite::PutEndpoint(..) => Err("E2BIG"),
            other => {
                store.apply_step(other);
                Ok(())
            }
        });

        assert_eq!(failures.len(), 1);
        assert_eq!(store.read(f), Some(old), "old generation must keep serving");
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
