//! Carries map entries across a pinned-map recreation.
//!
//! A pinned map whose `map_flags`/`max_entries` changed (same type, key and
//! value size) must be recreated, but recreating it empty would leave the
//! freshly attached programs with no state until the controller's first
//! reconcile -- and ingress passes a front-table miss straight to the host,
//! so established front flows would break. Instead the loader snapshots the
//! old map before unlinking its pin and restores the entries into the new map
//! after it is created and before any program is attached.
//!
//! Entries are raw key/value bytes read through `bpf(2)` so one path serves
//! every map regardless of its Rust key/value types.

use std::{
    collections::{BTreeMap, HashMap},
    io,
    os::fd::{AsFd, AsRawFd},
    path::Path,
};

use anyhow::Context;
use aya::{maps::MapData, Pod};
use beep_common::{FrontEndpointKey, FrontMeta, LbFrontKey};

pub type Entry = (Vec<u8>, Vec<u8>);

pub const FRONT_META: &str = "FRONT_META";
pub const FRONT_ENDPOINTS: &str = "FRONT_ENDPOINTS";

/// What to do with a pinned map whose shape differs from the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fate {
    Keep,
    /// Same layout, only `map_flags`/`max_entries` differ: copy the entries.
    Migrate,
    /// Layout (type/key/value size) differs: entries are meaningless.
    RecreateEmpty,
}

/// `FRONT_META` rows point at `FRONT_ENDPOINTS` rows, so the two are only
/// consistent as a pair: if either must change, both do, and a layout change
/// (or a missing pin) in either resets both. Input and output are in
/// `[FRONT_META, FRONT_ENDPOINTS]` order; `None` is "no pin".
pub fn couple_front_fates(fates: [Option<Fate>; 2]) -> [Fate; 2] {
    let [meta, endpoints] = fates;
    let both = match (meta, endpoints) {
        (Some(Fate::Keep), Some(Fate::Keep)) => Fate::Keep,
        (Some(Fate::Keep | Fate::Migrate), Some(Fate::Keep | Fate::Migrate)) => Fate::Migrate,
        (None, None) => Fate::Keep,
        _ => Fate::RecreateEmpty,
    };
    [both, both]
}

/// A front that survives the copy: its `FRONT_META` row and the live
/// generation's endpoint rows.
#[derive(Debug, PartialEq, Eq)]
pub struct FrontCopy {
    pub meta: Entry,
    pub rows: Vec<Entry>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RestorePlan {
    /// Maps other than the two front maps, truncated to their new cap.
    pub generic: Vec<(&'static str, Vec<Entry>)>,
    /// Applied rows-first-then-meta, so a meta row never points at a
    /// missing endpoint row.
    pub fronts: Vec<FrontCopy>,
    /// Loud, human-readable lines for whatever did not fit or was malformed.
    pub losses: Vec<String>,
}

fn decode<T: Pod>(bytes: &[u8]) -> Option<T> {
    (bytes.len() == std::mem::size_of::<T>()).then(|| {
        // SAFETY: `T: Pod` means every bit pattern is valid, and the length
        // was just checked; `read_unaligned` tolerates the Vec's alignment.
        unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) }
    })
}

/// Decides what to copy, in what order, and what fits. `snapshots` holds the
/// old contents of each migrating map; `cap` is the new `max_entries`.
///
/// Fronts are kept whole or not at all: a front is copied only if its
/// `FRONT_META` row, and all `count` endpoint rows of the live generation,
/// fit in the new caps. Previous generations are not copied (they exist only
/// for the swap grace). Fronts are admitted in key order so a cap shrink drops
/// the same fronts every time; the controller reconciles the rest.
pub fn plan_restore(
    snapshots: Vec<(&'static str, Vec<Entry>)>,
    cap: impl Fn(&str) -> u32,
) -> RestorePlan {
    let mut plan = RestorePlan::default();
    let mut metas = Vec::new();
    let mut endpoints = Vec::new();
    for (name, entries) in snapshots {
        match name {
            FRONT_META => metas = entries,
            FRONT_ENDPOINTS => endpoints = entries,
            _ => {
                let cap = cap(name) as usize;
                if entries.len() > cap {
                    plan.losses.push(format!(
                        "{name}: {} entries exceed the new cap {cap}; {} dropped",
                        entries.len(),
                        entries.len() - cap
                    ));
                }
                let mut entries = entries;
                entries.truncate(cap);
                plan.generic.push((name, entries));
            }
        }
    }

    let mut rows_by_gen: HashMap<(LbFrontKey, u32), Vec<(u16, Entry)>> = HashMap::new();
    for (key, value) in endpoints {
        match decode::<FrontEndpointKey>(&key) {
            Some(k) => rows_by_gen
                .entry((k.front, k.generation))
                .or_default()
                .push((k.slot, (key, value))),
            None => plan
                .losses
                .push("FRONT_ENDPOINTS: undecodable key skipped".to_owned()),
        }
    }
    let mut sorted_metas: BTreeMap<Vec<u8>, (FrontMeta, Vec<u8>)> = BTreeMap::new();
    let fronts_total = metas.len();
    for (key, value) in metas {
        match decode::<FrontMeta>(&value) {
            Some(m) => {
                sorted_metas.insert(key, (m, value));
            }
            None => plan
                .losses
                .push("FRONT_META: undecodable value skipped".to_owned()),
        }
    }
    let meta_cap = cap(FRONT_META) as usize;
    let ep_cap = cap(FRONT_ENDPOINTS) as usize;
    let mut rows_used = 0usize;
    let mut dropped_fronts = 0usize;
    for (key, (meta, value)) in sorted_metas {
        let front = decode::<LbFrontKey>(&key);
        let rows = front.and_then(|f| rows_by_gen.remove(&(f, meta.generation)));
        let mut rows: Vec<_> = rows
            .unwrap_or_default()
            .into_iter()
            .filter(|(slot, _)| *slot < meta.count)
            .collect();
        rows.sort_by_key(|(slot, _)| *slot);
        let complete = rows.len() == usize::from(meta.count);
        let fits = plan.fronts.len() < meta_cap && rows_used + rows.len() <= ep_cap;
        if !complete || !fits || front.is_none() {
            dropped_fronts += 1;
            continue;
        }
        rows_used += rows.len();
        plan.fronts.push(FrontCopy {
            meta: (key, value),
            rows: rows.into_iter().map(|(_, e)| e).collect(),
        });
    }
    if dropped_fronts > 0 {
        plan.losses.push(format!(
            "FRONT_META/FRONT_ENDPOINTS: copied {} of {fronts_total} fronts ({rows_used} \
             endpoint rows; caps {meta_cap} fronts / {ep_cap} rows); {dropped_fronts} dropped \
             until the controller reconciles them",
            plan.fronts.len()
        ));
    }
    plan
}

#[repr(C)]
struct ElemAttr {
    map_fd: u32,
    _pad: u32,
    key: u64,
    value_or_next_key: u64,
    flags: u64,
}

fn bpf_elem(cmd: aya_obj::generated::bpf_cmd, attr: &mut ElemAttr) -> io::Result<()> {
    // SAFETY: `attr` is a live `repr(C)` prefix of `union bpf_attr` for the
    // MAP_*_ELEM commands; the kernel reads at most `size_of::<ElemAttr>()`
    // bytes of it and the key/value pointers it holds reference buffers the
    // caller sized from the map's own key/value size.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd as libc::c_int,
            std::ptr::from_mut(attr),
            std::mem::size_of::<ElemAttr>(),
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Every entry of the map pinned at `path`. A concurrently mutated map
/// (programs of the previous loader are still attached) can restart the key
/// walk or vanish a key between steps, so keys are de-duplicated and the walk
/// is bounded; the result is a best-effort point-in-time copy.
pub fn snapshot_pin(path: &Path) -> anyhow::Result<Vec<Entry>> {
    let map = MapData::from_pin(path).with_context(|| format!("opening {}", path.display()))?;
    let info = map.info().context("reading map info")?;
    let (key_size, value_size) = (info.key_size() as usize, info.value_size() as usize);
    let walk_bound = 2 * info.max_entries() as usize + 1;
    let fd = map.fd().as_fd().as_raw_fd() as u32;

    let mut out: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    let mut key: Option<Vec<u8>> = None;
    for _ in 0..walk_bound {
        let mut next = vec![0u8; key_size];
        let mut attr = ElemAttr {
            map_fd: fd,
            _pad: 0,
            key: key.as_ref().map_or(0, |k| k.as_ptr() as u64),
            value_or_next_key: next.as_mut_ptr() as u64,
            flags: 0,
        };
        match bpf_elem(aya_obj::generated::bpf_cmd::BPF_MAP_GET_NEXT_KEY, &mut attr) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => break,
            Err(e) => return Err(e).context("BPF_MAP_GET_NEXT_KEY"),
        }
        let mut value = vec![0u8; value_size];
        let mut attr = ElemAttr {
            map_fd: fd,
            _pad: 0,
            key: next.as_ptr() as u64,
            value_or_next_key: value.as_mut_ptr() as u64,
            flags: 0,
        };
        match bpf_elem(aya_obj::generated::bpf_cmd::BPF_MAP_LOOKUP_ELEM, &mut attr) {
            Ok(()) => {
                out.insert(next.clone(), value);
            }
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
            Err(e) => return Err(e).context("BPF_MAP_LOOKUP_ELEM"),
        }
        key = Some(next);
    }
    Ok(out.into_iter().collect())
}

/// Writes `entries` into the map pinned at `path`; returns how many writes
/// failed (e.g. `ENOMEM`), each already printed.
fn write_entries<'a>(
    path: &Path,
    entries: impl IntoIterator<Item = &'a Entry>,
) -> anyhow::Result<Vec<bool>> {
    let map = MapData::from_pin(path).with_context(|| format!("opening {}", path.display()))?;
    let fd = map.fd().as_fd().as_raw_fd() as u32;
    Ok(entries
        .into_iter()
        .map(|(key, value)| {
            let mut attr = ElemAttr {
                map_fd: fd,
                _pad: 0,
                key: key.as_ptr() as u64,
                value_or_next_key: value.as_ptr() as u64,
                flags: 0,
            };
            match bpf_elem(aya_obj::generated::bpf_cmd::BPF_MAP_UPDATE_ELEM, &mut attr) {
                Ok(()) => true,
                Err(e) => {
                    eprintln!("beep: restoring an entry into {}: {e}", path.display());
                    false
                }
            }
        })
        .collect())
}

/// Applies `plan` to the freshly created pinned maps under `pin_dir`:
/// endpoint rows of every front first, then the meta rows of the fronts whose
/// rows all landed.
pub fn apply_restore(pin_dir: &Path, plan: &RestorePlan) -> anyhow::Result<()> {
    for line in &plan.losses {
        eprintln!("beep: migration loss: {line}");
    }
    for (name, entries) in &plan.generic {
        let failed = write_entries(&pin_dir.join(name), entries)?
            .iter()
            .filter(|ok| !**ok)
            .count();
        eprintln!(
            "beep: migrated {} of {} entries into {name}",
            entries.len() - failed,
            entries.len()
        );
    }
    if plan.fronts.is_empty() {
        return Ok(());
    }
    let mut landed = Vec::with_capacity(plan.fronts.len());
    for front in &plan.fronts {
        let results = write_entries(&pin_dir.join(FRONT_ENDPOINTS), &front.rows)?;
        landed.push(results.iter().all(|ok| *ok));
    }
    let metas: Vec<&Entry> = plan
        .fronts
        .iter()
        .zip(&landed)
        .filter(|(_, ok)| **ok)
        .map(|(f, _)| &f.meta)
        .collect();
    let written = write_entries(&pin_dir.join(FRONT_META), metas.iter().copied())?
        .iter()
        .filter(|ok| **ok)
        .count();
    eprintln!(
        "beep: migrated {written} of {} fronts into FRONT_META/FRONT_ENDPOINTS",
        plan.fronts.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use beep_common::FrontEndpoint;

    fn bytes<T: Copy>(t: &T) -> Vec<u8> {
        // SAFETY: test-only view of a plain `repr(C)` value's bytes.
        unsafe { std::slice::from_raw_parts(std::ptr::from_ref(t).cast::<u8>(), size_of::<T>()) }
            .to_vec()
    }

    fn front(n: u8) -> LbFrontKey {
        LbFrontKey {
            front_ip: [n; 16],
            front_port: 80,
            proto: 6,
            _pad: 0,
        }
    }

    fn ep_row(front: LbFrontKey, generation: u32, slot: u16) -> Entry {
        let key = FrontEndpointKey {
            front,
            generation,
            slot,
            _pad: 0,
        };
        let value: FrontEndpoint = decode(&vec![0u8; size_of::<FrontEndpoint>()]).unwrap();
        (bytes(&key), bytes(&value))
    }

    fn meta_row(front: LbFrontKey, generation: u32, count: u16) -> Entry {
        let meta = FrontMeta {
            generation,
            count,
            flags: 0,
            local_count: 0,
            _pad: 0,
        };
        (bytes(&front), bytes(&meta))
    }

    fn caps(meta: u32, endpoints: u32) -> impl Fn(&str) -> u32 {
        move |name| match name {
            FRONT_META => meta,
            FRONT_ENDPOINTS => endpoints,
            _ => 4,
        }
    }

    fn snaps(metas: Vec<Entry>, rows: Vec<Entry>) -> Vec<(&'static str, Vec<Entry>)> {
        vec![(FRONT_ENDPOINTS, rows), (FRONT_META, metas)]
    }

    #[test]
    fn flag_or_cap_only_change_migrates_so_established_flows_keep_their_front() {
        assert_eq!(
            couple_front_fates([Some(Fate::Migrate), Some(Fate::Keep)]),
            [Fate::Migrate; 2],
            "a changed endpoints-per-front cap recreates only FRONT_ENDPOINTS, \
             but META must follow or it would point at rows copied under a different plan"
        );
    }

    #[test]
    fn layout_change_or_missing_pin_in_one_front_map_resets_both() {
        for fates in [
            [Some(Fate::RecreateEmpty), Some(Fate::Keep)],
            [Some(Fate::Migrate), Some(Fate::RecreateEmpty)],
            [None, Some(Fate::Keep)],
        ] {
            assert_eq!(
                couple_front_fates(fates),
                [Fate::RecreateEmpty; 2],
                "{fates:?}: a surviving half would be orphan rows or meta pointing at nothing"
            );
        }
        assert_eq!(couple_front_fates([None, None]), [Fate::Keep; 2]);
        assert_eq!(
            couple_front_fates([Some(Fate::Keep), Some(Fate::Keep)]),
            [Fate::Keep; 2]
        );
    }

    #[test]
    fn everything_that_fits_is_copied_with_live_generation_rows_only() {
        let (a, b) = (front(1), front(2));
        let plan = plan_restore(
            snaps(
                vec![meta_row(a, 5, 2), meta_row(b, 0, 1)],
                vec![
                    ep_row(a, 5, 1),
                    ep_row(a, 5, 0),
                    ep_row(a, 4, 0),
                    ep_row(b, 0, 0),
                ],
            ),
            caps(8, 8),
        );
        assert!(plan.losses.is_empty(), "{:?}", plan.losses);
        assert_eq!(plan.fronts.len(), 2);
        let rows: usize = plan.fronts.iter().map(|f| f.rows.len()).sum();
        assert_eq!(rows, 3, "the g-1 row exists only for the swap grace");
    }

    #[test]
    fn cap_shrink_keeps_whole_fronts_in_key_order_and_reports_counts() {
        // A front with a META row but only part of its rows would send some
        // flows to a missing slot; all-or-nothing keeps every copied front
        // fully serviceable and the loss is named for the operator.
        let fronts: Vec<_> = (1..=3).map(front).collect();
        let metas = fronts.iter().map(|f| meta_row(*f, 1, 2)).collect();
        let rows = fronts
            .iter()
            .flat_map(|f| [ep_row(*f, 1, 0), ep_row(*f, 1, 1)])
            .collect();
        let plan = plan_restore(snaps(metas, rows), caps(8, 5));
        assert_eq!(plan.fronts.len(), 2, "5 rows fit two 2-row fronts");
        assert_eq!(plan.fronts[0].meta.0, bytes(&fronts[0]));
        assert_eq!(plan.fronts[1].meta.0, bytes(&fronts[1]));
        assert_eq!(plan.losses.len(), 1);
        assert!(
            plan.losses[0].contains("2 of 3 fronts") && plan.losses[0].contains("1 dropped"),
            "{}",
            plan.losses[0]
        );
    }

    #[test]
    fn meta_cap_shrink_drops_surplus_fronts() {
        let fronts: Vec<_> = (1..=3).map(front).collect();
        let metas = fronts.iter().map(|f| meta_row(*f, 0, 1)).collect();
        let rows = fronts.iter().map(|f| ep_row(*f, 0, 0)).collect();
        let plan = plan_restore(snaps(metas, rows), caps(1, 8));
        assert_eq!(plan.fronts.len(), 1);
    }

    #[test]
    fn front_with_missing_rows_is_not_copied() {
        // The source itself is mid-swap or damaged; copying the META would
        // reproduce a front that points at absent slots.
        let a = front(1);
        let plan = plan_restore(
            snaps(vec![meta_row(a, 0, 2)], vec![ep_row(a, 0, 0)]),
            caps(8, 8),
        );
        assert!(plan.fronts.is_empty());
        assert_eq!(plan.losses.len(), 1);
    }

    #[test]
    fn generic_maps_are_truncated_to_the_new_cap_with_a_loss_line() {
        let entries: Vec<Entry> = (0..6u8).map(|i| (vec![i], vec![i])).collect();
        let plan = plan_restore(vec![("POD_TARGETS", entries)], caps(8, 8));
        assert_eq!(plan.generic[0].1.len(), 4);
        assert!(plan.losses[0].contains("2 dropped"), "{}", plan.losses[0]);
    }
}
