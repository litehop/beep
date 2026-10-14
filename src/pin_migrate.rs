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

/// `BPF_NOEXIST`: a restore only fills gaps. An entry already in the new map
/// is newer than the parked snapshot (an earlier, interrupted restore landed
/// it, or a writer has updated it since), so overwriting it would revert live
/// state.
const BPF_NOEXIST: u64 = aya_obj::generated::BPF_NOEXIST as u64;

/// Writes one entry into the named map with the given `BPF_*` update flag.
type EntryWriter<'a> = dyn FnMut(&str, &Entry, u64) -> io::Result<()> + 'a;

/// Whether a restore write counts as done. `EEXIST` is done: the entry is
/// already in the new map. Anything else (`ENOMEM`, `EINVAL`, an `E2BIG` the
/// plan did not budget for) means the entry is missing from the new map.
/// Entries the plan truncated are never written, so they are not failures.
fn write_landed(result: &io::Result<()>) -> bool {
    match result {
        Ok(()) => true,
        Err(e) => e.raw_os_error() == Some(libc::EEXIST),
    }
}

/// One restore write that did not land.
#[derive(Debug, PartialEq, Eq)]
struct WriteFailure {
    map: String,
    errno: Option<i32>,
    text: String,
}

/// A restore that left entries out of the new maps for a reason the plan did
/// not budget for. The parked pins are kept; the start fails.
#[derive(Debug, PartialEq, Eq)]
pub struct RestoreFailure {
    /// Map of the first failed write.
    pub map: String,
    /// `errno` of the first failed write; `None` if it was not a syscall error.
    pub errno: Option<i32>,
    pub count: usize,
    /// Up to five failure lines.
    pub first: Vec<String>,
}

impl std::fmt::Display for RestoreFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} unexpected write failures restoring migrated entries (first: {}); \
             map {} {}: {}",
            self.count,
            self.first.join("; "),
            self.map,
            self.errno.map_or("error", errno_name),
            restore_remediation(self.errno)
        )
    }
}

impl std::error::Error for RestoreFailure {}

pub fn errno_name(errno: i32) -> &'static str {
    match errno {
        libc::ENOMEM => "ENOMEM",
        libc::E2BIG => "E2BIG",
        libc::EINVAL => "EINVAL",
        libc::EFAULT => "EFAULT",
        libc::EPERM => "EPERM",
        libc::EACCES => "EACCES",
        _ => "errno",
    }
}

/// What an operator should do about a restore write failing with `errno`.
pub fn restore_remediation(errno: Option<i32>) -> &'static str {
    match errno {
        Some(libc::ENOMEM) => {
            "no-prealloc maps allocate per insert, charged to the pod memory cgroup: raise the \
             pod memory limit or relieve node memory pressure"
        }
        Some(libc::E2BIG | libc::EINVAL | libc::EFAULT) => {
            "restore plan/layout mismatch, a beep bug: please report, with the log"
        }
        Some(libc::EPERM | libc::EACCES) => {
            "missing BPF capabilities or LSM denial: check the DaemonSet securityContext"
        }
        _ => "unexpected restore error: please report, with the log",
    }
}

/// Writes `entries` into `map`; one `landed` flag per entry, failures recorded.
fn write_all<'a>(
    write: &mut EntryWriter,
    map: &str,
    entries: impl IntoIterator<Item = &'a Entry>,
    failures: &mut Vec<WriteFailure>,
) -> Vec<bool> {
    entries
        .into_iter()
        .map(|entry| {
            let result = write(map, entry, BPF_NOEXIST);
            let landed = write_landed(&result);
            if let (false, Err(e)) = (landed, &result) {
                failures.push(WriteFailure {
                    map: map.to_owned(),
                    errno: e.raw_os_error(),
                    text: format!("{map}: {e}"),
                });
            }
            landed
        })
        .collect()
}

/// Applies `plan` through `write`: endpoint rows of every front first, then
/// the meta rows of the fronts whose rows all landed. Errors if any write
/// failed unexpectedly (after attempting all of them); the caller must then
/// keep the parked pins so the next start retries from the source.
fn apply_plan(plan: &RestorePlan, write: &mut EntryWriter) -> anyhow::Result<()> {
    for line in &plan.losses {
        eprintln!("beep: migration loss: {line}");
    }
    let mut failures = Vec::new();
    for (name, entries) in &plan.generic {
        let landed = write_all(write, name, entries, &mut failures);
        eprintln!(
            "beep: migrated {} of {} entries into {name}",
            landed.iter().filter(|ok| **ok).count(),
            entries.len()
        );
    }
    if !plan.fronts.is_empty() {
        let mut landed = Vec::with_capacity(plan.fronts.len());
        for front in &plan.fronts {
            let results = write_all(write, FRONT_ENDPOINTS, &front.rows, &mut failures);
            landed.push(results.iter().all(|ok| *ok));
        }
        let metas: Vec<&Entry> = plan
            .fronts
            .iter()
            .zip(&landed)
            .filter(|(_, ok)| **ok)
            .map(|(f, _)| &f.meta)
            .collect();
        let written = write_all(write, FRONT_META, metas.iter().copied(), &mut failures)
            .iter()
            .filter(|ok| **ok)
            .count();
        eprintln!(
            "beep: migrated {written} of {} fronts into FRONT_META/FRONT_ENDPOINTS",
            plan.fronts.len()
        );
    }
    let Some(first) = failures.first() else {
        return Ok(());
    };
    Err(RestoreFailure {
        map: first.map.clone(),
        errno: first.errno,
        count: failures.len(),
        first: failures.iter().take(5).map(|f| f.text.clone()).collect(),
    }
    .into())
}

/// Applies `plan` to the freshly created pinned maps under `pin_dir`.
pub fn apply_restore(pin_dir: &Path, plan: &RestorePlan) -> anyhow::Result<()> {
    let mut maps: HashMap<String, MapData> = HashMap::new();
    apply_plan(plan, &mut |name, (key, value), flags| {
        if !maps.contains_key(name) {
            let path = pin_dir.join(name);
            let map = MapData::from_pin(&path)
                .map_err(|e| io::Error::other(format!("opening {}: {e}", path.display())))?;
            maps.insert(name.to_owned(), map);
        }
        let mut attr = ElemAttr {
            map_fd: maps[name].fd().as_fd().as_raw_fd() as u32,
            _pad: 0,
            key: key.as_ptr() as u64,
            value_or_next_key: value.as_ptr() as u64,
            flags,
        };
        bpf_elem(aya_obj::generated::bpf_cmd::BPF_MAP_UPDATE_ELEM, &mut attr)
    })
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

    /// Kernel-like stand-in for the new pinned maps: honours `BPF_NOEXIST` and
    /// fails writes whose key's first byte is in `fail`.
    #[derive(Default)]
    struct FakeMaps {
        maps: HashMap<String, BTreeMap<Vec<u8>, Vec<u8>>>,
        fail: Vec<(u8, i32)>,
    }

    impl FakeMaps {
        fn write(&mut self, map: &str, (k, v): &Entry, flags: u64) -> io::Result<()> {
            if let Some((_, errno)) = self.fail.iter().find(|(b, _)| *b == k[0]) {
                return Err(io::Error::from_raw_os_error(*errno));
            }
            let m = self.maps.entry(map.to_owned()).or_default();
            if flags == BPF_NOEXIST && m.contains_key(k) {
                return Err(io::Error::from_raw_os_error(libc::EEXIST));
            }
            m.insert(k.clone(), v.clone());
            Ok(())
        }

        fn apply(&mut self, plan: &RestorePlan) -> anyhow::Result<()> {
            apply_plan(plan, &mut |m, e, f| self.write(m, e, f))
        }
    }

    fn generic_plan(n: u8, cap: u32) -> RestorePlan {
        let entries = (0..n).map(|i| (vec![i], vec![i])).collect();
        plan_restore(vec![("POD_TARGETS", entries)], |_| cap)
    }

    #[test]
    fn planned_cap_shrink_truncation_is_not_a_failure_so_the_pin_still_unparks() {
        // Every restart after a cap shrink has losses; treating them as errors
        // would leave `_migrating` parked, and retried, forever.
        let plan = generic_plan(6, 4);
        assert!(!plan.losses.is_empty());
        let mut maps = FakeMaps::default();
        maps.apply(&plan)
            .expect("truncated entries are never written, so nothing fails");
        assert_eq!(maps.maps["POD_TARGETS"].len(), 4);
    }

    #[test]
    fn unexpected_write_errno_fails_the_restore_so_the_parked_pin_is_kept() {
        // Ok here would unpark the source and lose the entry for good.
        for errno in [libc::ENOMEM, libc::EINVAL, libc::E2BIG] {
            let mut maps = FakeMaps {
                fail: vec![(2, errno)],
                ..Default::default()
            };
            let err = maps.apply(&generic_plan(4, 8)).unwrap_err().to_string();
            assert!(err.contains("1 unexpected write failures"), "{err}");
            assert_eq!(
                maps.maps["POD_TARGETS"].len(),
                3,
                "the remaining entries are still attempted"
            );
        }
    }

    #[test]
    fn remediation_names_the_action_for_each_errno_class() {
        // The operator only sees this text (log and Event); a wrong class sends
        // them to the wrong knob.
        let cases = [
            (libc::ENOMEM, "pod memory limit"),
            (libc::E2BIG, "a beep bug"),
            (libc::EINVAL, "a beep bug"),
            (libc::EFAULT, "a beep bug"),
            (libc::EPERM, "securityContext"),
            (libc::EACCES, "securityContext"),
        ];
        for (errno, needle) in cases {
            let text = restore_remediation(Some(errno));
            assert!(text.contains(needle), "errno {errno}: {text}");
        }
        assert!(restore_remediation(None).contains("report"));
        assert!(restore_remediation(Some(libc::EIO)).contains("report"));
    }

    #[test]
    fn restore_failure_survives_context_wrapping_with_map_errno_and_remediation() {
        // The controller downcasts the load error to build the Event; a
        // stringified error would lose the errno and the failing map.
        let mut maps = FakeMaps {
            fail: vec![(2, libc::ENOMEM)],
            ..Default::default()
        };
        let err = maps
            .apply(&generic_plan(4, 8))
            .map_err(|e| e.context("restoring migrated map entries"))
            .unwrap_err();
        let failure = err.downcast_ref::<RestoreFailure>().expect("typed error");
        assert_eq!(failure.map, "POD_TARGETS");
        assert_eq!(failure.errno, Some(libc::ENOMEM));
        let shown = failure.to_string();
        assert!(shown.contains("map POD_TARGETS ENOMEM"), "{shown}");
        assert!(shown.contains("pod memory limit"), "{shown}");
    }

    #[test]
    fn failed_endpoint_row_fails_the_restore_and_withholds_that_fronts_meta() {
        let (a, b) = (front(1), front(2));
        let plan = plan_restore(
            snaps(
                vec![meta_row(a, 0, 1), meta_row(b, 0, 1)],
                vec![ep_row(a, 0, 0), ep_row(b, 0, 0)],
            ),
            caps(8, 8),
        );
        let mut maps = FakeMaps {
            fail: vec![(1, libc::ENOMEM)],
            ..Default::default()
        };
        assert!(maps.apply(&plan).is_err());
        let metas = &maps.maps[FRONT_META];
        assert_eq!(metas.len(), 1, "a meta row must not point at a missing row");
        assert!(metas.contains_key(&bytes(&b)));
    }

    #[test]
    fn rerun_restore_does_not_overwrite_entries_newer_than_the_parked_source() {
        // A crash after the restore but before the unpark re-restores the same
        // snapshot on the next start; entries written since must survive.
        let plan = generic_plan(3, 8);
        let mut maps = FakeMaps::default();
        maps.apply(&plan).unwrap();
        let live = maps.maps.get_mut("POD_TARGETS").unwrap();
        live.insert(vec![1], vec![99]);
        maps.apply(&plan)
            .expect("EEXIST means the entry is already restored");
        let live = &maps.maps["POD_TARGETS"];
        assert_eq!(live[&vec![1]], vec![99], "newer value was reverted");
    }
}
