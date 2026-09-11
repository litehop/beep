//! Applies a `reconcile::DesiredEntries` to the dataplane's pinned
//! `VIP_MAP`/`TARGET_PORTS`/`POD_TARGETS` maps. Opens them from their bpffs
//! pins (`beep::attach_and_pin`'s loader already created them at load time)
//! rather than holding an `Ebpf` handle, so this process never touches
//! `FWD_PENDING`/`FLOW_TABLE` -- the kernel-written conntrack tables must
//! survive untouched across every controller reconcile.

use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    net::Ipv4Addr,
    path::Path,
};

use anyhow::Context;
use aya::maps::{HashMap as AyaHashMap, Map, MapData};
use beep_common::{VipBackend, VipKey};

use crate::reconcile::{self, DesiredEntries, MapOp};

/// The three controller-written maps, opened once from their pins and kept
/// open across every reconcile tick (avoids a `MapData::from_pin` syscall
/// round trip per event).
pub struct PinnedMaps {
    vip_map: AyaHashMap<MapData, VipKey, VipBackend>,
    target_ports: AyaHashMap<MapData, VipKey, u16>,
    pod_targets: AyaHashMap<MapData, u32, u8>,
}

fn open_hash_map<K: aya::Pod, V: aya::Pod>(
    pin_dir: &Path,
    name: &str,
) -> anyhow::Result<AyaHashMap<MapData, K, V>> {
    let path = pin_dir.join(name);
    let map_data = MapData::from_pin(&path)
        .with_context(|| format!("opening pinned map `{name}` from {}", path.display()))?;
    AyaHashMap::try_from(Map::HashMap(map_data))
        .with_context(|| format!("map `{name}` is not a BPF_MAP_TYPE_HASH"))
}

impl PinnedMaps {
    pub fn open(pin_dir: &Path) -> anyhow::Result<Self> {
        Ok(Self {
            vip_map: open_hash_map(pin_dir, "VIP_MAP")?,
            target_ports: open_hash_map(pin_dir, "TARGET_PORTS")?,
            pod_targets: open_hash_map(pin_dir, "POD_TARGETS")?,
        })
    }

    /// Diffs each map's live contents against `desired` and applies the
    /// minimal set of writes/deletes -- an unchanged reconcile costs no
    /// syscalls (`reconcile::diff`'s doc comment). Runs all three maps'
    /// diffs to completion before propagating any error: a capacity failure
    /// on VIP_MAP must never suppress the TARGET_PORTS/POD_TARGETS writes
    /// for OTHER, unrelated Services in the same reconcile tick (PR #51
    /// review's HIGH finding -- a bare `?` chain here silently left every
    /// later Service unrouted with no attempt at all).
    ///
    /// Skips the VIP_MAP/TARGET_PORTS diff entirely while
    /// `desired.fronts_known` is `false` (`DesiredEntries`'s doc comment):
    /// diffing an empty `vip_map`/`target_ports` against these maps' actual
    /// contents would delete every front, even ones a previous run already
    /// programmed and pinned -- `desired.fronts_known == false` means "not
    /// known yet", not "no fronts should exist".
    pub fn apply(&mut self, desired: &DesiredEntries) -> anyhow::Result<()> {
        let (vip_map_result, target_ports_result) = if desired.fronts_known {
            (
                apply_ops(
                    &mut self.vip_map,
                    &desired.vip_map,
                    reconcile::vip_backend_eq,
                    "VIP_MAP",
                    describe_vip_key,
                )
                .context("applying VIP_MAP"),
                apply_ops(
                    &mut self.target_ports,
                    &desired.target_ports,
                    |a: &u16, b: &u16| a == b,
                    "TARGET_PORTS",
                    describe_vip_key,
                )
                .context("applying TARGET_PORTS"),
            )
        } else {
            (Ok(()), Ok(()))
        };
        let pod_targets_result = apply_pod_targets(&mut self.pod_targets, &desired.pod_targets)
            .context("applying POD_TARGETS");

        vip_map_result?;
        target_ports_result?;
        pod_targets_result?;
        Ok(())
    }
}

fn describe_vip_key(key: &VipKey) -> String {
    format!(
        "{}:{}/proto={}",
        Ipv4Addr::from(u32::from_be(key.vip_ip)),
        u16::from_be(key.vip_port),
        key.proto
    )
}

/// Attempts every op against `write`, loudly logging (never silently
/// dropping) each individual failure by name instead of aborting the rest of
/// the diff on the first one -- a capacity failure on one entry must not
/// leave every entry AFTER it in the same map unattempted. Returns the
/// number of ops that failed so the caller can turn that into a loud
/// `anyhow::Error` for the reconcile as a whole. A free function (not a
/// method) taking `write` as a closure so this loop is testable without a
/// real pinned bpf map (`aya::maps::HashMap` needs a live kernel fd).
fn apply_diff_ops<K, V, E>(
    ops: Vec<MapOp<K, V>>,
    map_name: &str,
    describe_key: impl Fn(&K) -> String,
    mut write: impl FnMut(MapOp<K, V>) -> Result<(), E>,
) -> usize
where
    K: Copy,
    E: std::fmt::Display,
{
    let mut failed = 0;
    for op in ops {
        let key = match &op {
            MapOp::Upsert(k, _) => *k,
            MapOp::Delete(k) => *k,
        };
        let is_delete = matches!(op, MapOp::Delete(_));
        if let Err(e) = write(op) {
            failed += 1;
            let verb = if is_delete { "delete" } else { "upsert" };
            eprintln!(
                "controller: {map_name} {verb} for {} failed (entry left unrouted -- map may \
                 be at capacity): {e:#}",
                describe_key(&key)
            );
        }
    }
    failed
}

fn apply_ops<K, V>(
    map: &mut AyaHashMap<MapData, K, V>,
    desired: &HashMap<K, V>,
    values_equal: impl Fn(&V, &V) -> bool,
    map_name: &str,
    describe_key: impl Fn(&K) -> String,
) -> anyhow::Result<()>
where
    K: aya::Pod + Eq + Hash,
    V: aya::Pod,
{
    let current: HashMap<K, V> = map.iter().collect::<Result<_, _>>()?;
    let ops = reconcile::diff(&current, desired, values_equal);
    let failed = apply_diff_ops(ops, map_name, describe_key, |op| match op {
        MapOp::Upsert(k, v) => map.insert(k, v, 0),
        MapOp::Delete(k) => map.remove(&k),
    });
    if failed > 0 {
        anyhow::bail!("{failed} write(s) to `{map_name}` failed -- see per-entry errors above");
    }
    Ok(())
}

/// `POD_TARGETS` isn't map-shaped like `VIP_MAP`/`TARGET_PORTS`
/// (`reconcile::DesiredEntries::pod_targets` is a set, not a map), so it's a
/// full membership sync -- same prune-then-insert pattern as the loader's
/// own `populate_fixtures`, reusing the already-tested `beep::stale_pod_targets`.
/// Same continue-past-a-failure contract as `apply_ops` above.
fn apply_pod_targets(
    map: &mut AyaHashMap<MapData, u32, u8>,
    desired: &HashSet<u32>,
) -> anyhow::Result<()> {
    let existing: Vec<u32> = map.keys().collect::<Result<_, _>>()?;
    let live: Vec<u32> = desired.iter().copied().collect();
    let mut failed = 0;
    for stale in beep::stale_pod_targets(&existing, &live) {
        if let Err(e) = map.remove(&stale) {
            failed += 1;
            eprintln!(
                "controller: POD_TARGETS delete for pod {} failed: {e:#}",
                Ipv4Addr::from(u32::from_be(stale))
            );
        }
    }
    for ip in &live {
        if let Err(e) = map.insert(ip, 1u8, 0) {
            failed += 1;
            eprintln!(
                "controller: POD_TARGETS upsert for pod {} failed (entry left unrouted -- map \
                 may be at capacity): {e:#}",
                Ipv4Addr::from(u32::from_be(*ip))
            );
        }
    }
    if failed > 0 {
        anyhow::bail!("{failed} write(s) to `POD_TARGETS` failed -- see per-entry errors above");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_diff_ops_continues_past_a_write_failure_so_later_entries_still_get_applied() {
        // Regression for PR #51 review's HIGH finding: the old code used a
        // bare `?` per op, so ONE VIP_MAP capacity failure aborted every
        // LATER Service's write in the same reconcile -- those Services went
        // silently unrouted with no attempt made and no error naming them.
        let ops = vec![
            MapOp::Upsert(1u32, 10u8),
            MapOp::Upsert(2u32, 20u8), // simulated capacity failure
            MapOp::Upsert(3u32, 30u8),
            MapOp::Delete(4u32),
        ];
        let mut attempted = Vec::new();
        let failed = apply_diff_ops(
            ops,
            "TEST_MAP",
            |k: &u32| k.to_string(),
            |op| {
                let key = match op {
                    MapOp::Upsert(k, _) => k,
                    MapOp::Delete(k) => k,
                };
                attempted.push(key);
                if key == 2 {
                    Err("E2BIG: map at capacity")
                } else {
                    Ok(())
                }
            },
        );

        assert_eq!(
            attempted,
            vec![1, 2, 3, 4],
            "a write failure on entry 2 must not skip attempting entries 3/4 -- that's exactly \
             how a VIP_MAP overflow silently left later Services unrouted"
        );
        assert_eq!(
            failed, 1,
            "the one simulated failure must be counted, not swallowed, so the caller can turn \
             it into a loud reconcile-level error"
        );
    }
}
