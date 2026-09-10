//! Applies a `reconcile::DesiredEntries` to the dataplane's pinned
//! `VIP_MAP`/`TARGET_PORTS`/`POD_TARGETS` maps. Opens them from their bpffs
//! pins (`beep::attach_and_pin`'s loader already created them at load time)
//! rather than holding an `Ebpf` handle, so this process never touches
//! `FWD_PENDING`/`FLOW_TABLE` -- the kernel-written conntrack tables must
//! survive untouched across every controller reconcile.

use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
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
    /// syscalls (`reconcile::diff`'s doc comment).
    pub fn apply(&mut self, desired: &DesiredEntries) -> anyhow::Result<()> {
        apply_ops(
            &mut self.vip_map,
            &desired.vip_map,
            reconcile::vip_backend_eq,
        )
        .context("applying VIP_MAP")?;
        apply_ops(
            &mut self.target_ports,
            &desired.target_ports,
            |a: &u16, b: &u16| a == b,
        )
        .context("applying TARGET_PORTS")?;
        apply_pod_targets(&mut self.pod_targets, &desired.pod_targets)
            .context("applying POD_TARGETS")?;
        Ok(())
    }
}

fn apply_ops<K, V>(
    map: &mut AyaHashMap<MapData, K, V>,
    desired: &HashMap<K, V>,
    values_equal: impl Fn(&V, &V) -> bool,
) -> anyhow::Result<()>
where
    K: aya::Pod + Eq + Hash,
    V: aya::Pod,
{
    let current: HashMap<K, V> = map.iter().collect::<Result<_, _>>()?;
    for op in reconcile::diff(&current, desired, values_equal) {
        match op {
            MapOp::Upsert(k, v) => map.insert(k, v, 0)?,
            MapOp::Delete(k) => map.remove(&k)?,
        }
    }
    Ok(())
}

/// `POD_TARGETS` isn't map-shaped like `VIP_MAP`/`TARGET_PORTS`
/// (`reconcile::DesiredEntries::pod_targets` is a set, not a map), so it's a
/// full membership sync -- same prune-then-insert pattern as the loader's
/// own `populate_fixtures`, reusing the already-tested `beep::stale_pod_targets`.
fn apply_pod_targets(
    map: &mut AyaHashMap<MapData, u32, u8>,
    desired: &HashSet<u32>,
) -> anyhow::Result<()> {
    let existing: Vec<u32> = map.keys().collect::<Result<_, _>>()?;
    let live: Vec<u32> = desired.iter().copied().collect();
    for stale in beep::stale_pod_targets(&existing, &live) {
        map.remove(&stale)?;
    }
    for ip in &live {
        map.insert(ip, 1u8, 0)?;
    }
    Ok(())
}
