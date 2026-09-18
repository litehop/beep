//! Applies a `reconcile::DesiredEntries` to the dataplane's pinned
//! `LB_FRONT_MAP`/`TARGET_PORTS`/`POD_TARGETS`/`NODE_ALLOW` maps. Opens them from their bpffs
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
use beep_common::{LbFrontBackend, LbFrontKey};

use crate::reconcile::{self, DesiredEntries, MapOp};

/// The four controller-written maps, opened once from their pins and kept
/// open across every reconcile tick (avoids a `MapData::from_pin` syscall
/// round trip per event).
pub struct PinnedMaps {
    lb_front_map: AyaHashMap<MapData, LbFrontKey, LbFrontBackend>,
    target_ports: AyaHashMap<MapData, LbFrontKey, u16>,
    pod_targets: AyaHashMap<MapData, u32, u8>,
    node_allow: AyaHashMap<MapData, u32, u8>,
    /// "Has `fronts_known` ever been true in this process." Starts `false`
    /// on every controller start (including a restart), and once
    /// `apply` observes `fronts_known == true` it stays `true` for the rest
    /// of the process -- see `apply_node_allow`'s doc comment for why
    /// `NODE_ALLOW` needs its own sticky latch instead of just reading
    /// `desired.fronts_known` directly on each tick.
    fronts_ever_known: bool,
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
            lb_front_map: open_hash_map(pin_dir, "LB_FRONT_MAP")?,
            target_ports: open_hash_map(pin_dir, "TARGET_PORTS")?,
            pod_targets: open_hash_map(pin_dir, "POD_TARGETS")?,
            node_allow: open_hash_map(pin_dir, "NODE_ALLOW")?,
            fronts_ever_known: false,
        })
    }

    /// Diffs each map's live contents against `desired` and applies the
    /// minimal set of writes/deletes -- an unchanged reconcile costs no
    /// syscalls (`reconcile::diff`'s doc comment). Runs all four maps'
    /// diffs to completion before propagating any error: a capacity failure
    /// on LB_FRONT_MAP must never suppress the TARGET_PORTS/POD_TARGETS/
    /// NODE_ALLOW writes for OTHER, unrelated Services in the same
    /// reconcile tick -- a bare `?` chain here previously left every later
    /// Service unrouted with no attempt at all.
    ///
    /// Skips the LB_FRONT_MAP/TARGET_PORTS diffs entirely while
    /// `desired.fronts_known` is `false` (`DesiredEntries`'s doc comment):
    /// diffing an empty `lb_front_map`/`target_ports` against these maps'
    /// actual contents would delete every front, even ones a previous run
    /// already programmed and pinned -- `desired.fronts_known == false`
    /// means "not known yet", not "no fronts should exist". NODE_ALLOW runs
    /// every tick regardless (see `apply_node_allow`'s doc comment): it
    /// stays additive-only (upsert, never delete) until `fronts_known`
    /// first becomes true this process, narrowing the cold-start Geneve
    /// blackout without reopening the restart-wipe window `fronts_known`
    /// exists to prevent. Skips the POD_TARGETS full-sync the same way as
    /// LB_FRONT_MAP/TARGET_PORTS while `desired.pod_targets_known` is
    /// `false` -- same reasoning, keyed on this node's own Node LIST/watch
    /// entry instead of the whole list (`DesiredEntries::pod_targets_known`'s
    /// doc comment).
    pub fn apply(&mut self, desired: &DesiredEntries) -> anyhow::Result<()> {
        let (lb_front_map_result, target_ports_result) = if desired.fronts_known {
            (
                apply_ops(
                    &mut self.lb_front_map,
                    &desired.lb_front_map,
                    reconcile::lb_front_backend_eq,
                    "LB_FRONT_MAP",
                    describe_lb_front_key,
                )
                .context("applying LB_FRONT_MAP"),
                apply_ops(
                    &mut self.target_ports,
                    &desired.target_ports,
                    |a: &u16, b: &u16| a == b,
                    "TARGET_PORTS",
                    describe_lb_front_key,
                )
                .context("applying TARGET_PORTS"),
            )
        } else {
            (Ok(()), Ok(()))
        };
        self.fronts_ever_known =
            node_allow_may_delete(desired.fronts_known, self.fronts_ever_known);
        let node_allow_result = apply_node_allow(
            &mut self.node_allow,
            &desired.node_allow,
            self.fronts_ever_known,
        )
        .context("applying NODE_ALLOW");
        let pod_targets_result = if desired.pod_targets_known {
            apply_pod_targets(&mut self.pod_targets, &desired.pod_targets)
                .context("applying POD_TARGETS")
        } else {
            Ok(())
        };

        lb_front_map_result?;
        target_ports_result?;
        node_allow_result?;
        pod_targets_result?;
        Ok(())
    }
}

fn describe_lb_front_key(key: &LbFrontKey) -> String {
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

/// `POD_TARGETS` isn't map-shaped like `LB_FRONT_MAP`/`TARGET_PORTS`
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

/// Whether `apply_node_allow` may delete stale peers this tick, given
/// `fronts_known` (this tick's `DesiredEntries::fronts_known`) and
/// `fronts_ever_known` (the latch's value coming in, i.e.
/// `PinnedMaps::fronts_ever_known` before this tick). Sticky once true:
/// `desired.fronts_known` never actually regresses within one controller
/// process (`WatchState::nodes_listed` is itself a one-way latch), but this
/// stays defensive against that changing rather than trusting it -- a
/// controller RESTART is exactly the case that matters here, and a fresh
/// process's `PinnedMaps` starts this latch at `false` again regardless of
/// what the previous process last knew.
fn node_allow_may_delete(fronts_known: bool, fronts_ever_known: bool) -> bool {
    fronts_known || fronts_ever_known
}

/// `NODE_ALLOW`'s peer-attestation full-sync -- same set-shaped,
/// prune-then-insert pattern as `apply_pod_targets` above, reusing the same
/// generic `beep::stale_pod_targets` set diff. Unlike `POD_TARGETS`, this
/// map's keys are host-native (`DesiredEntries::node_allow`'s doc comment),
/// so logging uses `Ipv4Addr::from` directly rather than `POD_TARGETS`'s
/// `u32::from_be` unwrap.
///
/// `may_delete` (`node_allow_may_delete`'s output) gates the delete half of
/// the sync: while it's `false` -- before `fronts_known` has ever been true
/// this process -- already-discovered peers still get upserted, but nothing
/// is ever deleted, no matter how partial `desired.node_allow` is against
/// what's already pinned. That partial-vs-pinned gap is exactly the
/// restart-wipe scenario `fronts_known` exists to prevent: a controller
/// restart's `node_ips` mid-Node-LIST is a strict subset of the peer set a
/// previous run already pinned, and wiping down to that subset would drop
/// Geneve traffic from every not-yet-relisted peer.
fn apply_node_allow(
    map: &mut AyaHashMap<MapData, u32, u8>,
    desired: &HashSet<u32>,
    may_delete: bool,
) -> anyhow::Result<()> {
    let live: Vec<u32> = desired.iter().copied().collect();
    let existing: Vec<u32> = if may_delete {
        map.keys().collect::<Result<_, _>>()?
    } else {
        Vec::new()
    };
    let mut failed = 0;
    for stale in node_allow_stale_peers(&existing, &live, may_delete) {
        if let Err(e) = map.remove(&stale) {
            failed += 1;
            eprintln!(
                "controller: NODE_ALLOW delete for peer {} failed: {e:#}",
                Ipv4Addr::from(stale)
            );
        }
    }
    for ip in &live {
        if let Err(e) = map.insert(ip, 1u8, 0) {
            failed += 1;
            eprintln!(
                "controller: NODE_ALLOW upsert for peer {} failed (entry left unrouted -- map \
                 may be at capacity): {e:#}",
                Ipv4Addr::from(*ip)
            );
        }
    }
    if failed > 0 {
        anyhow::bail!("{failed} write(s) to `NODE_ALLOW` failed -- see per-entry errors above");
    }
    Ok(())
}

/// The additive-only guard itself: peers to delete from `NODE_ALLOW` this
/// tick. Returns nothing at all while `may_delete` is `false`, regardless of
/// how `existing`/`live` compare -- even when `live` is a strict subset of
/// `existing` (a controller restart mid-Node-LIST, the scenario
/// `apply_node_allow`'s doc comment describes). Once `may_delete` is `true`
/// it reduces to the plain `beep::stale_pod_targets` set diff, matching
/// `apply_pod_targets`'s destructive full-sync. Split out as its own pure
/// function (no bpf map I/O) so this guard is unit-testable without a live
/// pinned map.
fn node_allow_stale_peers(existing: &[u32], live: &[u32], may_delete: bool) -> Vec<u32> {
    if may_delete {
        beep::stale_pod_targets(existing, live)
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_diff_ops_continues_past_a_write_failure_so_later_entries_still_get_applied() {
        // Regression test: the old code used a bare `?` per op, so ONE
        // LB_FRONT_MAP capacity failure aborted every LATER Service's write in
        // the same reconcile -- those Services went silently unrouted with
        // no attempt made and no error naming them.
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
             how a LB_FRONT_MAP overflow silently left later Services unrouted"
        );
        assert_eq!(
            failed, 1,
            "the one simulated failure must be counted, not swallowed, so the caller can turn \
             it into a loud reconcile-level error"
        );
    }

    #[test]
    fn node_allow_stale_peers_never_deletes_before_fronts_known_first_seen() {
        // Regression test for the restart-wipe bug: a controller
        // restart's `desired.node_allow` mid-Node-LIST is a strict SUBSET of
        // what a previous run already pinned to NODE_ALLOW -- exactly what
        // `existing`/`live` model here. If this guard is reverted (deletes
        // computed unconditionally), this call returns `[2, 3]` instead of
        // `[]`, and every not-yet-relisted peer's Geneve traffic gets
        // dropped until the full Node LIST completes.
        let existing = [1u32, 2, 3];
        let live = [1u32];

        let stale = node_allow_stale_peers(&existing, &live, false);

        assert_eq!(
            stale,
            Vec::<u32>::new(),
            "additive-only mode (fronts_known not yet seen true) must never delete a peer, even \
             though the restarted controller's live set is a strict subset of what's already \
             pinned -- deleting here is the restart-wipe bug fronts_known exists to prevent"
        );
    }

    #[test]
    fn node_allow_stale_peers_deletes_once_fronts_known_has_been_seen_true() {
        // Complement of the test above: once the latch has flipped (the
        // Node LIST is known-complete), NODE_ALLOW must go back to a real
        // full-sync, or a peer removed from the cluster stays admitted
        // forever.
        let existing = [1u32, 2, 3];
        let live = [1u32];

        let mut stale = node_allow_stale_peers(&existing, &live, true);
        stale.sort_unstable();

        assert_eq!(
            stale,
            vec![2, 3],
            "destructive full-sync mode must delete every peer no longer in the desired set, \
             the same way apply_pod_targets's full-sync already does"
        );
    }

    #[test]
    fn node_allow_may_delete_latches_true_once_fronts_known_has_been_seen() {
        // The latch itself: once `fronts_known` has been observed true on
        // any past tick, later ticks must stay destructive even if
        // `fronts_known` were to report false again -- a fresh
        // `PinnedMaps` (a controller restart) is the only thing allowed to
        // reset this back to additive-only.
        assert!(
            !node_allow_may_delete(false, false),
            "fronts_known never yet true and no latch set -- must stay additive-only"
        );
        assert!(
            node_allow_may_delete(true, false),
            "fronts_known true on this tick must switch to destructive mode immediately, not \
             wait for a later tick"
        );
        assert!(
            node_allow_may_delete(false, true),
            "the latch must stay tripped even if fronts_known transiently reports false again \
             -- regressing back to additive-only would silently stop pruning removed peers"
        );
    }
}
