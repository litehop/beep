//! Applies a `reconcile::DesiredEntries` to the dataplane's pinned
//! `FRONT_META`/`FRONT_ENDPOINTS`/`POD_TARGETS`/`NODE_ALLOW` maps. Opens them
//! from their bpffs
//! pins (`beep::attach_and_pin`'s loader already created them at load time)
//! rather than holding an `Ebpf` handle. Also opens `FWD_PENDING`/`FLOW_TABLE`
//! -- narrowed from "never touches" to "touches only via one targeted,
//! per-departed-pod conntrack eviction" (`apply_pod_targets`/
//! `beep::evict_pod_flows`): the kernel-written rows for every OTHER flow
//! must still survive every controller reconcile untouched.
//!
//! The front maps are written with the generation-swap protocol of
//! `beep::front_swap`, per front and only when its endpoint set changes: (1)
//! delete endpoint generation `g-1`, (2) write all slots under `g+1`, (3) one
//! `FRONT_META` update to `{g+1, count, flags}`. `FRONT_META` is a HASH map so
//! that single update is an atomic element replace for concurrent readers;
//! deleting a front drops its `FRONT_META` entry first, then its endpoints.
//! Every tick also deletes endpoint generations other than current and `g-1`,
//! which is what cleans up after a crashed predecessor on startup.

use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    path::Path,
};

use anyhow::Context;
use aya::maps::{HashMap as AyaHashMap, Map, MapData};
use beep::front_swap::{apply_fronts, DesiredFront};
use beep_common::{
    unmap_ipv4, FlowKey, FlowValue, ForwardFlowValue, FrontEndpoint, FrontEndpointKey, FrontMeta,
    LbFrontKey, TcpFlowKey,
};

use crate::reconcile::DesiredEntries;

/// The controller-written/-swept maps, opened once from their pins and
/// kept open across every reconcile tick (avoids a `MapData::from_pin`
/// syscall round trip per event).
pub struct PinnedMaps {
    front_meta: AyaHashMap<MapData, LbFrontKey, FrontMeta>,
    front_endpoints: AyaHashMap<MapData, FrontEndpointKey, FrontEndpoint>,
    pod_targets: AyaHashMap<MapData, [u8; 16], u8>,
    node_allow: AyaHashMap<MapData, [u8; 16], u8>,
    /// Opened for the eviction sweep only (`apply_pod_targets`) -- never
    /// diffed/full-synced like the four maps above.
    fwd_pending: AyaHashMap<MapData, TcpFlowKey, ForwardFlowValue>,
    flow_table: AyaHashMap<MapData, FlowKey, FlowValue>,
    /// "Has `fronts_known` ever been true in this process." Starts `false`
    /// on every controller start (including a restart), and once
    /// `apply` observes `fronts_known == true` it stays `true` for the rest
    /// of the process -- see `apply_node_allow`'s doc comment for why
    /// `NODE_ALLOW` needs its own sticky latch instead of just reading
    /// `desired.fronts_known` directly on each tick.
    fronts_ever_known: bool,
    /// Every cluster backend (and its pod uid, if known) as of the last tick
    /// whose sweep finished. In-memory only, so it cannot see a pod that
    /// departed while the controller was down; `orphans_swept` covers that.
    /// Local departures also survive a restart via the `POD_TARGETS` rows.
    known_backends: HashMap<[u8; 16], Option<String>>,
    /// Whether this process has done its one walk of the conntrack pins for
    /// backends absent from every slice (pods that left while the controller
    /// was down). Stays `false` until it succeeds.
    orphans_swept: bool,
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
            front_meta: open_hash_map(pin_dir, "FRONT_META")?,
            front_endpoints: open_hash_map(pin_dir, "FRONT_ENDPOINTS")?,
            pod_targets: open_hash_map(pin_dir, "POD_TARGETS")?,
            node_allow: open_hash_map(pin_dir, "NODE_ALLOW")?,
            // Both `FWD_PENDING`/`FLOW_TABLE` are `BPF_MAP_TYPE_LRU_HASH`
            // (`ebpf/src/main.rs`), not `BPF_MAP_TYPE_HASH` -- `open_hash_map`
            // still opens them correctly regardless: aya's `HashMap<K, V>`
            // wrapper accepts either kernel map type on conversion (its
            // `impl_try_from_map!` macro's `HashMap from HashMap|LruHashMap`
            // arm), and this helper's `Map::HashMap(map_data)` construction
            // is just a compile-time `TryFrom` selector, not a runtime check
            // against the fd's actual kernel map type.
            fwd_pending: open_hash_map(pin_dir, "FWD_PENDING")?,
            flow_table: open_hash_map(pin_dir, "FLOW_TABLE")?,
            fronts_ever_known: false,
            known_backends: HashMap::new(),
            orphans_swept: false,
        })
    }

    /// Brings each map's live contents to `desired` with the minimal writes --
    /// an unchanged reconcile costs only the read-back (`beep::front_swap`'s
    /// module doc for the front maps' generation-swap order). Runs every
    /// map to completion before propagating any error: a capacity failure
    /// on the front maps must never suppress the POD_TARGETS/NODE_ALLOW
    /// writes, nor one front's failure the writes of OTHER, unrelated
    /// Services in the same reconcile tick.
    ///
    /// Skips the front maps entirely while
    /// `desired.fronts_known` is `false` (`DesiredEntries`'s doc comment):
    /// syncing an empty `fronts` against these maps'
    /// actual contents would delete every front, even ones a previous run
    /// already programmed and pinned -- `desired.fronts_known == false`
    /// means "not known yet", not "no fronts should exist". NODE_ALLOW runs
    /// every tick regardless (see `apply_node_allow`'s doc comment): it
    /// stays additive-only (upsert, never delete) until `fronts_known`
    /// first becomes true this process, narrowing the cold-start Geneve
    /// blackout without reopening the restart-wipe window `fronts_known`
    /// exists to prevent. Skips the POD_TARGETS full-sync the same way as
    /// the front maps while `desired.pod_targets_known` is
    /// `false` -- same reasoning, keyed on this node's own Node LIST/watch
    /// entry instead of the whole list (`DesiredEntries::pod_targets_known`'s
    /// doc comment).
    pub fn apply(&mut self, desired: &DesiredEntries) -> anyhow::Result<()> {
        // Departed and reused pod IPs (cluster-wide, local or remote) are
        // swept in one walk BEFORE any new state naming them is written; on a
        // failed sweep only the installs naming those IPs are withheld and the
        // next tick retries.
        let installed_pod_targets: anyhow::Result<Vec<[u8; 16]>> = if desired.pod_targets_known {
            self.pod_targets
                .keys()
                .collect::<Result<_, _>>()
                .context("reading POD_TARGETS")
        } else {
            Ok(Vec::new())
        };
        let orphan_walk = if orphan_sweep_due(desired, self.orphans_swept) {
            let live: HashSet<[u8; 16]> = desired.cluster_backends.keys().copied().collect();
            Some(
                beep::orphaned_pin_backends(&self.fwd_pending, &self.flow_table, &live)
                    .context("walking conntrack for pins to departed backends"),
            )
        } else {
            None
        };
        let (orphans, orphan_walk_error) = match orphan_walk {
            Some(Ok(orphans)) => (Some(orphans), None),
            Some(Err(e)) => (None, Some(e)),
            None => (None, None),
        };
        let (fwd_pending, flow_table) = (&mut self.fwd_pending, &mut self.flow_table);
        let mut plan = plan_tick(
            desired,
            installed_pod_targets.as_deref().unwrap_or_default(),
            &mut self.known_backends,
            orphans.as_ref(),
            |pods| beep::evict_pod_flows(fwd_pending, flow_table, pods),
        );
        if orphans.is_some() && plan.sweep_error.is_none() {
            self.orphans_swept = true;
        }
        let sweep_result = match plan.sweep_error.take() {
            Some(e) => Err(e.context("sweeping flows of departed or reused backend pods")),
            None => orphan_walk_error.map_or(Ok(()), Err),
        };
        let fronts_result = if desired.fronts_known {
            apply_front_maps(
                &mut self.front_meta,
                &mut self.front_endpoints,
                &plan.fronts,
                plan.prune_fronts,
            )
        } else {
            Ok(())
        };
        self.fronts_ever_known =
            node_allow_may_delete(desired.fronts_known, self.fronts_ever_known);
        let node_allow_result = apply_node_allow(
            &mut self.node_allow,
            &desired.node_allow,
            self.fronts_ever_known,
        )
        .context("applying NODE_ALLOW");
        let pod_targets_result = match installed_pod_targets {
            Ok(_) if desired.pod_targets_known => {
                apply_pod_targets(&mut self.pod_targets, &plan.pod_targets, &plan.delete_rows)
                    .context("applying POD_TARGETS")
            }
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        };

        fronts_result?;
        node_allow_result?;
        pod_targets_result?;
        sweep_result?;
        Ok(())
    }
}

/// Runs `beep::front_swap::apply_fronts` and turns its per-front failures
/// into logged lines plus one loud reconcile-level error.
fn apply_front_maps(
    front_meta: &mut AyaHashMap<MapData, LbFrontKey, FrontMeta>,
    front_endpoints: &mut AyaHashMap<MapData, FrontEndpointKey, FrontEndpoint>,
    fronts: &HashMap<LbFrontKey, DesiredFront>,
    prune_absent: bool,
) -> anyhow::Result<()> {
    let failures = apply_fronts(front_meta, front_endpoints, fronts, prune_absent)
        .context("reading FRONT_META/FRONT_ENDPOINTS")?;
    for (front, message) in &failures {
        eprintln!(
            "controller: front {} {message} (front left on its previous endpoints -- map may be \
             at capacity)",
            describe_lb_front_key(front)
        );
    }
    if !failures.is_empty() {
        anyhow::bail!(
            "{} front write(s) failed -- see per-front errors above; {} / {}",
            failures.len(),
            beep::capacity_hint("FRONT_META"),
            beep::capacity_hint("FRONT_ENDPOINTS")
        );
    }
    Ok(())
}

fn describe_lb_front_key(key: &LbFrontKey) -> String {
    // front_ip is [u8; 16]; every value in play today is v4-mapped-v6, so this
    // always takes the Some arm -- the None arm is just a legible fallback
    // for a genuine v6 front, not yet reachable.
    let front = match unmap_ipv4(&key.front_ip) {
        Some(v4) => Ipv4Addr::from(u32::from_be(v4)).to_string(),
        None => format!("{:x?}", key.front_ip),
    };
    format!(
        "{front}:{}/proto={}",
        u16::from_be(key.front_port),
        key.proto
    )
}

/// `POD_TARGETS` isn't map-shaped like the front maps
/// (`reconcile::DesiredEntries::pod_targets` is a set, not a map), so it's a
/// full membership sync -- same prune-then-insert pattern as the loader's
/// own `populate_fixtures`. `delete_rows` are the departed rows whose conntrack
/// sweep already succeeded (`plan_tick`); `install` excludes IPs whose sweep is
/// still pending. Continues past an individual write failure, like the front
/// writes.
fn apply_pod_targets(
    map: &mut AyaHashMap<MapData, [u8; 16], u8>,
    install: &HashSet<[u8; 16]>,
    delete_rows: &HashSet<[u8; 16]>,
) -> anyhow::Result<()> {
    let mut failed = 0;
    for pod in delete_rows {
        if let Err(e) = map.remove(pod) {
            failed += 1;
            eprintln!(
                "controller: POD_TARGETS delete for pod {} failed: {e:#}",
                describe_pod_target_ip(*pod)
            );
        }
    }
    for ip in install {
        if let Err(e) = map.insert(ip, 1u8, 0) {
            failed += 1;
            eprintln!(
                "controller: POD_TARGETS upsert for pod {} failed (pod left undeliverable): \
                 {e:#}",
                describe_pod_target_ip(*ip)
            );
        }
    }
    if failed > 0 {
        anyhow::bail!(
            "{failed} write(s) to `POD_TARGETS` failed -- see per-entry errors above; {}",
            beep::capacity_hint("POD_TARGETS")
        );
    }
    Ok(())
}

/// Pod IPs present in both maps under different known uids: the IP now belongs
/// to a different pod, so conntrack rows pinned for the old owner would steer
/// its in-flight packets to the new one. New IPs, unchanged uids, and IPs
/// without a known uid on either side are never reused.
fn reused_pod_ips(
    known: &HashMap<[u8; 16], Option<String>>,
    desired: &HashMap<[u8; 16], Option<String>>,
) -> HashSet<[u8; 16]> {
    desired
        .iter()
        .filter(|(ip, uid)| match (known.get(*ip), uid) {
            (Some(Some(old)), Some(new)) => old != new,
            _ => false,
        })
        .map(|(ip, _)| *ip)
        .collect()
}

/// Whether this tick should walk the conntrack pins for orphaned backends:
/// once per process, only after Services, EndpointSlices and Nodes have all
/// been listed (`fronts_known`), and never against an empty backend set. The
/// relist guards cannot protect a first list (nothing is held to compare), so
/// an empty `cluster_backends` is treated as "not trustworthy yet" rather than
/// "every pin is an orphan"; the walk waits for a non-empty one.
fn orphan_sweep_due(desired: &DesiredEntries, already_swept: bool) -> bool {
    desired.fronts_known && !already_swept && !desired.cluster_backends.is_empty()
}

/// What one reconcile tick may write after its conntrack sweep.
pub(crate) struct TickPlan {
    /// The sweep's failure, if any; the caller reports it after every map has
    /// converged.
    sweep_error: Option<anyhow::Error>,
    /// Fronts to write: those naming an IP whose sweep is pending are held
    /// back at their installed endpoints.
    fronts: HashMap<LbFrontKey, DesiredFront>,
    /// False while a front is held back (pruning would delete it). This
    /// pauses pruning of every absent front, not just the held one, until the
    /// sweep succeeds: `plan_front_writes` only knows all-or-nothing pruning,
    /// and the pause is bounded by the sweep retry.
    prune_fronts: bool,
    /// `POD_TARGETS` IPs to insert, minus IPs whose sweep is pending.
    pod_targets: HashSet<[u8; 16]>,
    /// Departed `POD_TARGETS` rows to delete: only once their sweep succeeded,
    /// since the row is what makes the pod show up as departed on a retry.
    delete_rows: HashSet<[u8; 16]>,
}

/// Decides the sweep and runs it through `evict` (one conntrack walk for every
/// IP in the set), then derives what the rest of the tick may install.
///
/// The sweep covers (a) local `POD_TARGETS` rows no longer desired and (b)
/// every cluster backend that left `desired.cluster_backends` or came back
/// under a different uid -- including remote pods, whose pins live on this
/// (ingress) node but which `POD_TARGETS` never holds. On failure only the
/// swept IPs stay pending (in `known`, and out of the installs); everything
/// else converges. `orphans` (once per process, `orphan_sweep_due`) adds the
/// pins found to name a backend no slice carries, i.e. one that left while the
/// controller was down.
pub(crate) fn plan_tick(
    desired: &DesiredEntries,
    installed_pod_targets: &[[u8; 16]],
    known: &mut HashMap<[u8; 16], Option<String>>,
    orphans: Option<&HashSet<[u8; 16]>>,
    evict: impl FnOnce(&HashSet<[u8; 16]>) -> anyhow::Result<()>,
) -> TickPlan {
    let mut sweep: HashSet<[u8; 16]> = orphans.cloned().unwrap_or_default();
    let mut delete_rows = HashSet::new();
    if desired.pod_targets_known {
        let live: Vec<[u8; 16]> = desired.pod_targets.iter().copied().collect();
        delete_rows = beep::stale_pod_targets(installed_pod_targets, &live)
            .into_iter()
            .collect();
        sweep.extend(delete_rows.iter().copied());
        sweep.extend(
            known
                .keys()
                .filter(|ip| !desired.cluster_backends.contains_key(*ip))
                .copied(),
        );
        sweep.extend(reused_pod_ips(known, &desired.cluster_backends));
    }

    let sweep_error = if sweep.is_empty() {
        None
    } else {
        evict(&sweep).err()
    };
    let pending: HashSet<[u8; 16]> = if sweep_error.is_some() {
        sweep
    } else {
        HashSet::new()
    };

    if desired.pod_targets_known {
        if sweep_error.is_some() {
            known.retain(|ip, _| pending.contains(ip));
            for (ip, uid) in &desired.cluster_backends {
                if !pending.contains(ip) {
                    known.insert(*ip, uid.clone());
                }
            }
            delete_rows.clear();
        } else {
            known.clone_from(&desired.cluster_backends);
        }
    }

    let fronts: HashMap<_, _> = desired
        .fronts
        .iter()
        .filter(|(_, front)| {
            !front
                .endpoints
                .iter()
                .any(|ep| pending.contains(&ep.backend.pod_ip))
        })
        .map(|(key, front)| (*key, front.clone()))
        .collect();
    TickPlan {
        prune_fronts: fronts.len() == desired.fronts.len(),
        fronts,
        pod_targets: desired.pod_targets.difference(&pending).copied().collect(),
        delete_rows,
        sweep_error,
    }
}

/// Formats a `POD_TARGETS` pod IP for logging. Unlike `describe_node_allow_peer`'s
/// host-native peer key, this key is wire_ip-wrapped (`pod_targets_for_node`'s doc
/// comment), so recovering the dotted-octet form needs the extra `u32::from_be`.
fn describe_pod_target_ip(ip: [u8; 16]) -> String {
    match unmap_ipv4(&ip) {
        Some(wire) => Ipv4Addr::from(u32::from_be(wire)).to_string(),
        None => format!("{ip:x?}"),
    }
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

/// Formats a `NODE_ALLOW` peer key for logging. Keys are host-native,
/// v4-mapped-v6 (`DesiredEntries::node_allow`'s doc comment) -- every value
/// in play today unmaps cleanly; the fallback is just a legible stand-in for
/// a genuine v6 peer, not yet reachable.
fn describe_node_allow_peer(peer: [u8; 16]) -> String {
    match unmap_ipv4(&peer) {
        Some(v4) => Ipv4Addr::from(v4).to_string(),
        None => format!("{peer:x?}"),
    }
}

/// `NODE_ALLOW`'s peer-attestation full-sync -- same set-shaped,
/// prune-then-insert pattern as `apply_pod_targets` above, reusing the same
/// generic `beep::stale_pod_targets` set diff.
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
    map: &mut AyaHashMap<MapData, [u8; 16], u8>,
    desired: &HashSet<[u8; 16]>,
    may_delete: bool,
) -> anyhow::Result<()> {
    let live: Vec<[u8; 16]> = desired.iter().copied().collect();
    let existing: Vec<[u8; 16]> = if may_delete {
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
                describe_node_allow_peer(stale)
            );
        }
    }
    for ip in &live {
        if let Err(e) = map.insert(ip, 1u8, 0) {
            failed += 1;
            eprintln!(
                "controller: NODE_ALLOW upsert for peer {} failed (node left unreachable): \
                 {e:#}",
                describe_node_allow_peer(*ip)
            );
        }
    }
    if failed > 0 {
        anyhow::bail!(
            "{failed} write(s) to `NODE_ALLOW` failed -- see per-entry errors above; {}",
            beep::capacity_hint("NODE_ALLOW")
        );
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
fn node_allow_stale_peers(
    existing: &[[u8; 16]],
    live: &[[u8; 16]],
    may_delete: bool,
) -> Vec<[u8; 16]> {
    if may_delete {
        beep::stale_pod_targets(existing, live)
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use beep_common::{ipv4_mapped_v6, LbFrontBackend};

    type Known = HashMap<[u8; 16], Option<String>>;

    fn ip(n: u32) -> [u8; 16] {
        ipv4_mapped_v6(n)
    }

    fn backends(pairs: &[(u32, Option<&str>)]) -> Known {
        pairs
            .iter()
            .map(|(n, uid)| (ip(*n), uid.map(str::to_owned)))
            .collect()
    }

    fn front_key(port: u16) -> LbFrontKey {
        LbFrontKey {
            front_ip: ip(100),
            front_port: port,
            proto: 6,
            _pad: 0,
        }
    }

    fn front_to(pod: u32) -> DesiredFront {
        DesiredFront {
            flags: 0,
            endpoints: vec![FrontEndpoint {
                backend: LbFrontBackend {
                    backend_node_ip: ip(200),
                    pod_ip: ip(pod),
                },
                target_port: 80,
                _pad: [0; 6],
            }],
        }
    }

    fn desired(cluster: Known, local: &[u32], fronts: &[(u16, u32)]) -> DesiredEntries {
        DesiredEntries {
            fronts: fronts
                .iter()
                .map(|(port, pod)| (front_key(*port), front_to(*pod)))
                .collect(),
            pod_targets: local.iter().map(|n| ip(*n)).collect(),
            cluster_backends: cluster,
            fronts_known: true,
            pod_targets_known: true,
            ..DesiredEntries::default()
        }
    }

    /// Runs `plan_tick` with an evictor that records its calls.
    fn tick(
        d: &DesiredEntries,
        installed: &[u32],
        known: &mut Known,
        fail: bool,
    ) -> (TickPlan, Vec<HashSet<[u8; 16]>>) {
        tick_with_orphans(d, installed, known, None, fail)
    }

    fn tick_with_orphans(
        d: &DesiredEntries,
        installed: &[u32],
        known: &mut Known,
        orphans: Option<&HashSet<[u8; 16]>>,
        fail: bool,
    ) -> (TickPlan, Vec<HashSet<[u8; 16]>>) {
        let installed: Vec<[u8; 16]> = installed.iter().map(|n| ip(*n)).collect();
        let mut calls = Vec::new();
        let plan = plan_tick(d, &installed, known, orphans, |pods| {
            calls.push(pods.clone());
            if fail {
                anyhow::bail!("map iter failed")
            }
            Ok(())
        });
        (plan, calls)
    }

    fn set(ns: &[u32]) -> HashSet<[u8; 16]> {
        ns.iter().map(|n| ip(*n)).collect()
    }

    #[test]
    fn departed_remote_backend_is_swept_on_the_ingress_node() {
        // Pins to a pod on another node live here, but POD_TARGETS only holds
        // local pods: without cluster-wide tracking the flow blackholes at
        // the backend's decap check until LRU eviction.
        let mut known = backends(&[(7, Some("remote"))]);
        let d = desired(Known::new(), &[], &[]);
        let (plan, calls) = tick(&d, &[], &mut known, false);
        assert_eq!(calls, vec![set(&[7])]);
        assert!(plan.sweep_error.is_none());
        assert!(known.is_empty(), "swept pod is forgotten");
    }

    #[test]
    fn reused_remote_ip_is_swept_before_the_new_pod_is_fronted() {
        // The old pod's pins would otherwise steer in-flight packets to the
        // different workload that now owns the IP.
        let mut known = backends(&[(7, Some("old"))]);
        let d = desired(backends(&[(7, Some("new"))]), &[], &[(80, 7)]);
        let (plan, calls) = tick(&d, &[], &mut known, false);
        assert_eq!(calls, vec![set(&[7])]);
        assert!(plan.sweep_error.is_none());
        assert_eq!(known, backends(&[(7, Some("new"))]));
    }

    #[test]
    fn unchanged_new_or_unidentified_backends_never_sweep() {
        // A sweep resets live flows; it must only fire on a real departure or
        // identity change.
        let mut known = backends(&[(1, Some("a")), (2, None), (3, Some("c"))]);
        let d = desired(
            backends(&[(1, Some("a")), (2, Some("x")), (3, None), (4, Some("d"))]),
            &[],
            &[],
        );
        let (_, calls) = tick(&d, &[], &mut known, false);
        assert!(calls.is_empty(), "no pod left or changed owner: {calls:?}");
    }

    #[test]
    fn local_departed_row_is_swept_even_after_a_controller_restart() {
        // `known` is empty after a restart; the POD_TARGETS row is the only
        // record that the local pod ever existed.
        let mut known = Known::new();
        let d = desired(Known::new(), &[], &[]);
        let (plan, calls) = tick(&d, &[5], &mut known, false);
        assert_eq!(calls, vec![set(&[5])]);
        assert_eq!(plan.delete_rows, set(&[5]));
    }

    #[test]
    fn remote_backend_that_left_while_the_controller_was_down_is_swept_after_restart() {
        // `known` is empty after a restart and the pod is remote, so neither
        // `known` nor POD_TARGETS remembers it: only the orphan walk's result
        // can get its pins swept, and without it they blackhole at the
        // backend's decap until LRU eviction.
        let mut known = Known::new();
        let d = desired(backends(&[(1, Some("live"))]), &[], &[(80, 1)]);
        let (plan, calls) = tick_with_orphans(&d, &[], &mut known, Some(&set(&[7])), false);
        assert_eq!(calls, vec![set(&[7])]);
        assert!(plan.sweep_error.is_none());
        assert_eq!(plan.fronts.len(), 1, "live fronts are unaffected");
    }

    #[test]
    fn failed_orphan_sweep_is_reported_so_the_next_tick_retries_it() {
        let mut known = Known::new();
        let d = desired(backends(&[(1, None)]), &[], &[]);
        let (plan, calls) = tick_with_orphans(&d, &[], &mut known, Some(&set(&[7])), true);
        assert_eq!(calls, vec![set(&[7])]);
        assert!(plan.sweep_error.is_some());
    }

    #[test]
    fn orphan_sweep_waits_for_a_full_listing_and_a_non_empty_backend_set_and_runs_once() {
        let d = desired(backends(&[(1, None)]), &[], &[]);
        assert!(orphan_sweep_due(&d, false));
        assert!(
            !orphan_sweep_due(&d, true),
            "a second walk would reset flows pinned since the first"
        );
        let mut partial = desired(backends(&[(1, None)]), &[], &[]);
        partial.fronts_known = false;
        assert!(
            !orphan_sweep_due(&partial, false),
            "before the full listing every pin looks orphaned"
        );
        let empty = desired(Known::new(), &[], &[]);
        assert!(
            !orphan_sweep_due(&empty, false),
            "an empty first list is untrusted: sweeping against it would reset every live flow"
        );
    }

    #[test]
    fn every_departed_and_reused_ip_shares_one_table_walk() {
        let mut known = backends(&[(1, Some("a")), (2, Some("b")), (3, Some("c"))]);
        let d = desired(backends(&[(3, Some("c2"))]), &[], &[]);
        let (_, calls) = tick(&d, &[9], &mut known, false);
        assert_eq!(calls, vec![set(&[1, 2, 3, 9])]);
    }

    #[test]
    fn unknown_pod_targets_skip_the_sweep_and_keep_tracking() {
        // Own node not resolved yet: the cluster set is untrustworthy, so
        // nothing may be swept or forgotten.
        let mut known = backends(&[(7, Some("remote"))]);
        let mut d = desired(Known::new(), &[], &[]);
        d.pod_targets_known = false;
        let (_, calls) = tick(&d, &[], &mut known, false);
        assert!(calls.is_empty());
        assert_eq!(known, backends(&[(7, Some("remote"))]));
    }

    #[test]
    fn failed_sweep_withholds_only_the_affected_ips_installs() {
        // R's IP changed owner and its sweep fails; S is unrelated. S's front
        // and POD_TARGETS row, and a new front, must still converge -- only
        // what names R waits for the retry.
        let mut known = backends(&[(7, Some("old")), (8, Some("s"))]);
        let d = desired(
            backends(&[(7, Some("new")), (8, Some("s")), (9, Some("t"))]),
            &[7, 8, 9],
            &[(80, 7), (81, 8), (82, 9)],
        );
        let (plan, calls) = tick(&d, &[7, 8], &mut known, true);
        assert_eq!(calls, vec![set(&[7])]);
        assert!(plan.sweep_error.is_some());
        assert_eq!(
            plan.fronts.keys().copied().collect::<HashSet<_>>(),
            [front_key(81), front_key(82)].into_iter().collect(),
            "only the front naming the unswept IP is held back"
        );
        assert!(
            !plan.prune_fronts,
            "pruning would delete the held-back front instead of leaving it"
        );
        assert_eq!(plan.pod_targets, set(&[8, 9]));
        assert_eq!(
            known,
            backends(&[(7, Some("old")), (8, Some("s")), (9, Some("t"))]),
            "the reuse stays pending; unaffected backends are tracked"
        );

        let (plan, calls) = tick(&d, &[7, 8], &mut known, false);
        assert_eq!(calls, vec![set(&[7])], "the retry sweeps the pending IP");
        assert_eq!(plan.fronts.len(), 3);
        assert!(plan.prune_fronts);
        assert_eq!(plan.pod_targets, set(&[7, 8, 9]));
    }

    #[test]
    fn failed_sweep_keeps_departed_pod_rows_so_next_tick_retries() {
        // Deleting the row before a failed sweep orphans that pod's flows
        // forever: nothing would mark it departed again.
        let mut known = Known::new();
        let d = desired(Known::new(), &[], &[]);
        let (plan, _) = tick(&d, &[1, 2], &mut known, true);
        assert!(plan.delete_rows.is_empty());
        let (plan, calls) = tick(&d, &[1, 2], &mut known, false);
        assert_eq!(calls, vec![set(&[1, 2])]);
        assert_eq!(plan.delete_rows, set(&[1, 2]));
    }

    #[test]
    fn departed_pod_whose_sweep_is_pending_is_recognised_when_its_ip_returns() {
        // The IP leaves, the sweep fails, the IP returns under a new pod: the
        // departed pod's pins must still be swept.
        let mut known = backends(&[(1, Some("old"))]);
        let gone = desired(Known::new(), &[], &[]);
        let (_, _) = tick(&gone, &[], &mut known, true);
        let back = desired(backends(&[(1, Some("new"))]), &[], &[]);
        let (_, calls) = tick(&back, &[], &mut known, false);
        assert_eq!(calls, vec![set(&[1])]);
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
        let existing = [ipv4_mapped_v6(1), ipv4_mapped_v6(2), ipv4_mapped_v6(3)];
        let live = [ipv4_mapped_v6(1)];

        let stale = node_allow_stale_peers(&existing, &live, false);

        assert_eq!(
            stale,
            Vec::<[u8; 16]>::new(),
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
        let existing = [ipv4_mapped_v6(1), ipv4_mapped_v6(2), ipv4_mapped_v6(3)];
        let live = [ipv4_mapped_v6(1)];

        let mut stale = node_allow_stale_peers(&existing, &live, true);
        stale.sort_unstable();

        assert_eq!(
            stale,
            vec![ipv4_mapped_v6(2), ipv4_mapped_v6(3)],
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
