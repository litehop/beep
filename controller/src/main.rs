//! beep-controller: the per-node ServiceLB DaemonSet binary
//! (`docs/design/ebpf-lb-dataplane.md`'s "Userspace control plane" section).
//! Loads, attaches, and pins the three tc-bpf classifiers via the `beep`
//! lib (the same load/attach/pin invariants the standalone loader uses),
//! sets `CONFIG`, then watches `Service`(type=LoadBalancer)/`EndpointSlice`/
//! `Node` and programs `FRONT_META`/`FRONT_ENDPOINTS`/`POD_TARGETS` on every
//! change. No persistent proxy loop -- the kernel forwards packets; this
//! process idles between watch events.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::Context;
use aya::programs::TcAttachType;
use beep::{
    attach_and_pin, disable_rp_filter, ensure_geneve_iface, front_map_max_entries, load_ebpf,
    parse_iface_name, populate_config, populate_uplink_config, DEFAULT_ENDPOINTS_PER_FRONT,
    DEFAULT_MAX_FRONTS, DEFAULT_NODE_ALLOW_MAX_ENTRIES, DEFAULT_POD_TARGETS_MAX_ENTRIES,
};
use beep_controller::{
    apply::PinnedMaps,
    event::{report_restore_failure, PodRef},
    lease::{
        confirmed_pruned_ingress, lease_name, list_leases, may_prune, renew_lease, LeaseTracker,
        PruneSuspects, LEASE_RENEW, PRUNE_JITTER_MAX,
    },
    reconcile::{DesiredEntries, IpCidr, Ipv4Cidr, Ipv6Cidr, NodeContext},
    seed::{converge_seed, load_or_create_seed},
    status::{ensure_node_ingress, update_ingress},
    watch::{
        deleted_service_key, run_list_watch, stale_ingress_key, stale_ingress_keys, ServiceKey,
        WatchState,
    },
};
use beep_kubeconfig::{build_tls_connector, parse_kubeconfig, HyperApiClient};
use clap::Parser;
use serde_json::Value;

// Heap-profiling build only: routes every allocation through dhat so a
// SIGINT-triggered flush (see `main`) can attribute idle RSS to call sites.
// Not present in the default build -- the shipped binary keeps the system
// allocator.
#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

const SEED_POLL: Duration = Duration::from_secs(30);

const DEFAULT_FWD_PENDING_MAX_ENTRIES: u32 = 2048;
const DEFAULT_FLOW_TABLE_MAX_ENTRIES: u32 = 16384;

#[derive(Parser, Debug)]
#[command(
    name = "beep-controller",
    about = "beep ServiceLB DaemonSet: watch Kubernetes, program the dataplane"
)]
struct Args {
    /// The CLIENT-FACING uplink interface(s) (e.g. eth0) -- NOT the Geneve
    /// tunnel device. Repeatable: a node admits client traffic on any
    /// configured uplink and symmetrically returns on the same one
    /// (`docs/decisions/servicelb-multi-symmetric-uplink.md`).
    /// `uplink_egress_return` only fires on the device it's attached to, and
    /// a backend node routes the client reply out its client-facing NIC, not
    /// the tunnel -- attaching this to the tunnel device would leak a raw
    /// backend-sourced reply out the real uplink unencapsulated.
    #[arg(long = "uplink-iface", required_unless_present = "node_prep", value_parser = parse_iface_name)]
    uplink_ifaces: Vec<String>,

    /// Geneve tunnel interface (hook: geneve ingress, both directions).
    #[arg(long, default_value = "geneve0", value_parser = parse_iface_name)]
    geneve_iface: String,

    /// Directory on a bpffs mount where programs/links/maps are pinned.
    #[arg(long, default_value = "/sys/fs/bpf/beep")]
    pin_dir: PathBuf,

    /// Runs ONLY node self-prep -- create `geneve0`, then write
    /// `rp_filter=0` on `all` and `geneve0` -- and exits. This is the
    /// entrypoint the privileged initContainer runs: containerd's default
    /// readonlyPaths mask `/proc/sys` off for the non-privileged main
    /// container, so that write has to happen somewhere privileged before
    /// the main container starts
    /// (`docs/decisions/servicelb-rp-filter-init-container.md`). Makes
    /// `pod_cidr`/`node_ip`/`kubeconfig` below optional, since this mode
    /// never reaches the code that needs them.
    #[arg(long)]
    node_prep: bool,

    /// Cluster pod CIDR (e.g. `10.244.0.0/16` or `fd00:10:244::/56`) --
    /// scopes `POD_TARGETS` membership to endpoints whose pod_ip actually
    /// falls inside it (`reconcile::NodeContext`'s doc comment).
    #[arg(long = "pod-cidr", value_parser = parse_ip_cidr, required_unless_present = "node_prep")]
    pod_cidr: Option<IpCidr>,

    /// This node's own address: the LB front IP every `type=LoadBalancer`
    /// Service resolves to on this node (the node-owned-address model,
    /// `ebpf-lb-dataplane.md`), and the value `POD_TARGETS` scopes local
    /// backend membership against.
    #[arg(long = "node-ip", required_unless_present = "node_prep")]
    node_ip: Option<IpAddr>,

    /// Path to a kubeconfig with credentials for this DaemonSet's watch.
    #[arg(long, required_unless_present = "node_prep")]
    kubeconfig: Option<String>,

    /// Namespace holding the `servicelb-flow-hash-seed` Secret: the cluster-wide
    /// key for backend selection, created by the first controller to start
    /// and read by the rest. Must be the namespace `deploy/rbac.yaml` grants
    /// Secret access in.
    #[arg(long, default_value = "kube-system")]
    seed_namespace: String,

    /// This node's Kubernetes name: names its liveness Lease
    /// (`beep-node-<name>`), which other controllers use to decide whether
    /// this node may stay in `status.loadBalancer.ingress`.
    #[arg(long, env = "NODE_NAME", required_unless_present = "node_prep")]
    node_name: Option<String>,

    /// This pod's name and namespace (downward API): with both set, a failed
    /// map restore also posts its Event on the pod.
    #[arg(long, env = "POD_NAME")]
    pod_name: Option<String>,

    #[arg(long, env = "POD_NAMESPACE")]
    pod_namespace: Option<String>,

    #[arg(long, env = "POD_UID")]
    pod_uid: Option<String>,

    /// Namespace for the per-node Leases; must be the namespace
    /// `deploy/rbac.yaml` grants Lease access in.
    #[arg(long, default_value = "beep-leases")]
    lease_namespace: String,

    /// `FWD_PENDING` max_entries (see `beep-ebpf`'s doc comment); a
    /// load-time DaemonSet config knob, not baked into the eBPF object.
    #[arg(long, default_value_t = DEFAULT_FWD_PENDING_MAX_ENTRIES)]
    fwd_pending_max_entries: u32,

    /// `FLOW_TABLE` max_entries (see `beep-ebpf`'s doc comment).
    #[arg(long, default_value_t = DEFAULT_FLOW_TABLE_MAX_ENTRIES)]
    flow_table_max_entries: u32,

    /// Most fronts (front address x Service port x protocol) the node can
    /// hold. Sizes `FRONT_META` (max_fronts rows) and, with
    /// `--endpoints-per-front`, `FRONT_ENDPOINTS` (max_fronts x
    /// endpoints_per_front x 2 rows; the 2 is swap headroom). Both maps are
    /// allocated on use, so unused capacity costs only ~16 B per slot.
    #[arg(long, env = "BEEP_MAX_FRONTS", default_value_t = DEFAULT_MAX_FRONTS)]
    max_fronts: u32,

    /// Endpoints each front is sized for; see `--max-fronts` for the
    /// `FRONT_ENDPOINTS` row formula.
    #[arg(
        long,
        env = "BEEP_ENDPOINTS_PER_FRONT",
        default_value_t = DEFAULT_ENDPOINTS_PER_FRONT
    )]
    endpoints_per_front: u32,

    /// `NODE_ALLOW` max_entries: one entry per node underlay address, so a
    /// dual-stack node costs two (see `beep-ebpf`'s doc comment).
    #[arg(long, default_value_t = DEFAULT_NODE_ALLOW_MAX_ENTRIES)]
    node_allow_max_entries: u32,

    /// `POD_TARGETS` max_entries: one entry per local backend pod IP, so a
    /// dual-stack pod costs two (see `beep-ebpf`'s doc comment).
    #[arg(long, default_value_t = DEFAULT_POD_TARGETS_MAX_ENTRIES)]
    pod_targets_max_entries: u32,
}

fn parse_ipv4_cidr(s: &str) -> Result<Ipv4Cidr, String> {
    let (network, prefix_len) = s
        .split_once('/')
        .ok_or_else(|| format!("expected network_ip/prefix_len, got `{s}`"))?;
    let network: Ipv4Addr = network
        .parse()
        .map_err(|e| format!("pod_cidr network `{network}`: {e}"))?;
    let prefix_len: u8 = prefix_len
        .parse()
        .map_err(|e| format!("pod_cidr prefix_len `{prefix_len}`: {e}"))?;
    if prefix_len > 32 {
        return Err(format!("pod_cidr prefix_len `{prefix_len}` must be 0..=32"));
    }
    Ok(Ipv4Cidr::new(network, prefix_len))
}

/// `--pod-cidr`'s dual-stack parser, same family dispatch as the loader's
/// own `parse_ip_cidr` (`src/main.rs`): the network address's own family,
/// not a separate flag, picks `IpCidr::V4`/`V6`, so an operator configures
/// exactly one CIDR for whichever pod network family this cluster actually
/// runs.
fn parse_ip_cidr(s: &str) -> Result<IpCidr, String> {
    let (network, prefix_len) = s
        .split_once('/')
        .ok_or_else(|| format!("expected network_ip/prefix_len, got `{s}`"))?;
    if network.parse::<Ipv6Addr>().is_ok() {
        let network: Ipv6Addr = network
            .parse()
            .map_err(|e| format!("pod_cidr network `{network}`: {e}"))?;
        let prefix_len: u8 = prefix_len
            .parse()
            .map_err(|e| format!("pod_cidr prefix_len `{prefix_len}`: {e}"))?;
        if prefix_len > 128 {
            return Err(format!(
                "pod_cidr prefix_len `{prefix_len}` must be 0..=128"
            ));
        }
        Ok(IpCidr::V6(Ipv6Cidr::new(network, prefix_len)))
    } else {
        parse_ipv4_cidr(s).map(IpCidr::V4)
    }
}

/// First retry delay after a failed apply. A failed eviction sweep leaves
/// flows pinned to a departed pod, so the first retry is quick.
const RETRY_INITIAL: Duration = Duration::from_secs(1);
/// Cap on the doubling delay: a persistent failure (e.g. a full map) costs one
/// cheap map read-back per 30s, while a transient one still heals within 30s.
const RETRY_MAX: Duration = Duration::from_secs(30);
/// How often the retry task checks whether a retry is due.
const RETRY_POLL: Duration = Duration::from_secs(1);

/// Bounded exponential backoff for re-running a failed reconcile without
/// waiting for a watch event (a quiet cluster may never send one).
#[derive(Default)]
struct RetryBackoff {
    failures: u32,
    retry_at: Option<Instant>,
}

impl RetryBackoff {
    /// A failure while a retry is still pending (a watch event mid-backoff)
    /// keeps the armed deadline and the delay, so an event storm cannot
    /// postpone the retry or inflate the backoff; only a failed attempt at or
    /// past the deadline grows it.
    fn record(&mut self, ok: bool, now: Instant) {
        if ok {
            *self = Self::default();
            return;
        }
        if self.retry_at.is_some_and(|at| now < at) {
            return;
        }
        let delay = RETRY_INITIAL
            .saturating_mul(1u32.checked_shl(self.failures).unwrap_or(u32::MAX))
            .min(RETRY_MAX);
        self.failures = self.failures.saturating_add(1);
        self.retry_at = Some(now + delay);
    }

    fn due(&self, now: Instant) -> bool {
        self.retry_at.is_some_and(|at| now >= at)
    }
}

/// Runs `apply` and records its outcome in `retry`.
fn reconcile_once(
    apply: impl FnOnce() -> anyhow::Result<()>,
    retry: &Mutex<RetryBackoff>,
    now: Instant,
) {
    let result = apply();
    if let Err(e) = &result {
        eprintln!("controller: applying reconciled maps failed (will retry): {e:#}");
    }
    retry.lock().unwrap().record(result.is_ok(), now);
}

/// Runs `run` only when a retry is due; returns whether it ran.
fn retry_tick(retry: &Mutex<RetryBackoff>, now: Instant, run: impl FnOnce()) -> bool {
    let due = retry.lock().unwrap().due(now);
    if due {
        run();
    }
    due
}

fn apply_reconcile(
    state: &Mutex<WatchState>,
    maps: &Mutex<PinnedMaps>,
    retry: &Mutex<RetryBackoff>,
    node: &NodeContext,
) {
    let desired = state.lock().unwrap().desired(node);
    warn_on_rejected_endpoints(&desired, node);
    reconcile_once(
        || maps.lock().unwrap().apply(&desired),
        retry,
        Instant::now(),
    );
}

/// Re-runs the full reconcile whenever `retry` says a failed apply is due, and
/// once a swapped front's previous generation has outlived its grace (a quiet
/// cluster sends no event that would delete it).
/// Never returns; `Result` only so it joins with the watches.
async fn run_retry_loop(
    state: Arc<Mutex<WatchState>>,
    maps: Arc<Mutex<PinnedMaps>>,
    retry: Arc<Mutex<RetryBackoff>>,
    node: NodeContext,
) -> anyhow::Result<()> {
    loop {
        tokio::time::sleep(RETRY_POLL).await;
        let ran = retry_tick(&retry, Instant::now(), || {
            apply_reconcile(&state, &maps, &retry, &node)
        });
        follow_up_tick(
            ran,
            || {
                maps.lock()
                    .unwrap()
                    .previous_generations_due(Instant::now())
            },
            || apply_reconcile(&state, &maps, &retry, &node),
        );
    }
}

/// Runs `reconcile` when a swapped front's previous generation has outlived
/// its grace, unless a retry already reconciled on this tick (that pass has
/// already deleted whatever was due). `grace_expired` is only asked when no
/// retry ran.
fn follow_up_tick(ran: bool, grace_expired: impl FnOnce() -> bool, reconcile: impl FnOnce()) {
    if !ran && grace_expired() {
        reconcile();
    }
}

/// Re-reads the seed Secret every `SEED_POLL` and converges CONFIG on it, so a
/// rotation or deletion cannot leave this node hashing with a seed the rest
/// of the cluster (or a restarting node) no longer uses. A failed pass keeps
/// the current seed and is retried on the next tick.
async fn run_seed_loop(
    client: Arc<HyperApiClient>,
    namespace: String,
    pin_dir: PathBuf,
    mut current: u64,
) -> anyhow::Result<()> {
    loop {
        tokio::time::sleep(SEED_POLL).await;
        current = converge_seed(&client, &namespace, &pin_dir, current).await;
    }
}

/// Renews this node's Lease every `LEASE_RENEW`. The first renew runs
/// immediately so the Lease exists before peers' warm-up ends.
async fn run_lease_loop(
    client: Arc<HyperApiClient>,
    state: Arc<Mutex<WatchState>>,
    namespace: String,
    node_name: String,
    node_ip: IpAddr,
) -> anyhow::Result<()> {
    loop {
        let ips = state.lock().unwrap().own_node_ips(node_ip);
        if let Err(e) = renew_lease(&client, &namespace, &node_name, &ips).await {
            eprintln!("controller: WARN renewing node Lease failed (will retry): {e:#}");
        }
        tokio::time::sleep(LEASE_RENEW).await;
    }
}

/// Removes ingress entries of nodes with no live Lease from every tracked
/// Service. Skipped until this process has observed leases for a full
/// duration and sees its own Lease renewing: if the Lease path is broken
/// (e.g. RBAC) every node would otherwise look dead.
async fn run_prune_loop(
    client: Arc<HyperApiClient>,
    state: Arc<Mutex<WatchState>>,
    namespace: String,
    node_name: String,
) -> anyhow::Result<()> {
    let own_lease = lease_name(&node_name);
    let mut tracker = LeaseTracker::new(Instant::now());
    let suspects = Mutex::new(PruneSuspects::default());
    loop {
        let jitter_ms = beep::random_seed().unwrap_or(0) % PRUNE_JITTER_MAX.as_millis() as u64;
        tokio::time::sleep(LEASE_RENEW + Duration::from_millis(jitter_ms)).await;
        match list_leases(&client, &namespace).await {
            Ok(listed) => tracker.observe(listed, Instant::now()),
            Err(e) => {
                eprintln!("controller: WARN listing node Leases failed: {e:#}");
                continue;
            }
        }
        let now = Instant::now();
        if !may_prune(&tracker, &own_lease, now) {
            suspects.lock().unwrap().reset();
            continue;
        }
        let keys = state.lock().unwrap().service_keys();
        for key in keys {
            let result = update_ingress(&client, &key.namespace, &key.name, |existing| {
                confirmed_pruned_ingress(
                    existing,
                    tracker.leases(),
                    now,
                    &mut suspects.lock().unwrap(),
                )
            })
            .await;
            if let Err(e) = result {
                eprintln!(
                    "controller: WARN pruning dead nodes from {}/{} failed: {e:#}",
                    key.namespace, key.name
                );
            }
        }
        suspects.lock().unwrap().end_pass();
    }
}

/// A rejected endpoint is nearly always a misconfigured `--pod-cidr` (every
/// endpoint on every node gets rejected the same way), not a one-off bad
/// actor -- see `RejectedEndpoint`'s doc comment. Without this, that
/// misconfiguration empties `POD_TARGETS` and drops every forward packet at
/// decap admission with nothing in any log naming why.
fn warn_on_rejected_endpoints(desired: &DesiredEntries, node: &NodeContext) {
    if desired.rejected.is_empty() {
        return;
    }
    let pod_ips: Vec<String> = desired
        .rejected
        .iter()
        .map(|r| r.pod_ip.to_string())
        .collect();
    eprintln!(
        "controller: WARN {} endpoint(s) rejected from POD_TARGETS: pod_ip [{}] outside \
         configured pod_cidr {} -- double check --pod-cidr matches this cluster's real pod \
         network (deploy/README.md's pod-cidr gotcha)",
        desired.rejected.len(),
        pod_ips.join(", "),
        node.pod_cidr
    );
}

/// Whether a Node event actually changed the set of addresses THIS node's
/// own Node object reports -- `on_node`'s decision on whether to republish
/// `status.loadBalancer.ingress` for every tracked Service. A Node event
/// that leaves this node's own addresses unchanged (a label-only update,
/// or the same address redelivered) must not trigger a redundant status
/// write for every Service just because *some* Node event fired.
fn own_node_ips_changed(before: &[IpAddr], after: &[IpAddr]) -> bool {
    let before: HashSet<&IpAddr> = before.iter().collect();
    let after: HashSet<&IpAddr> = after.iter().collect();
    before != after
}

/// Re-asserts this node's own address(es) in `status.loadBalancer.ingress`
/// for the ONE Service `key` that just changed -- not every tracked
/// Service -- since a Service watch event only ever means that Service's
/// own status could be stale. `own_ips`/`desired_ips` are
/// `WatchState::own_node_ips`/`ips_to_publish`'s outputs: a single
/// `ensure_node_ingress` call both publishes every family `key` currently
/// fronts on this node and prunes any of this node's own entries for a
/// family it stopped fronting (`status::merged_ingress`'s doc comment).
/// `tokio::spawn`s rather than awaiting inline in the (synchronous)
/// watch-event callback: `run_list_watch`'s `on_event` is a plain `FnMut`,
/// not an async fn, so a network round trip here can't be awaited inline
/// without blocking the single `current_thread` runtime this process's
/// other two list-watches also depend on.
fn publish_ingress(
    client: &Arc<HyperApiClient>,
    pending: &Arc<Mutex<PublishRetry>>,
    key: ServiceKey,
    own_ips: Vec<IpAddr>,
    desired_ips: Vec<IpAddr>,
    clear: bool,
) {
    let client = Arc::clone(client);
    let pending = Arc::clone(pending);
    tokio::spawn(async move {
        let result =
            ensure_node_ingress(&client, &key.namespace, &key.name, &own_ips, &desired_ips).await;
        if let Err(e) = &result {
            eprintln!(
                "controller: publishing status.loadBalancer.ingress for {}/{} failed (will retry): {e:#}",
                key.namespace, key.name
            );
        }
        pending
            .lock()
            .unwrap()
            .record(&key, result.is_ok(), clear, Instant::now());
    });
}

/// Publishes `key`'s ingress from the current state.
fn publish_ingress_for(
    client: &Arc<HyperApiClient>,
    pending: &Arc<Mutex<PublishRetry>>,
    state: &Mutex<WatchState>,
    node: &NodeContext,
    key: ServiceKey,
) {
    let (own_ips, desired_ips) = {
        let state = state.lock().unwrap();
        (
            state.own_node_ips(node.node_ip),
            state.ips_to_publish(&key, node.node_ip),
        )
    };
    publish_ingress(client, pending, key, own_ips, desired_ips, false);
}

/// Withdraws this node's own entries from `key`'s ingress: a Service that left
/// `type=LoadBalancer` is no longer fronted. Other nodes' entries are theirs to
/// withdraw (`status::merged_ingress` with no desired addresses).
fn clear_ingress_for(
    client: &Arc<HyperApiClient>,
    pending: &Arc<Mutex<PublishRetry>>,
    state: &Mutex<WatchState>,
    node: &NodeContext,
    key: ServiceKey,
) {
    let own_ips = state.lock().unwrap().own_node_ips(node.node_ip);
    publish_ingress(client, pending, key, own_ips, Vec::new(), true);
}

/// What to do with one Service's published ingress.
#[derive(Debug, PartialEq, Eq)]
enum IngressWork {
    /// Re-assert this node's entries for the families it fronts.
    Publish,
    /// Withdraw this node's entries: the Service left `type=LoadBalancer`.
    Clear,
    /// Nothing to publish or clear: stop retrying.
    Forget,
}

/// The work a Service watch event calls for. A delete forgets any pending
/// retry; a non-LB Service still carrying ingress is cleared.
fn service_event_work(
    changed: Option<ServiceKey>,
    event: &Value,
) -> Vec<(IngressWork, ServiceKey)> {
    changed
        .map(|key| (IngressWork::Publish, key))
        .into_iter()
        .chain(stale_ingress_key(event).map(|key| (IngressWork::Clear, key)))
        .chain(deleted_service_key(event).map(|key| (IngressWork::Forget, key)))
        .collect()
}

/// `service_event_work` over a complete Service LIST.
fn services_relist_work(keys: Vec<ServiceKey>, items: &[Value]) -> Vec<(IngressWork, ServiceKey)> {
    keys.into_iter()
        .map(|key| (IngressWork::Publish, key))
        .chain(
            stale_ingress_keys(items)
                .into_iter()
                .map(|key| (IngressWork::Clear, key)),
        )
        .collect()
}

/// What a retry of a failed publish (`clear == false`) or clear
/// (`clear == true`) should do now. A Service that is tracked again is
/// published whatever failed; an untracked one still has a stale ingress to
/// clear if a clear failed, and nothing to do if a publish failed.
fn retry_work(tracked: bool, clear: bool) -> IngressWork {
    match (tracked, clear) {
        (true, _) => IngressWork::Publish,
        (false, true) => IngressWork::Clear,
        (false, false) => IngressWork::Forget,
    }
}

fn run_ingress_work(
    client: &Arc<HyperApiClient>,
    pending: &Arc<Mutex<PublishRetry>>,
    state: &Mutex<WatchState>,
    node: &NodeContext,
    work: IngressWork,
    key: ServiceKey,
) {
    match work {
        IngressWork::Publish => publish_ingress_for(client, pending, state, node, key),
        IngressWork::Clear => clear_ingress_for(client, pending, state, node, key),
        IngressWork::Forget => pending
            .lock()
            .unwrap()
            .record(&key, true, false, Instant::now()),
    }
}

/// Services whose ingress publish or clear failed, retried with `RetryBackoff`
/// delays until it succeeds: without it a node that just lost its last
/// `externalTrafficPolicy: Local` pod, or a Service that left `LoadBalancer`,
/// stays advertised until the next event. The value is whether the failed
/// operation was a clear.
#[derive(Default)]
struct PublishRetry {
    keys: HashMap<ServiceKey, bool>,
    backoff: RetryBackoff,
}

impl PublishRetry {
    fn record(&mut self, key: &ServiceKey, ok: bool, clear: bool, now: Instant) {
        if ok {
            self.keys.remove(key);
            if self.keys.is_empty() {
                self.backoff = RetryBackoff::default();
            }
        } else {
            self.keys.insert(key.clone(), clear);
            self.backoff.record(false, now);
        }
    }

    /// The keys to retry now, each with whether it was a clear. Disarms the
    /// deadline so the next poll does not retry while these are in flight; a
    /// failure re-arms it.
    fn take_due(&mut self, now: Instant) -> Vec<(ServiceKey, bool)> {
        if !self.backoff.due(now) {
            return Vec::new();
        }
        self.backoff.retry_at = None;
        self.keys.iter().map(|(k, c)| (k.clone(), *c)).collect()
    }
}

/// Retries failed ingress publishes and clears when due. Never returns.
async fn run_publish_retry_loop(
    client: Arc<HyperApiClient>,
    pending: Arc<Mutex<PublishRetry>>,
    state: Arc<Mutex<WatchState>>,
    node: NodeContext,
) -> anyhow::Result<()> {
    loop {
        tokio::time::sleep(RETRY_POLL).await;
        let due = pending.lock().unwrap().take_due(Instant::now());
        if due.is_empty() {
            continue;
        }
        let tracked: HashSet<ServiceKey> =
            state.lock().unwrap().service_keys().into_iter().collect();
        for (key, clear) in due {
            let work = retry_work(tracked.contains(&key), clear);
            run_ingress_work(&client, &pending, &state, &node, work, key);
        }
    }
}

/// Re-publishes every tracked Service's ingress when this node's own address
/// set differs from `before` (e.g. its second family just resolved): a
/// Service added before that resolution never gets another chance to
/// publish the newly-resolved family. Services whose ingress depends on local
/// pods (`externalTrafficPolicy: Local`) are re-published on every Node event:
/// resolving this node's own Node entry changes what "local" means without
/// necessarily changing its address set.
fn republish_if_own_ips_changed(
    client: &Arc<HyperApiClient>,
    pending: &Arc<Mutex<PublishRetry>>,
    state: &Mutex<WatchState>,
    node: &NodeContext,
    before: &[IpAddr],
) {
    let after = state.lock().unwrap().own_node_ips(node.node_ip);
    // Bound to a `let` rather than locked inline in the `for` head: a
    // `for`-loop scrutinee's temporaries live for the whole loop, so an
    // inline lock would be held across every iteration and deadlock on the
    // lock inside `publish_ingress_for`.
    let keys = if own_node_ips_changed(before, &after) {
        state.lock().unwrap().service_keys()
    } else {
        state.lock().unwrap().local_policy_service_keys()
    };
    for key in keys {
        publish_ingress_for(client, pending, state, node, key);
    }
}

/// Runs the three list-watches (Service/EndpointSlice/Node) concurrently on
/// this task, forever -- there is no persistent proxy loop to hand control
/// back to (`ebpf-lb-dataplane.md`'s "Userspace control plane" section). In
/// practice this never returns; it's declared `Result` rather than `!` for
/// the same reason `run_list_watch` is (see that function's doc comment).
async fn run_controller_loop(
    client: Arc<HyperApiClient>,
    state: Arc<Mutex<WatchState>>,
    maps: Arc<Mutex<PinnedMaps>>,
    node: NodeContext,
) -> anyhow::Result<()> {
    let retry = Arc::new(Mutex::new(RetryBackoff::default()));
    let pending = Arc::new(Mutex::new(PublishRetry::default()));
    let on_service = {
        let state = Arc::clone(&state);
        let maps = Arc::clone(&maps);
        let retry = Arc::clone(&retry);
        let client = Arc::clone(&client);
        let pending = Arc::clone(&pending);
        move |event: Value| {
            let changed = state.lock().unwrap().apply_service_event(&event);
            apply_reconcile(&state, &maps, &retry, &node);
            for (work, key) in service_event_work(changed, &event) {
                run_ingress_work(&client, &pending, &state, &node, work, key);
            }
        }
    };
    let on_services_relist = {
        let state = Arc::clone(&state);
        let maps = Arc::clone(&maps);
        let retry = Arc::clone(&retry);
        let client = Arc::clone(&client);
        let pending = Arc::clone(&pending);
        move |items: Vec<Value>| {
            let keys = state.lock().unwrap().replace_services(&items)?;
            apply_reconcile(&state, &maps, &retry, &node);
            for (work, key) in services_relist_work(keys, &items) {
                run_ingress_work(&client, &pending, &state, &node, work, key);
            }
            Ok(())
        }
    };
    let on_endpoint_slice = {
        let state = Arc::clone(&state);
        let maps = Arc::clone(&maps);
        let retry = Arc::clone(&retry);
        let client = Arc::clone(&client);
        let pending = Arc::clone(&pending);
        move |event: Value| {
            let local_policy_key = state.lock().unwrap().apply_endpoint_slice_event(&event);
            apply_reconcile(&state, &maps, &retry, &node);
            if let Some(key) = local_policy_key {
                publish_ingress_for(&client, &pending, &state, &node, key);
            }
        }
    };
    let on_endpoint_slices_relist = {
        let state = Arc::clone(&state);
        let maps = Arc::clone(&maps);
        let retry = Arc::clone(&retry);
        let client = Arc::clone(&client);
        let pending = Arc::clone(&pending);
        move |items: Vec<Value>| {
            state.lock().unwrap().replace_endpoint_slices(&items)?;
            apply_reconcile(&state, &maps, &retry, &node);
            let keys = state.lock().unwrap().local_policy_service_keys();
            for key in keys {
                publish_ingress_for(&client, &pending, &state, &node, key);
            }
            Ok(())
        }
    };
    let on_node = {
        let state = Arc::clone(&state);
        let maps = Arc::clone(&maps);
        let retry = Arc::clone(&retry);
        let client = Arc::clone(&client);
        let pending = Arc::clone(&pending);
        move |event: Value| {
            let before = state.lock().unwrap().own_node_ips(node.node_ip);
            state.lock().unwrap().apply_node_event(&event);
            apply_reconcile(&state, &maps, &retry, &node);
            republish_if_own_ips_changed(&client, &pending, &state, &node, &before);
        }
    };
    // Every Node LIST replaces the node set and marks it known
    // (`nodes_listed`), then reconciles immediately so a genuinely node-less
    // cluster's correct (destructive) diff runs right away instead of
    // waiting on the next event (`WatchState::desired`'s doc comment).
    let on_nodes_relist = {
        let state = Arc::clone(&state);
        let maps = Arc::clone(&maps);
        let retry = Arc::clone(&retry);
        let client = Arc::clone(&client);
        let pending = Arc::clone(&pending);
        move |items: Vec<Value>| {
            let before = state.lock().unwrap().own_node_ips(node.node_ip);
            state.lock().unwrap().replace_nodes(&items, node.node_ip)?;
            apply_reconcile(&state, &maps, &retry, &node);
            republish_if_own_ips_changed(&client, &pending, &state, &node, &before);
            Ok(())
        }
    };

    // None of the branches actually complete in practice, so which
    // error (if any) wins here never matters at runtime -- `and` just gives
    // the whole function a single `Result` to return.
    let (services, endpoint_slices, nodes, retrier, publish_retrier) = tokio::join!(
        run_list_watch(&client, "/api/v1/services", on_service, on_services_relist),
        run_list_watch(
            &client,
            "/apis/discovery.k8s.io/v1/endpointslices",
            on_endpoint_slice,
            on_endpoint_slices_relist,
        ),
        run_list_watch(&client, "/api/v1/nodes", on_node, on_nodes_relist),
        run_retry_loop(Arc::clone(&state), maps, retry, node),
        run_publish_retry_loop(Arc::clone(&client), pending, state, node),
    );
    services
        .and(endpoint_slices)
        .and(nodes)
        .and(retrier)
        .and(publish_retrier)
}

// current_thread, not the default multi-thread runtime: this process's
// concurrency is 3 cooperatively-interleaved list-watches (`tokio::join!`
// in `run_controller_loop`), never CPU-parallel work -- a DaemonSet's own
// steady-state RSS/thread-count footprint stays lower without a thread pool
// it would never use.
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    // Held for `main`'s whole body; its `Drop` (on return, below) writes
    // dhat-heap.json. `run_controller_loop` never returns on its own, so a
    // dhat-heap build races it against Ctrl-C instead of awaiting it
    // directly -- that's the only way to reach this `Drop` at all.
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    let args = Args::parse();

    if args.node_prep {
        ensure_geneve_iface(&args.geneve_iface).context("ensuring geneve tunnel device exists")?;
        disable_rp_filter(&args.geneve_iface).context("disabling reverse-path filter")?;
        return Ok(());
    }

    // Pin dir must exist before `load_ebpf`: a fresh pin path's
    // `create_pinned_by_name` calls `bpf_obj_pin` on a miss, which fails if
    // its parent directory isn't there yet.
    std::fs::create_dir_all(&args.pin_dir)
        .with_context(|| format!("creating pin dir {}", args.pin_dir.display()))?;

    let (front_meta_max_entries, front_endpoints_max_entries) =
        front_map_max_entries(args.max_fronts, args.endpoints_per_front)?;
    let kubeconfig = args
        .kubeconfig
        .as_deref()
        .expect("clap requires --kubeconfig unless --node-prep, which already returned above");
    let creds = parse_kubeconfig(kubeconfig).context("parsing kubeconfig")?;
    let connector =
        build_tls_connector(&creds).context("building TLS connector from kubeconfig")?;
    let client = Arc::new(HyperApiClient {
        server: creds.server,
        connector,
        bearer: None,
    });

    let mut ebpf =
        match load_ebpf(
            &args.pin_dir,
            args.fwd_pending_max_entries,
            args.flow_table_max_entries,
            front_meta_max_entries,
            front_endpoints_max_entries,
            args.node_allow_max_entries,
            args.pod_targets_max_entries,
        ) {
            Ok(ebpf) => ebpf,
            Err(e) => {
                let node_name = args.node_name.as_deref().expect(
                    "clap requires --node-name unless --node-prep, which already returned above",
                );
                let pod = args.pod_name.clone().zip(args.pod_namespace.clone()).map(
                    |(name, namespace)| PodRef {
                        name,
                        namespace,
                        uid: args.pod_uid.clone(),
                    },
                );
                report_restore_failure(&client, node_name, pod.as_ref(), &e).await;
                return Err(e.context("loading beep-ebpf"));
            }
        };

    // The privileged initContainer's `--node-prep` run already created
    // `geneve0` and disabled its RPF exception before this container
    // started (`docs/decisions/servicelb-rp-filter-init-container.md`).
    // Re-running the idempotent iface check here is a no-op in that case,
    // and a clear error instead of a silent skip if it somehow didn't run.
    ensure_geneve_iface(&args.geneve_iface).context("ensuring geneve tunnel device exists")?;

    // Before attach: a classifier must never run with a seed other nodes
    // don't share. Failing here (apiserver down, RBAC missing) restarts the
    // pod rather than serving with a private seed.
    let flow_hash_seed = load_or_create_seed(&client, &args.seed_namespace)
        .await
        .context("loading cluster flow-hash seed")?;
    populate_config(&mut ebpf, &args.geneve_iface, flow_hash_seed)
        .context("populating CONFIG map")?;
    populate_uplink_config(&mut ebpf, &args.uplink_ifaces)
        .context("populating UPLINK_CONFIG map")?;

    let uplink_iface_refs: Vec<&str> = args.uplink_ifaces.iter().map(String::as_str).collect();
    let geneve_iface_refs = [args.geneve_iface.as_str()];
    let hooks: [(&str, &[&str], TcAttachType); 3] = [
        (
            "uplink_ingress",
            uplink_iface_refs.as_slice(),
            TcAttachType::Ingress,
        ),
        (
            "geneve_ingress",
            geneve_iface_refs.as_slice(),
            TcAttachType::Ingress,
        ),
        (
            "uplink_egress_return",
            uplink_iface_refs.as_slice(),
            TcAttachType::Egress,
        ),
    ];
    for (name, ifaces, attach_type) in hooks {
        attach_and_pin(&mut ebpf, name, ifaces, attach_type, &args.pin_dir)
            .with_context(|| format!("attaching {name} on {ifaces:?}"))?;
        eprintln!(
            "attached {name} on {ifaces:?} ({attach_type:?}), pinned under {}",
            args.pin_dir.display()
        );
    }

    // Same rationale as the standalone loader (`src/main.rs`): every hook's
    // link and every map are pinned, so this process doesn't need the
    // parsed `Ebpf` handle to keep the dataplane live -- dropping it here
    // keeps this DaemonSet's steady-state RSS below its load-time peak.
    drop(ebpf);
    // malloc_trim is a glibc extension; musl's allocator has no equivalent,
    // so the RSS-return optimization is simply skipped on musl builds.
    //
    // SAFETY: malloc_trim takes no pointers and only releases free heap pages.
    #[cfg(target_env = "gnu")]
    unsafe {
        libc::malloc_trim(0);
    }

    let node = NodeContext {
        node_ip: args
            .node_ip
            .expect("clap requires --node-ip unless --node-prep, which already returned above"),
        pod_cidr: args
            .pod_cidr
            .expect("clap requires --pod-cidr unless --node-prep, which already returned above"),
    };
    let state = Arc::new(Mutex::new(WatchState::default()));
    let maps = Arc::new(Mutex::new(
        PinnedMaps::open(&args.pin_dir).context("opening pinned dataplane maps")?,
    ));

    eprintln!("all 3 hooks attached; watching Service/EndpointSlice/Node");

    let node_name = args
        .node_name
        .clone()
        .expect("clap requires --node-name unless --node-prep, which already returned above");
    let controller = async {
        let (watches, seed, lease, prune) = tokio::join!(
            run_controller_loop(Arc::clone(&client), Arc::clone(&state), maps, node),
            run_seed_loop(
                Arc::clone(&client),
                args.seed_namespace.clone(),
                args.pin_dir.clone(),
                flow_hash_seed,
            ),
            run_lease_loop(
                Arc::clone(&client),
                Arc::clone(&state),
                args.lease_namespace.clone(),
                node_name.clone(),
                node.node_ip,
            ),
            run_prune_loop(
                Arc::clone(&client),
                state,
                args.lease_namespace.clone(),
                node_name.clone(),
            ),
        );
        watches.and(seed).and(lease).and(prune)
    };

    #[cfg(feature = "dhat-heap")]
    {
        tokio::select! {
            result = controller => result,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("controller: dhat-heap: SIGINT received, flushing dhat-heap.json");
                Ok(())
            }
        }
    }
    #[cfg(not(feature = "dhat-heap"))]
    controller.await
}

#[cfg(test)]
mod tests {
    use super::*;

    // The privileged initContainer invokes this binary as `beep-controller
    // --node-prep` alone -- no --pod-cidr/--node-ip/--kubeconfig, none of
    // which node-prep needs or has available at that point in the pod's
    // startup. If `required_unless_present` ever regresses back to plain
    // `required`, the initContainer's exec fails clap's arg validation and
    // the DaemonSet crash-loops again, just on a different error than the
    // original EROFS.
    #[test]
    fn node_prep_flag_alone_is_a_valid_invocation() {
        Args::try_parse_from(["beep-controller", "--node-prep"])
            .expect("--node-prep must not require --pod-cidr/--node-ip/--kubeconfig");
    }

    // The other side of the same guarantee: outside --node-prep mode, the
    // three watch/reconcile args are still mandatory. If `required_unless_present`
    // were ever loosened into unconditional non-required, this would start
    // the real controller with a garbage default pod_cidr/node_ip instead of
    // failing fast at argument parsing.
    #[test]
    fn watch_mode_still_requires_pod_cidr_node_ip_and_kubeconfig() {
        Args::try_parse_from(["beep-controller"]).expect_err(
            "pod-cidr/node-ip/kubeconfig must stay required when --node-prep is absent",
        );
    }

    // uplink_ifaces carries the same required_unless_present = "node_prep" as
    // pod_cidr/node_ip/kubeconfig above, but no test exercised it directly:
    // the two cases above both omit every required arg at once, so a
    // regression that dropped required_unless_present from uplink_ifaces
    // alone (making it either unconditionally required, breaking node-prep,
    // or unconditionally optional, letting the real controller start with no
    // uplinks and admit no client traffic) would pass both tests above.
    #[test]
    fn uplink_iface_required_unless_node_prep() {
        Args::try_parse_from([
            "beep-controller",
            "--pod-cidr",
            "10.244.0.0/16",
            "--node-ip",
            "10.0.0.1",
            "--kubeconfig",
            "/tmp/kubeconfig",
            "--node-name",
            "node-a",
        ])
        .expect_err("--uplink-iface must stay required when --node-prep is absent");

        Args::try_parse_from(["beep-controller", "--node-prep"])
            .expect("--node-prep must not require --uplink-iface either");
    }

    const REQUIRED: [&str; 11] = [
        "beep-controller",
        "--uplink-iface",
        "eth0",
        "--pod-cidr",
        "10.244.0.0/16",
        "--node-ip",
        "10.0.0.1",
        "--kubeconfig",
        "/tmp/kubeconfig",
        "--node-name",
        "node-a",
    ];

    // The 17th dual-stack node (or 65th dual-stack pod) is silently
    // unreachable if the caps regress below the sized defaults.
    #[test]
    fn node_allow_and_pod_targets_caps_default_to_the_sized_values() {
        let args = Args::try_parse_from(REQUIRED).unwrap();
        assert_eq!(args.node_allow_max_entries, 32);
        assert_eq!(args.pod_targets_max_entries, 128);
    }

    #[test]
    fn front_sizing_flags_default_to_the_decided_caps_and_have_env_aliases() {
        // 1024 fronts x 4 endpoints is the operator-decided small-cluster
        // cap; a silently different default changes every node's footprint.
        // The env names are the contract a ConfigMap relies on.
        use clap::CommandFactory;
        let args = Args::try_parse_from(REQUIRED).unwrap();
        assert_eq!((args.max_fronts, args.endpoints_per_front), (1024, 4));
        assert_eq!(
            front_map_max_entries(args.max_fronts, args.endpoints_per_front).unwrap(),
            (1024, 8192)
        );
        let cmd = Args::command();
        for (flag, env) in [
            ("max_fronts", "BEEP_MAX_FRONTS"),
            ("endpoints_per_front", "BEEP_ENDPOINTS_PER_FRONT"),
        ] {
            let arg = cmd.get_arguments().find(|a| a.get_id() == flag).unwrap();
            assert_eq!(arg.get_env().and_then(|e| e.to_str()), Some(env));
        }
        assert!(
            Args::try_parse_from(
                REQUIRED
                    .into_iter()
                    .chain(["--front-meta-max-entries", "16"])
            )
            .is_err(),
            "the raw front max-entries flags were replaced"
        );
    }

    // An operator with a bigger cluster must be able to raise the caps at
    // deploy time; a flag that parses but is not forwarded would not help,
    // so the field is checked end to end through `Args`.
    #[test]
    fn node_allow_and_pod_targets_caps_are_flag_overridable() {
        let args = Args::try_parse_from(REQUIRED.into_iter().chain([
            "--node-allow-max-entries",
            "64",
            "--pod-targets-max-entries",
            "512",
        ]))
        .unwrap();
        assert_eq!(args.node_allow_max_entries, 64);
        assert_eq!(args.pod_targets_max_entries, 512);
    }

    // The loader's own CLI (`src/main.rs`) already accepts a v6 --node-ip;
    // the controller's own `--node-ip` rejected one outright at argument
    // parsing until this change, so a v6-only node's DaemonSet could never
    // even start, regardless of anything watch.rs does.
    #[test]
    fn node_ip_accepts_a_v6_literal() {
        let args = Args::try_parse_from([
            "beep-controller",
            "--uplink-iface",
            "eth0",
            "--pod-cidr",
            "10.244.0.0/16",
            "--node-ip",
            "2001:db8::1",
            "--kubeconfig",
            "/tmp/kubeconfig",
            "--node-name",
            "node-a",
        ])
        .expect(
            "--node-ip must accept a v6 literal, or a v6-only node can never start this \
             DaemonSet",
        );
        assert_eq!(
            args.node_ip,
            Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)))
        );
    }

    // Mirrors the loader's own dual-stack `--pod-cidr`: the network
    // address's family alone picks `IpCidr::V4`/`V6`, so a v6 cluster pod
    // network doesn't need a separate flag to configure.
    #[test]
    fn pod_cidr_accepts_a_v6_literal() {
        let args = Args::try_parse_from([
            "beep-controller",
            "--uplink-iface",
            "eth0",
            "--pod-cidr",
            "fd00:10:244::/56",
            "--node-ip",
            "2001:db8::1",
            "--kubeconfig",
            "/tmp/kubeconfig",
            "--node-name",
            "node-a",
        ])
        .expect(
            "--pod-cidr must accept a v6 literal, or a v6-only cluster's pod CIDR can never be \
             configured",
        );
        assert_eq!(
            args.pod_cidr,
            Some(IpCidr::V6(Ipv6Cidr::new(
                Ipv6Addr::new(0xfd00, 0x10, 0x244, 0, 0, 0, 0, 0),
                56
            )))
        );
    }

    // A failed eviction sweep keeps departed pods' POD_TARGETS rows, but only
    // a later reconcile re-sweeps them. On a quiet cluster no watch event
    // arrives, so the retry must be due purely from elapsed time.
    #[test]
    fn failed_apply_is_retried_within_backoff_window_without_a_new_event() {
        let t0 = Instant::now();
        let mut b = RetryBackoff::default();
        assert!(!b.due(t0 + Duration::from_secs(3600)), "nothing to retry");
        b.record(false, t0);
        assert!(!b.due(t0), "retry must wait out the backoff");
        assert!(
            b.due(t0 + RETRY_INITIAL),
            "a failed apply must be retried after the initial delay with no watch event, or \
             flows stay pinned to departed pods on a quiet cluster"
        );
    }

    #[test]
    fn backoff_doubles_then_caps_so_a_persistent_failure_does_not_hammer_the_maps() {
        let t0 = Instant::now();
        let mut b = RetryBackoff::default();
        let mut now = t0;
        let mut secs = Vec::new();
        for _ in 0..8 {
            b.record(false, now);
            let at = b.retry_at.unwrap();
            secs.push((at - now).as_secs());
            now = at;
        }
        assert_eq!(secs, [1, 2, 4, 8, 16, 30, 30, 30]);
        for _ in 0..200 {
            b.record(false, now);
            let at = b.retry_at.unwrap();
            assert_eq!(at - now, RETRY_MAX, "no overflow past the cap");
            now = at;
        }
    }

    #[test]
    fn event_storm_during_failure_neither_postpones_retry_nor_inflates_backoff() {
        let t0 = Instant::now();
        let mut b = RetryBackoff::default();
        b.record(false, t0);
        let armed = b.retry_at.unwrap();
        for ms in 1..900 {
            b.record(false, t0 + Duration::from_millis(ms));
        }
        assert_eq!(
            b.retry_at,
            Some(armed),
            "watch-driven failures must not push the pending retry out"
        );
        assert_eq!(b.failures, 1, "only failed retry attempts grow the backoff");
        b.record(false, armed);
        assert_eq!(
            b.retry_at.unwrap() - armed,
            2 * RETRY_INITIAL,
            "a failed retry attempt must double the delay"
        );
    }

    fn failing() -> anyhow::Result<()> {
        Err(anyhow::anyhow!("map full"))
    }

    #[test]
    fn failed_reconcile_arms_a_retry_and_success_disarms_it() {
        let t0 = Instant::now();
        let retry = Mutex::new(RetryBackoff::default());
        reconcile_once(failing, &retry, t0);
        assert!(
            retry.lock().unwrap().due(t0 + RETRY_INITIAL),
            "a failed apply must arm a retry or departed pods stay pinned"
        );
        reconcile_once(|| Ok(()), &retry, t0 + RETRY_INITIAL);
        assert!(
            !retry.lock().unwrap().due(t0 + RETRY_MAX),
            "a successful apply must stop the retries"
        );
    }

    #[test]
    fn retry_tick_reruns_reconcile_only_when_due() {
        let t0 = Instant::now();
        let retry = Mutex::new(RetryBackoff::default());
        let mut runs = 0;
        assert!(!retry_tick(&retry, t0, || runs += 1), "nothing armed");
        reconcile_once(failing, &retry, t0);
        assert!(!retry_tick(&retry, t0, || runs += 1), "backoff not elapsed");
        assert_eq!(runs, 0);
        assert!(
            retry_tick(&retry, t0 + RETRY_INITIAL, || {
                runs += 1;
                reconcile_once(|| Ok(()), &retry, t0 + RETRY_INITIAL);
            }),
            "a due retry must re-run reconcile with no watch event"
        );
        assert_eq!(runs, 1);
        assert!(
            !retry_tick(&retry, t0 + RETRY_MAX, || runs += 1),
            "a successful retry must not run again"
        );
        assert_eq!(runs, 1);
    }

    fn svc(name: &str) -> ServiceKey {
        ServiceKey {
            namespace: "ns".into(),
            name: name.into(),
        }
    }

    #[test]
    fn failed_ingress_publish_is_retried_until_it_succeeds_without_a_new_event() {
        // A node that just lost its last eTP=Local pod stays listed until a
        // publish lands; a quiet cluster sends no event to trigger another.
        let t0 = Instant::now();
        let mut p = PublishRetry::default();
        p.record(&svc("a"), false, false, t0);
        assert!(p.take_due(t0).is_empty(), "backoff not elapsed");
        assert_eq!(p.take_due(t0 + RETRY_INITIAL), vec![(svc("a"), false)]);
        assert!(
            p.take_due(t0 + RETRY_INITIAL).is_empty(),
            "in-flight retry must not be re-issued on the next poll"
        );
        p.record(&svc("a"), false, false, t0 + RETRY_INITIAL);
        assert!(
            p.take_due(t0 + RETRY_INITIAL + RETRY_INITIAL).is_empty(),
            "a failed retry backs off further"
        );
        let t2 = t0 + RETRY_INITIAL + RETRY_INITIAL * 2;
        assert_eq!(p.take_due(t2), vec![(svc("a"), false)]);
        p.record(&svc("a"), true, false, t2);
        assert!(
            p.take_due(t2 + RETRY_MAX).is_empty(),
            "a successful publish must stop the retries"
        );
    }

    fn svc_event(kind: &str, service_type: &str, ingress: &[&str]) -> Value {
        let ingress: Vec<Value> = ingress
            .iter()
            .map(|ip| serde_json::json!({"ip": ip}))
            .collect();
        serde_json::json!({
            "type": kind,
            "object": {
                "metadata": {"namespace": "ns", "name": "a"},
                "spec": {"type": service_type, "ports": [{"port": 80}]},
                "status": {"loadBalancer": {"ingress": ingress}},
            },
        })
    }

    #[test]
    fn retyped_service_event_clears_its_ingress_so_no_dead_address_is_advertised() {
        let event = svc_event("MODIFIED", "ClusterIP", &["10.0.0.5"]);
        assert_eq!(
            service_event_work(None, &event),
            vec![(IngressWork::Clear, svc("a"))]
        );
    }

    #[test]
    fn changed_load_balancer_event_publishes_and_never_clears() {
        let event = svc_event("MODIFIED", "LoadBalancer", &["10.0.0.5"]);
        assert_eq!(
            service_event_work(Some(svc("a")), &event),
            vec![(IngressWork::Publish, svc("a"))],
            "a live LoadBalancer's ingress must not be withdrawn"
        );
    }

    #[test]
    fn deleted_service_event_forgets_pending_retries_so_they_do_not_loop_forever() {
        let event = svc_event("DELETED", "ClusterIP", &["10.0.0.5"]);
        assert_eq!(
            service_event_work(None, &event),
            vec![(IngressWork::Forget, svc("a"))]
        );
    }

    #[test]
    fn relist_clears_services_retyped_while_the_controller_was_down() {
        let items = [
            svc_event("ADDED", "ClusterIP", &["10.0.0.5"])["object"].clone(),
            svc_event("ADDED", "ClusterIP", &[])["object"].clone(),
        ];
        assert_eq!(
            services_relist_work(vec![svc("lb")], &items),
            vec![
                (IngressWork::Publish, svc("lb")),
                (IngressWork::Clear, svc("a"))
            ]
        );
    }

    #[test]
    fn failed_clear_is_retried_for_an_untracked_service_until_it_succeeds() {
        // A retyped Service is untracked and sees few events; dropping the
        // failed clear would leave a dead ingress advertised indefinitely.
        let t0 = Instant::now();
        let mut p = PublishRetry::default();
        p.record(&svc("a"), false, true, t0);
        let due = p.take_due(t0 + RETRY_INITIAL);
        assert_eq!(due, vec![(svc("a"), true)]);
        assert_eq!(retry_work(false, due[0].1), IngressWork::Clear);
        assert_eq!(retry_work(false, false), IngressWork::Forget);
        assert_eq!(retry_work(true, true), IngressWork::Publish);
    }

    #[test]
    fn one_services_success_does_not_cancel_anothers_pending_retry() {
        let t0 = Instant::now();
        let mut p = PublishRetry::default();
        p.record(&svc("a"), false, false, t0);
        p.record(&svc("b"), false, false, t0);
        p.record(&svc("a"), true, false, t0);
        assert_eq!(p.take_due(t0 + RETRY_INITIAL), vec![(svc("b"), false)]);
    }

    #[test]
    fn expired_grace_triggers_a_reconcile_on_a_quiet_cluster() {
        // No watch event arrives on a quiet cluster, so without this follow-up
        // the previous generation's rows would sit in the front map forever.
        let mut reconciles = 0;
        follow_up_tick(false, || true, || reconciles += 1);
        assert_eq!(reconciles, 1);
    }

    #[test]
    fn unexpired_grace_does_not_reconcile() {
        let mut reconciles = 0;
        follow_up_tick(false, || false, || reconciles += 1);
        assert_eq!(
            reconciles, 0,
            "reconciling every tick would hammer the maps"
        );
    }

    #[test]
    fn a_retry_that_ran_already_swept_the_expired_grace() {
        // A second back-to-back reconcile would double the write load on the
        // very tick a failing apply is being retried, and the grace is not
        // even consulted.
        let mut reconciles = 0;
        let mut asked = false;
        follow_up_tick(
            true,
            || {
                asked = true;
                true
            },
            || reconciles += 1,
        );
        assert_eq!(reconciles, 0);
        assert!(!asked);
    }

    #[test]
    fn success_clears_pending_retry_and_resets_backoff() {
        let t0 = Instant::now();
        let mut b = RetryBackoff::default();
        b.record(false, t0);
        b.record(false, t0 + RETRY_INITIAL);
        b.record(true, t0 + RETRY_INITIAL);
        assert!(
            !b.due(t0 + RETRY_MAX),
            "a healthy apply must not keep retrying"
        );
        b.record(false, t0);
        assert_eq!(
            b.retry_at.unwrap() - t0,
            RETRY_INITIAL,
            "a new failure after recovery must start from the initial delay"
        );
    }

    // `on_node`'s startup race: a Service can be ADDED before this node's
    // own multi-family Node object resolves its second family, so that
    // family never reaches status.loadBalancer.ingress unless the LATER
    // Node event that resolves it re-publishes. Reverting to "never
    // republish from on_node" would fail this by never detecting the
    // change at all.
    #[test]
    fn own_node_ips_changed_detects_a_newly_resolved_second_family() {
        let v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5));
        assert!(
            own_node_ips_changed(&[v4], &[v4, v6]),
            "a Node event that resolves this node's second family must be detected as a \
             change, or a Service added before that resolution would never gain the second \
             family in its status.loadBalancer.ingress"
        );
    }

    // The other side: a Node event that redelivers the same address set
    // (e.g. an unrelated label update, or a duplicate watch delivery) must
    // not be treated as a change, or `on_node` would republish
    // status.loadBalancer.ingress for every tracked Service on every such
    // no-op event.
    #[test]
    fn own_node_ips_changed_ignores_a_no_op_node_event() {
        let v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        assert!(
            !own_node_ips_changed(&[v4], &[v4]),
            "a Node event that doesn't change this node's own address set must not be treated \
             as one, or every unrelated Node update would trigger a redundant status write for \
             every tracked Service"
        );
    }
}
