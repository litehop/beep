//! beep-controller: the per-node ServiceLB DaemonSet binary
//! (`docs/design/ebpf-lb-dataplane.md`'s "Userspace control plane" section).
//! Loads, attaches, and pins the three tc-bpf classifiers via the `beep`
//! lib (the same load/attach/pin invariants the standalone loader uses),
//! sets `CONFIG`, then watches `Service`(type=LoadBalancer)/`EndpointSlice`/
//! `Node` and programs `LB_FRONT_MAP`/`TARGET_PORTS`/`POD_TARGETS` on every
//! change. No persistent proxy loop -- the kernel forwards packets; this
//! process idles between watch events.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::Context;
use aya::programs::TcAttachType;
use beep::{
    attach_and_pin, bump_memlock_rlimit, disable_rp_filter, ensure_geneve_iface, load_ebpf,
    populate_config, populate_uplink_config,
};
use beep_controller::{
    apply::PinnedMaps,
    reconcile::{DesiredEntries, IpCidr, Ipv4Cidr, Ipv6Cidr, NodeContext},
    status::ensure_node_ingress,
    watch::{run_list_watch, ServiceKey, WatchState},
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

const DEFAULT_FWD_PENDING_MAX_ENTRIES: u32 = 2048;
const DEFAULT_FLOW_TABLE_MAX_ENTRIES: u32 = 16384;
/// See `src/main.rs`'s identical constants: `LB_FRONT_MAP`/`TARGET_PORTS` scale
/// with nodes x Service ports under the every-node-is-a-front model, not a
/// fixed Service count.
const DEFAULT_LB_FRONT_MAP_MAX_ENTRIES: u32 = 4096;
const DEFAULT_TARGET_PORTS_MAX_ENTRIES: u32 = 4096;

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
    #[arg(long = "uplink-iface", required_unless_present = "node_prep")]
    uplink_ifaces: Vec<String>,

    /// Geneve tunnel interface (hook: geneve ingress, both directions).
    #[arg(long, default_value = "geneve0")]
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

    /// `FWD_PENDING` max_entries (see `beep-ebpf`'s doc comment); a
    /// load-time DaemonSet config knob, not baked into the eBPF object.
    #[arg(long, default_value_t = DEFAULT_FWD_PENDING_MAX_ENTRIES)]
    fwd_pending_max_entries: u32,

    /// `FLOW_TABLE` max_entries (see `beep-ebpf`'s doc comment).
    #[arg(long, default_value_t = DEFAULT_FLOW_TABLE_MAX_ENTRIES)]
    flow_table_max_entries: u32,

    /// `LB_FRONT_MAP` max_entries (see `beep-ebpf`'s doc comment).
    #[arg(long, default_value_t = DEFAULT_LB_FRONT_MAP_MAX_ENTRIES)]
    lb_front_map_max_entries: u32,

    /// `TARGET_PORTS` max_entries (see `beep-ebpf`'s doc comment).
    #[arg(long, default_value_t = DEFAULT_TARGET_PORTS_MAX_ENTRIES)]
    target_ports_max_entries: u32,
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

fn apply_reconcile(state: &Mutex<WatchState>, maps: &Mutex<PinnedMaps>, node: &NodeContext) {
    let desired = state.lock().unwrap().desired(node);
    warn_on_rejected_endpoints(&desired, node);
    if let Err(e) = maps.lock().unwrap().apply(&desired) {
        eprintln!("controller: applying reconciled maps failed: {e:#}");
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
    key: ServiceKey,
    own_ips: Vec<IpAddr>,
    desired_ips: Vec<IpAddr>,
) {
    let client = Arc::clone(client);
    tokio::spawn(async move {
        if let Err(e) =
            ensure_node_ingress(&client, &key.namespace, &key.name, &own_ips, &desired_ips).await
        {
            eprintln!(
                "controller: publishing status.loadBalancer.ingress for {}/{} failed: {e:#}",
                key.namespace, key.name
            );
        }
    });
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
    let on_service = {
        let state = Arc::clone(&state);
        let maps = Arc::clone(&maps);
        let client = Arc::clone(&client);
        move |event: Value| {
            let changed = state.lock().unwrap().apply_service_event(&event);
            apply_reconcile(&state, &maps, &node);
            if let Some(key) = changed {
                let (own_ips, desired_ips) = {
                    let state = state.lock().unwrap();
                    (
                        state.own_node_ips(node.node_ip),
                        state.ips_to_publish(&key, node.node_ip),
                    )
                };
                publish_ingress(&client, key, own_ips, desired_ips);
            }
        }
    };
    let on_endpoint_slice = {
        let state = Arc::clone(&state);
        let maps = Arc::clone(&maps);
        move |event: Value| {
            state.lock().unwrap().apply_endpoint_slice_event(&event);
            apply_reconcile(&state, &maps, &node);
        }
    };
    let on_node = {
        let state = Arc::clone(&state);
        let maps = Arc::clone(&maps);
        move |event: Value| {
            state.lock().unwrap().apply_node_event(&event);
            apply_reconcile(&state, &maps, &node);
        }
    };
    // Fires once the initial Node LIST has fully delivered -- flips
    // `nodes_listed` so `desired` stops suppressing front programming, then
    // immediately reconciles so a genuinely node-less cluster's correct
    // (destructive) diff runs right away instead of waiting on the next
    // event (`WatchState::desired`'s doc comment).
    let on_nodes_listed = move || {
        state.lock().unwrap().mark_nodes_listed();
        apply_reconcile(&state, &maps, &node);
    };

    // None of the three branches actually complete in practice, so which
    // error (if any) wins here never matters at runtime -- `and` just gives
    // the whole function a single `Result` to return.
    let (services, endpoint_slices, nodes) = tokio::join!(
        run_list_watch(&client, "/api/v1/services", on_service, || {}),
        run_list_watch(
            &client,
            "/apis/discovery.k8s.io/v1/endpointslices",
            on_endpoint_slice,
            || {},
        ),
        run_list_watch(&client, "/api/v1/nodes", on_node, on_nodes_listed),
    );
    services.and(endpoint_slices).and(nodes)
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

    bump_memlock_rlimit();
    // Pin dir must exist before `load_ebpf`: a fresh pin path's
    // `create_pinned_by_name` calls `bpf_obj_pin` on a miss, which fails if
    // its parent directory isn't there yet.
    std::fs::create_dir_all(&args.pin_dir)
        .with_context(|| format!("creating pin dir {}", args.pin_dir.display()))?;

    let mut ebpf = load_ebpf(
        &args.pin_dir,
        args.fwd_pending_max_entries,
        args.flow_table_max_entries,
        args.lb_front_map_max_entries,
        args.target_ports_max_entries,
    )
    .context("loading beep-ebpf")?;

    // The privileged initContainer's `--node-prep` run already created
    // `geneve0` and disabled its RPF exception before this container
    // started (`docs/decisions/servicelb-rp-filter-init-container.md`).
    // Re-running the idempotent iface check here is a no-op in that case,
    // and a clear error instead of a silent skip if it somehow didn't run.
    ensure_geneve_iface(&args.geneve_iface).context("ensuring geneve tunnel device exists")?;

    populate_config(&mut ebpf, &args.geneve_iface).context("populating CONFIG map")?;
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
    #[cfg(target_env = "gnu")]
    unsafe {
        libc::malloc_trim(0);
    }

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

    #[cfg(feature = "dhat-heap")]
    {
        tokio::select! {
            result = run_controller_loop(client, state, maps, node) => result,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("controller: dhat-heap: SIGINT received, flushing dhat-heap.json");
                Ok(())
            }
        }
    }
    #[cfg(not(feature = "dhat-heap"))]
    run_controller_loop(client, state, maps, node).await
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
        ])
        .expect_err("--uplink-iface must stay required when --node-prep is absent");

        Args::try_parse_from(["beep-controller", "--node-prep"])
            .expect("--node-prep must not require --uplink-iface either");
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
}
