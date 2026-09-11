//! beep-controller: the per-node ServiceLB DaemonSet binary
//! (`docs/design/ebpf-lb-dataplane.md`'s "Userspace control plane" section).
//! Loads, attaches, and pins the three tc-bpf classifiers via the `beep`
//! lib (the same load/attach/pin invariants the standalone loader uses),
//! sets `CONFIG`, then watches `Service`(type=LoadBalancer)/`EndpointSlice`/
//! `Node` and programs `VIP_MAP`/`TARGET_PORTS`/`POD_TARGETS` on every
//! change. No persistent proxy loop -- the kernel forwards packets; this
//! process idles between watch events.

use std::{
    net::Ipv4Addr,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::Context;
use aya::programs::TcAttachType;
use beep::{attach_and_pin, bump_memlock_rlimit, load_ebpf, populate_config};
use beep_controller::{
    apply::PinnedMaps,
    reconcile::{Ipv4Cidr, NodeContext},
    status::ensure_node_ingress,
    watch::{run_list_watch, ServiceKey, WatchState},
};
use beep_kubeconfig::{build_tls_connector, parse_kubeconfig, HyperApiClient};
use clap::Parser;
use serde_json::Value;

const DEFAULT_FWD_PENDING_MAX_ENTRIES: u32 = 2048;
const DEFAULT_FLOW_TABLE_MAX_ENTRIES: u32 = 16384;
/// See `src/main.rs`'s identical constants: `VIP_MAP`/`TARGET_PORTS` scale
/// with nodes x Service ports under the every-node-is-a-front model, not a
/// fixed Service count.
const DEFAULT_VIP_MAP_MAX_ENTRIES: u32 = 4096;
const DEFAULT_TARGET_PORTS_MAX_ENTRIES: u32 = 4096;

#[derive(Parser, Debug)]
#[command(
    name = "beep-controller",
    about = "beep ServiceLB DaemonSet: watch Kubernetes, program the dataplane"
)]
struct Args {
    /// The CLIENT-FACING uplink interface (e.g. eth0) -- NOT the Geneve
    /// tunnel device. `uplink_egress_return` only fires on the device it's
    /// attached to,
    /// and a backend node routes the client reply out its client-facing
    /// NIC, not the tunnel -- attaching this to the tunnel device would leak
    /// a raw backend-sourced reply out the real uplink unencapsulated.
    #[arg(long, default_value = "eth0")]
    uplink_iface: String,

    /// Geneve tunnel interface (hook: geneve ingress, both directions).
    #[arg(long, default_value = "geneve0")]
    geneve_iface: String,

    /// Directory on a bpffs mount where programs/links/maps are pinned.
    #[arg(long, default_value = "/sys/fs/bpf/beep")]
    pin_dir: PathBuf,

    /// Cluster pod CIDR (e.g. `10.244.0.0/16`) -- scopes `POD_TARGETS`
    /// membership to endpoints whose pod_ip actually falls inside it
    /// (`reconcile::NodeContext`'s doc comment).
    #[arg(long = "pod-cidr", value_parser = parse_ipv4_cidr)]
    pod_cidr: Ipv4Cidr,

    /// This node's own address: the LB front IP every `type=LoadBalancer`
    /// Service resolves to on this node (the node-owned-address model,
    /// `ebpf-lb-dataplane.md`), and the value `POD_TARGETS` scopes local
    /// backend membership against.
    #[arg(long = "node-ip")]
    node_ip: Ipv4Addr,

    /// Path to a kubeconfig with credentials for this DaemonSet's watch.
    #[arg(long)]
    kubeconfig: String,

    /// `FWD_PENDING` max_entries (see `beep-ebpf`'s doc comment); a
    /// load-time DaemonSet config knob, not baked into the eBPF object.
    #[arg(long, default_value_t = DEFAULT_FWD_PENDING_MAX_ENTRIES)]
    fwd_pending_max_entries: u32,

    /// `FLOW_TABLE` max_entries (see `beep-ebpf`'s doc comment).
    #[arg(long, default_value_t = DEFAULT_FLOW_TABLE_MAX_ENTRIES)]
    flow_table_max_entries: u32,

    /// `VIP_MAP` max_entries (see `beep-ebpf`'s doc comment).
    #[arg(long, default_value_t = DEFAULT_VIP_MAP_MAX_ENTRIES)]
    vip_map_max_entries: u32,

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

fn apply_reconcile(state: &Mutex<WatchState>, maps: &Mutex<PinnedMaps>, node: &NodeContext) {
    let desired = state.lock().unwrap().desired(node);
    if let Err(e) = maps.lock().unwrap().apply(&desired) {
        eprintln!("controller: applying reconciled maps failed: {e:#}");
    }
}

/// Re-asserts this node's own address in `status.loadBalancer.ingress` for
/// the ONE Service `key` that just changed -- not every tracked Service --
/// since a Service watch event only ever means that Service's own status
/// could be stale. `tokio::spawn`s rather than awaiting inline in the
/// (synchronous) watch-event callback: `run_list_watch`'s `on_event` is a
/// plain `FnMut`, not an async fn, so a network round trip here can't be
/// awaited inline without blocking the single `current_thread` runtime this
/// process's other two list-watches also depend on.
fn publish_ingress(client: &Arc<HyperApiClient>, key: ServiceKey, node_ip: Ipv4Addr) {
    let client = Arc::clone(client);
    tokio::spawn(async move {
        if let Err(e) = ensure_node_ingress(&client, &key.namespace, &key.name, node_ip).await {
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
                publish_ingress(&client, key, node.node_ip);
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
    let on_node = move |event: Value| {
        state.lock().unwrap().apply_node_event(&event);
        apply_reconcile(&state, &maps, &node);
    };

    // None of the three branches actually complete in practice, so which
    // error (if any) wins here never matters at runtime -- `and` just gives
    // the whole function a single `Result` to return.
    let (services, endpoint_slices, nodes) = tokio::join!(
        run_list_watch(&client, "/api/v1/services", on_service),
        run_list_watch(
            &client,
            "/apis/discovery.k8s.io/v1/endpointslices",
            on_endpoint_slice,
        ),
        run_list_watch(&client, "/api/v1/nodes", on_node),
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
    let args = Args::parse();

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
        args.vip_map_max_entries,
        args.target_ports_max_entries,
    )
    .context("loading beep-ebpf")?;

    populate_config(&mut ebpf, &args.geneve_iface, &args.uplink_iface)
        .context("populating CONFIG map")?;

    let hooks: [(&str, &str, TcAttachType); 3] = [
        (
            "uplink_ingress",
            args.uplink_iface.as_str(),
            TcAttachType::Ingress,
        ),
        (
            "geneve_ingress",
            args.geneve_iface.as_str(),
            TcAttachType::Ingress,
        ),
        (
            "uplink_egress_return",
            args.uplink_iface.as_str(),
            TcAttachType::Egress,
        ),
    ];
    for (name, iface, attach_type) in hooks {
        attach_and_pin(&mut ebpf, name, iface, attach_type, &args.pin_dir)
            .with_context(|| format!("attaching {name} on {iface}"))?;
        eprintln!(
            "attached {name} on {iface} ({attach_type:?}), pinned under {}",
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

    let creds = parse_kubeconfig(&args.kubeconfig).context("parsing kubeconfig")?;
    let connector =
        build_tls_connector(&creds).context("building TLS connector from kubeconfig")?;
    let client = Arc::new(HyperApiClient {
        server: creds.server,
        connector,
        bearer: None,
    });

    let node = NodeContext {
        node_ip: args.node_ip,
        pod_cidr: args.pod_cidr,
    };
    let state = Arc::new(Mutex::new(WatchState::default()));
    let maps = Arc::new(Mutex::new(
        PinnedMaps::open(&args.pin_dir).context("opening pinned dataplane maps")?,
    ));

    eprintln!("all 3 hooks attached; watching Service/EndpointSlice/Node");
    run_controller_loop(client, state, maps, node).await
}
