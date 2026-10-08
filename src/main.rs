//! Phase 2 beep eBPF dataplane loader: loads the three tc-bpf
//! classifiers from `beep-ebpf` (`uplink_ingress`, `geneve_ingress`,
//! `uplink_egress_return` -- Phase 1's separate `geneve_ingress_decap`/
//! `geneve_ingress_return` merged into one, see that program's doc comment),
//! attaches each at its hook point
//! (`docs/design/ebpf-lb-dataplane.md`), populates one or more static
//! FRONT_IP:PORT -> backend fixture entries this phase proves the mechanism
//! against (repeatable so one Pod behind more than one Service port is
//! expressible -- `beep-ebpf`'s `FRONT_META` keys on the front tuple,
//! not pod IP alone, precisely so this doesn't collide), and pins the
//! resulting links AND maps under a bpffs directory so a loader restart
//! re-adopts the existing attachment instead of leaving the interface
//! unprotected or double-attaching, and REUSES the existing `FWD_PENDING`/
//! `FLOW_TABLE` conntrack tables instead of swapping in an empty
//! set -- `Ebpf::load` alone creates a fresh map set on every call, which
//! would silently drop every established flow on each DaemonSet rollout,
//! eviction, or OOM kill. Real Service/EndpointSlice watching is Phase 5.
//!
//! `FWD_PENDING`/`FLOW_TABLE`/`FRONT_META`/`FRONT_ENDPOINTS` sizes are a load-time
//! DaemonSet config knob, not a value baked into the eBPF object
//! (`beep-ebpf`'s admission-control doc comment) -- overridden here via
//! `EbpfLoader::map_max_entries` before `load()`.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{anyhow, Context};
use aya::{
    maps::{HashMap as AyaHashMap, Map, MapData},
    programs::TcAttachType,
    Ebpf,
};
use beep::{
    attach_and_pin, bump_memlock_rlimit, capacity_hint, evict_pod_flows,
    front_swap::{apply_fronts, DesiredFront},
    load_ebpf, local_pod_ips, parse_fixture, populate_config, populate_uplink_config,
    stale_pod_targets, tunnel_remote_v6, wire_ip_v6, Fixture, DEFAULT_FRONT_ENDPOINTS_MAX_ENTRIES,
    DEFAULT_FRONT_META_MAX_ENTRIES, DEFAULT_NODE_ALLOW_MAX_ENTRIES,
    DEFAULT_POD_TARGETS_MAX_ENTRIES, MAP_NAMES,
};
use beep_common::{
    wire_port, FlowKey, FlowValue, ForwardFlowValue, FrontEndpoint, FrontEndpointKey, FrontMeta,
    LbFrontBackend, LbFrontKey, TcpFlowKey,
};
use clap::Parser;

/// `beep evict-pod <pod-ip> [--pin-dir <dir>]`: a HIDDEN, test-only one-shot
/// that runs the real conntrack eviction sweep (`beep::evict_pod_flows`)
/// against a running loader's already-pinned maps, without going through a
/// live kube API. Not advertised in `--help` -- dispatched by literal argv[1]
/// match in `main` below, before `Args::parse()` ever runs, so it never
/// appears in `Args`' own derived CLI surface at all. Exists solely so
/// `scripts/smoke.sh` (which never runs `beep-controller`, the real trigger
/// for this sweep -- `controller/src/apply.rs`'s `apply_pod_targets`) can
/// exercise the exact same sweep logic production reconciles run.
#[derive(Parser, Debug)]
struct EvictPodArgs {
    /// Pod IP to evict.
    pod_ip: IpAddr,

    /// Same bpffs pin directory the target loader instance was started
    /// with.
    #[arg(long, default_value = "/sys/fs/bpf/beep")]
    pin_dir: PathBuf,
}

fn open_pinned_hash_map<K: aya::Pod, V: aya::Pod>(
    pin_dir: &Path,
    name: &str,
) -> anyhow::Result<AyaHashMap<MapData, K, V>> {
    let path = pin_dir.join(name);
    let map_data = MapData::from_pin(&path)
        .with_context(|| format!("opening pinned map `{name}` from {}", path.display()))?;
    AyaHashMap::try_from(Map::HashMap(map_data))
        .with_context(|| format!("map `{name}` is not a BPF_MAP_TYPE_HASH"))
}

/// Deletes `pod_ip`'s `POD_TARGETS` entry and runs `beep::evict_pod_flows`
/// against the pinned `FWD_PENDING`/`FLOW_TABLE` -- the exact same two steps
/// `controller/src/apply.rs`'s `apply_pod_targets` runs on every reconcile
/// tick for a departed pod, so this trigger proves the real sweep logic
/// rather than a stand-in.
fn run_evict_pod(args: EvictPodArgs) -> anyhow::Result<()> {
    let EvictPodArgs { pod_ip, pin_dir } = args;
    let departed_pod = wire_ip_v6(pod_ip);

    let mut pod_targets: AyaHashMap<MapData, [u8; 16], u8> =
        open_pinned_hash_map(&pin_dir, "POD_TARGETS")?;
    let mut fwd_pending: AyaHashMap<MapData, TcpFlowKey, ForwardFlowValue> =
        open_pinned_hash_map(&pin_dir, "FWD_PENDING")?;
    let mut flow_table: AyaHashMap<MapData, FlowKey, FlowValue> =
        open_pinned_hash_map(&pin_dir, "FLOW_TABLE")?;

    if let Err(e) = pod_targets.remove(&departed_pod) {
        eprintln!("evict-pod: POD_TARGETS delete for {pod_ip} failed: {e:#}");
    }
    evict_pod_flows(&mut fwd_pending, &mut flow_table, departed_pod)
        .context("conntrack eviction sweep")?;
    eprintln!(
        "evict-pod: swept POD_TARGETS/FWD_PENDING/FLOW_TABLE for pod {pod_ip} under {}",
        pin_dir.display()
    );
    Ok(())
}

/// Defaults from the admission-control sizing derivation
/// (`beep-ebpf`'s `FWD_PENDING`/`FLOW_TABLE` doc comments): PENDING is the
/// only flood-exposed tier, sized to peak concurrent half-open connections
/// with headroom; FLOW_TABLE (the merged forward-established+reverse
/// conntrack table) is sized to peak legitimate established concurrency for
/// BOTH roles combined, a valid basis for its forward role only because
/// admission control keeps that role unreachable by a flood.
const DEFAULT_FWD_PENDING_MAX_ENTRIES: u32 = 2048;
const DEFAULT_FLOW_TABLE_MAX_ENTRIES: u32 = 16384;

#[derive(Parser, Debug)]
#[command(
    name = "beep",
    about = "Phase 2 beep eBPF loader: Geneve encap/decap, single-flow happy path"
)]
struct Args {
    /// Physical uplink interface admitting client traffic (hooks: uplink
    /// ingress, uplink egress-return) -- repeatable: a node with N configured
    /// uplinks (e.g. `eth0` + `wg0`) admits, and symmetrically returns, client
    /// traffic on any of them
    /// (`docs/decisions/servicelb-multi-symmetric-uplink.md`).
    #[arg(long = "uplink-iface", required = true)]
    uplink_ifaces: Vec<String>,

    /// Geneve tunnel interface (hook: geneve ingress, both directions).
    #[arg(long, default_value = "geneve0")]
    geneve_iface: String,

    /// Directory on a bpffs mount where programs/links are pinned.
    #[arg(long, default_value = "/sys/fs/bpf/beep")]
    pin_dir: PathBuf,

    /// One FRONT_IP:PORT -> backend-node/PodIP:TargetPort fixture entry, repeatable
    /// to cover one Pod behind more than one Service port (a plain multi-port
    /// Service, or one Pod backing two distinct Services) -- each repetition
    /// becomes its own front (`FRONT_META` + slot-0 `FRONT_ENDPOINTS`). The front address is
    /// this node's own IP in the node-owned-address model (`ebpf-lb-dataplane.md`).
    /// Format: `front_ip:front_port:proto:backend_node_ip:pod_ip:target_port`
    /// (`proto` is `tcp` or `udp`).
    #[arg(long = "fixture", required = true, value_parser = parse_fixture)]
    fixtures: Vec<Fixture>,

    /// Cluster pod CIDR (e.g. `10.244.0.0/16` or a v6 range). Every
    /// `--fixture` front_ip is rejected at startup if it falls inside this
    /// range AND shares its family: a hostNetwork Pod's IP equals its
    /// node's IP, i.e. front-IP space, so a same-family front inside the
    /// pod CIDR is not disjoint from pod-IP space by construction and can
    /// byte-collide a forward and reverse flow key (the
    /// `ebpf-lb-dataplane.md` disjointness correction). A cross-family front
    /// can never collide this way -- `beep_common::ipv4_mapped_v6`'s
    /// embedding keeps a v4-mapped and a genuine v6 address structurally
    /// disjoint -- so this check is a no-op across families.
    #[arg(long = "pod-cidr", value_parser = parse_ip_cidr)]
    pod_cidr: IpCidr,

    /// Cluster Service CIDR / ClusterIP range (e.g. `10.96.0.0/12` or a v6
    /// range). Optional: only enforced when given. Every `--fixture` front_ip
    /// is rejected at startup if it falls inside this range AND shares its
    /// family: tc runs before netfilter on ingress
    /// (`docs/design/kube-proxy-coexistence.md`), so a same-family front
    /// inside the Service CIDR would let beep's classifier shadow that
    /// ClusterIP Service's east-west traffic instead of falling through to
    /// kube-proxy.
    #[arg(long = "service-cidr", value_parser = parse_ip_cidr)]
    service_cidr: Option<IpCidr>,

    /// This node's own address -- the value a `--fixture`'s
    /// `backend_node_ip` names when THIS node is the one hosting that
    /// fixture's pod. Interim stand-in for real node identity (the eventual
    /// answer is a controller populating `POD_TARGETS` from a live
    /// per-node EndpointSlice watch): scopes `POD_TARGETS`, the LOCAL
    /// backend-membership map the decap and egress-return admission gates
    /// check, to fixtures whose `backend_node_ip` matches this address.
    /// `FRONT_META`/`FRONT_ENDPOINTS` (the forwarding tables) stay unfiltered --
    /// any node can be ingress for any front, so they need every fixture
    /// regardless of which node hosts the backend.
    #[arg(long = "node-ip")]
    node_ip: IpAddr,

    /// `FWD_PENDING` max_entries -- the only flood-exposed conntrack tier
    /// (admission control mints every new flow here; see `beep-ebpf`'s
    /// `FWD_PENDING` doc comment). A load-time DaemonSet config knob, not a
    /// value baked into the eBPF object.
    #[arg(long, default_value_t = DEFAULT_FWD_PENDING_MAX_ENTRIES)]
    fwd_pending_max_entries: u32,

    /// `FLOW_TABLE` max_entries -- the unified forward-established+reverse
    /// conntrack table. The forward role is reachable only via a flow's
    /// promoted (i.e. bidirectionally-confirmed) entry; the reverse role
    /// writes on a backend node's first forward-decap for a flow. Sized to
    /// legitimate peak established concurrency across BOTH roles combined,
    /// since they now share one physical capacity pool.
    #[arg(long, default_value_t = DEFAULT_FLOW_TABLE_MAX_ENTRIES)]
    flow_table_max_entries: u32,

    /// `FRONT_META` max_entries -- see `beep-ebpf`'s doc comment. A load-time
    /// DaemonSet config knob, not a value baked into the eBPF object.
    #[arg(long, default_value_t = DEFAULT_FRONT_META_MAX_ENTRIES)]
    front_meta_max_entries: u32,

    /// `FRONT_ENDPOINTS` max_entries -- see `beep-ebpf`'s doc comment.
    #[arg(long, default_value_t = DEFAULT_FRONT_ENDPOINTS_MAX_ENTRIES)]
    front_endpoints_max_entries: u32,

    /// `NODE_ALLOW` max_entries -- one entry per node underlay address, so a
    /// dual-stack node costs two. See `beep-ebpf`'s doc comment.
    #[arg(long, default_value_t = DEFAULT_NODE_ALLOW_MAX_ENTRIES)]
    node_allow_max_entries: u32,

    /// `POD_TARGETS` max_entries -- one entry per local backend pod IP, so a
    /// dual-stack pod costs two. See `beep-ebpf`'s doc comment.
    #[arg(long, default_value_t = DEFAULT_POD_TARGETS_MAX_ENTRIES)]
    pod_targets_max_entries: u32,
}

#[derive(Clone, Copy, Debug)]
struct Ipv4Cidr {
    network: Ipv4Addr,
    prefix_len: u8,
}

impl Ipv4Cidr {
    // prefix_len == 0 (match everything) would overflow a `<< 32` shift
    // (Rust's `<<` masks the shift amount mod 32, so `u32::MAX << 32` wraps
    // to `u32::MAX << 0`, silently turning "match everything" into "match
    // only the exact network address"), so it's handled as its own case
    // rather than folded into the general shift below.
    fn mask(prefix_len: u8) -> u32 {
        if prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - prefix_len)
        }
    }

    fn contains(self, ip: Ipv4Addr) -> bool {
        let mask = Self::mask(self.prefix_len);
        (u32::from(ip) & mask) == (u32::from(self.network) & mask)
    }
}

impl std::fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

fn parse_ipv4_cidr(s: &str) -> Result<Ipv4Cidr, String> {
    // Shared by --pod-cidr and --service-cidr's value_parser, so this
    // message can't name either flag specifically.
    let (network, prefix_len) = s
        .split_once('/')
        .ok_or_else(|| format!("expected network_ip/prefix_len, got `{s}`"))?;
    let network: Ipv4Addr = network
        .parse()
        .map_err(|e| format!("cidr network `{network}`: {e}"))?;
    let prefix_len: u8 = prefix_len
        .parse()
        .map_err(|e| format!("cidr prefix_len `{prefix_len}`: {e}"))?;
    if prefix_len > 32 {
        return Err(format!("cidr prefix_len `{prefix_len}` must be 0..=32"));
    }
    // Mask off host bits so Display/error text always shows the canonical
    // network address (e.g. `10.244.0.0/16`, not `10.244.1.7/16`); `contains`
    // masks both operands anyway, so this doesn't change matching behavior.
    let network = Ipv4Addr::from(u32::from(network) & Ipv4Cidr::mask(prefix_len));
    Ok(Ipv4Cidr {
        network,
        prefix_len,
    })
}

/// v6 analog of `Ipv4Cidr`, same `u128`-masked-comparison shape as the v4
/// version above -- kept as its own type rather than a generic one so each
/// family's bit width (`u32` vs `u128`) stays a plain, unambiguous integer
/// operation.
#[derive(Clone, Copy, Debug)]
struct Ipv6Cidr {
    network: Ipv6Addr,
    prefix_len: u8,
}

impl Ipv6Cidr {
    fn mask(prefix_len: u8) -> u128 {
        if prefix_len == 0 {
            0
        } else {
            u128::MAX << (128 - prefix_len)
        }
    }

    fn contains(self, ip: Ipv6Addr) -> bool {
        let mask = Self::mask(self.prefix_len);
        (u128::from(ip) & mask) == (u128::from(self.network) & mask)
    }
}

impl std::fmt::Display for Ipv6Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

/// `--pod-cidr`/`--service-cidr`'s parsed shape: a Service and its backend
/// Pod can independently be v4 or v6, so these CIDRs must accept either
/// family too, without forcing an operator to configure a range for a
/// family they don't use. A front's own family picks which side of this enum
/// (if either) the disjointness check in `front_outside_pod_cidr`/
/// `front_outside_service_cidr` actually compares against.
#[derive(Clone, Copy, Debug)]
enum IpCidr {
    V4(Ipv4Cidr),
    V6(Ipv6Cidr),
}

impl std::fmt::Display for IpCidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpCidr::V4(cidr) => cidr.fmt(f),
            IpCidr::V6(cidr) => cidr.fmt(f),
        }
    }
}

fn parse_ip_cidr(s: &str) -> Result<IpCidr, String> {
    let (network, prefix_len) = s
        .split_once('/')
        .ok_or_else(|| format!("expected network_ip/prefix_len, got `{s}`"))?;
    if network.parse::<Ipv6Addr>().is_ok() {
        let network: Ipv6Addr = network
            .parse()
            .map_err(|e| format!("cidr network `{network}`: {e}"))?;
        let prefix_len: u8 = prefix_len
            .parse()
            .map_err(|e| format!("cidr prefix_len `{prefix_len}`: {e}"))?;
        if prefix_len > 128 {
            return Err(format!("cidr prefix_len `{prefix_len}` must be 0..=128"));
        }
        let network = Ipv6Addr::from(u128::from(network) & Ipv6Cidr::mask(prefix_len));
        Ok(IpCidr::V6(Ipv6Cidr {
            network,
            prefix_len,
        }))
    } else {
        parse_ipv4_cidr(s).map(IpCidr::V4)
    }
}

/// A hostNetwork Pod's IP equals its node's IP, i.e. front-IP space,
/// so front-IP space and pod CIDR are disjoint only by configuration, not
/// by construction (the `ebpf-lb-dataplane.md` disjointness correction) --
/// a front placed inside the pod CIDR lets a forward flow key (keyed on front)
/// and a reverse flow key (keyed on a Pod's source IP) byte-collide.
/// Rejecting at startup is the only way to guarantee the two stay disjoint.
/// A `front`/`pod_cidr` family mismatch can never collide this way (a
/// v4-mapped and a genuine v6 address are structurally disjoint), so that
/// pairing is always accepted.
fn front_outside_pod_cidr(front: IpAddr, pod_cidr: IpCidr) -> Result<(), String> {
    let inside = match (front, pod_cidr) {
        (IpAddr::V4(front), IpCidr::V4(cidr)) => cidr.contains(front),
        (IpAddr::V6(front), IpCidr::V6(cidr)) => cidr.contains(front),
        _ => false,
    };
    if inside {
        Err(format!(
            "front_ip `{front}` falls inside pod CIDR `{pod_cidr}`: a hostNetwork Pod's IP equals \
             its node's IP (front-IP space), so this front can byte-collide a forward and \
             reverse flow key"
        ))
    } else {
        Ok(())
    }
}

/// tc runs before netfilter on ingress
/// (`docs/design/kube-proxy-coexistence.md`), so a front inside the Service
/// CIDR is not disjoint from ClusterIP space by construction, only by
/// configuration -- beep's classifier would shadow that ClusterIP Service's
/// east-west traffic instead of letting it fall through to kube-proxy's
/// chains. Rejecting at startup is the only way to guarantee the two stay
/// disjoint. Same cross-family no-op as `front_outside_pod_cidr` above.
fn front_outside_service_cidr(front: IpAddr, service_cidr: IpCidr) -> Result<(), String> {
    let inside = match (front, service_cidr) {
        (IpAddr::V4(front), IpCidr::V4(cidr)) => cidr.contains(front),
        (IpAddr::V6(front), IpCidr::V6(cidr)) => cidr.contains(front),
        _ => false,
    };
    if inside {
        Err(format!(
            "front_ip `{front}` falls inside Service CIDR `{service_cidr}`: beep's classifier \
             would shadow that ClusterIP Service's east-west traffic instead of falling \
             through to kube-proxy"
        ))
    } else {
        Ok(())
    }
}

fn main() -> anyhow::Result<()> {
    // Hidden `evict-pod` dispatch: checked by literal argv[1] BEFORE
    // `Args::parse()` runs, so this trigger never registers with clap's own
    // subcommand/help machinery and is invisible to `beep --help`
    // (`EvictPodArgs`'s doc comment).
    if std::env::args().nth(1).as_deref() == Some("evict-pod") {
        return run_evict_pod(EvictPodArgs::parse_from(std::env::args().skip(1)));
    }

    let Args {
        uplink_ifaces,
        geneve_iface,
        pin_dir,
        fixtures,
        pod_cidr,
        service_cidr,
        node_ip,
        fwd_pending_max_entries,
        flow_table_max_entries,
        front_meta_max_entries,
        front_endpoints_max_entries,
        node_allow_max_entries,
        pod_targets_max_entries,
    } = Args::parse();

    for fixture in &fixtures {
        front_outside_pod_cidr(fixture.front_ip, pod_cidr).map_err(|e| anyhow!(e))?;
        if let Some(service_cidr) = service_cidr {
            front_outside_service_cidr(fixture.front_ip, service_cidr).map_err(|e| anyhow!(e))?;
        }
    }

    bump_memlock_rlimit();

    // Pin dir must exist before `loader.load()`: `map_pin_path`'s
    // `create_pinned_by_name` calls `bpf_obj_pin` on a miss, which fails if
    // its parent directory isn't there yet.
    std::fs::create_dir_all(&pin_dir)
        .with_context(|| format!("creating pin dir {}", pin_dir.display()))?;

    let mut ebpf = load_ebpf(
        &pin_dir,
        fwd_pending_max_entries,
        flow_table_max_entries,
        front_meta_max_entries,
        front_endpoints_max_entries,
        node_allow_max_entries,
        pod_targets_max_entries,
    )
    .context("loading beep-ebpf")?;

    populate_config(&mut ebpf, &geneve_iface).context("populating CONFIG map")?;
    populate_uplink_config(&mut ebpf, &uplink_ifaces).context("populating UPLINK_CONFIG map")?;
    populate_fixtures(&mut ebpf, &fixtures, node_ip, &pin_dir)
        .context("populating FRONT_META/FRONT_ENDPOINTS/POD_TARGETS/NODE_ALLOW fixture")?;

    let uplink_iface_refs: Vec<&str> = uplink_ifaces.iter().map(String::as_str).collect();
    let geneve_iface_refs = [geneve_iface.as_str()];
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
        attach_and_pin(&mut ebpf, name, ifaces, attach_type, &pin_dir)
            .with_context(|| format!("attaching {name} on {ifaces:?}"))?;
        eprintln!(
            "attached {name} on {ifaces:?} ({attach_type:?}), pinned under {}",
            pin_dir.display()
        );
    }

    // The parsed object -- BTF, relocation state, and the embedded ELF blob
    // -- has no further use once every hook is attached: every hook's link
    // and every map (the loop above, `MAP_NAMES`) are pinned, so this
    // process doesn't need the `Ebpf` handle to keep the dataplane live.
    // Dropping it here rather than letting it live through the blocking
    // loop below is what keeps this DaemonSet container's steady-state RSS
    // below its load-time peak.
    //
    // On a restart, attach_and_pin's reused-link branch tracks each link via
    // `attach_to_link` rather than `take_link`, so the `SchedClassifier` here
    // still owns it -- this drop therefore runs the program's implicit
    // unload-driven detach on every restart, not only on abnormal process
    // death. That's safe: the bpffs pin at `{name}-{iface}-link` (not this
    // process's fd) anchors each kernel link object, so the implicit detach
    // only releases this process's handle to it and leaves the tc
    // attachment live for the next loader to reattach to.
    drop(ebpf);
    // glibc doesn't return freed heap to the OS on its own -- without an
    // explicit trim the drop above frees the allocator's own bookkeeping
    // but resident memory stays at the load-time high-water mark.
    unsafe {
        libc::malloc_trim(0);
    }

    // Prove the drop above didn't strand map access: every map must still
    // open from its pin file alone, the same path a future Phase 5
    // Service/EndpointSlice watcher would use to get map handles without
    // ever holding the parsed object.
    for name in MAP_NAMES {
        let path = pin_dir.join(name);
        MapData::from_pin(&path)
            .with_context(|| format!("reopening pinned map `{name}` from {}", path.display()))?;
    }

    eprintln!(
        "all 3 hooks attached; blocking (attachment lives in pinned kernel objects, safe to kill)"
    );
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

/// Writes one or more static FRONT_IP:PORT -> backend-node/PodIP:TargetPort
/// mappings this phase proves the mechanism against (`ebpf-lb-dataplane.md`;
/// real Service/EndpointSlice watching is Phase 5). Every node runs this same
/// loader with the same fixture set: which node ends up playing "ingress" vs
/// "backend" for a given packet is decided by which node the client dialed
/// and where the Pod landed, not by asymmetric per-node config
/// (`docs/decisions/servicelb-ebpf-geneve-dataplane.md`'s node-owned-address
/// model).
///
/// Fronts are keyed on the (FRONT_IP:PORT:proto) tuple, not on pod IP alone: one
/// `--fixture` per Service port, even when several share a backend Pod IP, so
/// a multi-port Service resolves each port to its own target port instead of
/// the last-written one silently winning.
fn fixture_key(fixture: &Fixture) -> LbFrontKey {
    LbFrontKey {
        front_ip: wire_ip_v6(fixture.front_ip),
        front_port: wire_port(fixture.front_port),
        proto: fixture.proto.as_ip_proto(),
        _pad: 0,
    }
}

/// One front per `--fixture`, slot 0 only. A repeated front tuple keeps the
/// last fixture, as the pre-consolidation maps did.
fn fixture_fronts(fixtures: &[Fixture]) -> HashMap<LbFrontKey, DesiredFront> {
    fixtures
        .iter()
        .map(|fixture| {
            let endpoint = FrontEndpoint {
                backend: LbFrontBackend {
                    // bpf_tunnel_key.remote_ipv4 is the one field the kernel
                    // itself converts host<->network internally on set/get --
                    // confirmed empirically (a wire-token value here came out
                    // byte-reversed on the wire, e.g. 192.168.109.3 ->
                    // 3.109.168.192): host-native order, unlike every other
                    // address/port field in this crate. `tunnel_remote_v6`
                    // picks that convention; a v6 address has no separate
                    // host-native form, so it's a no-op there.
                    backend_node_ip: tunnel_remote_v6(fixture.backend_node_ip),
                    pod_ip: wire_ip_v6(fixture.pod_ip),
                },
                target_port: wire_port(fixture.target_port),
                _pad: [0; 6],
            };
            (
                fixture_key(fixture),
                DesiredFront {
                    flags: 0,
                    endpoints: vec![endpoint],
                },
            )
        })
        .collect()
}

fn populate_fixtures(
    ebpf: &mut Ebpf,
    fixtures: &[Fixture],
    node_ip: IpAddr,
    pin_dir: &Path,
) -> anyhow::Result<()> {
    {
        // Opened from the pins `load_ebpf` just created: both maps are needed
        // at once, and taking them out of `ebpf` would close the fds the
        // programs still have to relocate against.
        let open = |name: &str| -> anyhow::Result<MapData> {
            let path = pin_dir.join(name);
            MapData::from_pin(&path)
                .with_context(|| format!("opening pinned map `{name}` from {}", path.display()))
        };
        let mut front_meta: AyaHashMap<_, LbFrontKey, FrontMeta> =
            AyaHashMap::try_from(Map::HashMap(open("FRONT_META")?))?;
        let mut front_endpoints: AyaHashMap<_, FrontEndpointKey, FrontEndpoint> =
            AyaHashMap::try_from(Map::HashMap(open("FRONT_ENDPOINTS")?))?;
        let failures = apply_fronts(
            &mut front_meta,
            &mut front_endpoints,
            &fixture_fronts(fixtures),
            false,
        )
        .context("reading FRONT_META/FRONT_ENDPOINTS")?;
        if !failures.is_empty() {
            let detail: Vec<String> = failures.into_iter().map(|(_, e)| e).collect();
            anyhow::bail!(
                "{} front write(s) failed: {}; {} / {}",
                detail.len(),
                detail.join("; "),
                capacity_hint("FRONT_META"),
                capacity_hint("FRONT_ENDPOINTS"),
            );
        }
    }

    {
        // Keyed on pod IP alone, unlike the front tables above -- the egress-return
        // gate this feeds (`beep_common::egress_return_admission`), and the
        // decap gate (`beep_common::decap_forward_pod_admission`), check only
        // that a pod is one of THIS node's own backends, deliberately not
        // which port it's replying from. Two fixtures sharing a pod IP (a
        // multi-port Service) collapse to one entry here on purpose:
        // membership doesn't need per-port granularity. Unlike the front
        // tables above, this map is scoped to `node_ip` via
        // `local_pod_ips`: any node can be ingress for any front, but only
        // the node actually running a pod may claim it as a local backend --
        // otherwise both gates' "is this still one of MY pods" check always
        // passes cluster-wide and never drops a misdelivered/drifted packet.
        let mut pod_targets: AyaHashMap<_, [u8; 16], u8> = AyaHashMap::try_from(
            ebpf.map_mut("POD_TARGETS")
                .ok_or_else(|| anyhow!("no map named `POD_TARGETS` in the eBPF object"))?,
        )?;
        let local_ips = local_pod_ips(fixtures, node_ip);
        // POD_TARGETS is pinned (`MAP_NAMES`) and so reused, not
        // recreated, across a loader restart with a different `--fixture`
        // set: a Pod that departed since the last run otherwise leaves a
        // stale entry here forever. That used to be harmless (this map was
        // read-only membership metadata), but it now gates
        // `uplink_egress_return`'s FLOW_TABLE-reverse lookup -- a stale
        // entry for a departed/reused Pod IP would make unrelated future
        // traffic on that address pay for that lookup. Pruned against the
        // same local set this block writes, not the full fixture list, or a
        // pod that moved OFF this node would never be pruned from its former
        // host's POD_TARGETS.
        let existing_ips: Vec<[u8; 16]> = pod_targets.keys().collect::<Result<_, _>>()?;
        for ip in stale_pod_targets(&existing_ips, &local_ips) {
            pod_targets.remove(&ip)?;
        }
        for pod_ip in &local_ips {
            pod_targets
                .insert(pod_ip, 1u8, 0)
                .with_context(|| capacity_hint("POD_TARGETS"))?;
        }
    }

    {
        // Fixture/smoke mode has no controller-driven Node watch to seed
        // this from (`beep_common::peer_node_admission`'s doc comment): the
        // only peer this loader can attest to is its own `--node-ip`, which
        // is also the outer Geneve source `geneve_ingress` sees for a
        // single-node fixture's self-loop decap (this node is both ingress
        // and backend for its own fixture). A real deployment's controller
        // keeps NODE_ALLOW's real peer set converged instead.
        let mut node_allow: AyaHashMap<_, [u8; 16], u8> = AyaHashMap::try_from(
            ebpf.map_mut("NODE_ALLOW")
                .ok_or_else(|| anyhow!("no map named `NODE_ALLOW` in the eBPF object"))?,
        )?;
        let node_ip_key = tunnel_remote_v6(node_ip);
        let existing_ips: Vec<[u8; 16]> = node_allow.keys().collect::<Result<_, _>>()?;
        for existing in existing_ips {
            if existing != node_ip_key {
                node_allow.remove(&existing)?;
            }
        }
        node_allow
            .insert(node_ip_key, 1u8, 0)
            .with_context(|| capacity_hint("NODE_ALLOW"))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // A hostNetwork Pod's IP equals its node's IP, i.e. front-IP
    // space -- so a front placed inside the pod CIDR is not disjoint from
    // pod-IP space by construction, only by configuration, and lets a
    // forward flow key (keyed on the front) and a reverse flow key (keyed on
    // a Pod's source IP) byte-collide. These four cases pin the boundary
    // of that rejection exactly at the CIDR's own edges.
    #[test]
    fn front_inside_pod_cidr_is_rejected() {
        let pod_cidr = IpCidr::V4(parse_ipv4_cidr("10.244.0.0/16").unwrap());
        let front = IpAddr::V4(Ipv4Addr::new(10, 244, 5, 9));

        let err = front_outside_pod_cidr(front, pod_cidr)
            .expect_err("a front inside the pod CIDR must be rejected, or it can byte-collide a forward and reverse flow key");
        assert!(
            err.contains("10.244.5.9") && err.contains("10.244.0.0/16"),
            "rejection must name both the offending front and the pod CIDR so an operator can fix the config: got `{err}`"
        );
    }

    #[test]
    fn front_outside_pod_cidr_is_accepted() {
        let pod_cidr = IpCidr::V4(parse_ipv4_cidr("10.244.0.0/16").unwrap());
        // Matches scripts/smoke-remote.sh's RFC 5737 front, deliberately
        // disjoint from the pod range -- this is the legitimate-config path
        // that must keep loading.
        let front = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));

        assert!(
            front_outside_pod_cidr(front, pod_cidr).is_ok(),
            "a front outside the pod CIDR is a legitimate config and must not be rejected"
        );
    }

    #[test]
    fn front_at_pod_cidr_network_or_broadcast_address_is_rejected() {
        // The network and broadcast addresses are still member addresses of
        // the block (a Pod CAN be assigned either, depending on the CNI),
        // so both boundary values must reject exactly like an interior front.
        let pod_cidr = IpCidr::V4(parse_ipv4_cidr("10.244.0.0/16").unwrap());
        assert!(
            front_outside_pod_cidr(IpAddr::V4(Ipv4Addr::new(10, 244, 0, 0)), pod_cidr).is_err(),
            "the pod CIDR's network address is still inside the block and must be rejected"
        );
        assert!(
            front_outside_pod_cidr(IpAddr::V4(Ipv4Addr::new(10, 244, 255, 255)), pod_cidr).is_err(),
            "the pod CIDR's broadcast address is still inside the block and must be rejected"
        );
    }

    #[test]
    fn front_one_address_outside_pod_cidr_boundary_is_accepted() {
        // The addresses immediately below the network address and above the
        // broadcast address are the tightest legitimate fronts possible --
        // an off-by-one in the mask calculation would reject these.
        let pod_cidr = IpCidr::V4(parse_ipv4_cidr("10.244.0.0/16").unwrap());
        assert!(
            front_outside_pod_cidr(IpAddr::V4(Ipv4Addr::new(10, 243, 255, 255)), pod_cidr).is_ok(),
            "one address below the pod CIDR's network address must be accepted"
        );
        assert!(
            front_outside_pod_cidr(IpAddr::V4(Ipv4Addr::new(10, 245, 0, 0)), pod_cidr).is_ok(),
            "one address above the pod CIDR's broadcast address must be accepted"
        );
    }

    #[test]
    fn pod_cidr_prefix_len_over_32_is_rejected_at_parse_time() {
        // An invalid prefix length must fail loud at arg-parse time, not
        // silently produce a mask that under- or over-matches at runtime.
        assert!(parse_ipv4_cidr("10.244.0.0/33").is_err());
    }

    #[test]
    fn pod_cidr_slash_zero_rejects_every_front_as_inside() {
        // A /0 pod CIDR must be treated as "contains every address", so
        // every front is rejected. Rust's `<<` masks its shift amount mod 32,
        // so deleting the `prefix_len == 0` special case in `Ipv4Cidr::mask`
        // would make `u32::MAX << 32` silently wrap to `u32::MAX << 0`,
        // turning "match everything" into "match only the exact network
        // address" -- this front (not equal to the network address) would then
        // wrongly be accepted instead of rejected.
        let pod_cidr = IpCidr::V4(parse_ipv4_cidr("0.0.0.0/0").unwrap());
        assert!(
            front_outside_pod_cidr(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), pod_cidr).is_err(),
            "a /0 pod CIDR spans the entire address space, so every front must be rejected"
        );
    }

    #[test]
    fn pod_cidr_slash_32_rejects_only_the_exact_address() {
        // A /32 pod CIDR is a single host route: it must reject a front equal
        // to that address, but accept every other address. An off-by-one in
        // the mask shift (e.g. treating 32 like 0, or vice versa) would
        // either widen this to reject everything or narrow it to reject
        // nothing.
        let pod_cidr = IpCidr::V4(parse_ipv4_cidr("10.244.5.9/32").unwrap());
        assert!(
            front_outside_pod_cidr(IpAddr::V4(Ipv4Addr::new(10, 244, 5, 9)), pod_cidr).is_err(),
            "a front equal to the /32 pod CIDR's single address must be rejected"
        );
        assert!(
            front_outside_pod_cidr(IpAddr::V4(Ipv4Addr::new(10, 244, 5, 10)), pod_cidr).is_ok(),
            "a front one address away from a /32 pod CIDR must be accepted"
        );
    }

    #[test]
    fn front_inside_pod_cidr_of_a_different_family_is_never_rejected() {
        // A v4-mapped and a genuine v6 address are structurally disjoint
        // (`beep_common::ipv4_mapped_v6`'s embedding) -- a v6 front can never
        // byte-collide with a v4 pod CIDR's address space, so cross-family
        // must always pass regardless of the numeric range.
        let pod_cidr = IpCidr::V4(parse_ipv4_cidr("0.0.0.0/0").unwrap());
        let front: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(
            front_outside_pod_cidr(front, pod_cidr).is_ok(),
            "a v6 front must never be rejected against a v4 pod CIDR, even a /0 spanning the \
             entire v4 address space -- the two families can't collide"
        );
    }

    #[test]
    fn front_inside_a_v6_pod_cidr_is_rejected() {
        // v6 mirror of `front_inside_pod_cidr_is_rejected`: a genuine v6
        // hostNetwork Pod's IP equally collides with a v6 front inside the
        // same v6 pod CIDR, so this bead's widening must reject it exactly
        // like the v4 case, not silently allow it because `Ipv4Cidr`'s
        // checks don't apply.
        let pod_cidr = parse_ip_cidr("2001:db8::/32").unwrap();
        let front: IpAddr = "2001:db8::5".parse().unwrap();

        let err = front_outside_pod_cidr(front, pod_cidr)
            .expect_err("a v6 front inside the v6 pod CIDR must be rejected, or it can byte-collide a forward and reverse flow key");
        assert!(
            err.contains("2001:db8::5") && err.contains("2001:db8::/32"),
            "rejection must name both the offending front and the pod CIDR so an operator can fix the config: got `{err}`"
        );
    }

    #[test]
    fn front_outside_a_v6_pod_cidr_is_accepted() {
        let pod_cidr = parse_ip_cidr("2001:db8::/32").unwrap();
        let front: IpAddr = "2001:db9::1".parse().unwrap();
        assert!(
            front_outside_pod_cidr(front, pod_cidr).is_ok(),
            "a v6 front outside the v6 pod CIDR is a legitimate config and must not be rejected"
        );
    }

    const REQUIRED_ARGS: [&str; 9] = [
        "beep",
        "--uplink-iface",
        "eth0",
        "--fixture",
        "10.0.0.5:80:tcp:10.0.0.6:10.244.1.7:8080",
        "--pod-cidr",
        "10.244.0.0/16",
        "--node-ip",
        "10.0.0.6",
    ];

    // The 17th dual-stack node (or 65th dual-stack pod) is silently
    // unreachable if the caps regress below the sized defaults.
    #[test]
    fn node_allow_and_pod_targets_caps_default_to_the_sized_values() {
        let args = Args::try_parse_from(REQUIRED_ARGS).unwrap();
        assert_eq!(args.node_allow_max_entries, 32);
        assert_eq!(args.pod_targets_max_entries, 128);
    }

    // A bigger cluster must be able to raise the caps at deploy time.
    #[test]
    fn node_allow_and_pod_targets_caps_are_flag_overridable() {
        let args = Args::try_parse_from(REQUIRED_ARGS.into_iter().chain([
            "--node-allow-max-entries",
            "64",
            "--pod-targets-max-entries",
            "512",
        ]))
        .unwrap();
        assert_eq!(args.node_allow_max_entries, 64);
        assert_eq!(args.pod_targets_max_entries, 512);
    }

    #[test]
    fn parse_ipv4_cidr_stores_canonical_network_address() {
        // Operators read this address back out of error/Display text when a
        // front is rejected; if host bits leak through unmasked, that message
        // shows a misleading, non-canonical network (e.g. `10.244.1.7/16`
        // instead of `10.244.0.0/16`), even though matching itself is
        // unaffected (`contains` masks both operands).
        let pod_cidr = parse_ipv4_cidr("10.244.1.7/16").unwrap();
        assert_eq!(
            pod_cidr.to_string(),
            "10.244.0.0/16",
            "the stored network address must be masked to its canonical form at parse time"
        );
    }

    // `front_outside_service_cidr` mirrors `front_outside_pod_cidr` above: same
    // boundary math (`Ipv4Cidr::contains`), same rejection shape, guarding
    // against beep's classifier shadowing a ClusterIP Service instead of
    // the flow-key collision the pod-CIDR guard prevents.
    #[test]
    fn front_inside_service_cidr_is_rejected() {
        let service_cidr = IpCidr::V4(parse_ipv4_cidr("10.96.0.0/12").unwrap());
        let front = IpAddr::V4(Ipv4Addr::new(10, 96, 5, 9));

        let err = front_outside_service_cidr(front, service_cidr)
            .expect_err("a front inside the Service CIDR must be rejected, or beep's classifier can shadow a ClusterIP Service");
        assert!(
            err.contains("10.96.5.9") && err.contains("10.96.0.0/12"),
            "rejection must name both the offending front and the Service CIDR so an operator can fix the config: got `{err}`"
        );
    }

    #[test]
    fn front_outside_service_cidr_is_accepted() {
        let service_cidr = IpCidr::V4(parse_ipv4_cidr("10.96.0.0/12").unwrap());
        // Matches scripts/smoke-remote.sh's RFC 5737 front, deliberately
        // disjoint from the Service range -- this is the legitimate-config
        // path that must keep loading.
        let front = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));

        assert!(
            front_outside_service_cidr(front, service_cidr).is_ok(),
            "a front outside the Service CIDR is a legitimate config and must not be rejected"
        );
    }

    #[test]
    fn front_at_service_cidr_network_or_broadcast_address_is_rejected() {
        let service_cidr = IpCidr::V4(parse_ipv4_cidr("10.96.0.0/12").unwrap());
        assert!(
            front_outside_service_cidr(IpAddr::V4(Ipv4Addr::new(10, 96, 0, 0)), service_cidr)
                .is_err(),
            "the Service CIDR's network address is still inside the block and must be rejected"
        );
        assert!(
            front_outside_service_cidr(IpAddr::V4(Ipv4Addr::new(10, 111, 255, 255)), service_cidr)
                .is_err(),
            "the Service CIDR's broadcast address is still inside the block and must be rejected"
        );
    }

    #[test]
    fn front_one_address_outside_service_cidr_boundary_is_accepted() {
        let service_cidr = IpCidr::V4(parse_ipv4_cidr("10.96.0.0/12").unwrap());
        assert!(
            front_outside_service_cidr(IpAddr::V4(Ipv4Addr::new(10, 95, 255, 255)), service_cidr)
                .is_ok(),
            "one address below the Service CIDR's network address must be accepted"
        );
        assert!(
            front_outside_service_cidr(IpAddr::V4(Ipv4Addr::new(10, 112, 0, 0)), service_cidr)
                .is_ok(),
            "one address above the Service CIDR's broadcast address must be accepted"
        );
    }

    #[test]
    fn front_inside_a_v6_service_cidr_is_rejected() {
        // v6 mirror of `front_inside_service_cidr_is_rejected`.
        let service_cidr = parse_ip_cidr("fd00::/16").unwrap();
        let front: IpAddr = "fd00::5".parse().unwrap();

        let err = front_outside_service_cidr(front, service_cidr)
            .expect_err("a v6 front inside the v6 Service CIDR must be rejected, or beep's classifier can shadow a ClusterIP Service");
        assert!(
            err.contains("fd00::5") && err.contains("fd00::/16"),
            "rejection must name both the offending front and the Service CIDR so an operator can fix the config: got `{err}`"
        );
    }

    #[test]
    fn two_service_ports_on_one_pod_route_to_distinct_target_ports() {
        // A plain multi-port Service (e.g. 80->8080 alongside 443->8443 on
        // the SAME Pod) needs each Service port to resolve its own target
        // port independently. The pre-fix `POD_TARGETS: HashMap<u32, u16>`
        // keyed only on pod IP, so both fixtures collapsed into ONE entry --
        // whichever `--fixture` was populated last silently won, and the
        // other Service port's traffic got mis-DNATed to the wrong
        // container port.
        let pod_ip = IpAddr::V4(Ipv4Addr::new(10, 244, 1, 7));
        let fixtures = [
            parse_fixture("10.0.0.5:80:tcp:10.0.0.6:10.244.1.7:8080").unwrap(),
            parse_fixture("10.0.0.5:443:tcp:10.0.0.6:10.244.1.7:8443").unwrap(),
        ];
        assert_eq!(
            (fixtures[0].pod_ip, fixtures[1].pod_ip),
            (pod_ip, pod_ip),
            "fixture invariant: both entries must share one Pod IP to exercise the bug"
        );

        let fronts = fixture_fronts(&fixtures);
        assert_eq!(
            fronts.len(),
            2,
            "two distinct Service ports on one Pod must produce two distinct \
             fronts, not collapse into one"
        );
        for f in &fixtures {
            let front = &fronts[&fixture_key(f)];
            assert_eq!(front.endpoints.len(), 1, "one endpoint per front today");
            assert_eq!(
                Some(front.endpoints[0].target_port),
                Some(wire_port(f.target_port)),
                "front port {} must resolve to its own target port {}, not the \
                 other Service port's",
                f.front_port,
                f.target_port
            );
        }

        // The bug this closes, made concrete: keying on pod IP alone cannot
        // represent this at all -- both fixtures collapse to the same entry.
        let mut old_pod_targets: HashMap<[u8; 16], u16> = HashMap::new();
        for f in &fixtures {
            old_pod_targets.insert(wire_ip_v6(f.pod_ip), wire_port(f.target_port));
        }
        assert_eq!(
            old_pod_targets.len(),
            1,
            "this demonstrates why pod-IP-only keying was insufficient -- \
             both Service ports collapse to the same map key"
        );
    }

    #[test]
    fn a_v6_fixture_populates_front_tables_and_pod_targets() {
        // .6's core acceptance criterion: a v6 Service/Pod must populate the
        // same maps a v4 fixture does, at the same wire-encode boundary --
        // if a v6 fixture silently failed to land in any of these, a v6
        // Service would get accepted at parse time but never actually route
        // any traffic.
        let node_ip: IpAddr = "2001:db8::1".parse().unwrap();
        let fixture =
            parse_fixture("[2001:db8::10]:80:tcp:[2001:db8::1]:[2001:db8::2]:8080").unwrap();
        let front_ip: IpAddr = "2001:db8::10".parse().unwrap();
        let pod_ip: IpAddr = "2001:db8::2".parse().unwrap();
        assert_eq!(fixture.front_ip, front_ip);
        assert_eq!(fixture.backend_node_ip, node_ip);
        assert_eq!(fixture.pod_ip, pod_ip);

        let key = fixture_key(&fixture);
        assert_eq!(
            key.front_ip,
            wire_ip_v6(front_ip),
            "the front key must carry the v6 front's raw octets, \
             the same wire-encode boundary a v4 front's ipv4_mapped_v6 embedding uses"
        );
        let fronts = fixture_fronts(std::slice::from_ref(&fixture));
        assert_eq!(
            fronts[&key].endpoints[0].backend.pod_ip,
            wire_ip_v6(pod_ip),
            "a v6 fixture must land its pod in the front's slot-0 endpoint"
        );

        assert_eq!(
            local_pod_ips(&[fixture], node_ip),
            vec![wire_ip_v6(pod_ip)],
            "POD_TARGETS must contain the v6 fixture's pod_ip, or this node never admits its \
             own v6 backend Pod's return traffic"
        );
    }
}
