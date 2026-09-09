//! Phase 2 beep eBPF dataplane loader: loads the three tc-bpf
//! classifiers from `beep-ebpf` (`uplink_ingress`, `geneve_ingress`,
//! `uplink_egress_return` -- Phase 1's separate `geneve_ingress_decap`/
//! `geneve_ingress_return` merged into one, see that program's doc comment),
//! attaches each at its hook point
//! (`docs/design/ebpf-lb-dataplane.md`), populates one or more static
//! VIP:PORT -> backend fixture entries this phase proves the mechanism
//! against (repeatable so one Pod behind more than one Service port is
//! expressible -- `beep-ebpf`'s `TARGET_PORTS` keys on the front tuple,
//! not pod IP alone, precisely so this doesn't collide), and pins the
//! resulting links AND maps under a bpffs directory so a loader restart
//! re-adopts the existing attachment instead of leaving the interface
//! unprotected or double-attaching, and REUSES the existing `FWD_PENDING`/
//! `FLOW_TABLE` conntrack tables instead of swapping in an empty
//! set -- `Ebpf::load` alone creates a fresh map set on every call, which
//! would silently drop every established flow on each DaemonSet rollout,
//! eviction, or OOM kill. Real Service/EndpointSlice watching is Phase 5.
//!
//! `FWD_PENDING`/`FLOW_TABLE` sizes are a load-time DaemonSet config knob,
//! not a value baked into the eBPF object (`beep-ebpf`'s admission-control
//! doc comment) -- overridden here via `EbpfLoader::map_max_entries` before
//! `load()`.

use std::{
    net::Ipv4Addr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{anyhow, Context};
use aya::{
    include_bytes_aligned,
    maps::{Array as AyaArray, HashMap as AyaHashMap},
    programs::{
        links::{FdLink, LinkError, PinnedLink},
        tc::{SchedClassifierLink, TcAttachOptions},
        LinkOrder, SchedClassifier, TcAttachType,
    },
    sys::SyscallError,
    Ebpf, EbpfLoader, Pod,
};
use clap::{Parser, ValueEnum};

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

// Every map `beep-ebpf` declares (`ebpf/src/main.rs`'s
// `#[map]` statics). Pinned by name below so a loader restart reuses them
// instead of `Ebpf::load` creating an empty set -- an omission here silently
// drops that map's state on every restart with no build-time signal.
const MAP_NAMES: [&str; 6] = [
    "CONFIG",
    "VIP_MAP",
    "TARGET_PORTS",
    "POD_TARGETS",
    "FWD_PENDING",
    "FLOW_TABLE",
];

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
    /// Physical uplink interface (hooks: uplink ingress, uplink egress-return).
    #[arg(long, default_value = "eth0")]
    uplink_iface: String,

    /// Geneve tunnel interface (hook: geneve ingress, both directions).
    #[arg(long, default_value = "geneve0")]
    geneve_iface: String,

    /// Directory on a bpffs mount where programs/links are pinned.
    #[arg(long, default_value = "/sys/fs/bpf/beep")]
    pin_dir: PathBuf,

    /// One VIP:PORT -> backend-node/PodIP:TargetPort fixture entry, repeatable
    /// to cover one Pod behind more than one Service port (a plain multi-port
    /// Service, or one Pod backing two distinct Services) -- each repetition
    /// becomes its own `VIP_MAP`/`TARGET_PORTS` entry. VIP address is this
    /// node's own IP in the node-owned-address model (`ebpf-lb-dataplane.md`).
    /// Format: `vip_ip:vip_port:proto:backend_node_ip:pod_ip:target_port`
    /// (`proto` is `tcp` or `udp`).
    #[arg(long = "fixture", required = true, value_parser = parse_fixture)]
    fixtures: Vec<Fixture>,

    /// Cluster pod CIDR (e.g. `10.244.0.0/16`). Every `--fixture` vip_ip is
    /// rejected at startup if it falls inside this range: a hostNetwork
    /// Pod's IP equals its node's IP, i.e. front-IP (VIP) space, so a VIP
    /// inside the pod CIDR is not disjoint from pod-IP space by
    /// construction and can byte-collide a forward and reverse flow key
    /// (the `ebpf-lb-dataplane.md` disjointness correction).
    #[arg(long = "pod-cidr", value_parser = parse_ipv4_cidr)]
    pod_cidr: Ipv4Cidr,

    /// This node's own address -- the value a `--fixture`'s
    /// `backend_node_ip` names when THIS node is the one hosting that
    /// fixture's pod. Interim stand-in for real node identity (the eventual
    /// answer is a controller populating `POD_TARGETS` from a live
    /// per-node EndpointSlice watch): scopes `POD_TARGETS`, the LOCAL
    /// backend-membership map the decap and egress-return admission gates
    /// check, to fixtures whose `backend_node_ip` matches this address.
    /// `VIP_MAP`/`TARGET_PORTS` (the forwarding tables) stay unfiltered --
    /// any node can be ingress for any VIP, so they need every fixture
    /// regardless of which node hosts the backend.
    #[arg(long = "node-ip")]
    node_ip: Ipv4Addr,

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
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    fn as_ip_proto(self) -> u8 {
        match self {
            Proto::Tcp => IPPROTO_TCP,
            Proto::Udp => IPPROTO_UDP,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Fixture {
    vip_ip: Ipv4Addr,
    vip_port: u16,
    proto: Proto,
    backend_node_ip: Ipv4Addr,
    pod_ip: Ipv4Addr,
    target_port: u16,
}

fn parse_fixture(s: &str) -> Result<Fixture, String> {
    let parts: Vec<&str> = s.split(':').collect();
    let [vip_ip, vip_port, proto, backend_node_ip, pod_ip, target_port] = parts.as_slice() else {
        return Err(format!(
            "expected vip_ip:vip_port:proto:backend_node_ip:pod_ip:target_port, got `{s}`"
        ));
    };
    Ok(Fixture {
        vip_ip: vip_ip
            .parse()
            .map_err(|e| format!("vip_ip `{vip_ip}`: {e}"))?,
        vip_port: vip_port
            .parse()
            .map_err(|e| format!("vip_port `{vip_port}`: {e}"))?,
        proto: match *proto {
            "tcp" => Proto::Tcp,
            "udp" => Proto::Udp,
            other => return Err(format!("proto: expected `tcp` or `udp`, got `{other}`")),
        },
        backend_node_ip: backend_node_ip
            .parse()
            .map_err(|e| format!("backend_node_ip `{backend_node_ip}`: {e}"))?,
        pod_ip: pod_ip
            .parse()
            .map_err(|e| format!("pod_ip `{pod_ip}`: {e}"))?,
        target_port: target_port
            .parse()
            .map_err(|e| format!("target_port `{target_port}`: {e}"))?,
    })
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
    // Mask off host bits so Display/error text always shows the canonical
    // network address (e.g. `10.244.0.0/16`, not `10.244.1.7/16`); `contains`
    // masks both operands anyway, so this doesn't change matching behavior.
    let network = Ipv4Addr::from(u32::from(network) & Ipv4Cidr::mask(prefix_len));
    Ok(Ipv4Cidr {
        network,
        prefix_len,
    })
}

/// A hostNetwork Pod's IP equals its node's IP, i.e. front-IP (VIP) space,
/// so front-IP space and pod CIDR are disjoint only by configuration, not
/// by construction (the `ebpf-lb-dataplane.md` disjointness correction) --
/// a VIP placed inside the pod CIDR lets a forward flow key (keyed on VIP)
/// and a reverse flow key (keyed on a Pod's source IP) byte-collide.
/// Rejecting at startup is the only way to guarantee the two stay disjoint.
fn vip_outside_pod_cidr(vip: Ipv4Addr, pod_cidr: Ipv4Cidr) -> Result<(), String> {
    if pod_cidr.contains(vip) {
        Err(format!(
            "vip_ip `{vip}` falls inside pod CIDR `{pod_cidr}`: a hostNetwork Pod's IP equals \
             its node's IP (front-IP space), so this VIP can byte-collide a forward and \
             reverse flow key"
        ))
    } else {
        Ok(())
    }
}

/// Converts a host-order value into the "raw wire token" representation the
/// eBPF side compares packet bytes against verbatim (see
/// `ebpf/src/main.rs`'s module doc for why this conversion exists
/// and why it's applied exactly once, here, at the map-population boundary).
fn wire_ip(ip: Ipv4Addr) -> u32 {
    u32::from(ip).to_be()
}

fn wire_port(port: u16) -> u16 {
    port.to_be()
}

// Byte-layout-identical to beep-ebpf's types of the same name -- the
// eBPF side has no visibility into this crate (separate, no_std nested
// workspace), so these are kept in sync by hand. A drift here corrupts map
// lookups silently; the wire-value convention doc comment there is the
// source of truth for what each field must contain.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct VipKey {
    vip_ip: u32,
    vip_port: u16,
    proto: u8,
    _pad: u8,
}
unsafe impl Pod for VipKey {}

#[repr(C)]
#[derive(Clone, Copy)]
struct VipBackend {
    backend_node_ip: u32,
    pod_ip: u32,
}
unsafe impl Pod for VipBackend {}

#[repr(C)]
#[derive(Clone, Copy)]
struct Config {
    geneve_ifindex: u32,
    uplink_ifindex: u32,
    // Field order/types must mirror `beep-ebpf`'s `Config` exactly --
    // this struct's bytes are written straight into the `CONFIG` map, and
    // nothing else enforces the two definitions staying in sync.
    uplink_l2_hlen: u32,
}
unsafe impl Pod for Config {}

fn main() -> anyhow::Result<()> {
    let Args {
        uplink_iface,
        geneve_iface,
        pin_dir,
        fixtures,
        pod_cidr,
        node_ip,
        fwd_pending_max_entries,
        flow_table_max_entries,
    } = Args::parse();

    for fixture in &fixtures {
        vip_outside_pod_cidr(fixture.vip_ip, pod_cidr).map_err(|e| anyhow!(e))?;
    }

    bump_memlock_rlimit();

    // Pin dir must exist before `loader.load()`: `map_pin_path`'s
    // `create_pinned_by_name` calls `bpf_obj_pin` on a miss, which fails if
    // its parent directory isn't there yet.
    std::fs::create_dir_all(&pin_dir)
        .with_context(|| format!("creating pin dir {}", pin_dir.display()))?;

    let mut loader = EbpfLoader::new();
    for name in MAP_NAMES {
        loader.map_pin_path(name, pin_dir.join(name));
    }
    // Only takes effect the FIRST time a pin path is created: a reused pin
    // (loader restart against the same --pin-dir) opens the existing map via
    // its live fd and this override is silently a no-op, which is the
    // intended behavior -- sizing is decided once at initial provisioning,
    // not resized on every restart (the declined-runtime-resize decision).
    loader.map_max_entries("FWD_PENDING", fwd_pending_max_entries);
    loader.map_max_entries("FLOW_TABLE", flow_table_max_entries);
    let mut ebpf = loader
        .load(include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/beep-ebpf"
        )))
        .context("loading the beep-ebpf object")?;

    populate_config(&mut ebpf, &geneve_iface, &uplink_iface).context("populating CONFIG map")?;
    populate_fixtures(&mut ebpf, &fixtures, node_ip)
        .context("populating VIP_MAP/TARGET_PORTS/POD_TARGETS fixture")?;

    let hooks: [(&str, &str, TcAttachType); 3] = [
        (
            "uplink_ingress",
            uplink_iface.as_str(),
            TcAttachType::Ingress,
        ),
        (
            "geneve_ingress",
            geneve_iface.as_str(),
            TcAttachType::Ingress,
        ),
        (
            "uplink_egress_return",
            uplink_iface.as_str(),
            TcAttachType::Egress,
        ),
    ];

    for (name, iface, attach_type) in hooks {
        attach_and_pin(&mut ebpf, name, iface, attach_type, &pin_dir)
            .with_context(|| format!("attaching {name} on {iface}"))?;
        eprintln!(
            "attached {name} on {iface} ({attach_type:?}), pinned under {}",
            pin_dir.display()
        );
    }

    eprintln!(
        "all 3 hooks attached; blocking (attachment lives in pinned kernel objects, safe to kill)"
    );
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

/// Resolves the Geneve device's ifindex (unknown until this host's `ip link`
/// state is inspected, so it can't be a compile-time constant in the eBPF
/// program), the uplink's L2 header length (a WireGuard/tun uplink has no
/// Ethernet header, unlike a real NIC/veth -- see `uplink_l2_header_len`'s
/// doc comment), and writes both to the single-entry `CONFIG` map the
/// classifiers read at runtime.
fn populate_config(ebpf: &mut Ebpf, geneve_iface: &str, uplink_iface: &str) -> anyhow::Result<()> {
    let geneve_ifindex = iface_index(geneve_iface)
        .with_context(|| format!("resolving ifindex for {geneve_iface}"))?;
    let uplink_ifindex = iface_index(uplink_iface)
        .with_context(|| format!("resolving ifindex for {uplink_iface}"))?;
    let uplink_arphrd = iface_arphrd_type(uplink_iface)
        .with_context(|| format!("resolving ARPHRD type for {uplink_iface}"))?;
    let uplink_l2_hlen = beep_common::uplink_l2_header_len(uplink_arphrd);
    eprintln!(
        "uplink {uplink_iface}: ARPHRD type {uplink_arphrd}, L2 header skip {uplink_l2_hlen} byte(s)"
    );
    let mut config: AyaArray<_, Config> = AyaArray::try_from(
        ebpf.map_mut("CONFIG")
            .ok_or_else(|| anyhow!("no map named `CONFIG` in the eBPF object"))?,
    )?;
    config.set(
        0,
        Config {
            geneve_ifindex,
            uplink_ifindex,
            uplink_l2_hlen,
        },
        0,
    )?;
    Ok(())
}

/// Reads the uplink's Linux ARPHRD_* hardware type from sysfs -- the no_std
/// `beep-ebpf` classifiers have no syscall of their own to tell a real
/// NIC/veth apart from an L3-only overlay like WireGuard, so the loader
/// resolves it once here and feeds the result to `uplink_l2_header_len`.
fn iface_arphrd_type(name: &str) -> anyhow::Result<u16> {
    let path = format!("/sys/class/net/{name}/type");
    let raw = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
    raw.trim()
        .parse::<u16>()
        .with_context(|| format!("parsing ARPHRD type from {path} (got {raw:?})"))
}

fn iface_index(name: &str) -> anyhow::Result<u32> {
    let c_name = std::ffi::CString::new(name).context("interface name contains a NUL byte")?;
    let ifindex = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if ifindex == 0 {
        return Err(anyhow!(
            "if_nametoindex({name}) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(ifindex)
}

/// Writes one or more static VIP:PORT -> backend-node/PodIP:TargetPort
/// mappings this phase proves the mechanism against (`ebpf-lb-dataplane.md`;
/// real Service/EndpointSlice watching is Phase 5). Every node runs this same
/// loader with the same fixture set: which node ends up playing "ingress" vs
/// "backend" for a given packet is decided by which node the client dialed
/// and where the Pod landed, not by asymmetric per-node config
/// (`docs/decisions/servicelb-ebpf-geneve-dataplane.md`'s node-owned-address
/// model).
///
/// `TARGET_PORTS` is keyed on the same (VIP:PORT:proto) front as `VIP_MAP`,
/// not on pod IP alone: one `--fixture` per Service port, even when several
/// share a backend Pod IP, so a multi-port Service resolves each port to its
/// own target port instead of the last-written one silently winning.
fn fixture_key(fixture: &Fixture) -> VipKey {
    VipKey {
        vip_ip: wire_ip(fixture.vip_ip),
        vip_port: wire_port(fixture.vip_port),
        proto: fixture.proto.as_ip_proto(),
        _pad: 0,
    }
}

fn populate_fixtures(
    ebpf: &mut Ebpf,
    fixtures: &[Fixture],
    node_ip: Ipv4Addr,
) -> anyhow::Result<()> {
    {
        let mut vip_map: AyaHashMap<_, VipKey, VipBackend> = AyaHashMap::try_from(
            ebpf.map_mut("VIP_MAP")
                .ok_or_else(|| anyhow!("no map named `VIP_MAP` in the eBPF object"))?,
        )?;
        for fixture in fixtures {
            vip_map.insert(
                fixture_key(fixture),
                VipBackend {
                    // bpf_tunnel_key.remote_ipv4 is the one field the kernel
                    // itself converts host<->network internally on set/get --
                    // confirmed empirically (a wire-token value here came out
                    // byte-reversed on the wire, e.g. 192.168.109.3 ->
                    // 3.109.168.192): host-native order, unlike every other
                    // address/port field in this crate.
                    backend_node_ip: u32::from(fixture.backend_node_ip),
                    pod_ip: wire_ip(fixture.pod_ip),
                },
                0,
            )?;
        }
    }

    {
        let mut target_ports: AyaHashMap<_, VipKey, u16> = AyaHashMap::try_from(
            ebpf.map_mut("TARGET_PORTS")
                .ok_or_else(|| anyhow!("no map named `TARGET_PORTS` in the eBPF object"))?,
        )?;
        for fixture in fixtures {
            target_ports.insert(fixture_key(fixture), wire_port(fixture.target_port), 0)?;
        }
    }

    {
        // Keyed on pod IP alone, unlike TARGET_PORTS above -- the egress-return
        // gate this feeds (`beep_common::egress_return_admission`), and the
        // decap gate (`beep_common::decap_forward_pod_admission`), check only
        // that a pod is one of THIS node's own backends, deliberately not
        // which port it's replying from. Two fixtures sharing a pod IP (a
        // multi-port Service) collapse to one entry here on purpose:
        // membership doesn't need per-port granularity. Unlike VIP_MAP/
        // TARGET_PORTS above, this map is scoped to `node_ip` via
        // `local_pod_ips`: any node can be ingress for any VIP, but only
        // the node actually running a pod may claim it as a local backend --
        // otherwise both gates' "is this still one of MY pods" check always
        // passes cluster-wide and never drops a misdelivered/drifted packet.
        let mut pod_targets: AyaHashMap<_, u32, u8> = AyaHashMap::try_from(
            ebpf.map_mut("POD_TARGETS")
                .ok_or_else(|| anyhow!("no map named `POD_TARGETS` in the eBPF object"))?,
        )?;
        let local_ips = local_pod_ips(fixtures, node_ip);
        // POD_TARGETS is pinned (`MAP_NAMES`) and so reused, not
        // recreated, across a loader restart with a different `--fixture`
        // set: a Pod that departed since the last run otherwise leaves a
        // stale entry here forever. That used to be harmless (this map was
        // read-only membership metadata), but it now gates
        // `uplink_egress_return`'s drop-on-FLOW_TABLE-reverse-tagged-miss
        // decision -- a stale entry for a departed/reused Pod IP would
        // misclassify unrelated future traffic on that address as "ours"
        // and drop it. Pruned against the same local set this block writes,
        // not the full fixture list, or a pod that moved OFF this node
        // would never be pruned from its former host's POD_TARGETS.
        let existing_ips: Vec<u32> = pod_targets.keys().collect::<Result<_, _>>()?;
        for ip in stale_pod_targets(&existing_ips, &local_ips) {
            pod_targets.remove(&ip)?;
        }
        for pod_ip in &local_ips {
            pod_targets.insert(pod_ip, 1u8, 0)?;
        }
    }

    Ok(())
}

/// Wire-form pod_ips of fixtures THIS node itself backs (`backend_node_ip
/// == node_ip`) -- the `POD_TARGETS` local serving-set, unlike `VIP_MAP`/
/// `TARGET_PORTS` which every node populates identically from the full
/// fixture set since any node can be ingress for any VIP.
fn local_pod_ips(fixtures: &[Fixture], node_ip: Ipv4Addr) -> Vec<u32> {
    fixtures
        .iter()
        .filter(|f| f.backend_node_ip == node_ip)
        .map(|f| wire_ip(f.pod_ip))
        .collect()
}

/// Pod IPs in `existing` (POD_TARGETS's current keys, carried over from a
/// prior loader run against the same pinned map) that `live` (this run's
/// local serving-set, i.e. `local_pod_ips`'s output) no longer claims. Split
/// out of `populate_fixtures` as a pure function so the prune decision is
/// testable without a live eBPF map.
fn stale_pod_targets(existing: &[u32], live: &[u32]) -> Vec<u32> {
    let live: std::collections::HashSet<u32> = live.iter().copied().collect();
    existing
        .iter()
        .copied()
        .filter(|ip| !live.contains(ip))
        .collect()
}

/// Bumps the memlock rlimit for kernels that still account eBPF map memory
/// against it instead of the memcg-based accounting used since Linux 5.11.
fn bump_memlock_rlimit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        eprintln!(
            "warning: setrlimit(RLIMIT_MEMLOCK) failed (harmless on memcg-accounted kernels)"
        );
    }
}

/// Loads and attaches the named classifier at `iface`, pinning its link
/// under `pin_dir` so the attachment survives this process exiting. If a
/// link is already pinned from a prior run, atomically swaps in the freshly
/// loaded program on that same kernel link object instead of creating a
/// second attachment.
fn attach_and_pin(
    ebpf: &mut Ebpf,
    name: &str,
    iface: &str,
    attach_type: TcAttachType,
    pin_dir: &Path,
) -> anyhow::Result<()> {
    // No `tc::qdisc_add_clsact` call: `attach_with_options` below always
    // requests `TcxOrder`, and aya's TCX branch of `do_attach` calls
    // `bpf_link_create` directly -- it never touches (or needs) a clsact
    // qdisc, that's only for the legacy netlink attach path.
    let program: &mut SchedClassifier = ebpf
        .program_mut(name)
        .ok_or_else(|| anyhow!("no program named `{name}` in the eBPF object"))?
        .try_into()?;
    program.load()?;

    // Pin filenames must not contain a literal `.`: this kernel's bpffs
    // rejects `BPF_OBJ_PIN`/`BPF_OBJ_GET` on any path whose final component
    // has a dot with EPERM (verified by bisecting an otherwise-identical
    // repro down to a single `-` vs `.` swap) -- a narrow, surprising
    // constraint worth more investigation, but not a verifier or aya bug.
    let link_pin_path = pin_dir.join(format!("{name}-link"));
    match PinnedLink::from_pin(&link_pin_path) {
        Ok(existing) => {
            // bpf_link_update swaps the target program on the *same* kernel
            // link object referenced by the existing pin file, so the pin
            // file itself needs no changes.
            let link: SchedClassifierLink = FdLink::from(existing).try_into()?;
            program.attach_to_link(link)?;
        }
        Err(LinkError::SyscallError(SyscallError { io_error, .. }))
            if io_error.kind() == std::io::ErrorKind::NotFound =>
        {
            let link_id = program.attach_with_options(
                iface,
                attach_type,
                TcAttachOptions::TcxOrder(LinkOrder::default()),
            )?;
            let link = program.take_link(link_id)?;
            let fd_link: FdLink = link.try_into()?;
            fd_link.pin(&link_pin_path)?;
        }
        Err(e) => return Err(e.into()),
    }

    // Pinning the program itself (separate from the link) is only for
    // `bpftool prog show pinned ...` introspection by name; restart-survival
    // of the attachment depends solely on the link pin above.
    let prog_pin_path = pin_dir.join(format!("{name}-prog"));
    let _ = std::fs::remove_file(&prog_pin_path);
    program.pin(&prog_pin_path)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every checksum update and tunnel-key field the eBPF side touches
    // requires the exact wire byte order (see beep-ebpf's module doc);
    // a regression here silently corrupts every packet this dataplane
    // touches rather than failing loudly, so the round-trip is pinned here.
    #[test]
    fn wire_ip_matches_dotted_octet_order() {
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        assert_eq!(wire_ip(ip).to_le_bytes(), [10, 0, 0, 1]);
    }

    #[test]
    fn wire_port_matches_network_byte_order() {
        // 8080 = 0x1F90; on the wire the high byte (0x1F) comes first.
        assert_eq!(wire_port(8080).to_le_bytes(), [0x1F, 0x90]);
    }

    // A hostNetwork Pod's IP equals its node's IP, i.e. front-IP (VIP)
    // space -- so a VIP placed inside the pod CIDR is not disjoint from
    // pod-IP space by construction, only by configuration, and lets a
    // forward flow key (keyed on the VIP) and a reverse flow key (keyed on
    // a Pod's source IP) byte-collide. These four cases pin the boundary
    // of that rejection exactly at the CIDR's own edges.
    #[test]
    fn vip_inside_pod_cidr_is_rejected() {
        let pod_cidr = parse_ipv4_cidr("10.244.0.0/16").unwrap();
        let vip = Ipv4Addr::new(10, 244, 5, 9);

        let err = vip_outside_pod_cidr(vip, pod_cidr)
            .expect_err("a VIP inside the pod CIDR must be rejected, or it can byte-collide a forward and reverse flow key");
        assert!(
            err.contains("10.244.5.9") && err.contains("10.244.0.0/16"),
            "rejection must name both the offending VIP and the pod CIDR so an operator can fix the config: got `{err}`"
        );
    }

    #[test]
    fn vip_outside_pod_cidr_is_accepted() {
        let pod_cidr = parse_ipv4_cidr("10.244.0.0/16").unwrap();
        // Matches scripts/smoke-remote.sh's RFC 5737 VIP, deliberately
        // disjoint from the pod range -- this is the legitimate-config path
        // that must keep loading.
        let vip = Ipv4Addr::new(203, 0, 113, 1);

        assert!(
            vip_outside_pod_cidr(vip, pod_cidr).is_ok(),
            "a VIP outside the pod CIDR is a legitimate config and must not be rejected"
        );
    }

    #[test]
    fn vip_at_pod_cidr_network_or_broadcast_address_is_rejected() {
        // The network and broadcast addresses are still member addresses of
        // the block (a Pod CAN be assigned either, depending on the CNI),
        // so both boundary values must reject exactly like an interior VIP.
        let pod_cidr = parse_ipv4_cidr("10.244.0.0/16").unwrap();
        assert!(
            vip_outside_pod_cidr(Ipv4Addr::new(10, 244, 0, 0), pod_cidr).is_err(),
            "the pod CIDR's network address is still inside the block and must be rejected"
        );
        assert!(
            vip_outside_pod_cidr(Ipv4Addr::new(10, 244, 255, 255), pod_cidr).is_err(),
            "the pod CIDR's broadcast address is still inside the block and must be rejected"
        );
    }

    #[test]
    fn vip_one_address_outside_pod_cidr_boundary_is_accepted() {
        // The addresses immediately below the network address and above the
        // broadcast address are the tightest legitimate VIPs possible --
        // an off-by-one in the mask calculation would reject these.
        let pod_cidr = parse_ipv4_cidr("10.244.0.0/16").unwrap();
        assert!(
            vip_outside_pod_cidr(Ipv4Addr::new(10, 243, 255, 255), pod_cidr).is_ok(),
            "one address below the pod CIDR's network address must be accepted"
        );
        assert!(
            vip_outside_pod_cidr(Ipv4Addr::new(10, 245, 0, 0), pod_cidr).is_ok(),
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
    fn pod_cidr_slash_zero_rejects_every_vip_as_inside() {
        // A /0 pod CIDR must be treated as "contains every address", so
        // every VIP is rejected. Rust's `<<` masks its shift amount mod 32,
        // so deleting the `prefix_len == 0` special case in `Ipv4Cidr::mask`
        // would make `u32::MAX << 32` silently wrap to `u32::MAX << 0`,
        // turning "match everything" into "match only the exact network
        // address" -- this VIP (not equal to the network address) would then
        // wrongly be accepted instead of rejected.
        let pod_cidr = parse_ipv4_cidr("0.0.0.0/0").unwrap();
        assert!(
            vip_outside_pod_cidr(Ipv4Addr::new(203, 0, 113, 1), pod_cidr).is_err(),
            "a /0 pod CIDR spans the entire address space, so every VIP must be rejected"
        );
    }

    #[test]
    fn pod_cidr_slash_32_rejects_only_the_exact_address() {
        // A /32 pod CIDR is a single host route: it must reject a VIP equal
        // to that address, but accept every other address. An off-by-one in
        // the mask shift (e.g. treating 32 like 0, or vice versa) would
        // either widen this to reject everything or narrow it to reject
        // nothing.
        let pod_cidr = parse_ipv4_cidr("10.244.5.9/32").unwrap();
        assert!(
            vip_outside_pod_cidr(Ipv4Addr::new(10, 244, 5, 9), pod_cidr).is_err(),
            "a VIP equal to the /32 pod CIDR's single address must be rejected"
        );
        assert!(
            vip_outside_pod_cidr(Ipv4Addr::new(10, 244, 5, 10), pod_cidr).is_ok(),
            "a VIP one address away from a /32 pod CIDR must be accepted"
        );
    }

    #[test]
    fn parse_ipv4_cidr_stores_canonical_network_address() {
        // Operators read this address back out of error/Display text when a
        // VIP is rejected; if host bits leak through unmasked, that message
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

    #[test]
    fn two_service_ports_on_one_pod_route_to_distinct_target_ports() {
        // A plain multi-port Service (e.g. 80->8080 alongside 443->8443 on
        // the SAME Pod) needs each Service port to resolve its own target
        // port independently. The pre-fix `POD_TARGETS: HashMap<u32, u16>`
        // keyed only on pod IP, so both fixtures collapsed into ONE entry --
        // whichever `--fixture` was populated last silently won, and the
        // other Service port's traffic got mis-DNATed to the wrong
        // container port.
        use std::collections::HashMap;

        let pod_ip = Ipv4Addr::new(10, 244, 1, 7);
        let fixtures = [
            parse_fixture("10.0.0.5:80:tcp:10.0.0.6:10.244.1.7:8080").unwrap(),
            parse_fixture("10.0.0.5:443:tcp:10.0.0.6:10.244.1.7:8443").unwrap(),
        ];
        assert_eq!(
            (fixtures[0].pod_ip, fixtures[1].pod_ip),
            (pod_ip, pod_ip),
            "fixture invariant: both entries must share one Pod IP to exercise the bug"
        );

        // Simulates `TARGET_PORTS`: keyed on the front tuple, exactly like
        // `populate_fixtures`/`try_geneve_decap_forward`.
        let mut target_ports: HashMap<VipKey, u16> = HashMap::new();
        for f in &fixtures {
            target_ports.insert(fixture_key(f), wire_port(f.target_port));
        }
        assert_eq!(
            target_ports.len(),
            2,
            "two distinct Service ports on one Pod must produce two distinct \
             TARGET_PORTS entries, not collapse into one"
        );
        for f in &fixtures {
            assert_eq!(
                target_ports.get(&fixture_key(f)).copied(),
                Some(wire_port(f.target_port)),
                "VIP port {} must resolve to its own target port {}, not the \
                 other Service port's",
                f.vip_port,
                f.target_port
            );
        }

        // The bug this closes, made concrete: keying on pod IP alone cannot
        // represent this at all -- both fixtures collapse to the same entry.
        let mut old_pod_targets: HashMap<u32, u16> = HashMap::new();
        for f in &fixtures {
            old_pod_targets.insert(wire_ip(f.pod_ip), wire_port(f.target_port));
        }
        assert_eq!(
            old_pod_targets.len(),
            1,
            "this demonstrates why pod-IP-only keying was insufficient -- \
             both Service ports collapse to the same map key"
        );
    }

    #[test]
    fn pod_targets_excludes_pods_backed_by_a_different_node() {
        // POD_TARGETS is the LOCAL serving-set the decap
        // (`decap_forward_pod_admission`) and egress-return
        // (`egress_return_admission`) gates check to answer "is this pod
        // still one of MY backends" -- before this fix, `populate_fixtures`
        // wrote every `--fixture`'s pod_ip into POD_TARGETS on every node
        // regardless of `backend_node_ip`, so both gates' membership check
        // always passed cluster-wide and never caught a misdelivered or
        // drifted packet. If `local_pod_ips` regresses to node-blind
        // filtering, this must fail by including the non-local pod.
        let node_ip = Ipv4Addr::new(10, 0, 0, 6);
        let other_node_ip = Ipv4Addr::new(10, 0, 0, 7);
        let local_fixture = parse_fixture("10.0.0.5:80:tcp:10.0.0.6:10.244.1.7:8080").unwrap();
        let remote_fixture = parse_fixture("10.0.0.5:81:tcp:10.0.0.7:10.244.1.8:8081").unwrap();
        assert_eq!(local_fixture.backend_node_ip, node_ip);
        assert_eq!(remote_fixture.backend_node_ip, other_node_ip);
        let fixtures = [local_fixture, remote_fixture];

        assert_eq!(
            local_pod_ips(&fixtures, node_ip),
            vec![wire_ip(local_fixture.pod_ip)],
            "POD_TARGETS must contain only pods this node's own fixtures back \
             (backend_node_ip == node_ip) -- a pod backed by a different node \
             must never appear, or the decap/egress-return membership gates \
             pass traffic for pods that don't actually live here"
        );
    }

    #[test]
    fn departed_pod_ip_is_pruned_from_pod_targets() {
        // POD_TARGETS is pinned and reused across loader restarts, so a Pod
        // absent from the fresh `--fixture` set is one that's gone away.
        // uplink_egress_return now DROPS on a POD_TARGETS hit with no
        // matching FLOW_TABLE reverse-tagged entry -- an unpruned stale
        // entry would misclassify unrelated traffic that later reuses this
        // address as "ours" and drop it instead of passing it through.
        let departed_pod_ip = wire_ip(Ipv4Addr::new(10, 244, 1, 9));
        let existing = [departed_pod_ip];
        let live: [u32; 0] = [];

        assert_eq!(
            stale_pod_targets(&existing, &live),
            vec![departed_pod_ip],
            "a pod absent from the new fixture set must be pruned from \
             POD_TARGETS, or egress traffic from a future, unrelated owner \
             of that IP gets dropped instead of passed"
        );
    }

    #[test]
    fn live_pod_ip_is_not_pruned_from_pod_targets() {
        // The other side of the same guarantee: a Pod still present in the
        // fixture set must survive the prune, or every reconcile would
        // drop live backends' own egress-return admission.
        let fixture = parse_fixture("10.0.0.5:80:tcp:10.0.0.6:10.244.1.7:8080").unwrap();
        let live = [wire_ip(fixture.pod_ip)];

        assert!(
            stale_pod_targets(&live, &live).is_empty(),
            "a pod still claimed by the local serving-set must not be pruned from POD_TARGETS"
        );
    }
}
