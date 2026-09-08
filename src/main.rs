//! Phase 2 ServiceLB eBPF dataplane loader: loads the three tc-bpf
//! classifiers from `servicelb-ebpf` (`uplink_ingress`, `geneve_ingress`,
//! `uplink_egress_return` -- Phase 1's separate `geneve_ingress_decap`/
//! `geneve_ingress_return` merged into one, see that program's doc comment),
//! attaches each at its hook point
//! (`ai/extended-context/ebpf-lb-dataplane.md`), populates one or more static
//! VIP:PORT -> backend fixture entries this phase proves the mechanism
//! against (repeatable so one Pod behind more than one Service port is
//! expressible -- `servicelb-ebpf`'s `TARGET_PORTS` keys on the front tuple,
//! not pod IP alone, precisely so this doesn't collide), and pins the
//! resulting links AND maps under a bpffs directory so a loader restart
//! re-adopts the existing attachment instead of leaving the interface
//! unprotected or double-attaching, and REUSES the existing `FWD_PENDING`/
//! `FWD_MAIN`/`REV_FLOW` conntrack tables instead of swapping in an empty
//! set -- `Ebpf::load` alone creates a fresh map set on every call, which
//! would silently drop every established flow on each DaemonSet rollout,
//! eviction, or OOM kill. Real Service/EndpointSlice watching is Phase 5.
//!
//! `FWD_PENDING`/`FWD_MAIN` sizes are a load-time DaemonSet config knob, not
//! a value baked into the eBPF object (`servicelb-ebpf`'s admission-control
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

// Every map `servicelb-ebpf` declares (`servicelb-ebpf/src/main.rs`'s
// `#[map]` statics). Pinned by name below so a loader restart reuses them
// instead of `Ebpf::load` creating an empty set -- an omission here silently
// drops that map's state on every restart with no build-time signal.
const MAP_NAMES: [&str; 7] = [
    "CONFIG",
    "VIP_MAP",
    "TARGET_PORTS",
    "POD_TARGETS",
    "FWD_PENDING",
    "FWD_MAIN",
    "REV_FLOW",
];

/// Defaults from the admission-control sizing derivation
/// (`servicelb-ebpf`'s `FWD_PENDING`/`FWD_MAIN` doc comment): PENDING is the
/// only flood-exposed tier, sized to peak concurrent half-open connections
/// with headroom; MAIN is sized to peak legitimate established concurrency,
/// a valid basis only because admission control keeps it unreachable by a
/// flood.
const DEFAULT_FWD_PENDING_MAX_ENTRIES: u32 = 2048;
const DEFAULT_FWD_MAIN_MAX_ENTRIES: u32 = 8192;

#[derive(Parser, Debug)]
#[command(
    name = "u7s-servicelb",
    about = "Phase 2 ServiceLB eBPF loader: Geneve encap/decap, single-flow happy path"
)]
struct Args {
    /// Physical uplink interface (hooks: uplink ingress, uplink egress-return).
    #[arg(long, default_value = "eth0")]
    uplink_iface: String,

    /// Geneve tunnel interface (hook: geneve ingress, both directions).
    #[arg(long, default_value = "geneve0")]
    geneve_iface: String,

    /// Directory on a bpffs mount where programs/links are pinned.
    #[arg(long, default_value = "/sys/fs/bpf/servicelb")]
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

    /// `FWD_PENDING` max_entries -- the only flood-exposed conntrack tier
    /// (admission control mints every new flow here; see `servicelb-ebpf`'s
    /// `FWD_PENDING` doc comment). A load-time DaemonSet config knob, not a
    /// value baked into the eBPF object.
    #[arg(long, default_value_t = DEFAULT_FWD_PENDING_MAX_ENTRIES)]
    fwd_pending_max_entries: u32,

    /// `FWD_MAIN` max_entries -- reachable only via a flow's promoted (i.e.
    /// bidirectionally-confirmed) conntrack entry, sized to legitimate peak
    /// established concurrency.
    #[arg(long, default_value_t = DEFAULT_FWD_MAIN_MAX_ENTRIES)]
    fwd_main_max_entries: u32,
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

/// Converts a host-order value into the "raw wire token" representation the
/// eBPF side compares packet bytes against verbatim (see
/// `servicelb-ebpf/src/main.rs`'s module doc for why this conversion exists
/// and why it's applied exactly once, here, at the map-population boundary).
fn wire_ip(ip: Ipv4Addr) -> u32 {
    u32::from(ip).to_be()
}

fn wire_port(port: u16) -> u16 {
    port.to_be()
}

// Byte-layout-identical to servicelb-ebpf's types of the same name -- the
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
    // Field order/types must mirror `servicelb-ebpf`'s `Config` exactly --
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
        fwd_pending_max_entries,
        fwd_main_max_entries,
    } = Args::parse();

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
    loader.map_max_entries("FWD_MAIN", fwd_main_max_entries);
    let mut ebpf = loader
        .load(include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/servicelb-ebpf"
        )))
        .context("loading the servicelb-ebpf object")?;

    populate_config(&mut ebpf, &geneve_iface, &uplink_iface).context("populating CONFIG map")?;
    populate_fixtures(&mut ebpf, &fixtures).context("populating VIP_MAP/TARGET_PORTS fixture")?;

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
    let uplink_l2_hlen = u7s_servicelb_common::uplink_l2_header_len(uplink_arphrd);
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
/// `servicelb-ebpf` classifiers have no syscall of their own to tell a real
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

fn populate_fixtures(ebpf: &mut Ebpf, fixtures: &[Fixture]) -> anyhow::Result<()> {
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
        // gate this feeds (`u7s_servicelb_common::egress_return_admission`)
        // checks only that a packet's source is one of this node's backend
        // Pods, deliberately not which port it's replying from. Two fixtures
        // sharing a pod IP (a multi-port Service) collapse to one entry here
        // on purpose: membership doesn't need per-port granularity.
        let mut pod_targets: AyaHashMap<_, u32, u8> = AyaHashMap::try_from(
            ebpf.map_mut("POD_TARGETS")
                .ok_or_else(|| anyhow!("no map named `POD_TARGETS` in the eBPF object"))?,
        )?;
        // POD_TARGETS is pinned (`MAP_NAMES`) and so reused, not
        // recreated, across a loader restart with a different `--fixture`
        // set: a Pod that departed since the last run otherwise leaves a
        // stale entry here forever. That used to be harmless (this map was
        // read-only membership metadata), but it now gates
        // `uplink_egress_return`'s drop-on-REV_FLOW-miss decision -- a
        // stale entry for a departed/reused Pod IP would misclassify
        // unrelated future traffic on that address as "ours" and drop it.
        // Prune anything the fresh fixture set no longer claims before
        // writing it.
        let existing_ips: Vec<u32> = pod_targets.keys().collect::<Result<_, _>>()?;
        for ip in stale_pod_targets(&existing_ips, fixtures) {
            pod_targets.remove(&ip)?;
        }
        for fixture in fixtures {
            pod_targets.insert(wire_ip(fixture.pod_ip), 1u8, 0)?;
        }
    }

    Ok(())
}

/// Pod IPs in `existing` (POD_TARGETS's current keys, carried over from a
/// prior loader run against the same pinned map) that no fixture in the
/// fresh `fixtures` set claims any more. Split out of `populate_fixtures`
/// as a pure function so the prune decision is testable without a live
/// eBPF map.
fn stale_pod_targets(existing: &[u32], fixtures: &[Fixture]) -> Vec<u32> {
    let live: std::collections::HashSet<u32> = fixtures.iter().map(|f| wire_ip(f.pod_ip)).collect();
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
    // requires the exact wire byte order (see servicelb-ebpf's module doc);
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
    fn departed_pod_ip_is_pruned_from_pod_targets() {
        // POD_TARGETS is pinned and reused across loader restarts, so a Pod
        // absent from the fresh `--fixture` set is one that's gone away.
        // uplink_egress_return now DROPS on a POD_TARGETS hit with no
        // matching REV_FLOW entry -- an unpruned stale entry would
        // misclassify unrelated traffic that later reuses this address as
        // "ours" and drop it instead of passing it through.
        let departed_pod_ip = wire_ip(Ipv4Addr::new(10, 244, 1, 9));
        let existing = [departed_pod_ip];
        let fixtures: [Fixture; 0] = [];

        assert_eq!(
            stale_pod_targets(&existing, &fixtures),
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
        let existing = [wire_ip(fixture.pod_ip)];

        assert!(
            stale_pod_targets(&existing, &[fixture]).is_empty(),
            "a pod still claimed by the fixture set must not be pruned from POD_TARGETS"
        );
    }
}
