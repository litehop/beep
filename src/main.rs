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
//! unprotected or double-attaching, and REUSES the existing `FWD_FLOW`/
//! `REV_FLOW` conntrack tables instead of swapping in an empty pair --
//! `Ebpf::load` alone creates a fresh map set on every call, which would
//! silently drop every established flow on each DaemonSet rollout, eviction,
//! or OOM kill. Real Service/EndpointSlice watching is Phase 5.

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
const MAP_NAMES: [&str; 5] = ["CONFIG", "VIP_MAP", "TARGET_PORTS", "FWD_FLOW", "REV_FLOW"];

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
}
unsafe impl Pod for Config {}

fn main() -> anyhow::Result<()> {
    let Args {
        uplink_iface,
        geneve_iface,
        pin_dir,
        fixtures,
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
/// program) and writes it to the single-entry `CONFIG` map both redirecting
/// classifiers read at runtime.
fn populate_config(ebpf: &mut Ebpf, geneve_iface: &str, uplink_iface: &str) -> anyhow::Result<()> {
    let geneve_ifindex = iface_index(geneve_iface)
        .with_context(|| format!("resolving ifindex for {geneve_iface}"))?;
    let uplink_ifindex = iface_index(uplink_iface)
        .with_context(|| format!("resolving ifindex for {uplink_iface}"))?;
    let mut config: AyaArray<_, Config> = AyaArray::try_from(
        ebpf.map_mut("CONFIG")
            .ok_or_else(|| anyhow!("no map named `CONFIG` in the eBPF object"))?,
    )?;
    config.set(
        0,
        Config {
            geneve_ifindex,
            uplink_ifindex,
        },
        0,
    )?;
    Ok(())
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

    Ok(())
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
}
