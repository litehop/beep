//! Phase 2 ServiceLB eBPF dataplane loader: loads the three tc-bpf
//! classifiers from `servicelb-ebpf` (`uplink_ingress`, `geneve_ingress`,
//! `uplink_egress_return` -- Phase 1's separate `geneve_ingress_decap`/
//! `geneve_ingress_return` merged into one, see that program's doc comment),
//! attaches each at its hook point
//! (`ai/extended-context/ebpf-lb-dataplane.md`), populates the one static
//! VIP:PORT -> backend fixture this phase proves the mechanism against, and
//! pins the resulting links under a bpffs directory so a loader restart
//! re-adopts the existing attachment instead of leaving the interface
//! unprotected or double-attaching. Real Service/EndpointSlice watching is
//! Phase 5.

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
    Ebpf, Pod,
};
use clap::{Parser, ValueEnum};

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

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

    /// VIP address this node accepts Service traffic on (its own node IP
    /// in the node-owned-address model, `ebpf-lb-dataplane.md`).
    #[arg(long)]
    vip_ip: Ipv4Addr,

    /// VIP port.
    #[arg(long)]
    vip_port: u16,

    /// Protocol for the fixture VIP:PORT mapping.
    #[arg(long, value_enum, default_value_t = Proto::Tcp)]
    proto: Proto,

    /// Node hosting the chosen backend Pod (Geneve remote for the forward leg).
    #[arg(long)]
    backend_node_ip: Ipv4Addr,

    /// Backend Pod IP (stamped as the forward-leg Geneve pod-identifier option).
    #[arg(long)]
    pod_ip: Ipv4Addr,

    /// Pod's container port the Service targets.
    #[arg(long)]
    target_port: u16,
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
#[derive(Clone, Copy)]
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
        vip_ip,
        vip_port,
        proto,
        backend_node_ip,
        pod_ip,
        target_port,
    } = Args::parse();

    bump_memlock_rlimit();

    let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/servicelb-ebpf"
    )))
    .context("loading the servicelb-ebpf object")?;

    std::fs::create_dir_all(&pin_dir)
        .with_context(|| format!("creating pin dir {}", pin_dir.display()))?;

    populate_config(&mut ebpf, &geneve_iface, &uplink_iface).context("populating CONFIG map")?;
    populate_fixture(
        &mut ebpf,
        vip_ip,
        vip_port,
        proto,
        backend_node_ip,
        pod_ip,
        target_port,
    )
    .context("populating VIP_MAP/POD_TARGETS fixture")?;

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

/// Writes the one static VIP:PORT -> backend-node/PodIP:TargetPort mapping
/// this phase proves the mechanism against (`ebpf-lb-dataplane.md`; real
/// Service/EndpointSlice watching is Phase 5). Every node runs this same
/// loader with the same fixture: which node ends up playing "ingress" vs
/// "backend" for a given packet is decided by which node the client dialed
/// and where the Pod landed, not by asymmetric per-node config
/// (`docs/decisions/servicelb-ebpf-geneve-dataplane.md`'s node-owned-address
/// model).
fn populate_fixture(
    ebpf: &mut Ebpf,
    vip_ip: Ipv4Addr,
    vip_port: u16,
    proto: Proto,
    backend_node_ip: Ipv4Addr,
    pod_ip: Ipv4Addr,
    target_port: u16,
) -> anyhow::Result<()> {
    let mut vip_map: AyaHashMap<_, VipKey, VipBackend> = AyaHashMap::try_from(
        ebpf.map_mut("VIP_MAP")
            .ok_or_else(|| anyhow!("no map named `VIP_MAP` in the eBPF object"))?,
    )?;
    vip_map.insert(
        VipKey {
            vip_ip: wire_ip(vip_ip),
            vip_port: wire_port(vip_port),
            proto: proto.as_ip_proto(),
            _pad: 0,
        },
        VipBackend {
            // bpf_tunnel_key.remote_ipv4 is the one field the kernel itself
            // converts host<->network internally on set/get -- confirmed
            // empirically (a wire-token value here came out byte-reversed
            // on the wire, e.g. 192.168.109.3 -> 3.109.168.192): host-native
            // order, unlike every other address/port field in this crate.
            backend_node_ip: u32::from(backend_node_ip),
            pod_ip: wire_ip(pod_ip),
        },
        0,
    )?;

    let mut pod_targets: AyaHashMap<_, u32, u16> = AyaHashMap::try_from(
        ebpf.map_mut("POD_TARGETS")
            .ok_or_else(|| anyhow!("no map named `POD_TARGETS` in the eBPF object"))?,
    )?;
    pod_targets.insert(wire_ip(pod_ip), wire_port(target_port), 0)?;

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
}
