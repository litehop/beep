//! Reusable attach/pin/config logic behind the `beep` eBPF loader's
//! hard-won invariants -- extracted out of the `beep` binary (`src/main.rs`)
//! into this library target so a future control-plane binary (Phase 5's
//! Service/EndpointSlice watcher) reuses it instead of re-deriving the same
//! invariants from scratch: the `drop(ebpf)` restart-branch detach, pin
//! reuse across a loader restart, the dot-in-filename EPERM avoidance in
//! link pin paths, and map-reopen-from-pin.

use std::{net::Ipv4Addr, path::Path};

use anyhow::{anyhow, Context};
use aya::{
    maps::Array as AyaArray,
    programs::{
        links::{FdLink, LinkError, PinnedLink},
        tc::{SchedClassifierLink, TcAttachOptions},
        LinkOrder, SchedClassifier, TcAttachType,
    },
    sys::SyscallError,
    Ebpf,
};
use beep_common::{wire_ip, Config};
use clap::ValueEnum;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

// Every map `beep-ebpf` declares (`ebpf/src/main.rs`'s
// `#[map]` statics). Pinned by name below so a loader restart reuses them
// instead of `Ebpf::load` creating an empty set -- an omission here silently
// drops that map's state on every restart with no build-time signal.
pub const MAP_NAMES: [&str; 6] = [
    "CONFIG",
    "VIP_MAP",
    "TARGET_PORTS",
    "POD_TARGETS",
    "FWD_PENDING",
    "FLOW_TABLE",
];

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_ip_proto(self) -> u8 {
        match self {
            Proto::Tcp => IPPROTO_TCP,
            Proto::Udp => IPPROTO_UDP,
        }
    }
}

/// One VIP:PORT -> backend-node/PodIP:TargetPort fixture entry (see the
/// `--fixture` CLI flag's doc comment in `src/main.rs` for the full field
/// semantics). Lives here, not in the binary, because `local_pod_ips`'s
/// signature and its tests need the type.
#[derive(Clone, Copy, Debug)]
pub struct Fixture {
    pub vip_ip: Ipv4Addr,
    pub vip_port: u16,
    pub proto: Proto,
    pub backend_node_ip: Ipv4Addr,
    pub pod_ip: Ipv4Addr,
    pub target_port: u16,
}

pub fn parse_fixture(s: &str) -> Result<Fixture, String> {
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

/// Wire-form pod_ips of fixtures THIS node itself backs (`backend_node_ip
/// == node_ip`) -- the `POD_TARGETS` local serving-set, unlike `VIP_MAP`/
/// `TARGET_PORTS` which every node populates identically from the full
/// fixture set since any node can be ingress for any VIP.
pub fn local_pod_ips(fixtures: &[Fixture], node_ip: Ipv4Addr) -> Vec<u32> {
    fixtures
        .iter()
        .filter(|f| f.backend_node_ip == node_ip)
        .map(|f| wire_ip(u32::from(f.pod_ip)))
        .collect()
}

/// Pod IPs in `existing` (POD_TARGETS's current keys, carried over from a
/// prior loader run against the same pinned map) that `live` (this run's
/// local serving-set, i.e. `local_pod_ips`'s output) no longer claims. Split
/// out of `populate_fixtures` as a pure function so the prune decision is
/// testable without a live eBPF map.
pub fn stale_pod_targets(existing: &[u32], live: &[u32]) -> Vec<u32> {
    let live: std::collections::HashSet<u32> = live.iter().copied().collect();
    existing
        .iter()
        .copied()
        .filter(|ip| !live.contains(ip))
        .collect()
}

/// Bumps the memlock rlimit for kernels that still account eBPF map memory
/// against it instead of the memcg-based accounting used since Linux 5.11.
pub fn bump_memlock_rlimit() {
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

/// Reads the uplink's Linux ARPHRD_* hardware type from sysfs -- the no_std
/// `beep-ebpf` classifiers have no syscall of their own to tell a real
/// NIC/veth apart from an L3-only overlay like WireGuard, so the loader
/// resolves it once here and feeds the result to `uplink_l2_header_len`.
pub fn iface_arphrd_type(name: &str) -> anyhow::Result<u16> {
    let path = format!("/sys/class/net/{name}/type");
    let raw = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
    raw.trim()
        .parse::<u16>()
        .with_context(|| format!("parsing ARPHRD type from {path} (got {raw:?})"))
}

pub fn iface_index(name: &str) -> anyhow::Result<u32> {
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

/// Resolves the Geneve device's ifindex (unknown until this host's `ip link`
/// state is inspected, so it can't be a compile-time constant in the eBPF
/// program), the uplink's L2 header length (a WireGuard/tun uplink has no
/// Ethernet header, unlike a real NIC/veth -- see `uplink_l2_header_len`'s
/// doc comment), and writes both to the single-entry `CONFIG` map the
/// classifiers read at runtime.
pub fn populate_config(
    ebpf: &mut Ebpf,
    geneve_iface: &str,
    uplink_iface: &str,
) -> anyhow::Result<()> {
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

/// Loads and attaches the named classifier at `iface`, pinning its link
/// under `pin_dir` so the attachment survives this process exiting. If a
/// link is already pinned from a prior run, atomically swaps in the freshly
/// loaded program on that same kernel link object instead of creating a
/// second attachment.
pub fn attach_and_pin(
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
            vec![wire_ip(u32::from(local_fixture.pod_ip))],
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
        let departed_pod_ip = wire_ip(u32::from(Ipv4Addr::new(10, 244, 1, 9)));
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
        let live = [wire_ip(u32::from(fixture.pod_ip))];

        assert!(
            stale_pod_targets(&live, &live).is_empty(),
            "a pod still claimed by the local serving-set must not be pruned from POD_TARGETS"
        );
    }
}
