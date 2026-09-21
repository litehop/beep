//! Reusable attach/pin/config logic behind the `beep` eBPF loader's
//! hard-won invariants -- extracted out of the `beep` binary (`src/main.rs`)
//! into this library target so a future control-plane binary (Phase 5's
//! Service/EndpointSlice watcher) reuses it instead of re-deriving the same
//! invariants from scratch: the `drop(ebpf)` restart-branch detach, pin
//! reuse across a loader restart, the dot-in-filename EPERM avoidance in
//! link pin paths, and map-reopen-from-pin.

use std::{net::IpAddr, path::Path};

use anyhow::{anyhow, Context};
use aya::{
    include_bytes_aligned,
    maps::{Array as AyaArray, HashMap as AyaHashMap, MapData},
    programs::{
        links::{FdLink, LinkError, PinnedLink},
        tc::{SchedClassifierLink, TcAttachOptions},
        LinkOrder, SchedClassifier, TcAttachType,
    },
    sys::SyscallError,
    Ebpf, EbpfLoader,
};
use beep_common::{
    decode_tcp_flow_key, ipv4_mapped_v6, wire_ip, Config, FlowDirection, FlowKey, FlowValue,
    ForwardFlowValue, TcpFlowKey, UplinkConfig, TCP_FLOW_KEY_LEN,
};
use clap::ValueEnum;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

// Every map `beep-ebpf` declares (`ebpf/src/main.rs`'s
// `#[map]` statics). Pinned by name below so a loader restart reuses them
// instead of `Ebpf::load` creating an empty set -- an omission here silently
// drops that map's state on every restart with no build-time signal.
pub const MAP_NAMES: [&str; 8] = [
    "CONFIG",
    "UPLINK_CONFIG",
    "LB_FRONT_MAP",
    "TARGET_PORTS",
    "POD_TARGETS",
    "NODE_ALLOW",
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
///
/// Address fields are `IpAddr`, not `Ipv4Addr`: a Service and its backend
/// Pod can each independently be IPv4 or IPv6 (`beep-ebpf`'s dual-stack
/// inner-packet parsing), so the fixture format itself must not assume one
/// family. `wire_ip_v6`/`tunnel_remote_v6` below widen a parsed field into
/// the `[u8; 16]` shape the maps store, picking the convention (wire-token
/// vs. `bpf_tunnel_key`-native) that field's map actually uses.
#[derive(Clone, Copy, Debug)]
pub struct Fixture {
    pub vip_ip: IpAddr,
    pub vip_port: u16,
    pub proto: Proto,
    pub backend_node_ip: IpAddr,
    pub pod_ip: IpAddr,
    pub target_port: u16,
}

/// Widens a *wire-token* address field (`Fixture::vip_ip`/`pod_ip`) into
/// `beep_common`'s dual-stack `[u8; 16]` shape: a v4 address goes through
/// `wire_ip` + `ipv4_mapped_v6`, exactly the embedding `beep-ebpf`'s inner-
/// packet parsing produces for a real v4 packet; a v6 address's own octets
/// already ARE that same wire representation (an IPv6 address has no
/// separate host-order form the way a v4 address's `u32` does), so no
/// conversion beyond `Ipv6Addr::octets()` is needed.
pub fn wire_ip_v6(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => ipv4_mapped_v6(wire_ip(u32::from(v4))),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// Widens a Geneve tunnel-remote address field (`Fixture::backend_node_ip`,
/// and `--node-ip` for `NODE_ALLOW`) into the same `[u8; 16]` shape, but in
/// `bpf_tunnel_key.remote_ipv4`'s host-native convention for a v4 address
/// (confirmed empirically against a live kernel -- see `ebpf/src/main.rs`'s
/// module doc) rather than `wire_ip_v6`'s wire-token one. A v6 address has
/// no such host/wire distinction, so this is identical to `wire_ip_v6`'s v6
/// arm.
pub fn tunnel_remote_v6(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => ipv4_mapped_v6(u32::from(v4)),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// Splits a `--fixture` string on top-level `:` delimiters, treating a
/// bracketed `[...]` span as one token -- the same convention `SocketAddr`'s
/// own `Display`/`FromStr` uses to disambiguate a literal IPv6 address's own
/// internal `:` characters from the fixture format's field separators.
fn split_fixture_fields(s: &str) -> Vec<&str> {
    let mut fields = Vec::new();
    let mut rest = s;
    while !rest.is_empty() {
        let (field, remainder) = if let Some(after_bracket) = rest.strip_prefix('[') {
            match after_bracket.find(']') {
                Some(end) => {
                    let after = &after_bracket[end + 1..];
                    (
                        &after_bracket[..end],
                        after.strip_prefix(':').unwrap_or(after),
                    )
                }
                None => (rest, ""),
            }
        } else if let Some(i) = rest.find(':') {
            (&rest[..i], &rest[i + 1..])
        } else {
            (rest, "")
        };
        fields.push(field);
        rest = remainder;
    }
    fields
}

pub fn parse_fixture(s: &str) -> Result<Fixture, String> {
    let parts = split_fixture_fields(s);
    let [vip_ip, vip_port, proto, backend_node_ip, pod_ip, target_port] = parts.as_slice() else {
        return Err(format!(
            "expected vip_ip:vip_port:proto:backend_node_ip:pod_ip:target_port (bracket an IPv6 \
             address, e.g. `[2001:db8::1]`), got `{s}`"
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
/// == node_ip`) -- the `POD_TARGETS` local serving-set, unlike `LB_FRONT_MAP`/
/// `TARGET_PORTS` which every node populates identically from the full
/// fixture set since any node can be ingress for any VIP. `node_ip`'s family
/// need not match every fixture's `backend_node_ip`; `IpAddr`'s `PartialEq`
/// already treats a v4 and a v6 address as unequal regardless of numeric
/// value, so a cross-family fixture is correctly excluded rather than
/// spuriously matched.
pub fn local_pod_ips(fixtures: &[Fixture], node_ip: IpAddr) -> Vec<[u8; 16]> {
    fixtures
        .iter()
        .filter(|f| f.backend_node_ip == node_ip)
        .map(|f| wire_ip_v6(f.pod_ip))
        .collect()
}

/// Keys in `existing` (a map's current contents, carried over from a prior
/// loader/controller run against the same pinned map) that `live` (this
/// run's desired set) no longer claims. Split out of `populate_fixtures` as
/// a pure function so the prune decision is testable without a live eBPF
/// map. Generic over the key type (`[u8; 16]` for both `POD_TARGETS` and
/// `NODE_ALLOW`) rather than duplicated per map: both are the identical
/// prune-then-insert set diff.
pub fn stale_pod_targets<T: Copy + Eq + std::hash::Hash>(existing: &[T], live: &[T]) -> Vec<T> {
    let live: std::collections::HashSet<T> = live.iter().copied().collect();
    existing
        .iter()
        .copied()
        .filter(|ip| !live.contains(ip))
        .collect()
}

/// A `FLOW_TABLE` key's own `FlowDirection` tag byte (`FlowKey`'s last byte,
/// `beep_common::encode_flow_key`'s doc comment), or `None` for a tag value
/// `beep-ebpf` never writes. Callers MUST branch on this before reading
/// either the key (Reverse/PortMemo) or the value's union arm (Forward) --
/// `FlowValue::as_forward`/`as_reverse`/`as_port_memo` are unchecked reads
/// (`beep_common`'s own doc comment on `FlowValue`) that silently return
/// garbage for the wrong arm instead of erroring.
pub fn flow_key_direction(key: &FlowKey) -> Option<FlowDirection> {
    match key[TCP_FLOW_KEY_LEN] {
        x if x == FlowDirection::Forward as u8 => Some(FlowDirection::Forward),
        x if x == FlowDirection::Reverse as u8 => Some(FlowDirection::Reverse),
        x if x == FlowDirection::PortMemo as u8 => Some(FlowDirection::PortMemo),
        _ => None,
    }
}

/// Forward-role rows (`FWD_PENDING` entries, or `FLOW_TABLE` rows the caller
/// has already confirmed are `FlowDirection::Forward`-tagged via
/// `flow_key_direction` and read with `FlowValue::as_forward`) whose backend
/// points at `departed_pod` -- the eviction sweep's Forward case. Forward is
/// the ONLY role where pod identity lives in the VALUE rather than the key: the
/// key is `(client, VIP, proto)`, which never carries pod identity at all.
/// Generic over `K` so the identical filter serves both `FWD_PENDING`'s
/// `TcpFlowKey` and `FLOW_TABLE`'s wider `FlowKey`.
pub fn stale_forward_entries<K: Copy>(
    entries: &[(K, ForwardFlowValue)],
    departed_pod: [u8; 16],
) -> Vec<K> {
    entries
        .iter()
        .filter(|(_, value)| value.backend.pod_ip == departed_pod)
        .map(|(key, _)| *key)
        .collect()
}

/// `FLOW_TABLE` keys tagged `Reverse` or `PortMemo` whose key embeds
/// `departed_pod` in bytes 16..32 (`decode_tcp_flow_key`'s `other_ip`) --
/// the eviction sweep's Reverse/PortMemo case. Both roles key on
/// `(client, ..., pod_ip, ...)`, the exact opposite of Forward's value-based
/// match above, and share this identical match: PortMemo's key shape is
/// Reverse's own (`common/src/lib.rs`'s `PortMemo` doc comment), so a stale
/// memo for a reused pod IP is the same misrouting hazard a stale reverse
/// entry is. Caller must pass only already tag-filtered keys (via
/// `flow_key_direction`) -- this function does not itself check the tag.
pub fn stale_flow_table_keys(keys: &[FlowKey], departed_pod: [u8; 16]) -> Vec<FlowKey> {
    keys.iter()
        .copied()
        .filter(|key| {
            let tcp_key: TcpFlowKey = key[..TCP_FLOW_KEY_LEN].try_into().unwrap();
            let (_, _, other_ip, _, _) = decode_tcp_flow_key(&tcp_key);
            other_ip == departed_pod
        })
        .collect()
}

/// Runs the full conntrack eviction sweep for one departed pod IP against
/// the live pinned `FWD_PENDING`/`FLOW_TABLE` maps -- shared by the
/// controller's per-reconcile `POD_TARGETS` prune (`apply_pod_targets`) and
/// the loader's hidden `evict-pod` one-shot test trigger, so
/// `scripts/smoke.sh` exercises the exact sweep logic production runs.
///
/// Collects every matching key from BOTH maps into `Vec`s before removing
/// any of them: `FWD_PENDING`/`FLOW_TABLE` are both `BPF_MAP_TYPE_LRU_HASH`,
/// and deleting while `.iter()` is still walking a live LRU map races the
/// kernel's own LRU bookkeeping. Logs and continues past an individual
/// delete failure rather than aborting -- same convention as
/// `apply_diff_ops` (`controller/src/apply.rs`) -- so one map-at-capacity
/// error never leaves the other map's stale rows behind.
pub fn evict_pod_flows(
    fwd_pending: &mut AyaHashMap<MapData, TcpFlowKey, ForwardFlowValue>,
    flow_table: &mut AyaHashMap<MapData, FlowKey, FlowValue>,
    departed_pod: [u8; 16],
) -> anyhow::Result<()> {
    let pending_entries: Vec<(TcpFlowKey, ForwardFlowValue)> =
        fwd_pending.iter().collect::<Result<_, _>>()?;
    let stale_pending = stale_forward_entries(&pending_entries, departed_pod);

    let mut forward_entries = Vec::new();
    let mut reverse_and_port_memo_keys = Vec::new();
    for entry in flow_table.iter() {
        let (key, value) = entry?;
        match flow_key_direction(&key) {
            Some(FlowDirection::Forward) => forward_entries.push((key, value.as_forward())),
            Some(FlowDirection::Reverse) | Some(FlowDirection::PortMemo) => {
                reverse_and_port_memo_keys.push(key)
            }
            None => {}
        }
    }
    let mut stale_flow_table = stale_forward_entries(&forward_entries, departed_pod);
    stale_flow_table.extend(stale_flow_table_keys(
        &reverse_and_port_memo_keys,
        departed_pod,
    ));

    let mut failed = 0;
    for key in &stale_pending {
        if let Err(e) = fwd_pending.remove(key) {
            failed += 1;
            eprintln!("controller: FWD_PENDING eviction delete failed: {e:#}");
        }
    }
    for key in &stale_flow_table {
        if let Err(e) = flow_table.remove(key) {
            failed += 1;
            eprintln!("controller: FLOW_TABLE eviction delete failed: {e:#}");
        }
    }
    if failed > 0 {
        anyhow::bail!("{failed} conntrack eviction delete(s) failed -- see per-entry errors above");
    }
    Ok(())
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

/// Loads the `beep-ebpf` object embedded at build time (`build.rs`'s
/// aya-build cross-build, embedded here via `OUT_DIR`, which Cargo sets
/// identically for every target in this package -- lib or bin -- that has a
/// build script), pinning each of `MAP_NAMES` under `pin_dir` so a loader
/// restart reuses the existing map set instead of `Ebpf::load` creating an
/// empty one (`MAP_NAMES`'s own doc comment). `fwd_pending_max_entries`/
/// `flow_table_max_entries`/`lb_front_map_max_entries`/`target_ports_max_entries`
/// size the four maps whose entry count scales with cluster/Service state --
/// a load-time DaemonSet config knob, not a value baked into the eBPF
/// object -- and only take effect the first time each pin path is created (a
/// reused pin from a prior run opens the existing map via its live fd and
/// silently ignores this override; see `EbpfLoader::map_max_entries`'s own
/// semantics).
///
/// Shared by the `beep` loader binary and the controller binary (Phase 5's
/// Service/EndpointSlice watcher) so both embed and load the exact same
/// object the exact same way, rather than each re-deriving this from
/// scratch.
pub fn load_ebpf(
    pin_dir: &Path,
    fwd_pending_max_entries: u32,
    flow_table_max_entries: u32,
    lb_front_map_max_entries: u32,
    target_ports_max_entries: u32,
) -> anyhow::Result<Ebpf> {
    let mut loader = EbpfLoader::new();
    for name in MAP_NAMES {
        loader.map_pin_path(name, pin_dir.join(name));
    }
    loader.map_max_entries("FWD_PENDING", fwd_pending_max_entries);
    loader.map_max_entries("FLOW_TABLE", flow_table_max_entries);
    loader.map_max_entries("LB_FRONT_MAP", lb_front_map_max_entries);
    loader.map_max_entries("TARGET_PORTS", target_ports_max_entries);
    loader
        .load(include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/beep-ebpf"
        )))
        .context("loading the beep-ebpf object")
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

/// Creates `iface` as an external-mode ("collect metadata") Geneve device
/// and brings it up, if it doesn't already exist -- idempotent so a restart
/// against a node that already has it (or a test fixture that pre-creates
/// it) is a no-op. The shipped DaemonSet has no other node-prep step, and a
/// missing `geneve0` used to crash-loop it at `populate_config`'s ifindex
/// resolution ("resolving ifindex for geneve0 / No such device").
///
/// Shells out to `ip` (iproute2, added to the runtime image in `Dockerfile`)
/// rather than emitting a raw `RTM_NEWLINK` netlink message directly: this
/// workspace has no netlink crate dependency (minimal-deps stance), and
/// hand-rolling the GENEVE collect-metadata link-info attributes over a raw
/// `AF_NETLINK` socket is a lot of unsafe FFI for a one-shot node-prep step.
pub fn ensure_geneve_iface(iface: &str) -> anyhow::Result<()> {
    if iface_index(iface).is_err() {
        let out = std::process::Command::new("ip")
            .args(["link", "add", iface, "type", "geneve", "external"])
            .output()
            .with_context(|| format!("running `ip link add {iface} type geneve external`"))?;
        if !out.status.success() {
            return Err(anyhow!(
                "`ip link add {iface} type geneve external` exited with {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            ));
        }
    }
    let out = std::process::Command::new("ip")
        .args(["link", "set", iface, "up"])
        .output()
        .with_context(|| format!("running `ip link set {iface} up`"))?;
    if !out.status.success() {
        return Err(anyhow!(
            "`ip link set {iface} up` exited with {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// Disables the kernel reverse-path filter on `all` and on `iface` (the
/// Geneve device) -- effective RPF is `max(conf.all.rp_filter,
/// conf.<iface>.rp_filter)` (see `ip-sysctl.rst`), so both writes are
/// required or the `all` exception alone is moot.
///
/// DELIBERATE, operator-decided tradeoff (2026-09-17), not an oversight: to
/// preserve the client's real source IP across the tunnel -- the entire
/// point of this LB -- the decapped inner packet's source address is the
/// external client, never reachable back out an address-less `geneve0`;
/// strict or loose RPF drops it by construction (Cilium and Katran run the
/// same way, for the same reason). This weakens anti-spoof protection
/// node-wide (`all`), not just on `geneve0`. REVISIT if that turns out to
/// matter -- the escape hatch is a routing-based/policy-routing decap
/// alternative that preserves symmetric RPF at a real datapath cost.
pub fn disable_rp_filter(iface: &str) -> anyhow::Result<()> {
    for dev in ["all", iface] {
        let path = format!("/proc/sys/net/ipv4/conf/{dev}/rp_filter");
        std::fs::write(&path, b"0").with_context(|| format!("writing 0 to {path}"))?;
    }
    Ok(())
}

/// Resolves the Geneve device's ifindex (unknown until this host's `ip link`
/// state is inspected, so it can't be a compile-time constant in the eBPF
/// program) and writes it to the single-entry `CONFIG` map the classifiers
/// read at runtime. Per-uplink data (ifindex, L2 header length) is a
/// separate map -- see `populate_uplink_config`.
pub fn populate_config(ebpf: &mut Ebpf, geneve_iface: &str) -> anyhow::Result<()> {
    let geneve_ifindex = iface_index(geneve_iface)
        .with_context(|| format!("resolving ifindex for {geneve_iface}"))?;
    let mut config: AyaArray<_, Config> = AyaArray::try_from(
        ebpf.map_mut("CONFIG")
            .ok_or_else(|| anyhow!("no map named `CONFIG` in the eBPF object"))?,
    )?;
    config.set(0, Config { geneve_ifindex }, 0)?;
    Ok(())
}

/// Resolves each uplink's ifindex and L2 header length (a WireGuard/tun
/// uplink has no Ethernet header, unlike a real NIC/veth -- see
/// `uplink_l2_header_len`'s doc comment) and writes one `UPLINK_CONFIG`
/// entry per uplink, keyed by ifindex -- `try_uplink_ingress`'s hit-is-
/// admission gate for multi-uplink client traffic
/// (`docs/decisions/servicelb-multi-symmetric-uplink.md`).
pub fn populate_uplink_config(ebpf: &mut Ebpf, uplink_ifaces: &[String]) -> anyhow::Result<()> {
    let mut uplink_config: AyaHashMap<_, u32, UplinkConfig> = AyaHashMap::try_from(
        ebpf.map_mut("UPLINK_CONFIG")
            .ok_or_else(|| anyhow!("no map named `UPLINK_CONFIG` in the eBPF object"))?,
    )?;
    for uplink_iface in uplink_ifaces {
        let uplink_ifindex = iface_index(uplink_iface)
            .with_context(|| format!("resolving ifindex for {uplink_iface}"))?;
        let uplink_arphrd = iface_arphrd_type(uplink_iface)
            .with_context(|| format!("resolving ARPHRD type for {uplink_iface}"))?;
        let l2_hlen = beep_common::uplink_l2_header_len(uplink_arphrd);
        eprintln!(
            "uplink {uplink_iface}: ifindex {uplink_ifindex}, ARPHRD type {uplink_arphrd}, L2 header skip {l2_hlen} byte(s)"
        );
        uplink_config.insert(uplink_ifindex, UplinkConfig { l2_hlen }, 0)?;
    }
    Ok(())
}

/// Loads the named classifier once, then attaches it at EVERY iface in
/// `ifaces`, pinning each link under `pin_dir` so every attachment survives
/// this process exiting. If a link is already pinned from a prior run for a
/// given iface, atomically swaps in the freshly loaded program on that same
/// kernel link object instead of creating a second attachment.
///
/// One `program.load()` call regardless of `ifaces.len()`: aya's
/// `load_program` errors `AlreadyLoaded` on a second call for the same
/// program, so a multi-uplink `--uplink-iface` attaches the SAME loaded
/// `SchedClassifier` to each configured uplink via repeated
/// `attach_with_options`/`attach_to_link` calls on that one handle, never a
/// second `load()`. Every link returned by `attach_with_options` MUST be
/// pinned (or otherwise retained) individually -- an un-pinned,
/// un-retained link auto-detaches silently on drop, with no error surfaced.
pub fn attach_and_pin(
    ebpf: &mut Ebpf,
    name: &str,
    ifaces: &[&str],
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

    for iface in ifaces {
        // Pin filenames must not contain a literal `.`: this kernel's bpffs
        // rejects `BPF_OBJ_PIN`/`BPF_OBJ_GET` on any path whose final
        // component has a dot with EPERM (verified by bisecting an
        // otherwise-identical repro down to a single `-` vs `.` swap) -- a
        // narrow, surprising constraint worth more investigation, but not a
        // verifier or aya bug. Suffixed by iface so N links for the same
        // program (one per configured uplink) each get their own pin file.
        let link_pin_path = pin_dir.join(format!("{name}-{iface}-link"));
        match PinnedLink::from_pin(&link_pin_path) {
            Ok(existing) => {
                // bpf_link_update swaps the target program on the *same*
                // kernel link object referenced by the existing pin file, so
                // the pin file itself needs no changes.
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
    }

    // Pinning the program itself (separate from the link) is only for
    // `bpftool prog show pinned ...` introspection by name; restart-survival
    // of the attachment depends solely on the per-iface link pins above.
    let prog_pin_path = pin_dir.join(format!("{name}-prog"));
    let _ = std::fs::remove_file(&prog_pin_path);
    program.pin(&prog_pin_path)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use beep_common::{encode_flow_key, encode_tcp_flow_key};
    use std::net::Ipv4Addr;

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
        let node_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6));
        let other_node_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7));
        let local_fixture = parse_fixture("10.0.0.5:80:tcp:10.0.0.6:10.244.1.7:8080").unwrap();
        let remote_fixture = parse_fixture("10.0.0.5:81:tcp:10.0.0.7:10.244.1.8:8081").unwrap();
        assert_eq!(local_fixture.backend_node_ip, node_ip);
        assert_eq!(remote_fixture.backend_node_ip, other_node_ip);
        let fixtures = [local_fixture, remote_fixture];

        assert_eq!(
            local_pod_ips(&fixtures, node_ip),
            vec![wire_ip_v6(local_fixture.pod_ip)],
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
        let departed_pod_ip = wire_ip_v6(IpAddr::V4(Ipv4Addr::new(10, 244, 1, 9)));
        let existing = [departed_pod_ip];
        let live: [[u8; 16]; 0] = [];

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
        let live = [wire_ip_v6(fixture.pod_ip)];

        assert!(
            stale_pod_targets(&live, &live).is_empty(),
            "a pod still claimed by the local serving-set must not be pruned from POD_TARGETS"
        );
    }

    fn forward_flow_value_for(pod_ip: [u8; 16]) -> ForwardFlowValue {
        ForwardFlowValue {
            backend: beep_common::LbFrontBackend {
                backend_node_ip: wire_ip_v6(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6))),
                pod_ip,
            },
            ingress_ifindex: 2,
        }
    }

    #[test]
    fn stale_forward_entries_selects_fwd_pending_rows_for_the_departed_pod_only() {
        // FWD_PENDING's key ((client, VIP, proto)) never carries pod
        // identity -- only the value does. If this filter is reverted to a
        // no-op (e.g. always `true`), a departed pod's pre-promotion
        // FWD_PENDING rows survive eviction and can still be promoted into
        // FLOW_TABLE by a later packet, resurrecting routing to a dead
        // backend.
        let departed_pod = wire_ip_v6(IpAddr::V4(Ipv4Addr::new(10, 244, 1, 9)));
        let other_pod = wire_ip_v6(IpAddr::V4(Ipv4Addr::new(10, 244, 1, 10)));
        let departed_key: TcpFlowKey = encode_tcp_flow_key(
            wire_ip_v6(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2))),
            1,
            wire_ip_v6(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
            80,
            6,
        );
        let other_key: TcpFlowKey = encode_tcp_flow_key(
            wire_ip_v6(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 3))),
            2,
            wire_ip_v6(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
            81,
            6,
        );
        let entries = [
            (departed_key, forward_flow_value_for(departed_pod)),
            (other_key, forward_flow_value_for(other_pod)),
        ];

        assert_eq!(
            stale_forward_entries(&entries, departed_pod),
            vec![departed_key],
            "only the departed pod's FWD_PENDING row must be selected -- an unrelated pod's \
             pending row must survive"
        );
    }

    #[test]
    fn stale_forward_entries_selects_flow_table_forward_rows_for_the_departed_pod_only() {
        // FLOW_TABLE's Forward-tagged rows share FWD_PENDING's value shape
        // (`ForwardFlowValue`) and the same value-based match, just keyed on
        // the wider `FlowKey`. Same regression as the FWD_PENDING test
        // above, but against the promoted/established tier: a reverted
        // filter here leaves a departed pod's ESTABLISHED forward affinity
        // routing live traffic to a dead backend indefinitely.
        let departed_pod = wire_ip_v6(IpAddr::V4(Ipv4Addr::new(10, 244, 1, 9)));
        let other_pod = wire_ip_v6(IpAddr::V4(Ipv4Addr::new(10, 244, 1, 10)));
        let client_ip = wire_ip_v6(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)));
        let vip_ip = wire_ip_v6(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
        let departed_key: FlowKey =
            encode_flow_key(client_ip, 1, vip_ip, 80, 6, FlowDirection::Forward);
        let other_key: FlowKey =
            encode_flow_key(client_ip, 2, vip_ip, 81, 6, FlowDirection::Forward);
        let entries = [
            (departed_key, forward_flow_value_for(departed_pod)),
            (other_key, forward_flow_value_for(other_pod)),
        ];

        assert_eq!(
            stale_forward_entries(&entries, departed_pod),
            vec![departed_key],
            "only the departed pod's FLOW_TABLE Forward-tagged row must be selected -- an \
             unrelated pod's established forward entry must survive"
        );
    }

    #[test]
    fn stale_flow_table_keys_selects_reverse_tagged_rows_for_the_departed_pod_only() {
        // Reverse-tagged rows key on (client, ..., pod_ip, ...) -- pod
        // identity lives in the KEY, the opposite of Forward's value-based
        // match. If this filter is reverted to a no-op, a departed pod's
        // reverse (un-DNAT) conntrack entry survives, and a FUTURE, unrelated
        // owner of that reused pod IP has its return traffic un-DNATed using
        // the departed flow's stale VIP/ingress-node state.
        let departed_pod = wire_ip_v6(IpAddr::V4(Ipv4Addr::new(10, 244, 1, 9)));
        let other_pod = wire_ip_v6(IpAddr::V4(Ipv4Addr::new(10, 244, 1, 10)));
        let client_ip = wire_ip_v6(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)));
        let departed_key: FlowKey =
            encode_flow_key(client_ip, 1, departed_pod, 8080, 6, FlowDirection::Reverse);
        let other_key: FlowKey =
            encode_flow_key(client_ip, 1, other_pod, 8080, 6, FlowDirection::Reverse);

        assert_eq!(
            stale_flow_table_keys(&[departed_key, other_key], departed_pod),
            vec![departed_key],
            "only the departed pod's Reverse-tagged key must be selected -- an unrelated pod's \
             reverse conntrack entry must survive"
        );
    }

    #[test]
    fn stale_flow_table_keys_selects_port_memo_tagged_rows_for_the_departed_pod_only() {
        // PortMemo shares Reverse's exact key shape (pod IP in the key) and
        // the identical pod-IP-reuse hazard: a stale memo for a reused pod
        // IP would feed a stale backend-src-port decision to an unrelated
        // new flow through that IP. Same regression shape as the Reverse
        // test above, proven separately since `evict_pod_flows` calls this
        // function on PortMemo-tagged keys too (a corrected-in-review scope
        // widening past the original design's Forward+Reverse-only sketch).
        let departed_pod = wire_ip_v6(IpAddr::V4(Ipv4Addr::new(10, 244, 1, 9)));
        let other_pod = wire_ip_v6(IpAddr::V4(Ipv4Addr::new(10, 244, 1, 10)));
        let client_ip = wire_ip_v6(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)));
        let departed_key: FlowKey =
            encode_flow_key(client_ip, 1, departed_pod, 8080, 6, FlowDirection::PortMemo);
        let other_key: FlowKey =
            encode_flow_key(client_ip, 1, other_pod, 8080, 6, FlowDirection::PortMemo);

        assert_eq!(
            stale_flow_table_keys(&[departed_key, other_key], departed_pod),
            vec![departed_key],
            "only the departed pod's PortMemo-tagged key must be selected -- an unrelated pod's \
             port-remap memo must survive"
        );
    }

    #[test]
    fn flow_key_direction_reads_the_tag_byte_each_role_was_encoded_with() {
        // The eviction sweep's tag-check-before-union-read guardrail
        // (`FlowValue::as_forward`/`as_reverse`/`as_port_memo` are unchecked
        // reads) depends entirely on this decode being correct -- a
        // mismatched tag byte here would make the sweep call the wrong
        // union arm's reader on a Forward-tagged row.
        let ip = wire_ip_v6(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
        let fwd_key = encode_flow_key(ip, 1, ip, 2, 6, FlowDirection::Forward);
        let rev_key = encode_flow_key(ip, 1, ip, 2, 6, FlowDirection::Reverse);
        let port_memo_key = encode_flow_key(ip, 1, ip, 2, 6, FlowDirection::PortMemo);

        assert_eq!(flow_key_direction(&fwd_key), Some(FlowDirection::Forward));
        assert_eq!(flow_key_direction(&rev_key), Some(FlowDirection::Reverse));
        assert_eq!(
            flow_key_direction(&port_memo_key),
            Some(FlowDirection::PortMemo)
        );
    }

    #[test]
    fn local_pod_ips_accepts_a_v6_fixture_and_writes_the_raw_v6_octets() {
        // A v6 Service/Pod must populate POD_TARGETS exactly like a v4 one
        // does, or a v6 backend Pod silently gets no local-serving-set entry
        // and every decap/egress-return admission check drops its traffic.
        // Unlike a v4 pod_ip (embedded via `ipv4_mapped_v6`), a genuine v6
        // address needs no embedding -- its own octets already are the
        // `[u8; 16]` wire shape.
        let node_ip: IpAddr = "2001:db8::1".parse().unwrap();
        let fixture =
            parse_fixture("[2001:db8::1]:80:tcp:[2001:db8::1]:[2001:db8::2]:8080").unwrap();
        assert_eq!(fixture.backend_node_ip, node_ip);

        let pod_ip: IpAddr = "2001:db8::2".parse().unwrap();
        let IpAddr::V6(pod_v6) = pod_ip else {
            unreachable!()
        };
        assert_eq!(
            local_pod_ips(&[fixture], node_ip),
            vec![pod_v6.octets()],
            "a v6 fixture's pod_ip must land in POD_TARGETS as its raw octets, not silently \
             dropped or corrupted by v4-only wire-encode logic"
        );
    }
}
