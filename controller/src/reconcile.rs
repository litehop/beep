//! Pure (Service, EndpointSlices, NodeContext) -> desired-map-entries
//! reconciliation. No I/O, no k8s client, no aya --
//! `ServiceView`/`EndpointSliceView` are plain parsed views the eventual
//! watch layer fills in from real API objects. Kept pure so a wrong
//! map-population decision (stale entry, missed update, wrong backend) is
//! caught by a fixture-driven unit test instead of only showing up as
//! silent misrouting against a live cluster.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use beep::front_swap::DesiredFront;
use beep::{tunnel_remote_v6, wire_ip_v6};
use beep_common::{wire_port, FrontEndpoint, LbFrontBackend, LbFrontKey};

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    fn as_ip_proto(self) -> u8 {
        match self {
            Protocol::Tcp => IPPROTO_TCP,
            Protocol::Udp => IPPROTO_UDP,
        }
    }
}

/// Minimal IPv4 CIDR match, independent of the loader's own (`src/main.rs`)
/// copy: this is a userspace-only parsing concept that never crosses the
/// kernel boundary, so it doesn't belong in `beep-common` (unlike `LbFrontKey`/
/// `LbFrontBackend`, whose byte layout must stay identical on both sides).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Cidr {
    network: Ipv4Addr,
    prefix_len: u8,
}

impl Ipv4Cidr {
    pub fn new(network: Ipv4Addr, prefix_len: u8) -> Self {
        let mask = Self::mask(prefix_len);
        Ipv4Cidr {
            network: Ipv4Addr::from(u32::from(network) & mask),
            prefix_len,
        }
    }

    // prefix_len == 0 (match everything) would overflow a `<< 32` shift
    // (Rust masks the shift amount mod 32), so it's handled as its own case
    // rather than folded into the general shift -- same reasoning as the
    // loader's `Ipv4Cidr::mask`.
    fn mask(prefix_len: u8) -> u32 {
        if prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - prefix_len)
        }
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask = Self::mask(self.prefix_len);
        (u32::from(ip) & mask) == (u32::from(self.network) & mask)
    }
}

impl std::fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

/// v6 analog of `Ipv4Cidr`, same `u128`-masked-comparison shape -- kept as
/// its own type rather than a generic one so each family's bit width (`u32`
/// vs `u128`) stays a plain, unambiguous integer operation.
// `pub`, unlike its fields/methods below: `IpCidr::V6` (a `pub` enum
// variant) holds one of these, and a variant's field type can't be less
// visible than the enum itself (`private_interfaces`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv6Cidr {
    network: Ipv6Addr,
    prefix_len: u8,
}

impl Ipv6Cidr {
    pub fn new(network: Ipv6Addr, prefix_len: u8) -> Self {
        let mask = Self::mask(prefix_len);
        Ipv6Cidr {
            network: Ipv6Addr::from(u128::from(network) & mask),
            prefix_len,
        }
    }

    fn mask(prefix_len: u8) -> u128 {
        if prefix_len == 0 {
            0
        } else {
            u128::MAX << (128 - prefix_len)
        }
    }

    fn contains(&self, ip: Ipv6Addr) -> bool {
        let mask = Self::mask(self.prefix_len);
        (u128::from(ip) & mask) == (u128::from(self.network) & mask)
    }
}

impl std::fmt::Display for Ipv6Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

/// `NodeContext::pod_cidr`'s dual-stack shape, mirroring the loader's own
/// `Ipv4Cidr`/`IpCidr` split (`src/main.rs`): a Service's front and its
/// backend Pod can each independently be v4 or v6, so `is_admitted` must
/// compare a dual-stack `Endpoint.pod_ip` against a CIDR of either family
/// without assuming one. `main.rs`'s CLI parser (`parse_ip_cidr`) picks
/// `IpCidr::V4`/`V6` off the configured `--pod-cidr` network address's own
/// family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpCidr {
    V4(Ipv4Cidr),
    V6(Ipv6Cidr),
}

impl IpCidr {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (IpCidr::V4(cidr), IpAddr::V4(ip)) => cidr.contains(ip),
            (IpCidr::V6(cidr), IpAddr::V6(ip)) => cidr.contains(ip),
            // A v6 pod_ip can never be "inside" a v4 pod_cidr (or vice
            // versa) -- `is_admitted`'s hostNetwork disjunct is still free
            // to admit it, same as an out-of-range same-family address.
            _ => false,
        }
    }
}

// So a caller (`main.rs`'s `apply_reconcile`) can name the misconfigured
// `--pod-cidr` value in its WARN without reaching into either CIDR
// variant's private fields.
impl std::fmt::Display for IpCidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpCidr::V4(cidr) => cidr.fmt(f),
            IpCidr::V6(cidr) => cidr.fmt(f),
        }
    }
}

/// This node's own identity for reconciling a `Service`. `node_ip` is the
/// value the loader's `--node-ip` already gates `POD_TARGETS` scoping on
/// (`src/main.rs`'s `local_pod_ips`: `backend_node_ip == node_ip`); `pod_cidr`
/// is this node's own pod subnet, checked as a second, independent signal
/// before trusting an `EndpointSliceView` entry's `node_ip` as one of this
/// node's own backends -- an `EndpointSlice` object is a value another
/// component wrote, and `node_ip` alone can't be cross-checked without a
/// second field to disagree with it. A pod is admitted if it's in
/// `pod_cidr` OR it carries the hostNetwork signature (`pod_ip == node_ip`):
/// bare metal has no cloud LB / BGP virtual IP, beep fronts the node's
/// physical IP directly, so a hostNetwork pod's IP IS the node IP and must
/// be servable as a backend. An arbitrary `pod_ip` that is neither in
/// `pod_cidr` nor equal to `node_ip` is still rejected -- anti-spoof for a
/// value another (untrusted) component wrote. Locking down which
/// control-plane ports may be fronted this way is deliberately out of
/// beep's scope: that's the firewall's job (ufw/NetworkPolicy), not the
/// load balancer's. The loader's own `local_pod_ips` (node_ip-only, driven
/// by trusted fixture args, not EndpointSlice input) intentionally stays
/// laxer than this -- no loader change accompanies this relaxation.
#[derive(Clone, Copy, Debug)]
pub struct NodeContext {
    pub node_ip: IpAddr,
    pub pod_cidr: IpCidr,
}

/// One `Service.spec.ports[]` entry: `port` is the front-facing front port,
/// `target_port` the numeric container port, stored on the front's endpoint
/// (`FrontEndpoint::target_port`). A container-port-by-name Service must be
/// resolved to a number before reaching this type.
#[derive(Clone, Copy, Debug)]
pub struct ServicePort {
    pub port: u16,
    pub protocol: Protocol,
    pub target_port: u16,
}

/// A `type=LoadBalancer` Service's parsed view: front address plus its ports.
#[derive(Clone, Debug)]
pub struct ServiceView {
    pub front_ip: IpAddr,
    pub ports: Vec<ServicePort>,
}

/// One `EndpointSlice` endpoint. `node_ip` is the IP of the node hosting
/// this pod (Phase B's watch resolves the real `EndpointSlice.endpoints[].
/// nodeName` hostname to this IP via a `Node` object lookup before building
/// this view) -- needed verbatim as `LbFrontBackend.backend_node_ip`, the Geneve
/// tunnel remote for this pod's forward leg. `ports` are this endpoint's
/// resolved numeric ports; an endpoint missing a `ServicePort`'s
/// `target_port` here is excluded as a backend candidate for that specific
/// front (e.g. a Pod mid-rollout that hasn't started listening on a newly
/// added container port yet).
#[derive(Clone, Debug)]
pub struct Endpoint {
    pub pod_ip: IpAddr,
    pub node_ip: IpAddr,
    /// Every address (underlay and front, any family) the hosting node's
    /// `Node` object reports. `node_ip` is only the one Geneve remote
    /// picked from these, so node identity must be decided against this set.
    pub node_addrs: Vec<IpAddr>,
    pub ready: bool,
    pub ports: Vec<u16>,
    /// `endpoints[].targetRef.uid`: the owning pod's identity, absent when the
    /// slice carries no `targetRef`. Lets the controller notice a pod IP
    /// handed to a different pod (`cluster_backends`).
    pub pod_uid: Option<String>,
}

/// One `EndpointSlice` object. A Service can be backed by more than one of
/// these (sharding once a Service exceeds ~100 endpoints, or per-zone
/// slicing), so `reconcile_service` takes a slice of these, not a single one.
#[derive(Clone, Debug)]
pub struct EndpointSliceView {
    pub endpoints: Vec<Endpoint>,
}

/// An endpoint hosted on THIS node (`ep.node_addrs` contains `node.node_ip`) that
/// `pod_targets_for_node`'s admission check excluded from `POD_TARGETS`
/// because its `pod_ip` matched neither `pod_cidr` nor the hostNetwork
/// signature. The rejection itself is correct anti-spoof behavior (see
/// `pod_targets_for_node`'s doc comment) -- this type exists purely so a
/// caller can log what got rejected instead of the dataplane going quietly
/// backend-less. A misconfigured `--pod-cidr` (e.g. left at a different
/// CNI's default) rejects every endpoint on every node this way, which
/// previously surfaced as no traffic delivered and nothing in any log
/// naming why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RejectedEndpoint {
    pub pod_ip: IpAddr,
    pub reason: &'static str,
}

/// Desired `FRONT_META`/`FRONT_ENDPOINTS`/`POD_TARGETS`/`NODE_ALLOW` contents
/// for one Service, keyed exactly like the maps themselves.
#[derive(Default)]
pub struct DesiredEntries {
    /// Per front: the endpoint set (`FRONT_ENDPOINTS` slots) and `FRONT_META`
    /// flags. `PinnedMaps::apply` turns this into generation-swap writes
    /// (`beep::front_swap`).
    pub fronts: HashMap<LbFrontKey, DesiredFront>,
    pub pod_targets: HashSet<[u8; 16]>,
    /// Every backend pod IP still in a slice, with its owning pod uid, if
    /// known (`cluster_backends`). Drives the departed/reused sweep in
    /// `PinnedMaps::apply`; `pod_targets` stays this node's local subset.
    pub cluster_backends: HashMap<[u8; 16], Option<String>>,
    /// Desired `NODE_ALLOW` contents: every known node's address, wrapped in
    /// `tunnel_remote_v6` (`NODE_ALLOW`'s key is `[u8; 16]`) over the
    /// host-native value -- the same convention `LbFrontBackend::
    /// backend_node_ip` uses, since `beep-ebpf`'s `geneve_ingress` checks
    /// this set against `tkey.remote_ipv4`, a kernel-tunnel-key field the
    /// kernel itself converts host<->network internally, never a raw wire
    /// byte load (`beep-ebpf`'s module doc). Same source as `fronts`'s
    /// per-Service front-IP loop (`WatchState::desired`'s
    /// `front_ips`), NOT the narrower `pod_targets_known` the
    /// pre-existing `try_geneve_decap_forward` admission check (POD_TARGETS)
    /// alone used to bound: `node_allow`'s content is the WHOLE known-node
    /// set (like `fronts`), not this node's own entry alone
    /// (like `pod_targets`), so a restart's partially-caught-up `node_ips`
    /// must never DELETE already-pinned peer entries before the full Node
    /// LIST (`fronts_known` below) is known-complete. `PinnedMaps::
    /// apply_node_allow` still upserts this set every tick
    /// regardless of `fronts_known` -- only the delete half of its sync is
    /// latched on `fronts_known` having been seen true once this process --
    /// so already-discovered peers get admitted without waiting for the
    /// full list, without reopening the restart-wipe window `fronts_known`
    /// exists to prevent.
    pub node_allow: HashSet<[u8; 16]>,
    /// Endpoints excluded from `pod_targets` by the pod-CIDR admission
    /// check -- see `RejectedEndpoint`'s doc comment. Purely observational:
    /// nothing here changes `pod_targets` itself.
    pub rejected: Vec<RejectedEndpoint>,
    /// Whether `fronts`/`node_allow` were computed from a
    /// fully-known node set. `WatchState::desired` (the only real producer
    /// of an aggregate `DesiredEntries`) sets this to `false` while the
    /// initial Node LIST hasn't completed yet, so `PinnedMaps::apply` knows
    /// an empty `fronts` here means "node set not known
    /// yet", not "no fronts should exist" -- diffing against the latter
    /// would delete every already-programmed front that survived a
    /// controller restart. `node_allow` is upserted every tick regardless
    /// (`node_allow` field's doc comment); this flag only latches ON the
    /// destructive half of ITS sync once true, never back off.
    pub fronts_known: bool,
    /// Whether `pod_targets` was computed with THIS node's own address
    /// already resolvable in `WatchState::desired`'s endpoint->node_ip
    /// lookup (`pod_targets_for_node` can only admit an endpoint whose
    /// node reports `NodeContext::node_ip` among its addresses). `false` means
    /// "this node's own Node LIST/watch entry hasn't landed yet", not
    /// "this node hosts no backends" -- in a multi-node cluster, whichever
    /// position THIS node's own entry lands at in the startup Node LIST is
    /// unrelated to every OTHER node's position, so gating this on the
    /// full list (`fronts_known`) would still let an already-pinned local
    /// backend get wiped while unrelated nodes are still being listed.
    /// `PinnedMaps::apply` skips the destructive POD_TARGETS full-sync
    /// while this is `false`.
    pub pod_targets_known: bool,
}

#[cfg(test)]
impl DesiredEntries {
    /// Slot-0 backend per front (every front has exactly one endpoint today).
    pub(crate) fn backends(&self) -> HashMap<LbFrontKey, LbFrontBackend> {
        self.fronts
            .iter()
            .map(|(k, f)| {
                assert_eq!(
                    f.endpoints.len(),
                    1,
                    "count is 1 until multi-endpoint lands"
                );
                (*k, f.endpoints[0].backend)
            })
            .collect()
    }

    /// Slot-0 wire-order target port per front.
    pub(crate) fn target_ports(&self) -> HashMap<LbFrontKey, u16> {
        self.fronts
            .iter()
            .map(|(k, f)| (*k, f.endpoints[0].target_port))
            .collect()
    }
}

fn front_key(front_ip: IpAddr, port: &ServicePort) -> LbFrontKey {
    LbFrontKey {
        front_ip: wire_ip_v6(front_ip),
        front_port: wire_port(port.port),
        proto: port.protocol.as_ip_proto(),
        _pad: 0,
    }
}

/// The CIDR/hostNetwork admission disjunct shared by `pod_targets_for_node`
/// and `rejected_endpoints_for_node`: an endpoint is admitted if its pod_ip
/// is in this node's pod_cidr OR it carries the hostNetwork signature
/// (pod_ip is one of the endpoint's own node's addresses, in any family --
/// not `ep.node_ip`, which is coerced to the reconciling node's family). In
/// bare metal (no cloud LB, no BGP -- beep fronts the node's physical IP) a
/// hostNetwork pod's IP IS the node IP, so
/// without the second disjunct a Service backed by a hostNetwork pod would
/// be silently excluded and every forward packet dropped at decap
/// admission. Guarding which control-plane ports (6443/10250/2379/...) may
/// be fronted this way is deliberately out of scope -- that's
/// perimeter/firewall policy (ufw/NetworkPolicy), not the load balancer's
/// job. Extracted to one predicate both callers share, so a future change
/// to this condition can't silently drift between the admit path and its
/// negated, observational complement below.
fn is_admitted(ep: &Endpoint, node: &NodeContext) -> bool {
    node.pod_cidr.contains(ep.pod_ip) || ep.node_addrs.contains(&ep.pod_ip)
}

/// POD_TARGETS is this node's own local serving-set, port-agnostic by
/// design (`beep_common::egress_return_admission`'s doc comment) --
/// membership must never depend on which front port an endpoint answers,
/// only on whether THIS node hosts it and it is still present in a slice --
/// readiness is not consulted, since a terminating pod's already-pinned flows
/// need decap and return admission until the endpoint is removed. New flows
/// only ever reach ready endpoints via `FRONT_ENDPOINTS`. Deliberately
/// independent of `ServiceView` (no `front_ip`/`ports` input): unlike
/// `FRONT_META`/`FRONT_ENDPOINTS`, POD_TARGETS is EndpointSlice/local-node-derived,
/// not front-derived, so `WatchState::desired` can (and must) call this even
/// while the front set is still unknown (`nodes_listed == false`) -- see its
/// call site's comment for the restart-blackhole this independence avoids.
/// See `is_admitted` for the CIDR/hostNetwork admission check itself.
/// Arbitrary out-of-cidr pod_ips that are also != node_ip are still
/// rejected below.
pub fn pod_targets_for_node(slices: &[EndpointSliceView], node: &NodeContext) -> HashSet<[u8; 16]> {
    let mut pod_targets = HashSet::new();
    for slice in slices {
        for ep in &slice.endpoints {
            if ep.node_addrs.contains(&node.node_ip) && is_admitted(ep, node) {
                // POD_TARGETS' key is `[u8; 16]` (like NODE_ALLOW's), but wire-token
                // (`wire_ip_v6`) like `LbFrontBackend::pod_ip` -- unlike NODE_ALLOW's
                // host-native peer address, POD_TARGETS membership is checked against a
                // wire-order source IP the dataplane never asks the kernel to convert for it.
                pod_targets.insert(wire_ip_v6(ep.pod_ip));
            }
        }
    }
    pod_targets
}

/// Every endpoint still present in a slice, wherever it is hosted, keyed by
/// wire pod IP with its owning pod uid when the slice carries a `targetRef`.
/// Readiness is deliberately not consulted: a terminating-but-serving pod or
/// one flapping its readiness probe still owns its pinned flows, which end only
/// when the endpoint leaves every slice. Unlike `pod_targets_for_node` this is
/// cluster-wide: the conntrack pins a node holds for a flow name the backend
/// pod, which is usually on another node.
pub fn cluster_backends(
    endpoints: impl IntoIterator<Item = (IpAddr, Option<String>)>,
) -> HashMap<[u8; 16], Option<String>> {
    let mut backends: HashMap<[u8; 16], Option<String>> = HashMap::new();
    for (pod_ip, pod_uid) in endpoints {
        let uid = backends.entry(wire_ip_v6(pod_ip)).or_default();
        if uid.is_none() {
            *uid = pod_uid;
        }
    }
    backends
}

/// The observational complement of `pod_targets_for_node`: every
/// this-node-hosted endpoint that `is_admitted` excluded, paired with why.
pub fn rejected_endpoints_for_node(
    slices: &[EndpointSliceView],
    node: &NodeContext,
) -> Vec<RejectedEndpoint> {
    let mut rejected = Vec::new();
    for slice in slices {
        for ep in &slice.endpoints {
            if ep.node_addrs.contains(&node.node_ip) && !is_admitted(ep, node) {
                rejected.push(RejectedEndpoint {
                    pod_ip: ep.pod_ip,
                    reason: "pod_ip is outside the configured --pod-cidr and is not this \
                             node's own address (hostNetwork)",
                });
            }
        }
    }
    rejected
}

/// Reconciles one Service against its EndpointSlices into the map entries
/// this node's dataplane needs. Pure: same inputs always produce the same
/// `DesiredEntries`, so a caller (Phase B's watch handler) can call this on
/// every observed change and hand the result to `diff` against the maps'
/// current contents.
pub fn reconcile_service(
    svc: &ServiceView,
    slices: &[EndpointSliceView],
    node: &NodeContext,
) -> DesiredEntries {
    let mut desired = DesiredEntries::default();
    let endpoints: Vec<&Endpoint> = slices.iter().flat_map(|s| s.endpoints.iter()).collect();

    desired.pod_targets = pod_targets_for_node(slices, node);
    desired.rejected = rejected_endpoints_for_node(slices, node);

    // Fronts are NOT node-scoped (any node can be ingress for any front,
    // mirroring the loader's fixture population), so backend candidates are
    // drawn from every endpoint across every slice -- regardless of which
    // node hosts them -- not just this node's own. Only endpoints of the
    // front's own address family qualify: the Geneve inner packet keeps the
    // client's family, so a cross-family pod can never answer.
    for port in &svc.ports {
        let mut candidates: Vec<&Endpoint> = endpoints
            .iter()
            .copied()
            .filter(|e| {
                e.ready
                    && e.ports.contains(&port.target_port)
                    && e.pod_ip.is_ipv4() == svc.front_ip.is_ipv4()
            })
            .collect();
        // One endpoint per front (slot 0) for now: pick deterministically --
        // lowest pod IP -- rather than arbitrarily (e.g. HashMap iteration
        // order), so two reconciles over the same input always agree and a
        // fixture-driven test can assert a specific outcome. It does not
        // spread load across endpoints.
        candidates.sort_by_key(|e| e.pod_ip);
        let Some(backend) = candidates.first() else {
            continue;
        };

        desired.fronts.insert(
            front_key(svc.front_ip, port),
            DesiredFront {
                flags: 0,
                endpoints: vec![FrontEndpoint {
                    backend: LbFrontBackend {
                        // Host-native, not wire_ip: the kernel's own
                        // bpf_tunnel_key.remote_ipv4 set/get converts this
                        // field itself (`src/main.rs`'s `fixture_fronts`
                        // comment) -- `tunnel_remote_v6` is that
                        // convention's dual-stack widening (`src/lib.rs`).
                        backend_node_ip: tunnel_remote_v6(backend.node_ip),
                        pod_ip: wire_ip_v6(backend.pod_ip),
                    },
                    target_port: wire_port(port.target_port),
                    _pad: [0; 6],
                }],
            },
        );
    }

    desired
}

/// The service ports `reconcile_service` left without a front because no
/// ready endpoint of the front's own address family serves them, while ready
/// endpoints of the OTHER family do: a v6 front with only v4 pods (or the
/// reverse) is a misconfiguration worth naming, unlike a Service that simply
/// has no ready endpoints yet.
pub fn ports_without_same_family_endpoint(
    svc: &ServiceView,
    slices: &[EndpointSliceView],
) -> Vec<ServicePort> {
    let serving = |port: &ServicePort, same_family: bool| {
        slices.iter().flat_map(|s| s.endpoints.iter()).any(|e| {
            e.ready
                && e.ports.contains(&port.target_port)
                && (e.pod_ip.is_ipv4() == svc.front_ip.is_ipv4()) == same_family
        })
    };
    svc.ports
        .iter()
        .filter(|p| !serving(p, true) && serving(p, false))
        .copied()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use beep_common::unmap_ipv4;

    fn cluster_pod_cidr() -> IpCidr {
        IpCidr::V4(Ipv4Cidr::new(Ipv4Addr::new(10, 244, 0, 0), 16))
    }

    fn node(ip: Ipv4Addr) -> NodeContext {
        NodeContext {
            node_ip: IpAddr::V4(ip),
            pod_cidr: cluster_pod_cidr(),
        }
    }

    fn node_v6(ip: Ipv6Addr, pod_cidr: IpCidr) -> NodeContext {
        NodeContext {
            node_ip: IpAddr::V6(ip),
            pod_cidr,
        }
    }

    fn single_port_service(front_ip: Ipv4Addr, port: u16, target_port: u16) -> ServiceView {
        ServiceView {
            front_ip: IpAddr::V4(front_ip),
            ports: vec![ServicePort {
                port,
                protocol: Protocol::Tcp,
                target_port,
            }],
        }
    }

    fn single_port_service_v6(front_ip: Ipv6Addr, port: u16, target_port: u16) -> ServiceView {
        ServiceView {
            front_ip: IpAddr::V6(front_ip),
            ports: vec![ServicePort {
                port,
                protocol: Protocol::Tcp,
                target_port,
            }],
        }
    }

    fn ready_endpoint(pod_ip: Ipv4Addr, node_ip: Ipv4Addr, ports: Vec<u16>) -> Endpoint {
        Endpoint {
            pod_ip: IpAddr::V4(pod_ip),
            node_ip: IpAddr::V4(node_ip),
            node_addrs: vec![IpAddr::V4(node_ip)],
            ready: true,
            ports,
            pod_uid: None,
        }
    }

    fn ready_endpoint_v6(pod_ip: Ipv6Addr, node_ip: Ipv6Addr, ports: Vec<u16>) -> Endpoint {
        Endpoint {
            pod_ip: IpAddr::V6(pod_ip),
            node_ip: IpAddr::V6(node_ip),
            node_addrs: vec![IpAddr::V6(node_ip)],
            ready: true,
            ports,
            pod_uid: None,
        }
    }

    // A conntrack keying bug corrupts routing silently instead of failing
    // loudly (beep-common's own module doc), so the exact wire bytes this
    // reconcile fn hands to FRONT_META/FRONT_ENDPOINTS are pinned here the same
    // way beep-common pins `wire_ip`/`wire_port` themselves.
    #[test]
    fn reconcile_wire_encodes_addresses_exactly_like_the_loader() {
        let node_ip = Ipv4Addr::new(10, 0, 0, 5);
        let svc = single_port_service(Ipv4Addr::new(10, 0, 0, 1), 80, 8080);
        let slices = vec![EndpointSliceView {
            endpoints: vec![ready_endpoint(
                Ipv4Addr::new(10, 244, 0, 9),
                node_ip,
                vec![8080],
            )],
        }];

        let desired = reconcile_service(&svc, &slices, &node(node_ip));

        assert_eq!(
            desired.fronts.len(),
            1,
            "exactly one front port was configured, so exactly one front is expected"
        );
        let (key, backend) = desired.backends().into_iter().next().unwrap();
        let front_wire = unmap_ipv4(&key.front_ip)
            .expect("a v4 front stored via ipv4_mapped_v6 must unmap back to a wire value");
        assert_eq!(
            front_wire.to_le_bytes(),
            [10, 0, 0, 1],
            "front wire encoding regressed vs beep_common::wire_ip's dotted-octet pin -- a \
             regression here corrupts every packet matched against this front"
        );
        assert_eq!(
            key.front_port.to_le_bytes(),
            [0, 80],
            "front port wire encoding regressed vs beep_common::wire_port's network-byte-order pin"
        );
        let pod_wire = unmap_ipv4(&backend.pod_ip)
            .expect("a v4 pod IP stored via ipv4_mapped_v6 must unmap back to a wire value");
        assert_eq!(
            pod_wire.to_le_bytes(),
            [10, 244, 0, 9],
            "backend pod_ip wire encoding regressed -- the dataplane would stamp the wrong \
             Geneve pod-identifier option"
        );
        let backend_node_native = unmap_ipv4(&backend.backend_node_ip).expect(
            "a v4 backend node IP stored via ipv4_mapped_v6 must unmap back to a native value",
        );
        assert_eq!(
            backend_node_native,
            u32::from(node_ip),
            "backend_node_ip must stay host-native (unconverted): the kernel's own \
             bpf_tunnel_key.remote_ipv4 set/get converts it, so pre-converting here would \
             double-flip the byte order and misdirect the Geneve tunnel"
        );
        let target_port = desired
            .target_ports()
            .get(&key)
            .copied()
            .expect("target port must be recorded");
        assert_eq!(
            target_port.to_le_bytes(),
            [0x1F, 0x90],
            "target port wire encoding regressed vs beep_common::wire_port's pin (8080)"
        );
    }

    fn plan_for(
        current: &DesiredEntries,
        next: &DesiredEntries,
    ) -> Vec<beep::front_swap::FrontPlan> {
        // Replays `current` through the planner into an in-memory pair of
        // maps, then plans `next` against them -- the same read-back-and-plan
        // loop `PinnedMaps::apply` runs against the pinned maps.
        let mut meta = HashMap::new();
        let mut endpoints = HashMap::new();
        for plan in beep::front_swap::plan_front_writes(&meta, &endpoints, &current.fronts, true) {
            for step in plan.steps {
                match step {
                    beep::front_swap::FrontWrite::PutEndpoint(k, v) => {
                        endpoints.insert(k, v);
                    }
                    beep::front_swap::FrontWrite::PutMeta(k, v) => {
                        meta.insert(k, v);
                    }
                    beep::front_swap::FrontWrite::DeleteEndpoint(k) => {
                        endpoints.remove(&k);
                    }
                    beep::front_swap::FrontWrite::DeleteMeta(k) => {
                        meta.remove(&k);
                    }
                }
            }
        }
        beep::front_swap::plan_front_writes(&meta, &endpoints, &next.fronts, true)
    }

    // A Service's first-ever reconcile against empty maps: this is what a
    // freshly created type=LoadBalancer Service must produce, or new
    // Services silently never get routed to.
    #[test]
    fn new_service_programs_one_endpoint_and_publishes_meta_with_count_one() {
        let node_ip = Ipv4Addr::new(10, 0, 0, 5);
        let svc = single_port_service(Ipv4Addr::new(10, 0, 0, 1), 80, 8080);
        let slices = vec![EndpointSliceView {
            endpoints: vec![ready_endpoint(
                Ipv4Addr::new(10, 244, 0, 9),
                node_ip,
                vec![8080],
            )],
        }];
        let desired = reconcile_service(&svc, &slices, &node(node_ip));

        let plans = plan_for(&DesiredEntries::default(), &desired);

        assert_eq!(plans.len(), 1, "one new front is one plan");
        let steps = &plans[0].steps;
        assert!(
            matches!(&steps[0], beep::front_swap::FrontWrite::PutEndpoint(k, ep)
                if k.slot == 0 && ep.target_port == wire_port(8080)),
            "a new Service must write its slot-0 endpoint with the wire-order target port"
        );
        assert!(
            matches!(&steps[1], beep::front_swap::FrontWrite::PutMeta(_, m) if m.count == 1),
            "FRONT_META is published last, with exactly one endpoint"
        );
    }

    // The resolved backend changes (e.g. a rolling deploy replaces the
    // previously-picked pod) -- the SAME front must move to the new backend
    // through a new generation, not keep pointing at the old (now-gone) pod.
    #[test]
    fn backend_change_swaps_the_front_to_a_new_generation_with_the_new_backend() {
        let node_ip = Ipv4Addr::new(10, 0, 0, 5);
        let svc = single_port_service(Ipv4Addr::new(10, 0, 0, 1), 80, 8080);
        let before = reconcile_service(
            &svc,
            &[EndpointSliceView {
                endpoints: vec![ready_endpoint(
                    Ipv4Addr::new(10, 244, 0, 9),
                    node_ip,
                    vec![8080],
                )],
            }],
            &node(node_ip),
        );
        // The old pod is gone; a new one (different, higher IP so the
        // deterministic pick has no other candidate to prefer) has replaced
        // it on a different node.
        let other_node_ip = Ipv4Addr::new(10, 0, 0, 6);
        let after = reconcile_service(
            &svc,
            &[EndpointSliceView {
                endpoints: vec![ready_endpoint(
                    Ipv4Addr::new(10, 244, 0, 40),
                    other_node_ip,
                    vec![8080],
                )],
            }],
            &node(node_ip),
        );

        let plans = plan_for(&before, &after);

        assert_eq!(plans.len(), 1);
        let steps = &plans[0].steps;
        let new_endpoint = steps
            .iter()
            .find_map(|s| match s {
                beep::front_swap::FrontWrite::PutEndpoint(k, ep) if k.generation == 2 => Some(ep),
                _ => None,
            })
            .expect("the replacement must be written under the next generation");
        assert_eq!(
            unmap_ipv4(&new_endpoint.backend.backend_node_ip),
            Some(u32::from(other_node_ip)),
            "the swap must point at the NEW backend's node, or traffic keeps going to the pod \
             that no longer exists"
        );
        let Some(beep::front_swap::FrontWrite::PutMeta(_, meta)) = steps.last() else {
            panic!("the meta flip must be the commit point and come last; got {steps:?}");
        };
        assert_eq!((meta.generation, meta.count), (2, 1));
    }

    // Once a Service is removed, its last-known desired set is replaced by
    // an empty one. A stale front surviving Service deletion would keep
    // routing client traffic at a backend that's since been reassigned to
    // something else entirely.
    #[test]
    fn removed_service_deletes_its_meta_before_its_endpoints() {
        let node_ip = Ipv4Addr::new(10, 0, 0, 5);
        let svc = single_port_service(Ipv4Addr::new(10, 0, 0, 1), 80, 8080);
        let desired = reconcile_service(
            &svc,
            &[EndpointSliceView {
                endpoints: vec![ready_endpoint(
                    Ipv4Addr::new(10, 244, 0, 9),
                    node_ip,
                    vec![8080],
                )],
            }],
            &node(node_ip),
        );

        let plans = plan_for(&desired, &DesiredEntries::default());

        assert_eq!(plans.len(), 1);
        assert!(
            matches!(
                plans[0].steps.as_slice(),
                [
                    beep::front_swap::FrontWrite::DeleteMeta(_),
                    beep::front_swap::FrontWrite::DeleteEndpoint(_)
                ]
            ),
            "a removed Service's front must stop resolving (meta first) before its endpoint \
             disappears; got {:?}",
            plans[0].steps
        );
    }

    // A multi-port Service (e.g. HTTP + metrics on one Pod) must resolve
    // each exposed port independently -- collapsing to one front
    // would silently drop routing for every port after the first.
    #[test]
    fn multi_port_service_gets_one_front_per_port_from_the_same_pod() {
        let node_ip = Ipv4Addr::new(10, 0, 0, 5);
        let pod_ip = Ipv4Addr::new(10, 244, 0, 9);
        let svc = ServiceView {
            front_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            ports: vec![
                ServicePort {
                    port: 80,
                    protocol: Protocol::Tcp,
                    target_port: 8080,
                },
                ServicePort {
                    port: 443,
                    protocol: Protocol::Tcp,
                    target_port: 8443,
                },
            ],
        };
        let slices = vec![EndpointSliceView {
            endpoints: vec![ready_endpoint(pod_ip, node_ip, vec![8080, 8443])],
        }];

        let desired = reconcile_service(&svc, &slices, &node(node_ip));

        assert_eq!(
            desired.fronts.len(),
            2,
            "each Service port must resolve to its own front, not one that shadows \
             the other"
        );
        assert_eq!(desired.fronts.len(), 2);
        for backend in desired.backends().into_values() {
            assert_eq!(
                unmap_ipv4(&backend.pod_ip).unwrap().to_le_bytes(),
                [10, 244, 0, 9],
                "both fronts back onto the same Pod in this fixture"
            );
        }
    }

    // Real EndpointSlices shard endpoints across multiple objects once a
    // Service exceeds ~100 endpoints (or across zones). Treating only the
    // first slice as authoritative would silently ignore backends in later
    // slices, and could pick the WRONG (higher-IP) backend if the actual
    // lowest-IP endpoint happens to land in a later slice -- breaking
    // decision #5's determinism guarantee.
    #[test]
    fn endpoints_split_across_multiple_slices_are_pooled_before_picking_a_backend() {
        let node_ip = Ipv4Addr::new(10, 0, 0, 5);
        let svc = single_port_service(Ipv4Addr::new(10, 0, 0, 1), 80, 8080);
        let slices = vec![
            EndpointSliceView {
                endpoints: vec![ready_endpoint(
                    Ipv4Addr::new(10, 244, 0, 20),
                    node_ip,
                    vec![8080],
                )],
            },
            EndpointSliceView {
                endpoints: vec![ready_endpoint(
                    Ipv4Addr::new(10, 244, 0, 2),
                    node_ip,
                    vec![8080],
                )],
            },
        ];

        let desired = reconcile_service(&svc, &slices, &node(node_ip));

        let (_, backend) = desired.backends().into_iter().next().unwrap();
        assert_eq!(
            unmap_ipv4(&backend.pod_ip).unwrap().to_le_bytes(),
            [10, 244, 0, 2],
            "the lowest-IP endpoint across BOTH slices must win -- a reconcile that only looked \
             at the first slice would wrongly pick .20 here"
        );
    }

    // POD_TARGETS gates whether this node's dataplane treats a source IP as
    // one of its own backend pods (`beep_common::egress_return_admission`/
    // `decap_forward_pod_admission`). Including a pod that actually lives on
    // a different node would let this node wrongly claim ownership of
    // traffic it doesn't host, defeating the gate those functions exist for.
    #[test]
    fn endpoint_hosted_on_a_different_node_is_excluded_from_pod_targets() {
        let this_node = Ipv4Addr::new(10, 0, 0, 5);
        let other_node = Ipv4Addr::new(10, 0, 0, 6);
        let svc = single_port_service(Ipv4Addr::new(10, 0, 0, 1), 80, 8080);
        let local_pod = Ipv4Addr::new(10, 244, 0, 9);
        let remote_pod = Ipv4Addr::new(10, 244, 0, 40);
        let slices = vec![EndpointSliceView {
            endpoints: vec![
                ready_endpoint(local_pod, this_node, vec![8080]),
                ready_endpoint(remote_pod, other_node, vec![8080]),
            ],
        }];

        let desired = reconcile_service(&svc, &slices, &node(this_node));

        assert_eq!(
            desired.pod_targets,
            HashSet::from([wire_ip_v6(IpAddr::V4(local_pod))]),
            "POD_TARGETS must contain only pods THIS node hosts -- a remote node's pod leaking \
             in here would misclassify that node's traffic as this node's own backend"
        );
    }

    // The ingress node pins flows to backends hosted anywhere, so its departed/
    // reused sweep must see every backend, not just the local ones, and a pod
    // that is merely unready (terminating, or flapping its probe) must stay
    // tracked or its pinned flows are cut mid-drain.
    #[test]
    fn cluster_backends_spans_nodes_keeps_unready_endpoints_and_known_uids() {
        let this_node = Ipv4Addr::new(10, 0, 0, 5);
        let other_node = Ipv4Addr::new(10, 0, 0, 6);
        let mut local = ready_endpoint(Ipv4Addr::new(10, 244, 0, 9), this_node, vec![8080]);
        local.pod_uid = Some("local".to_owned());
        let mut remote = ready_endpoint(Ipv4Addr::new(10, 244, 1, 9), other_node, vec![8080]);
        remote.pod_uid = Some("remote".to_owned());
        let mut unready = ready_endpoint(Ipv4Addr::new(10, 244, 1, 10), other_node, vec![8080]);
        unready.ready = false;
        let anonymous = ready_endpoint(Ipv4Addr::new(10, 244, 1, 11), other_node, vec![8080]);

        let backends = cluster_backends(
            [local, remote, unready, anonymous]
                .into_iter()
                .map(|ep| (ep.pod_ip, ep.pod_uid)),
        );

        let wire =
            |third: u8, last: u8| wire_ip_v6(IpAddr::V4(Ipv4Addr::new(10, 244, third, last)));
        assert_eq!(
            backends,
            HashMap::from([
                (wire(0, 9), Some("local".to_owned())),
                (wire(1, 9), Some("remote".to_owned())),
                (wire(1, 10), None),
                (wire(1, 11), None),
            ]),
            "a remote pod must be tracked or its pins on this node outlive it; an unready pod \
             must be too, or draining flows are swept the moment readiness drops"
        );
    }

    // A terminating pod on this node still receives its pinned flows' packets
    // and sends their replies; dropping it from POD_TARGETS would cut them at
    // decap/return admission and make the controller sweep them as departed.
    #[test]
    fn unready_local_endpoint_stays_in_pod_targets_so_pinned_flows_drain() {
        let this_node = Ipv4Addr::new(10, 0, 0, 5);
        let mut draining = ready_endpoint(Ipv4Addr::new(10, 244, 0, 9), this_node, vec![8080]);
        draining.ready = false;

        let targets = pod_targets_for_node(
            &[EndpointSliceView {
                endpoints: vec![draining],
            }],
            &node(this_node),
        );

        assert!(targets.contains(&wire_ip_v6(IpAddr::V4(Ipv4Addr::new(10, 244, 0, 9)))));
    }

    // node_ip matching alone must not be sufficient to admit a pod into
    // POD_TARGETS -- pod_cidr containment (or the hostNetwork pod_ip ==
    // node_ip signature) is the cross-check that catches a claim node_ip
    // can't. An arbitrary pod_ip that is neither in pod_cidr nor equal to
    // node_ip must still be rejected as a local backend.
    #[test]
    fn endpoint_reporting_a_pod_ip_outside_the_node_cidr_is_excluded_from_pod_targets() {
        let this_node = Ipv4Addr::new(10, 0, 0, 5);
        let svc = single_port_service(Ipv4Addr::new(10, 0, 0, 1), 80, 8080);
        let implausible_pod = Ipv4Addr::new(192, 168, 1, 9); // outside 10.244.0.0/16, != node_ip
        let slices = vec![EndpointSliceView {
            endpoints: vec![ready_endpoint(implausible_pod, this_node, vec![8080])],
        }];

        let desired = reconcile_service(&svc, &slices, &node(this_node));

        assert!(
            desired.pod_targets.is_empty(),
            "an out-of-cidr pod_ip that also isn't the hostNetwork signature (pod_ip == \
             node_ip) must not be admitted into POD_TARGETS -- node_ip alone is a claim an \
             untrusted EndpointSlice entry can't be trusted on without this cross-check"
        );
        assert_eq!(
            desired.rejected,
            vec![RejectedEndpoint {
                pod_ip: IpAddr::V4(implausible_pod),
                reason: "pod_ip is outside the configured --pod-cidr and is not this node's \
                         own address (hostNetwork)",
            }],
            "the exclusion above is correct anti-spoof, but it must not go back to being \
             SILENT: a misconfigured --pod-cidr rejecting every endpoint on every node with \
             nothing naming why cost a prior operator multiple sessions to diagnose \
             (a day-one baffling outage, not an edge case) -- reconcile_service's return must \
             name the offending pod_ip so the caller can log it"
        );
    }

    // A hostNetwork pod's IP IS the node IP in bare metal (no cloud LB, no
    // BGP -- beep fronts the node's physical IP), so it's outside pod_cidr
    // by construction. Before this fix that meant a hostNetwork Service
    // backend was silently excluded from POD_TARGETS on every node, and its
    // forward packets were dropped at decap admission -- reverting the
    // `|| ep.node_addrs.contains(&ep.pod_ip)` relaxation reintroduces that black hole.
    #[test]
    fn hostnetwork_endpoint_with_pod_ip_equal_to_node_ip_is_admitted_into_pod_targets() {
        let this_node = Ipv4Addr::new(10, 0, 0, 5);
        let svc = single_port_service(Ipv4Addr::new(10, 0, 0, 1), 80, 8080);
        let slices = vec![EndpointSliceView {
            endpoints: vec![ready_endpoint(this_node, this_node, vec![8080])],
        }];

        let desired = reconcile_service(&svc, &slices, &node(this_node));

        assert_eq!(
            desired.pod_targets,
            HashSet::from([wire_ip_v6(IpAddr::V4(this_node))]),
            "a hostNetwork backend (pod_ip == node_ip, outside pod_cidr) must be admitted into \
             POD_TARGETS or its forward traffic is dropped at decap on every node"
        );
    }

    fn dual_stack_endpoint(pod_ip: IpAddr, node_addrs: Vec<IpAddr>) -> Endpoint {
        Endpoint {
            pod_ip,
            // The Geneve remote is coerced to the reconciling node's (v4)
            // family regardless of which address the pod uses.
            node_ip: node_addrs[0],
            node_addrs,
            ready: true,
            ports: vec![8080],
            pod_uid: None,
        }
    }

    #[test]
    fn dual_stack_hostnetwork_v6_pod_ip_is_admitted_on_a_v4_primary_node() {
        let node_v4 = Ipv4Addr::new(10, 0, 0, 5);
        let node_v6_ip = Ipv6Addr::new(0xfd00, 0xbeef, 0x98, 0, 0, 0, 0, 4);
        let svc = single_port_service(Ipv4Addr::new(10, 0, 0, 1), 80, 8080);
        let slices = vec![EndpointSliceView {
            endpoints: vec![dual_stack_endpoint(
                IpAddr::V6(node_v6_ip),
                vec![IpAddr::V4(node_v4), IpAddr::V6(node_v6_ip)],
            )],
        }];

        let desired = reconcile_service(&svc, &slices, &node(node_v4));

        assert_eq!(
            desired.pod_targets,
            HashSet::from([wire_ip_v6(IpAddr::V6(node_v6_ip))]),
            "a dual-stack hostNetwork backend's v6 pod_ip is its own node's address and must be \
             admitted into POD_TARGETS, or the v6 return leg is never recognised as node-local"
        );
        assert!(desired.rejected.is_empty(), "nothing should be rejected");
    }

    #[test]
    fn external_ip_node_ip_selects_its_own_endpoints_and_never_a_peers() {
        let internal = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let external = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6));
        let local_pod = IpAddr::V4(Ipv4Addr::new(10, 244, 0, 9));
        let peer_pod = IpAddr::V4(Ipv4Addr::new(10, 244, 1, 9));
        let svc = single_port_service(Ipv4Addr::new(203, 0, 113, 5), 80, 8080);
        let slices = vec![EndpointSliceView {
            endpoints: vec![
                dual_stack_endpoint(local_pod, vec![internal, external]),
                dual_stack_endpoint(peer_pod, vec![peer]),
            ],
        }];

        let desired = reconcile_service(&svc, &slices, &node(Ipv4Addr::new(203, 0, 113, 5)));

        assert_eq!(
            desired.pod_targets,
            HashSet::from([wire_ip_v6(local_pod)]),
            "with --node-ip set to the ExternalIP, endpoints resolve to the InternalIP underlay \
             address; local backends must still land in POD_TARGETS (else their traffic is \
             never recognised as node-local) and a peer's backend must never"
        );
    }

    #[test]
    fn dual_stack_node_still_rejects_an_out_of_cidr_non_hostnetwork_pod() {
        let node_v4 = Ipv4Addr::new(10, 0, 0, 5);
        let node_v6_ip = Ipv6Addr::new(0xfd00, 0xbeef, 0x98, 0, 0, 0, 0, 4);
        let stranger = IpAddr::V6(Ipv6Addr::new(0xfd00, 0xbeef, 0x98, 0, 0, 0, 0, 99));
        let svc = single_port_service(Ipv4Addr::new(10, 0, 0, 1), 80, 8080);
        let slices = vec![EndpointSliceView {
            endpoints: vec![dual_stack_endpoint(
                stranger,
                vec![IpAddr::V4(node_v4), IpAddr::V6(node_v6_ip)],
            )],
        }];

        let desired = reconcile_service(&svc, &slices, &node(node_v4));

        assert!(
            desired.pod_targets.is_empty(),
            "widening hostNetwork identity to every node family must not admit an arbitrary \
             out-of-cidr pod_ip (anti-spoof)"
        );
    }

    // A v6 Service's front/backend must be stored as raw v6 octets, not passed
    // through the v4-mapped-v6 embedding a v4 address needs -- reusing that
    // embedding for a genuine v6 address would silently corrupt every field
    // into a bogus `::ffff:`-prefixed value the dataplane can't route. Also
    // exercises `Ipv6Cidr::contains` directly (the pod is admitted via the
    // CIDR disjunct, not the hostNetwork one).
    #[test]
    fn reconcile_wire_encodes_v6_addresses_as_raw_octets_not_v4_mapped() {
        let node_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5);
        let pod_cidr = Ipv6Cidr::new(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0), 64);
        let node = node_v6(node_ip, IpCidr::V6(pod_cidr));
        let front_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let pod_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 9);
        let svc = single_port_service_v6(front_ip, 80, 8080);
        let slices = vec![EndpointSliceView {
            endpoints: vec![ready_endpoint_v6(pod_ip, node_ip, vec![8080])],
        }];

        let desired = reconcile_service(&svc, &slices, &node);

        assert_eq!(
            desired.fronts.len(),
            1,
            "exactly one front port was configured, so exactly one front is expected"
        );
        let (key, backend) = desired.backends().into_iter().next().unwrap();
        assert_eq!(
            key.front_ip,
            front_ip.octets(),
            "a v6 front must be stored as its own raw octets, not re-embedded via \
             ipv4_mapped_v6 -- a v6-only front would otherwise resolve to a bogus address"
        );
        assert!(
            unmap_ipv4(&key.front_ip).is_none(),
            "a genuine v6 front must never unmap as if it were a v4-mapped one, or it would \
             collide with a v4 front that maps to the same 32 low bits"
        );
        assert_eq!(
            backend.pod_ip,
            pod_ip.octets(),
            "a v6 backend pod_ip must stay raw octets -- the dataplane would stamp the wrong \
             Geneve pod-identifier option otherwise"
        );
        assert_eq!(
            backend.backend_node_ip,
            node_ip.octets(),
            "a v6 backend_node_ip must stay raw octets: like the v4 case this field is never \
             passed through wire_ip, but a v6 address also has no separate host/wire form to \
             convert in the first place"
        );
        assert_eq!(
            desired.pod_targets,
            HashSet::from([pod_ip.octets()]),
            "POD_TARGETS must admit a v6 pod inside a v6 pod_cidr the same way a v4 one inside \
             a v4 pod_cidr is admitted"
        );
    }

    // bare metal has no cloud LB/BGP virtual IP, so a hostNetwork pod's IP IS
    // the node IP regardless of family -- an operator running today's
    // v4-only --pod-cidr must not lose v6 hostNetwork admission because of
    // it: `IpCidr::contains` returns false across families instead of
    // wrongly matching, and `is_admitted`'s hostNetwork disjunct still
    // admits the pod.
    #[test]
    fn hostnetwork_v6_endpoint_is_admitted_despite_an_ipv4_only_pod_cidr() {
        let node_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5);
        let node = node_v6(node_ip, cluster_pod_cidr());
        let svc = single_port_service_v6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 80, 8080);
        let slices = vec![EndpointSliceView {
            endpoints: vec![ready_endpoint_v6(node_ip, node_ip, vec![8080])],
        }];

        let desired = reconcile_service(&svc, &slices, &node);

        assert_eq!(
            desired.pod_targets,
            HashSet::from([node_ip.octets()]),
            "a v6 hostNetwork backend must be admitted into POD_TARGETS even though the \
             configured pod_cidr is v4-only -- rejecting every v6 hostNetwork pod on every \
             node would repeat the pre-dual-stack POD_TARGETS black hole, just for v6 instead \
             of v4"
        );
    }

    // The anti-spoof rejection (`is_admitted`'s doc comment) must hold for v6
    // too: a v6 pod_ip that is neither inside any configured pod_cidr nor
    // the hostNetwork signature must still be excluded, the same as an
    // implausible v4 one is.
    #[test]
    fn v6_pod_ip_outside_pod_cidr_and_not_hostnetwork_is_rejected() {
        let node_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5);
        let node = node_v6(node_ip, cluster_pod_cidr());
        let svc = single_port_service_v6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 80, 8080);
        let implausible_pod = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 99);
        let slices = vec![EndpointSliceView {
            endpoints: vec![ready_endpoint_v6(implausible_pod, node_ip, vec![8080])],
        }];

        let desired = reconcile_service(&svc, &slices, &node);

        assert!(
            desired.pod_targets.is_empty(),
            "a v6 pod_ip outside every configured pod_cidr and not equal to node_ip must not \
             be admitted -- an untrusted EndpointSlice entry's node_ip claim must stay \
             cross-checked for v6 the same way it is for v4"
        );
        assert_eq!(
            desired.rejected,
            vec![RejectedEndpoint {
                pod_ip: IpAddr::V6(implausible_pod),
                reason: "pod_ip is outside the configured --pod-cidr and is not this node's \
                         own address (hostNetwork)",
            }],
            "the exclusion must name the offending v6 pod_ip too, or the pod-cidr \
             misconfiguration diagnostic (`endpoint_reporting_a_pod_ip_outside_the_node_cidr_\
             is_excluded_from_pod_targets`'s doc comment) silently stops working once a \
             cluster goes dual-stack"
        );
    }

    // A Service scaled to zero, or mid-rollout with no ready pods yet, must
    // not resolve to a stale backend -- FRONT_META keeping a PREVIOUS entry
    // here would misroute client traffic to a pod that's no longer healthy.
    #[test]
    fn service_with_no_ready_endpoints_produces_no_entries() {
        let node_ip = Ipv4Addr::new(10, 0, 0, 5);
        let svc = single_port_service(Ipv4Addr::new(10, 0, 0, 1), 80, 8080);
        let mut not_ready = ready_endpoint(Ipv4Addr::new(10, 244, 0, 9), node_ip, vec![8080]);
        not_ready.ready = false;
        let slices = vec![EndpointSliceView {
            endpoints: vec![not_ready],
        }];

        let desired = reconcile_service(&svc, &slices, &node(node_ip));

        assert!(
            desired.fronts.is_empty(),
            "no ready endpoint exists, so FRONT_META must get no entry for this front -- \
             fabricating one would route to an unready pod"
        );
    }

    // A dual-stack Service gets one front per family; a v6 front pointing at
    // a v4 pod makes every v6 client silently time out (the reply can't be
    // sent back in the client's family).
    #[test]
    fn dual_stack_pod_gets_each_front_programmed_with_its_own_family_address() {
        let v4_pod = Ipv4Addr::new(192, 168, 104, 14);
        let v6_pod: Ipv6Addr = "fd00:beef:98::4".parse().unwrap();
        let node_v4 = Ipv4Addr::new(10, 0, 0, 5);
        let node_v6_ip: Ipv6Addr = "fd00:beef:98::5".parse().unwrap();
        let slices = vec![
            EndpointSliceView {
                endpoints: vec![ready_endpoint(v4_pod, node_v4, vec![80])],
            },
            EndpointSliceView {
                endpoints: vec![ready_endpoint_v6(v6_pod, node_v6_ip, vec![80])],
            },
        ];
        let node_ctx = node(node_v4);

        let v4_front = single_port_service(Ipv4Addr::new(10, 0, 0, 1), 8080, 80);
        let v6_front = single_port_service_v6("fd00:beef:98::3".parse().unwrap(), 8080, 80);

        let d4 = reconcile_service(&v4_front, &slices, &node_ctx);
        let d6 = reconcile_service(&v6_front, &slices, &node_ctx);

        let b4 = d4
            .backends()
            .into_values()
            .next()
            .expect("v4 front backend");
        let b6 = d6
            .backends()
            .into_values()
            .next()
            .expect("v6 front backend");
        assert_eq!(
            b4.pod_ip,
            wire_ip_v6(IpAddr::V4(v4_pod)),
            "v4 front must get the v4 pod"
        );
        assert_eq!(
            b6.pod_ip,
            wire_ip_v6(IpAddr::V6(v6_pod)),
            "v6 front must get the v6 pod; a v4 pod here makes v6 clients time out"
        );
    }

    #[test]
    fn dual_stack_service_with_only_v4_endpoints_gets_no_v6_front_entry() {
        let node_v4 = Ipv4Addr::new(10, 0, 0, 5);
        let slices = vec![EndpointSliceView {
            endpoints: vec![ready_endpoint(
                Ipv4Addr::new(10, 244, 0, 9),
                node_v4,
                vec![80],
            )],
        }];
        let v6_front = single_port_service_v6("fd00:beef:98::3".parse().unwrap(), 8080, 80);

        let desired = reconcile_service(&v6_front, &slices, &node(node_v4));

        assert!(
            desired.fronts.is_empty(),
            "a v6 front with no v6 endpoint must fail closed; a cross-family backend would \
             silently time out every v6 client"
        );
        assert_eq!(
            ports_without_same_family_endpoint(&v6_front, &slices).len(),
            1,
            "this front is unprogrammed because of a family mismatch, so the caller must be \
             told to WARN -- otherwise a v6 front silently never routes"
        );
    }

    #[test]
    fn a_front_with_no_ready_endpoints_at_all_is_not_reported_as_a_family_mismatch() {
        // A Service still rolling out has no endpoints in either family; a
        // WARN there would fire on every normal deploy and bury the real one.
        let svc = single_port_service(Ipv4Addr::new(10, 0, 0, 1), 80, 8080);
        let slices = vec![EndpointSliceView { endpoints: vec![] }];

        assert!(ports_without_same_family_endpoint(&svc, &slices).is_empty());
    }

    #[test]
    fn dual_stack_fronts_each_get_one_endpoint_with_their_own_target_port() {
        // Both families of one Service programmed from one slice set: each
        // front must carry exactly one endpoint of its own family and the
        // resolved wire-order target port.
        let node_v4 = Ipv4Addr::new(10, 0, 0, 5);
        let node_v6: Ipv6Addr = "fd00::5".parse().unwrap();
        let v4_pod = Ipv4Addr::new(10, 244, 0, 9);
        let v6_pod: Ipv6Addr = "fd00:244::9".parse().unwrap();
        let slices = vec![EndpointSliceView {
            endpoints: vec![
                ready_endpoint(v4_pod, node_v4, vec![8080]),
                ready_endpoint_v6(v6_pod, node_v6, vec![8080]),
            ],
        }];
        let v4_front = single_port_service(Ipv4Addr::new(10, 0, 0, 1), 80, 8080);
        let v6_front = single_port_service_v6("fd00:beef::1".parse().unwrap(), 80, 8080);

        for (front, expected_pod) in [
            (&v4_front, IpAddr::V4(v4_pod)),
            (&v6_front, IpAddr::V6(v6_pod)),
        ] {
            let desired = reconcile_service(front, &slices, &node(node_v4));
            let f = desired.fronts.values().next().expect("one front");
            assert_eq!(
                f.endpoints.len(),
                1,
                "count must be 1 until selection exists"
            );
            assert_eq!(f.endpoints[0].target_port, wire_port(8080));
            assert_eq!(f.endpoints[0].backend.pod_ip, wire_ip_v6(expected_pod));
        }
    }
}
