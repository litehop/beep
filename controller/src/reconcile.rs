//! Pure (Service, EndpointSlices, NodeContext) -> desired-map-entries
//! reconciliation, plus a pure map diff. No I/O, no k8s client, no aya --
//! `ServiceView`/`EndpointSliceView` are plain parsed views the eventual
//! watch layer fills in from real API objects. Kept pure so a wrong
//! map-population decision (stale entry, missed update, wrong backend) is
//! caught by a fixture-driven unit test instead of only showing up as
//! silent misrouting against a live cluster.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::net::Ipv4Addr;

use beep_common::{wire_ip, wire_port, VipBackend, VipKey};

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
/// kernel boundary, so it doesn't belong in `beep-common` (unlike `VipKey`/
/// `VipBackend`, whose byte layout must stay identical on both sides).
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
    pub node_ip: Ipv4Addr,
    pub pod_cidr: Ipv4Cidr,
}

/// One `Service.spec.ports[]` entry: `port` is the VIP-facing front port,
/// `target_port` the numeric container port. `TARGET_PORTS` (`beep-common`)
/// keys on the front tuple alone, so this dataplane assumes one numeric
/// target port per front regardless of which backend answers it -- a
/// container-port-by-name Service would need to be resolved to a number
/// before reaching this type, same as `beep-ebpf`'s existing map shape
/// requires.
#[derive(Clone, Copy, Debug)]
pub struct ServicePort {
    pub port: u16,
    pub protocol: Protocol,
    pub target_port: u16,
}

/// A `type=LoadBalancer` Service's parsed view: front VIP plus its ports.
#[derive(Clone, Debug)]
pub struct ServiceView {
    pub vip_ip: Ipv4Addr,
    pub ports: Vec<ServicePort>,
}

/// One `EndpointSlice` endpoint. `node_ip` is the IP of the node hosting
/// this pod (Phase B's watch resolves the real `EndpointSlice.endpoints[].
/// nodeName` hostname to this IP via a `Node` object lookup before building
/// this view) -- needed verbatim as `VipBackend.backend_node_ip`, the Geneve
/// tunnel remote for this pod's forward leg. `ports` are this endpoint's
/// resolved numeric ports; an endpoint missing a `ServicePort`'s
/// `target_port` here is excluded as a backend candidate for that specific
/// front (e.g. a Pod mid-rollout that hasn't started listening on a newly
/// added container port yet).
#[derive(Clone, Debug)]
pub struct Endpoint {
    pub pod_ip: Ipv4Addr,
    pub node_ip: Ipv4Addr,
    pub ready: bool,
    pub ports: Vec<u16>,
}

/// One `EndpointSlice` object. A Service can be backed by more than one of
/// these (sharding once a Service exceeds ~100 endpoints, or per-zone
/// slicing), so `reconcile_service` takes a slice of these, not a single one.
#[derive(Clone, Debug)]
pub struct EndpointSliceView {
    pub endpoints: Vec<Endpoint>,
}

/// Desired `VIP_MAP`/`TARGET_PORTS`/`POD_TARGETS` contents for one Service,
/// keyed exactly like the maps themselves so `diff` can compare this against
/// a previous reconcile's output (or the maps' actual current contents) with
/// no extra translation.
#[derive(Default)]
pub struct DesiredEntries {
    pub vip_map: HashMap<VipKey, VipBackend>,
    pub target_ports: HashMap<VipKey, u16>,
    pub pod_targets: HashSet<u32>,
    /// Whether `vip_map`/`target_ports` were computed from a fully-known
    /// node set. `WatchState::desired` (the only real producer of an
    /// aggregate `DesiredEntries`) sets this to `false` while the initial
    /// Node LIST hasn't completed yet, so `PinnedMaps::apply` knows an empty
    /// `vip_map`/`target_ports` here means "node set not known yet", not
    /// "no fronts should exist" -- diffing against the latter would delete
    /// every already-programmed front that survived a controller restart.
    pub fronts_known: bool,
}

fn front_key(vip_ip: Ipv4Addr, port: &ServicePort) -> VipKey {
    VipKey {
        vip_ip: wire_ip(u32::from(vip_ip)),
        vip_port: wire_port(port.port),
        proto: port.protocol.as_ip_proto(),
        _pad: 0,
    }
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

    // POD_TARGETS is this node's own local serving-set, port-agnostic by
    // design (`beep_common::egress_return_admission`'s doc comment) --
    // membership must never depend on which front port an endpoint answers,
    // only on whether THIS node hosts it and is ready to serve it. An
    // endpoint is admitted if its pod_ip is in this node's pod_cidr OR it
    // carries the hostNetwork signature (pod_ip == node_ip): in bare metal
    // (no cloud LB, no BGP -- beep fronts the node's physical IP) a
    // hostNetwork pod's IP IS the node IP, so without this a Service backed
    // by a hostNetwork pod would be silently excluded here and every
    // forward packet dropped at decap admission. Guarding which control-
    // plane ports (6443/10250/2379/...) may be fronted this way is
    // deliberately out of scope -- that's perimeter/firewall policy
    // (ufw/NetworkPolicy), not the load balancer's job. Arbitrary out-of-
    // cidr pod_ips that are also != node_ip are still rejected below.
    for ep in &endpoints {
        if ep.ready
            && ep.node_ip == node.node_ip
            && (node.pod_cidr.contains(ep.pod_ip) || ep.pod_ip == ep.node_ip)
        {
            desired.pod_targets.insert(wire_ip(u32::from(ep.pod_ip)));
        }
    }

    // VIP_MAP/TARGET_PORTS are NOT node-scoped (any node can be ingress for
    // any VIP, mirroring the loader's fixture population), so backend
    // candidates are drawn from every endpoint across every slice --
    // regardless of which node hosts them -- not just this node's own.
    for port in &svc.ports {
        let mut candidates: Vec<&Endpoint> = endpoints
            .iter()
            .copied()
            .filter(|e| e.ready && e.ports.contains(&port.target_port))
            .collect();
        // Decision #5 (single backend per front): today's VIP_MAP schema
        // holds exactly one backend per front, so pick deterministically --
        // lowest pod IP -- rather than arbitrarily (e.g. HashMap iteration
        // order), so two reconciles over the same input always agree and a
        // fixture-driven test can assert a specific outcome. This is a
        // placeholder for real multi-endpoint selection, tracked separately;
        // it does not attempt to spread load across endpoints.
        candidates.sort_by_key(|e| e.pod_ip);
        let Some(backend) = candidates.first() else {
            continue;
        };

        let key = front_key(svc.vip_ip, port);
        desired.vip_map.insert(
            key,
            VipBackend {
                // Host-native, not wire_ip: the kernel's own
                // bpf_tunnel_key.remote_ipv4 set/get converts this field
                // itself (`src/main.rs`'s `populate_fixtures` comment).
                backend_node_ip: u32::from(backend.node_ip),
                pod_ip: wire_ip(u32::from(backend.pod_ip)),
            },
        );
        desired
            .target_ports
            .insert(key, wire_port(port.target_port));
    }

    desired
}

/// A single map mutation `diff` decides is needed to move `current` to
/// `desired`. Left generic over `K`/`V` so the same logic serves `VIP_MAP`
/// (`VipKey` -> `VipBackend`), `TARGET_PORTS` (`VipKey` -> `u16`), and any
/// `HashMap`-shaped map this dataplane grows later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapOp<K, V> {
    Upsert(K, V),
    Delete(K),
}

/// Diffs `current` (a map's actual live contents) against `desired` (a fresh
/// `reconcile_service` result) into the minimal set of writes/deletes that
/// gets `current` to match `desired` -- an unchanged entry produces no op,
/// so a reconcile tick that changes nothing costs no syscalls once a caller
/// applies these.
///
/// Takes an explicit `values_equal` closure rather than requiring
/// `V: PartialEq`: `VipBackend` (`VIP_MAP`'s value type) doesn't implement
/// it, and adding it is a `beep-common` type-definition change out of this
/// crate's scope -- pinning `diff` to that bound would make it unusable for
/// the very map this reconciliation exists to keep correct. See
/// `vip_backend_eq` for `VIP_MAP`'s comparison; plain types (`u16`, `u8`,
/// ...) can pass `|a, b| a == b`.
pub fn diff<K, V>(
    current: &HashMap<K, V>,
    desired: &HashMap<K, V>,
    values_equal: impl Fn(&V, &V) -> bool,
) -> Vec<MapOp<K, V>>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    let mut ops = Vec::new();
    for (k, v) in desired {
        let unchanged = current
            .get(k)
            .is_some_and(|existing| values_equal(existing, v));
        if !unchanged {
            ops.push(MapOp::Upsert(k.clone(), v.clone()));
        }
    }
    for k in current.keys() {
        if !desired.contains_key(k) {
            ops.push(MapOp::Delete(k.clone()));
        }
    }
    ops
}

/// `VipBackend` equality for `diff`'s `values_equal` closure -- field-wise,
/// since the type itself doesn't derive `PartialEq` (see `diff`'s doc).
pub fn vip_backend_eq(a: &VipBackend, b: &VipBackend) -> bool {
    a.backend_node_ip == b.backend_node_ip && a.pod_ip == b.pod_ip
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cluster_pod_cidr() -> Ipv4Cidr {
        Ipv4Cidr::new(Ipv4Addr::new(10, 244, 0, 0), 16)
    }

    fn node(ip: Ipv4Addr) -> NodeContext {
        NodeContext {
            node_ip: ip,
            pod_cidr: cluster_pod_cidr(),
        }
    }

    fn single_port_service(vip_ip: Ipv4Addr, port: u16, target_port: u16) -> ServiceView {
        ServiceView {
            vip_ip,
            ports: vec![ServicePort {
                port,
                protocol: Protocol::Tcp,
                target_port,
            }],
        }
    }

    fn ready_endpoint(pod_ip: Ipv4Addr, node_ip: Ipv4Addr, ports: Vec<u16>) -> Endpoint {
        Endpoint {
            pod_ip,
            node_ip,
            ready: true,
            ports,
        }
    }

    // A conntrack keying bug corrupts routing silently instead of failing
    // loudly (beep-common's own module doc), so the exact wire bytes this
    // reconcile fn hands to VIP_MAP/TARGET_PORTS are pinned here the same
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
            desired.vip_map.len(),
            1,
            "exactly one front port was configured, so exactly one VIP_MAP entry is expected"
        );
        let (key, backend) = desired.vip_map.iter().next().unwrap();
        assert_eq!(
            key.vip_ip.to_le_bytes(),
            [10, 0, 0, 1],
            "VIP wire encoding regressed vs beep_common::wire_ip's dotted-octet pin -- a \
             regression here corrupts every packet matched against this front"
        );
        assert_eq!(
            key.vip_port.to_le_bytes(),
            [0, 80],
            "VIP port wire encoding regressed vs beep_common::wire_port's network-byte-order pin"
        );
        assert_eq!(
            backend.pod_ip.to_le_bytes(),
            [10, 244, 0, 9],
            "backend pod_ip wire encoding regressed -- the dataplane would stamp the wrong \
             Geneve pod-identifier option"
        );
        assert_eq!(
            backend.backend_node_ip,
            u32::from(node_ip),
            "backend_node_ip must stay host-native (unconverted): the kernel's own \
             bpf_tunnel_key.remote_ipv4 set/get converts it, so pre-converting here would \
             double-flip the byte order and misdirect the Geneve tunnel"
        );
        let target_port = desired
            .target_ports
            .get(key)
            .expect("target port must be recorded");
        assert_eq!(
            target_port.to_le_bytes(),
            [0x1F, 0x90],
            "target port wire encoding regressed vs beep_common::wire_port's pin (8080)"
        );
    }

    // "add": a Service's first-ever reconcile, diffed against an empty
    // (never-before-populated) map -- this is what a freshly created
    // type=LoadBalancer Service must produce, or new Services silently never
    // get routed to.
    #[test]
    fn new_service_diffs_to_upsert_ops_against_an_empty_map() {
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

        let ops = diff(&HashMap::new(), &desired.target_ports, |a, b| a == b);
        assert_eq!(
            ops.len(),
            1,
            "a brand-new front must produce exactly one TARGET_PORTS write"
        );
        assert!(
            matches!(&ops[0], MapOp::Upsert(_, port) if *port == wire_port(8080)),
            "a new Service's first reconcile must upsert its target port, not skip it"
        );
    }

    // "update": the resolved backend changes (e.g. a rolling deploy replaces
    // the previously-picked pod) -- the SAME front key must get an Upsert to
    // the new backend, not silently keep pointing at the old (now-gone) pod.
    #[test]
    fn backend_change_diffs_to_an_upsert_with_the_new_backend() {
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

        let ops = diff(&before.vip_map, &after.vip_map, vip_backend_eq);
        assert_eq!(
            ops.len(),
            1,
            "the front key is unchanged, so this must be a single Upsert, not a Delete+Upsert \
             pair -- a stale VIP_MAP entry between the two would blackhole traffic"
        );
        match &ops[0] {
            MapOp::Upsert(_, backend) => {
                assert_eq!(
                    backend.backend_node_ip,
                    u32::from(other_node_ip),
                    "the diff must point at the NEW backend's node, or traffic keeps going to \
                     the pod that no longer exists"
                );
            }
            MapOp::Delete(_) => panic!("backend replacement must upsert, not delete, the front"),
        }
    }

    // "delete (Service gone)": once a Service is removed, the caller diffs
    // its last-known desired map against an empty one. A stale VIP_MAP/
    // TARGET_PORTS entry surviving Service deletion would keep routing
    // client traffic at a backend that's since been reassigned to something
    // else entirely.
    #[test]
    fn removed_service_diffs_to_delete_ops_for_every_front() {
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

        let vip_ops = diff(&desired.vip_map, &HashMap::new(), vip_backend_eq);
        assert_eq!(vip_ops.len(), 1);
        assert!(
            matches!(&vip_ops[0], MapOp::Delete(_)),
            "a removed Service's front must be deleted from VIP_MAP, not left resolving to a \
             now-meaningless backend"
        );

        let port_ops = diff(&desired.target_ports, &HashMap::new(), |a, b| a == b);
        assert_eq!(port_ops.len(), 1);
        assert!(
            matches!(&port_ops[0], MapOp::Delete(_)),
            "the matching TARGET_PORTS entry must be deleted too, or a future front reusing \
             this VIP:port would inherit a stale target port"
        );
    }

    // A multi-port Service (e.g. HTTP + metrics on one Pod) must resolve
    // each exposed port independently -- collapsing to one VIP_MAP entry
    // would silently drop routing for every port after the first.
    #[test]
    fn multi_port_service_gets_one_front_per_port_from_the_same_pod() {
        let node_ip = Ipv4Addr::new(10, 0, 0, 5);
        let pod_ip = Ipv4Addr::new(10, 244, 0, 9);
        let svc = ServiceView {
            vip_ip: Ipv4Addr::new(10, 0, 0, 1),
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
            desired.vip_map.len(),
            2,
            "each Service port must resolve to its own VIP_MAP entry, not one that shadows \
             the other"
        );
        assert_eq!(desired.target_ports.len(), 2);
        for backend in desired.vip_map.values() {
            assert_eq!(
                backend.pod_ip.to_le_bytes(),
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

        let (_, backend) = desired.vip_map.iter().next().unwrap();
        assert_eq!(
            backend.pod_ip.to_le_bytes(),
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
            HashSet::from([wire_ip(u32::from(local_pod))]),
            "POD_TARGETS must contain only pods THIS node hosts -- a remote node's pod leaking \
             in here would misclassify that node's traffic as this node's own backend"
        );
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
    }

    // A hostNetwork pod's IP IS the node IP in bare metal (no cloud LB, no
    // BGP -- beep fronts the node's physical IP), so it's outside pod_cidr
    // by construction. Before this fix that meant a hostNetwork Service
    // backend was silently excluded from POD_TARGETS on every node, and its
    // forward packets were dropped at decap admission -- reverting the
    // `|| ep.pod_ip == ep.node_ip` relaxation reintroduces that black hole.
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
            HashSet::from([wire_ip(u32::from(this_node))]),
            "a hostNetwork backend (pod_ip == node_ip, outside pod_cidr) must be admitted into \
             POD_TARGETS or its forward traffic is dropped at decap on every node"
        );
    }

    // A Service scaled to zero, or mid-rollout with no ready pods yet, must
    // not resolve to a stale backend -- VIP_MAP keeping a PREVIOUS entry
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
            desired.vip_map.is_empty(),
            "no ready endpoint exists, so VIP_MAP must get no entry for this front -- \
             fabricating one would route to an unready pod"
        );
        assert!(desired.target_ports.is_empty());
        assert!(desired.pod_targets.is_empty());
    }

    // diff() is the exact machinery translating two successive reconcile
    // passes into the actual map writes/deletes Phase B applies -- a bug
    // here (missing a delete, or reissuing an unchanged upsert) either
    // leaves stale routes alive or wastes a syscall on every reconcile tick.
    #[test]
    fn diff_upserts_added_and_changed_entries_deletes_removed_ones_and_skips_unchanged() {
        let mut current = HashMap::new();
        current.insert(1u32, 10u8); // unchanged below
        current.insert(2u32, 20u8); // changed below
        current.insert(3u32, 30u8); // removed below

        let mut desired = HashMap::new();
        desired.insert(1u32, 10u8); // unchanged
        desired.insert(2u32, 99u8); // changed value
        desired.insert(4u32, 40u8); // newly added

        let mut ops = diff(&current, &desired, |a, b| a == b);
        ops.sort_by_key(|op| match op {
            MapOp::Upsert(k, _) => (*k, 0),
            MapOp::Delete(k) => (*k, 1),
        });

        assert_eq!(
            ops,
            vec![MapOp::Upsert(2, 99), MapOp::Delete(3), MapOp::Upsert(4, 40),],
            "key 1 is unchanged and must produce no op; key 2 changed value and must upsert; \
             key 3 is gone and must delete; key 4 is new and must upsert"
        );
    }
}
