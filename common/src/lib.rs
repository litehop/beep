//! Pure-Rust conntrack key encode/decode + backend source-port remap logic
//! for the beep eBPF dataplane, extracted out of `beep-ebpf` so it
//! is unit-testable outside a kernel (a conntrack keying bug is not
//! verifiable by inspection alone). Shared by `beep-ebpf` as a no_std
//! dependency; `cargo test` here runs natively with `std`'s test harness
//! (see `Cargo.toml`).
//!
//! Design settled in `docs/design/ebpf-lb-dataplane.md`'s "Conntrack
//! & affinity" section and its "Settled wire-format decisions".
#![cfg_attr(not(test), no_std)]

/// TCP/UDP flow-affinity key: IPv6-primary, 37 bytes (16+16+2+2+1), no
/// padding. A flat byte array rather than a `#[repr(C)]` struct: the kernel
/// hashes/compares a `BPF_MAP_TYPE_*_HASH` key's raw bytes, and a padded
/// struct leaves compiler-inserted alignment gaps as uninitialized garbage
/// that differs between independent call sites even when every named field
/// matches (the exact bug `beep-ebpf`'s old `FlowKey` hit on a live
/// kernel). A byte array has no such gap by construction.
pub const TCP_FLOW_KEY_LEN: usize = 37;
pub type TcpFlowKey = [u8; TCP_FLOW_KEY_LEN];

/// Embeds an IPv4 address (already in the wire-token representation --
/// exact bytes as read off the packet, see `beep-ebpf`'s module doc)
/// as an IPv4-mapped IPv6 address (RFC 4291 SS2.5.5.2: `::ffff:a.b.c.d`),
/// so one 37-byte key shape covers both address families -- IPv4 flows and
/// real IPv6 flows never collide, since a genuine IPv6 address can't carry
/// the `::ffff:0:0/96` prefix this produces.
pub fn ipv4_mapped_v6(wire_ip: u32) -> [u8; 16] {
    let mut v6 = [0u8; 16];
    v6[10] = 0xff;
    v6[11] = 0xff;
    v6[12..16].copy_from_slice(&wire_ip.to_ne_bytes());
    v6
}

/// Inverse of `ipv4_mapped_v6`: recovers the original wire-token IPv4
/// address if `v6` carries the `::ffff:0:0/96` prefix, `None` if it's a
/// genuine (non-mapped) IPv6 address.
pub fn unmap_ipv4(v6: &[u8; 16]) -> Option<u32> {
    if v6[0..10] == [0u8; 10] && v6[10..12] == [0xff, 0xff] {
        Some(u32::from_ne_bytes(v6[12..16].try_into().unwrap()))
    } else {
        None
    }
}

/// Packs a TCP/UDP flow key. `client_port`/`other_port` are wire tokens
/// (see module doc); `other` is the VIP on the forward/ingress role or the
/// backend Pod on the reverse/backend role (`ebpf-lb-dataplane.md`).
pub fn encode_tcp_flow_key(
    client_ip: [u8; 16],
    client_port: u16,
    other_ip: [u8; 16],
    other_port: u16,
    proto: u8,
) -> TcpFlowKey {
    let mut key = [0u8; TCP_FLOW_KEY_LEN];
    key[0..16].copy_from_slice(&client_ip);
    key[16..32].copy_from_slice(&other_ip);
    key[32..34].copy_from_slice(&client_port.to_ne_bytes());
    key[34..36].copy_from_slice(&other_port.to_ne_bytes());
    key[36] = proto;
    key
}

/// Unpacks a TCP/UDP flow key; the exact inverse of `encode_tcp_flow_key`.
pub fn decode_tcp_flow_key(key: &TcpFlowKey) -> ([u8; 16], u16, [u8; 16], u16, u8) {
    let client_ip: [u8; 16] = key[0..16].try_into().unwrap();
    let other_ip: [u8; 16] = key[16..32].try_into().unwrap();
    let client_port = u16::from_ne_bytes(key[32..34].try_into().unwrap());
    let other_port = u16::from_ne_bytes(key[34..36].try_into().unwrap());
    let proto = key[36];
    (client_ip, client_port, other_ip, other_port, proto)
}

/// Discriminates entries in `beep-ebpf`'s unified flow table
/// (`FLOW_TABLE`): forward-role (ingress-node, established-affinity),
/// reverse-role (backend-node, un-DNAT conntrack), and port-memo-role
/// (backend-node, persisted backend-src-port remap decision) entries share
/// one physical `LRU_HASH` keyed on the same 5-tuple shape for a given flow,
/// so this explicit tag byte is the only thing keeping the roles from
/// colliding -- deliberately NOT VIP-vs-pod-CIDR address disjointness, which
/// does not hold for a hostNetwork Pod (`docs/design/ebpf-lb-dataplane.md`'s
/// disjointness correction; a hostNetwork Pod's IP can equal a VIP, which is
/// the exact misdelivery this tag exists to prevent). The same disjointness
/// gap is why `PortMemo` needs its own tag rather than reusing `Reverse`'s:
/// address-based aliasing avoidance was never sound, and the port-memo key
/// (client, real client port, pod, target port) is a legitimate 5-tuple a
/// `Reverse`-tagged entry could also carry for a different flow.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowDirection {
    Forward = 0,
    Reverse = 1,
    /// Persists `resolve_backend_src_port`'s decision for a flow keyed on
    /// its natural (client, real client port, pod, target port) tuple --
    /// see `backend_port_resolution`'s doc comment for why re-deriving the
    /// port from scratch on every packet is unsafe under LRU eviction.
    PortMemo = 2,
}

/// `encode_tcp_flow_key`'s 37 bytes plus one `FlowDirection` tag byte. Only
/// `FLOW_TABLE` (the merged forward+reverse table) uses this wider key --
/// `FWD_PENDING` (the flood-exposed admission tier, never merged: eviction
/// there must never reach an established entry) keeps the plain,
/// untagged `TcpFlowKey`. Free: BPF pads an `LRU_HASH` element's key size up
/// to a multiple of 8 regardless, so 37->38 costs the same bytes_memlock as
/// 37, confirmed by measuring both against a live kernel.
pub const FLOW_KEY_LEN: usize = TCP_FLOW_KEY_LEN + 1;
pub type FlowKey = [u8; FLOW_KEY_LEN];

/// Packs a `FlowKey` for `FLOW_TABLE`: `encode_tcp_flow_key`'s bytes plus the
/// direction tag that keeps a forward-role and reverse-role entry for the
/// same 5-tuple from aliasing each other in the shared table.
pub fn encode_flow_key(
    client_ip: [u8; 16],
    client_port: u16,
    other_ip: [u8; 16],
    other_port: u16,
    proto: u8,
    direction: FlowDirection,
) -> FlowKey {
    let mut key = [0u8; FLOW_KEY_LEN];
    key[0..TCP_FLOW_KEY_LEN].copy_from_slice(&encode_tcp_flow_key(
        client_ip,
        client_port,
        other_ip,
        other_port,
        proto,
    ));
    key[TCP_FLOW_KEY_LEN] = direction as u8;
    key
}

/// QUIC flow-affinity key: a fixed-length prefix of the Destination
/// Connection ID the LB itself mints into the RFC 9000 SS17.2 Initial-packet
/// DCID -- not derived from the client's address, so it carries no
/// TCP-style collision risk (`ebpf-lb-dataplane.md`). Fixed-length because
/// the 1-RTT short header (RFC 9000 SS17.3.1) has no length field; 8 bytes
/// is this dataplane's externally-agreed length (one hop, no chained-LB
/// scheme needed yet).
pub const QUIC_DCID_KEY_LEN: usize = 8;
pub type QuicDcidKey = [u8; QUIC_DCID_KEY_LEN];

/// Packs a QUIC DCID key from a minted DCID's leading bytes. Zero-pads a
/// shorter-than-`QUIC_DCID_KEY_LEN` input rather than panicking -- the LB
/// always mints exactly this length in practice, but a pure function
/// should be total.
pub fn encode_quic_dcid_key(dcid_prefix: &[u8]) -> QuicDcidKey {
    let mut key = [0u8; QUIC_DCID_KEY_LEN];
    let n = dcid_prefix.len().min(QUIC_DCID_KEY_LEN);
    key[..n].copy_from_slice(&dcid_prefix[..n]);
    key
}

/// Unpacks a QUIC DCID key; the exact inverse of `encode_quic_dcid_key` for
/// a full-length input.
pub fn decode_quic_dcid_key(key: &QuicDcidKey) -> [u8; QUIC_DCID_KEY_LEN] {
    *key
}

/// Linux ARPHRD_* value (`uapi/linux/if_arp.h`) for a real Ethernet-framed
/// device -- the only uplink type `beep-ebpf`'s uplink hooks treat as
/// carrying a 14-byte L2 header.
pub const ARPHRD_ETHER: u16 = 1;

/// How many L2 header bytes `beep-ebpf`'s uplink hooks (`try_uplink_ingress`,
/// `try_uplink_egress_return`) must skip before the IPv4 header starts, given
/// the uplink interface's ARPHRD type -- resolved once by the userspace
/// loader at load time (the no_std eBPF program has no syscall to query this
/// itself) and written into the `CONFIG` map. A real NIC/veth (`ARPHRD_ETHER`)
/// carries a 14-byte Ethernet header; a WireGuard (or any other L3-only/tun)
/// uplink delivers the raw IP packet with none at all -- treating it as 14
/// anyway reads 14 bytes into the middle of the real IP header, the
/// EtherType/version check never matches, and the dataplane silently no-ops
/// on every packet on that uplink (the bug this function exists to prevent a
/// regression of).
pub fn uplink_l2_header_len(arphrd_type: u16) -> u32 {
    if arphrd_type == ARPHRD_ETHER {
        14
    } else {
        0
    }
}

/// Converts a host-order value (e.g. `u32::from(Ipv4Addr)`) into the "raw
/// wire token" representation `beep-ebpf` compares packet bytes against
/// verbatim (see `beep-ebpf`'s module doc for why this conversion exists
/// and why it's applied exactly once, at the map-population boundary).
pub fn wire_ip(ip: u32) -> u32 {
    ip.to_be()
}

pub fn wire_port(port: u16) -> u16 {
    port.to_be()
}

/// Loader-populated VIP:PORT(+proto) front-tuple key -- shared by
/// `beep-ebpf`'s `VIP_MAP` and `TARGET_PORTS`, which key on the same front
/// tuple for two different roles (ingress backend selection, backend
/// target-port selection). `#[repr(C)]`, byte-identical on both sides of the
/// kernel boundary is the whole point: aya's userspace `HashMap<K, V>`
/// requires `K: Pod`, and the kernel's `BPF_MAP_TYPE_HASH` hashes/compares
/// this struct's raw bytes.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct VipKey {
    pub vip_ip: u32,
    pub vip_port: u16,
    pub proto: u8,
    pub _pad: u8,
}

/// `VIP_MAP`/`FWD_PENDING` value: the backend identity a `VipKey` resolves
/// to.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VipBackend {
    /// Geneve remote for the forward leg -- the node hosting the chosen Pod.
    pub backend_node_ip: u32,
    /// Pod-identifier stamped as the forward-leg Geneve option.
    pub pod_ip: u32,
}

/// Host-specific runtime config the loader fills in after attach (an
/// ifindex isn't known until then). Single entry (`CONFIG` map).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Config {
    pub geneve_ifindex: u32,
    pub uplink_ifindex: u32,
    /// `uplink_l2_header_len`'s result for the uplink iface -- 14 for a
    /// real Ethernet-framed NIC/veth, 0 for an L3-only uplink (WireGuard or
    /// any other tun-style device with no L2 header). `geneve0` is
    /// unaffected: it's always a real (Ethernet-framed) netdev regardless
    /// of what the uplink is.
    pub uplink_l2_hlen: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for VipKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for VipBackend {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for Config {}

/// Flow-table admission: forward-path decision (`beep-ebpf`'s
/// `try_uplink_ingress`, `docs/decisions/servicelb-flow-admission-affinity.md`).
/// A new flow is minted ONLY into the small, flood-exposed PENDING tier --
/// this enum has no variant that writes MAIN, so an off-path flood of
/// forward-only packets (never observed on the return leg) structurally
/// cannot populate MAIN no matter how many distinct tuples it tries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardAdmission {
    /// Already established in MAIN -- the lookup that found it already
    /// refreshed its LRU recency; nothing else to write.
    Established,
    /// No MAIN entry -- (re)mint the PENDING entry, the only place a new
    /// flow is ever created.
    MintPending,
}

/// `in_main`: result of an `FWD_MAIN.get(key)` lookup.
pub fn forward_admission(in_main: bool) -> ForwardAdmission {
    if in_main {
        ForwardAdmission::Established
    } else {
        ForwardAdmission::MintPending
    }
}

/// Flow-table admission: return-path decision (`beep-ebpf`'s
/// `try_geneve_decap_return`, step 7). A MAIN hit is already-established and
/// authorized outright. A PENDING hit is this flow's FIRST observed return
/// leg -- proof of bidirectionality that an off-path spoofer cannot produce
/// without actually receiving traffic -- so it is authorized AND promoted
/// into MAIN. A miss in both tiers is stale or spoofed and must drop, same
/// as the pre-split single-table behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReturnAuthorization {
    Established,
    Promote,
    Drop,
}

/// `in_main`/`in_pending`: results of `FWD_MAIN.get(key)`/`FWD_PENDING.get(key)`
/// lookups. Callers should short-circuit the PENDING lookup when `in_main`
/// is already true (the established/happy-path case costs one lookup, not
/// two).
pub fn return_authorization(in_main: bool, in_pending: bool) -> ReturnAuthorization {
    if in_main {
        ReturnAuthorization::Established
    } else if in_pending {
        ReturnAuthorization::Promote
    } else {
        ReturnAuthorization::Drop
    }
}

/// Uplink-egress return-path admission (`beep-ebpf`'s
/// `try_uplink_egress_return`, hook 3): whether a packet leaving the node on
/// the physical uplink is one of this node's own backend Pods replying to a
/// client, checked BEFORE the ~37-byte REV_FLOW conntrack key is even built.
/// This hook sees ALL uplink egress traffic, not just beep's, so most
/// packets take the `NotBackendTraffic` branch and must never pay for a
/// REV_FLOW lookup at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressReturnAdmission {
    /// Source is not one of this node's backend Pods -- not beep's
    /// traffic, pass through untouched.
    NotBackendTraffic,
    /// Source IS one of this node's backend Pods -- proceed to the
    /// REV_FLOW lookup.
    BackendTraffic,
}

/// `is_backend_pod`: `POD_TARGETS.get(src_ip)` membership on the packet's
/// SOURCE ADDRESS ONLY -- deliberately not its port. `POD_TARGETS` is keyed
/// on pod IP alone precisely so this stays true across a rolling update or a
/// targetPort edit: a flow only ever earns a REV_FLOW entry because the
/// forward path already found its pod in this same map, so admitting on
/// membership alone can never drop a live flow whose target port has since
/// changed -- comparing the port too would couple this gate to a value that
/// can change out from under an established flow. This is a structural
/// guarantee, not just a documented convention: the signature takes no port,
/// so no caller can wire one in without changing this function itself.
pub fn egress_return_admission(is_backend_pod: bool) -> EgressReturnAdmission {
    if is_backend_pod {
        EgressReturnAdmission::BackendTraffic
    } else {
        EgressReturnAdmission::NotBackendTraffic
    }
}

/// Outcome of the REV_FLOW lookup for a packet already confirmed
/// `EgressReturnAdmission::BackendTraffic`. A miss here can no longer be
/// treated as "not ours" the way `EgressReturnAdmission::NotBackendTraffic`
/// is -- the source has already been positively identified as one of this
/// node's own backend Pods, most likely evicted from the LRU REV_FLOW table
/// rather than genuinely unrelated. Letting an identified backend Pod's
/// reply through unencapsulated would leak a pod-CIDR-sourced packet onto
/// the underlay while still stalling the connection either way, so dropping
/// is strictly better -- consistent with the forward decap path's
/// equivalent miss (`geneve_ingress`'s `try_geneve_decap_return`, mapped to
/// `TC_ACT_SHOT` via `unwrap_or`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressReturnOutcome {
    /// No live REV_FLOW entry for this identified backend Pod's packet --
    /// drop it rather than forward it raw onto the underlay.
    Drop,
    /// A live REV_FLOW entry exists -- proceed with the un-DNAT + re-encap.
    Forward,
}

/// `has_rev_flow_entry`: result of a `REV_FLOW.get(key)` lookup, for a
/// packet the caller has already gated through
/// `EgressReturnAdmission::BackendTraffic`.
pub fn egress_return_outcome(has_rev_flow_entry: bool) -> EgressReturnOutcome {
    if has_rev_flow_entry {
        EgressReturnOutcome::Forward
    } else {
        EgressReturnOutcome::Drop
    }
}

/// Inbound decap-forward pod-membership gate (`beep-ebpf`'s
/// `try_geneve_decap_forward`, hook 4) -- the egress-side analogue of
/// `EgressReturnAdmission` above, mirrored onto the opposite hook.
/// `TARGET_PORTS.get(front tuple)` only confirms this node hosts SOME
/// backend for the front; it never confirms the specific `pod_ip` the
/// ingress node stamped into the Geneve option is still one of this node's
/// own pods. Under cross-node convergence drift a lagging ingress can replay
/// a stale forward pin naming a pod IP that's since been evicted here and
/// reused by an unrelated pod -- trusting it unconditionally misdelivers to
/// that live, unrelated workload instead of dropping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecapForwardPodAdmission {
    /// `pod_ip` is not a member of this node's current `POD_TARGETS` --
    /// drop rather than DNAT+deliver to a pod this node no longer owns.
    Drop,
    /// `pod_ip` is a current member -- proceed with the DNAT+deliver.
    Deliver,
}

/// `is_local_pod`: `POD_TARGETS.get(pod_ip)` membership on the Geneve
/// option's stamped pod IP alone -- deliberately the same pod-IP-only key
/// `egress_return_admission` gates on for `try_uplink_egress_return`, not a
/// (front tuple, pod_ip) pair. `POD_TARGETS` has exactly one membership
/// notion today (this node's current backend Pods), and reusing it here
/// makes the delivery node -- not the ingress node -- the authoritative
/// consistency point for both directions of a flow with the same map.
pub fn decap_forward_pod_admission(is_local_pod: bool) -> DecapForwardPodAdmission {
    if is_local_pod {
        DecapForwardPodAdmission::Deliver
    } else {
        DecapForwardPodAdmission::Drop
    }
}

/// Backend source-port remap, on-conflict-only (Decision 3,
/// `ai/extended-context/ebpf-lb-dataplane.md`). The backend's naive
/// reverse-flow key `(CLIENT_IP, SRC_PORT, PodIP, TargetPort, proto)`
/// collides when two Services with different front addresses (VIPs) share
/// a backend Pod:targetPort and the client reuses one ephemeral source
/// port across both -- legal, since the two connections differ by remote
/// (front) address even though local port matches. Remapping the backend-
/// facing source port (not the client's real IP -- that would destroy
/// real-client-IP-at-L3, ADR servicelb-ebpf-geneve-dataplane.md) makes the
/// reverse key unique again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendPortDecision {
    /// No prior entry for this reverse key, or the prior entry belongs to
    /// the same front address (same flow refreshing) -- use the client's
    /// real source port unchanged.
    NoRemap,
    /// A different front address already holds this reverse key -- use
    /// this synthetic port instead, only on the backend-facing segment
    /// (un-remapped back to the real port on return).
    Remap(u16),
    /// Every candidate in the bounded probe window (`PROBE_LIMIT` tries)
    /// was already occupied in REV_FLOW -- e.g. an (N+1)th Service piling
    /// onto the same backend Pod:targetPort/client-port collision. The
    /// caller MUST drop the packet rather than fall back to an unprobed
    /// port: reusing an occupied reverse key silently reproduces the exact
    /// clobbering bug Decision 3 exists to close.
    Exhausted,
}

/// Upper bound on probe attempts in `resolve_backend_src_port`. Bounded so
/// the eBPF verifier can prove the loop terminates; small enough to keep
/// the per-packet map-lookup cost low. A single low-entropy hash derived
/// from the front address only guaranteed uniqueness for exactly 2
/// conflicting fronts (~14 bits of entropy -- 75008/91392 realistic front
/// pairs collided in simulation), so this many fronts piling onto one
/// backend Pod:targetPort/client-port combination is the realistic ceiling
/// this dataplane needs to survive without silently clobbering a live flow.
pub const PROBE_LIMIT: u16 = 16;

/// `existing_occupant`: the `(front, original_client_port)` identity already
/// stored under the naive reverse key, if any (`None` = first writer, no
/// conflict possible). Both fields matter: comparing front alone lets a
/// distinct flow through the same front, whose real source port happens to
/// equal some other flow's already-committed synthetic port, misread that
/// other flow's entry as its own earlier commit and silently clobber it.
/// `new_front`: the front address the current packet arrived through -- a
/// raw `(vip_ip, vip_port)` scalar pair, not an `ipv4_mapped_v6`-widened
/// shape: this dataplane's front is always IPv4 at the wire level and
/// `RevFlowValue`'s stored `vip_ip` is already a bare `u32`, so widening it
/// just to compare is pure overhead with no correctness benefit.
/// `original_port`: the client's real source port -- excluded as a
/// candidate remap value so the remapped reverse key can never collide
/// with the natural (unremapped) one.
/// `is_reverse_key_taken`: probes REV_FLOW -- the actual source of
/// occupancy truth -- for whether a candidate synthetic port's resulting
/// reverse key is already held by some OTHER flow. Injectable so this
/// stays pure and unit-testable outside a kernel: `beep-ebpf` passes
/// a closure that performs the real map lookup; tests pass a closure over
/// a plain `HashSet`. `FnMut`, not `Fn`: the eBPF caller's closure patches a
/// hoisted key buffer's port bytes in place per candidate rather than
/// rebuilding the whole key from scratch every probe iteration.
pub fn resolve_backend_src_port(
    existing_occupant: Option<((u32, u16), u16)>,
    new_front: (u32, u16),
    original_port: u16,
    mut is_reverse_key_taken: impl FnMut(u16) -> bool,
) -> BackendPortDecision {
    if !occupant_conflicts(existing_occupant, new_front, original_port) {
        return BackendPortDecision::NoRemap;
    }
    let seed = synthetic_port_seed(new_front.0, new_front.1);
    let mut i: u16 = 0;
    while i < PROBE_LIMIT {
        let offset = seed.wrapping_add(i) % REMAP_PORT_RANGE;
        let candidate = REMAP_PORT_BASE.wrapping_add(offset);
        if candidate != original_port && !is_reverse_key_taken(candidate) {
            return BackendPortDecision::Remap(candidate);
        }
        i += 1;
    }
    BackendPortDecision::Exhausted
}

/// Whether an occupant already sitting on a candidate reverse key should
/// count as taken for `resolve_backend_src_port`'s probe (also used for the
/// natural-key check above it). Identity is `(front, original_client_port)`,
/// not front alone: comparing front only lets a genuinely distinct flow
/// through the SAME front, whose real source port happens to equal another
/// flow's already-committed synthetic remap port, be misread as "my own
/// earlier commit" -- it then skips re-probing and silently clobbers the
/// other flow's REV_FLOW entry, misdelivering that flow's return traffic. An
/// occupant matching on BOTH front and client port is our own earlier
/// packet's committed remap; anything else -- different front, or same
/// front with a different client port -- is a genuine conflict.
pub fn occupant_conflicts(
    occupant: Option<((u32, u16), u16)>,
    resolving_front: (u32, u16),
    resolving_client_port: u16,
) -> bool {
    matches!(occupant, Some(identity) if identity != (resolving_front, resolving_client_port))
}

/// IANA dynamic/private port range (RFC 6335 SS6) -- this dataplane
/// controls both ends of the backend<->Pod segment the remapped port is
/// visible on, so it doesn't need to avoid the client's own ephemeral
/// range at all, just be internally distinct.
pub const REMAP_PORT_BASE: u16 = 49152;
pub const REMAP_PORT_RANGE: u16 = u16::MAX - REMAP_PORT_BASE + 1; // 16384

/// Deterministic starting point for `resolve_backend_src_port`'s probe:
/// the same conflicting front always starts probing from the same offset,
/// so distinct fronts spread out across the port range instead of all
/// colliding on the same first guess. Deliberately NOT the final decision
/// on its own anymore (that was this fix's bug: two independently-computed
/// seeds can coincide, and did for the majority of realistic front pairs)
/// -- `resolve_backend_src_port`'s occupancy probe is what actually
/// guarantees uniqueness.
fn synthetic_port_seed(front_ip: u32, front_port: u16) -> u16 {
    let mixed =
        front_ip ^ front_ip.rotate_right(16) ^ (front_port as u32) ^ ((front_port as u32) << 3);
    (mixed as u16) % REMAP_PORT_RANGE
}

/// Whether `try_geneve_decap_forward` should reuse a previously-committed
/// backend-src-port for this flow, or run `resolve_backend_src_port`'s probe
/// fresh. `resolve_backend_src_port`'s occupancy check only proves
/// idempotency while every occupant already in the probe's window stays
/// alive: with no persisted decision, an LRU eviction of some UNRELATED
/// occupant at an EARLIER probe index, between two packets of THIS flow,
/// makes a fresh probe land back on that now-free earlier candidate instead
/// of continuing on to this flow's actual committed port -- a reverse-path-
/// breaking mid-connection port change the ingress node has no way to learn
/// about. Persisting the first resolution (under `FlowDirection::PortMemo`)
/// and reusing it makes every later packet's outcome independent of any
/// other flow's occupancy in the table -- a structural guarantee, not one
/// that depends on address disjointness (round-1 of this fix, a second
/// REV_FLOW key keyed on VIP+client, relied on exactly that and broke for a
/// hostNetwork Pod).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendPortResolution {
    /// A port was already committed for this flow on an earlier packet --
    /// reuse it unconditionally. No probe, so no other flow's table churn
    /// can ever change it.
    Memoized(u16),
    /// No commitment persisted yet (this flow's first packet, or its memo
    /// entry was itself evicted) -- run `resolve_backend_src_port`'s probe.
    Probe,
}

/// `memoized_port`: the result of a `FLOW_TABLE` `PortMemo`-tagged lookup
/// for this flow's natural (client, real client port, pod, target port)
/// key, if any.
pub fn backend_port_resolution(memoized_port: Option<u16>) -> BackendPortResolution {
    match memoized_port {
        Some(port) => BackendPortResolution::Memoized(port),
        None => BackendPortResolution::Probe,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `beep-ebpf` used to hard-code a 14-byte Ethernet skip for every
    // uplink, so a WireGuard (L3-only, no L2 header) uplink silently
    // no-op'd on every packet instead of erroring -- the offset math read
    // into the middle of the real IP header and the EtherType check never
    // matched. These two cases must resolve to different skip lengths, or
    // that regression is back.

    #[test]
    fn ethernet_uplink_keeps_the_14_byte_l2_skip() {
        // The existing, already-working single-node veth smoke harness
        // (scripts/smoke.sh) depends on this staying 14 -- a
        // regression here breaks the L2 path this fix must not touch, not
        // just the new WireGuard one.
        assert_eq!(uplink_l2_header_len(ARPHRD_ETHER), 14);
    }

    #[test]
    fn non_ethernet_uplink_skips_no_l2_header() {
        // ARPHRD_NONE is WireGuard's (and any other L3-only/tun device's)
        // type -- there is no Ethernet header to skip at all. Reverting to
        // an unconditional 14 here reproduces the exact silent no-op the
        // WireGuard spike found: offset math lands inside the real IP
        // header instead of past a header that was never there.
        const ARPHRD_NONE: u16 = 0xFFFE;
        assert_eq!(uplink_l2_header_len(ARPHRD_NONE), 0);
    }

    // Every checksum update and tunnel-key field the eBPF side touches
    // requires the exact wire byte order (see beep-ebpf's module doc);
    // a regression here silently corrupts every packet this dataplane
    // touches rather than failing loudly, so the round-trip is pinned here.
    #[test]
    fn wire_ip_matches_dotted_octet_order() {
        // u32::from(Ipv4Addr::new(10, 0, 0, 1)) == this literal.
        let ip = u32::from_be_bytes([10, 0, 0, 1]);
        assert_eq!(wire_ip(ip).to_le_bytes(), [10, 0, 0, 1]);
    }

    #[test]
    fn wire_port_matches_network_byte_order() {
        // 8080 = 0x1F90; on the wire the high byte (0x1F) comes first.
        assert_eq!(wire_port(8080).to_le_bytes(), [0x1F, 0x90]);
    }

    // A conntrack keying bug corrupts flow affinity silently instead of
    // failing loudly, so every encode/decode path is round-tripped here
    // rather than trusted by inspection.

    #[test]
    fn tcp_key_round_trips_ipv6_addresses() {
        let client_ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let other_ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let key = encode_tcp_flow_key(client_ip, 0x1234, other_ip, 0x5678, 6);
        assert_eq!(
            decode_tcp_flow_key(&key),
            (client_ip, 0x1234, other_ip, 0x5678, 6)
        );
    }

    #[test]
    fn tcp_key_round_trips_ipv4_via_mapped_embedding() {
        // The sizing table's whole justification for 37 bytes over 13
        // (IPv4-only) is that one map shape serves both families -- prove
        // an IPv4 address survives the v6 embedding and back unchanged.
        let client_v4: u32 = 0x0100_000a; // wire-token bytes: 10.0.0.1
        let other_v4: u32 = 0x0200_000a; // 10.0.0.2
        let key = encode_tcp_flow_key(
            ipv4_mapped_v6(client_v4),
            0x1234,
            ipv4_mapped_v6(other_v4),
            0x5678,
            17,
        );
        let (client_ip, client_port, other_ip, other_port, proto) = decode_tcp_flow_key(&key);
        assert_eq!(unmap_ipv4(&client_ip), Some(client_v4));
        assert_eq!(unmap_ipv4(&other_ip), Some(other_v4));
        assert_eq!((client_port, other_port, proto), (0x1234, 0x5678, 17));
    }

    #[test]
    fn unmap_ipv4_rejects_a_genuine_ipv6_address() {
        // A real IPv6 flow must never be silently misread as IPv4 --
        // that would let an IPv6 and an IPv4 flow collide despite the
        // whole point of the mapped-embedding scheme being to keep them
        // disjoint.
        let real_v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(unmap_ipv4(&real_v6), None);
    }

    #[test]
    fn flow_key_is_38_bytes_the_tcp_key_plus_one_tag_byte() {
        // Adding a tag byte instead of relying on VIP-vs-pod-CIDR
        // disjointness is only justified because it's free (BPF rounds key
        // size up to a multiple of 8 regardless) -- a length regression here
        // would silently make that trade-off no longer hold.
        assert_eq!(FLOW_KEY_LEN, 38);
    }

    #[test]
    fn same_5_tuple_forward_and_reverse_tagged_keys_never_collide() {
        // A hostNetwork Pod's IP can equal a VIP, so the forward, reverse,
        // and port-memo roles can all share the identical (client_ip,
        // client_port, other_ip, other_port, proto) 5-tuple. Without the
        // explicit tag, entries for two of these roles on that shared tuple
        // would alias the same map slot and one role would silently
        // clobber another's state.
        let client_ip = ipv4_mapped_v6(0x0100_000a);
        let other_ip = ipv4_mapped_v6(0x0200_000a);
        let fwd_key = encode_flow_key(
            client_ip,
            0x1234,
            other_ip,
            0x5678,
            6,
            FlowDirection::Forward,
        );
        let rev_key = encode_flow_key(
            client_ip,
            0x1234,
            other_ip,
            0x5678,
            6,
            FlowDirection::Reverse,
        );
        let port_memo_key = encode_flow_key(
            client_ip,
            0x1234,
            other_ip,
            0x5678,
            6,
            FlowDirection::PortMemo,
        );
        assert_ne!(fwd_key, rev_key);
        assert_ne!(fwd_key, port_memo_key);
        assert_ne!(rev_key, port_memo_key);
        assert_eq!(&fwd_key[..TCP_FLOW_KEY_LEN], &rev_key[..TCP_FLOW_KEY_LEN]);
        assert_eq!(
            &fwd_key[..TCP_FLOW_KEY_LEN],
            &port_memo_key[..TCP_FLOW_KEY_LEN]
        );
    }

    #[test]
    fn quic_dcid_key_round_trips() {
        let dcid = [1, 2, 3, 4, 5, 6, 7, 8];
        let key = encode_quic_dcid_key(&dcid);
        assert_eq!(decode_quic_dcid_key(&key), dcid);
    }

    #[test]
    fn quic_dcid_key_zero_pads_a_short_input() {
        let key = encode_quic_dcid_key(&[9, 9]);
        assert_eq!(key, [9, 9, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn non_colliding_flow_leaves_client_src_port_untouched() {
        // The happy path (first writer, or the same flow's later packets)
        // must never remap -- doing so on every packet would break the
        // client's real connection identity for the common case.
        let vip_a = (0x0100_000au32, 0x5000u16);
        assert_eq!(
            resolve_backend_src_port(None, vip_a, 0x9999, |_| false),
            BackendPortDecision::NoRemap
        );
        assert_eq!(
            resolve_backend_src_port(Some((vip_a, 0x9999)), vip_a, 0x9999, |_| false),
            BackendPortDecision::NoRemap
        );
    }

    #[test]
    fn two_services_sharing_a_backend_pod_and_client_port_get_a_unique_reverse_tuple() {
        // The exact scenario Decision 3 closes: Service A and Service B
        // have different front addresses but resolve to the same backend
        // Pod:targetPort, and the client reuses one local port for both
        // connections (legal -- remote addresses differ). Without the
        // remap, both flows' reverse keys are byte-identical and the
        // second write clobbers the first, misrouting its replies.
        let client_ip = ipv4_mapped_v6(0x0100_000a);
        let pod_ip = ipv4_mapped_v6(0x0a00_a8c0);
        let target_port = 0x1f90u16;
        let client_src_port = 0x9999u16;
        let front_a = (0x0100_000au32, 0x5000u16);
        let front_b = (0x0200_000au32, 0x5001u16);

        // Service A's flow writes first: no existing entry, no conflict.
        let decision_a = resolve_backend_src_port(None, front_a, client_src_port, |_| false);
        assert_eq!(decision_a, BackendPortDecision::NoRemap);
        let port_a = client_src_port;

        // Service B's flow arrives with the same natural reverse key
        // already held by Service A's (different) front -- conflict. The
        // only occupied reverse port so far is Service A's (port_a).
        let decision_b = resolve_backend_src_port(
            Some((front_a, client_src_port)),
            front_b,
            client_src_port,
            |p| p == port_a,
        );
        let BackendPortDecision::Remap(port_b) = decision_b else {
            panic!("expected a remap on front-address conflict, got {decision_b:?}");
        };
        assert_ne!(
            port_b, client_src_port,
            "remapped port must differ from the client's real port, or the reverse key still collides"
        );

        let key_a = encode_tcp_flow_key(client_ip, port_a, pod_ip, target_port, 6);
        let key_b = encode_tcp_flow_key(client_ip, port_b, pod_ip, target_port, 6);
        assert_ne!(
            key_a, key_b,
            "Decision 3's whole purpose: the two services' reverse tuples must be unique by construction"
        );
    }

    #[test]
    fn three_plus_services_sharing_a_backend_pod_and_client_port_get_distinct_reverse_ports() {
        // Deriving the synthetic port from a single low-entropy hash of the
        // front address (~14 bits) only guaranteed uniqueness for exactly 2
        // conflicting fronts -- a THIRD
        // Service sharing this backend Pod:targetPort with a reused client
        // source port could derive the SAME synthetic port as the second
        // and silently clobber it. Concretely, these four front VIPs (IP
        // octets 30/94/158/222, all on VIP port 31000 -- a stride of 64
        // that resonates with the old formula's `rotate_right(16)` mixing)
        // all hash to the identical seed:
        let colliding_fronts: [(u32, u16); 4] = [
            (u32::from_ne_bytes([10, 0, 0, 30]), 31000),
            (u32::from_ne_bytes([10, 0, 0, 94]), 31000),
            (u32::from_ne_bytes([10, 0, 0, 158]), 31000),
            (u32::from_ne_bytes([10, 0, 0, 222]), 31000),
        ];
        let shared_seed = synthetic_port_seed(colliding_fronts[0].0, colliding_fronts[0].1);
        for front in &colliding_fronts[1..] {
            assert_eq!(
                synthetic_port_seed(front.0, front.1),
                shared_seed,
                "fixture invariant broken: this test only proves the fix if these fronts \
                 actually share a derive-only seed"
            );
        }

        let client_ip = ipv4_mapped_v6(0x0100_000a);
        let pod_ip = ipv4_mapped_v6(0x0a00_a8c0);
        let target_port = 0x1f90u16;
        let client_src_port = 0x9999u16;
        let first_writer = (u32::from_ne_bytes([10, 0, 0, 1]), 6000u16);

        // First writer: no existing entry, natural reverse key holds the
        // client's real port unremapped.
        let mut taken = vec![client_src_port];
        assert_eq!(
            resolve_backend_src_port(None, first_writer, client_src_port, |p| taken.contains(&p)),
            BackendPortDecision::NoRemap
        );

        // Each of the four colliding fronts conflicts against the first
        // writer's occupied natural key. Pre-fix, all four would derive
        // `shared_seed` and collide with each other, not just avoid
        // `client_src_port`. Post-fix, each must probe REV_FLOW occupancy
        // (the `taken` closure below) and land on a fresh port.
        let mut resolved_ports = vec![client_src_port];
        for front in colliding_fronts {
            let decision = resolve_backend_src_port(
                Some((first_writer, client_src_port)),
                front,
                client_src_port,
                |p| taken.contains(&p),
            );
            let BackendPortDecision::Remap(port) = decision else {
                panic!("expected a remap for conflicting front {front:?}, got {decision:?}");
            };
            assert!(
                !taken.contains(&port),
                "port {port} for front {front:?} was already occupied by an earlier flow -- \
                 the occupancy probe failed to avoid a live REV_FLOW entry"
            );
            taken.push(port);
            resolved_ports.push(port);
        }

        let mut dedup = resolved_ports.clone();
        dedup.sort_unstable();
        dedup.dedup();
        assert_eq!(
            dedup.len(),
            resolved_ports.len(),
            "N-front collision in {resolved_ports:?}: a later Service on this backend \
             Pod:targetPort would silently clobber an earlier one's REV_FLOW entry, exactly \
             the bug Decision 3 exists to close"
        );

        // The actual invariant REV_FLOW depends on: the encoded reverse
        // keys, not just the raw port numbers, must be pairwise distinct.
        let keys: Vec<TcpFlowKey> = resolved_ports
            .iter()
            .map(|&port| encode_tcp_flow_key(client_ip, port, pod_ip, target_port, 6))
            .collect();
        for i in 0..keys.len() {
            for key in &keys[i + 1..] {
                assert_ne!(
                    &keys[i], key,
                    "reverse keys for two of these services collide"
                );
            }
        }
    }

    #[test]
    fn many_fronts_sharing_a_backend_pod_never_produce_a_duplicate_reverse_key() {
        // Sweep many front VIP:port pairs that all resolve to the same
        // backend Pod:targetPort with one reused client source port
        // (75008/91392 realistic front pairs collided under the pre-fix
        // derive-only formula). Every resulting reverse key this dataplane
        // hands out for the backend must be distinct.
        let client_ip = ipv4_mapped_v6(0x0100_000a);
        let pod_ip = ipv4_mapped_v6(0x0a00_a8c0);
        let target_port = 0x1f90u16;
        let client_src_port = 0x9999u16;

        let mut fronts = Vec::new();
        for ip_octet in 0u8..=250 {
            for port in [5000u16, 5001, 5002, 8080, 8443, 30000, 31000, 32000] {
                fronts.push((u32::from_ne_bytes([10, 0, 0, ip_octet]), port));
            }
        }
        let first_writer = fronts[0];

        let mut taken = vec![client_src_port];
        let mut keys = vec![encode_tcp_flow_key(
            client_ip,
            client_src_port,
            pod_ip,
            target_port,
            6,
        )];
        for &front in &fronts[1..] {
            let decision = resolve_backend_src_port(
                Some((first_writer, client_src_port)),
                front,
                client_src_port,
                |p| taken.contains(&p),
            );
            let BackendPortDecision::Remap(port) = decision else {
                panic!("expected a remap for conflicting front {front:?}, got {decision:?}");
            };
            taken.push(port);
            keys.push(encode_tcp_flow_key(client_ip, port, pod_ip, target_port, 6));
        }

        let mut dedup = keys.clone();
        dedup.sort_unstable();
        dedup.dedup();
        assert_eq!(
            dedup.len(),
            keys.len(),
            "{} of {} reverse keys collided across {} fronts sharing one backend -- an (N+1)th \
             Service would silently clobber a live flow",
            keys.len() - dedup.len(),
            keys.len(),
            fronts.len()
        );
    }

    #[test]
    fn remapped_flows_resolve_to_the_same_port_on_every_packet() {
        // The probe's occupancy closure once checked only
        // `REV_FLOW.get(candidate).is_some()`, with no comparison to the
        // flow's own front. A remapped flow's natural reverse key is (and
        // stays) held by the OTHER, first-writer front -- this flow never
        // overwrites it, it writes its own remapped key instead -- so every
        // packet re-entered the conflict branch and re-probed from the same
        // deterministic seed. Without front-aware occupancy, the flow's own
        // prior candidate read back as "taken", so it picked a NEW port
        // each packet: the port churned and the flow was eventually dropped
        // as Exhausted. This test simulates REV_FLOW across two packets of
        // the same flow and requires the SAME synthetic port both times.
        use std::collections::HashMap;

        let client_src_port = 0x9999u16;
        let first_writer = (u32::from_ne_bytes([10, 0, 0, 1]), 6000u16);
        let front_a = (u32::from_ne_bytes([10, 0, 0, 30]), 31000u16);

        // Sim of REV_FLOW keyed by candidate port -> the (front,
        // original_client_port) identity that committed a reverse-flow
        // entry there (main.rs's occupant lookup maps a full 38-byte key to
        // a `RevFlowValue`; the port is enough here since every candidate in
        // this test shares client/pod/target).
        let mut rev_flow: HashMap<u16, ((u32, u16), u16)> = HashMap::new();
        rev_flow.insert(client_src_port, (first_writer, client_src_port));

        let resolve = |rev_flow: &HashMap<u16, ((u32, u16), u16)>| {
            resolve_backend_src_port(
                Some((first_writer, client_src_port)),
                front_a,
                client_src_port,
                |candidate| {
                    occupant_conflicts(rev_flow.get(&candidate).copied(), front_a, client_src_port)
                },
            )
        };

        // Packet 1: no candidate committed yet for front_a.
        let decision_1 = resolve(&rev_flow);
        let BackendPortDecision::Remap(port_1) = decision_1 else {
            panic!("expected a remap on front-address conflict, got {decision_1:?}");
        };
        rev_flow.insert(port_1, (front_a, client_src_port));

        // Packet 2 of the SAME flow: the natural reverse key still shows
        // first_writer's front (this flow never writes there), so
        // resolution runs the conflict branch again -- it must land back
        // on port_1, not churn to a new candidate.
        let decision_2 = resolve(&rev_flow);
        let BackendPortDecision::Remap(port_2) = decision_2 else {
            panic!("expected a remap on repeat resolution, got {decision_2:?}");
        };
        assert_eq!(
            port_1, port_2,
            "the same flow's repeated resolution returned different ports ({port_1} then \
             {port_2}) -- readback of our own committed remap is being treated as a conflict, \
             which churns the port every packet until PROBE_LIMIT is exhausted and the flow is \
             dropped"
        );

        // A genuinely different conflicting front must still land on its
        // own, distinct port -- idempotency for one flow must not collapse
        // distinctness across flows.
        let front_b = (u32::from_ne_bytes([10, 0, 0, 94]), 31000u16);
        let decision_b = resolve_backend_src_port(
            Some((first_writer, client_src_port)),
            front_b,
            client_src_port,
            {
                let rev_flow = &rev_flow;
                move |candidate| {
                    occupant_conflicts(rev_flow.get(&candidate).copied(), front_b, client_src_port)
                }
            },
        );
        let BackendPortDecision::Remap(port_b) = decision_b else {
            panic!("expected a remap for a distinct conflicting front, got {decision_b:?}");
        };
        assert_ne!(
            port_1, port_b,
            "a distinct conflicting front must not be handed the same synthetic port as an \
             unrelated flow's own committed remap"
        );
    }

    #[test]
    fn distinct_flow_reusing_a_committed_synthetic_port_is_not_mistaken_for_a_self_read() {
        // Comparing occupant identity by front alone left a gap: a
        // genuinely DISTINCT flow through the SAME front, whose real source
        // port happens to equal another flow's already-committed synthetic
        // remap port, was misread as "my own earlier commit" -- so it
        // skipped re-probing and silently clobbered the other flow's
        // REV_FLOW entry, misdelivering that flow's return traffic. Identity
        // must be (front, original_client_port): same front with a
        // DIFFERENT client port is a real conflict, not a self-read.
        use std::collections::HashMap;

        let client_port_a = 0x1111u16;
        let first_writer = (u32::from_ne_bytes([10, 0, 0, 1]), 6000u16);
        let front_a = (u32::from_ne_bytes([10, 0, 0, 30]), 31000u16);

        // Sim of REV_FLOW keyed by candidate port -> (front,
        // original_client_port), mirroring main.rs's occupant lookup.
        let mut rev_flow: HashMap<u16, ((u32, u16), u16)> = HashMap::new();
        rev_flow.insert(client_port_a, (first_writer, client_port_a));

        // Flow A: conflicts with first_writer at its natural key, gets
        // remapped to a synthetic port.
        let decision_a = resolve_backend_src_port(
            Some((first_writer, client_port_a)),
            front_a,
            client_port_a,
            |candidate| {
                occupant_conflicts(rev_flow.get(&candidate).copied(), front_a, client_port_a)
            },
        );
        let BackendPortDecision::Remap(port_a) = decision_a else {
            panic!(
                "expected flow A to be remapped on conflict with first_writer, got {decision_a:?}"
            );
        };
        rev_flow.insert(port_a, (front_a, client_port_a));

        // Flow B: a DISTINCT flow through the SAME front (front_a) whose
        // real source port happens to equal flow A's committed synthetic
        // port. Its natural reverse key already holds flow A's entry.
        let client_port_b = port_a;
        let existing_occupant = rev_flow.get(&client_port_b).copied();
        let decision_b =
            resolve_backend_src_port(existing_occupant, front_a, client_port_b, |candidate| {
                occupant_conflicts(rev_flow.get(&candidate).copied(), front_a, client_port_b)
            });
        let BackendPortDecision::Remap(port_b) = decision_b else {
            panic!(
                "flow B (real src port {client_port_b} colliding with flow A's synthetic port, \
                 through the same front) must be treated as a conflict and get its own remap, \
                 got {decision_b:?} -- front-only occupant identity misreads it as flow A's own \
                 earlier commit, which would silently clobber flow A's REV_FLOW entry and \
                 misdeliver flow A's return traffic"
            );
        };
        rev_flow.insert(port_b, (front_a, client_port_b));

        assert_eq!(
            rev_flow.get(&port_a).copied(),
            Some((front_a, client_port_a)),
            "flow A's REV_FLOW entry at its synthetic port must survive untouched -- flow B \
             must never have been allowed to write here"
        );
        assert_eq!(
            rev_flow.get(&client_port_a).copied(),
            Some((first_writer, client_port_a)),
            "first_writer's original entry must also survive untouched"
        );
    }

    #[test]
    fn evicting_an_unrelated_earlier_probe_occupant_does_not_change_a_memoized_ports_resolution() {
        // resolve_backend_src_port probes REV_FLOW occupancy in a fixed,
        // deterministic order on EVERY packet. If an UNRELATED
        // flow occupying an EARLIER probe candidate gets evicted by the LRU
        // between two packets of THIS flow, a naive re-probe finds that
        // earlier slot free now and commits to a DIFFERENT port than the one
        // this flow already committed -- breaking the reverse path
        // mid-connection, since the ingress node's un-remap still expects
        // the ORIGINAL port. Memoizing the first resolution and reusing it
        // (`backend_port_resolution`) must make this flow's outcome
        // independent of any other flow's table churn.
        use std::collections::HashMap;

        let client_src_port = 0x9999u16;
        let first_writer = (0x0a00_0001u32, 6000u16); // occupies the natural key
        let front_a = (0x0a00_001eu32, 31000u16); // conflicts -> triggers a probe

        let mut rev_flow: HashMap<u16, ((u32, u16), u16)> = HashMap::new();
        rev_flow.insert(client_src_port, (first_writer, client_src_port));

        // An UNRELATED flow occupies the probe's very first candidate (seed
        // offset 0) -- this is the earlier-probe-index occupant the
        // eviction below frees.
        let seed = synthetic_port_seed(front_a.0, front_a.1);
        let earliest_candidate = REMAP_PORT_BASE.wrapping_add(seed);
        let unrelated_earlier_occupant = ((0x0a00_00ffu32, 9999u16), 1234u16);
        rev_flow.insert(earliest_candidate, unrelated_earlier_occupant);

        let resolve_fresh = |rev_flow: &HashMap<u16, ((u32, u16), u16)>| {
            resolve_backend_src_port(
                Some((first_writer, client_src_port)),
                front_a,
                client_src_port,
                |candidate| {
                    occupant_conflicts(rev_flow.get(&candidate).copied(), front_a, client_src_port)
                },
            )
        };

        // Packet 1: no memo yet -- the real probe must skip the occupied
        // earliest candidate and land on the next free one.
        let BackendPortDecision::Remap(port_x) = resolve_fresh(&rev_flow) else {
            panic!("expected a remap on front-address conflict");
        };
        assert_ne!(
            port_x, earliest_candidate,
            "fixture invariant broken: the earliest candidate must be occupied so packet 1's \
             probe is actually forced past it, or this test doesn't exercise the bug at all"
        );
        rev_flow.insert(port_x, (front_a, client_src_port));
        let memo = Some(port_x);

        // Between packet 1 and packet 2, an UNRELATED flow's entry at the
        // earlier probe index gets evicted by the LRU -- nothing to do with
        // this flow.
        rev_flow.remove(&earliest_candidate);

        // Demonstrates the bug precondition: WITHOUT the memo, a fresh
        // re-probe of the SAME flow now finds the earlier candidate free and
        // commits to a DIFFERENT port than packet 1's.
        let BackendPortDecision::Remap(churned_port) = resolve_fresh(&rev_flow) else {
            panic!("expected a remap on repeat resolution");
        };
        assert_eq!(
            churned_port, earliest_candidate,
            "fixture invariant broken: freeing the earlier occupant must change what a fresh \
             re-probe returns, or this test isn't exercising the bug at all"
        );

        // The fix: packet 2 must never re-probe -- it reuses the memoized
        // port from packet 1, so the just-freed earlier candidate (or any
        // other unrelated table churn) has no way to reach the decision.
        assert_eq!(
            backend_port_resolution(memo),
            BackendPortResolution::Memoized(port_x),
            "packet 2 of the same flow must reuse packet 1's committed port ({port_x}) even \
             though an unrelated occupant at an earlier probe index was freed in between -- \
             reusing the memo instead of re-probing is what keeps the reverse path from \
             breaking mid-connection"
        );
    }

    // Flow-table admission (promote-on-bidirectionality):
    // an evicted-forward-entry-turns-into-a-dropped-return-packet bug would
    // pass every test above (they never touch MAIN/PENDING at all) but break
    // every live connection under a flood, so these get their own group.

    #[test]
    fn forward_admission_established_flow_needs_no_pending_write() {
        // A live flow's forward packets must skip the PENDING insert
        // entirely -- writing PENDING on every packet of an already-
        // established flow would waste PENDING capacity on flows that don't
        // need protecting, shrinking the headroom actually-new connections
        // get during a flood.
        assert_eq!(forward_admission(true), ForwardAdmission::Established);
    }

    #[test]
    fn forward_admission_new_flow_mints_into_pending_only() {
        // The only mint site: a flow with no MAIN entry gets a PENDING
        // write. Critically, `ForwardAdmission` has no variant that asks the
        // caller to write MAIN -- an off-path flood of forward-only packets
        // (arbitrarily many distinct tuples, never producing a return leg)
        // can therefore never populate MAIN by construction, not just by
        // convention.
        assert_eq!(forward_admission(false), ForwardAdmission::MintPending);
    }

    #[test]
    fn return_authorization_established_flow_is_not_re_promoted() {
        // A MAIN hit must short-circuit before PENDING is even consulted --
        // re-running the promote (insert+remove) on every packet of an
        // already-established flow would be wasted work on the hot path and
        // would repeatedly touch PENDING for a flow that no longer needs it.
        assert_eq!(
            return_authorization(true, false),
            ReturnAuthorization::Established
        );
        assert_eq!(
            return_authorization(true, true),
            ReturnAuthorization::Established,
            "a MAIN hit must win even if a stale PENDING entry for the same key also exists"
        );
    }

    #[test]
    fn return_authorization_first_return_leg_promotes_from_pending() {
        // The core anti-flush mechanism: the first packet on the return
        // direction is proof of bidirectionality an off-path spoofer cannot
        // manufacture (it would need to actually receive the reply), so it
        // is both authorized and promoted into MAIN.
        assert_eq!(
            return_authorization(false, true),
            ReturnAuthorization::Promote
        );
    }

    #[test]
    fn return_authorization_drops_stale_or_spoofed_return() {
        // Absent from both tiers means this return answers no flow this
        // node ever forwarded -- the same drop the single-table version
        // performed via FWD_FLOW.get returning None.
        assert_eq!(
            return_authorization(false, false),
            ReturnAuthorization::Drop
        );
    }

    #[test]
    fn established_flow_in_main_survives_a_flood_of_forward_only_flows() {
        // The property the whole split exists for: a spoofed/off-path flood
        // that only ever sends forward-direction packets from varying
        // source ports must not be able to touch -- let alone evict -- an
        // already-established flow sitting in MAIN. Simulates both tiers as
        // plain sets and drives the two pure decision functions exactly as
        // `beep-ebpf` would, without a kernel.
        use std::collections::HashSet;

        let mut main: HashSet<u32> = HashSet::new();
        let mut pending: HashSet<u32> = HashSet::new();
        let established_flow: u32 = 1;

        // Establish one flow the ordinary way: forward mints it into
        // PENDING, then its first return leg promotes it into MAIN.
        assert_eq!(
            forward_admission(main.contains(&established_flow)),
            ForwardAdmission::MintPending
        );
        pending.insert(established_flow);
        match return_authorization(
            main.contains(&established_flow),
            pending.contains(&established_flow),
        ) {
            ReturnAuthorization::Promote => {
                main.insert(established_flow);
                pending.remove(&established_flow);
            }
            other => panic!("expected the first return leg to promote, got {other:?}"),
        }
        assert!(main.contains(&established_flow));

        // Flood: 10,000 distinct never-returning flows hammer the forward
        // path. Each is a genuinely new tuple (never in MAIN), so each must
        // mint into PENDING -- never MAIN -- and the established flow's own
        // forward traffic during the flood must keep finding it already in
        // MAIN and skip PENDING entirely.
        for flood_flow in 100..10_100u32 {
            assert_eq!(
                forward_admission(main.contains(&flood_flow)),
                ForwardAdmission::MintPending,
                "flood tuple {flood_flow} was never established, so it must only ever mint \
                 into PENDING"
            );
            pending.insert(flood_flow); // simulates the LRU churning PENDING
            assert_eq!(
                forward_admission(main.contains(&established_flow)),
                ForwardAdmission::Established,
                "an unpromoted flood must not evict established flows out of MAIN -- the \
                 established flow's own forward packets must keep resolving as already-\
                 established throughout the flood, never fall back to re-minting"
            );
        }

        assert!(
            main.contains(&established_flow) && main.len() == 1,
            "MAIN must contain exactly the one flow that was actually promoted via a real \
             return leg -- a flood of {} forward-only tuples must never have written MAIN",
            pending.len()
        );
    }

    #[test]
    fn egress_return_admission_passes_non_backend_traffic_without_a_conntrack_lookup() {
        // uplink_egress_return sees ALL egress traffic leaving the node, not
        // just beep's -- unrelated traffic must be recognizable from
        // POD_TARGETS membership alone, before the caller ever builds the
        // ~37-byte REV_FLOW key, or every unrelated packet leaving the node
        // pays a needless conntrack lookup.
        assert_eq!(
            egress_return_admission(false),
            EgressReturnAdmission::NotBackendTraffic,
            "a packet not sourced from one of this node's backend Pods must short-circuit \
             before REV_FLOW is ever probed"
        );
    }

    #[test]
    fn egress_return_outcome_drops_an_identified_backend_pods_evicted_flow() {
        // This is the fix `egress_return_outcome` exists for: BEFORE it, a
        // REV_FLOW miss on already-identified backend traffic fell back to
        // TC_ACT_OK, so an LRU eviction let the backend Pod's raw reply
        // leave the node unencapsulated, carrying a pod-CIDR source address
        // onto the underlay -- a stalled connection AND a pod-source packet
        // leak. If this assertion ever reverts to `Forward`, that leak comes
        // back.
        assert_eq!(
            egress_return_outcome(false),
            EgressReturnOutcome::Drop,
            "an identified backend Pod's packet with no live REV_FLOW entry must be dropped, \
             not forwarded raw onto the underlay"
        );
    }

    #[test]
    fn egress_return_outcome_forwards_a_live_flow() {
        // The happy path this bead must not regress: a genuinely live flow
        // (REV_FLOW hit) still gets un-DNAT'd and re-encapsulated, not
        // dropped just because it's now backend-identified traffic.
        assert_eq!(egress_return_outcome(true), EgressReturnOutcome::Forward);
    }

    #[test]
    fn dropping_identified_backend_misses_never_touches_unrelated_egress_traffic() {
        // The two-stage split this bead relies on: admission (source
        // membership) gates whether `egress_return_outcome` is ever
        // consulted at all. Unrelated egress traffic (this hook sees ALL of
        // it, not just beep's) must keep passing untouched -- only a
        // packet already positively identified as a backend Pod's reply
        // reaches the new drop-on-miss behavior.
        assert_eq!(
            egress_return_admission(false),
            EgressReturnAdmission::NotBackendTraffic,
            "unrelated egress traffic must never reach egress_return_outcome -- only \
             identified backend Pod traffic may be dropped on a REV_FLOW miss"
        );
        assert_eq!(
            egress_return_outcome(false),
            EgressReturnOutcome::Drop,
            "meanwhile, identified backend traffic with the same REV_FLOW miss must drop, not \
             pass -- the two outcomes for the same has_rev_flow_entry value diverge precisely \
             because admission already separated the two cases"
        );
    }

    #[test]
    fn decap_forward_drops_a_geneve_pod_ip_no_longer_in_the_local_serving_set() {
        // This is the fix this gate exists for: under cross-node
        // convergence drift, a lagging ingress node can replay a stale
        // Geneve pod_ip that this node has since evicted from POD_TARGETS
        // and reassigned to an unrelated pod. Before this gate,
        // try_geneve_decap_forward DNAT'd to that pod_ip unconditionally --
        // misdelivering a client's traffic to a live, unrelated workload. If
        // this assertion ever reverts to `Deliver`, that cross-pod leak
        // comes back.
        assert_eq!(
            decap_forward_pod_admission(false),
            DecapForwardPodAdmission::Drop,
            "a pod_ip that is not a current POD_TARGETS member must be dropped, never DNAT'd \
             and delivered -- ingress-side drift must degrade to a boundary drop, not a \
             cross-pod leak"
        );
    }

    #[test]
    fn decap_forward_delivers_a_pod_ip_still_in_the_local_serving_set() {
        // The happy path this bead must not regress: a genuinely live,
        // still-serving pod's flow keeps being delivered, not dropped just
        // because the membership gate now exists.
        assert_eq!(
            decap_forward_pod_admission(true),
            DecapForwardPodAdmission::Deliver
        );
    }
}
