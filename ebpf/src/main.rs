#![no_std]
#![no_main]

//! Phase 2 (Geneve encap/decap on the symmetric-return path) plus Phase 3
//! (conntrack full-tuple keying + backend source-port remap on conflict) of
//! the beep eBPF dataplane
//! (`docs/design/ebpf-lb-dataplane.md`'s "Packet flow" and
//! "Conntrack & affinity" sections, `docs/decisions/servicelb-symmetric-geneve-return.md`).
//! Dual-stack inner-packet parsing (v4 and v6, dispatched on EtherType/IP
//! version), one static LB-front-IP:PORT -> backend-node/PodIP:TargetPort
//! mapping populated by the userspace loader at startup -- real Service/
//! EndpointSlice watching is Phase 5. Flow-affinity keys are IPv6-primary
//! (`beep_common`), so a v4 address is embedded as IPv4-mapped IPv6
//! (`ipv4_mapped_v6`) before keying and a genuine v6 address is used as-is;
//! the two families never collide (a real v6 address can't carry the
//! `::ffff:0:0/96` prefix the embedding produces). Every v4-specific
//! function below (`*_v4`/unsuffixed helpers with only a v4 arm) has a `_v6`
//! sibling parsing the analogous IPv6 header shape -- kept as separate
//! functions, not one runtime-branched implementation, because `load_direct`
//! requires every packet-offset argument to be a compile-time constant (see
//! its own doc comment) and the two families' header layouts differ in both
//! width and field offsets.
//!
//! # Wire-value convention (load-bearing, read before editing)
//!
//! Every IPv4 address and port field this file reads off or writes into a
//! *packet* is kept as a "raw wire token": the exact bytes as they appear on
//! the wire, copied verbatim via `TcContext::load`/`store` (which wrap
//! `bpf_skb_load_bytes`/`bpf_skb_store_bytes`, plain memcpy, no byte-swap)
//! into a same-sized native integer. `bpf_l3_csum_replace`/
//! `bpf_l4_csum_replace`'s `from`/`to` arguments and the Geneve option TLVs
//! (raw bytes this code constructs by hand) all require that same
//! representation, so tokens flow between packet, map, and option buffer
//! without any conversion; the map/const boundaries that start from a
//! human-typed host-order value apply `.to_be()` once to enter it.
//!
//! `bpf_tunnel_key`'s `remote_ipv4` is the one field that does NOT follow
//! this convention: the kernel converts it host<->network internally on
//! both `bpf_skb_set_tunnel_key`/`bpf_skb_get_tunnel_key`, confirmed
//! empirically against a live kernel after a wire-token value here came out
//! byte-reversed on the wire (192.168.109.3 encoded as a wire token, put
//! straight into `remote_ipv4`, arrived as outer dst `3.109.168.192`). It
//! must be supplied in plain host-native order -- see
//! `src/main.rs`'s `populate_fixture` for where that
//! conversion happens at the map-population boundary. `tunnel_id` (VNI)
//! also takes plain host order (the kernel applies `cpu_to_be64`
//! internally), consistent with `remote_ipv4` here.

use aya_ebpf::{
    bindings::{
        bpf_tunnel_key, BPF_F_PSEUDO_HDR, BPF_F_TUNINFO_IPV6, TC_ACT_OK, TC_ACT_REDIRECT,
        TC_ACT_SHOT,
    },
    helpers::{
        bpf_redirect, bpf_redirect_neigh, bpf_skb_change_head, bpf_skb_change_type,
        bpf_skb_get_tunnel_key, bpf_skb_get_tunnel_opt, bpf_skb_set_tunnel_key,
        bpf_skb_set_tunnel_opt,
    },
    macros::{classifier, map},
    maps::{Array, HashMap, LruHashMap, PerCpuArray},
    programs::TcContext,
};
use beep_common::{
    address_rewrite_checksums, backend_port_resolution, decap_forward_pod_admission,
    egress_return_admission, egress_return_outcome, encode_flow_key, encode_tcp_flow_key,
    forward_admission, fwd_pending_affinity_pin, ipv4_mapped_v6, is_redirected_return_mark,
    occupant_conflicts, peer_node_admission, resolve_backend_src_port, return_authorization,
    unmap_ipv4, AddressRewriteChecksums, BackendPortDecision, BackendPortResolution, Config,
    DecapForwardPodAdmission, EgressReturnAdmission, EgressReturnOutcome, FlowDirection, FlowKey,
    FlowValue, ForwardAdmission, ForwardFlowValue, FwdPendingPin, LbFrontBackend, LbFrontKey,
    PeerNodeAdmission, PortMemoValue, ReturnAuthorization, RevFlowValue, TcpFlowKey, UplinkConfig,
    REDIRECTED_RETURN_MARK,
};

/// VNI stamped on the forward leg (ingress -> backend). Host order -- see
/// module doc's wire-value convention.
const VNI_FWD: u32 = 100;
/// VNI stamped on the return leg (backend -> ingress). Distinguishing the
/// two directions by VNI is how `geneve_ingress` below resolves the
/// TC_ACT_OK-shadowing hazard from Phase 1's review: one program, one TCX
/// attachment on `geneve0` ingress, dispatching on this value, instead of
/// two programs racing to terminally-`TC_ACT_OK` the same chain.
const VNI_RET: u32 = 200;

/// Geneve option class for both TLVs this dataplane defines. `0xffff` is
/// IANA's "Experimental" class (RFC 8926 SS3.1) -- no allocation needed for a
/// private, single-implementation encoding. Wire order (see module doc).
const GENEVE_OPT_CLASS: u16 = 0xffffu16.to_be();
/// Forward-leg option: the pod-identifier the backend needs to pick a
/// target port (`docs/decisions/servicelb-ebpf-geneve-dataplane.md`
/// wire-format settlement: "raw pod IP for the pod identifier"), widened to
/// always carry the full dual-stack `[u8; 16]` shape (16 bytes: opt[4..20])
/// -- a v4 pod IP goes in `ipv4_mapped_v6`-embedded, a genuine v6 one as-is,
/// so this option's own encoding never needs a family branch, only the
/// surrounding inner-header parsing does.
const GENEVE_OPT_TYPE_POD_ID: u8 = 0x01;
/// Return-leg option: `LB_FRONT_IP:LB_FRONT_PORT` echo, captured by the
/// backend before it DNATs and echoed back so the ingress can un-DNAT
/// without its own state lookup racing the encap. Widened the same way as
/// `GENEVE_OPT_TYPE_POD_ID`: vip_ip is the full 16 bytes (opt[4..20]), plus
/// vip_port (2 bytes, opt[20..22]) and 2 bytes of padding to round the
/// option's data length up to a 4-byte-word multiple (RFC 8926 SS3.4).
const GENEVE_OPT_TYPE_VIP_ECHO: u8 = 0x02;

const ETH_HLEN: usize = 14;
const ETH_P_IPV4: u16 = 0x0800u16.to_be();
const ETH_P_IPV6: u16 = 0x86ddu16.to_be();
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
/// `enum pkt_type` value from `uapi/linux/if_packet.h` -- not exposed as a
/// binding constant by this aya-ebpf version, but a stable kernel uABI value.
/// See `bpf_skb_change_type`'s call sites below for why this is needed.
const PACKET_HOST: u32 = 0;

// IPv4-header-relative offsets (no options: IHL must be 5, checked before use).
const IP_VER_IHL: usize = ETH_HLEN;
const IP_PROTO: usize = ETH_HLEN + 9;
const IP_CSUM: usize = ETH_HLEN + 10;
const IP_SRC: usize = ETH_HLEN + 12;
const IP_DST: usize = ETH_HLEN + 16;
const IP_HLEN: usize = 20;
const L4_OFF: usize = ETH_HLEN + IP_HLEN;
// TCP and UDP share the same first 4 bytes: src_port(2), dst_port(2).
const L4_SPORT: usize = L4_OFF;
const L4_DPORT: usize = L4_OFF + 2;
const TCP_CSUM: usize = L4_OFF + 16;
const UDP_CSUM: usize = L4_OFF + 6;

// IPv6-header-relative offsets, for the `geneve0`-attached functions below
// that always parse a fixed `ETH_HLEN` (see each one's own doc comment on
// why `geneve0`'s inner frame is always Ethernet-framed regardless of the
// uplink). No extension headers: Next Header must name TCP/UDP directly,
// checked before use -- the same "no options" simplicity the v4 IHL==5
// check above applies. IPv6 has no header checksum field at all (module
// doc), so there is no `IP6_CSUM` analog of `IP_CSUM`.
const IP6_HLEN: usize = 40;
const IP6_NEXT_HDR: usize = ETH_HLEN + 6;
const IP6_SRC: usize = ETH_HLEN + 8;
const IP6_DST: usize = ETH_HLEN + 24;
const L4_OFF_V6: usize = ETH_HLEN + IP6_HLEN;
const L4_SPORT_V6: usize = L4_OFF_V6;
const L4_DPORT_V6: usize = L4_OFF_V6 + 2;
const TCP_CSUM_V6: usize = L4_OFF_V6 + 16;
const UDP_CSUM_V6: usize = L4_OFF_V6 + 6;

/// One static LB-front-IP:PORT -> backend mapping (fixture, populated once
/// by the userspace loader). Same `LbFrontKey` (`beep_common`) shape as
/// `TARGET_PORTS` below, but a separate map -- the two never interact, just
/// key on the same front tuple for the two different roles that need it
/// (ingress backend selection here, backend target-port selection there).
///
/// `max_entries` below is a load-time DEFAULT, not the enforced ceiling: the
/// userspace loader overrides it via `EbpfLoader::map_max_entries`
/// (`src/lib.rs`'s `load_ebpf`), same pattern as `FWD_PENDING`/`FLOW_TABLE`.
/// The controller's every-node-is-a-front keying (`ebpf-lb-dataplane.md`'s
/// "Packet flow" step 1) makes this map's entry count nodes x Service ports,
/// not just Service ports, so the old fixture-era 16 overflows at modest
/// cluster scale.
#[map]
static LB_FRONT_MAP: HashMap<LbFrontKey, LbFrontBackend> = HashMap::with_max_entries(4096, 0);

/// Backend-local: which target port a decap'd, DNAT'd packet should land on
/// for a given front (LB front IP:PORT:proto) -- keyed the same way as
/// `LB_FRONT_MAP` above, deliberately NOT on pod IP alone. A pod IP alone
/// cannot disambiguate a multi-port Service, a pod backing two Services, or
/// TCP/UDP on different ports; the forward Geneve option only ever carries
/// the raw pod IP (`ebpf-lb-dataplane.md`'s settled wire-format decision), so
/// the front tuple this map keys on -- still present on the packet's own
/// untouched inner dst at decap time -- is what disambiguates instead.
///
/// `max_entries` below is a load-time DEFAULT, not the enforced ceiling,
/// same override path and same nodes x Service-ports sizing pressure as
/// `LB_FRONT_MAP` above (every front_ip x Service-port pair -- `watch.rs`'s
/// `desired()` -- inserts into both maps 1:1, so the two share one default).
#[map]
static TARGET_PORTS: HashMap<LbFrontKey, u16> = HashMap::with_max_entries(4096, 0);

/// Backend-local: which pod IPs are this node's own beep backend Pods,
/// keyed on pod IP alone -- deliberately NOT on target port, unlike
/// `TARGET_PORTS` above. `try_uplink_egress_return` (hook 3) sees ALL
/// uplink egress traffic, not just beep's, so it probes this cheap
/// membership table BEFORE building the ~38-byte FLOW_TABLE key, to reject
/// unrelated traffic without ever touching the conntrack table.
/// Membership-only is what makes this safe across a rolling update or a
/// targetPort edit: a flow's FLOW_TABLE reverse-tagged entry was written
/// because the forward path found its pod here, so anything still live is
/// admitted regardless of what its target port used to be
/// (`beep_common::egress_return_admission`'s doc comment). Value is a bare
/// existence marker, never read.
///
/// Keyed on `[u8; 16]`, not a bare `u32`: same dual-stack union-key shape as
/// `NODE_ALLOW`/`LB_FRONT_MAP` -- a v4 pod IP is stored `ipv4_mapped_v6`-
/// embedded, a genuine v6 one as-is. A bare `u32` key could never represent
/// a real v6 backend Pod at all, so that Pod's traffic would silently miss
/// every membership check below and hook 3/4's decap+DNAT would drop it.
///
/// `try_geneve_decap_forward` (hook 4, the opposite direction) reuses this
/// same map and the same pod-IP-only key, not a (front tuple, pod_ip) pair:
/// this map has exactly one membership notion (this node's current backend
/// Pods), and a pod that's still one of this node's own is still one of
/// this node's own regardless of which front named it in the packet --
/// giving both directions of a flow one authoritative membership check
/// instead of two that could disagree.
/// <20 entries per `ebpf-lb-dataplane.md`'s sizing table, same as `TARGET_PORTS`.
#[map]
static POD_TARGETS: HashMap<[u8; 16], u8> = HashMap::with_max_entries(32, 0);

/// Peer-node attestation for the outer Geneve tunnel source
/// (`beep_common::peer_node_admission`'s doc comment for the threat this
/// closes). Keyed on `tkey.remote_ipv4` -- the outer source
/// `bpf_skb_get_tunnel_key` decap'd, in ITS host-native byte-order
/// convention (module doc), deliberately NOT `POD_TARGETS`' raw-wire-token
/// convention, since the two maps key on values read through different
/// paths (a kernel helper vs. a raw packet load). Populated by the
/// controller's Node watch (every known node's address, including this
/// node's own -- a node that is both ingress and backend for the same flow
/// legitimately sees its own address as the outer source) or, in fixture/
/// smoke mode with no controller, by the loader seeding `--node-ip` alone.
/// Same bare-existence-marker value as `POD_TARGETS` above; sized an order
/// of magnitude smaller (cluster node count, not Service count). Keyed on
/// `[u8; 16]`, not a bare `u32`: `remote_ipv4` is embedded via
/// `ipv4_mapped_v6` before lookup/insert so this map shares `FLOW_TABLE`'s
/// dual-stack union-key shape. Still `remote_ipv4`-only on the GET side
/// today (`geneve_ingress`'s tunnel-key read): the peer-attestation lookup
/// itself doesn't yet branch on whether the OUTER Geneve underlay is v4 or
/// v6 -- that's a separate concern from this bead's inner-packet family
/// support, and every fixture/smoke deployment today runs a v4-only
/// underlay regardless of the inner packet's own family. v1 constraint: one
/// IP per node (the single address `node_ips`/
/// `front_ips` in `controller/src/watch.rs` records) -- a multi-homed or
/// NAT'd node whose actual Geneve outer-source address differs from that
/// recorded address is dropped by this admission check. Symmetric
/// single-IP-per-node addressing is the deployment beep v1 targets; admitting
/// every address a Node reports is tracked separately.
#[map]
static NODE_ALLOW: HashMap<[u8; 16], u8> = HashMap::with_max_entries(16, 0);

/// Ingress-side forward-flow ADMISSION tier, written at stamp time (step
/// 2): every new flow mints here, and ONLY here (`try_uplink_ingress`, on a
/// `FLOW_TABLE` forward-tagged miss) -- so this is the only flood-exposed
/// conntrack table. A single floodable table let ~8192 packets from varying
/// source ports evict every established flow's forward entry in
/// milliseconds, since BPF LRU evicts strictly by recency with no notion of
/// "established" (`docs/decisions/servicelb-flow-admission-affinity.md`).
/// Modelled on nf_conntrack's unreplied/assured split: a flow reaches
/// `FLOW_TABLE`'s forward role exclusively via `try_geneve_decap_return`'s
/// promotion once the return leg proves the flow is genuinely bidirectional
/// -- a round trip an off-path spoofer cannot produce. A flood can churn
/// `FWD_PENDING` but can never evict a promoted forward entry out of
/// `FLOW_TABLE`. Kept as its OWN physical map rather than folded into
/// `FLOW_TABLE` as a third tag value, because BPF LRU eviction isn't
/// predicate-aware -- it cannot be told to skip assured entries, so a
/// flood-exposed tier must never share a physical LRU pool with an
/// admission-gated one. Both stay LRU (not plain HASH) so genuine
/// over-capacity degrades gracefully instead of returning E2BIG.
///
/// `max_entries` below is a load-time DEFAULT, not the enforced ceiling: the
/// userspace loader overrides it via `EbpfLoader::map_max_entries`
/// (`src/main.rs`'s `--fwd-pending-max-entries`), so sizing is a DaemonSet
/// config knob, not a value baked into this object.
///
/// Value type is `ForwardFlowValue` (the full backend identity --
/// `backend_node_ip` + `pod_ip` -- plus the ifindex this flow was admitted
/// on): aie31.21 pins the backend identity as the per-flow affinity target,
/// so this bead's admission logic already carries the shape aie31.21 needs
/// -- no map-shape change once affinity-follow lands. The admitting ifindex
/// rides along so `try_geneve_decap_return`'s multi-uplink symmetric-return
/// redirect can send the reply back out the SAME uplink the client's packet
/// arrived on (`docs/decisions/servicelb-multi-symmetric-uplink.md`).
///
/// Key type: `beep_common::TcpFlowKey`, a flat 37-byte array, not a
/// `#[repr(C)]` struct -- `BPF_MAP_TYPE_*_HASH` compares/hashes a key's raw
/// bytes including any compiler-inserted alignment padding, and a struct's
/// padding gap is left as whatever garbage was already on the call site's
/// stack, differing between independent call sites despite every named
/// field matching (Phase 2 hit exactly this on a live kernel: a byte-
/// identical insert+lookup, microseconds apart, still missed). A byte array
/// has no such gap. `FLOW_TABLE` below widens this same shape by one tag
/// byte rather than reusing it unmodified -- see its own doc comment.
///
/// `LRU_HASH`, not the doc's `LRU_PERCPU_HASH`: a per-CPU map keeps a
/// SEPARATE value per key per CPU, so a write on one CPU is invisible to a
/// read on another -- fatal for a rendezvous table where the write (step 2)
/// and the read (step 7) are different packets of the same flow with no
/// guaranteed same-CPU affinity. Confirmed empirically on this dataplane's
/// own single-VM smoke fixture (8 vCPUs): a plain retransmitted SYN,
/// processed on a different CPU than the original, saw a per-CPU miss and
/// broke the round trip intermittently -- not a churn/eviction edge case,
/// reproducible on the very first connection. `LRU_HASH` is still bounded
/// and evicting (the doc's core requirement over a naive `HashMap`), just
/// with one shared table instead of per-CPU shards.
#[map]
static FWD_PENDING: LruHashMap<TcpFlowKey, ForwardFlowValue> =
    LruHashMap::with_max_entries(2048, 0);

/// Unified forward(established)+reverse conntrack table, replacing the
/// former separate `FWD_MAIN`/`REV_FLOW` maps. Both roles key on the
/// identical 5-tuple shape for a given flow -- front tuple for forward,
/// backend tuple for reverse -- so `beep_common::FlowKey`'s explicit
/// `FlowDirection` tag byte, NOT VIP-vs-pod-CIDR address disjointness, is
/// what keeps the two from aliasing the same slot (that disjointness
/// invariant does not hold for a hostNetwork Pod, whose IP can equal a
/// VIP -- the tag is the fix for that exact misdelivery class). Value is
/// `FlowValue`, sized to the larger of the two prior maps (12 bytes,
/// `RevFlowValue`'s shape) -- see its own doc comment.
///
/// A node serving BOTH roles at once (common at small/single-digit endpoint
/// counts) now shares one LRU capacity pool between them: `FWD_PENDING`'s
/// isolation guarantee above still holds for the ADMISSION-GATED forward
/// role, but the reverse role has no admission gate of its own -- it writes
/// unconditionally on a backend node's first forward-decap for a flow, no
/// return leg required. On a dual-role node, a large enough burst of
/// reverse-role writes can therefore now evict an established forward-role
/// entry it could never reach while the two lived in separate physical
/// maps. Accepted trade-off for the tag-byte design's simplicity; the
/// entry-count ceiling below is sized to keep this a large-burst-only
/// concern, not a routine one, but the residual risk is real and worth a
/// follow-up if a dual-role deployment's reverse-role churn rate turns out
/// to be routine rather than exceptional. A remapped flow spends a third
/// slot in this same pool -- its `PortMemo` entry -- so it costs more than
/// the two slots a plain forward+reverse flow already occupies.
///
/// `max_entries` below is a load-time DEFAULT, not the enforced ceiling
/// (`src/main.rs`'s `--flow-table-max-entries`), same as `FWD_PENDING`.
/// 16384, not 8192: bpftool-measured bytes_memlock shows unifying at 8192
/// would halve today's combined FWD_MAIN+REV_FLOW capacity for a
/// single-role node while still halving worst-case capacity for a
/// dual-role one, whereas 16384 costs only ~64 KiB more than the 8192+8192
/// pair it replaces and gives back the full combined capacity as one
/// flexible pool -- strictly dominates 8192 for both node shapes.
///
/// `scripts/flow-table-burst-char.sh` empirically bounds the dual-role
/// eviction risk two paragraphs up: on a simulated dual-role node with 8
/// pre-established forward entries, a geometric burst of concurrent
/// reverse-role flows left all 8 intact through 32768 (this table at
/// ~16300-16370/16384 entries) but had evicted every one of them by
/// 65536, reproduced across four trials. Read as an order-of-magnitude
/// operational limit -- tens of thousands of concurrent reverse-role
/// flows, not low thousands -- not a precise boundary: the harness's
/// 90-second wall-clock cap stops sweeping at the first geometric
/// doubling step (512, 1024, ...) that shows an eviction, so the true
/// threshold is only bounded to (32768, 65536], and at that scale its
/// ephemeral-port-keyed burst generator collides against itself (65536
/// send attempts yielded ~16300 distinct entries, not 65536) -- "burst
/// size" above means send attempts, not a guaranteed distinct-flow count.
#[map]
static FLOW_TABLE: LruHashMap<FlowKey, FlowValue> = LruHashMap::with_max_entries(16384, 0);

/// `FLOW_TABLE.get` plus the union-field read for the caller's own role,
/// each wrapped so every call site names which role it expects instead of
/// repeating the `unsafe` union read inline. `#[inline(always)]` for the
/// same reason `try_geneve_decap_forward`/`_return` are (module doc):
/// several call sites, no downside to forcing inlining, and it sidesteps
/// this toolchain's non-inlined-BPF-to-BPF-call miscompile risk outright.
#[inline(always)]
fn flow_table_get_forward(key: FlowKey) -> Option<ForwardFlowValue> {
    unsafe { FLOW_TABLE.get(key) }.map(|v| unsafe { v.forward })
}

#[inline(always)]
fn flow_table_get_reverse(key: FlowKey) -> Option<RevFlowValue> {
    unsafe { FLOW_TABLE.get(key) }.map(|v| unsafe { v.reverse })
}

#[inline(always)]
fn flow_table_get_port_memo(key: FlowKey) -> Option<PortMemoValue> {
    unsafe { FLOW_TABLE.get(key) }.map(|v| unsafe { v.port_memo })
}

/// Counts packets dropped by `try_uplink_egress_return` on a FLOW_TABLE
/// reverse-tagged miss for already-identified backend Pod traffic
/// (`EgressReturnOutcome::Drop`) -- almost always an LRU eviction,
/// observable from userspace via `bpftool map dump` without needing a
/// kernel tracepoint. Single entry, per-CPU to avoid a shared-counter atomic
/// on this hot path.
#[map]
static EGRESS_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Host-specific runtime config the loader fills in after attach (an
/// ifindex isn't known until then). Single entry, `Config` (`beep_common`).
/// `geneve_ingress`'s parsing keeps using the compile-time `ETH_HLEN`
/// unconditionally -- `geneve0` is always a real (Ethernet-framed) netdev
/// regardless of what the uplink is.
#[map]
static CONFIG: Array<Config> = Array::with_max_entries(1, 0);

/// Per-uplink admission + L2 header length, keyed by ifindex
/// (`beep_common::UplinkConfig`) -- `try_uplink_ingress`'s hit-is-admission
/// gate for multi-uplink client traffic
/// (`docs/decisions/servicelb-multi-symmetric-uplink.md`). One entry per
/// configured `--uplink-iface`, written once by the loader at load time.
/// Bounded to a realistic per-node uplink count, not a raw-ifindex-sized
/// array -- ifindex values the host assigns aren't guaranteed contiguous.
/// Map name kept at 13 bytes: BPF_OBJ_NAME_LEN is 16 incl. NUL, and a
/// 17-char map name has been confirmed to truncate silently in `bpftool`.
#[map]
static UPLINK_CONFIG: HashMap<u32, UplinkConfig> = HashMap::with_max_entries(8, 0);

/// `TcContext::load`'s underlying helper (`bpf_skb_load_bytes`) is a
/// per-field helper call; `try_uplink_ingress`/`try_uplink_egress_return`
/// see every packet crossing the node's uplink, not just beep's, and pay
/// that cost on each header field before either hook can even reject
/// non-beep traffic. `ctx.data()`/`ctx.data_end()` expose the skb's linear
/// head directly, so a single bounds check against `data_end` is enough for
/// the verifier to accept a raw pointer read in its place. Linear-head-only
/// (no `bpf_skb_pull_data`), which is what both callers' headers are in
/// practice. Same raw-wire-token semantics as `TcContext::load` (module
/// doc): an unaligned copy of the bytes as they sit on the wire, no
/// byte-swap.
///
/// `offset` must be a compile-time constant at every call site, and NEVER
/// literally 0 -- confirmed against a live 6.8 kernel. A register-sourced
/// offset (even one the verifier can prove is a single exact value via
/// branch narrowing or a bitmask) never gets the bounds check's safe-range
/// credit; `try_uplink_ingress`/`try_uplink_egress_return` dispatch on a
/// const generic for exactly this reason (their doc comments). A literal
/// `0` offset fails too, for a different reason: `start + 0` optimizes away
/// the add entirely, so the pointer being checked is byte-for-byte the same
/// register `ctx.data()` produced, and that specific case never gets the
/// same credit a nonzero literal offset does either. Both are read as
/// "the verifier only credits a packet pointer that carries a nonzero
/// constant delta from `ctx.data()`" -- callers needing offset 0 must use
/// `TcContext::load` instead.
#[inline(always)]
fn load_direct<T: Copy>(ctx: &TcContext, offset: usize) -> Option<T> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + core::mem::size_of::<T>() > end {
        return None;
    }
    Some(unsafe { core::ptr::read_unaligned((start + offset) as *const T) })
}

/// Sets `tkey`'s Geneve tunnel remote from a `beep_common`-shaped dual-
/// stack node address (`LbFrontBackend::backend_node_ip`/
/// `RevFlowValue::ingress_node_ip`), returning the `flags`
/// `bpf_skb_set_tunnel_key` must be called with. A v4-mapped address goes
/// into `remote_ipv4` in the kernel's host-native convention (module doc,
/// confirmed empirically against a live kernel). A genuine v6 address has
/// no such host/wire distinction -- an IPv6 address's wire representation
/// IS its octets, there's no separate "host-order integer" form the way a
/// v4 address's `u32` has -- so its own bytes go into `remote_ipv6` as-is
/// (reinterpreted per 4-byte word, no swap) and `BPF_F_TUNINFO_IPV6` is set.
/// UNLIKE `remote_ipv4`'s convention, the v6 arm is reasoned from
/// `net/core/filter.c`'s `bpf_skb_set_tunnel_key` (its v6 arm does a raw
/// `struct in6_addr` memcpy with no host<->network conversion, unlike the
/// v4 arm's explicit `cpu_to_be32`) rather than confirmed against a live
/// kernel -- no v6-underlay rig exists yet to confirm it against.
#[inline(always)]
fn set_tunnel_remote(tkey: &mut bpf_tunnel_key, node_ip: &[u8; 16]) -> u64 {
    match unmap_ipv4(node_ip) {
        Some(v4) => {
            tkey.__bindgen_anon_1.remote_ipv4 = v4;
            0
        }
        None => {
            let mut words = [0u32; 4];
            for (i, word) in words.iter_mut().enumerate() {
                *word = u32::from_ne_bytes(node_ip[i * 4..i * 4 + 4].try_into().unwrap());
            }
            tkey.__bindgen_anon_1.remote_ipv6 = words;
            BPF_F_TUNINFO_IPV6 as u64
        }
    }
}

/// Hook 1: ingress classifier on the physical uplink, every node (forward
/// leg). Classifies LB-front-IP:PORT traffic, stamps Geneve metadata, redirects to
/// `geneve0`. Everything else passes through untouched -- this hook sees
/// all uplink traffic, not just beep's.
#[classifier]
pub fn uplink_ingress(ctx: TcContext) -> i32 {
    try_uplink_ingress(&ctx).unwrap_or(TC_ACT_OK)
}

fn try_uplink_ingress(ctx: &TcContext) -> Option<i32> {
    // A plain `__sk_buff` context-struct field read, not packet-data access
    // -- not subject to `load_direct`'s compile-time-offset constraint
    // below, and confirmed verifier-clean against a live kernel. At this
    // hook the packet's ingress ifindex IS the physical uplink it just
    // arrived on (this classifier is attached directly to that device's
    // ingress, before any redirect).
    let ingress_ifindex = unsafe { (*ctx.skb.skb).ingress_ifindex };
    // A per-uplink map hit is simultaneously admission (this ifindex is a
    // configured `--uplink-iface`) and the L2 header length to parse with --
    // a miss means an unconfigured interface, passed through untouched like
    // any other non-beep traffic
    // (`docs/decisions/servicelb-multi-symmetric-uplink.md`). The uplink can
    // be a real NIC/veth (14-byte Ethernet header) or an L3-only overlay
    // like WireGuard (no L2 header at all) -- resolved once by the loader
    // (`UplinkConfig`'s doc comment) since this no_std program has no
    // syscall of its own to tell the two apart.
    let l2_hlen = unsafe { UPLINK_CONFIG.get(ingress_ifindex) }?.l2_hlen as usize;
    // Dispatch on a const generic rather than threading `l2_hlen` through as
    // a runtime header-relative offset: this kernel's verifier never
    // re-establishes a packet pointer's safe range after a bounds check once
    // a register-sourced value has gone into the pointer arithmetic, even
    // when that register is provably a single constant (confirmed
    // empirically -- narrowing the value via an equality branch, and via a
    // bitmask, both still left `load_direct`'s read rejected as "offset is
    // outside of the packet"). Every `load_direct` offset in
    // `try_uplink_ingress_headers` needs to fold to a literal at compile
    // time, which only a const generic guarantees.
    match l2_hlen {
        0 => try_uplink_ingress_headers::<0>(ctx, ingress_ifindex),
        ETH_HLEN => try_uplink_ingress_headers::<ETH_HLEN>(ctx, ingress_ifindex),
        _ => Some(TC_ACT_OK),
    }
}

/// Dispatches on the inner packet's own address family before parsing any
/// family-specific header field -- an Ethernet-framed uplink has an
/// EtherType to read (offset 12); an L3-only uplink (L2_HLEN==0) has none,
/// so the IP-version nibble at offset 0 is the only signal. Two siblings,
/// not one runtime-branched body: `load_direct`'s offsets must be compile-
/// time literals (its own doc comment), and v4/v6 header layouts differ in
/// both width and field offsets.
#[inline(always)]
fn try_uplink_ingress_headers<const L2_HLEN: usize>(
    ctx: &TcContext,
    ingress_ifindex: u32,
) -> Option<i32> {
    if L2_HLEN == ETH_HLEN {
        match load_direct::<u16>(ctx, 12)? {
            ETH_P_IPV4 => try_uplink_ingress_headers_v4::<L2_HLEN>(ctx, ingress_ifindex),
            ETH_P_IPV6 => try_uplink_ingress_headers_v6::<L2_HLEN>(ctx, ingress_ifindex),
            _ => Some(TC_ACT_OK),
        }
    } else {
        let ver: u8 = ctx.load(0).ok()?;
        match ver >> 4 {
            4 => try_uplink_ingress_headers_v4::<L2_HLEN>(ctx, ingress_ifindex),
            6 => try_uplink_ingress_headers_v6::<L2_HLEN>(ctx, ingress_ifindex),
            _ => Some(TC_ACT_OK),
        }
    }
}

#[inline(always)]
fn try_uplink_ingress_headers_v4<const L2_HLEN: usize>(
    ctx: &TcContext,
    ingress_ifindex: u32,
) -> Option<i32> {
    // `load_direct`'s doc comment: offset 0 (the L3-only/WireGuard branch,
    // L2_HLEN==0) can't go through it, so this one field on that branch
    // stays on the helper call; every other read on both branches has a
    // nonzero literal offset and gets direct access.
    let ver_ihl: u8 = if L2_HLEN == 0 {
        ctx.load(0).ok()?
    } else {
        load_direct(ctx, L2_HLEN)?
    };
    if ver_ihl >> 4 != 4 || ver_ihl & 0x0f != 5 {
        return Some(TC_ACT_OK);
    }
    let ip_proto = L2_HLEN + 9;
    let ip_src = L2_HLEN + 12;
    let ip_dst = L2_HLEN + 16;
    let l4_off = L2_HLEN + IP_HLEN;
    let l4_sport = l4_off;
    let l4_dport = l4_off + 2;

    let proto: u8 = load_direct(ctx, ip_proto)?;
    if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
        return Some(TC_ACT_OK);
    }

    let dst_ip: u32 = load_direct(ctx, ip_dst)?;
    let dst_port: u16 = load_direct(ctx, l4_dport)?;
    let vip_ip_v6 = ipv4_mapped_v6(dst_ip);
    let key = LbFrontKey {
        vip_ip: vip_ip_v6,
        vip_port: dst_port,
        proto,
        _pad: 0,
    };
    let backend = *unsafe { LB_FRONT_MAP.get(key) }?;

    let src_ip: u32 = load_direct(ctx, ip_src)?;
    let src_port: u16 = load_direct(ctx, l4_sport)?;
    let client_ip_v6 = ipv4_mapped_v6(src_ip);
    // Untagged: only FWD_PENDING (never merged into FLOW_TABLE, see its doc
    // comment) uses this shape.
    let flow_key = encode_tcp_flow_key(client_ip_v6, src_port, vip_ip_v6, dst_port, proto);
    let fwd_key = encode_flow_key(
        client_ip_v6,
        src_port,
        vip_ip_v6,
        dst_port,
        proto,
        FlowDirection::Forward,
    );
    // Admission control: an established flow (FLOW_TABLE forward-tagged
    // hit) needs no write at all -- the lookup itself refreshed its LRU
    // recency. A new flow mints ONLY into FWD_PENDING, never FLOW_TABLE
    // directly, so an off-path flood of forward-only packets can churn
    // FWD_PENDING but can never touch an established flow's FLOW_TABLE
    // entry.
    if let ForwardAdmission::MintPending =
        forward_admission(unsafe { FLOW_TABLE.get(fwd_key) }.is_some())
    {
        // A PENDING lookup is an RCU read that already refreshes this
        // entry's LRU recency, so once minted the backend choice never
        // needs rewriting -- a write takes the bucket's raw_spinlock and can
        // run the LRU shrink path, unlike a read.
        let admitted = ForwardFlowValue {
            backend,
            ingress_ifindex,
        };
        match fwd_pending_affinity_pin(unsafe { FWD_PENDING.get(flow_key) }.copied(), admitted) {
            FwdPendingPin::Insert(candidate) => {
                FWD_PENDING.insert(flow_key, candidate, 0).ok()?;
            }
            FwdPendingPin::Keep => {}
        }
    }

    let geneve_ifindex = CONFIG.get(0)?.geneve_ifindex;

    let mut tkey: bpf_tunnel_key = unsafe { core::mem::zeroed() };
    let tkey_flags = set_tunnel_remote(&mut tkey, &backend.backend_node_ip);
    tkey.tunnel_id = VNI_FWD;
    tkey.tunnel_ttl = 64;
    if unsafe {
        bpf_skb_set_tunnel_key(
            ctx.skb.skb,
            &mut tkey,
            core::mem::size_of::<bpf_tunnel_key>() as u32,
            tkey_flags,
        )
    } != 0
    {
        return Some(TC_ACT_SHOT);
    }

    let mut opt = [0u8; 20];
    opt[0..2].copy_from_slice(&GENEVE_OPT_CLASS.to_ne_bytes());
    opt[2] = GENEVE_OPT_TYPE_POD_ID;
    opt[3] = 4; // opt_data length in 4-byte words (16 bytes, dual-stack pod_ip).
    opt[4..20].copy_from_slice(&backend.pod_ip);
    if unsafe { bpf_skb_set_tunnel_opt(ctx.skb.skb, opt.as_mut_ptr().cast(), opt.len() as u32) }
        != 0
    {
        return Some(TC_ACT_SHOT);
    }

    // An L3-only (WireGuard) uplink never gave this skb a MAC header, but
    // geneve0 is always Ethernet-type: dev_queue_xmit's redirect path drops
    // any skb with mac_len==0 targeting an Ethernet device (confirmed via a
    // live kfree_skb trace, __bpf_redirect, reason NOT_SPECIFIED).
    // bpf_skb_change_head resets both mac_header and mac_len, satisfying
    // that contract; the zeroed 14 bytes it inserts become the Geneve
    // inner frame's L2 header, which decap's hard-coded ETH_HLEN skip
    // already expects (see try_geneve_decap_forward/_return). The inserted
    // bytes are otherwise zero, so the EtherType field must be stamped
    // explicitly -- decap's own EtherType check (unconditional, since
    // geneve0's inner frame is always "real" Ethernet from its point of
    // view) would otherwise silently no-op on a live-captured all-zero
    // EtherType (confirmed via a raw packet capture on the peer's wg0).
    if L2_HLEN == 0 {
        if unsafe { bpf_skb_change_head(ctx.skb.skb, ETH_HLEN as u32, 0) } != 0 {
            return Some(TC_ACT_SHOT);
        }
        // A stack local, not `&ETH_P_IPV4` directly: referencing the const
        // promotes it into a shared `.rodata` allocation, which bpftool's
        // map-discovery walk (and the CI memory-smoke gate) counts as a 9th
        // "map".
        let ethertype = ETH_P_IPV4;
        if ctx.store(12, &ethertype, 0).is_err() {
            return Some(TC_ACT_SHOT);
        }
    }

    if unsafe { bpf_redirect(geneve_ifindex, 0) } as i32 != TC_ACT_REDIRECT {
        return Some(TC_ACT_SHOT);
    }
    Some(TC_ACT_REDIRECT)
}

/// IPv6 sibling of `try_uplink_ingress_headers_v4` -- same steps, IPv6
/// header shape (module doc): a 16-byte address at a different offset, no
/// IHL/options check (v6's base header is always exactly `IP6_HLEN`), Next
/// Header instead of Protocol. `vip_ip_v6`/`client_ip_v6` need no
/// `ipv4_mapped_v6` embedding -- a genuine v6 address's own octets already
/// are the dual-stack `[u8; 16]` shape every map below keys on.
#[inline(always)]
fn try_uplink_ingress_headers_v6<const L2_HLEN: usize>(
    ctx: &TcContext,
    ingress_ifindex: u32,
) -> Option<i32> {
    let ver: u8 = if L2_HLEN == 0 {
        ctx.load(0).ok()?
    } else {
        load_direct(ctx, L2_HLEN)?
    };
    if ver >> 4 != 6 {
        return Some(TC_ACT_OK);
    }
    let ip6_next_hdr = L2_HLEN + 6;
    let ip6_src = L2_HLEN + 8;
    let ip6_dst = L2_HLEN + 24;
    let l4_off = L2_HLEN + IP6_HLEN;
    let l4_sport = l4_off;
    let l4_dport = l4_off + 2;

    let proto: u8 = load_direct(ctx, ip6_next_hdr)?;
    if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
        return Some(TC_ACT_OK);
    }

    let vip_ip_v6: [u8; 16] = load_direct(ctx, ip6_dst)?;
    let dst_port: u16 = load_direct(ctx, l4_dport)?;
    let key = LbFrontKey {
        vip_ip: vip_ip_v6,
        vip_port: dst_port,
        proto,
        _pad: 0,
    };
    let backend = *unsafe { LB_FRONT_MAP.get(key) }?;

    let client_ip_v6: [u8; 16] = load_direct(ctx, ip6_src)?;
    let src_port: u16 = load_direct(ctx, l4_sport)?;
    // Untagged: only FWD_PENDING (never merged into FLOW_TABLE, see its doc
    // comment) uses this shape.
    let flow_key = encode_tcp_flow_key(client_ip_v6, src_port, vip_ip_v6, dst_port, proto);
    let fwd_key = encode_flow_key(
        client_ip_v6,
        src_port,
        vip_ip_v6,
        dst_port,
        proto,
        FlowDirection::Forward,
    );
    if let ForwardAdmission::MintPending =
        forward_admission(unsafe { FLOW_TABLE.get(fwd_key) }.is_some())
    {
        let admitted = ForwardFlowValue {
            backend,
            ingress_ifindex,
        };
        match fwd_pending_affinity_pin(unsafe { FWD_PENDING.get(flow_key) }.copied(), admitted) {
            FwdPendingPin::Insert(candidate) => {
                FWD_PENDING.insert(flow_key, candidate, 0).ok()?;
            }
            FwdPendingPin::Keep => {}
        }
    }

    let geneve_ifindex = CONFIG.get(0)?.geneve_ifindex;

    let mut tkey: bpf_tunnel_key = unsafe { core::mem::zeroed() };
    let tkey_flags = set_tunnel_remote(&mut tkey, &backend.backend_node_ip);
    tkey.tunnel_id = VNI_FWD;
    tkey.tunnel_ttl = 64;
    if unsafe {
        bpf_skb_set_tunnel_key(
            ctx.skb.skb,
            &mut tkey,
            core::mem::size_of::<bpf_tunnel_key>() as u32,
            tkey_flags,
        )
    } != 0
    {
        return Some(TC_ACT_SHOT);
    }

    let mut opt = [0u8; 20];
    opt[0..2].copy_from_slice(&GENEVE_OPT_CLASS.to_ne_bytes());
    opt[2] = GENEVE_OPT_TYPE_POD_ID;
    opt[3] = 4; // opt_data length in 4-byte words (16 bytes, dual-stack pod_ip).
    opt[4..20].copy_from_slice(&backend.pod_ip);
    if unsafe { bpf_skb_set_tunnel_opt(ctx.skb.skb, opt.as_mut_ptr().cast(), opt.len() as u32) }
        != 0
    {
        return Some(TC_ACT_SHOT);
    }

    // See try_uplink_ingress_headers_v4's matching comment: an L3-only
    // uplink's synthesized MAC header needs its EtherType stamped
    // explicitly, this inner packet's own family this time.
    if L2_HLEN == 0 {
        if unsafe { bpf_skb_change_head(ctx.skb.skb, ETH_HLEN as u32, 0) } != 0 {
            return Some(TC_ACT_SHOT);
        }
        let ethertype = ETH_P_IPV6;
        if ctx.store(12, &ethertype, 0).is_err() {
            return Some(TC_ACT_SHOT);
        }
    }

    if unsafe { bpf_redirect(geneve_ifindex, 0) } as i32 != TC_ACT_REDIRECT {
        return Some(TC_ACT_SHOT);
    }
    Some(TC_ACT_REDIRECT)
}

/// Hook 2+4 merged: ingress classifier on `geneve0`, dispatched by the
/// stamped VNI into the backend's forward-decap role or the ingress node's
/// return-decap role. A node that is both roles at once is exactly the case
/// Phase 1's review flagged: two `TC_ACT_OK`-terminal TCX programs on the
/// same ingress chain permanently shadow one another once either carries
/// real logic. Merging into one program keyed on the flow (here, the VNI)
/// removes the ambiguity outright instead of ordering it away with
/// `TC_ACT_UNSPEC` hand-off, which would still depend on attach order.
///
/// `try_geneve_decap_forward`/`_return` are `#[inline(always)]`, not
/// `#[inline(never)]`: the bpf-linker/LLVM combination in this toolchain
/// miscompiles a real (non-inlined) BPF-to-BPF call whose callee returns
/// `Option<i32>` -- the caller reads the discriminant back out of a
/// scratch argument register (R2) instead of the return register (R0),
/// which the verifier correctly rejects as a read of an uninitialized,
/// call-clobbered register (confirmed on a live kernel: `bpf_link_create`
/// EPERM, verifier trace pinpoints `R2 !read_ok` immediately after the
/// call instruction). Since each of these helpers has exactly one call
/// site, forcing inlining has no downside and sidesteps the bug entirely.
#[classifier]
pub fn geneve_ingress(ctx: TcContext) -> i32 {
    let mut tkey: bpf_tunnel_key = unsafe { core::mem::zeroed() };
    if unsafe {
        bpf_skb_get_tunnel_key(
            ctx.skb.skb,
            &mut tkey,
            core::mem::size_of::<bpf_tunnel_key>() as u32,
            0,
        )
    } != 0
    {
        return TC_ACT_OK;
    }

    match tkey.tunnel_id {
        VNI_FWD => try_geneve_decap_forward(&ctx, &tkey).unwrap_or(TC_ACT_SHOT),
        VNI_RET => try_geneve_decap_return(&ctx, &tkey).unwrap_or(TC_ACT_SHOT),
        _ => TC_ACT_OK,
    }
}

/// Backend role (step 4): gate the Geneve option's stamped pod_ip on
/// POD_TARGETS membership -- this node, not a possibly-lagging ingress, is
/// the authoritative consistency point for whether that pod is still one of
/// its own -- read `LB_FRONT_IP:LB_FRONT_PORT` off the still-untouched inner dst
/// BEFORE rewriting anything, record the reverse-flow entry, DNAT dst to
/// `PodIP:TargetPort` (src untouched -- the Pod must see the real client IP
/// at L3), then hand the packet to the normal receive path: `TC_ACT_OK` on
/// an inbound decap leaves the now-foreign-dst'd packet to the kernel's own
/// routing, which is flannel's job from here, not ours.
#[inline(always)]
fn try_geneve_decap_forward(ctx: &TcContext, tkey: &bpf_tunnel_key) -> Option<i32> {
    // Peer-node attestation, checked before anything else this hook does
    // (`beep_common::peer_node_admission`'s doc comment): with rp_filter=0
    // node-wide, the outer tunnel source is the only thing standing between
    // a spoofed decap-forward and delivery. NODE_ALLOW is empty until the
    // controller's Node LIST fully completes (`reconcile::DesiredEntries::
    // node_allow`'s doc comment) -- a strictly cold-start-only, wider window
    // than the pre-existing POD_TARGETS check below alone required; accepted
    // as the cost of not reintroducing a restart-wipe risk on this map.
    let is_known_peer =
        unsafe { NODE_ALLOW.get(ipv4_mapped_v6(tkey.__bindgen_anon_1.remote_ipv4)) }.is_some();
    if let PeerNodeAdmission::Drop = peer_node_admission(is_known_peer) {
        return Some(TC_ACT_SHOT);
    }

    // The Geneve option and the POD_TARGETS membership gate it feeds are
    // both family-agnostic (module doc's option-widening: the pod-id TLV is
    // always the full dual-stack `[u8; 16]` shape) -- read and check them
    // once here, before the inner packet's own family is even known, so
    // `_v4`/`_v6` below don't each need their own copy of this block.
    let mut opt = [0u8; 20];
    if unsafe { bpf_skb_get_tunnel_opt(ctx.skb.skb, opt.as_mut_ptr().cast(), opt.len() as u32) } < 0
    {
        return Some(TC_ACT_SHOT);
    }
    if opt[0..2] != GENEVE_OPT_CLASS.to_ne_bytes() || opt[2] != GENEVE_OPT_TYPE_POD_ID {
        return Some(TC_ACT_SHOT);
    }
    let pod_ip_v6: [u8; 16] = opt[4..20].try_into().ok()?;

    // Membership gate: TARGET_PORTS below only confirms this node hosts
    // SOME backend for the front, never that this specific pod_ip -- as
    // stamped by the ingress node, possibly stale under cross-node
    // convergence drift -- is still one of this node's own pods. Same
    // pod-IP-only POD_TARGETS membership `try_uplink_egress_return` gates
    // its own direction on (`egress_return_admission`'s doc comment),
    // checked here before the front-tuple TARGET_PORTS lookup so a
    // not-our-pod packet is rejected off the cheaper key first.
    let is_local_pod = unsafe { POD_TARGETS.get(pod_ip_v6) }.is_some();
    if let DecapForwardPodAdmission::Drop = decap_forward_pod_admission(is_local_pod) {
        return Some(TC_ACT_SHOT);
    }

    match ctx.load::<u16>(12).ok()? {
        ETH_P_IPV4 => try_geneve_decap_forward_v4(ctx, tkey, pod_ip_v6),
        ETH_P_IPV6 => try_geneve_decap_forward_v6(ctx, tkey, pod_ip_v6),
        _ => Some(TC_ACT_OK),
    }
}

#[inline(always)]
fn try_geneve_decap_forward_v4(
    ctx: &TcContext,
    tkey: &bpf_tunnel_key,
    pod_ip_v6: [u8; 16],
) -> Option<i32> {
    if ctx.load::<u8>(IP_VER_IHL).ok()? & 0x0f != 5 {
        return Some(TC_ACT_OK);
    }
    let proto: u8 = ctx.load(IP_PROTO).ok()?;
    if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
        return Some(TC_ACT_OK);
    }

    let client_ip: u32 = ctx.load(IP_SRC).ok()?;
    let client_port: u16 = ctx.load(L4_SPORT).ok()?;
    let vip_ip: u32 = ctx.load(IP_DST).ok()?; // captured before rewrite
    let vip_port: u16 = ctx.load(L4_DPORT).ok()?; // captured before rewrite

    // Re-keyed off the front the packet still carries at decap time, not the
    // Geneve option's pod IP: the pod IP alone can't tell 80->8080 apart from
    // 443->8443 on the same pod (`TARGET_PORTS`' doc comment).
    let target_port = *unsafe {
        TARGET_PORTS.get(LbFrontKey {
            vip_ip: ipv4_mapped_v6(vip_ip),
            vip_port,
            proto,
            _pad: 0,
        })
    }?;

    let client_ip_v6 = ipv4_mapped_v6(client_ip);
    let vip_ip_v6 = ipv4_mapped_v6(vip_ip);
    let natural_rev_key = encode_flow_key(
        client_ip_v6,
        client_port,
        pod_ip_v6,
        target_port,
        proto,
        FlowDirection::Reverse,
    );
    // Keyed on the flow's natural (real client port, never a remapped one)
    // tuple, so it's the same key on every packet of this flow regardless of
    // whether the flow ends up remapped -- see
    // `beep_common::backend_port_resolution`'s doc comment for why
    // re-deriving the port from `resolve_backend_src_port`'s probe on every
    // packet is unsafe under LRU eviction.
    let port_memo_key = encode_flow_key(
        client_ip_v6,
        client_port,
        pod_ip_v6,
        target_port,
        proto,
        FlowDirection::PortMemo,
    );
    let memoized_port = flow_table_get_port_memo(port_memo_key).map(|v| v.backend_src_port);

    let (rev_key, backend_src_port) = match backend_port_resolution(memoized_port) {
        BackendPortResolution::Memoized(port) => (
            encode_flow_key(
                client_ip_v6,
                port,
                pod_ip_v6,
                target_port,
                proto,
                FlowDirection::Reverse,
            ),
            port,
        ),
        BackendPortResolution::Probe => {
            // Decision 3 (`ebpf-lb-dataplane.md`): two Services with different front
            // addresses sharing this backend Pod:targetPort, hit by a client
            // reusing one source port across both, would otherwise write this same
            // reverse key twice. Check whether a DIFFERENT (front, original client
            // port) identity already holds it before trusting the natural key -- a
            // matching identity (or no entry at all) means this is the same flow
            // refreshing, or the first writer. Front alone isn't enough: a distinct
            // flow through this same front whose real source port happens to equal
            // another flow's already-committed synthetic port would otherwise be
            // misread as that flow's own state and clobber its reverse-tagged entry.
            // `RevFlowValue::vip_ip` and `resolve_backend_src_port`'s `new_front` are
            // both `[u8; 16]`, so this compares the full dual-stack shape directly --
            // no `unmap_ipv4` round-trip needed (that round-trip used to be required
            // because this probe was `u32`-only; widened once a genuine, non-mapped
            // v6 front became possible to parse at all).
            let existing_occupant = flow_table_get_reverse(natural_rev_key)
                .map(|v| ((v.vip_ip, v.vip_port), v.original_client_port));
            let new_front = (vip_ip_v6, vip_port);
            // The probe's occupancy check: FLOW_TABLE's reverse-tagged entries are
            // the source of truth for which candidate ports are actually free, not
            // a derived guess -- a single low-entropy hash of the front address only
            // guaranteed uniqueness for exactly 2 conflicting fronts. An occupant
            // matching both our own front and our own original client port is a
            // prior packet of this exact flow's already-committed remap, not a
            // conflict -- without that full comparison the flow (or an unrelated
            // flow reusing its synthetic port as a real source port) reads state
            // back as "taken"/"mine" incorrectly and either churns ports until
            // PROBE_LIMIT is exhausted, or silently clobbers another flow's entry.
            //
            // `candidate_key` is built ONCE and patched in place per candidate: its
            // address escapes into `bpf_map_lookup_elem` on every probe call, so the
            // compiler can't hoist the build itself, and PROBE_LIMIT's constant trip
            // count means this loop very likely fully unrolls -- re-encoding all 38
            // bytes per iteration would put 16 copies of that build into program
            // text for the sake of the 2 bytes (the port) that actually change.
            let mut candidate_key = encode_flow_key(
                client_ip_v6,
                0,
                pod_ip_v6,
                target_port,
                proto,
                FlowDirection::Reverse,
            );
            let is_reverse_key_taken = |candidate_port: u16| {
                candidate_key[32..34].copy_from_slice(&candidate_port.to_ne_bytes());
                let occupant = flow_table_get_reverse(candidate_key)
                    .map(|v| ((v.vip_ip, v.vip_port), v.original_client_port));
                occupant_conflicts(occupant, new_front, client_port)
            };
            match resolve_backend_src_port(
                existing_occupant,
                new_front,
                client_port,
                is_reverse_key_taken,
            ) {
                BackendPortDecision::NoRemap => (natural_rev_key, client_port),
                BackendPortDecision::Remap(synthetic_port) => {
                    // Persist so every later packet of this flow reuses this
                    // exact port instead of re-probing. Never written for
                    // NoRemap: that outcome is already stable across any
                    // table churn (it never depends on other occupants), so
                    // it needs no memo.
                    FLOW_TABLE
                        .insert(
                            port_memo_key,
                            FlowValue {
                                port_memo: PortMemoValue {
                                    backend_src_port: synthetic_port,
                                },
                            },
                            0,
                        )
                        .ok()?;
                    // The probe's last iteration already patched
                    // `candidate_key` to exactly this winning port -- reuse
                    // it instead of re-encoding.
                    (candidate_key, synthetic_port)
                }
                // Every candidate in the bounded probe window was already taken --
                // drop rather than reuse an occupied reverse key, which would
                // silently reproduce the exact clobbering bug Decision 3 closes.
                BackendPortDecision::Exhausted => return Some(TC_ACT_SHOT),
            }
        }
    };

    let rev_value = RevFlowValue {
        ingress_node_ip: ipv4_mapped_v6(unsafe { tkey.__bindgen_anon_1.remote_ipv4 }),
        vip_ip: vip_ip_v6,
        vip_port,
        original_client_port: client_port,
    };
    // Unlike FWD_PENDING's value, this one can legitimately change under the
    // SAME key -- e.g. the ingress node for this flow changes -- so the gate
    // is exists-AND-matches, not existence alone: a write is skipped only
    // when it would be a byte-for-byte no-op.
    if flow_table_get_reverse(rev_key) != Some(rev_value) {
        FLOW_TABLE
            .insert(rev_key, FlowValue { reverse: rev_value }, 0)
            .ok()?;
    }

    // Remap only touches the backend<->Pod segment: the client's real src
    // port is restored by the egress classifier before the packet re-enters
    // the Geneve tunnel (see RevFlowValue's doc comment). A no-op when this
    // flow wasn't remapped.
    rewrite_l4_port(ctx, L4_OFF, L4_SPORT, client_port, backend_src_port, proto)?;

    // `?`, not a fallback: this front is v4 (dispatched here on ETH_P_IPV4),
    // so its Service must pair a v4 pod_ip too, or there is no v4 IP_DST
    // width to DNAT into at all -- a v6-pod-behind-a-v4-VIP fixture is a
    // misconfiguration this drops rather than corrupts.
    rewrite_ip_port(
        ctx,
        IP_DST,
        vip_ip,
        unmap_ipv4(&pod_ip_v6)?,
        L4_DPORT,
        vip_port,
        target_port,
        proto,
    )?;

    // A decap'd skb inherits the tunneled inner Ethernet header UNCHANGED
    // from the encapsulating end (`bpf_skb_set_tunnel_key`/`_opt` stamp
    // metadata alongside the packet, they never touch its data), so its dst
    // MAC is still whatever real NIC address received it there -- never
    // this node's `geneve0`. `ip_rcv_core()` silently drops any inbound skb
    // classified `PACKET_OTHERHOST` before routing/delivery ever runs
    // (confirmed on a live kernel via the `kfree_skb` tracepoint:
    // `location=ip_rcv_core+.. reason: OTHERHOST`); `bpf_skb_change_type`
    // is the kernel's own escape hatch for exactly this class of
    // encap/decap mismatch, forcing local-delivery eligibility so routing
    // keys off the (correct, just-rewritten) IP destination instead.
    if unsafe { bpf_skb_change_type(ctx.skb.skb, PACKET_HOST) } != 0 {
        return Some(TC_ACT_SHOT);
    }

    Some(TC_ACT_OK)
}

/// IPv6 sibling of `try_geneve_decap_forward_v4` -- same steps (Decision 3's
/// port-remap probe now works identically for either family, since
/// `resolve_backend_src_port`'s front tuple is `[u8; 16]`), IPv6 header
/// shape (module doc), and `rewrite_ipv6_port` in place of `rewrite_ip_port`
/// for the final DNAT (no IP-header checksum to fix up, pseudo-header fixup
/// done 4 words at a time).
#[inline(always)]
fn try_geneve_decap_forward_v6(
    ctx: &TcContext,
    tkey: &bpf_tunnel_key,
    pod_ip_v6: [u8; 16],
) -> Option<i32> {
    let proto: u8 = ctx.load(IP6_NEXT_HDR).ok()?;
    if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
        return Some(TC_ACT_OK);
    }

    let client_ip_v6: [u8; 16] = ctx.load(IP6_SRC).ok()?;
    let client_port: u16 = ctx.load(L4_SPORT_V6).ok()?;
    let vip_ip_v6: [u8; 16] = ctx.load(IP6_DST).ok()?; // captured before rewrite
    let vip_port: u16 = ctx.load(L4_DPORT_V6).ok()?; // captured before rewrite

    let target_port = *unsafe {
        TARGET_PORTS.get(LbFrontKey {
            vip_ip: vip_ip_v6,
            vip_port,
            proto,
            _pad: 0,
        })
    }?;

    let natural_rev_key = encode_flow_key(
        client_ip_v6,
        client_port,
        pod_ip_v6,
        target_port,
        proto,
        FlowDirection::Reverse,
    );
    let port_memo_key = encode_flow_key(
        client_ip_v6,
        client_port,
        pod_ip_v6,
        target_port,
        proto,
        FlowDirection::PortMemo,
    );
    let memoized_port = flow_table_get_port_memo(port_memo_key).map(|v| v.backend_src_port);

    let (rev_key, backend_src_port) = match backend_port_resolution(memoized_port) {
        BackendPortResolution::Memoized(port) => (
            encode_flow_key(
                client_ip_v6,
                port,
                pod_ip_v6,
                target_port,
                proto,
                FlowDirection::Reverse,
            ),
            port,
        ),
        BackendPortResolution::Probe => {
            let existing_occupant = flow_table_get_reverse(natural_rev_key)
                .map(|v| ((v.vip_ip, v.vip_port), v.original_client_port));
            let new_front = (vip_ip_v6, vip_port);
            let mut candidate_key = encode_flow_key(
                client_ip_v6,
                0,
                pod_ip_v6,
                target_port,
                proto,
                FlowDirection::Reverse,
            );
            let is_reverse_key_taken = |candidate_port: u16| {
                candidate_key[32..34].copy_from_slice(&candidate_port.to_ne_bytes());
                let occupant = flow_table_get_reverse(candidate_key)
                    .map(|v| ((v.vip_ip, v.vip_port), v.original_client_port));
                occupant_conflicts(occupant, new_front, client_port)
            };
            match resolve_backend_src_port(
                existing_occupant,
                new_front,
                client_port,
                is_reverse_key_taken,
            ) {
                BackendPortDecision::NoRemap => (natural_rev_key, client_port),
                BackendPortDecision::Remap(synthetic_port) => {
                    FLOW_TABLE
                        .insert(
                            port_memo_key,
                            FlowValue {
                                port_memo: PortMemoValue {
                                    backend_src_port: synthetic_port,
                                },
                            },
                            0,
                        )
                        .ok()?;
                    (candidate_key, synthetic_port)
                }
                BackendPortDecision::Exhausted => return Some(TC_ACT_SHOT),
            }
        }
    };

    let rev_value = RevFlowValue {
        ingress_node_ip: ipv4_mapped_v6(unsafe { tkey.__bindgen_anon_1.remote_ipv4 }),
        vip_ip: vip_ip_v6,
        vip_port,
        original_client_port: client_port,
    };
    if flow_table_get_reverse(rev_key) != Some(rev_value) {
        FLOW_TABLE
            .insert(rev_key, FlowValue { reverse: rev_value }, 0)
            .ok()?;
    }

    rewrite_l4_port(
        ctx,
        L4_OFF_V6,
        L4_SPORT_V6,
        client_port,
        backend_src_port,
        proto,
    )?;

    rewrite_ipv6_port(
        ctx,
        IP6_DST,
        vip_ip_v6,
        pod_ip_v6,
        L4_DPORT_V6,
        vip_port,
        target_port,
        proto,
        if proto == IPPROTO_TCP {
            TCP_CSUM_V6
        } else {
            UDP_CSUM_V6
        },
        UDP_CSUM_V6,
    )?;

    if unsafe { bpf_skb_change_type(ctx.skb.skb, PACKET_HOST) } != 0 {
        return Some(TC_ACT_SHOT);
    }

    Some(TC_ACT_OK)
}

/// Ingress role (step 7): read `CLIENT_IP:SRC_PORT` off the inner dst and
/// `LB_FRONT_IP:LB_FRONT_PORT` off the Geneve echo, confirm this return answers a flow
/// this node actually forwarded (drop otherwise -- an echo with no matching
/// forward entry is stale or spoofed), then un-DNAT src back to the VIP and
/// let normal routing carry it out to the client.
#[inline(always)]
fn try_geneve_decap_return(ctx: &TcContext, tkey: &bpf_tunnel_key) -> Option<i32> {
    // Same peer-node attestation as `try_geneve_decap_forward` above -- this
    // branch used to take `tkey` unused, relying entirely on the FLOW_TABLE
    // reverse-key match with no outer-source check of its own.
    let is_known_peer =
        unsafe { NODE_ALLOW.get(ipv4_mapped_v6(tkey.__bindgen_anon_1.remote_ipv4)) }.is_some();
    if let PeerNodeAdmission::Drop = peer_node_admission(is_known_peer) {
        return Some(TC_ACT_SHOT);
    }

    // The Geneve VIP-echo option is family-agnostic (module doc's option-
    // widening), same as forward-decap's pod-id option -- read it once here
    // before the inner packet's own family is known.
    let mut opt = [0u8; 24];
    if unsafe { bpf_skb_get_tunnel_opt(ctx.skb.skb, opt.as_mut_ptr().cast(), opt.len() as u32) } < 0
    {
        return Some(TC_ACT_SHOT);
    }
    if opt[0..2] != GENEVE_OPT_CLASS.to_ne_bytes() || opt[2] != GENEVE_OPT_TYPE_VIP_ECHO {
        return Some(TC_ACT_SHOT);
    }
    let vip_ip_v6: [u8; 16] = opt[4..20].try_into().ok()?;
    let vip_port = u16::from_ne_bytes(opt[20..22].try_into().ok()?);

    match ctx.load::<u16>(12).ok()? {
        ETH_P_IPV4 => try_geneve_decap_return_v4(ctx, vip_ip_v6, vip_port),
        ETH_P_IPV6 => try_geneve_decap_return_v6(ctx, vip_ip_v6, vip_port),
        _ => Some(TC_ACT_OK),
    }
}

/// Shared tail of `try_geneve_decap_return_v4`/`_v6`'s final client-bound
/// redirect. The packet just arrived off `geneve0`'s L3-only tunnel decap,
/// which leaves an all-zero synthetic L2 header in place -- fine for
/// carrying straight back onto another L3-only uplink (a tunnel device has
/// no L2 to check), but a real Ethernet uplink's peer runs `eth_type_trans`
/// on receipt and classifies that all-zero destination MAC
/// `PACKET_OTHERHOST`, dropping it before IP delivery. `UPLINK_CONFIG`
/// already carries the signal needed to tell the two apart -- `l2_hlen`,
/// the same field `try_uplink_ingress`'s parsing branch above keys on --
/// so an Ethernet egress (`l2_hlen == ETH_HLEN`) resolves L2 via
/// `bpf_redirect_neigh` (FIB + neighbor lookup, done by the kernel) instead
/// of the plain `bpf_redirect` a tunnel egress still uses unchanged.
/// Chosen over a manual `bpf_fib_lookup` + `bpf_skb_store_bytes` header
/// write: it's a straight swap for the existing `bpf_redirect` call, with
/// no new map lookups or hand-built header bytes on this side.
#[inline(always)]
fn redirect_client_bound(ingress_ifindex: u32) -> Option<i32> {
    let l2_hlen = unsafe { UPLINK_CONFIG.get(ingress_ifindex) }?.l2_hlen as usize;
    let redirect = if l2_hlen == ETH_HLEN {
        unsafe { bpf_redirect_neigh(ingress_ifindex, core::ptr::null_mut(), 0, 0) }
    } else {
        unsafe { bpf_redirect(ingress_ifindex, 0) }
    };
    if redirect as i32 != TC_ACT_REDIRECT {
        return Some(TC_ACT_SHOT);
    }
    Some(TC_ACT_REDIRECT)
}

#[inline(always)]
fn try_geneve_decap_return_v4(ctx: &TcContext, vip_ip_v6: [u8; 16], vip_port: u16) -> Option<i32> {
    if ctx.load::<u8>(IP_VER_IHL).ok()? & 0x0f != 5 {
        return Some(TC_ACT_OK);
    }
    let proto: u8 = ctx.load(IP_PROTO).ok()?;
    if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
        return Some(TC_ACT_OK);
    }

    let pod_ip: u32 = ctx.load(IP_SRC).ok()?;
    let target_port: u16 = ctx.load(L4_SPORT).ok()?;
    let client_ip: u32 = ctx.load(IP_DST).ok()?;
    let client_port: u16 = ctx.load(L4_DPORT).ok()?;

    let client_ip_v6 = ipv4_mapped_v6(client_ip);
    // Untagged: only FWD_PENDING (never merged into FLOW_TABLE, see its doc
    // comment) uses this shape.
    let key = encode_tcp_flow_key(client_ip_v6, client_port, vip_ip_v6, vip_port, proto);
    let fwd_key = encode_flow_key(
        client_ip_v6,
        client_port,
        vip_ip_v6,
        vip_port,
        proto,
        FlowDirection::Forward,
    );
    // Admission control: a FLOW_TABLE forward-tagged hit is already
    // established and authorized -- skip the PENDING lookup entirely (the
    // doc's stated steady-state cost is one lookup, matching the pre-split
    // FWD_FLOW.get). A PENDING hit is this flow's FIRST observed return leg
    // -- proof of bidirectionality an off-path spoofer cannot produce -- so
    // promote it into FLOW_TABLE and drop the PENDING copy. A miss in both
    // is stale or spoofed, same drop the pre-split FWD_FLOW.get()? performed.
    //
    // `forward_value` is also this multi-uplink redirect's only source of
    // truth for which physical uplink to send the reply back out: unlike
    // the old single-uplink `CONFIG.get(0).uplink_ifindex`, there is no
    // longer one uplink to fall back on, so the ifindex the flow was
    // admitted on (stamped by `try_uplink_ingress_headers` at mint time)
    // MUST already be sitting in this same lookup
    // (`docs/decisions/servicelb-multi-symmetric-uplink.md`).
    let existing_forward = flow_table_get_forward(fwd_key);
    let forward_value = if let Some(value) = existing_forward {
        Some(value)
    } else {
        let pending_value = unsafe { FWD_PENDING.get(key) }.copied();
        match return_authorization(false, pending_value.is_some()) {
            ReturnAuthorization::Promote => {
                let value = pending_value?;
                FLOW_TABLE
                    .insert(fwd_key, FlowValue { forward: value }, 0)
                    .ok()?;
                let _ = FWD_PENDING.remove(key);
                Some(value)
            }
            ReturnAuthorization::Drop => return None,
            // Unreachable in practice: `return_authorization`'s first
            // argument is hardcoded `false` above, and it only ever answers
            // `Established` when its `in_main` argument is `true`. Falling
            // through to the `?` below (drop) rather than panicking keeps
            // this fail-closed if that invariant ever changes.
            ReturnAuthorization::Established => None,
        }
    };
    let ingress_ifindex = forward_value?.ingress_ifindex;

    // `?`: this front is v4 (dispatched here on ETH_P_IPV4), so the echoed
    // vip_ip must unmap to a v4 wire token -- see
    // `try_geneve_decap_forward_v4`'s matching comment.
    rewrite_ip_port(
        ctx,
        IP_SRC,
        pod_ip,
        unmap_ipv4(&vip_ip_v6)?,
        L4_SPORT,
        target_port,
        vip_port,
        proto,
    )?;

    // Unlike the forward decap, this can't hand off with TC_ACT_OK: `src` is
    // now the VIP -- an address THIS node genuinely owns -- and the kernel's
    // normal receive-side routing decision (`ip_rcv_finish_core`) unconditionally
    // martian-drops any packet whose source is one of the node's own local
    // addresses arriving for forwarding rather than local origination
    // (confirmed on a live kernel via the `kfree_skb` tracepoint:
    // `reason: IP_LOCAL_SOURCE`, independent of rp_filter, which does NOT
    // gate this check). `bpf_redirect` straight to the uplink transmits the
    // skb directly, bypassing that receive-side routing decision entirely --
    // the same "receive on one device, redirect for transmit on another"
    // pattern `uplink_ingress` already uses for the forward leg's geneve0
    // redirect, just in the opposite direction.
    //
    // That same redirect re-enters the uplink's OWN egress pipeline, so
    // `try_uplink_egress_return` (hook 3) sees this already-un-DNAT'd,
    // client-bound packet a second time with src == vip_ip. Stamp it before
    // redirecting so hook 3 can recognize and skip its own redirected-back
    // packet: without this, vip_ip == pod_ip -- a hostNetwork Service
    // fronted by a same-node backend's own address -- fools hook 3's
    // POD_TARGETS admission into misreading this packet as the pod's raw
    // reply and dropping it.
    ctx.set_mark(REDIRECTED_RETURN_MARK);
    // `ingress_ifindex` here is the FLOW_TABLE-stored value resolved above,
    // NOT `ctx.skb.skb->ingress_ifindex` read fresh at this call site: this
    // hook runs on `geneve0`'s ingress (the packet just arrived there via
    // its own tunnel decap), so a fresh read would resolve to `geneve0`
    // itself, not the client's uplink. See `redirect_client_bound`'s doc
    // comment for why this isn't a plain `bpf_redirect` call.
    redirect_client_bound(ingress_ifindex)
}

/// IPv6 sibling of `try_geneve_decap_return_v4`.
#[inline(always)]
fn try_geneve_decap_return_v6(ctx: &TcContext, vip_ip_v6: [u8; 16], vip_port: u16) -> Option<i32> {
    let proto: u8 = ctx.load(IP6_NEXT_HDR).ok()?;
    if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
        return Some(TC_ACT_OK);
    }

    let pod_ip_v6: [u8; 16] = ctx.load(IP6_SRC).ok()?;
    let target_port: u16 = ctx.load(L4_SPORT_V6).ok()?;
    let client_ip_v6: [u8; 16] = ctx.load(IP6_DST).ok()?;
    let client_port: u16 = ctx.load(L4_DPORT_V6).ok()?;

    let key = encode_tcp_flow_key(client_ip_v6, client_port, vip_ip_v6, vip_port, proto);
    let fwd_key = encode_flow_key(
        client_ip_v6,
        client_port,
        vip_ip_v6,
        vip_port,
        proto,
        FlowDirection::Forward,
    );
    let existing_forward = flow_table_get_forward(fwd_key);
    let forward_value = if let Some(value) = existing_forward {
        Some(value)
    } else {
        let pending_value = unsafe { FWD_PENDING.get(key) }.copied();
        match return_authorization(false, pending_value.is_some()) {
            ReturnAuthorization::Promote => {
                let value = pending_value?;
                FLOW_TABLE
                    .insert(fwd_key, FlowValue { forward: value }, 0)
                    .ok()?;
                let _ = FWD_PENDING.remove(key);
                Some(value)
            }
            ReturnAuthorization::Drop => return None,
            ReturnAuthorization::Established => None,
        }
    };
    let ingress_ifindex = forward_value?.ingress_ifindex;

    rewrite_ipv6_port(
        ctx,
        IP6_SRC,
        pod_ip_v6,
        vip_ip_v6,
        L4_SPORT_V6,
        target_port,
        vip_port,
        proto,
        if proto == IPPROTO_TCP {
            TCP_CSUM_V6
        } else {
            UDP_CSUM_V6
        },
        UDP_CSUM_V6,
    )?;

    // See try_geneve_decap_return_v4's matching comment.
    ctx.set_mark(REDIRECTED_RETURN_MARK);
    redirect_client_bound(ingress_ifindex)
}

/// Hook 3: egress classifier on the physical uplink, backend node (return
/// leg). Every non-matching packet -- i.e. everything that isn't a
/// beep backend Pod's reply -- passes through untouched; this hook
/// sees all uplink egress traffic, not just beep's.
#[classifier]
pub fn uplink_egress_return(ctx: TcContext) -> i32 {
    try_uplink_egress_return(&ctx).unwrap_or(TC_ACT_OK)
}

fn try_uplink_egress_return(ctx: &TcContext) -> Option<i32> {
    // `try_geneve_decap_return`'s final redirect re-enters this same uplink's
    // egress pipeline, so this hook sees that already-processed,
    // already-un-DNAT'd client-bound packet a SECOND time before the
    // POD_TARGETS admission below ever runs. When vip_ip == pod_ip -- a
    // hostNetwork Service fronted by a same-node backend's own address --
    // that second pass spuriously matches POD_TARGETS and gets misread as
    // the pod's raw reply, then dropped. Recognize and pass it through
    // untouched instead. Cleared rather than left stamped: nothing else in
    // this datapath reads skb->mark today, but leaving a stale internal
    // marker on a packet leaving the node is a needless landmine for any
    // future mark-based tc/iptables rule on this uplink.
    if is_redirected_return_mark(unsafe { (*ctx.skb.skb).mark }) {
        ctx.set_mark(0);
        return Some(TC_ACT_OK);
    }
    // This classifier is attached to EVERY configured uplink's egress, same
    // as `uplink_ingress` is to their ingress -- but at egress, a locally
    // routed packet's OWN `ingress_ifindex` is unset (it was never received
    // on any device), so unlike `try_uplink_ingress`, the per-uplink lookup
    // here keys on `ifindex`: at a TC egress attachment this is already the
    // device this classifier instance is transmitting on, i.e. exactly
    // which configured uplink this invocation is running for. See
    // `try_uplink_ingress`'s matching comment for why the L2 header length
    // is resolved once by the loader, not assumed to be Ethernet's 14 bytes.
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    let l2_hlen = unsafe { UPLINK_CONFIG.get(ifindex) }?.l2_hlen as usize;
    // See `try_uplink_ingress`'s matching comment: dispatches on a const
    // generic so every `load_direct` offset below is a compile-time literal.
    match l2_hlen {
        0 => try_uplink_egress_return_headers::<0>(ctx),
        ETH_HLEN => try_uplink_egress_return_headers::<ETH_HLEN>(ctx),
        _ => Some(TC_ACT_OK),
    }
}

/// Dispatches on the inner packet's own address family -- see
/// `try_uplink_ingress_headers`'s matching comment (same reasoning, same
/// two-siblings-not-one-runtime-branch structure).
#[inline(always)]
fn try_uplink_egress_return_headers<const L2_HLEN: usize>(ctx: &TcContext) -> Option<i32> {
    if L2_HLEN == ETH_HLEN {
        match load_direct::<u16>(ctx, 12)? {
            ETH_P_IPV4 => try_uplink_egress_return_headers_v4::<L2_HLEN>(ctx),
            ETH_P_IPV6 => try_uplink_egress_return_headers_v6::<L2_HLEN>(ctx),
            _ => Some(TC_ACT_OK),
        }
    } else {
        let ver: u8 = ctx.load(0).ok()?;
        match ver >> 4 {
            4 => try_uplink_egress_return_headers_v4::<L2_HLEN>(ctx),
            6 => try_uplink_egress_return_headers_v6::<L2_HLEN>(ctx),
            _ => Some(TC_ACT_OK),
        }
    }
}

#[inline(always)]
fn try_uplink_egress_return_headers_v4<const L2_HLEN: usize>(ctx: &TcContext) -> Option<i32> {
    // See `try_uplink_ingress_headers_v4`'s matching comment: offset 0 can't
    // go through `load_direct`.
    let ver_ihl: u8 = if L2_HLEN == 0 {
        ctx.load(0).ok()?
    } else {
        load_direct(ctx, L2_HLEN)?
    };
    if ver_ihl >> 4 != 4 || ver_ihl & 0x0f != 5 {
        return Some(TC_ACT_OK);
    }
    let ip_proto = L2_HLEN + 9;
    let ip_src = L2_HLEN + 12;
    let ip_dst = L2_HLEN + 16;
    let l4_off = L2_HLEN + IP_HLEN;
    let l4_sport = l4_off;
    let l4_dport = l4_off + 2;

    let proto: u8 = load_direct(ctx, ip_proto)?;
    if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
        return Some(TC_ACT_OK);
    }

    // This is the Pod's own raw reply: src=PodIP:TargetPort, dst=CLIENT_IP:SRC_PORT
    // (or Decision 3's remapped synthetic port -- see RevFlowValue's doc comment).
    let pod_ip: u32 = load_direct(ctx, ip_src)?;

    // Reject before the remaining fields are even loaded, let alone the
    // ~38-byte FLOW_TABLE key built: POD_TARGETS is a cheap membership
    // table, far cheaper to probe than this hook's own conntrack table, and
    // most packets crossing this hook (ALL uplink egress, not just
    // beep's) take this branch.
    let is_backend_pod = unsafe { POD_TARGETS.get(ipv4_mapped_v6(pod_ip)) }.is_some();
    if let EgressReturnAdmission::NotBackendTraffic = egress_return_admission(is_backend_pod) {
        return Some(TC_ACT_OK);
    }

    let target_port: u16 = load_direct(ctx, l4_sport)?;
    let client_ip: u32 = load_direct(ctx, ip_dst)?;
    let backend_dst_port: u16 = load_direct(ctx, l4_dport)?;

    let key = encode_flow_key(
        ipv4_mapped_v6(client_ip),
        backend_dst_port,
        ipv4_mapped_v6(pod_ip),
        target_port,
        proto,
        FlowDirection::Reverse,
    );
    let rev_lookup = flow_table_get_reverse(key);
    if let EgressReturnOutcome::Drop = egress_return_outcome(rev_lookup.is_some()) {
        // Positively identified backend Pod traffic with no live
        // FLOW_TABLE reverse-tagged entry (an LRU eviction, almost always)
        // -- letting it through unencapsulated leaks a pod-CIDR source
        // address onto the underlay while still stalling the connection, so
        // drop instead. Consistent with the forward decap path's equivalent
        // miss (`geneve_ingress`'s `unwrap_or(TC_ACT_SHOT)`).
        if let Some(count) = EGRESS_DROPS.get_ptr_mut(0) {
            unsafe { *count += 1 };
        }
        return Some(TC_ACT_SHOT);
    }
    let rev = rev_lookup?;

    // Un-remap: restore the client's real port before this packet re-enters
    // the Geneve tunnel -- the ingress node's return-decap step rebuilds its
    // own lookup key from this inner dst and has no knowledge of any
    // backend-local remap. A no-op when this flow was never remapped.
    rewrite_l4_port(
        ctx,
        l4_off,
        l4_dport,
        backend_dst_port,
        rev.original_client_port,
        proto,
    )?;

    let geneve_ifindex = CONFIG.get(0)?.geneve_ifindex;

    let mut tkey: bpf_tunnel_key = unsafe { core::mem::zeroed() };
    let tkey_flags = set_tunnel_remote(&mut tkey, &rev.ingress_node_ip);
    tkey.tunnel_id = VNI_RET;
    tkey.tunnel_ttl = 64;
    if unsafe {
        bpf_skb_set_tunnel_key(
            ctx.skb.skb,
            &mut tkey,
            core::mem::size_of::<bpf_tunnel_key>() as u32,
            tkey_flags,
        )
    } != 0
    {
        return Some(TC_ACT_SHOT);
    }

    let mut opt = [0u8; 24];
    opt[0..2].copy_from_slice(&GENEVE_OPT_CLASS.to_ne_bytes());
    opt[2] = GENEVE_OPT_TYPE_VIP_ECHO;
    opt[3] = 5; // opt_data length in 4-byte words (16 + 2 + 2 padding bytes).
    opt[4..20].copy_from_slice(&rev.vip_ip);
    opt[20..22].copy_from_slice(&rev.vip_port.to_ne_bytes());
    if unsafe { bpf_skb_set_tunnel_opt(ctx.skb.skb, opt.as_mut_ptr().cast(), opt.len() as u32) }
        != 0
    {
        return Some(TC_ACT_SHOT);
    }

    // See try_uplink_ingress's matching comment: this node's uplink can be
    // the same L3-only WireGuard device, so its geneve0 redirect needs the
    // same synthesized MAC header (including the EtherType stamp decap
    // relies on).
    if L2_HLEN == 0 {
        if unsafe { bpf_skb_change_head(ctx.skb.skb, ETH_HLEN as u32, 0) } != 0 {
            return Some(TC_ACT_SHOT);
        }
        // See try_uplink_ingress's matching comment on why this is a local,
        // not `&ETH_P_IPV4` directly.
        let ethertype = ETH_P_IPV4;
        if ctx.store(12, &ethertype, 0).is_err() {
            return Some(TC_ACT_SHOT);
        }
    }

    if unsafe { bpf_redirect(geneve_ifindex, 0) } as i32 != TC_ACT_REDIRECT {
        return Some(TC_ACT_SHOT);
    }
    Some(TC_ACT_REDIRECT)
}

/// IPv6 sibling of `try_uplink_egress_return_headers_v4`.
#[inline(always)]
fn try_uplink_egress_return_headers_v6<const L2_HLEN: usize>(ctx: &TcContext) -> Option<i32> {
    let ver: u8 = if L2_HLEN == 0 {
        ctx.load(0).ok()?
    } else {
        load_direct(ctx, L2_HLEN)?
    };
    if ver >> 4 != 6 {
        return Some(TC_ACT_OK);
    }
    let ip6_next_hdr = L2_HLEN + 6;
    let ip6_src = L2_HLEN + 8;
    let ip6_dst = L2_HLEN + 24;
    let l4_off = L2_HLEN + IP6_HLEN;
    let l4_sport = l4_off;
    let l4_dport = l4_off + 2;

    let proto: u8 = load_direct(ctx, ip6_next_hdr)?;
    if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
        return Some(TC_ACT_OK);
    }

    let pod_ip_v6: [u8; 16] = load_direct(ctx, ip6_src)?;

    let is_backend_pod = unsafe { POD_TARGETS.get(pod_ip_v6) }.is_some();
    if let EgressReturnAdmission::NotBackendTraffic = egress_return_admission(is_backend_pod) {
        return Some(TC_ACT_OK);
    }

    let target_port: u16 = load_direct(ctx, l4_sport)?;
    let client_ip_v6: [u8; 16] = load_direct(ctx, ip6_dst)?;
    let backend_dst_port: u16 = load_direct(ctx, l4_dport)?;

    let key = encode_flow_key(
        client_ip_v6,
        backend_dst_port,
        pod_ip_v6,
        target_port,
        proto,
        FlowDirection::Reverse,
    );
    let rev_lookup = flow_table_get_reverse(key);
    if let EgressReturnOutcome::Drop = egress_return_outcome(rev_lookup.is_some()) {
        if let Some(count) = EGRESS_DROPS.get_ptr_mut(0) {
            unsafe { *count += 1 };
        }
        return Some(TC_ACT_SHOT);
    }
    let rev = rev_lookup?;

    rewrite_l4_port(
        ctx,
        l4_off,
        l4_dport,
        backend_dst_port,
        rev.original_client_port,
        proto,
    )?;

    let geneve_ifindex = CONFIG.get(0)?.geneve_ifindex;

    let mut tkey: bpf_tunnel_key = unsafe { core::mem::zeroed() };
    let tkey_flags = set_tunnel_remote(&mut tkey, &rev.ingress_node_ip);
    tkey.tunnel_id = VNI_RET;
    tkey.tunnel_ttl = 64;
    if unsafe {
        bpf_skb_set_tunnel_key(
            ctx.skb.skb,
            &mut tkey,
            core::mem::size_of::<bpf_tunnel_key>() as u32,
            tkey_flags,
        )
    } != 0
    {
        return Some(TC_ACT_SHOT);
    }

    let mut opt = [0u8; 24];
    opt[0..2].copy_from_slice(&GENEVE_OPT_CLASS.to_ne_bytes());
    opt[2] = GENEVE_OPT_TYPE_VIP_ECHO;
    opt[3] = 5; // opt_data length in 4-byte words (16 + 2 + 2 padding bytes).
    opt[4..20].copy_from_slice(&rev.vip_ip);
    opt[20..22].copy_from_slice(&rev.vip_port.to_ne_bytes());
    if unsafe { bpf_skb_set_tunnel_opt(ctx.skb.skb, opt.as_mut_ptr().cast(), opt.len() as u32) }
        != 0
    {
        return Some(TC_ACT_SHOT);
    }

    // See try_uplink_ingress_headers_v6's matching comment.
    if L2_HLEN == 0 {
        if unsafe { bpf_skb_change_head(ctx.skb.skb, ETH_HLEN as u32, 0) } != 0 {
            return Some(TC_ACT_SHOT);
        }
        let ethertype = ETH_P_IPV6;
        if ctx.store(12, &ethertype, 0).is_err() {
            return Some(TC_ACT_SHOT);
        }
    }

    if unsafe { bpf_redirect(geneve_ifindex, 0) } as i32 != TC_ACT_REDIRECT {
        return Some(TC_ACT_SHOT);
    }
    Some(TC_ACT_REDIRECT)
}

/// Rewrites one address:port pair in place (dst for forward DNAT, src for
/// return un-DNAT) and incrementally fixes up the IP and L4 checksums to
/// match, all in the raw-wire-token representation the checksum helpers
/// require (module doc). UDP's checksum is optional in IPv4 (0 means
/// disabled) -- a 0 is left alone rather than "fixed up" into a real one.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn rewrite_ip_port(
    ctx: &TcContext,
    ip_off: usize,
    old_ip: u32,
    new_ip: u32,
    port_off: usize,
    old_port: u16,
    new_port: u16,
    proto: u8,
) -> Option<()> {
    let l4_csum_off = if proto == IPPROTO_TCP {
        TCP_CSUM
    } else {
        UDP_CSUM
    };
    let is_udp = proto == IPPROTO_UDP;
    let udp_csum_disabled = is_udp && ctx.load::<u16>(UDP_CSUM).ok()? == 0;

    // This function only ever rewrites a v4 header (`rewrite_ipv6_port` is
    // v6's own sibling), so this always resolves to `Ipv4HeaderAndL4Pseudo`
    // -- consulting the shared decision (rather than calling
    // `l3_csum_replace` unconditionally) keeps this arm and `rewrite_ipv6_port`'s
    // in lockstep with the one tested source of truth for which fixup a
    // given family needs.
    if let AddressRewriteChecksums::Ipv4HeaderAndL4Pseudo = address_rewrite_checksums(false) {
        ctx.l3_csum_replace(IP_CSUM, old_ip as u64, new_ip as u64, 4)
            .ok()?;
    }
    if !udp_csum_disabled {
        ctx.l4_csum_replace(
            l4_csum_off,
            old_ip as u64,
            new_ip as u64,
            (BPF_F_PSEUDO_HDR | 4) as u64,
        )
        .ok()?;
        ctx.l4_csum_replace(l4_csum_off, old_port as u64, new_port as u64, 2)
            .ok()?;
    }

    ctx.store(ip_off, &new_ip, 0).ok()?;
    ctx.store(port_off, &new_port, 0).ok()?;
    Some(())
}

/// IPv6 sibling of `rewrite_ip_port`: no IP-header checksum field exists on
/// a v6 header at all (`address_rewrite_checksums(true)` resolves to
/// `L4PseudoOnly` -- the missing `l3_csum_replace` call below, compared to
/// `rewrite_ip_port`'s, IS that arm), so only the L4 pseudo-header fixup
/// runs, one 32-bit word at a time: `bpf_l4_csum_replace`'s `flags` low
/// bits select a `from`/`to` width of 0, 2, or 4 bytes -- never 8
/// (`net/core/filter.c`'s `bpf_l4_csum_replace` has no larger case) -- so a
/// 16-byte v6 address needs 4 calls where v4's 4-byte address needed 1.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn rewrite_ipv6_port(
    ctx: &TcContext,
    ip_off: usize,
    old_ip: [u8; 16],
    new_ip: [u8; 16],
    port_off: usize,
    old_port: u16,
    new_port: u16,
    proto: u8,
    l4_csum_off: usize,
    udp_csum_off: usize,
) -> Option<()> {
    let is_udp = proto == IPPROTO_UDP;
    let udp_csum_disabled = is_udp && ctx.load::<u16>(udp_csum_off).ok()? == 0;

    if !udp_csum_disabled {
        let mut i = 0;
        while i < 4 {
            let old_word = u32::from_ne_bytes(old_ip[i * 4..i * 4 + 4].try_into().unwrap());
            let new_word = u32::from_ne_bytes(new_ip[i * 4..i * 4 + 4].try_into().unwrap());
            ctx.l4_csum_replace(
                l4_csum_off,
                old_word as u64,
                new_word as u64,
                (BPF_F_PSEUDO_HDR | 4) as u64,
            )
            .ok()?;
            i += 1;
        }
        ctx.l4_csum_replace(l4_csum_off, old_port as u64, new_port as u64, 2)
            .ok()?;
    }

    ctx.store(ip_off, &new_ip, 0).ok()?;
    ctx.store(port_off, &new_port, 0).ok()?;
    Some(())
}

/// Rewrites a TCP/UDP port in place with no IP change -- no L3 checksum
/// involved, only the L4 one. Backs Decision 3's backend source-port remap
/// (forward leg) and its un-remap (return leg); a no-op when
/// `old_port == new_port`, so callers can invoke it unconditionally.
///
/// `l4_off` is the caller's own L4-header base offset, not the module's
/// `L4_OFF` const: `try_uplink_egress_return`'s call site resolves it at
/// runtime from `UplinkConfig::l2_hlen` (an L3-only WireGuard uplink has no
/// 14-byte Ethernet header to add), while `try_geneve_decap_forward`'s
/// (always on `geneve0`, always Ethernet-framed) passes the compile-time
/// `L4_OFF`.
#[inline(always)]
fn rewrite_l4_port(
    ctx: &TcContext,
    l4_off: usize,
    port_off: usize,
    old_port: u16,
    new_port: u16,
    proto: u8,
) -> Option<()> {
    if old_port == new_port {
        return Some(());
    }
    let udp_csum_off = l4_off + 6;
    let l4_csum_off = if proto == IPPROTO_TCP {
        l4_off + 16
    } else {
        udp_csum_off
    };
    if proto == IPPROTO_UDP && ctx.load::<u16>(udp_csum_off).ok()? == 0 {
        ctx.store(port_off, &new_port, 0).ok()?;
        return Some(());
    }
    ctx.l4_csum_replace(l4_csum_off, old_port as u64, new_port as u64, 2)
        .ok()?;
    ctx.store(port_off, &new_port, 0).ok()?;
    Some(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// The kernel verifier gates several helpers (e.g. bpf_skb_set_tunnel_key,
// needed from Phase 2 onward) on a GPL-compatible LICENSE section. This is a
// property of the compiled eBPF object the kernel loads, independent of this
// crate's own Apache-2.0 Cargo.toml license.
#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
