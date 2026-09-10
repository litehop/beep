#![no_std]
#![no_main]

//! Phase 2 (Geneve encap/decap on the symmetric-return path) plus Phase 3
//! (conntrack full-tuple keying + backend source-port remap on conflict) of
//! the beep eBPF dataplane
//! (`docs/design/ebpf-lb-dataplane.md`'s "Packet flow" and
//! "Conntrack & affinity" sections, `docs/decisions/servicelb-symmetric-geneve-return.md`).
//! IPv4 only, one static VIP:PORT -> backend-node/PodIP:TargetPort mapping
//! populated by the userspace loader at startup -- real Service/EndpointSlice
//! watching is Phase 5. Flow-affinity keys are IPv6-primary (`beep_common`)
//! so the same map shape covers real IPv6 flows once packet parsing grows
//! that far; today's IPv4-only parsing embeds each address as IPv4-mapped
//! IPv6 before keying.
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
    bindings::{bpf_tunnel_key, BPF_F_PSEUDO_HDR, TC_ACT_OK, TC_ACT_REDIRECT, TC_ACT_SHOT},
    helpers::{
        bpf_redirect, bpf_skb_change_head, bpf_skb_change_type, bpf_skb_get_tunnel_key,
        bpf_skb_get_tunnel_opt, bpf_skb_set_tunnel_key, bpf_skb_set_tunnel_opt,
    },
    macros::{classifier, map},
    maps::{Array, HashMap, LruHashMap, PerCpuArray},
    programs::TcContext,
};
use beep_common::{
    backend_port_resolution, decap_forward_pod_admission, egress_return_admission,
    egress_return_outcome, encode_flow_key, encode_tcp_flow_key, forward_admission, ipv4_mapped_v6,
    is_redirected_return_mark, occupant_conflicts, resolve_backend_src_port, return_authorization,
    BackendPortDecision, BackendPortResolution, Config, DecapForwardPodAdmission,
    EgressReturnAdmission, EgressReturnOutcome, FlowDirection, FlowKey, ForwardAdmission,
    ReturnAuthorization, TcpFlowKey, VipBackend, VipKey, REDIRECTED_RETURN_MARK,
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
/// Forward-leg option: raw pod IP (4 bytes), the pod-identifier the backend
/// needs to pick a target port (`docs/decisions/servicelb-ebpf-geneve-dataplane.md`
/// wire-format settlement: "raw pod IP for the pod identifier").
const GENEVE_OPT_TYPE_POD_ID: u8 = 0x01;
/// Return-leg option: raw `VIP_IP:VIP_PORT` echo (6 bytes + 2 padding),
/// captured by the backend before it DNATs and echoed back so the ingress
/// can un-DNAT without its own state lookup racing the encap.
const GENEVE_OPT_TYPE_VIP_ECHO: u8 = 0x02;

const ETH_HLEN: usize = 14;
const ETH_P_IPV4: u16 = 0x0800u16.to_be();
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

/// One static VIP:PORT -> backend mapping (fixture, populated once by the
/// userspace loader). Same `VipKey` (`beep_common`) shape as `TARGET_PORTS`
/// below, but a separate map -- the two never interact, just key on the same
/// front tuple for the two different roles that need it (ingress backend
/// selection here, backend target-port selection there).
#[map]
static VIP_MAP: HashMap<VipKey, VipBackend> = HashMap::with_max_entries(16, 0);

/// Backend-local: which target port a decap'd, DNAT'd packet should land on
/// for a given front (VIP:PORT:proto) -- keyed the same way as `VIP_MAP`
/// above, deliberately NOT on pod IP alone. A pod IP alone cannot
/// disambiguate a multi-port Service, a pod backing two Services, or TCP/UDP
/// on different ports; the forward Geneve option only ever carries the raw
/// pod IP (`ebpf-lb-dataplane.md`'s settled wire-format decision), so the
/// front tuple this map keys on -- still present on the packet's own
/// untouched inner dst at decap time -- is what disambiguates instead.
/// <20 entries per `ebpf-lb-dataplane.md`'s sizing table.
#[map]
static TARGET_PORTS: HashMap<VipKey, u16> = HashMap::with_max_entries(32, 0);

/// Backend-local: which pod IPs are this node's own beep backend Pods,
/// keyed on pod IP alone -- deliberately NOT on target port, unlike
/// `TARGET_PORTS` above. `try_uplink_egress_return` (hook 3) sees ALL
/// uplink egress traffic, not just beep's, so it probes this cheap
/// 4-byte-keyed membership table BEFORE building the ~38-byte FLOW_TABLE
/// key, to reject unrelated traffic without ever touching the conntrack
/// table. Membership-only is what makes this safe across a rolling update or
/// a targetPort edit: a flow's FLOW_TABLE reverse-tagged entry was written
/// because the forward path found its pod here, so anything still live is
/// admitted regardless of what its target port used to be
/// (`beep_common::egress_return_admission`'s doc comment). Value is a bare
/// existence marker, never read.
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
static POD_TARGETS: HashMap<u32, u8> = HashMap::with_max_entries(32, 0);

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
/// Value type is `VipBackend`, the full backend identity
/// (`backend_node_ip` + `pod_ip`), not just the node IP: aie31.21 pins this
/// as the per-flow affinity target, so this bead's admission logic already
/// carries the shape aie31.21 needs -- no map-shape change once
/// affinity-follow lands. This bead only existence-checks it.
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
static FWD_PENDING: LruHashMap<TcpFlowKey, VipBackend> = LruHashMap::with_max_entries(2048, 0);

/// Union of the three roles `FLOW_TABLE` stores, discriminated by the
/// `FlowDirection` tag in its key. `forward` is the promoted,
/// established-affinity value `FWD_MAIN` used to store; `reverse` is the
/// backend-side un-DNAT conntrack value `REV_FLOW` used to store;
/// `port_memo` persists a backend-src-port remap decision so it survives
/// unrelated LRU churn instead of being re-derived per packet.
/// Callers must only ever read the field matching the key's own tag -- the
/// other field's bytes are whatever the last write to that slot happened to
/// leave there, exactly like reading the wrong arm of any tagged union.
#[repr(C)]
#[derive(Clone, Copy)]
pub union FlowValue {
    pub forward: VipBackend,
    pub reverse: RevFlowValue,
    pub port_memo: PortMemoValue,
}

/// Backend-side reverse-flow: captured at decap+DNAT time (step 4, BEFORE
/// the dst rewrite) so the egress classifier (step 6) can recover the
/// ingress node and the original VIP to echo, since by the time it runs the
/// packet's own header no longer carries the VIP -- DNAT already overwrote
/// it (`ebpf-lb-dataplane.md`, Conntrack & affinity).
///
/// `original_client_port` backs Decision 3's un-remap: when the forward
/// decap below remapped the backend-facing source port to keep this key
/// unique (two Services sharing a backend Pod:targetPort, client reusing
/// one source port across both), the egress classifier restores the
/// client's real port here before the packet leaves this node -- the
/// ingress node's own return-decap step has no knowledge of any backend-
/// local remap and must see the true client port in the inner dst.
#[repr(C)]
#[derive(Clone, Copy, PartialEq)]
pub struct RevFlowValue {
    pub ingress_node_ip: u32,
    pub vip_ip: u32,
    pub vip_port: u16,
    pub original_client_port: u16,
}

/// Backend-side persisted port-remap decision, keyed under
/// `FlowDirection::PortMemo` on the flow's natural (client, real client
/// port, pod, target port) tuple. `resolve_backend_src_port`'s occupancy
/// probe only guarantees a STABLE answer while every occupant in its probe
/// window stays alive; without this memo, an LRU eviction of some unrelated
/// occupant at an earlier probe index between two packets of the same flow
/// makes a fresh probe land on a DIFFERENT port than the one already in use
/// -- breaking the reverse path mid-connection. See
/// `beep_common::backend_port_resolution`'s doc comment.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PortMemoValue {
    pub backend_src_port: u16,
}

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
#[map]
static FLOW_TABLE: LruHashMap<FlowKey, FlowValue> = LruHashMap::with_max_entries(16384, 0);

/// `FLOW_TABLE.get` plus the union-field read for the caller's own role,
/// each wrapped so every call site names which role it expects instead of
/// repeating the `unsafe` union read inline. `#[inline(always)]` for the
/// same reason `try_geneve_decap_forward`/`_return` are (module doc):
/// several call sites, no downside to forcing inlining, and it sidesteps
/// this toolchain's non-inlined-BPF-to-BPF-call miscompile risk outright.
#[inline(always)]
fn flow_table_get_forward(key: FlowKey) -> Option<VipBackend> {
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

/// Hook 1: ingress classifier on the physical uplink, every node (forward
/// leg). Classifies VIP:PORT traffic, stamps Geneve metadata, redirects to
/// `geneve0`. Everything else passes through untouched -- this hook sees
/// all uplink traffic, not just beep's.
#[classifier]
pub fn uplink_ingress(ctx: TcContext) -> i32 {
    try_uplink_ingress(&ctx).unwrap_or(TC_ACT_OK)
}

fn try_uplink_ingress(ctx: &TcContext) -> Option<i32> {
    // Runtime, not the compile-time `ETH_HLEN`-based consts below `geneve_ingress`
    // uses: the uplink can be a real NIC/veth (14-byte Ethernet header) or an
    // L3-only overlay like WireGuard (no L2 header at all), decided once by
    // the loader (`Config` doc comment) since this no_std program has no
    // syscall of its own to tell the two apart.
    let l2_hlen = CONFIG.get(0)?.uplink_l2_hlen as usize;
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
        0 => try_uplink_ingress_headers::<0>(ctx),
        ETH_HLEN => try_uplink_ingress_headers::<ETH_HLEN>(ctx),
        _ => Some(TC_ACT_OK),
    }
}

fn try_uplink_ingress_headers<const L2_HLEN: usize>(ctx: &TcContext) -> Option<i32> {
    // No Ethernet header at all on an L3-only uplink -- there's no EtherType
    // field to check; the IP-version nibble below is this path's only gate.
    if L2_HLEN == ETH_HLEN && load_direct::<u16>(ctx, 12)? != ETH_P_IPV4 {
        return Some(TC_ACT_OK);
    }
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
    let key = VipKey {
        vip_ip: dst_ip,
        vip_port: dst_port,
        proto,
        _pad: 0,
    };
    let backend = *unsafe { VIP_MAP.get(key) }?;

    let src_ip: u32 = load_direct(ctx, ip_src)?;
    let src_port: u16 = load_direct(ctx, l4_sport)?;
    let client_ip_v6 = ipv4_mapped_v6(src_ip);
    let vip_ip_v6 = ipv4_mapped_v6(dst_ip);
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
        // run the LRU shrink path, unlike a read. Existence alone is enough
        // to skip it: the backend picked on this flow's first packet is the
        // one affinity should keep, not whatever VIP_MAP would pick if
        // re-run on a later pre-promotion packet.
        if unsafe { FWD_PENDING.get(flow_key) }.is_none() {
            FWD_PENDING.insert(flow_key, backend, 0).ok()?;
        }
    }

    let geneve_ifindex = CONFIG.get(0)?.geneve_ifindex;

    let mut tkey: bpf_tunnel_key = unsafe { core::mem::zeroed() };
    tkey.__bindgen_anon_1.remote_ipv4 = backend.backend_node_ip;
    tkey.tunnel_id = VNI_FWD;
    tkey.tunnel_ttl = 64;
    if unsafe {
        bpf_skb_set_tunnel_key(
            ctx.skb.skb,
            &mut tkey,
            core::mem::size_of::<bpf_tunnel_key>() as u32,
            0,
        )
    } != 0
    {
        return Some(TC_ACT_SHOT);
    }

    let mut opt = [0u8; 8];
    opt[0..2].copy_from_slice(&GENEVE_OPT_CLASS.to_ne_bytes());
    opt[2] = GENEVE_OPT_TYPE_POD_ID;
    opt[3] = 1; // opt_data length in 4-byte words.
    opt[4..8].copy_from_slice(&backend.pod_ip.to_ne_bytes());
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
    // explicitly -- decap's own ETH_P_IPV4 check (unconditional, since
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
/// its own -- read `VIP_IP:VIP_PORT` off the still-untouched inner dst
/// BEFORE rewriting anything, record the reverse-flow entry, DNAT dst to
/// `PodIP:TargetPort` (src untouched -- the Pod must see the real client IP
/// at L3), then hand the packet to the normal receive path: `TC_ACT_OK` on
/// an inbound decap leaves the now-foreign-dst'd packet to the kernel's own
/// routing, which is flannel's job from here, not ours.
#[inline(always)]
fn try_geneve_decap_forward(ctx: &TcContext, tkey: &bpf_tunnel_key) -> Option<i32> {
    if ctx.load::<u16>(12).ok()? != ETH_P_IPV4 {
        return Some(TC_ACT_OK);
    }
    if ctx.load::<u8>(IP_VER_IHL).ok()? & 0x0f != 5 {
        return Some(TC_ACT_OK);
    }
    let proto: u8 = ctx.load(IP_PROTO).ok()?;
    if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
        return Some(TC_ACT_OK);
    }

    let mut opt = [0u8; 8];
    if unsafe { bpf_skb_get_tunnel_opt(ctx.skb.skb, opt.as_mut_ptr().cast(), opt.len() as u32) } < 0
    {
        return Some(TC_ACT_SHOT);
    }
    if opt[0..2] != GENEVE_OPT_CLASS.to_ne_bytes() || opt[2] != GENEVE_OPT_TYPE_POD_ID {
        return Some(TC_ACT_SHOT);
    }
    let pod_ip = u32::from_ne_bytes(opt[4..8].try_into().ok()?);

    // Membership gate: TARGET_PORTS below only confirms this node hosts
    // SOME backend for the front, never that this specific pod_ip -- as
    // stamped by the ingress node, possibly stale under cross-node
    // convergence drift -- is still one of this node's own pods. Same
    // pod-IP-only POD_TARGETS membership `try_uplink_egress_return` gates
    // its own direction on (`egress_return_admission`'s doc comment),
    // checked here before the front-tuple TARGET_PORTS lookup so a
    // not-our-pod packet is rejected off the cheaper 4-byte key first.
    let is_local_pod = unsafe { POD_TARGETS.get(pod_ip) }.is_some();
    if let DecapForwardPodAdmission::Drop = decap_forward_pod_admission(is_local_pod) {
        return Some(TC_ACT_SHOT);
    }

    let client_ip: u32 = ctx.load(IP_SRC).ok()?;
    let client_port: u16 = ctx.load(L4_SPORT).ok()?;
    let vip_ip: u32 = ctx.load(IP_DST).ok()?; // captured before rewrite
    let vip_port: u16 = ctx.load(L4_DPORT).ok()?; // captured before rewrite

    // Re-keyed off the front the packet still carries at decap time, not the
    // Geneve option's pod IP: the pod IP alone can't tell 80->8080 apart from
    // 443->8443 on the same pod (`TARGET_PORTS`' doc comment).
    let target_port = *unsafe {
        TARGET_PORTS.get(VipKey {
            vip_ip,
            vip_port,
            proto,
            _pad: 0,
        })
    }?;

    let client_ip_v6 = ipv4_mapped_v6(client_ip);
    let pod_ip_v6 = ipv4_mapped_v6(pod_ip);
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
            let existing_occupant = flow_table_get_reverse(natural_rev_key)
                .map(|v| ((v.vip_ip, v.vip_port), v.original_client_port));
            // Raw scalars, not an `ipv4_mapped_v6`-widened pair: `RevFlowValue`'s
            // `vip_ip` and this packet's `vip_ip` are already bare `u32`s, and the
            // mapping is injective, so comparing the wire values directly is exactly
            // equivalent to comparing their v6-mapped forms and turns a 20-byte
            // compare into an 8-byte one on every probe iteration.
            let new_front = (vip_ip, vip_port);
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
        ingress_node_ip: unsafe { tkey.__bindgen_anon_1.remote_ipv4 },
        vip_ip,
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

    rewrite_ip_port(
        ctx,
        IP_DST,
        vip_ip,
        pod_ip,
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

/// Ingress role (step 7): read `CLIENT_IP:SRC_PORT` off the inner dst and
/// `VIP_IP:VIP_PORT` off the Geneve echo, confirm this return answers a flow
/// this node actually forwarded (drop otherwise -- an echo with no matching
/// forward entry is stale or spoofed), then un-DNAT src back to the VIP and
/// let normal routing carry it out to the client.
#[inline(always)]
fn try_geneve_decap_return(ctx: &TcContext, _tkey: &bpf_tunnel_key) -> Option<i32> {
    if ctx.load::<u16>(12).ok()? != ETH_P_IPV4 {
        return Some(TC_ACT_OK);
    }
    if ctx.load::<u8>(IP_VER_IHL).ok()? & 0x0f != 5 {
        return Some(TC_ACT_OK);
    }
    let proto: u8 = ctx.load(IP_PROTO).ok()?;
    if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
        return Some(TC_ACT_OK);
    }

    let mut opt = [0u8; 12];
    if unsafe { bpf_skb_get_tunnel_opt(ctx.skb.skb, opt.as_mut_ptr().cast(), opt.len() as u32) } < 0
    {
        return Some(TC_ACT_SHOT);
    }
    if opt[0..2] != GENEVE_OPT_CLASS.to_ne_bytes() || opt[2] != GENEVE_OPT_TYPE_VIP_ECHO {
        return Some(TC_ACT_SHOT);
    }
    let vip_ip = u32::from_ne_bytes(opt[4..8].try_into().ok()?);
    let vip_port = u16::from_ne_bytes(opt[8..10].try_into().ok()?);

    let pod_ip: u32 = ctx.load(IP_SRC).ok()?;
    let target_port: u16 = ctx.load(L4_SPORT).ok()?;
    let client_ip: u32 = ctx.load(IP_DST).ok()?;
    let client_port: u16 = ctx.load(L4_DPORT).ok()?;

    let client_ip_v6 = ipv4_mapped_v6(client_ip);
    let vip_ip_v6 = ipv4_mapped_v6(vip_ip);
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
    let in_main = flow_table_get_forward(fwd_key).is_some();
    if !in_main {
        let pending_value = unsafe { FWD_PENDING.get(key) }.copied();
        match return_authorization(false, pending_value.is_some()) {
            ReturnAuthorization::Promote => {
                FLOW_TABLE
                    .insert(
                        fwd_key,
                        FlowValue {
                            forward: pending_value?,
                        },
                        0,
                    )
                    .ok()?;
                let _ = FWD_PENDING.remove(key);
            }
            ReturnAuthorization::Drop => return None,
            ReturnAuthorization::Established => {}
        }
    }

    rewrite_ip_port(
        ctx,
        IP_SRC,
        pod_ip,
        vip_ip,
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
    let uplink_ifindex = CONFIG.get(0)?.uplink_ifindex;
    if unsafe { bpf_redirect(uplink_ifindex, 0) } as i32 != TC_ACT_REDIRECT {
        return Some(TC_ACT_SHOT);
    }
    Some(TC_ACT_REDIRECT)
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
    // See `try_uplink_ingress`'s matching comment: the uplink's L2 header
    // length is resolved once by the loader, not assumed to be Ethernet's 14
    // bytes.
    let l2_hlen = CONFIG.get(0)?.uplink_l2_hlen as usize;
    // See `try_uplink_ingress`'s matching comment: dispatches on a const
    // generic so every `load_direct` offset below is a compile-time literal.
    match l2_hlen {
        0 => try_uplink_egress_return_headers::<0>(ctx),
        ETH_HLEN => try_uplink_egress_return_headers::<ETH_HLEN>(ctx),
        _ => Some(TC_ACT_OK),
    }
}

fn try_uplink_egress_return_headers<const L2_HLEN: usize>(ctx: &TcContext) -> Option<i32> {
    if L2_HLEN == ETH_HLEN && load_direct::<u16>(ctx, 12)? != ETH_P_IPV4 {
        return Some(TC_ACT_OK);
    }
    // See `try_uplink_ingress_headers`'s matching comment: offset 0 can't go
    // through `load_direct`.
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
    // ~38-byte FLOW_TABLE key built: POD_TARGETS is a 4-byte-keyed, 32-entry
    // map, far cheaper to probe than this hook's own conntrack table, and
    // most packets crossing this hook (ALL uplink egress, not just
    // beep's) take this branch.
    let is_backend_pod = unsafe { POD_TARGETS.get(pod_ip) }.is_some();
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
    tkey.__bindgen_anon_1.remote_ipv4 = rev.ingress_node_ip;
    tkey.tunnel_id = VNI_RET;
    tkey.tunnel_ttl = 64;
    if unsafe {
        bpf_skb_set_tunnel_key(
            ctx.skb.skb,
            &mut tkey,
            core::mem::size_of::<bpf_tunnel_key>() as u32,
            0,
        )
    } != 0
    {
        return Some(TC_ACT_SHOT);
    }

    let mut opt = [0u8; 12];
    opt[0..2].copy_from_slice(&GENEVE_OPT_CLASS.to_ne_bytes());
    opt[2] = GENEVE_OPT_TYPE_VIP_ECHO;
    opt[3] = 2; // opt_data length in 4-byte words (6 bytes + 2 padding).
    opt[4..8].copy_from_slice(&rev.vip_ip.to_ne_bytes());
    opt[8..10].copy_from_slice(&rev.vip_port.to_ne_bytes());
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

    ctx.l3_csum_replace(IP_CSUM, old_ip as u64, new_ip as u64, 4)
        .ok()?;
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

/// Rewrites a TCP/UDP port in place with no IP change -- no L3 checksum
/// involved, only the L4 one. Backs Decision 3's backend source-port remap
/// (forward leg) and its un-remap (return leg); a no-op when
/// `old_port == new_port`, so callers can invoke it unconditionally.
///
/// `l4_off` is the caller's own L4-header base offset, not the module's
/// `L4_OFF` const: `try_uplink_egress_return`'s call site resolves it at
/// runtime from `Config::uplink_l2_hlen` (an L3-only WireGuard uplink has no
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
