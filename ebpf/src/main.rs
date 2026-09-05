#![no_std]
#![no_main]

//! Phase 2 (Geneve encap/decap on the symmetric-return path) plus Phase 3
//! (conntrack full-tuple keying + backend source-port remap on conflict) of
//! the ServiceLB eBPF dataplane
//! (`ai/extended-context/ebpf-lb-dataplane.md`'s "Packet flow" and
//! "Conntrack & affinity" sections, `docs/decisions/servicelb-symmetric-geneve-return.md`).
//! IPv4 only, one static VIP:PORT -> backend-node/PodIP:TargetPort mapping
//! populated by the userspace loader at startup -- real Service/EndpointSlice
//! watching is Phase 5. Flow-affinity keys are IPv6-primary (`u7s_servicelb_common`)
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
//! `crates/servicelb/src/main.rs`'s `populate_fixture` for where that
//! conversion happens at the map-population boundary. `tunnel_id` (VNI)
//! also takes plain host order (the kernel applies `cpu_to_be64`
//! internally), consistent with `remote_ipv4` here.

use aya_ebpf::{
    bindings::{bpf_tunnel_key, BPF_F_PSEUDO_HDR, TC_ACT_OK, TC_ACT_REDIRECT, TC_ACT_SHOT},
    helpers::{
        bpf_redirect, bpf_skb_change_type, bpf_skb_get_tunnel_key, bpf_skb_get_tunnel_opt,
        bpf_skb_set_tunnel_key, bpf_skb_set_tunnel_opt,
    },
    macros::{classifier, map},
    maps::{Array, HashMap, LruHashMap},
    programs::TcContext,
};
use u7s_servicelb_common::{
    encode_tcp_flow_key, ipv4_mapped_v6, occupant_conflicts, resolve_backend_src_port,
    BackendPortDecision, TcpFlowKey,
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
/// userspace loader). Same `VipKey` shape as `TARGET_PORTS` below, but a
/// separate map -- the two never interact, just key on the same front tuple
/// for the two different roles that need it (ingress backend selection here,
/// backend target-port selection there).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VipKey {
    pub vip_ip: u32,
    pub vip_port: u16,
    pub proto: u8,
    pub _pad: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VipBackend {
    /// Geneve remote for the forward leg -- the node hosting the chosen Pod.
    pub backend_node_ip: u32,
    /// Pod-identifier stamped as the forward-leg Geneve option.
    pub pod_ip: u32,
}

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

/// Ingress-side forward-flow affinity, written at stamp time (step 2),
/// rebuilt and checked at return-decap time (step 7) from the Geneve VIP
/// echo plus the inner dst -- confirms the return is answering a flow this
/// node actually forwarded, not stale/spoofed.
///
/// Key type: `u7s_servicelb_common::TcpFlowKey`, a flat 37-byte array, not a
/// `#[repr(C)]` struct -- `BPF_MAP_TYPE_*_HASH` compares/hashes a key's raw
/// bytes including any compiler-inserted alignment padding, and a struct's
/// padding gap is left as whatever garbage was already on the call site's
/// stack, differing between independent call sites despite every named
/// field matching (Phase 2 hit exactly this on a live kernel: a byte-
/// identical insert+lookup, microseconds apart, still missed). A byte array
/// has no such gap. 8192-entry ceiling per `ebpf-lb-dataplane.md`'s TCP
/// sizing row.
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
static FWD_FLOW: LruHashMap<TcpFlowKey, u32> = LruHashMap::with_max_entries(8192, 0);

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
#[derive(Clone, Copy)]
pub struct RevFlowValue {
    pub ingress_node_ip: u32,
    pub vip_ip: u32,
    pub vip_port: u16,
    pub original_client_port: u16,
}

#[map]
static REV_FLOW: LruHashMap<TcpFlowKey, RevFlowValue> = LruHashMap::with_max_entries(8192, 0);

/// Host-specific runtime config the loader fills in after attach (an
/// ifindex isn't known until then). Single entry.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Config {
    pub geneve_ifindex: u32,
    pub uplink_ifindex: u32,
}

#[map]
static CONFIG: Array<Config> = Array::with_max_entries(1, 0);

/// Hook 1: ingress classifier on the physical uplink, every node (forward
/// leg). Classifies VIP:PORT traffic, stamps Geneve metadata, redirects to
/// `geneve0`. Everything else passes through untouched -- this hook sees
/// all uplink traffic, not just ServiceLB's.
#[classifier]
pub fn uplink_ingress(ctx: TcContext) -> i32 {
    try_uplink_ingress(&ctx).unwrap_or(TC_ACT_OK)
}

fn try_uplink_ingress(ctx: &TcContext) -> Option<i32> {
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

    let dst_ip: u32 = ctx.load(IP_DST).ok()?;
    let dst_port: u16 = ctx.load(L4_DPORT).ok()?;
    let key = VipKey {
        vip_ip: dst_ip,
        vip_port: dst_port,
        proto,
        _pad: 0,
    };
    let backend = *unsafe { VIP_MAP.get(key) }?;

    let src_ip: u32 = ctx.load(IP_SRC).ok()?;
    let src_port: u16 = ctx.load(L4_SPORT).ok()?;
    let flow_key = encode_tcp_flow_key(
        ipv4_mapped_v6(src_ip),
        src_port,
        ipv4_mapped_v6(dst_ip),
        dst_port,
        proto,
    );
    FWD_FLOW.insert(flow_key, backend.backend_node_ip, 0).ok()?;

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

/// Backend role (step 4): read `VIP_IP:VIP_PORT` off the still-untouched
/// inner dst BEFORE rewriting anything, record the reverse-flow entry, DNAT
/// dst to `PodIP:TargetPort` (src untouched -- the Pod must see the real
/// client IP at L3), then hand the packet to the normal receive path:
/// `TC_ACT_OK` on an inbound decap leaves the now-foreign-dst'd packet to
/// the kernel's own routing, which is flannel's job from here, not ours.
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
    let natural_rev_key =
        encode_tcp_flow_key(client_ip_v6, client_port, pod_ip_v6, target_port, proto);

    // Decision 3 (`ebpf-lb-dataplane.md`): two Services with different front
    // addresses sharing this backend Pod:targetPort, hit by a client
    // reusing one source port across both, would otherwise write this same
    // reverse key twice. Check whether a DIFFERENT (front, original client
    // port) identity already holds it before trusting the natural key -- a
    // matching identity (or no entry at all) means this is the same flow
    // refreshing, or the first writer. Front alone isn't enough: a distinct
    // flow through this same front whose real source port happens to equal
    // another flow's already-committed synthetic port would otherwise be
    // misread as that flow's own state and clobber its REV_FLOW entry.
    let existing_occupant = unsafe { REV_FLOW.get(natural_rev_key) }.map(|v| {
        (
            (ipv4_mapped_v6(v.vip_ip), v.vip_port),
            v.original_client_port,
        )
    });
    let new_front = (ipv4_mapped_v6(vip_ip), vip_port);
    // The probe's occupancy check: REV_FLOW itself is the source of truth
    // for which candidate ports are actually free, not a derived guess --
    // a single low-entropy hash of the front address only guaranteed
    // uniqueness for exactly 2 conflicting fronts. An occupant matching both
    // our own front and our own original client port is a prior packet of
    // this exact flow's already-committed remap, not a conflict -- without
    // that full comparison the flow (or an unrelated flow reusing its
    // synthetic port as a real source port) reads state back as "taken"/
    // "mine" incorrectly and either churns ports until PROBE_LIMIT is
    // exhausted, or silently clobbers another flow's entry.
    let is_reverse_key_taken = |candidate_port: u16| {
        let candidate_key =
            encode_tcp_flow_key(client_ip_v6, candidate_port, pod_ip_v6, target_port, proto);
        let occupant = unsafe { REV_FLOW.get(candidate_key) }.map(|v| {
            (
                (ipv4_mapped_v6(v.vip_ip), v.vip_port),
                v.original_client_port,
            )
        });
        occupant_conflicts(occupant, new_front, client_port)
    };
    let (rev_key, backend_src_port) = match resolve_backend_src_port(
        existing_occupant,
        new_front,
        client_port,
        is_reverse_key_taken,
    ) {
        BackendPortDecision::NoRemap => (natural_rev_key, client_port),
        BackendPortDecision::Remap(synthetic_port) => (
            encode_tcp_flow_key(client_ip_v6, synthetic_port, pod_ip_v6, target_port, proto),
            synthetic_port,
        ),
        // Every candidate in the bounded probe window was already taken --
        // drop rather than reuse an occupied reverse key, which would
        // silently reproduce the exact clobbering bug Decision 3 closes.
        BackendPortDecision::Exhausted => return Some(TC_ACT_SHOT),
    };

    let rev_value = RevFlowValue {
        ingress_node_ip: unsafe { tkey.__bindgen_anon_1.remote_ipv4 },
        vip_ip,
        vip_port,
        original_client_port: client_port,
    };
    REV_FLOW.insert(rev_key, rev_value, 0).ok()?;

    // Remap only touches the backend<->Pod segment: the client's real src
    // port is restored by the egress classifier before the packet re-enters
    // the Geneve tunnel (see RevFlowValue's doc comment). A no-op when this
    // flow wasn't remapped.
    rewrite_l4_port(ctx, L4_SPORT, client_port, backend_src_port, proto)?;

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

    let key = encode_tcp_flow_key(
        ipv4_mapped_v6(client_ip),
        client_port,
        ipv4_mapped_v6(vip_ip),
        vip_port,
        proto,
    );
    unsafe { FWD_FLOW.get(key) }?;

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
    let uplink_ifindex = CONFIG.get(0)?.uplink_ifindex;
    if unsafe { bpf_redirect(uplink_ifindex, 0) } as i32 != TC_ACT_REDIRECT {
        return Some(TC_ACT_SHOT);
    }
    Some(TC_ACT_REDIRECT)
}

/// Hook 3: egress classifier on the physical uplink, backend node (return
/// leg). Every non-matching packet -- i.e. everything that isn't a
/// ServiceLB backend Pod's reply -- passes through untouched; this hook
/// sees all uplink egress traffic, not just ServiceLB's.
#[classifier]
pub fn uplink_egress_return(ctx: TcContext) -> i32 {
    try_uplink_egress_return(&ctx).unwrap_or(TC_ACT_OK)
}

fn try_uplink_egress_return(ctx: &TcContext) -> Option<i32> {
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

    // This is the Pod's own raw reply: src=PodIP:TargetPort, dst=CLIENT_IP:SRC_PORT
    // (or Decision 3's remapped synthetic port -- see RevFlowValue's doc comment).
    let pod_ip: u32 = ctx.load(IP_SRC).ok()?;
    let target_port: u16 = ctx.load(L4_SPORT).ok()?;
    let client_ip: u32 = ctx.load(IP_DST).ok()?;
    let backend_dst_port: u16 = ctx.load(L4_DPORT).ok()?;

    let key = encode_tcp_flow_key(
        ipv4_mapped_v6(client_ip),
        backend_dst_port,
        ipv4_mapped_v6(pod_ip),
        target_port,
        proto,
    );
    let rev = *unsafe { REV_FLOW.get(key) }?;

    // Un-remap: restore the client's real port before this packet re-enters
    // the Geneve tunnel -- the ingress node's return-decap step rebuilds its
    // own lookup key from this inner dst and has no knowledge of any
    // backend-local remap. A no-op when this flow was never remapped.
    rewrite_l4_port(
        ctx,
        L4_DPORT,
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
#[inline(always)]
fn rewrite_l4_port(
    ctx: &TcContext,
    port_off: usize,
    old_port: u16,
    new_port: u16,
    proto: u8,
) -> Option<()> {
    if old_port == new_port {
        return Some(());
    }
    let l4_csum_off = if proto == IPPROTO_TCP {
        TCP_CSUM
    } else {
        UDP_CSUM
    };
    if proto == IPPROTO_UDP && ctx.load::<u16>(UDP_CSUM).ok()? == 0 {
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
