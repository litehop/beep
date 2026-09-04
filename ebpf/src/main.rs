#![no_std]
#![no_main]

//! Phase 2 of the ServiceLB eBPF dataplane: Geneve encap/decap on the
//! symmetric-return path, single-flow happy path
//! (`ai/extended-context/ebpf-lb-dataplane.md`'s "Packet flow" section,
//! `docs/decisions/servicelb-symmetric-geneve-return.md`). IPv4 only, one
//! static VIP:PORT -> backend-node/PodIP:TargetPort mapping populated by the
//! userspace loader at startup -- real Service/EndpointSlice watching is
//! Phase 5. Naive single-entry flow-affinity maps; collision-proofing and
//! LRU sizing are Phase 3 (mayor-pa0ze).
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
        bpf_redirect, bpf_skb_get_tunnel_key, bpf_skb_get_tunnel_opt, bpf_skb_set_tunnel_key,
        bpf_skb_set_tunnel_opt,
    },
    macros::{classifier, map},
    maps::{Array, HashMap},
    programs::TcContext,
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
/// needs to pick a target port (`docs/decisions/servicelb-ebpf-geneve-dataplane.md`,
/// mayor-gjbov wire-format settlement: "raw pod IP for the pod identifier").
const GENEVE_OPT_TYPE_POD_ID: u8 = 0x01;
/// Return-leg option: raw `VIP_IP:VIP_PORT` echo (6 bytes + 2 padding),
/// captured by the backend before it DNATs and echoed back so the ingress
/// can un-DNAT without its own state lookup racing the encap.
const GENEVE_OPT_TYPE_VIP_ECHO: u8 = 0x02;

const ETH_HLEN: usize = 14;
const ETH_P_IPV4: u16 = 0x0800u16.to_be();
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

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
/// userspace loader). VIP-space and flannel's pod-CIDR are disjoint by
/// construction (`ebpf-lb-dataplane.md`), so this and `POD_TARGETS` below
/// never collide despite sharing no key structure.
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

/// Backend-local: which port a decap'd, DNAT'd packet should land on for a
/// given pod IP. <20 entries per `ebpf-lb-dataplane.md`'s sizing table.
#[map]
static POD_TARGETS: HashMap<u32, u16> = HashMap::with_max_entries(32, 0);

/// Ingress-side forward-flow affinity, written at stamp time (step 2),
/// rebuilt and checked at return-decap time (step 7) from the Geneve VIP
/// echo plus the inner dst -- confirms the return is answering a flow this
/// node actually forwarded, not stale/spoofed. Naive single-entry map:
/// collision-proofing is Phase 3 (mayor-pa0ze), not here.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowKey {
    pub client_ip: u32,
    pub client_port: u16,
    pub other_ip: u32,
    pub other_port: u16,
    pub proto: u8,
    pub _pad: u8,
}

#[map]
static FWD_FLOW: HashMap<FlowKey, u32> = HashMap::with_max_entries(64, 0);

/// Backend-side reverse-flow: captured at decap+DNAT time (step 4, BEFORE
/// the dst rewrite) so the egress classifier (step 6) can recover the
/// ingress node and the original VIP to echo, since by the time it runs the
/// packet's own header no longer carries the VIP -- DNAT already overwrote
/// it (`ebpf-lb-dataplane.md`, Conntrack & affinity).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RevFlowValue {
    pub ingress_node_ip: u32,
    pub vip_ip: u32,
    pub vip_port: u16,
    pub _pad: u16,
}

#[map]
static REV_FLOW: HashMap<FlowKey, RevFlowValue> = HashMap::with_max_entries(64, 0);

/// Host-specific runtime config the loader fills in after attach (an
/// ifindex isn't known until then). Single entry.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Config {
    pub geneve_ifindex: u32,
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
    let flow_key = FlowKey {
        client_ip: src_ip,
        client_port: src_port,
        other_ip: dst_ip,
        other_port: dst_port,
        proto,
        _pad: 0,
    };
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
#[inline(never)]
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
    if unsafe { bpf_skb_get_tunnel_opt(ctx.skb.skb, opt.as_mut_ptr().cast(), opt.len() as u32) }
        < 0
    {
        return Some(TC_ACT_SHOT);
    }
    if opt[0..2] != GENEVE_OPT_CLASS.to_ne_bytes() || opt[2] != GENEVE_OPT_TYPE_POD_ID {
        return Some(TC_ACT_SHOT);
    }
    let pod_ip = u32::from_ne_bytes(opt[4..8].try_into().ok()?);

    let target_port = *unsafe { POD_TARGETS.get(pod_ip) }?;

    let client_ip: u32 = ctx.load(IP_SRC).ok()?;
    let client_port: u16 = ctx.load(L4_SPORT).ok()?;
    let vip_ip: u32 = ctx.load(IP_DST).ok()?; // captured before rewrite
    let vip_port: u16 = ctx.load(L4_DPORT).ok()?; // captured before rewrite

    let rev_key = FlowKey {
        client_ip,
        client_port,
        other_ip: pod_ip,
        other_port: target_port,
        proto,
        _pad: 0,
    };
    let rev_value = RevFlowValue {
        ingress_node_ip: unsafe { tkey.__bindgen_anon_1.remote_ipv4 },
        vip_ip,
        vip_port,
        _pad: 0,
    };
    REV_FLOW.insert(rev_key, rev_value, 0).ok()?;

    rewrite_ip_port(ctx, IP_DST, vip_ip, pod_ip, L4_DPORT, vip_port, target_port, proto)?;

    Some(TC_ACT_OK)
}

/// Ingress role (step 7): read `CLIENT_IP:SRC_PORT` off the inner dst and
/// `VIP_IP:VIP_PORT` off the Geneve echo, confirm this return answers a flow
/// this node actually forwarded (drop otherwise -- an echo with no matching
/// forward entry is stale or spoofed), then un-DNAT src back to the VIP and
/// let normal routing carry it out to the client.
#[inline(never)]
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
    if unsafe { bpf_skb_get_tunnel_opt(ctx.skb.skb, opt.as_mut_ptr().cast(), opt.len() as u32) }
        < 0
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

    let key = FlowKey {
        client_ip,
        client_port,
        other_ip: vip_ip,
        other_port: vip_port,
        proto,
        _pad: 0,
    };
    unsafe { FWD_FLOW.get(key) }?;

    rewrite_ip_port(ctx, IP_SRC, pod_ip, vip_ip, L4_SPORT, target_port, vip_port, proto)?;

    Some(TC_ACT_OK)
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

    // This is the Pod's own raw reply: src=PodIP:TargetPort, dst=CLIENT_IP:SRC_PORT.
    let pod_ip: u32 = ctx.load(IP_SRC).ok()?;
    let target_port: u16 = ctx.load(L4_SPORT).ok()?;
    let client_ip: u32 = ctx.load(IP_DST).ok()?;
    let client_port: u16 = ctx.load(L4_DPORT).ok()?;

    let key = FlowKey {
        client_ip,
        client_port,
        other_ip: pod_ip,
        other_port: target_port,
        proto,
        _pad: 0,
    };
    let rev = *unsafe { REV_FLOW.get(key) }?;

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
#[inline(never)]
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
    let l4_csum_off = if proto == IPPROTO_TCP { TCP_CSUM } else { UDP_CSUM };
    let is_udp = proto == IPPROTO_UDP;
    let udp_csum_disabled = is_udp && ctx.load::<u16>(UDP_CSUM).ok()? == 0;

    ctx.l3_csum_replace(IP_CSUM, old_ip as u64, new_ip as u64, 4).ok()?;
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
