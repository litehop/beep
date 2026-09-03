#![no_std]
#![no_main]

//! Phase 1 skeleton of the ServiceLB eBPF dataplane: four no-op tc-bpf
//! (clsact) classifiers, one per hook point in
//! `ai/extended-context/ebpf-lb-dataplane.md`. None mutate or redirect
//! packets yet -- that is Phase 2. Each just accepts the packet
//! (`TC_ACT_OK`) so the four hook shapes can be proven loadable and
//! attachable without verifier rejection before any packet logic is added.

use aya_ebpf::{bindings::TC_ACT_OK, macros::classifier, programs::TcContext};

/// Hook 1: ingress classifier on the physical uplink, every node (forward leg).
#[classifier]
pub fn uplink_ingress(_ctx: TcContext) -> i32 {
    TC_ACT_OK
}

/// Hook 2: ingress classifier on `geneve0`, backend node (forward leg, decap).
#[classifier]
pub fn geneve_ingress_decap(_ctx: TcContext) -> i32 {
    TC_ACT_OK
}

/// Hook 3: egress classifier on the physical uplink, backend node (return leg).
#[classifier]
pub fn uplink_egress_return(_ctx: TcContext) -> i32 {
    TC_ACT_OK
}

/// Hook 4: ingress classifier on `geneve0`, ingress node (return leg, decap).
#[classifier]
pub fn geneve_ingress_return(_ctx: TcContext) -> i32 {
    TC_ACT_OK
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
