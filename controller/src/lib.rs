//! Per-node userspace control plane for beep's ServiceLB dataplane
//! (`docs/design/ebpf-lb-dataplane.md`'s "Userspace control plane" section).
//! This crate currently holds only the pure Service/EndpointSlice-to-map-diff
//! logic (`reconcile`) -- no async runtime, no k8s client, no aya. Splitting
//! it out from the eventual watch-handler plumbing keeps the actual
//! map-population decision unit-testable without a live cluster (Rule 14):
//! a wrong decision here is a silent-wrong-routing bug, not a crash.

pub mod reconcile;
