//! Per-node userspace control plane for beep's ServiceLB dataplane
//! (`docs/design/ebpf-lb-dataplane.md`'s "Userspace control plane" section).
//! `reconcile` is the pure Service/EndpointSlice-to-map-diff logic -- no
//! async runtime, no k8s client, no aya. Splitting it out from the
//! watch-handler plumbing (`watch`, `apply`) keeps the actual map-population
//! decision unit-testable without a live cluster (Rule 14): a wrong decision
//! here is a silent-wrong-routing bug, not a crash. `watch`/`apply` need aya
//! (via `beep-common`'s `user` feature) to write the dataplane maps, so this
//! crate -- unlike `reconcile` alone -- only builds on Linux.

pub mod apply;
pub mod reconcile;
pub mod status;
pub mod watch;
