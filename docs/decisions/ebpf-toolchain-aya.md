# eBPF toolchain: aya

**Status:** Accepted
**Date:** 2026-09-01

## Context

The ServiceLB dataplane (`servicelb-ebpf-geneve-dataplane.md`) needs a
Rust-callable toolchain to write, load, and manage tc-bpf programs and
their maps. Candidates: `aya` (pure Rust), `libbpf-rs` (a Rust wrapper
around the C libbpf library), and C + libbpf directly.

## Decision

Use `aya` as the initial toolchain.

## Rationale

| | aya | libbpf-rs | C + libbpf |
|---|---|---|---|
| Rust-fit | Pure Rust, no C toolchain in the build | Wraps the real libbpf C library — adds a C dependency to an all-Rust workspace | A second language in a project with zero C today |
| CO-RE | Own BTF-based CO-RE, already matches the multi-kernel matrix confirmed live (Lima 7.0.0-30 arm64 vs. 7.0.0-28 x86_64) | Relies on libbpf's CO-RE, mature and field-proven | Same libbpf CO-RE, most mature but manual |
| Compiler maturity | `bpf-linker`, an LLVM-based Rust→BPF backend with materially less production mileage than clang's — the real trade-off, since the kernel verifier itself is identical regardless of toolchain | Compiles via clang | clang, most mature |
| Precedent at this problem class | `kubernetes-retired/blixt` — Rust+aya k8s L4 LB, TC classifiers, hand-rolled hash-map conntrack, DNAT+redirect — closest architectural analog | None found at this problem class | Katran (C++, general-purpose) |

`aya` is the only option with no C toolchain or C dependency in a workspace
whose entire stance is minimal-deps and all-Rust; the `bpf-linker` maturity
gap is real but narrower than the cost of introducing C, and blixt already
proved the toolchain viable for a directly comparable dataplane.

## Consequences

- Both userspace and kernelspace memory use must be fully monitorable: the
  userspace control-plane process's RSS via normal OS tooling, and every
  eBPF map's actual (not just ceiling) memory use via `bpftool map
  dump`/`bpftool map show` or equivalent — a Phase-3 prototype gate, not
  optional instrumentation added later.
- **Revisit trigger**: if `aya`'s runtime efficiency or its
  memory-observability tooling proves limiting in practice, reconsider
  `libbpf-rs` or raw C/C++ — this comparison is not a one-time decision
  closed permanently.
