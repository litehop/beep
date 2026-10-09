# Unsafe-blocks audit

Bead: beep-uqn

Answer: the repo has 76 `unsafe` sites, none unsound today, but zero carry a
`SAFETY` comment and about 35 are avoidable (7 map `.get().is_some()` reads
have a fully safe alternative, 2 helper calls have a safe aya wrapper, 16
helper calls are 4 copies of one sequence, 11 `Pod` impls rest on a
host-test-only invariant); the rest are inherent to eBPF/FFI and need
documentation, not removal.

Counted 2026-10-09 against `main` @ 9b555ec with `grep -w unsafe` (doc/comment
mentions excluded; `kubeconfig` has none; no crate sets
`unsafe_op_in_unsafe_fn`/`unsafe_code` lints; `grep SAFETY` returns nothing).

## Counts by crate

| Crate | Sites | Notes |
|---|---|---|
| `beep-ebpf` (`ebpf/src/main.rs`) | 58 | 20 map reads, 3 union reads, 24 helper calls, 5 `zeroed`, 2 tunnel-key union reads, 3 skb field reads, 1 raw packet read |
| `beep-common` (`common/src/lib.rs`) | 14 | 11 `unsafe impl aya::Pod` (L446-466), 3 union-arm reads (L481/486/491) |
| `beep` loader (`src/`) | 3 | `setrlimit` (`src/lib.rs:352`), `if_nametoindex` (`src/lib.rs:607`), `malloc_trim` (`src/main.rs:513`) |
| `beep-controller` | 1 | `malloc_trim` (`controller/src/main.rs:432`, glibc-only cfg) |
| Total | 76 | |

## Patterns

### P1 -- map `.get()` returning `&V` (ebpf, 20 sites incl. 1 raw deref) -- MED

Sites: `FLOW_TABLE` L370/375/380 (the three `flow_table_get_*` wrappers),
`FRONT_META` L390, `FRONT_ENDPOINTS` L392, `UPLINK_CONFIG` L554/1368/1599,
`FWD_PENDING` L661/671/796/802/1430/1526, `NODE_ALLOW` L914/1325,
`POD_TARGETS` L942/1663/1778, `FRONT_MISSES` L395 (`*misses += 1`).

Invariant: aya's `HashMap::get`/`LruHashMap::get` is `unsafe` because the
returned `&V` aliases kernel map memory that another CPU or userspace can
mutate/evict; it is only sound if the reference is consumed before any
concurrent writer matters (here: copied out immediately). All sites copy or
test-and-drop, so none holds the reference across a call. No SAFETY comment.
L395 derefs a `PerCpuArray` slot, so the non-atomic `+= 1` is sound because the
slot is CPU-local; undocumented.

Avoidable:
- 7 sites only test presence (`.get(k).is_some()`: L661, L796, L914, L942,
  L1325, L1663, L1778). `get_ptr(k).is_some()` is safe in aya-ebpf 0.2.1
  (`hash_map.rs:57`) and issues the same `bpf_map_lookup_elem` + null check. 
- The remaining value-reading sites are irreducible, but they repeat the
  `unsafe { M.get(k) }.copied()` shape per map. One `#[inline(always)]`
  copy-out accessor per map (the `flow_table_get_*` precedent) collapses them
  and puts the single SAFETY comment in one place.

Verifier notes (`bd memories ebpf-verifier-gotcha`: packet-pointer arithmetic
must keep a nonzero constant delta from `ctx.data()`; helpers must be
`#[inline(always)]`, non-inlined BPF-to-BPF calls are a miscompile risk on this
toolchain): map lookups are not packet-pointer arithmetic, but wrappers MUST be
`#[inline(always)]` and the change needs `scripts/smoke.sh`.

### P2 -- duplicated Geneve tunnel stamp + redirect sequence (ebpf, 16 sites in 4 copies) -- MED

Sites: copies at ~L681-L737, L812-L854, L1703-L1749, L1812-L1853, each
`zeroed` `bpf_tunnel_key` + `bpf_skb_set_tunnel_key` + `bpf_skb_set_tunnel_opt`
+ conditional `bpf_skb_change_head` + `bpf_redirect` (5 unsafe each = 20,
counting `zeroed`; 16 helper calls).

Invariant: pointers come from stack locals of the exact helper-expected
size (`size_of::<bpf_tunnel_key>()`, `opt.len()`), `ctx.skb.skb` is the live
skb. Sound; unstated. The copies already drift in comments only (the L2_HLEN==0
`change_head` block is duplicated verbatim, a latent fix-in-one-place hazard).

Avoidable: one `#[inline(always)] fn redirect_to_geneve(ctx, ...)` taking the
remote, VNI, 20-byte option and `L2_HLEN` const generic would leave 5 unsafe
sites instead of 20. Verifier risk is real: `ctx.store(12, ...)` after
`change_head` invalidates packet pointers, and any packet read after the
helper call must re-derive pointers; keep the order byte-for-byte. Requires
`scripts/smoke.sh` (front -> Geneve -> backend) on the assigned VM, plus the
uplink-WireGuard (`L2_HLEN == 0`) path if the smoke covers it.

### P3 -- other helper calls (ebpf, 8 sites) -- DEFER, 2 avoidable

- `bpf_skb_get_tunnel_key` x2 (L503/506), `bpf_skb_get_tunnel_opt` x2
  (L925/1334), `bpf_redirect_neigh`/`bpf_redirect` (L1370/1372): no aya safe
  wrapper in 0.2.1 (`TcContext` has `clone_redirect`, not these). DEFER:
  inherent to eBPF; add one SAFETY line (arguments are stack locals of the
  size passed).
- `bpf_skb_change_type` (L1158, L1308): `TcContext::change_type` exists and is
  safe (`aya-ebpf-0.2.1/src/programs/tc.rs:168`). Avoidable, LOW effort. 
  Must be `smoke.sh`-verified because it is on the return path.

### P4 -- skb field reads and `zeroed` (ebpf, 8 sites) -- LOW

- `(*ctx.skb.skb).ingress_ifindex`/`.mark`/`.ifindex` (L544, L1585, L1598):
  raw deref of the program context pointer, valid for the duration of the
  program; no safe aya accessor for these fields. Fold into three tiny
  helpers or just add SAFETY comments.
- `core::mem::zeroed::<bpf_tunnel_key>()` x5 (L501/681/812/1703/1812): valid
  because the bindgen struct is plain integers/unions of integers (all-zero
  is valid). Replaceable by P2's single constructor; otherwise SAFETY.
- `tkey.__bindgen_anon_1.remote_ipv4/remote_ipv6` (L523/524): reading both
  union arms of integer data is sound; the decision logic already lives in the
  host-tested `tunnel_remote_addr`. LOW (comment).

### P5 -- `load_direct` raw packet read (ebpf, 1 site, L453) -- DEFER

`read_unaligned` after `start + offset + size_of::<T>() > end` bounds check.
Sound given the check (no overflow: usize on BPF is 64-bit, offsets are
constants) and `T: Copy` -- but `T: Copy` does not guarantee every bit
pattern is valid (e.g. `bool`/enums). Every caller passes integer/array types
today. Tighten with a `Pod`-like marker bound or document in SAFETY. Do not
alter the body: the doc comment (L433-445) records live-kernel verifier
findings (const nonzero offset). LOW-MED (unenforced caller invariant).

### P6 -- `unsafe impl aya::Pod` (common, 11 sites, L446-466) -- MED

Invariant: `aya::Pod` requires every bit pattern valid and NO padding bytes
(padding would be copied to kernel memory uninitialized). It is enforced only
by host unit tests (`*_has_no_padding`, `common/src/lib.rs` L1093-1200); a
new field that introduces padding fails `cargo test` but not the build, and
`Config` is checked only by a size assert (L978). `FlowValue` is a union of
three arms of unequal size: a smaller-arm write leaves trailing bytes
unspecified; Pod holds only because userspace/eBPF zero-initialize.

Avoidable: replace the 11 hand-written impls with one `macro_rules! impl_pod`
that emits both the impl and a `const _: () = assert!(size_of::<T>() == $sum)`
no-padding check (compile-time, so enforcement moves from test to build).
Do not add `bytemuck` (new dependency; `aya::Pod` is what the loader needs).
Add a SAFETY comment on the macro. No ebpf/ change, so no smoke needed.

### P7 -- union-arm readers `FlowValue::as_forward/reverse/port_memo` (common, 3 sites, L481-491) -- LOW

Invariant: caller already knows the key's direction tag. The doc comment states
it; there is no SAFETY comment and the wrapper is a safe fn that can return
bytes of the wrong arm without UB (all arms are integer data), so the
function is memory-safe, just semantically unchecked. Tighten by taking a
`FlowDirection`-typed key and returning `Option`, or leave. LOW.

### P8 -- loader/controller FFI (4 sites) -- DEFER, 1 avoidable

- `libc::setrlimit` (`src/lib.rs:352`): valid `&rlimit` of a local; DEFER.
- `libc::malloc_trim(0)` (`src/main.rs:513`, `controller/src/main.rs:432`):
  glibc-only, no pointers, cannot violate memory safety; identical blocks in
  two crates (the controller one has a `cfg(target_env="gnu")` gate the loader
  lacks, so the loader would not build on musl). DEFER, add SAFETY and align
  the cfg gate. Duplicate: a shared `trim_heap()` would need a home crate
  (`beep-common` is `no_std`, not suitable) -- not worth a new crate.
- `libc::if_nametoindex` (`src/lib.rs:607`): avoidable. The sibling
  `iface_arphrd_type` already reads `/sys/class/net/<name>/type`; reading
  `/sys/class/net/<name>/ifindex` removes the FFI block and the `CString`
  dance, returns a typed `io::Error`, and parses safely. Caveat: sysfs shows the
  caller's network namespace, same as `if_nametoindex`. MED-LOW.

## Severity totals (by pattern, not site)

| Severity | Patterns | Sites |
|---|---|---|
| HIGH (unsound / invariant unenforced) | 0 | 0 |
| MED (avoidable, widely duplicated) | P1, P2, P6 | 20 + 20 + 11 |
| LOW (missing SAFETY comment / minor tighten) | P4, P5, P7, P8-if_nametoindex | 8 + 1 + 3 + 1 |
| DEFER (inherent) | P3, P8 FFI | 6 + 3 |

(P1/P2 sites overlap partially with DEFER: after reduction ~12 map and ~10
helper sites remain irreducible.) No HIGH finding: every unsafe site was read
and none holds a reference across a concurrent writer or reads uninitialized
memory today; the HIGH-adjacent exposure is P6's test-only padding check.

## Reduction plan (follow-on beads, one per pattern)

1. P6: `impl_pod!` macro + compile-time no-padding asserts + SAFETY (common/).
2. P1: presence checks via `get_ptr`, per-map copy-out accessors, SAFETY
   (ebpf/, smoke required).
3. P2 + P3 (`change_type`) + P4 `zeroed`: single `redirect_to_geneve` helper
   and safe `change_type` (ebpf/, smoke required).
4. P4/P5/P3 residual: SAFETY comments on every remaining ebpf site, and the
   `load_direct` `T` bound; enable `#![warn(clippy::undocumented_unsafe_blocks)]`
   once all sites are documented, so new ones cannot regress (clippy lint is
   in-tree; no new dependency).
5. P8: SAFETY on the FFI blocks, align `malloc_trim` cfg gate, replace
   `if_nametoindex` with a sysfs read (loader + controller, Linux CI).

Target after plan: 76 -> ~42 unsafe sites, 100% with SAFETY comments, lint
guarding new ones.
