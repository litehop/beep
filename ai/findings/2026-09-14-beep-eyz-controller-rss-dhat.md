# beep-controller idle RSS: measured heap attribution (dhat)

Bead: beep-eyz

**Answer: beep-gcd's audit picked the wrong single largest lever.** Measured
per-allocation-site data (dhat, real Linux run on `beep-smoke`, single-node
k3s) shows the dominant heap event in the whole controller lifecycle is
**not** `rustls`/`aws-lc-rs` — it's `aya`/`aya-obj` parsing the kernel's BTF
blob (`/sys/kernel/btf/vmlinux`) inside `load_ebpf`, a **17-31 MiB transient
spike** that dwarfs everything else roughly 40:1, but which the *existing*
`malloc_trim(0)` call already reclaims almost completely (confirmed with a
direct RSS trace on the real, non-instrumented binary). Everything
beep-z6c's second trim and beep-8d0's rustls backend swap target is, by
measurement, small: total Rust-heap retained at idle is ~128 KiB, and
`rustls`'s own Rust-side code totals under 1 MiB ever allocated across the
whole run. Halving the ~6.8-7.7 MiB baseline via any of the three filed
levers now looks **less** plausible than the estimate-only audit thought,
not more — the two "free" levers (z6c, ota) have near-zero measured heap
yield, and the one lever that might still matter (beep-8d0) has a payoff
this tool structurally cannot see (explained below), so it stays unconfirmed
either way.

## Method

- `controller/Cargo.toml` gained an off-by-default `dhat-heap` feature
  (`dhat` crate as `#[global_allocator]`, gated `dep:dhat` + `tokio/signal`).
  `controller/src/main.rs` holds a `dhat::Profiler` guard for `main`'s whole
  body and races `run_controller_loop` against `tokio::signal::ctrl_c()`
  under the feature, so a SIGINT flushes `dhat-heap.json` on the way out —
  the loop never returns on its own otherwise.
- **Cross-built binaries produced empty dhat stacks** (`"fs": []` for every
  program point, all bytes landing in a single unresolved `[root]` frame).
  The cross-built ELF (`cargo zigbuild --target aarch64-unknown-linux-gnu`
  from macOS) had `.eh_frame` but no `.symtab` (`nm` reported "no symbols") —
  the `backtrace` crate dhat depends on for stack walking could not resolve
  any caller past its own allocator-wrapper frame. Building **natively**
  on `beep-smoke` (nightly + bpf-linker + cmake, all already present or
  `apt`-installed for `aws-lc-sys`) produced a binary with a full symbol
  table (16k+ `nm` entries) and real per-callsite attribution. This is a
  real gotcha for any future dhat run on this codebase: cross-build for
  smoke-testing the dataplane, but build **natively on the target VM** for
  dhat attribution, or it silently degrades to no data.
- Harness: `scripts/memory-smoke-controller.sh` + `scripts/controller-rss.sh`
  (from beep-toi, #57) reused unmodified, driven against a real single-node
  k3s server installed on `beep-smoke` (`--disable=traefik,servicelb,
  metrics-server,local-storage`, same flags as `ci.yaml`'s memory-smoke
  job) — idle settle, then a real Service+Deployment reconcile, then SIGINT.
  k3s was uninstalled and all scratch state removed from `beep-smoke`
  afterward.

## Measured: top allocation sites (dhat)

Cumulative for the whole run (idle settle + reconcile + exit):
`Total: 53,704,043 B` ever allocated, `At t-gmax (peak): 30,918,469 B`,
`At t-end (retained): 130,993 B`.

| Site (leaf call site, resolved) | Total ever (B) | At peak (B) | Retained at exit (B) |
|---|---|---|---|
| `aya_obj::btf::Btf::parse`/`from_sys_fs` reading `/sys/kernel/btf/vmlinux`, called from `aya::bpf::EbpfLoader::new` <- `beep::load_ebpf` | 52,352,360 | 30,918,370 | 0 |
| `rustls` (all Rust-side code: handshake, session cache, record buffers, **and** the thin Rust wrapper around `aws-lc-rs`'s FFI calls — not `aws-lc-sys`'s own C allocations, see caveat below) | 750,735 | 0 | 117,444 |
| `serde_json` (list/watch-event body parsing) | 382,891 | 0 | 0 |
| `tokio` runtime (task/registration bookkeeping for the 3 live watches) | 103,553 | 0 | 12,744 |
| `hyper` (HTTP/1.1 framing, separate from the `bytes`/`rustls`-tagged buffers above) | 59,592 | 0 | 0 |
| `clap` (one-time arg parsing) | 9,760 | 0 | 0 |
| `beep-kubeconfig` (our code) | 6,169 | 0 | 788 |
| `beep-controller` (our code: `WatchState`/`PinnedMaps`/reconcile) | 38,759 | 99 | 17 |

The single largest allocation is one 18,874,368-byte (18 MiB) block —
`std::fs::read::inner` reading the kernel's BTF blob is a separate,
6,972,891-byte read (`vmlinux`'s exact on-disk size on this kernel,
confirmed with `ls -la /sys/kernel/btf/vmlinux`); the larger figure is the
*parsed*, structured `BtfType`/`BtfMember`/`u32` array representation aya
builds from that raw blob. Every byte of this is freed (`eb: 0`) by program
end — this is not a leak, `drop(ebpf)` and aya's own internals both work as
intended.

`rustls`'s retained 117 KiB is legitimate live state for 3 open HTTP/1.1
connections (Service/EndpointSlice/Node watches), not bloat: 3x 8 KiB hyper
read buffers, 3x ~8 KiB tokio mpsc channel buffers, 3x ~3.5 KiB per-watch
tokio tasks, plus one 13.9 KiB `ClientSessionMemoryCache`. `aws-lc-rs`'s own
Rust-side wrapper allocations (AEAD encrypter/decrypter state, EC signing
key wrapping, `LcCBB`-to-`Vec` conversion) total under 500 bytes retained —
present, but negligible.

## Measured: real RSS trace (non-instrumented binary, confirms the above)

Sampling `/proc/<pid>/status` `VmRSS` every ~2 ms on the plain (no
`dhat-heap`) cross-built binary through `load_ebpf`+attach+the existing
`malloc_trim(0)` (kubeconfig deliberately pointed at a missing path to stop
right after that phase):

```
  5,172 kB  (just forked, before load_ebpf)
 15,656 kB
 22,132 kB  <- peak, mid BTF parse (+17 MiB over the fork baseline)
 18,024 kB
  7,284 kB  <- attach + drop(ebpf) + the EXISTING malloc_trim(0) already ran
  7,348 kB
```

A second trace with a valid kubeconfig, sampled every 30 ms for 9 s through
kubeconfig parsing, the mTLS handshake, and all 3 watches establishing
(confirmed via the "all 3 hooks attached; watching..." log line), never
moved off **7,040 kB** — flat for the entire 9 s window. This is the direct,
non-estimated confirmation of the audit's PR #57 baseline (6,948 kB): the
one large transient spike is already fully absorbed by the trim call that
exists today, and the phase beep-z6c's second trim targets adds no
measurable RSS at all in this trace.

## Method limitation (read before trusting the aws-lc-rs numbers)

`dhat::Alloc` (like any Rust `#[global_allocator]`) only instruments calls
that go through Rust's own `alloc()`/`dealloc()` — i.e. `Vec`/`Box`/`String`/
`HashMap` etc. `aws-lc-sys` compiles AWS-LC as a C library via `cc`+`cmake`;
its internal `malloc()`/`free()` calls (RSA/EC bignum scratch buffers, RNG
state, TLS record crypto working memory) go straight to libc's malloc
**without ever passing through Rust's allocator hook**, so dhat is
structurally blind to them. The small `rustls::crypto::aws_lc_rs::*` numbers
above are only the thin Rust wrapper around those FFI calls — they say
nothing about AWS-LC's own heap footprint. **dhat cannot answer beep-8d0's
core question.** That still needs `size`/`bloaty` (for `.text`/`.rodata`) or
a real process-wide malloc interposer (heaptrack, an `LD_PRELOAD` counter,
or Massif) that intercepts the actual libc `malloc` symbol, not a Rust-level
tool.

## Revised per-lever verdicts

- **beep-8d0** (`aws-lc-rs` -> `ring`): **UNCONFIRMED, weaker case than the
  audit's estimate.** dhat cannot see AWS-LC's own C-level heap allocations
  at all (see caveat above) — its 1-3 MiB estimate is neither confirmed nor
  refuted by this measurement. What IS now measured: the Rust-visible slice
  of the TLS stack (`rustls` itself, plus `aws-lc-rs`'s thin FFI wrapper)
  totals under 1 MiB ever allocated and ~117 KiB retained — nowhere near
  multi-MiB. If aws-lc-rs really costs several MiB, that cost is almost
  certainly in compiled `.text`/`.rodata` code size and/or AWS-LC's own
  C-heap state, not anything a Rust allocator swap touches directly. This
  bead still needs its own planned `size`/`bloaty` binary comparison before
  any go/no-go — treat it as a disk/code-size question first, an idle-RSS
  question second.
- **beep-z6c** (second `malloc_trim`): **MEASURED, near-zero yield —
  recommend closing rather than shipping a no-op.** The dominant transient
  peak (BTF parse, 17-31 MiB) happens *before* the existing single
  `malloc_trim(0)` call, and that call already reclaims it (direct RSS
  trace above: 22,132 kB -> 7,284 kB). The *later* phase beep-z6c's bead
  targets (kubeconfig/TLS/JSON-list-parse) shows **zero** measurable RSS
  growth in a 9-second trace, and its total dhat-tracked allocator churn
  across the whole run (`rustls`+`serde_json`+`hyper`+`tokio`+`clap`
  combined) is under 1.4 MiB *ever allocated*, not simultaneously live — so
  a second trim's ceiling is well under the audit's already-conservative
  0.1-0.3 MiB estimate, likely closer to 0. The existing trim call's
  placement (right after `drop(ebpf)`) turns out to already be well-timed
  for the one peak that matters.
- **beep-ota** (release profile: LTO/strip/panic=abort/codegen-units=1):
  **unchanged verdict.** dhat is an allocation tracer; it has nothing to say
  about code-size/`.text`/`.rodata` effects one way or the other. Still a
  disk-size/attack-surface lever with low, unmeasured confidence on idle
  RSS, exactly as the audit found — this measurement neither strengthens
  nor weakens it.
- **Halving (6.8-7.7 MiB -> ~3.4 MiB), revised:** less plausible than the
  audit's own estimate suggested. There is essentially no retained or
  trim-reclaimable Rust-heap fat left (idle retained heap measures ~128
  KiB; the one large transient peak is already fully trimmed). Whatever
  remains in the fixed baseline is either AWS-LC's own C-heap state
  (unmeasured, possibly small given how little its Rust wrapper touches
  the allocator) or, more likely given how small `rustls`'s own footprint
  is, simply the fixed cost of mapping in this binary's own `.text`/
  `.rodata` across its whole dependency graph (`aya`/`aya-obj`, `tokio`,
  `hyper`, `rustls`, `aws-lc-sys`, `clap`, `serde`) plus the base Rust/glibc
  process overhead — neither of which a `malloc_trim` call or a crypto
  backend swap can touch.
