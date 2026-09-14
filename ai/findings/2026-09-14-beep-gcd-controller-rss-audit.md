# beep-controller idle RSS: attribution and halving assessment

Bead: beep-gcd

**Verdict: partial.** The single verified, actionable lever — swapping
rustls's crypto provider off `aws-lc-rs` (a statically-linked C crypto
library, AWS-LC, pulled in by rustls 0.23's default features) — is an
estimated 1-3 MiB of the ~6.8 MiB baseline, the largest candidate found.
Two levers the dispatch brief flagged as open (tokio runtime flavor, a
retained aya/eBPF object) are **already optimized** in the current code —
no savings available there. Reaching a full ~50% cut (down to ~3.4 MiB) is
plausible only if the aws-lc-rs estimate is at the high end of my range;
none of these numbers are measured, all need a live Linux profile
(`size`/`pmap`/heaptrack) to confirm before treating "halved" as achieved.

## Measured baseline (for context, not reproduced here)

Per PR #57 (beep-toi), built from source and run against a real single-node
k3s apiserver on `beep-node-a` (Lima, aarch64):
- Idle, after initial LIST+watch settle: **6948 kB (~6.8 MiB)**
- After reconciling 6 Services + 5 backend Pods: **7004 kB**, a 56 kB delta

The 56 kB delta means dynamic reconcile state (`WatchState`'s
`HashMap<ServiceKey, RawService>` etc., `PinnedMaps`' aya map handles) is
not where the mass is — confirmed by reading `controller/src/{watch,apply}.rs`:
`WatchState` stores small typed structs (`RawService`, `RawEndpointSlice`),
never raw `serde_json::Value` objects long-term, and `PinnedMaps` holds only
three `aya::maps::HashMap` fd-backed handles. This audit is aimed entirely
at the fixed baseline per the dispatch brief, not this 56 kB.

## Top levers (estimated MiB, risk, effort)

1. **`rustls` crypto provider: `aws-lc-rs` -> `ring` (or trim further).**
   Est. **1-3 MiB**, MEDIUM-LOW confidence (no Linux build available to
   measure). `kubeconfig/Cargo.toml`'s `rustls = "0.23"` takes rustls's
   default features, which select `aws-lc-rs` as the crypto provider —
   confirmed via `cargo tree -p beep-controller`: `aws-lc-sys` compiles
   the full AWS-LC C library (a BoringSSL/OpenSSL-derived codebase with
   RSA/EC/hash/HMAC/ML-KEM) via `cc`+`cmake`, not a pure-Rust minimal
   backend. `ring` (rustls's lighter alternative, pure Rust, deliberately
   small) is present in `Cargo.lock` but only as a **dev-dependency of
   `rcgen`** (test cert generation, confirmed via `cargo tree --workspace
   -i ring`) — it never ships in the release binary today. AWS-LC's
   compiled code and its own heap-managed TLS/RNG/session state are the
   most plausible single largest contributor to the fixed baseline given
   the size gap between AWS-LC and `ring` is well known in the Rust
   ecosystem.
   **Risk:** `rustls-post-quantum`'s ML-KEM-768 hybrid key exchange is
   implemented via `aws-lc-rs`, not `ring` — dropping `aws-lc-rs` means
   dropping post-quantum TLS to the apiserver entirely. That is a
   security-posture decision, not a free swap; needs explicit sign-off.
   **Effort:** medium (feature-flag swap + drop `rustls-post-quantum` +
   retest the real mTLS handshake against a live apiserver).

2. **A second `malloc_trim(0)` call after initial watch bootstrap.**
   Est. **0.1-0.3 MiB**, LOW confidence, but essentially free and safe.
   `controller/src/main.rs:264-267` calls `malloc_trim(0)` once, right
   after `drop(ebpf)` — before `parse_kubeconfig`, `build_tls_connector`,
   and the three initial LIST responses are parsed. Any transient peak
   from that later phase (JSON list-body parsing, DER/cert parsing,
   AWS-LC init buffers) is never handed back to the OS: glibc's malloc
   only releases heap memory to the OS via an explicit trim or when a
   freed chunk sits at the top of the heap above the trim threshold —
   neither is guaranteed here. The PR #57 "idle baseline" measurement was
   taken *after* this untrimmed phase, so this cost may already be baked
   into the reported 6948 kB.
   **Risk:** none — same call already used elsewhere in this file, only
   gated `#[cfg(target_env = "gnu")]` (matches the existing pattern for
   musl skip).
   **Effort:** trivial (one more call site, after
   `on_nodes_listed`/watch-bootstrap settles).

3. **Release profile: LTO + strip + `panic = "abort"` + `codegen-units = 1`.**
   Est. **0.1-0.5 MiB**, LOW confidence — mostly a disk-size/attack-surface
   win, not an idle-RSS one. The root `Cargo.toml` only overrides the
   *ebpf-target* build profile (`[profile.release.package.beep-ebpf]`);
   the host `beep-controller` binary (built by CI's `cargo +nightly
   zigbuild --release`, per `.github/workflows/delivery.yaml`) uses
   Cargo's default release profile: no LTO, `codegen-units = 16`,
   `panic = "unwind"`, unstripped. `panic = "abort"` drops unwind tables;
   LTO does cross-crate dead-code elimination, which could reduce the
   number of AWS-LC/hyper/tokio code paths that get touched (and thus
   paged into RSS) over the process's lifetime — but for a long-idle
   daemon whose hot paths (3 persistent watch connections + occasional
   status PATCH) are fixed and small, most savings here land on-disk
   rather than in resident pages.
   **Risk:** low — verify no code relies on `catch_unwind` before setting
   `panic = "abort"` (a quick grep found none in `controller/`/`kubeconfig/`,
   but re-check at implementation time).
   **Effort:** low (a `[profile.release]` block + CI verification).

## Per-contributor attribution (best estimate against ~6.8 MiB; ALL of this section is ESTIMATED, not measured)

| Contributor | Est. share | Confidence | Notes |
|---|---|---|---|
| `rustls` + `aws-lc-rs` (TLS 1.3, PQ hybrid KEX, cert verify) | 2-4 MiB | LOW-MEDIUM | Largest candidate; C library, not pure Rust. Lever #1. |
| Base Rust/glibc process (dynamic linker, libc, std runtime, clap arg parsing) | ~1-1.5 MiB | LOW | Fixed cost of any Rust async binary; no lever identified. |
| tokio runtime (current_thread; `rt`,`macros`,`time` only) + mio/socket2 reactor | ~0.3-0.5 MiB | MEDIUM | **Already minimal** — `main.rs:208`'s `#[tokio::main(flavor = "current_thread")]` and the trimmed feature list are already the efficient choice; the brief's "is multi-thread even needed" question is already answered no in the code, with a comment explaining why. No further savings. |
| hyper (HTTP/1.1 client, 3 persistent watch connections + periodic status PATCH) + http-body-util/bytes | ~0.3-0.5 MiB | LOW-MEDIUM | No kube-rs anywhere in this dependency graph — `controller`/`kubeconfig` hand-roll a minimal hyper+JSON-Lines watch client (`kubeconfig/src/lib.rs`'s `HyperApiClient`), not a reflector/informer cache. This is already the lean design the brief worried kube-rs might not be. |
| serde_json (event/list-body parsing, transient `Value`, typed `Raw*` structs) | ~0.2-0.4 MiB | LOW | Retained state is the 56 kB delta; this line is code + transient parse buffers, not a cache. |
| Retained `aya`/eBPF object post-attach | ~0 MiB | HIGH (verified in code) | `main.rs:261`'s `drop(ebpf)` confirms aie31.16's claim: the parsed `Ebpf` handle **is** dropped after all three hooks attach and pin; the dataplane survives via pinned links/maps alone. `malloc_trim(0)` immediately follows specifically to reclaim this. Lever is already taken — the brief's "verify" item resolves to "already done," not "found a bug." |
| glibc malloc/arena overhead | ~0.1-0.3 MiB | LOW | Single OS thread (current_thread executor; `tokio::spawn`ed tasks run in-thread, not a new OS thread), so glibc's multi-arena-per-thread growth doesn't apply here — that part of the brief's concern doesn't materialize. The real gap is the *timing* of the one existing `malloc_trim` call (lever #2), not arena count. |
| Build/link flags (opt-level=3 default, no LTO, unstripped, panic=unwind) | ~0.1-0.5 MiB RSS (larger on disk) | LOW | Lever #3; mostly disk/pull-time, secondary RSS effect from fewer paged-in pages. |
| **Total (estimated)** | **~4.0-7.7 MiB** | — | Brackets the measured 6.8 MiB; wide range reflects estimate-only method. |

## What needs a live Linux profile to confirm

Everything in the attribution table above is reasoned from `Cargo.lock`/
`cargo tree`/source reading, not measured — no Lima VM was available (all
held by an in-flight e2e run) and this binary is Linux-only (aya + real
`bpf(2)`/netlink syscalls), so nothing here could be built or profiled on
this macOS host. Specifically unconfirmed:
- The actual MiB delta between `aws-lc-rs` and `ring` for this exact
  dependency set (`size`/`bloaty` on both binary variants).
- Whether AWS-LC's own heap allocations (RNG/session/PQ-KEM state) show up
  as resident heap RSS at idle, vs. purely `.text`/`.rodata` page-ins.
- The actual size of the pre-watch-setup allocation peak lever #2 targets
  (would need `pmap`/`/proc/<pid>/smaps` snapshots before and after the
  first `malloc_trim(0)` call, and again after a hypothetical second one).
- Whether lever #3's build-flag changes move idle RSS at all, versus only
  on-disk/image-pull size.

A follow-on bead recommends running heaptrack or `/proc/<pid>/smaps_rollup`
diffs on a freed Linux node once the e2e run releases the Lima VMs.
