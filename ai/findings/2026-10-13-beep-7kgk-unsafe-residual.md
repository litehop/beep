# Residual unsafe audit after #216

Bead: beep-7kgk

Answer: of the 50 textual `unsafe` sites left, 9 can go at an estimated ~0 B
of eBPF object (3 in `common/`, 1 in the loader, 5 net in `ebpf/`), 2 more go
only after an aya-ebpf release that is not out yet, and the other ~39 are
inherent (raw map-value derefs, helpers with no safe wrapper, `Pod` /
`AnyBitPattern` marker impls, libc FFI); nothing is unsound, and removing the
inherent ones would cost more than the 1,616 B of headroom.

Audited 2026-10-13 against `main` @ 37ee60e. Pinned: `aya` 0.14.0,
`aya-ebpf` 0.2.1 (`Cargo.lock`). Counting method: `grep -n unsafe` over
`ebpf/src`, `common/src`, `src`, `controller` (lib.rs doc/comment hits
excluded), then read every site. Everything labelled "est." is an estimate:
no build was run (macOS host, no bpf-linker). Measured facts are limited to
source reads and the #216 figures quoted in the task (`Option<u16>` param
+432 B; `&mut [u8; N]` +480 B over that; object 129,456 / 131,072 B).

Builds on the beep-uqn audit (76 sites, 0 with SAFETY). Since then #216/#187
took the count from 76 to 50 and put a SAFETY comment on every site; the
workspace lint `undocumented_unsafe_blocks = "warn"` (`Cargo.toml:19`) now
guards regressions. Not re-derived here.

## Per-site table

Line numbers are `main` @ 37ee60e. Severity = value of acting (HIGH =
unsound/unenforced invariant; MED = removable at ~0 B or a real semantic
caveat; LOW = documented, inherent; DEFER = removal costs bytes/risk not yet
justified). There are no HIGH sites.

### `ebpf/src/main.rs`

| Site | Why unsafe | Safe alternative (0.2.1 / newer) | Est. size cost | Verifier risk | Rec. | Sev. |
|---|---|---|---|---|---|---|
| 385, 391, 397 `flow_table_get_*` | deref of the `get_ptr` map-value pointer, then read of one union arm | `LruHashMap::get` is `unsafe` in 0.2.1 and on aya `main` (`maps/hash_map.rs`); `get_ptr` returns a raw pointer in both. No safe copy-out exists. | n/a | none | keep-inherent | LOW |
| 403, 409, 415, 421 `front_meta_get` / `front_endpoints_get` / `fwd_pending_get` / `uplink_config_get` | deref of `get_ptr` pointer (plain `Copy` struct) | same as above | n/a | none | keep-inherent | LOW |
| 444 `count_front_miss` `*misses += 1` | write through `get_ptr_mut` on a `PerCpuArray` slot | `PerCpuArray::get` is safe (`maps/per_cpu_array.rs:24`); `get(0).copied()` then `set(0, &v+1, 0)` is fully safe | est. +80-150 B (extra `bpf_map_update_elem` call) | low | defer | DEFER |
| 524 `(*skb).pkt_type`; 969 `ingress_ifindex`; 1921 `mark`; 1936 `ifindex` | raw deref of the `__sk_buff` context pointer | no reader in 0.2.1 or on main (`sk_buff.rs`/`tc.rs` expose only `set_mark`, `len`, `cb`, `protocol`/`family` for sock-ops variants) | one `#[inline(always)] fn skb_ctx(ctx) -> &__sk_buff` collapses 4 sites to 1: est. 0 B (same ctx-offset loads) | low: ctx field loads, not packet pointers; keep the reference short-lived so no load spans a `change_head` | remove (consolidate 4 to 1) | MED |
| 556, 595 `&mut *raw.as_mut_ptr()` (uninit `[u8; N]`) | forms `&mut [u8]` over uninitialised bytes; correct only because every byte is written before it is read | `[0u8; N]`: the doc comment at 532-547 records that the zero-fill is a `memset` subprogram that blows the 160 B remaining stack frame | est. +stack/frame risk, not bytes | low | defer; language-level soundness of `&mut` to uninit `u8` is unsettled, the practical hazard is nil | DEFER (MED-adjacent) |
| 637 `&mut *bucket` | `&mut` from `get_ptr_mut` of a per-CPU slot | `PerCpuArray::get` + `set` (safe) | est. +100-150 B | low | defer | DEFER |
| 639 `bpf_ktime_get_ns` | helper bindings are `unsafe fn`; no safe wrapper (0.2.1 `helpers.rs` has safe wrappers only for comm/pid/uid) | none on main either | n/a | none | keep-inherent | LOW |
| 659 `bpf_csum_diff` | raw pointer + length | none | n/a | none | keep-inherent | LOW |
| 676 `bpf_skb_load_bytes` in `load_into` | raw dst pointer | `TcContext::load_bytes` is safe but clamps to a short packet (`sk_buff.rs:86`: `len.min(dst.len())`), which `load_into` deliberately avoids | n/a | none | keep-inherent | LOW |
| 691 `bpf_skb_change_tail` | helper with `*mut __sk_buff` | main only (#1617, merged 2026-10-06, unreleased): safe `TcContext::change_tail` | ~0 B (est.) | low | defer until release | DEFER |
| 698 `bpf_skb_store_bytes` in `put` | raw src pointer, runtime length | `TcContext::store<T>` is safe but needs a const-sized `&T`; `put` takes a runtime slice, and `send_reply` is `inline(always)` x4, so a const-generic version monomorphises 4 copies (#216: `&mut [u8; N]` +480 B) | est. +0.4-1 KiB | low | defer | DEFER |
| 764 `read_unaligned` in `load_direct` | raw packet read | see assessment (b) | n/a | high (see (b)) | keep-inherent | LOW |
| 771 `unsafe trait AnyBitPattern`, 777 (macro, 3 impls), 784 (`[u8; N]`) | marker trait asserting "every bit pattern valid" | none (`aya::Pod` is not in the eBPF dependency graph; `bytemuck` would be a new dependency) | 0 B | none | keep-inherent | LOW |
| 833, 904 `mem::zeroed::<bpf_tunnel_key>()` | zero-init of a bindgen struct | `bpf_tunnel_key` is 44 B with no padding (4+16+1+1+2+4+16) and unions are safely constructible, so a struct literal (`tunnel_id: 0, __bindgen_anon_1: ..{ remote_ipv6: [0;4] }, ...`) is fully safe | est. 0 B (same 44 B of zero stores) | low | remove (one `fn new_tunnel_key()`) | MED |
| 837, 841 `bpf_skb_get_tunnel_key` | raw `*mut bpf_tunnel_key` | none in 0.2.1 or main | n/a | none | keep-inherent | LOW |
| 858 `tunnel_remote` union reads | reading a union field | none; reading a union arm is always `unsafe`. Both arms are plain ints, already host-tested via `tunnel_remote_addr` | 0 B | none | keep-inherent | LOW |
| 910 `bpf_skb_set_tunnel_key`, 924 `bpf_skb_set_tunnel_opt` | raw pointers | none | n/a | none | keep-inherent | LOW |
| 933 `bpf_skb_change_head` | helper with `*mut __sk_buff` | main only (#1617, unreleased): `TcContext::change_head` | ~0 B (est.) | medium: invalidates packet pointers; `redirect_to_geneve` doc records the post-call ordering | defer until release | DEFER |
| 946 `bpf_redirect`; 1704 `bpf_redirect_neigh`; 1707 `bpf_redirect` | helper bindings | none (`TcContext` has `clone_redirect` only, which is not a redirect verdict) | n/a | none | keep-inherent | LOW |
| 1259, 1666 `bpf_skb_get_tunnel_opt` | raw dst pointer (20 B / 24 B arrays) | none; a local `get_tunnel_opt<const N>` wrapper would dedupe 2 to 1 | est. +-200 B (#216 showed array-by-reference signatures swing 0.5-1.6 KiB) | low | defer | DEFER |

### `common/`

| Site | Why unsafe | Safe alternative | Est. size cost | Verifier risk | Rec. | Sev. |
|---|---|---|---|---|---|---|
| `common/src/reject.rs:189` `write_volatile` in `zero` | volatile write defeats LLVM fusing the run into a `memset` call (not for aliasing reasons) | none in safe Rust that guarantees the same codegen. `*black_box(&mut buf[i]) = 0` is safe and may work, but is best-effort | n/a | low | keep-inherent | LOW |
| `common/src/lib.rs:433` `FlowValue::zeroed` | `mem::zeroed` of a union | construct the largest arm in a literal: `ForwardFlowValue` is 36 B, padding-free (asserted by `impl_pod!`), so `FlowValue { forward: ForwardFlowValue { backend: LbFrontBackend { backend_node_ip: [0;16], pod_ip: [0;16] }, ingress_ifindex: 0 } }` zeroes all 36 B; assigning another arm afterwards is safe | est. 0 B | none | remove | MED |
| `common/src/lib.rs:514` (struct arm), `:525` (union arm) `unsafe impl aya::Pod` in `impl_pod!` (11 + 1 expansions) | `Pod` is an `unsafe trait` | none; see assessment (c) | 0 B | none | keep-inherent | LOW |
| `common/src/lib.rs:604` `as_forward` | union arm read | see assessment (a); one caller path in the loader (`src/lib.rs:309, 355`) | 0 B (user feature only) | none | keep-inherent | LOW |
| `common/src/lib.rs:610` `as_reverse`, `:616` `as_port_memo` | union arm reads | **no callers anywhere** (`grep as_reverse() / as_port_memo()` over `src controller ebpf common` finds none; only `as_forward` is used). Dead code | 0 B | none | remove | MED |
| `common/src/lib.rs:1392` `transmute_copy`, `:1428`, `:1430` | test-only union reads / byte view | `as_*` would work but sit behind the non-default `user` feature, and `cargo test -p beep-common` does not enable it | 0 B | none | keep-inherent (test code) | LOW |

### `src/`, `controller/`

| Site | Why unsafe | Safe alternative | Est. size cost | Verifier risk | Rec. | Sev. |
|---|---|---|---|---|---|---|
| `src/lib.rs:396` `libc::setrlimit(RLIMIT_MEMLOCK)` | FFI | `bump_memlock_rlimit` exists only for kernels older than 5.11 (its own doc). No safe std/aya API (aya 0.14 does not bump it). Deleting the function (callers `src/main.rs:459`, `controller/src/main.rs:529`) removes the site; needs an operator decision on a kernel floor (smoke runs on 6.8/6.17) | none | none | remove if kernel floor >= 5.11 is accepted, else keep-inherent | MED |
| `src/main.rs:540`, `controller/src/main.rs:616` `libc::malloc_trim(0)` | FFI, glibc-only, no pointers | none safe; the call exists to hold steady-state RSS (memory-smoke gate). A shared helper needs a home crate (`beep-common` is `no_std`) | none | none | keep-inherent | LOW |

### Counts

50 textual sites: ebpf 37, common 10 (lib.rs 9 + reject.rs 1), loader 2,
controller 1 (macro-expanded impls counted once). By severity: HIGH 0,
MED 10 (skb field reads x4, tunnel-key zero x2, `FlowValue::zeroed`, dead
`as_reverse`/`as_port_memo` x2, `setrlimit`), DEFER 9 (444, 556, 595, 637,
691, 698, 933, 1259, 1666), LOW 31. Of the 10 MED, 9 net removals (the 4 skb
reads collapse to 1 accessor).

## Specific assessments

### (a) FlowValue as a union vs a tagged layout

Sizes (read from `common/src/lib.rs`, asserted by `impl_pod!`):
`ForwardFlowValue` 36 B, `RevFlowValue` 36 B, `PortMemoValue` 2 B, union 36 B.
`FlowKey` is 38 B (37 + direction tag, `lib.rs:140`). `FLOW_TABLE` is an LRU
hash of 16,384 entries (`ebpf/src/main.rs:368`).

- Memory: the kernel pads key and value to 8 B, so each entry carries
  40 B key + 40 B value = 80 B payload; 16,384 entries is about 1.25 MiB of
  key+value payload (est.; the kernel's per-element header, LRU node and
  per-CPU free lists add to this, not measured). A tagged layout does not
  shrink it: the map value must still hold the larger arms, so
  `max(36, 36, 2)` stays. A 1-byte tag makes 37 B, rounded to 40 B, i.e. the
  same bytes the union uses today. The tag is also redundant with the
  direction byte already in the key.
- Per-packet code: a tag adds a compare per read (est. 2-3 insns, ~16-24 B)
  at about a dozen reader sites, est. +200-300 B, buying a check that the
  key's direction tag already provides.
- Can the readers be safe without a layout change? In eBPF, no: the dominant
  `unsafe` at 385/391/397 is the deref of the map-value pointer (`get_ptr` is
  raw, `get` is `unsafe` on both released and main aya). Even a byte-array
  value would still be read through that pointer. The union read itself is a
  small share of the risk, and all arms are padding-free plain integers (so
  any bytes are a valid value of any arm; a wrong arm gives wrong data, not
  UB). On the user side the three `as_*` readers could be made safe by
  reading the map as `[u8; 36]` and decoding with `from_ne_bytes`, at the
  price of hand-written decode code and a duplicated layout; since only
  `as_forward` has a caller, the cheaper move is to delete the other two
  (table above) and keep one audited reader.
- Splitting `PortMemo` into its own map would shrink its rows to 8 B but
  reverses the unified-`FLOW_TABLE` decision (`bd memories
  beep-s-conntrack-maps-are-unified...`) and adds a map to the CI map-count
  gate. Not recommended.
- Recommendation: keep the union.

One caveat on the SAFETY text at `ebpf/src/main.rs:382-384`: it says a
concurrent update "can only make the copy stale". An in-place update of an
existing map element by another CPU can also yield a torn 36-byte copy. I did
not verify whether any writer rewrites an existing key with different
content; if none does, the claim holds in practice. Worth a wording fix when
next touched, not a code change.

### (b) `load_direct` vs `ctx.load()` / bounds-checked access

`load_direct` (`ebpf/src/main.rs:755`) is the only direct packet access: a
`data_end` bounds check then `read_unaligned`, used at ~30 call sites in the
uplink hooks (grep count 36 including doc/comment mentions). `ctx.load::<T>`
is a `bpf_skb_load_bytes` helper call per field.

- Size: per site, the direct form is a compare + one load (est. ~3-4 insns,
  ~24-32 B); the helper form sets up 4 arguments, a stack slot, the call, a
  result check and a stack reload (est. ~8-10 insns, ~64-80 B). About +40-50 B
  x ~30 sites is an est. +1.2-1.5 KiB: essentially all remaining headroom.
- Per-packet: these hooks see every uplink packet, so a helper call per field
  is paid on non-beep traffic too; the doc comment at 729-753 gives that as
  the reason `load_direct` exists.
- Verifier: the helper form is the verifier-safe one (no packet-pointer
  arithmetic). The direct form requires a compile-time nonzero offset
  (`bd memories ebpf-verifier-gotcha`; the doc comment records live-6.8
  rejections), which is why the hooks dispatch on a const generic.
- Safe alternatives that stay direct: none. `ctx.data()` / `ctx.data_end()`
  return `usize`; turning them into a reference needs `unsafe`. The trait
  bound added by #216 already makes the read sound given the bounds check.
  Possible shrink (defer): keep only the `[u8; N]` impl and decode with
  `from_ne_bytes`, dropping 3 trait impls; risk est. MED because LLVM's BPF
  backend may not merge byte loads into a `u16`/`u32` load, growing code.
- Recommendation: keep-inherent.

### (c) Are the `impl_pod!` Pod impls irreducible?

Yes on this aya. `aya::Pod` is an `unsafe trait` with no derive and no
blanket impl for user structs in 0.14.0 (and none on aya `main`; the maps
bound `V: Pod`). What #216 already achieved is the strongest available shape:
one `unsafe impl` per macro arm with the no-padding property proven at compile
time by `const _: () = assert!(size_of::<T>() == sum of fields)`. The only
way to cut the sites further is a derive from a new crate (`bytemuck` /
`zerocopy`), which the dependency stance rules out, and those would still
need a `Pod` bridge. Declare keep-inherent. (The macro has 2 textual sites,
11 expansions.)

### (d) Would an aya / aya-ebpf bump remove unsafe?

Recommendation only; nothing was bumped. Pinned versions are the latest
releases (aya 0.14.0 2026-06-24; aya-ebpf 0.2.1 2026-06-30, per
`gh api repos/aya-rs/aya/releases`). `main` (commit f63a6b2e, 2026-10-12) is
still version 0.2.1 but contains #1617 (merged 2026-10-06): safe
`SkBuff`/`TcContext::change_head` and `change_tail`. That would remove
`ebpf/src/main.rs:691` and `:933`. It is a pre-release, and the same
`sk_buff.rs` changes the struct to `skb: NonNull<__sk_buff>` (private),
which breaks every `ctx.skb.skb` use (about 14 sites), and `HashMap::get`
etc. now take `&K` rather than `impl Borrow<K>`. Net: -2 unsafe for one
churn-heavy bump with an unmeasured size swing. Wait for a tagged
aya-ebpf release, then bump once, measure, and take the two removals
together. Nothing on `main` adds safe tunnel-key/opt, redirect, `ktime`, or
skb-field-reader wrappers.

## Ranked recommendation

Ranked by safety gain per byte (all est., 0 B unless noted):

1. Delete `FlowValue::as_reverse` and `as_port_memo`
   (`common/src/lib.rs:608-617`): -2 sites, dead code, no eBPF effect.
2. `FlowValue::zeroed` (`common/src/lib.rs:430`) as a safe struct literal:
   -1 site, no eBPF effect (the object bytes it produces are the same
   zero stores).
3. Safe `bpf_tunnel_key` constructor replacing the two `mem::zeroed` calls
   (`ebpf/src/main.rs:833, 904`): -2 sites, est. 0 B, needs `scripts/smoke.sh`
   and a size check.
4. Consolidate the four `__sk_buff` field reads (524, 969, 1921, 1936) behind
   one `#[inline(always)]` accessor: -3 sites, est. 0 B; keep the reference
   short-lived.
5. Delete `bump_memlock_rlimit` (`src/lib.rs:389`) if a kernel floor of 5.11
   is acceptable: -1 site, a small binary shrink. Operator call.

Together: -9 sites (50 to 41) at about 0 B of object. With the future aya-ebpf
release: -2 more. Everything else (map-value pointer derefs 385-421, helpers
without wrappers, `load_direct`, `AnyBitPattern`, `Pod`, `malloc_trim`,
`write_volatile`, the union reads, test code) should be declared
**keep-inherent**; the DEFER rows (444, 556/595, 637, 698, 1259/1666) cost an
est. +80 B to +1 KiB each for one `unsafe` apiece and should not be pursued
unless the headroom grows.

## Surprising / worth the operator's attention

- Two of the three `FlowValue` readers are dead code.
- The union is not the main hazard: the raw map-value deref is, and it is
  irreducible on every released and unreleased aya.
- aya `main` already has the safe `change_head`/`change_tail`, but taking it
  means a breaking `SkBuff` change for this crate.
- No HIGH site; the only semantic caveat is the "can only make the copy
  stale" SAFETY wording (possible torn read), unverified against the writers.
