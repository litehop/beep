# beep-kw33: bpf_dynptr_slice spike + object size breakdown

Bead: beep-kw33
Date: 2026-10-13
Spike branch (not for merge): `spike/beep-kw33-dynptr` (2 commits: dynptr parse, build.rs BTF trim)

**Answer:** dynptr is not adoptable today -- the kfunc calls compile and the verifier accepts runtime-offset slices, but neither aya 0.14.0 nor the Rust-to-bpf-linker path can load a kfunc call, while ~49 KB (38%) of the 129 KB object is `.rel.BTF.ext` + `.BTF.ext` line info that a build.rs strip removes with the full smoke still passing.

## 1. Size breakdown (measured tree: main a7dd38a, PR #221 not merged)

Gated object `OUT_DIR/beep-ebpf` after build.rs's `--strip-debug`: **129,456 B** (ceiling 131,072; CI measures it at `.github/workflows/ci.yaml:283` via `scripts/assert-ebpf-object-stripped.sh`). Built on aarch64 (`cargo +nightly zigbuild`); CI builds x86_64 hosts, so expect +-100 B (#221's 129,352 is the same tree minus its change).

| Section | Bytes | % |
|---|---|---|
| `classifier` (3 hooks) | 50,392 | 38.9 |
| `.rel.BTF.ext` | 24,336 | 18.8 |
| `.BTF.ext` | 24,344 | 18.8 |
| `.BTF` | 17,539 | 13.5 |
| `.text` (reject_tcp/udp, memcpy/set/move) | 9,376 | 7.2 |
| `.relclassifier` + `.rel.text` + `.rel.BTF` + symtab/strtab/maps/license + ELF headers | ~3.5K | 2.7 |

Per function (llvm-nm -S): `geneve_ingress` 28,976; `uplink_egress_return` 12,000; `uplink_ingress` 9,416; `reject_tcp` 5,328; `reject_udp` 3,696; mem* 352. Everything else is `#[inline(always)]` into those, so per-function attribution needs DWARF line tables (unstripped object, `llvm-objdump -d -l`, aggregated by source line; leaf attribution, so helper cost shows under `aya-ebpf-bindings`/`beep-common`/`core::ptr` rather than the caller). Largest leaf buckets in `geneve_ingress`: aya-ebpf-bindings 4,512; beep-common 3,696; aya-ebpf 3,352; `try_geneve_decap_forward_v6` 2,984; `flow_table_get_reverse` 2,752. Sum of attributed insns = 59,768 B = classifier + .text, so nothing was dropped.

**v4/v6 duplication** (experiment: stub every family arm to `None` at the 6 dispatch sites, rebuild):

| Variant | Object | Delta vs 129,456 |
|---|---|---|
| v6 arms stubbed (v4 only) | 85,920 | -43,536 (v6 = 33.6%) |
| v4 arms stubbed (v6 only) | 101,664 | -27,792 (v4 = 21.5%) |

The two are not additive (shared tail code). v6 is the larger family because of 16-byte keys/rewrites. Directly-attributed `_v4`/`_v6` function bodies are only ~7.2 KB; the rest of the per-family cost is inlined map/key/rewrite code that dynptr cannot merge.

`uplink_ingress` and `uplink_egress_return` also instantiate every parse body twice more through the `<L2_HLEN>` const generic (0 and 14): 4 parse bodies per hook.

## 2. Feasibility: kfuncs from Rust

- `aya-ebpf-bindings 0.2.0` has the `bpf_dynptr_from_mem/read/write/data` helpers but not `bpf_dynptr_from_skb` / `bpf_dynptr_slice`; those are kfuncs (`bpftool btf dump /sys/kernel/btf/vmlinux` on beep-smoke, kernel 6.8.0-146: `FUNC 'bpf_dynptr_slice'`, `FUNC 'bpf_dynptr_from_skb'` present).
- **Compile/link: works.** `unsafe extern "C" { fn bpf_dynptr_from_skb(..); fn bpf_dynptr_slice(..); }` builds, bpf-linker emits `R_BPF_64_32` relocs against UND symbols `bpf_dynptr_from_skb`/`bpf_dynptr_slice` (4 call sites).
- **BTF: missing.** The object's BTF has no extern `FUNC` entries and no `.ksyms` DATASEC (`bpftool btf dump file`). Rust cannot attach `link_section = ".ksyms"` to an extern fn (aya-rs/aya#432 shows the same). Also tried a C trampoline compiled to bitcode (`clang -g -target bpf -emit-llvm`, passed via `cargo:rustc-link-arg-bins`): it links and inlines, but the installed bpf-linker still drops the extern FUNC BTF, even for a pure-C bitcode through `bpf-linker --btf`. The fix (aya-rs/bpf-linker#317, "Don't internalize extern definitions and add proper section info for ksyms") merged 2026-09-17, after the latest release v0.11.1 (2026-09-07); building it needs LLVM 23 (`llvm-config` not available here), so this was not verified.
- **Loader: not in the pinned aya.** Loading the spike object with aya 0.14.0: `smoke.sh` exit 1, `error relocating uplink_ingress: function 0xa080 not found while relocating` (0xa080 = the first kfunc call offset). aya-rs/aya#1372 ("Support loading programs with ksyms") merged 2026-07-09, after aya 0.14.0 (2026-06-24); it is BTF-driven (needs the extern FUNC + `.ksyms` DATASEC above) and its tests use C programs only. A git-dependency on aya main plus an unreleased bpf-linker would be required, with no known-good Rust example.
- `bpftool gen object` (libbpf static link) of the Rust object with a C stub declaring the kfuncs fails: `failed to find BTF info for global/extern symbol 'bpf_dynptr_from_skb'`.

## 3. Measurements

**Spike on `uplink_ingress` only** (4 const-generic v4/v6 x L2 parse bodies replaced by one runtime-offset dynptr body: 1-byte slice for the version nibble, then a 24-byte (v4) or 44-byte (v6) slice at runtime `l2_hlen`; 4 `*_v4/_v6` helpers become dead):

| | main | spike | delta |
|---|---|---|---|
| gated object | 129,456 | 127,048 | -2,408 (-1.9%) |
| `classifier` section | 50,392 | 48,656 | -1,736 |
| `unsafe` tokens in `ebpf/src/main.rs` | 39 | 46 | +7 |

The `unsafe` increase is the extern block, the dynptr init, two kfunc calls and three raw reads; a typed safe wrapper around slice-and-read would collapse that to 2-3 sites (not done). The spike object does not load, so verifier acceptance of the real program and a smoke pass are NOT measured. The size win is the only measured property of the Rust spike.

**Verifier acceptance of the technique** (separate C program built with clang `-target bpf`, which does emit kfunc BTF; `bpftool prog load` on beep-smoke, kernel 6.8): one program with runtime `l2 = skb->mark` (0 or 14, unknown to the verifier), v4 and v6 parsed through `bpf_dynptr_slice(&dp, l2, buf, N)`, accepted: `processed 103 insns`, 10 states. So the runtime-offset path that `load_direct`'s literal-offset rule forbids is verifier-legal through dynptr. Does it really replace the `_v4`/`_v6` pair? Only the header parse: the version nibble still branches to two field layouts, and the downstream address/checksum/rewrite code stays per family.

**Per-packet cost** (`bpftool prog run repeat 2000000`, one v4 TCP packet, same parse, 3 runs): dynptr ~9 ns vs direct `data/data_end` ~5-6 ns, ~+3-4 ns per packet; single-family C xlated 352 B (dynptr) vs 160 B (direct). Hot-cache TEST_RUN only, not a throughput claim.

## 4. Non-dynptr experiments (also measured)

Both applied to the baseline in `build.rs`'s post-link objcopy step (spike branch commit 2), full `scripts/smoke.sh --vm beep-smoke` run each time, no FAIL lines, exit 0:

| Change | Object | Delta |
|---|---|---|
| `--remove-section=.rel.BTF.ext --remove-section=.rel.BTF` | 104,808 | -24,648 |
| plus rewrite `.BTF.ext` without `line_info` (24,228 of its 24,340 B; func_info kept) | 80,576 | -48,880 total (-37.8%) |

`scripts/assert-ebpf-object-stripped.sh` still passes in spirit (`.BTF` and `.BTF.ext` both present) but would need its comment/ceiling reviewed. Cost: no source-line annotation in verifier logs / `bpftool prog dump xlated linum`.

## 5. Recommendation for beep-dz73

1. **Do not adopt dynptr now.** Three independent blockers (no kfunc BTF from rustc/bpf-linker release, aya 0.14.0 loader, no maintained Rust precedent), a bounded payoff (-2.4 KB for one hook, ~-4..6 KB if applied to the egress hook and the other ingress parses, still +unsafe, +3-4 ns/pkt), and the family-specific rewrite code (the bulk of the v4/v6 cost) is untouched. Revisit when bpf-linker with #317 and an aya release with #1372 are out; then re-run this spike (the branch has the code and the C trampoline).
2. **Largest wins, no new dependencies** (bytes measured unless marked est.):
   - drop `.rel.BTF.ext` + `.rel.BTF` in build.rs: -24.6 KB (verified with smoke);
   - drop `.BTF.ext` `line_info`: -24.2 KB (verified with smoke);
   - prune the `.BTF` string table: its strings are 15,327 of 17,539 B, mostly source-line text and paths referenced only by line_info; after the previous item most are dead. est. -10..12 KB, needs a BTF rewriter (not tried);
   - L3-only (`L2_HLEN == 0`) uplinks through `ctx.load` runtime offsets instead of a second const-generic instantiation of the ingress/egress parse: est. -2..3 KB, removes 2 of 4 parse bodies per hook; costs helper calls only on WireGuard-style uplinks.
3. If more headroom is still needed after (2), the real lever is v6 (43.5 KB): sharing key construction/rewrite across families, not parsing.
