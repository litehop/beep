# Kernel floor research

Bead: beep-zmzp
Date: 2026-10-13 (UTC, `date -u` at 09:57Z)

**Answer: set the documented floor to 6.6 LTS-or-newer (in practice 6.12 LTS), not 5.11 and not 7.0, because beep already hard-requires 6.6 (TCX attach) and nothing in 6.7-7.x unlocks a feature that aya can use today without raw unsafe bindings.**

The 131,072 B "cap" is a CI script constant, not a kernel limit, and no kernel version relaxes it.

## 0. Surprise: the real floor is already 6.6, not 5.11

- `src/lib.rs:911-946` (`attach_and_pin`) always attaches with `TcAttachOptions::TcxOrder(LinkOrder::default())` via `bpf_link_create`. There is no netlink/clsact fallback in beep (the comment at `src/lib.rs:911-914` says so, and `README.md:88` documents "attached as a TCX link").
- aya 0.14.0 docs (`aya-0.14.0/src/programs/tc.rs:130-132`): "Kernels older than 6.6.0 must utilize netlink for attachments, while newer kernels can utilize the modern TCX eBPF link type". Only `attach()` auto-falls-back (tc.rs:220-221); `attach_with_options(TcxOrder)` does not.
- So on 5.11-6.5 beep fails at attach. The "5.11 floor" that beep-vofi documents (derived from memcg accounting, `src/lib.rs:388`) is not the binding constraint. There is also no `src/netlink.rs` in the tree (the bead text assumed one); netlink/clsact code does not exist, so TCX "simplifies" nothing further.
- Verified-in-repo kernels: `ebpf/src/main.rs:742` ("confirmed against a live 6.8 kernel"), `docs/design/cni-svclb-landscape.md:56` ("Lima VM (kernel 6.17)").
- Recommendation for beep-vofi's doc line: state 6.6, with the reason.

## 1. Hard constraints (with sources)

### CI runner (`memory-smoke` runs natively on `ubuntu-latest`, `.github/workflows/ci.yaml:232-233`; every job uses `ubuntu-latest`)

| Runner | Kernel | Source |
|---|---|---|
| `ubuntu-latest` today (Ubuntu 24.04.5, image 20261004.327.1) | **6.17.0-1022-azure** | `actions/runner-images` `images/ubuntu/Ubuntu2404-Readme.md` (fetched 2026-10-13) |
| Ubuntu 26.04 image (`ubuntu-26.04`, GA) | **7.0.0-1012-azure** | `images/ubuntu/Ubuntu2604-Readme.md`: "OS Version: 26.04.1 LTS, Kernel Version: 7.0.0-1012-azure" |
| `ubuntu-latest` after migration | 26.04 / 7.0.0-azure | runner-images issue #14748 (opened 2026-09-17): rollout "beginning October 19, 2026", complete by November 19, 2026; its diff table lists Kernel 6.17.0-1022-azure -> 7.0.0-1012-azure |

Implications:
- Any floor up to 6.17 is satisfied by CI today. A floor of 7.0 is NOT satisfied by the 24.04 image (6.17); it only holds after the `ubuntu-latest` migration (Oct 19-Nov 19), and during the multi-week rollout `ubuntu-latest` may resolve to either image. A 7.0 floor therefore needs `runs-on: ubuntu-26.04` pinned in CI first.
- `ubuntu-latest` is going to move to 7.0 regardless, which means beep's dataplane gets exercised on 7.0 for free from late Oct/Nov; this is a forward-compat test, not a reason to require 7.0.
- Azure-tuned kernels (`-azure`) are not stock distro kernels; BTF/BPF config on them is evidently fine (memory-smoke loads beep today) but is not proof of generic-kernel behavior.

### Lima images (`lima/beep.yaml:21-24`, `lima/beep-k3s.yaml:26-29`, `lima/beep-client.yaml:31-34`)
- All three use `cloud-images.ubuntu.com/releases/24.04/release/` (floating "release" pointer). Kernel not pinned in the YAML. Repo evidence: 6.8 (`ebpf/src/main.rs:742`) and 6.17 (`docs/design/cni-svclb-landscape.md:56`) at different times. A cloud image's kernel moves with the `release` pointer and apt updates (unverified which is current today; I did not boot a VM).
- Ubuntu 24.04 GA kernel is 6.8 (well-known; not re-verified here). So a floor above 6.8 requires pinning/updating the Lima kernel (HWE `linux-generic-hwe-24.04`, which tracks 6.17 per the runner image above), a one-line provisioning change, not a blocker.

### k3s/u7s target nodes
- Docs name Linode (2), a home NAT router (1), Scaleway IPv6-only (3) (`docs/design/cni-svclb-landscape.md:9`). The node OS is not specified anywhere in the repo (`git grep` for debian/ubuntu/talos/flatcar/rhel in docs/ finds nothing). **Unverified: actual target OS/kernels; the operator needs to confirm.** k3s itself imposes no kernel floor beyond its own needs.

### Mainstream distro kernels (from distro knowledge, NOT re-fetched; verify before relying)
| Distro | Kernel | >= 6.6? |
|---|---|---|
| Ubuntu 22.04 | 5.15 GA, HWE 6.8 | only via HWE |
| Ubuntu 24.04 | 6.8 GA, HWE up to 6.17 | yes |
| Ubuntu 26.04 | 7.0 (runner image shows 7.0.0-azure) | yes |
| Debian 12 | 6.1 (backports newer) | NO without backports |
| Debian 13 | 6.12 | yes |
| RHEL/Alma/Rocky 9 | 5.14 + heavy backports | almost certainly no TCX (unverified) |
| RHEL/Alma/Rocky 10 | 6.12 | yes |
| Flatcar / Talos | recent releases ride the 6.12 LTS line (unverified) | yes |
| Amazon Linux 2023 | 6.1 / 6.12 variants (unverified) | 6.1 no |

### Newest kernel release as of 2026-10-13 (verified via GitHub `torvalds/linux` tags/commits)
- v7.0 tagged 2026-04-12; v7.1 and v7.2 exist; v7.2 tagged 2026-08-16 is the newest stable; v7.3-rc7 is the current mainline candidate. v6.12 tagged 2024-11-17. So "7.0" exists and is two releases old. Linux 7.0 is simply the version after 6.19 (renumbering, no eBPF discontinuity; unverified assertion, consistent with the 6.19 -> 7.0 sequence).

## 2. The 131,072 B cap

- 131,072 = 128 KiB = `ceiling=$((128 * 1024))` at `scripts/assert-ebpf-object-stripped.sh:58-62`. It is a **repo-local CI gross-regression proxy** on the size of the stripped embedded ELF (`wc -c`), introduced at 100 KiB (beep-9w5) and raised to 128 KiB (commit 1a39255, for dual-stack `_v4/_v6` duplication). The script header (lines 11-15) says the precise guard is the `.debug_*` check; the size ceiling only catches a ~270 KB DWARF revert.
- It is NOT a kernel/verifier/tail-call limit and is not in `build.rs`. The kernel never sees ELF byte size: it sees loaded BPF instructions (privileged limit 1,000,000 verifier-processed insns since 5.2; per-program 4096 insn limit applies only to unprivileged; both from kernel docs, not re-fetched). No kernel version changes the ELF-size question.
- Note a doc inconsistency: `CHANGELOG.md:100-101` claims "gross-size ceiling is 160 KB (#195, #202)" but the script on `origin/main` (fetched today) still says 128 KiB. One of the two is stale (or the 160 KB bump is on an unmerged branch); I did not locate #195/#202.
- Consequence for the pending decision: raising the ceiling is a one-line, floor-independent edit; shrinking is about source structure. The genuine shrink levers are (a) the dual-stack duplication forced by `load_direct`'s compile-time-offset rule (`ebpf/src/main.rs:19-22, 741-753`), see dynptr below, and (b) toolchain inlining policy (`#[inline(always)]` everywhere because of a bpf-linker/LLVM miscompile of non-inlined BPF-to-BPF calls, `ebpf/src/main.rs:1199-1203`, a toolchain issue, not kernel). The 512 B stack (`ebpf/src/main.rs:537`) is a kernel constant that no kernel through 7.x raises for tc programs (private-stack work targets other program types; unverified).

## 3. Features by floor

aya status: aya 0.14.0 (2026-06-24), aya-ebpf 0.2.1 (2026-06-30) per `gh api repos/aya-rs/aya/releases`; "main" checked via `gh search code` (not built).

| Feature | Kernel | beep use | aya 0.14 / aya-ebpf 0.2.1 | aya main |
|---|---|---|---|---|
| bpf_redirect_neigh/peer | 5.10 | already used (`ebpf/src/main.rs:1704`) | yes | yes |
| Atomics (BPF_ATOMIC) | 5.12 | none needed (`FRONT_MISSES` is PerCpuArray, `main.rs:442-444`) | n/a | n/a |
| bpf_for_each_map_elem | 5.13 | possible in-kernel conntrack walk | raw binding only (unverified) | raw |
| BPF_PROG_TYPE_SYSCALL | 5.14 | in-kernel eviction sweep | no program type (unverified) | unverified |
| bpf_timer | 5.15 | idle/TTL expiry | helper bindings only (`bpf_timer_init` in aya-ebpf-bindings), no map-value wrapper | same |
| bpf_loop | 5.17 | none | raw binding | raw |
| dynptr helpers | 5.19 | -- | bindings | bindings |
| bpf_dynptr_from_skb / slice (kfuncs) | 6.4 | replace `load_direct` | no kfunc declaration support in aya-ebpf; aya-obj relocation handles `BPF_PSEUDO_KFUNC_CALL` | relocation present (aya-obj `relocation.rs`) |
| open-coded iterators (`bpf_for`), `may_goto` | 6.4 / 6.9 | none | none | none |
| TCX | **6.6** | already used | full (`tc.rs`) | full |
| netkit | 6.7 | none (beep attaches to uplinks and the geneve device; netkit is a pod-veth replacement) | link type enum only, no `Netkit` program attach | link type enum only |
| BPF arena | 6.9 | none | `Arena` listed in `maps/info.rs`, loading is `Unsupported(map_data)` | same |
| BPF token | 6.9 | none (DaemonSet runs privileged) | none found | none found |
| bpf_wq (workqueue) | 6.10 | none | none | none |

### Per candidate floor
- **5.11 (current doc) is fiction**: unusable with TCX (see section 0). Costs nothing to drop.
- **5.15 LTS**: unlocks bpf_timer (conntrack idle expiry; but see below) and bpf_for_each_map_elem/SYSCALL programs. Still fails TCX, so irrelevant unless beep re-adds a netlink attach path (it would add code to support old kernels the operator said are not needed).
- **6.1 LTS**: adds nothing beep can use beyond 5.15 (dynptr_from_skb is 6.4). Debian 12 and AL2023-6.1 are the only reason to care, and TCX already excludes them.
- **6.6 LTS (= effective floor today)**: TCX (in use). Gains `bpf_dynptr_from_skb`/`bpf_dynptr_slice` (6.4) and open-coded iterators.
- **6.12 LTS (recommended documented floor)**: nothing new for beep's dataplane over 6.6, but: it is what Debian 13, RHEL 10, current Flatcar/Talos ship (unverified), it is a still-supported LTS, Ubuntu 24.04 HWE and the CI runner (6.17) are above it, and it adds bpf_wq (6.10), `may_goto` (6.9), arena (6.9), tokens (6.9). Choosing 6.12 as a hard minimum would additionally exclude Ubuntu 24.04 GA (6.8), which runs beep today. Raising 6.6 to 6.12 therefore only buys "current LTS" and costs "Lima must move to HWE"; so use 6.12 as the tested baseline, keep 6.6 as the enforced minimum, and let the operator tighten if Ubuntu 24.04 GA nodes do not matter.
- **7.0 / newest**: no beep-relevant eBPF feature identified that needs 7.x (I did not enumerate 6.13-7.2 BPF changes commit by commit; **unverified, not exhaustively researched**). Costs: CI needs `ubuntu-26.04` pinned until the `ubuntu-latest` migration completes (Nov 19), Lima needs a kernel newer than 24.04 HWE can offer (6.17), and distro coverage drops to Ubuntu 26.04/Fedora/rolling.

### Feature assessments

**TCX / netkit vs netlink code.** TCX already adopted; there is no netlink code to delete. netkit is a device type (replacement for veth in CNIs), not an attach point for beep's uplinks. No gain.

**kfuncs.** The only candidate kfuncs for tc programs are `bpf_dynptr_*` (6.4) and nf_conntrack kfuncs (`bpf_skb_ct_lookup`, `bpf_ct_*`, 6.0; unverified). The nf_conntrack kfuncs would couple beep to netfilter conntrack, contradicting its own full-tuple `FLOW_TABLE`/`FWD_PENDING` design; reject. Using any kfunc adds a hard runtime requirement on vmlinux BTF (`/sys/kernel/btf/vmlinux`, `CONFIG_DEBUG_INFO_BTF`) because aya resolves kfunc BTF ids against it; beep currently relies only on its own `.BTF`/`.BTF.ext` (`scripts/assert-ebpf-object-stripped.sh:48-55`) and stable UAPI `__sk_buff` fields, so there is no CO-RE today.

**bpf_dynptr for packet access vs `load_direct`.** `load_direct` (`ebpf/src/main.rs:755-765`, one `unsafe` read plus the `AnyBitPattern` unsafe trait/impls at 771-784) exists because `bpf_skb_load_bytes` is a per-field helper call and offsets must be compile-time literals for the verifier to credit the bounds check (`main.rs:741-753`). That literal-offset rule forces the const-generic L2/L3 duplication and the `_v4`/`_v6` function pairs (`main.rs:19-22`, `1084-1176`, `1950-2094`), i.e. the object-size pressure. `bpf_dynptr_slice(&dptr, runtime_offset, buf, const_len)` takes a runtime offset with a constant length and returns a verifier-checked pointer, which could let one function body serve both families and L2 modes. This is the single feature in the matrix with a plausible effect on object size and `unsafe` count. Cost: 6.4 minimum (covered by 6.6), aya has only raw kfunc plumbing: you would write `extern "C"` kfunc declarations (more `unsafe`, not less) and have to prove aya-ebpf/bpf-linker emits a valid `.ksyms` BTF extern; **unverified, needs a spike**. Slice also copies into `buf` when the data is non-linear, changing the "linear-head-only" semantics (`main.rs:735-736`). Treat as a spike, not a reason to move the floor.

**bpf_loop.** No loop in the dataplane needs it (flow lookup is O(1) map access; Geneve options are fixed-size). No gain.

**BPF timers vs eviction/churn (FIRM v1).** Current design: userspace sweep on endpoint removal, `evict_pod_flows` (`src/lib.rs:338-385`), with a documented hazard that `.iter()` over a live LRU hash can restart on a concurrent delete (`src/lib.rs:291-296`, `332-335`). A bpf_timer lives in the map value (value layout in `beep-common` would grow, byte-identical on both sides), fires per-entry on a clock, and so addresses idle/TTL expiry that pure LRU does not do. It does not address "evict flows pinned to a departed endpoint", which is event-driven; that still needs a sweep. An in-kernel sweep (SYSCALL program + `bpf_for_each_map_elem`, 5.13/5.14) would be atomic w.r.t. the dataplane and avoid the userspace restart race; whether `bpf_for_each_map_elem` callbacks may delete from the iterated LRU map is **unverified** (check kernel doc comment on the helper in `bpf-helpers(7)`). Both options are available at 6.6 already; they do not argue for a higher floor. aya support is the real cost: no timer map-value wrapper, no SYSCALL program type found in 0.14.

**BPF arena (6.9).** No use: beep needs bounded hash maps with LRU, not arbitrary shared heap. aya lists the type but does not load it.

**BPF tokens (6.9).** Only useful for unprivileged-container BPF loading; beep's controller is a privileged DaemonSet. No aya support found. No gain.

**Verifier limits.** The binding constraint is the 512 B stack shared across inlined/called frames (`ebpf/src/main.rs:537-548`; CHANGELOG "trimmed to fit the shared stack"), not the 1M insn budget. Nothing in 6.6-7.2 raises the tc-program stack limit (unverified for 7.x). Newer verifiers are smarter about bounds propagation, which could relax the "never literal offset 0 / must be a constant" quirks (`main.rs:741-753`) but this was confirmed only on 6.8; re-test on 6.12/6.17/7.0 before assuming.

**BTF/CO-RE.** No change from a higher floor unless kfuncs are adopted (then vmlinux BTF becomes mandatory on every node, which Raspberry Pi/home-router/minimal kernels may lack; unverified).

## 4. Recommendation

Document and enforce **6.6 as the hard minimum** (what the code needs today) and treat **6.12 LTS as the supported/tested baseline**; do not go to 7.0.

What it buys: removes the false 5.11 claim, makes failures explicit (a startup `KernelVersion` check or README line), guarantees TCX. Raising further buys no dataplane feature beep can consume through aya today.

What it costs: CI none (runner is 6.17 now, 7.0 after Nov 19). Lima: unpinned `release` image may be 6.8 (fine for 6.6) but should be pinned/tested on HWE for 6.12+. Targets: excludes Debian 12 (6.1) and RHEL 9 (5.14) nodes, which cannot run beep anyway.

What would need to change: README/docs floor line (beep-vofi) to 6.6; optionally add a loader-side kernel-version check with a clear error; add a CI/Lima matrix leg on 7.0 (free via `ubuntu-26.04`) as a forward-compat signal; correct the CHANGELOG (160 KB) vs script (128 KiB) inconsistency; operator to confirm real target OS kernels.

Re-evaluate raising the floor when (a) aya ships safe timer/kfunc/dynptr support, or (b) a dynptr spike shows a measurable object-size/unsafe reduction.

## Unverified / not done
- Distro kernel table (section 1) is from memory, not fetched.
- Per-kernel BPF feature versions in section 3 are from kernel-history knowledge, not re-fetched from commits; verify against `bpf-helpers(7)` / kernel BPF docs before an implementation bead.
- aya "main" support judged by GitHub code search only, not built.
- 6.13-7.2 BPF changes not enumerated.
- No VM booted; Lima kernel today unknown.
