# Project Instructions for AI Agents

This file provides instructions and context for AI coding agents working on this project.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:7510c1e2 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md for details and anti-patterns.

## Session Completion

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->


## Build & Test

Requires a nightly toolchain with `rust-src` (pinned in `rust-toolchain.toml`)
and `bpf-linker` on `PATH` (`cargo install bpf-linker` or an aya-rs prebuilt).

```bash
cargo build --release        # build.rs cross-builds beep-ebpf and embeds it
cargo test -p beep-common    # host unit/regression tests (run on any host)
cd ebpf && cargo clippy --release --target bpfel-unknown-none -Z build-std=core
```

The loader (`beep`) links Linux-only syscalls (`bpf(2)`, netlink) and only
builds/runs on **Linux** — build and smoke-test it in CI or a Linux/Lima VM, not
on macOS. `cargo test -p beep-common` is the only cargo step that runs on macOS.
Load-and-round-trip smoke: `scripts/smoke.sh [--vm <lima-vm>]` locally; CI runs
`scripts/smoke-remote.sh`.

## Architecture Overview

beep is an eBPF service load balancer (Geneve encap/decap, full-tuple conntrack)
built on aya. Three crates:

- **`beep`** (repo root, `src/main.rs`) — userspace loader: attaches the tc-bpf
  classifiers, pins them under a bpffs dir, and populates VIP→backend maps.
- **`beep-ebpf`** (`ebpf/`) — the `#![no_std]`, `bpfel-unknown-none` dataplane
  program.
- **`beep-common`** (`common/`) — shared `no_std` types (conntrack keys,
  `Config`) depended on by both, so conntrack map key/value layouts are
  byte-identical on each side of the kernel/user boundary.

Design docs: `docs/design/ebpf-lb-dataplane.md` and the ADRs in `docs/decisions/`.

## Conventions & Patterns

- Any type shared between the loader and the eBPF program MUST live in
  `beep-common` — never duplicated — to keep map layouts identical.
- `beep-ebpf` is cross-built by `build.rs` (aya-build) and embedded into the
  loader via `include_bytes_aligned!`; there is no separate build step for it.
- Imported from the u7s monorepo (u7s@4f898a4d) with git history preserved.
