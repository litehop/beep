# Project Instructions for AI Agents

This file provides instructions and context for AI coding agents working on this project.

## Rules

Bias: caution over speed on non-trivial work. Use judgment on trivial tasks.

### Rule 1 — State Success Before You Start
Before any tool call: write one sentence naming the done-when criterion.
If you cannot state it, ask — do not start. If mid-task you lose track of
what "done" looks like, stop and restate it before continuing.

### Rule 2 — Simplicity First
For every piece of code you are about to write, ask: would removing this
leave the test passing and the feature working? If yes, remove it. No
speculative features. No abstractions for single-use code. No fallbacks for
scenarios that cannot happen.

### Rule 3 — Surgical Changes
Gate: does this file path appear in the task description, the failing test
output, or the diff you were asked to produce? If not, do not touch it.
Clean up only your own mess. Match existing style without comment.

### Rule 4 — Goal-Driven Execution
Define done-when criteria before the first tool call. At each checkpoint,
compare actual state to those criteria — not to a checklist of steps. If
the steps are done but the criteria aren't met, keep going. If the criteria
are met before the steps are done, stop.

### Rule 5 — Use the Model Only for Judgment Calls
Use for: classification, drafting, summarization, extraction.
Not for: routing, retries, regex, JSON parsing, deterministic transforms.
If code can answer, code answers.

### Rule 6 — Surface Budget Pressure
If a single task is burning more than ~20,000 tokens without a clear
checkpoint, stop and summarize what's done, what's verified, and what
remains. Overruns happen; silent overruns without a handoff are the problem.

### Rule 7 — Surface Conflicts, Don't Average Them
If two patterns contradict, pick the more recent or more tested one, explain
the choice in one line, and flag the other for cleanup. Never blend
conflicting patterns into a third thing neither was.

### Rule 8 — Read Before You Write
Before adding code, read exports, immediate callers, and shared utilities.
"Looks orthogonal" is not safe. If you do not know why something is
structured a certain way, ask before changing it.

### Rule 9 — Tests Verify Intent, Not Just Behavior
A test that cannot fail when business logic breaks is wrong. Test names and
assertion messages must state WHY the behaviour matters (what breaks for a
user if it regresses), not just WHAT the code does.

### Rule 10 — Checkpoint After Every Significant Step
After each meaningful unit of work: one sentence on what changed, one
sentence on what's verified, one sentence on what's next. If you find
yourself in step 4 without having done this at step 2, stop and do it now.

### Rule 11 — Match the Codebase's Conventions
Conformance over taste. If you genuinely believe a convention is harmful,
surface it with a concrete example — then follow it while you wait for a
decision. Do not silently fork.

### Rule 12 — Fail Loud
"Completed" means done AND verified. "Tests pass" means all tests ran, none
were skipped. If anything was skipped or assumed, say so explicitly. Default
to surfacing uncertainty rather than papering over it.

### Rule 13 — Prefer Native Tooling
Use Bash and Rust over Python. Do not introduce Python scripts or Python
dependencies. For file I/O: Read over cat/head/tail; Edit over sed/awk;
Write over echo>/heredoc; Grep over shell grep/find. Bash is for runtime
commands only: git, cargo, gh, kubectl, bd.

### Rule 14 — Every Bug Fix Ships with a Regression Test
Gate: can this test fail if the fix is reverted? If not, it is not a
regression test — it is documentation. Extract untestable async handler logic
into a pure function and test that. A fix without a failing-on-revert test is
not complete.

### Rule 15 — Prefer Merge Commits for PRs
Use `gh pr merge --merge` by default. Use `--squash` only for branches with
many noisy fixup commits — and say why in the merge message. Never `--rebase`
(rewrites SHAs, breaks history). Resolve merge conflicts by merging `main`
into the branch; do not force-push.

### Rule 16 — Prose Is Code
Rule 2 applies to sentences. Cut every clause that restates a doc you linked,
narrates how a decision was reached, defends against an objection nobody
raised, or reports what "this session" did. A concise "why" is sufficient if
something is not obvious, but otherwise text (comments, commits) should be as
concise and factual as possible.

### Rule 17 — Answer First
Every artefact written for another agent to read cold — bead note, PR body,
dashboard entry, findings doc, worker brief — opens with a single-sentence
answer or decision before any evidence, mechanism, or chronology. Evidence
supports the answer; it does not precede it.

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
