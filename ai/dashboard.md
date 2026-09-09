# Dashboard

**Fresh mayor. Resume: `bd prime` → this file.**

## Operator
Nothing blocking. beep: eBPF service load balancer (Geneve encap/decap,
full-tuple conntrack) on aya. Known blocker: cross-node WireGuard path
(bead mayor-f3ru5), tracked on `beep-node-a` + `beep-node-b`.

**Stance:** correctness > security > perf > features; merge-on-green via
native merge queue; plan-first.
**Crons:** mayor-tick (15m) · reread (60m) · worktree-hygiene (60m).
**Lima VMs:** `beep-smoke` (single-node smoke gate), `beep-node-a` +
`beep-node-b` (cross-node WireGuard). MCP tools: `mcp__beep-*`.

## Quality gate
5-command gate (`.github/workflows/ci.yaml` `ebpf-build`): `cargo fmt
--check` → `cargo clippy --tests -- -D warnings` → `cargo test -p
beep-common` → `ebpf/` clippy on `bpfel-unknown-none` → `cargo build
--release`. Required merge-queue checks: `ebpf-build`, `ebpf-memory-smoke`.
Reviewer app id `4746811` (`litehop-reviewer[bot]`); marker:
`## critical-reviewer findings`.

## Cron loops
<!-- BEGIN AUTO: cron-loops -->
<!-- END AUTO: cron-loops -->

## Repo state
<!-- BEGIN AUTO: repo-state -->
<!-- END AUTO: repo-state -->

## Open PRs
<!-- BEGIN AUTO: open-prs -->
<!-- END AUTO: open-prs -->

## Review queue
<!-- BEGIN AUTO: review-queue -->
<!-- END AUTO: review-queue -->

## Worktrees / hygiene
<!-- BEGIN AUTO: worktrees -->
<!-- END AUTO: worktrees -->
