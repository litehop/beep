# Dashboard

**Updated 2026-09-10T09:29Z · SESSION WRAPPED · Resume: `bd prime` → this file.**

**Outcome:** Controller-shipping wave landed end-to-end. Image LIVE + pullable at `valerauko/beep-lb:latest` (dual-arch glibc), and the delivery pipeline now builds in CI (setup-zig + trixie + rust-cache, ~4min) and publishes on main — **confirmed working on main**. Board clean: no open PRs, no workers, no worktrees, all Lima VMs free.

## 🎯 Operator — what needs you now
- Nothing — session is wrapped.

**Stance:** correctness > security > perf > features; pre-alpha, break freely; bare-metal (node's PHYSICAL IP is the front, no cloud LB/BGP); merge-on-green.
**Gate:** `ebpf-build` + `ebpf-memory-smoke` required. Delivery = `delivery.yaml` on push:main (+ `workflow_dispatch` with `push` input, default false = dry-run).

## ▶ Next major (for the next mayor)
- **beep-s5k** P2 — controller-driven e2e on the k3s rig (real Service → beep → backend round trip). The whole stack is now shipped (image live; controller feature-complete: watch→reconcile→program maps + `status.loadBalancer.ingress` + hostNet). This is the validation gate. Depends on `mayor-9gr0n`.
- **`mayor-9gr0n`** (controller epic) is CODE-COMPLETE + shipped but left OPEN — its done-when includes live integration, which IS beep-s5k. Close it once beep-s5k proves the controller live.

## Backlog (filed this session)
- **beep-pw4** P3 — PR-gate the aarch64-gnu cross-compile (delivery builds it; only amd64 PR-covered).
- **beep-5jb** P3 (PARKED) — split `ebpf-build` job → lint/test/build (needs ruleset-22605658 coord on a clean board).
- **beep-867** P4 — strengthen `is_redirected_return_mark` test (reject non-marker nonzero).
- **mayor-axzsf** P3 — rename misleading "VIP" (real confusion, surfaced live this session).
- Other open: `mayor-waqhd` (kube-proxy/flannel coexistence — Phase 6; note the beep-nxn status-IP overlap), `mayor-g9l0f` (e2e/conformance wiring, informed by #35's findings doc), `beep-n24` (cross-node martian-source blocker), `mayor-aie31.21` (affinity), + P3/P4 misc.

## ✅ Merged this session (7 PRs)
#34 image+delivery.yaml · #35 sonobuoy findings · #36 status.loadBalancer.ingress · #37 hostNet relax · #38 return-leg fix (vip==pod_ip) · #39 CI-native build · #40 setup-zig+trixie+dry-run pipeline fix.

## Memories banked
`ci-rust-cache-convention` · `rust-cache-matrix-keying-gotcha` (matrix legs need per-target key; sequential doesn't).

## Key learnings (session)
- **hostNetwork semantics:** in bare-metal the front IS the node's physical IP, so a hostNet backend has vip-adjacent addressing; the guard black-holed it (fixed #37+#38). Perimeter defense = firewall's job (ufw/NetworkPolicy), not the LB.
- **Verify CI-only steps IN CI:** #39 shipped a hand-rolled zig install that passed local build but died on `tar -C /usr/local` in CI. #40 added a `workflow_dispatch` dry-run so pipeline changes are provable on a branch before merge — use it.

## Cron loops
<!-- BEGIN AUTO: cron-loops -->
15m mayor tick (`scripts/mayor-tick.sh`) · 60m reread posture · 60m worktree hygiene
<!-- END AUTO: cron-loops -->

## Repo state
<!-- BEGIN AUTO: repo-state -->
As of 2026-09-10T09:29Z — Branch `main` @ b39a9b3, up to date with origin. 0 open PRs, only `main` locally, all VMs free. Working-tree: dashboard + .beads/*.jsonl (operator commits out-of-session).
<!-- END AUTO: repo-state -->
