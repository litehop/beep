# Dashboard

**Updated 2026-10-14 · SESSION CLOSED.** Main @ `07d3a06`, up to date. 0 workers · 0 open PRs · loops stopped. Resume: paste `ai/prompts/mayor-bootstrap.md`, re-arm loops (tick `7,22,37,52` · reread `:13` · hygiene `:43`). **Stance** (`bd recall project-stance-2026-10-13`): pre-1.0 break freely · correctness > perf > elegance · merge on green · LE only · no "VIP".

## 🎯 NEXT SESSION — first things
1. **`lo44` (P2) VM hygiene rules first**, before any VM-heavy dispatch: per-worker VM dir + no-delete + stop at 80% disk into worker.md / dispatch template (interim: `bd recall vm-disk-no-delete-rule-2026-10-13`). `beep-client` is at 93% of 3.9G → operator: resize or drop its `.cache`.
2. Finish multi-endpoint LB epic `5lw`: `5lw.11` (P2) Lease-heartbeat pruning of dead nodes from `status.loadBalancer.ingress` · `5lw.8` design docs (incl. decap trust model, locality matrix from #240).
3. `p880` (P2) ConfigMap for `BEEP_MAX_FRONTS` / `BEEP_ENDPOINTS_PER_FRONT` + documented options.
4. Small: `uov3` crash-safe pin migration · `r54o` DROP-WIRE per-family SYN guard + tcpdump strictness · `46t5` leg-d parsing · `thl0` metrics surface (design first).
5. Leftover: W-AI's dirty worktree `ai/worktrees/agent-a8170ae9c67e7ecbf`. Its edits shipped in #242 (also saved as `wai-242.patch`); safe to remove on operator OK.

## 🧭 Decisions this session (all in bead notes `zmzp` `dz73` `vksr` `5lw` `noak` `pyeb` `5lw.4`)
Floor Linux 6.6 enforced, tested 6.6/6.12/7.2 (CI matrix) + 6.12 (beep-smoke) + 6.8 (rigs) · 128 KiB ceiling kept; BTF strip → object ~65 KB · LE only · no-prealloc front maps, `--max-fronts 1024 × --endpoints-per-front 4`, ×2 retention dropped (2 s grace), migrate on flag/cap recreation · decap trusts NODE_ALLOW peer (no-spoof underlay) · **locality:** uniform default, `PreferSameNode` opt-in (spec.trafficDistribution), eTP=Local local-only + terminating fallback, ingress per-node (Local → nodes with a local pod), count-0 fronts **silently drop** · QUIC migration not v1 · dynptr after next aya/bpf-linker release (`kofb`) · healthCheckNodePort left to kube-proxy (`a3eh`).

## ✅ Merged this session (30 PRs, #211–#242)
Renovate #211 #212 · controller #213 #217 #222 #237 #242 · dataplane #216 #221 #226 #229 #241 · smoke/CI #214 #215 #218 #225 #227 #230 #231 #234 #235 #236 · infra #224 · findings #219 #220 #223 #228 #233 #240. **Multi-endpoint LB is live** (all-endpoint emission, eTP/trafficDistribution policy, node-local opt-in, silent drop).

## 🧠 Banked
`project-stance-2026-10-13` · `quic-migration-not-v1-blocker-2026-10-13` · `reviewer-skips-posting-2026-10-13` · `endianness-le-only-pre-1-0` · `decap-trust-model-2026-10-13` · `mayor-cwd-gotcha-2026-10-13` · `vm-disk-no-delete-rule-2026-10-13` · `curl-reconnect-test-gotcha-2026-10-13`

## 🗄 Handoff notes
- Beads are LOCAL (no Dolt remote); `.beads/*.jsonl` exports uncommitted (main rejects direct pushes).
- Reviewer sometimes skips posting → confirm the review is on the CURRENT head before queuing; draft a PR while its fix commits are unreviewed.
- `bd ready`: 28 (incl. larger features `7qm` IPv6, `eix` multi-iface; decision-gated `4gp`).

## Cron loops
<!-- BEGIN AUTO: cron-loops -->
Stopped at session close (re-arm on resume).
<!-- END AUTO: cron-loops -->

## Open PRs
<!-- BEGIN AUTO: open-prs -->
None open.
<!-- END AUTO: open-prs -->

## Repo state
<!-- BEGIN AUTO: repo-state -->
Session close 2026-10-14 — Branch `main` @ `07d3a06`, up to date with origin/main.
<!-- END AUTO: repo-state -->

## 🌲 Worktrees
<!-- BEGIN AUTO: worktrees -->
- `ai/worktrees/agent-a8170ae9c67e7ecbf` (`fix-242`): dirty but superseded; awaiting operator OK to remove.
<!-- END AUTO: worktrees -->

## 📋 Review queue
<!-- BEGIN AUTO: review-queue -->
0 pending review-queue entries.
<!-- END AUTO: review-queue -->
