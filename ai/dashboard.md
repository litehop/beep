# Dashboard

**Updated 2026-09-21 · SESSION LIVE (mayor).** Main @ `197dff3`, up to date with origin. **3 loops ARMED. 0 workers, 0 open worker PRs.** **0.3.0 bumped on main — READY TO TAG.**

## 🎯 WHAT NEEDS THE OPERATOR NOW
- **Tag `v0.3.0` (operator-only).** Main `197dff3` is the release commit: all 5 crates at 0.3.0, CHANGELOG dated. Cut it with:
  `git tag v0.3.0 && git push origin v0.3.0` → fires `delivery.yaml` (Docker image `docker.io/valerauko/beep-lb:v0.3.0` + `:latest`, GitHub Release from CHANGELOG). I do NOT tag/push releases.
- (Renovate PR #123 — operator handling; mayor hands-off.)
- `beep-5lw` design fork PARKED (slot-renumbering vs BackendId); impl blocks on eviction epic `beep-03i`.

## ✅ Merged this session
- **#125** (beep-1no) — workspace version bump 0.2.0→0.3.0 + CHANGELOG dated.
- **#124** (beep-9au) — consolidated release notes into root `CHANGELOG.md`; removed `docs/release-notes/*`; repointed `delivery.yaml`.
- **#121** (beep-5lx) — 0.3.0 gate: valid L2 header on Ethernet client-egress return leg.
- **#120** (beep-8vn + beep-3e0) — ci.yaml bead-ID leak + 2 ADR citations.

## 🗺 v1.0 roadmap
0.3.0 (ready to tag) → real-hardware [beep-903] → perf+code-quality audit (**beep-uqn**) → security audit → docs. **beep-03i** eviction = FIRM v1 req (NOT built). v6 Geneve *outer*: **beep-8b0** (P3).

## 🗄 Handoff / START NEXT SESSION
Beads LOCAL (no remote). Parked: `beep-5lw`. Post-0.3.0 P4 follow-ons: **beep-c9k** (delivery.yaml extraction test), **beep-puf** (cold-cache rig). All VMs FREE. No worktrees.
- **If session was closed, re-arm loops:** 15m tick `7,22,37,52 * * * *` · 60m reread `13 * * * *` · 60m hygiene `43 * * * *`.
- **Verify after operator tags `v0.3.0`:** `delivery.yaml` run green + GitHub Release body rendered from CHANGELOG (first use of the new extraction path) + Docker image published. Then bump these dashboard sections to `[0.3.0] shipped`.

## Cron loops
<!-- BEGIN AUTO: cron-loops -->
15m mayor tick (`scripts/mayor-tick.sh`) · 60m reread posture · 60m worktree hygiene
<!-- END AUTO: cron-loops -->

## Open PRs
<!-- BEGIN AUTO: open-prs -->
- #123 chore: Configure Renovate (`renovate/configure`) — operator handling.
<!-- END AUTO: open-prs -->

## Repo state
<!-- BEGIN AUTO: repo-state -->
2026-09-21 — main @ `197dff3`, up to date with origin/main.
<!-- END AUTO: repo-state -->

## 🌲 Worktrees
<!-- BEGIN AUTO: worktrees -->
None.
<!-- END AUTO: worktrees -->

## 📋 Review queue
<!-- BEGIN AUTO: review-queue -->
0 pending.
<!-- END AUTO: review-queue -->
