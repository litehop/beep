---
Bead: beep-2ka
Date: 2026-09-17
Scope: read-only audit of beep's operator/durable docs against Rule 16, Rule 17, and the humans-AND-agents standard. No fixes; MED+ findings get follow-on beads.
---

# Doc-standards audit: beep's operator/durable docs vs. Rule 16/17

## Answer first

The corpus mostly meets its own standard: every primary decision/how-to doc
opens with the answer (two docs literally start with the word "Answer:"),
budgets are respected, and `docs/design/kube-proxy-coexistence.md` is the
strongest humans-AND-agents exemplar in the repo. The real defects are
mechanical, not stylistic: dead `bd show`/file cross-references left over
from the u7s-monorepo extraction, one doc's stale claim about work already
done, one file's literal internal duplication, and one ADR-shaped decision
inlined into a README instead of living in `docs/decisions/`. 4 MED findings
filed as follow-on beads; 0 HIGH.

## README.md — verdict: compliant, no bead filed

Opens with what beep is, then the pre-alpha warning, then mechanism —
correct order. Every section (Building/Running/Deploying/Memory
observability) leads with the actionable point before detail.

- LOW: line 90 ("Per `docs/decisions/ebpf-toolchain-aya.md`, you need to
  monitor both sides of memory use independently") lightly restates that
  ADR's own Consequences bullet. Cosmetic; not worth a bead.

## AGENTS.md — verdict: 1 MED (internal duplication)

- **MED** `AGENTS.md:16-24` vs `AGENTS.md:55-62`: two near-identical "Quick
  Reference" `bd` command blocks in the same file — a hand-authored one
  near the top, and a second inside the auto-injected `<!-- BEGIN BEADS
  INTEGRATION -->` block. Rule 16 bans restating a doc already linked;
  restating within the *same file* is the same defect turned up to 11. Fix
  sketch: delete the hand-authored block, keep only the tool-managed one (or
  vice versa) so a future `bd`-tooling update can't silently re-diverge them.
  File never touched since `bd init` (2026-09-08) — nobody has looked at it
  since the tool generated it.

## docs/style-guide.md — verdict: compliant, no bead filed

Terse, numbered rules, each with a positive/negative example. Rule 11
("depart when it makes a doc clearer") is itself a clean Rule-16 move —
it forecloses treating the guide as a lint gate. No findings.

## deploy/README.md — verdict: 1 MED; otherwise a humans+agents exemplar

Graded against `origin/main` (PR #80 already merged, gotcha #1's WARN-log
rewrite is in place — not re-flagging it). "Verify your deployment" gives
humans a curl-based check AND agents a `bpftool`-based one in the same
section — exactly the FIRM operator preference.

- **MED** `deploy/README.md`'s "Deployment model" section, the `rp_filter=0`
  paragraph (dated 2026-09-17, compares to Cilium/Katran/Calico, states an
  explicit REVISIT trigger): this is ADR content — dated tradeoff decision
  with rationale and a revisit condition — inlined into a deployment README
  instead of living in `docs/decisions/` like every comparable tradeoff in
  this repo. Gotchas #2 and #3 in the same file correctly link out to
  `docs/design/kube-proxy-coexistence.md` rather than inlining rationale;
  this paragraph should follow the same pattern. Fix sketch: extract to a
  new `docs/decisions/geneve-rp-filter-disable.md` ADR, replace the inline
  paragraph with a one-line pointer.

## docs/decisions/*.md (6 ADRs) — verdict: compliant on budget and structure

All six are under the 400-word enforced budget (344-399 raw words per
`wc -w`, before the script's fenced-code exclusion shrinks them further).
Every ADR's title states the decision (Rule-17 compliant at the document
level); Context->Decision->Rationale->Consequences is the consistent,
appropriate mechanism for the genre. No prose-quality MED+ findings.

- (see "Dead cross-references" below for a hit in
  `servicelb-flow-admission-affinity.md:56`.)

## docs/design/*.md — verdict: 1 shared MED (dead refs); 1 exemplary doc

- `kube-proxy-coexistence.md` — **exemplary.** Opens with a bolded
  `**Verdict:**` line (the clearest Rule-17 compliance in the corpus), then
  has separate "Verifying this (agent-facing)" and "Verifying this
  (human-facing)" sections. Point future doc work at this file.
- `cni-svclb-landscape.md` and `ebpf-lb-dataplane.md`: `kind:
  initiative-state` research-digest docs that open with context/scope
  before conclusions. This is genre-appropriate (a landscape survey's
  conclusion needs the survey's scope stated first) — LOW, not filing.
- **MED** (shared bead, see below): both files carry dead `bd show`/file
  cross-references from the u7s import.

### Dead cross-references (one shared MED bead)

References that don't resolve today, confirmed via `bd show <id>` and
`ls`:

- `docs/decisions/servicelb-flow-admission-affinity.md:56` — `bd show
  mayor-dksf5` -> "no issue found"
- `docs/design/ebpf-lb-dataplane.md:9` and `:171` — `bd show mayor-mma08`
  -> "no issue found"
- `docs/design/ebpf-lb-dataplane.md:155` — `bd show mayor-gjbov` -> "no
  issue found"
- `docs/design/ebpf-lb-dataplane.md:45` — `bd show mayor-s82zr` -> "no
  issue found"
- `docs/design/ebpf-lb-dataplane.md:172` — `docs/decisions/flannel-for-cni.md`
  does not exist in this repo
- `docs/design/ebpf-lb-dataplane.md:173` — `crates/scheduler` does not
  exist (no `crates/` directory at all in beep)
- `docs/design/cni-svclb-landscape.md:14` — `docs/decisions/network-policy-engine.md`
  does not exist
- `docs/design/cni-svclb-landscape.md:20` — `docs/decisions/flannel-for-cni.md`
  does not exist (same dead file as above)

Cross-checked ~20 other `mayor-*` references across the corpus
(`ai/extended-context/roadmap.md`, `versioning.md`,
`vm-operations.md`, etc.) — all resolve. This is a bounded, specific list,
not a systemic rot across every u7s-era reference. Fix sketch: either
re-point each dead ref at its actual successor bead/file, or strip the
parenthetical if none exists — a follow-on bead, not a fix here.

## ai/extended-context/*.md — verdict: 1 MED (staleness); 2 exemplary docs

- `vm-operations.md` — **exemplary.** Opens with the literal sentence
  "Answer: use `scripts/lima-up.sh` to bring up a VM, build on the host
  with `scripts/smoke.sh`, and inspect running state through the
  `mcp__beep-*` tools" — the single most literal Rule-17 compliance in the
  repo.
- `k3s-e2e-rig.md` (graded on `origin/main`, PR #81 already merged — not
  re-flagging its already-fixed 6/7 framing) — also opens with "Answer:
  ...", and has a dedicated "Driving the rig as an agent" section. LOW: at
  1307 words it's over the ~1200-word convention (not script-enforced, and
  the file was already touched today by #81) — noting only, not filing.
- `README.md` (the catalog) — compliant, terse table, no findings.
- **MED** `roadmap.md:86-94` ("Near-term work items", the "u7s-facing 'how
  to test beep on a VM rig' doc" bullet): claims `vm-operations.md` "says
  nothing about the k3s-controller e2e rig" and that extending it is
  "unclaimed work." This is stale — `ai/extended-context/k3s-e2e-rig.md`
  already exists (added 2026-09-14, the same day this roadmap bullet was
  written) and covers exactly that rig; it's even listed in
  `ai/extended-context/README.md`'s own catalog table. `roadmap.md` was
  edited again as recently as 2026-09-17 without correcting this. Fix
  sketch: delete or rewrite the bullet to point at `k3s-e2e-rig.md` instead
  of describing it as a gap.

## docs/release-notes/v0.1.0.md — verdict: compliant, no bead filed

Short, list-based, no narration of how any decision was reached. No
findings.

## Severity summary

- HIGH: 0
- MED: 4 (all filed as follow-on beads below)
- LOW/DEFER: 5 (listed inline above, no beads filed)

## Follow-on beads filed

- beep-anq — dedupe AGENTS.md's duplicate Quick Reference block
- beep-4u6 — fix dead `bd show`/file cross-references (u7s-import rot)
- beep-9zx — reconcile roadmap.md's stale "vm-operations.md gap" claim
- beep-4r2 — extract deploy/README.md's rp_filter=0 rationale into its own ADR
