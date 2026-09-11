# Dispatch Prompt Template

Mayor sessions should use the following canonical prompts when dispatching
to background agents to ensure safe delegation.

Placeholders used throughout:

- `<MAYOR_CHECKOUT>` — absolute path of the mayor's primary checkout
- `<WORKTREE_ROOT>` — absolute path of the directory holding worker
  worktrees. For this project: `<MAYOR_CHECKOUT>/ai/worktrees/` (inside
  the repo so workers inherit `.claude/settings.json` permissions
  automatically via the `WorktreeCreate` hook)
- `<ASSIGNED_WORKTREE>` — absolute path of the worktree the worker should
  edit (always a subdirectory of `<WORKTREE_ROOT>`)
- `<BEAD_ID>` — the bead identifier (`mayor-*`)

## Worktree boundary — mandatory in every editing dispatch

**Why this block exists.** Shell commands use `workdir`, but `apply_patch` and
some edit tools have no workdir, so relative patch paths can resolve against
the mayor checkout instead of the assigned worktree. "Use your worktree" is
not a strong enough prompt. Workers must verify before each edit and check
both checkouts after the first one.

**The path-resolution leak failure mode.** Observed repeatedly in audit
dispatches: the worker correctly ran the worktree guard and got the right
`WORKTREE_ROOT`, then a file `Write` (especially of a new `ai/findings/<name>.md`
file) landed in the mayor checkout because the edit tool resolved a
repo-relative path against the agent's session root instead of the worker's
git root. Symptoms:

- `git status` inside the worker worktree shows no new findings file.
- `git status` inside the mayor checkout shows a new untracked file under
  `ai/findings/` that the worker thinks it wrote to its worktree.
- The findings file is git-tracked (see README's "Findings lifecycle"), so
  the leak doesn't vanish quietly — it sits as a live untracked file in the
  mayor's working tree, one careless `git add` away from riding into an
  unrelated mayor commit. The `Write` itself gives no error, so only an
  explicit check on both sides catches it before that happens.

**Defence:** any `Write` of a brand-new file (especially under `ai/findings/`)
must be IMMEDIATELY followed by verifying the file landed in the worker
worktree and NOT in the mayor checkout (see the block below).

### The block (paste into every editing-worker dispatch)

The full checklist (per-edit verification, the after-first-edit check, the
new-file extra check, the stop condition) now lives in worker.md's "Worktree
boundary" section, loaded automatically for every worker — do not re-paste
it here. A dispatch brief only needs to supply the two bead-specific
absolute paths worker.md's block references as placeholders:

```text
Your assigned worktree: <ASSIGNED_WORKTREE>
The mayor checkout: <MAYOR_CHECKOUT>
```

### Mayor checks after dispatch

- Check the mayor checkout immediately after dispatching:
  `git status --short --branch`.
- Also scan: `git -C <MAYOR_CHECKOUT> status --porcelain ai/findings/` and
  look for `??` (untracked) entries — those are leaks. A legitimately
  tracked finding awaiting its bead's close commit is already committed, so
  it won't appear in this output at all; a bare `ls` can't tell the two
  apart.
- If the mayor checkout gains unexpected code changes, interrupt the
  worker before it does more work.
- Preserve any accidental changes into the worker worktree before
  restoring the mayor checkout.
- Only restore specific known files after preservation. Do **not** use
  broad destructive reset commands.

## Mayor pre-dispatch checklist (run BEFORE calling Agent)

```bash
# For dataplane-touching beads only: assign the Lima VM the bead needs.
#   scripts/smoke.sh (single-node gate) defaults to beep-smoke.
#   scripts/smoke-wg-2node.sh (cross-node WireGuard rig) defaults to
#     beep-node-a (ingress) + beep-node-b (backend).
#   Check which VMs are already claimed by another in-flight worker before
#   assigning — unlike u7s's port-isolated pool, beep has exactly three named
#   VMs and no port table: a second worker on the SAME VM at the same time
#   will collide. `limactl list` shows what's running.
```

No pre-create needed: `isolation="worktree"` in the Agent call creates the
worktree automatically and sets the subagent CWD to its root. `settings.json`
is tracked in git and present in every fresh worktree. `.claude/agents/worker.md`
is loaded from the mayor's `.claude/agents/` by the harness, not from the worktree.

**Agent tool call — mandatory fields:**

```python
Agent(
    subagent_type="worker",          # required — loads worker.md with permissionMode:auto
    run_in_background=True,
    isolation="worktree",            # creates worktree, sets CWD to its root
    prompt="... include Step 0 below ...",
)
```

**Every dispatch prompt must include Step 0:**

```bash
   pwd                              # confirm CWD is the worktree root
   git rev-parse --show-toplevel    # must match pwd
   git branch --show-current
   git -C <ASSIGNED_WORKTREE> status --short
   ```

## Reviewer effort tiering

Not every critical-reviewer dispatch needs Sonnet. Rule: a PR whose diff is
**≤50 changed lines** (`gh pr diff <N> --stat` total, additions + deletions)
AND touches **only doc/config surfaces** — `docs/`, `*.md`, `.claude/agents/*.md`,
`ai/dashboard.md`, CI YAML, `Cargo.toml` version/dependency bumps with no
code behind them, `scripts/*.sh`, non-`src/` test dirs — with **no changes
to code or any public-API surface** (eBPF map key/value layouts shared via
`common/`, packet-parsing or redirect logic in `ebpf/src/**/*.rs`, VIP/backend
map population in `src/**/*.rs`, or any other `**/*.rs` logic) qualifies for
the low-effort tier: dispatch critical-reviewer with `model="haiku"`. Every
other PR — larger diff, or any diff touching code or a public-API surface,
regardless of size — stays on critical-reviewer.md's Sonnet default. A
one-line `src/` fix does NOT qualify just because it's small; the surface
criterion is independent of the size criterion and both must hold.

Concrete invocation for a low-risk case (a 12-line `docs/decisions/` typo fix):

```python
Agent(
    subagent_type="critical-reviewer",
    model="haiku",
    prompt="Review PR https://github.com/litehop/beep/pull/<N> ...",
)
```

For everything else, omit `model` and let critical-reviewer.md's own
frontmatter (`model: sonnet`) apply.

This tier ships `model="haiku"` only. An `effort="low"` override was
considered but is non-functional: the Agent tool's JSONSchema declares
`additionalProperties: false` with property set `{description, isolation,
model, prompt, subagent_type}` — no `effort`.

**Asking the reviewer to "confirm" a claim does not mean asking it to
re-run anything.** Confirming that a test genuinely tests the behaviour is
a reading task the reviewer can usually answer from the diff and test
source; critical-reviewer.md's default posture is to read first and
execute only when reading is insufficient, naming the hypothesis when it
does. No wording change is needed in briefs.

## Common preamble (every dispatch)

worker.md (loaded automatically by the harness as every worker's system
prompt) is the complete home for the stable, always-applicable rules —
command shaping, native-tool preferences, LSP-first navigation, code
style, evidence & time discipline, and the git-hooks/quality-gate order.
Do not re-paste any of that into a dispatch brief. A brief needs only:
task-specifics (bead ID, context, concrete steps, quality-gate commands),
a VM assignment if the bead touches the dataplane (Lima VM protocol block,
below), and the two worktree paths (Worktree boundary block, above).

```
You are implementing bead **<BEAD_ID>** in beep, an eBPF service load
balancer (Geneve encap/decap, full-tuple conntrack) built on aya, in Rust.

<include project stance obtained from operator — pre-alpha/greenfield,
break freely, no backward compat; correctness first, then performance;
any type shared between the loader and the eBPF program lives in
beep-common>

<task-specific context with file:line citations, numbered concrete steps,
quality-gate commands (see Shape 1 below), and — for dataplane-touching
beads — the Lima VM protocol block>
```

**Note on Shape 1's quality-gate commands below:** they are the canonical
5-command gate CI's `fmt` / `lint-matrix` / `test-matrix` / `memory-smoke`
jobs run — the same gate `.claude/settings.json`'s `PreToolUse Bash` hook,
`.githooks/pre-push`, and worker.md's Workflow step 5 all carry. On a macOS
host only `cargo fmt
--check` + `cargo test -p beep-common` run locally; CI enforces the full
gate on the PR. Change it in all four places together —
`scripts/test-quality-gate-consistency.sh` guards the drift.

## Worktree path convention

Per project policy, worker worktrees live under:

```
<WORKTREE_ROOT>
```

Not `.claude/worktrees/agent-*` (forbidden — leaks edits to mayor checkout
via tool-path-resolution quirks; see "Worktree boundary" above).
Not a sibling directory outside the repo (`.claude/settings.json` is tracked
in git and present in any worktree inside the repo — no copying needed).
For this project the correct root is `<MAYOR_CHECKOUT>/ai/worktrees/`, on
branch `worker/<name>`.

---

## Shape 1 — Solo bead implementation

One bead, one PR. Standard shape. Sections: bead ID + verbatim title; 2–4
paragraphs of context with `file:line` citations; numbered concrete steps;
quality gates with exact commands; push + `gh pr create` titled
`<scope>(<artefact>): <summary> (<BEAD_ID>)`; return PR URL + per-step
summary + test deltas, under 250 words.

Step 0 — verify CWD is the worktree root:
```bash
pwd
git rev-parse --show-toplevel   # must match pwd
git branch --show-current       # must be worker/agent-<id>
git status --short              # must be clean
```

Quality gate — mandatory, run in this exact order, paste output into return
(byte-identical to `.githooks/pre-push` and CI's `fmt` / `lint-matrix` /
`test-matrix` / `memory-smoke` jobs):
```bash
cargo fmt --check
cargo clippy --tests -- -D warnings
cargo test -p beep-common
(cd ebpf && cargo clippy --release --target bpfel-unknown-none -Z build-std=core -- -D warnings)
cargo build --release
```
On macOS only `cargo fmt --check` and `cargo test -p beep-common` run
(the rest is Linux-only — the loader links Linux-only syscalls and the
`ebpf/` crate cross-builds for `bpfel-unknown-none`); CI runs the full
five-command gate on every PR regardless of dev host.

For any bead touching the dataplane (`ebpf/`, `common/`'s shared conntrack
or map types, or `src/`'s map-population logic), also run, before opening
the PR:
```bash
scripts/smoke.sh --vm <assigned VM, default beep-smoke>
```
This is the one gate that actually loads the compiled object into a live
kernel verifier and drives real packets through it — the host gate above
only proves the build compiles. CI's `memory-smoke` job re-runs an
equivalent round trip on merge, so a worker skipping this locally still
gets caught, just later and with less context.

Do not proceed to commit if any command fails. `.githooks/pre-commit`
checks `cargo fmt` plus the findings/bead-ref link checks; `.githooks/pre-push`
re-runs the full gate above — running it here first means you see failures
with context, not as a hook rejection that gives you no stacktrace.

Commit and push:
```bash
git add <files>
git commit -m "..."
git push
gh pr create --title "..." --body "..."
```

---

## Shape 2 — Cluster (multiple beads, single PR, sequenced commits)

3–12 beads on a shared surface. Sections: cluster name + N beads + source
findings; numbered bead list ordered **smallest cleanup → biggest correctness
fix** (so a failing P1 fix doesn't strand the small cleanups); commit format
`<scope>(<artefact>): <summary> (<BEAD_ID>)`; worktree at
`<WORKTREE_ROOT>/<cluster-name>-<HEAD_BEAD_ID>`; pre-claim each bead BEFORE
its commit (so bd state mirrors history one-to-one and a stalled cluster
leaves a clean partial trail); quality gates after EACH commit + full
regression after ALL; PR titled `<scope>(<artefact>): <cluster name> (N beads
incl. <P1 highlights>)`; return PR URL + per-bead one-liner + cross-bead
unifications spotted. Disjoint-surface "small-misc" clusters are valid at
the tail of a drain — the binding rule is hot-zone parallelism, not strict
same-surface.

Key cluster discipline:

- **Smallest+safest commit first; biggest correctness fix last.** If the P1
  fix breaks something, the small refactors land cleanly first.
- **Spell out commit ordering.** Don't leave it to the agent.
- **Note cross-bead unifications.** They surface real wins.
- **Bead pre-claim before each commit.** So bd state mirrors commit history
  one-to-one and a stalled cluster leaves a clean partial trail.

---

## Shape 3 — Audit (read-only research)

One bead asks for a finding, not a fix. Sections: goal (read `<surface>`
end-to-end; identify correctness drifts, perf hotspots, API hygiene, testing
gaps, cross-artefact coupling); reference (surface paths, relevant design
docs / ADRs, recent landings that changed the surface, prior audit findings to
avoid re-discovering); worktree + boundary block + `--status=in_progress`;
**WRITE THE FINDINGS DOC FIRST** to
`ai/findings/<YYYY-MM-DD>-<BEAD_ID>-<slug>.md`, starting with `Bead: <BEAD_ID>`
in its first 5 lines (a pre-commit hook rejects a new finding without it);
commit it with the bead's work — it is git-tracked only for the bead's
lifetime, deleted from the working tree in the close commit; file follow-on
beads ONE AT A TIME after the doc lands, appending each bead ID to the
audit-bead's notes so partial progress is durable across a watchdog timeout;
close audit-bead with verdict + cross-refs; no PR by default (trivial
one-line obvious fixes can ride along in a small PR); return under 400 words
with per-finding `file:line` citations + follow-on bead IDs + severity counts
(HIGH/MED/LOW/DEFER) + verdict.

Critical learnings:

- **Findings doc FIRST, before any `bd create`.** Audit work can stall
  mid-bead-filing (watchdog timeout, model error). Doc-first preserves
  the analysis even if the bead-filing loop never completes.
- **One bd-create at a time + update parent notes after each.** Partial
  progress survives a watchdog timeout.
- **Name the recent landings** so the audit reads the current reality.
- **Severity tags** (HIGH/MED/LOW/DEFER) make later cluster-formation trivial.
- **Commit the doc, don't wrap it in a PR.** It's git-tracked under the bead
  lifecycle (see README's "Findings lifecycle"), but audit output isn't code
  needing review-before-merge — commit it directly and reference it from the
  bead's notes.

---

## Shape 4 — Cluster reviewer (research + recommendation only, no dispatch)

Used between major dispatch waves to shape the next round. Read-only — no
worktree boundary block needed. Sections: cluster policy verbatim; in-flight
workers + their surfaces (do NOT recommend changes that touch these); enumerate
beads filed in the last ~30 min via
`git log -p --since='35 minutes ago' -- .beads/issues.jsonl`; per-bead decide:
(A) add to in-flight cluster / (B) form new cluster (3+ beads on shared
non-in-flight surface) / (C) solo (P0/P1 correctness, structural >250 LoC,
decision-resolved, cross-cutting) / (D) defer; structured output template;
net recommendation in 2–3 sentences with specific timing + dispatch shape.
**Do not change bd state.**

---

## Shape 5 — Fix CI failure on a specific PR

One PR has a failing check that isn't obviously irrelevant. Sections:
the failing check name (`test-gate`, `lint-gate`, `fmt`, or `memory-smoke`)
+ log lines verbatim; 2–3 root-cause hypotheses; worktree at
`<WORKTREE_ROOT>/<branch-name>-fix` checking out the existing branch (not a
new one); boundary block; investigation steps; pick the fix: (A) surgical /
(B) medium / (C) skip + file follow-on bead (appropriate when stance allows
a safe-out and the fix proves deeper than the bead's scope); verify locally
(the Shape 1 quality gate, plus `scripts/smoke.sh` if the failure is in
`memory-smoke`); **push to the existing PR branch, not main**; return
under 300 words with root cause + fix chosen + verification. Diagnosis often
surfaces deeper insight than the failure log shows — test the hypothesis
before applying the fix.

---

## Shape 6 — Durable doc change (ADR, roadmap, extended-context)

One bead asks for a decision recorded or durable context refreshed, not code.
Sections: what is being settled and what stays open; source material (findings
doc, bead thread, prior ADRs on the surface); the target file **and its word
budget** — `docs/decisions/` 400 and `ai/dashboard.md` 400, both enforced by
`scripts/check-doc-budget.sh` (it does not yet cover `ai/extended-context/` —
keep new files there to ~1200 words by convention, not an enforced gate); for
a new ADR, start from `docs/decisions/_template.md`; return under 200 words
with the paths written and their before/after word counts.

Critical learnings:

- **Budget the artefact, not just the return.** Shapes 1–5 cap the worker's
  message to the mayor, which is read once. This shape caps what lands in the
  repo, which is re-read by every session that touches the surface. State the
  target file's word budget in the brief: a brief that leaves it unstated
  reliably comes back with a doc that grew.
- **Require deletions.** An all-`+` diff on an existing doc is accretion, not
  editing. `Write` the whole file rather than appending to it.
- **Words, never lines.** Do not brief a line budget: joining lines satisfies
  it with zero content change.
- **A tracked doc must never cite a bare `ai/findings/<file>.md` path.** The
  file is git-tracked only for its bead's lifetime — deleted in the close
  commit — so any checkout taken after that point (every checkout, once the
  bead is closed) resolves the path to nothing. A findings citation in a
  durable doc is a broken reference on a delay, not a pointer. Anything that
  must survive the session gets extracted into a tracked document under
  `docs/` or a tracked `ai/` subfolder; anything still open gets a bead. The
  brief must say which.
- **Only settled material becomes a durable doc.** Needs-data and deferred
  sections of a sketch are not ADR content. Name them in the brief as
  out-of-scope so the worker files beads for them instead of distilling
  half-decisions into prose that reads as settled.
- **No measurement is an acceptable rationale.** If a decision was a judgment
  call, the brief should say to name the principle applied rather than
  manufacture justification for it.

---

## Shape 7 — Review-fix round on an existing PR

A review left findings on an already-open PR; the fix needs to land as new
commits on that branch. Dispatch a FRESH worker (`isolation="worktree"`)
that checks out the EXISTING PR branch — mirrors Shape 5's worktree
convention — rather than a `SendMessage`-resume of the worker that opened
the PR. Sections: worktree at `<WORKTREE_ROOT>/<branch-name>-fix` checking
out the existing branch; boundary block; a TIGHT brief listing exact
`file:line` sites from the review, with "mirror the adjacent pattern,
LSP-jump don't full-read"; quality gates; push to the existing branch, not
main; return under 200 words with sites fixed + verification.

**Why fresh, not resume:** resuming a completed large-context worker
re-ingests its entire prior transcript COLD — the prompt cache expires
after ~5 min — so a small fix balloons to hundreds of thousands of
cumulative tokens dominated by inherited bloat. A fresh worker on a tight
brief pays only for the fix.

**Exception:** `SendMessage`-resume is fine for a small continuation still
inside the ~5-minute cache-warm window. The rule targets cold
re-ingestion, not resume itself.

---

## Lima VM protocol

### VM model

beep verifies its dataplane on real Lima Linux VMs, since the loader links
Linux-only syscalls and the eBPF verifier only exists on Linux — there is no
macOS-native way to prove a load succeeds. Unlike a large pool of
interchangeable ported/isolated slots, beep has exactly **three fixed-role
VMs**:

| VM name | Role | Driven by |
|---|---|---|
| `beep-smoke` | single-node smoke gate — a local veth-pair fixture stands in for a client | `scripts/smoke.sh --vm beep-smoke` |
| `beep-node-a` | cross-node WireGuard rig, ingress side (owns the VIP) | `scripts/smoke-wg-2node.sh --vm-a beep-node-a --vm-b beep-node-b` |
| `beep-node-b` | cross-node WireGuard rig, backend side (backend Pod + "client") | same as above |

No port table and no per-worker port flags exist for these scripts
— each takes only a `--vm` (or `--vm-a`/`--vm-b`) name, defaulting to the
table above. The isolation boundary is therefore the VM itself, not a port:
**two workers must never be assigned the same VM at the same time.** Check
`limactl list` before dispatching a second dataplane bead and confirm the
VM you're about to assign isn't already claimed by an in-flight worker.

The MCP server name mirrors the VM name: `mcp__beep-smoke__run_shell_command`,
`mcp__beep-node-a__*`, `mcp__beep-node-b__*` — already registered in
`.mcp.json` for live in-VM inspection (`bpftool map dump`, `ip -s link`,
`dmesg`). The smoke scripts still drive Lima via `limactl` directly, so the
gate holds even if an MCP server connection is down.

### Known blocker — `beep-node-a`/`beep-node-b` cross-node rig

The original blocker (`bpf_redirect` from `wg0` into `geneve0` dropped
in-kernel) is fixed by PR #9 (bead `mayor-f3ru5`). `scripts/smoke-wg-2node.sh`
now reaches a different, documented, non-flaky failure: the rig co-locates
the "client" with the backend node, so the DNAT'd forward packet gets
martian-source-dropped at `ip_rcv_finish_core` — see bead **beep-n24** for
the full evidence trail and candidate fix directions. Every step through
decap+DNAT+`REV_FLOW` population is a genuine, asserted PASS; the script's
own output ends in a documented "ROUND-TRIP: FAIL (known blocker)" rather
than a false green. Do not treat a `beep-node-a`/`beep-node-b` dispatch as
"broken" just because the final round trip fails — only escalate if a step
BEFORE that regresses, or if the failure signature differs from `beep-n24`'s
martian-source-drop.

### Verification protocol

- **Host gate always.** The Shape 1 five-command sequence
  (`cargo fmt --check` → `cargo clippy --tests` → `cargo test -p beep-common`
  → `ebpf/`'s cross-target clippy → `cargo build --release`) runs for every
  bead, dataplane or not — it's the only Linux-only-safe subset that also
  runs (partially) on a macOS dev host.
- **`scripts/smoke.sh --vm <assigned>` before opening the PR**, for any bead
  touching `ebpf/`, `common/`'s shared conntrack/map types, or `src/`'s
  map-population logic. This is what actually loads the compiled object into
  a live kernel verifier — the host gate only proves it compiles.
- **CI re-runs an equivalent round trip as `memory-smoke` on merge**
  (native on `ubuntu-latest`, no Lima/cross-build) as a backstop, so a worker
  who skips the local smoke step is still caught before landing on `main` —
  just later, and with a less specific failure than the local script gives.
- **No manual teardown needed.** `scripts/smoke.sh` and `smoke-wg-2node.sh`
  both tear down their own fixture (`smoke-remote.sh cleanup` under a `trap`
  on exit, success or failure) — unlike a pool of long-lived host processes
  that outlive a worktree, there is nothing for a worker to reap by hand
  after a dispatch. If a VM is ever left in a bad state (stuck fixture,
  stale binary), `limactl stop <vm>` + `limactl start <vm>` resets it; a full
  `limactl delete --force` + reprovision from `lima/beep.yaml` is the last
  resort, not a routine step.
- Reserve `smoke-wg-2node.sh` for beads that actually need the cross-node
  path — it's slower (two VM boots + a real WireGuard handshake) than
  `smoke.sh`, and today it can only ever confirm everything up to the
  known blocker above, never a full green.

---

## Common failure modes these patterns close

- **Mayor omits `isolation="worktree"` in Agent tool call.** Without it the
  subagent CWD stays at the repo root on branch main — causing path-resolution
  and permission bugs. Always include `isolation="worktree"` so the harness
  creates the worktree and pins the CWD to its root automatically.
- **Agents add back-compat shims by default.** Pre-alpha posture must be
  explicit in every preamble.
- **Same-file races between concurrent agents.** "Concurrent agents on
  disjoint surfaces: <list>" prevents this.
- **Two workers claim the same Lima VM.** With no port table, a second
  dataplane worker assigned the VM another worker is already using will
  collide mid-run. Check `limactl list` and in-flight dispatches before
  assigning `beep-smoke`, `beep-node-a`, or `beep-node-b`.
- **Workers leak edits into mayor checkout.** The worktree-boundary block
  is the only reliable defence.
- **Path-resolution leak on new-file Write** (especially `ai/findings/*` from
  an audit) routes the file into the mayor checkout silently → new-file
  double-check with `ls` on both paths in the worktree-boundary block.
- **Stalled agents lose analysis.** "Findings doc FIRST" recovery protocol
  salvages partial progress.
- **Clusters split when they should be one PR.** Cluster reviewer
  pre-validates dispatch shape.
- **Hot-zone files cause merge conflicts.** Explicit hot-zone list in every prompt.
- **Agents re-discover known issues.** Naming recent landings + prior
  findings docs prevents this.
- **Workers use `gh pr create` to bypass the pre-push hook.** The PreToolUse
  hook intercepts `gh pr create` and `gh pr edit` the same way it intercepts
  `git push`. Dispatch prompt must also mandate running quality gates before
  pushing so workers see failures with context, not as a hook rejection.
- **Workers pass the host quality gate but skip `scripts/smoke.sh`
  verification.** Unit/clippy gates cannot prove the verifier accepts the
  program or that the encap/decap round trip actually works. Inject the
  Lima VM protocol block and enforce local smoke-script evidence at
  return-review time for any dataplane-touching bead.
- **Workers use Python or shell tools instead of permitted built-ins.**
  `python3 -c` for JSON, `cat`/`head` for file reads, `sed`/`awk` for edits
  — all trigger permission prompts and slow the session. worker.md's Rule 6
  already covers this for every worker — no brief injection needed.
- **Workers grep `~/.cargo` vendored crate files to understand a dependency's
  API instead of using the LSP.** `get_hover` on an external symbol returns
  its signature + resolved generics + doc + docs.rs link without reading a
  file; `get_definition` jumps to the exact vendored file+line. Grepping the
  registry by hand is slower, misses resolved types, and triggers permission
  prompts — see worker.md Rule 9.
- **Agents (and the mayor) fabricate temporal claims instead of checking timestamps.**
  Observed repeatedly: an agent calls a log line "from a previous run" when it was
  20 seconds earlier in the run it just executed; the mayor asserts evidence
  "predates PR #X" without checking `mergedAt`, conflating runs across different
  binaries and chasing the wrong root cause for hours. Before any "when / before /
  after / previous / stale" claim, verify against the log timestamp, run-dir name,
  `gh pr view --json mergedAt`, or commit time. See worker.md Rule 11
  ("Evidence & time discipline") — every worker already has it, no injection needed.
- **Workers rebuild the Lima fixture by hand and stall on un-permitted tools.**
  `scripts/smoke.sh` already does the whole sequence — cross-build, VM
  bring-up, copy, run, teardown — via one allowlisted command. A worker who
  improvises `cargo zigbuild` + `limactl copy` + `limactl shell` calls by
  hand instead of invoking the script bare is reinventing (and likely
  breaking) something that already works.
- **Hook split: pre-commit checks fmt + findings/bead-id refs; pre-push runs
  the full five-command gate.** Workers who only run `cargo fmt` before
  committing will hit a clippy/test/build failure at push time with no
  stacktrace. The quality gate must run before commit, not just before push.
- **Workers re-run `cargo test`/`cargo clippy` after a green pass to
  double-check via grep.** `cargo test`'s summary line (`test result: ok. N
  passed; 0 failed;`) is authoritative; re-running piped to `grep -E
  'FAILED|ERROR'` duplicates the run for zero additional signal.
- **Workers manually re-run the quality gate right before `git push`.** They
  ran it before commit (correct), then re-run it before push "to be safe" —
  but the pre-push hook runs the exact same commands unconditionally right
  after. Net: duplicated wall-clock for zero signal.
- **Mayor "gets into the flow" and codes instead of dispatching.** The
  four-condition exception test is easy to rationalize past once the mayor has
  already read several files. The fourth condition (≤2 files read) is the
  circuit breaker. Workers have their own assigned VM with MCP access and can
  debug live. Write a better brief.
- **Workers guess at VM behaviour instead of observing it.**
  `mcp__beep-*__*` and `limactl shell <VM_NAME>` are both available. Inject
  the Lima VM protocol block for any bead touching `ebpf/`, `common/`'s
  shared conntrack/map types, or `src/`'s map-population logic.
- **Workers embed bead IDs and task refs in source comments.** These rot
  immediately as beads close and PRs age. worker.md Rule 10 bans bead IDs
  in source. Enforce it at review time — if a diff contains `(mayor-`, send
  the worker back.
- **Generic prompts produce generic work.** Always include file:line
  citations + concrete fix sketches.
- **Timing/perf PoCs asked to reproduce a "slow / pathological cost" claim
  without a wall-clock cap.** When a brief asks a worker to empirically
  confirm a pathological runtime cost, the brief MUST specify a hard
  wall-clock cap and direct the worker to demonstrate scaling via
  geometrically-increasing sizes under the cap, not by running the worst
  case to completion.
- **Findings docs leak into unrelated PRs.** A findings doc's `Bead:` header
  names the audit bead that produced it — if it rides along in an unrelated
  PR's diff, that's scope creep to catch at review time (PR-opened checklist
  item 1), not evidence the doc shouldn't have been committed.
- **Mayor force-merges through a failing check with `--admin`.** NEVER use
  `--admin`. If a check fails: read the log first. If it is a transient GitHub
  infra flake (e.g. `fatal: could not read Username`, checkout auth failure,
  runner timeout unrelated to the diff), rerun the specific job with
  `gh run rerun <run-id> --failed` and wait for green. Only merge when all
  required checks (`test-gate`, `lint-gate`, `memory-smoke`, `fmt`) are green.

## Pointers to canonical examples

These are project-specific. Record beep's own canonical examples here once
you have them:

- **Solo done well**: <bead-id + 1-line of why this is exemplary>
- **Cluster done well**: <cluster name + bead-count + a surprise the
  cluster surfaced that wasn't visible bead-by-bead>
- **Audit done well**: <audit bead-id + per-finding follow-on count +
  the analytical move that made it valuable>
- **CI fix done well**: <bead-id + the diagnosis-vs-surface-log
  distinction the worker drew>

Keep the list short. Three or four good examples teach a new mayor more
than thirty mediocre ones.
