# The Mayor Method

Most people use AI coding tools as if the chat window were the whole team.

They ask one session to design the feature, read the repo, write the patch,
debug the tests, do some investigation, remember the decisions, open the PR, review the PR, and then
somehow still know what happened four hours later. This works for toy tasks
and demos. It falls apart on real projects, for the utterly boring reason that one
context window is not a project-management system.

The Mayor Method is the workflow I use for non-trivial AI-assisted work. 

## Inspiration 

The inspiration is [Gastown](https://github.com/gastownhall/gastown). I do not
use Gastown directly, but the shape came from studying it. Credit lands there.

## TLDR

Prompt engineering and context management are still the keys. 

- One long-lived AI session is the **mayor**.
- Many short-lived AI sessions are **workers**.
- [Beads](https://github.com/gastownhall/beads) are used to work.
- Prompts are treated very seriously.
- Git worktrees isolate workers.
- `/ai/dashboard.md` keeps me oriented.
- I make the important calls.

The rest is good discipline.


## The mayor does not code

The mayor's job is to stay oriented and to coordinate.

It talks to you. It knows you, your processes, and your goals. It files beads.
It dispatches background workers. It reviews their output. It merges PRs when
CI is green. It records decisions in beads.

I guard the mayor's context like a jealous lover. It must **not** burn its
context window implementing features.

This is the part everyone struggles with, because watching the mayor code
feels productive. It is not. It is like asking the air-traffic controller to
leave the tower and help unload bags. For five minutes, sure, a few bags
move. Then the planes start doing interesting things.

Workers do the work. They get a tight brief, a worktree, and one bounded
task. They spend their context window on that task, report back, and become
disposable. The mayor remains.


## Prompts are the work

An AI implementation is only as good as the prompt behind it. So do not
leave the prompt in chat. Put it in `/ai/prompts/` and iterate on it.

Good use of AIs is all about prompt engineering and context management.
Nothing much has changed there for two years.

The workflow is:

1. Write the prompt.
2. Stress-test the prompt.
3. Fix the prompt.
4. Fix the prompt some more.
5. Turn the prompt into a bead.
6. Get a background agent to action the bead.

If the AI does the wrong thing, that's on you.

You are dealing with a 12-year-old savant. It can do a staggeringly good job
if it is given the right guidance. If it does the wrong thing, you didn't
get the guidance right.

## How to write a prompt with the mayor

Put implementation prompts under `/ai/prompts/`. Some will be spec-like.
The point is that they are durable instructions for an AI, not chat exhaust.

Start with:

> I want to write an RFC-grade implementation prompt for X. Create
> `/ai/prompts/X.md`. Do not implement anything yet. Interview me until the
> problem is crystal clear.

Then make the mayor work:

- Ask it where the prompt is ambiguous.
- Ask it which cases are missing.
- Ask it what the repo already does in nearby areas.
- Ask it what could go wrong.
- Ask it to restate the problem in two sentences.

A terminology section is usually worth it. So is a list of in-scope and
out-of-scope changes.

The prompt is ready when a worker can read it cold and know what to do, and
when you can read it aloud without internally adding "...well, obviously I
meant..." after every second paragraph.

## The `/ai` directory

Keep AI working material out of the product tree:

- `/ai/prompts/` — durable AI instructions: implementation, decision, review.
- `/ai/findings/` — audits, research notes, design drafts, second opinions.
  **Git-tracked under bead lifecycle** (see below).
- `/ai/extended-context/` — durable project context not obvious from code.
  The mayor consults it on bootstrap and contributes on retrospectives.
- `/ai/dashboard.md` — my dashboard.

## Findings lifecycle

Findings are named `ai/findings/<YYYY-MM-DD>-<bead-id>-<slug>.md` and start
with `Bead: <bead-id>` in their first 5 lines — a pre-commit hook rejects
new findings without it.

A finding is committed alongside the bead's work, referenced from the
bead's notes, and deleted from the working tree in the close commit. Git
history is the archive — retrieve a removed finding with `git show
<sha>:ai/findings/<file>.md`.

Pre-convention files live in `ai/findings/legacy/`, which stays gitignored
until migrated to this scheme.

## Beads are the work queue

Use [beads](https://github.com/gastownhall/beads) for task tracking. Every
real piece of work becomes a bead.

A good bead says:

- what is wrong or missing;
- where to look (file:line where possible);
- what should change (a sketch is fine; a fix is great);
- what counts as done;
- what tests or checks matter;
- what not to touch.

Workers do not get vibes. They get beads. Vague beads produce vague PRs.

Beads also have memories: `bd remember` stores project-shaped insights that
outlive the current mayor; `bd memories <topic>` retrieves them. Use them
for the operations knowledge a fresh mayor would otherwise rediscover at
2 a.m.



## You still own the hard calls

The mayor can explain options. Workers can explore options. Another model
can review options.

But policy calls, product calls, taste calls, and "what kind of project
is this trying to be?" calls belong to me.

The mayor should surface those decisions clearly:

> Bead X is blocked on a design choice. Option A is smaller. Option B is
> cleaner. Option C is safer but changes the public surface. My
> recommendation is B because ...

Then I decide, and the mayor records the decision in the bead.

That recording step is not paperwork. It is how future agents inherit your
judgment instead of rediscovering the same argument at 2 a.m.

## Verification: the quality gate and the Lima rig

beep's dataplane is eBPF that only builds and runs on Linux, so "the tests
pass" means two different things depending on host.

The **canonical 5-command quality gate** (from `.github/workflows/ci.yaml`'s
`fmt`, `lint-matrix`, `test-matrix`, and `memory-smoke` jobs, byte-exact) is:

1. `cargo fmt --check`
2. `cargo clippy --tests -- -D warnings`
3. `cargo test -p beep-common`
4. `cd ebpf && cargo clippy --release --target bpfel-unknown-none -Z build-std=core -- -D warnings`
5. `cargo build --release`

Steps 2, 4, and 5 need a Linux toolchain and `bpf-linker`; on macOS only the
**macOS-host subset** — `cargo fmt --check` and `cargo test -p beep-common`
— runs. Workers on macOS run the subset locally and let CI's `fmt` +
`lint-gate` + `test-gate` + `memory-smoke` jobs enforce the full gate on the PR.

For beads that touch the dataplane, the gate alone is not enough — it
proves the eBPF program compiles, not that it loads and forwards packets.
Verify those on **Lima Linux VMs**: `beep-smoke` is the single-node smoke
gate (`scripts/smoke.sh`), and `beep-node-a` + `beep-node-b` are a
same-network pair for cross-node WireGuard verification — currently the
known-blocker path (bead `beep-n24`). Agent-driven in-VM inspection
(`bpftool map dump`, `ip -s link`, `dmesg`) goes through the `mcp__beep-*`
MCP tools registered for each VM.

## PRs are the gate

Workers may open PRs. The mayor merges them.

Before merging, the mayor checks:

- the diff matches the bead;
- scope did not sprawl;
- failure output remains actionable;
- required checks are green — the merge queue enforces `test-gate`,
  `lint-gate`, `memory-smoke`, and `fmt` on every PR to `litehop/beep`, so
  "CI is green" means all four, not just a subset;
- bead state will be updated after merge.

After merge, the mayor pulls main, closes the bead with a concrete reason,
and updates `/ai/dashboard.md`.

This is the difference between "a lot of agents did things" and "the
project advanced."

## Cross-review

Use another model for second opinions. Do not let it become a second
mayor.

The useful prompt is:

> Review XXX (recent check-ins? repo security? design?). For each actionable issue, file or propose a bead as a
> suggestion. Do not implement. Do not override existing decisions. Frame the bead you create as a suggestion

Different models notice different things. That is useful. But one
authority must decide what lands, or the project becomes a committee made
of weather.

On beep, this same principle runs automatically on every worker PR: a
reviewer app (GitHub App id 4746811, posting as `litehop-reviewer[bot]`)
reviews the diff and posts findings under a load-bearing marker header,
`## critical-reviewer findings`, verbatim. The mayor treats that review the
same way it treats a human second opinion — informative, not authoritative
— and still makes the merge call itself.

## Checkpoints

Every so often, stop and run two reviews.

**First**, ask the mayor for a retrospective:

> What information not already recorded in the code or beads would have
> been helpful to have had before we started this session? What's not
> obvious from the code alone? Capture that information in a file within
> `/ai/extended-context/` if it is not already present. Ensure you are not
> creating a duplicate. Structure your insight like an AI Skill, with
> front matter and then a body. Give the file a good expressive name;
> long is fine. Itemise it in the README.

**Second**, ask the mayor to spawn independent reviewers against recent
commits:

> Regarding the recent commits, spawn agents to review independently for:
> - identify hot spots for performance, and see if they can be improved, but not at the expense of clarity;
> - completeness;
> - correctness;
> - clarity and simplicity;
> - best practice;
> - test coverage and rigour;
> - comments and explanation;
> - documentation updates, including READMEs and changelogs;
> - backwards compatibility, where it matters.
>
> Create beads for each actionable observation. Then cluster beads by
> surface area for potential actioning. 

Different lenses find different issues.

## Standing prompts

The cron prompts I register with the scheduler are defined in
[`mayor-bootstrap.md`](../../ai/prompts/mayor-bootstrap.md) — a single flat pasteable prompt, not
separate documents. It sets up beep's three standing `/loop` cadences —
15-minute `mayor-tick` (dispatch review + serialize merges through the
merge queue), 60-minute `reread` (re-absorb this posture), and 60-minute
`worktree-hygiene` (prune stale `ai/worktrees/<name>` / `worker/<name>`
branches) — and inlines the worktree-hygiene loop body directly; the rest
point to their canonical bodies in
[`mayor-dispatch-template.md`](../../ai/prompts/mayor-dispatch-template.md). Register
the prompt once with your local scheduler; let the cadence carry the loop.



## Ready to run it

If you've read this far and want to actually try the method, the
pasteable prompt is [`mayor-bootstrap.md`](../../ai/prompts/mayor-bootstrap.md). It's terse —
deliberately — and it expects you've absorbed the philosophy above
first. Paste it into a fresh AI session as your opening message;
the mayor takes it from there.

Two siblings carry the operational detail you'll need once the mayor
is running:

- [`mayor-dispatch-template.md`](../../ai/prompts/mayor-dispatch-template.md) — the
  canonical worker-prompt shapes (solo / cluster / audit /
  cluster-reviewer / CI-fix) and the worktree-boundary block that must
  go into every editing dispatch verbatim.
- [`mayor-bootstrap.md`](../../ai/prompts/mayor-bootstrap.md) — re-read on cadence; it carries
  the three `/loop` blocks the mayor registers with its scheduler,
  each with its own inline operating manual.


## Warnings

You'll need to be in yolo mode. Sandbox appropriately.

This is not free. You will spend tokens, a lot of them, and you'll need
a Claude Max plan, 5x or better.

Also: this is a single-player method. Teams need more protocol, more
explicit ownership, and probably less cowboy orchestration.

But for one person trying to move a serious project quickly without
losing the plot, it works.

The mayor does not make the project good. You still have to do that.

It just keeps the city from burning down while the workers build it.
