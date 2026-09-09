# Docs Style Guide

Governs future user-facing docs — README, install/operator guides, design
docs, and other docs written for people setting up or operating beep. It
does not require rewriting docs that already exist; apply it going forward
and whenever an existing doc is next substantially edited.

Base: [Google's developer documentation style guide](https://developers.google.com/style).
This distills the subset that matters for a small infra project into
beep's own voice.

Agents read and maintain these docs at least as much as humans do.
Machine-parseable structure — fenced code blocks, numbered steps,
consistent headings — is load-bearing here, not a nicety: it is what
lets an agent parse and safely edit a doc without misreading its
structure.

## Rules

1. **Second person.** Write "you attach the tc-bpf classifier," not "the
   operator attaches the tc-bpf classifier" or "developers can attach."
2. **Active voice.** "The loader programs the VIP-to-backend map," not
   "the VIP-to-backend map is programmed by the loader."
3. **Present tense.** Describe what the system does now, not what it
   will or would do. Reserve "will" for ADR consequences, not
   how-to docs.
4. **Short, single-purpose sentences.** One claim per sentence. Split
   compound sentences joined by "and" or "which" when each half stands
   alone.
5. **One term per concept, everywhere.** Pick a single name for each
   thing — e.g. "backend," not "endpoint," "upstream," and "target"
   interchangeably — and use it in every doc.
6. **Fence every code and CLI example, with a language tag.** Never
   inline a command or config snippet in prose; use ` ```bash `,
   ` ```yaml `, or ` ```rust ` as appropriate.
7. **Numbered lists for procedures.** Any sequence a reader executes
   step by step is a numbered list, never narrative prose.
8. **Consistent heading hierarchy.** Do not skip levels (no `####`
   directly under `##`). A heading's children sit exactly one level
   down.
9. **Prescriptive phrasing.** "Pin the program under the bpffs directory
   before attaching it," not "some operators pin the program first."
10. **No minimizing words.** Avoid "just," "simply," "easily," and
    "obviously" when describing a step — if it needed documenting, it
    wasn't trivial to the reader. (The adverbial "just" meaning "only,"
    as in "decaps just the Geneve header," is fine; the ban targets
    minimizing a step's difficulty, not the word itself.)
11. **Depart from any rule above when it makes a doc clearer.** These
    are defaults, not a lint gate — judgment beats mechanical
    compliance.
