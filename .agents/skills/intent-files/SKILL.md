---
name: intent-files
description: Discipline for INTENT.md and *.intent.md files - what belongs, where they go, how to word statements so they stay true. Use when drafting, revising, or reasoning about intent files, or when another intent skill needs the vocabulary.
---

# Intent files

An intent file records what a human has deliberately decided the software must remain.
It is human-owned and authoritative where present; `CONTRACT.md` holds the exact normative interface, `AGENTS.md` holds how agents work, tests and code realise the result.
If the repository has `docs/intent-files.md`, it is the house convention; read it once.

## Ownership

Repositories forbid agents from creating or editing intent files, so that their presence proves human design work.
Drafting on request is fine: a draft becomes intent only when the human edits and commits it.
Write drafts where the user says, otherwise outside the source tree, and say so in the handoff.
Never touch an intent file as a side effect of other work; a conflict between a change and intent is surfaced, not resolved by rewriting the intent.

## Placement

- `INTENT.md` at a crate, module, or service root that carries a role worth defending.
- `<name>.intent.md` beside one file when a single module carries a policy its crate does not.
- A shared `docs/<feature>/INTENT.md` beside `CONTRACT.md` when several components share a design; each component intent links to it, because intent applies by directory.
- Cross-cutting rules live once in the most general file; siblings refer to them.

Never one per source file.
Files are cumulative; a specific one adds to a broader one, and contradictions are for a human.

## What belongs

Two tests decide:

> If tests passed but this were violated, would the software be wrong?
> Would this matter if the contributor were human, not an agent?

Yes to the first makes a candidate; no to the second sends it to `AGENTS.md`.
Keep decisions, invariants, boundaries, security and compatibility properties, non-goals, and the reasons behind them.
Drop anything one `grep` away, anything CI enforces, exact detail the contract owns, process, history, and what the README or the path already says.
Precision may vary within a file: pin what must be exact, leave the rest as constraints; a complete specification belongs in `CONTRACT.md`.

## Writing

- One decision per bullet, reason on the next line.
- Rules over inventories; point at the authoritative list instead of copying it.
- Scope every `never`, `only`, `always` to the boundary it protects; agents read absolutes literally.
- Name exceptions beside the rule, with their removal condition.
- Observables a reviewer can check, with what they rule out; no "handles", "supports", "properly".
- True for every configuration and backend, not the one you looked at.
- Defer exact detail: "see `CONTRACT.md` §11".
- Normative present tense about the software, never about agents or a plan; "we would like" fits only behaviour deliberately not implemented yet, marked as such.
- Rationale, not history; one sentence per line; stable anchors for cross-file links.
- Before handing back, check each sentence against the code; "isn't always true" means state the actual rule.

Typical length is 10 to 40 lines: `Purpose`, `Invariants`, optionally `Scope`, `Design principle`, `Non-goals`, and a closing `> **Boundary:**` note.

Read `references/examples.md` for complete files that passed review, `references/pitfalls.md` before handing a draft back, and `references/templates.md` for skeletons and the draft handoff note.
