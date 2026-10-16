---
name: intent-files
description: Discipline for INTENT.md and *.intent.md files - what belongs, where they go, how to word statements so they stay true. Use when drafting, revising, or reasoning about intent files, or when another intent skill needs the vocabulary.
---

# Intent files

An intent file holds the design commitments a human has made durable: each one rules out a plausible, locally correct change that was deliberately rejected.
It is authoritative where present and optional everywhere; `AGENTS.md` constrains how contributors work, `CONTRACT.md` exists only when a surface must be implemented or tested independently of one implementation.
If the repository has `docs/intent-files.md`, it is the house convention.

Agents may draft on request but never create, edit, or delete intent files on their own; a draft becomes intent when a human has approved each commitment, not merely committed the file.
Write drafts where the user says, otherwise outside the source tree, and say so.
When code, tests, contract, and intent disagree, report the divergence; the human decides which is wrong.

## Admission

A statement belongs when all three hold:

> Would the software be wrong if tests passed but this were violated?
> Does it rule out a plausible change a human deliberately rejected, in a way a maintainer could not cheaply recover from code, manifest, or contract?
> Can it be falsified, and is it consequential enough that violating it should stop a change?

If it constrains how a contributor performs the work rather than the resulting software, it is `AGENTS.md`.
"Adding a variant requires an explicit decision" is process; the intent is "a variant without an explicit mapping is rejected, never given a fallback".
Default to no file: create one only when at least one commitment passes.

## Placement

`INTENT.md` at the narrowest directory covering all governed code; `<name>.intent.md` beside one file when a single module carries a policy its crate does not.
Applicable files are cumulative and a specific file never overrides a broader one; a shared `docs/<feature>/INTENT.md` governs a component only when that component's own intent says so in a sentence, not through a bare link.
Never one per source file, never mechanically.

## Shape

No mandatory sections; one commitment may be the whole file.
A flat list for a handful; topical headings only when they aid retrieval; `Purpose` only for a non-obvious role; `Non-goals` only for plausible, deliberately excluded behaviour.
A reason accompanies a commitment when it explains why a tempting alternative stays excluded; related commitments may share one.
State precision in the wording (`exactly these`, `at least`, `may vary provided`) rather than labelling the file exact or broad.
Normative present tense about the software, never about agents; `must not` only where a declarative sentence would be ambiguous; an unimplemented target is marked as such.
Scope every `never`, `only`, `always` to the boundary it protects and name the configurations a conditional commitment applies to.
A scope sentence earns its place only when placement leaves a likely misapplication, stated once, next to the commitment it qualifies.
A small exact table is intent only when the closed set itself is the decision and nothing else owns it.
An implementation detail (an ordering, a helper, a layout) is intent when a human chose to pin it and says why; the file should not become a description of the implementation, and incidental detail is the first thing a reviewer will question.
When a file grows, cut first the statement that neither changes the set of acceptable implementations nor explains why an alternative is excluded.

`references/pitfalls.md` lists how drafts have failed review and what the maintainer said; read it before handing a draft back or when reviewing.
`references/examples.md` points at files the maintainer wrote himself and says what makes each work.
`references/handoff.md` has the review note and provenance table for a set of drafts.
