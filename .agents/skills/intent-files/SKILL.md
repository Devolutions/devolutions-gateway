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
> Could a reviewer cite it to reject a change?

If it constrains how a contributor performs the work rather than the resulting software, it is `AGENTS.md`.
"Adding a variant requires an explicit decision" is process; the intent is "a variant without an explicit mapping is rejected, never given a fallback".
Default to no file: create one only when at least one commitment passes.

## Placement

`INTENT.md` at the narrowest directory covering all governed code; `<name>.intent.md` beside one file when a single module carries a policy its crate does not.
Applicable files are cumulative and a specific file never overrides a broader one; a shared `docs/<feature>/INTENT.md` governs a component only when that component's own intent says so in a sentence, not through a bare link.
Never one per source file, never mechanically.

## Shape

No mandatory sections and no title; one commitment may be the whole file, and a new component's intent may run to a hundred lines when the commitments are many.
A flat list for a handful; topical headings only when they aid retrieval; `Overview` or `Purpose` only for a non-obvious role; `Non-goals` only for plausible, deliberately excluded behaviour.
A reason accompanies a commitment when it explains why a tempting alternative stays excluded; related commitments may share one.
Normative in any mood (declarative, imperative, `must`, `should`); never plan tense, never addressed to agents.
Distinguish a deferral ("for now") from a non-goal ("the intention is not to"); the word tells a reader whether to expect change.
State precision in the wording (`exactly these`, `at least`, `may vary provided`, `is permitted to`) rather than labelling the file exact or broad.
Scope every `never`, `only`, `always` to the boundary it protects and name the configurations a conditional commitment applies to.
A scope sentence earns its place only when placement leaves a likely misapplication, stated once, next to the commitment it qualifies.
When the component introduces its own terms, a glossary (one heading per term, one to three sentences, an example) can carry the rules inside the definitions: "A missing requirement is an error, not an applicability skip."
Specifics the human wants pinned (an exact set of variants, a dependency allowlist, a permitted tool, a pipeline order, a CLI's selector semantics) are intent even though they look like implementation; put them under the glossary entry of the concept they refine, or in a `<module>.intent.md` beside the one module they govern, and word them as the set or the permission, never as "things I have in mind" or "may be used", which read as optional.
The file still does not describe the implementation: incidental detail is the first thing a reviewer questions, and doubt about where a statement belongs goes in the PR.
When a file grows, cut first the statement that neither changes the set of acceptable implementations nor explains why an alternative is excluded.

`references/pitfalls.md` lists how drafts have failed review and what the maintainer said; read it before handing a draft back or when reviewing.
`references/examples.md` points at the file the maintainer wrote by hand and says what makes it work.
`references/handoff.md` has the review note and provenance table for a set of drafts.
