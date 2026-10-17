---
name: intent-files
description: Discipline for INTENT.md and *.intent.md files - the durable design decisions and rationale behind a component; what belongs there versus CONTRACT.md or AGENTS.md, where they go, how to word statements so they stay true. Use when drafting or revising intent files, or when another intent skill needs the vocabulary.
---

# Intent files

An intent file holds the design commitments a human has made durable: each one rules out a plausible, locally correct change that was deliberately rejected.
It is authoritative where present and optional everywhere; `AGENTS.md` constrains how contributors work, `CONTRACT.md` exists only for a surface that two independently built parties must agree on.
A component's own interface (its CLI, config, storage) with the reason it is shaped so is intent, not contract, until a named second party depends on it.
If the repository has `docs/intent-files.md`, it is the house convention.

An agent never writes intent from code or a brief, and never creates, edits, or deletes an intent file on its own; it may interview the human (`grill-intent`), record the commitments the human states in their own words, tidy them to these conventions, and hand the assembled file back for the human to confirm, since ordering, placement, and tidying are the agent's and the human has seen only the sentences.
Write drafts where the user says, otherwise outside the source tree, and say so.
When code, tests, contract, and intent disagree, report the divergence; the human decides which is wrong.

## Admission

A statement belongs when all three hold:

> Would the software be wrong if tests passed but this were violated?
> Does it rule out a plausible change a human deliberately rejected, rather than restating the contract without naming the rejected alternative?
> Could a reviewer cite it to reject a change?

If it constrains how a contributor performs the work rather than the resulting software, it is `AGENTS.md`.
"Adding a variant requires an explicit decision" is process; the intent is "a variant without an explicit mapping is rejected, never given a fallback".
A test can enforce a property without recording why it exists; the intent beside it says what the test protects, so that an agent facing a red check escalates instead of deleting the test.
Default to no file: create one only when at least one commitment passes.

## Placement

`INTENT.md` at the narrowest directory covering all governed code; `<name>.intent.md` beside one file when a single module carries a policy its component does not.
Applicable files are those in the directory and its ancestors, cumulative, and a specific file never overrides a broader one; nothing follows a link.
A design shared by several components is a part file, `INTENT.<feature>.md` or `<module>.intent.<feature>.md`, present in each governed directory; a symlink to one source keeps the parts identical, and where a symlink is not possible the copies are one text and a difference between them is a defect.
A part is read from several directories, so it names repository paths as code (`docs/agent-identity/CONTRACT.md`) rather than relative links.
A file per source file is the exception, never the default, and never mechanical.

## Shape

No mandatory sections, no title, and no length budget; one commitment may be the whole file, and intent is read on demand by directory, like a doc comment, not loaded on every task.
A flat list for a handful; topical headings only when they aid retrieval; `Overview` or `Purpose` only for a non-obvious role; `Non-goals` only for plausible, deliberately excluded behaviour.
A reason accompanies a commitment when it explains why a tempting alternative stays excluded; related commitments may share one, and reasons live in the same file as the commitments they support, never in a separate rationale document.
One meaning per verb: the declarative present or an imperative states a requirement, `should` a recommendation, `may` a permission, `can` a capability; never addressed to agents.
Everything written normatively is to be realised by the time the branch merges; what is not is marked in the sentence ("for now", "later", a `NOTE:`), so an implementer knows not to build it yet and a reviewer knows not to expect it.
Distinguish a deferral ("for now") from a non-goal ("the intention is not to"); the word tells a reader whether to expect change.
State precision in the wording (`exactly these`, `at least`, `may vary provided`, `is permitted to`) rather than labelling the file exact or broad.
Give a conditional commitment a trigger or state and one response ("when a token is deleted, …", "while a rotation is in progress, …", "if the response is lost, then …"); one condition and one outcome per sentence is what a reviewer can check and an audit can split.
Scope every `never`, `only`, `always` to the boundary it protects and name the configurations a conditional commitment applies to.
A scope sentence earns its place only when placement leaves a likely misapplication, stated once, next to the commitment it qualifies.
When the component introduces its own terms, a glossary entry per term opens with one or two sentences saying what it *is*, continues with its commitments, and ends with an example where the boundary is unclear and an *Avoid:* line where a competing word exists; a heading per term when entries carry commitments or will be cited, a flat `**Term**:` list otherwise; commitments that outgrow an entry move to their own section with a pointer from the entry.
A term belongs when this component gives it a meaning a reader could not have guessed, common word or not; a general programming concept used in its usual sense does not.
Specifics the human wants pinned (an exact set of variants, a dependency allowlist, a permitted tool, a pipeline order, a CLI's selector semantics) are intent even though they look like implementation; put them under the glossary entry of the concept they refine, or in a `<module>.intent.md` beside the one module they govern, and word them as the set or the permission.
The file still does not describe the implementation: incidental detail is the first thing a reviewer questions.
When a file grows, cut first the statement that neither changes the set of acceptable implementations nor explains why an alternative is excluded.
A commitment that will be cited in reviews may carry a short name ("the single-classification rule") so it is referred to, not restated.

`references/pitfalls.md` lists how drafts have failed review and what the maintainer said; read it before handing a draft back or when reviewing.
`references/examples.md` points at the file the maintainer wrote by hand and says what makes it work.
`references/handoff.md` has the review note and provenance table for a set of drafts.
