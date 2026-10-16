---
name: intent-review
description: Review INTENT.md and *.intent.md files or drafts for contradictions, unscoped absolutes, misplaced content, rot, and missing rationale; returns findings and proposed rewordings, never edits. Use when asked to review, check, or tighten intent files.
---

# Intent review

Read `intent-files` first.
Agents read intent literally, so an unscoped "never" or a stale reference becomes a wrong implementation later.
Output is findings and proposals; the human applies them.

## Gather

State which revision you reviewed; if the checkout may be behind, fetch the file from the remote default branch and say which findings apply to which version.
Collect the files under review plus everything that applies cumulatively: broader `INTENT.md` up the tree, shared `docs/<feature>/INTENT.md` they link to, the `CONTRACT.md` they defer to.
Contradictions mostly live between files.
Read the governed code, not just the intent: the manifest, public surface, features, and configurations; most false absolutes are found there.
Load `intent-files/references/pitfalls.md` as the checklist; skip its templates.

## Lenses

Apply each to every normative sentence; quote the sentence in the finding.

- **Contradiction**: two statements that cannot both hold, including a specific file quietly narrowing a broader one.
- **Unscoped absolute**: `never`, `always`, `only`, `every`; which boundary, and does a sibling, feature flag, backend, or build falsify it?
- **Unverified universal**: "every library does X" with no cited check.
- **Plan tense**: "we would like", "will be extended", "we now want" for behaviour that already exists; a file that narrates the task that produced it reads like a ticket body.
- **Wrong artifact**: process and anything phrased in terms of agents to `AGENTS.md`; exact fields, limits, statuses, check order to the contract; history to rationale or deletion.
- **Restatement**: repeats the contract, a sibling, the README, the path, or what CI enforces; "does that belong to this crate?"
- **Enforced but unwritten**: a wire format, state machine, or ordering the code enforces that no document states; propose where it belongs.
- **Inventory**: a list the code owns; propose the rule form or a pointer.
- **Implementation leak**: helper names, layout, one library's behaviour or numbers as a general rule.
- **Missing reason**: a rule a contributor could plausibly "fix".
- **Not checkable**: "handles", "supports", "properly"; propose an observable with a bound.
- **Dangling reference**: removed rule still named, link or anchor that does not resolve, renamed symbol; verify against the tree.
- **Missing boundary**: module file with no scope, or an obvious misreading not pre-empted.
- **Duplication across siblings**: state once in the most general file.
- **Style**: soft wraps, uppercase MUST in a declarative repository, decision IDs, session or approver names.

## Report

Order by consequence: contradictions and false absolutes, then wrong artifact and restatement, then style.

```md
### <N>. <lens> — `<file>`

> <quoted sentence>

<Why, citing code or another file when relevant.>

**Proposed:** <reworded sentence>, or move to `<artifact>`, or delete.
```

Close with what is strong as written, the questions only the human can settle, and a one-line verdict: adopt, adopt after corrections, or rework.
When two readings are plausible and the code does not settle which is intended, file a question rather than a finding.
A clean file gets a short report.
