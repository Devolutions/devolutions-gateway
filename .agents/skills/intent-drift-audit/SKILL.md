---
name: intent-drift-audit
description: Audit code, a diff, or a PR against the applicable INTENT.md, *.intent.md, or CONTRACT.md and report conforms, violates, partial, or cannot-verify per statement with file:line evidence, ready for a PR comment. Use for intent or contract conformance checks, automated review, or before modifying governed code.
---

# Intent drift audit

Intent and contracts hold even when tests pass, so this audit reads code against each statement with evidence instead of trusting the suite.
It reports; it never edits intent or contract and never silently fixes code during a review.

## Scope

Paths under audit: the diff, the named crate or module, or the subtree.
State which revision you audited; if the checkout may be behind, fetch intent and code from the remote default branch or the PR head.
Applicable intent is cumulative: every `INTENT.md` and `INTENT.<feature>.md` from the root down to each audited directory, and every `*.intent.md` or `*.intent.<feature>.md` beside an audited file.
Where a statement says "see `CONTRACT.md` §N", the contract section is the statement; when the user names a contract, audit an implementation against it directly, treating each operation's valid domain, must-support set, error mapping, and precedence as separate statements and the conformance suite's coverage of each as part of the evidence.

## Verify

Split each file into normative statements, one per bullet or sentence, skipping purpose prose; a sentence about an external producer or environment is context for the statements that depend on it, not a statement.
Give each an ID of section plus ordinal (`xtask/INTENT.md#dependencies-1`, `CONTRACT.md#6.3-2`) so a later audit can diff against this one.
A statement marked as deferred or prospective ("for now", "later", `NOTE:`) is a target, not a requirement; the implementation is expected not to realise it yet, and realising it anyway is worth a note.
For each: cite `path:line`; decide **conforms**, **violates**, **partial** (honoured on some paths, configurations, or the primary path and bypassed on another), **not yet realised** (a deferred target the code does not implement, which is the expected state), or **cannot verify** (say what is missing); for a diff, mark **introduced**, **fixed**, or **pre-existing**.
Statements that need design judgement rather than code reading are audited only when the diff plainly bears on them, and labelled as judgement.
Note `INVARIANT:` and `UNTESTED:` comments that relate; they are the code's own claims.
"Probably fine" is cannot verify.
When a statement's span is feature-gated or build-specific, check each variant.

Also report **intent rot** (names, paths, sections the intent cites that no longer exist, and plan tense for behaviour that now exists) and **not covered** (behaviour no statement decides: in a diff, new public surface, dependency, fallback, or configuration; in a module audit, any path that looks like a design choice or a latent defect).

## Report

```md
## Intent drift audit: <scope>

Audited against: `<file>` (<n> statements), ...

| ID | Statement (abridged) | Status | Evidence | Note |
|---|---|---|---|---|
| xtask/INTENT.md#dependencies-1 | Only lexopt, anyhow, xshell, tinyjson | Violates (introduced) | `xtask/Cargo.toml:14` | adds `serde_json` |

### Violations
### Partials
<Per entry: what intent requires, what the code does, smallest conforming change as a proposal.>

### Cannot verify
### Not yet realised
### Intent rot
### Not covered by intent
```

Lead the table with violations and partials, then cannot verify, then not yet realised, then conforms; drop empty sections.
A clean audit is two lines plus the table.
When the human wants the mapping kept, the table becomes an `EVIDENCE.md` beside the intent, one row per claim with the directive, intent line, and code paths that realise it and `[unsure]` on inferred rows.

When the audit runs because you are about to change governed code, a violation you would introduce is a stop: surface the statement ID, evidence, and options to the human.
