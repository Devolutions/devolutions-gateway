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
Applicable intent is cumulative: every `INTENT.md` from the root down to each audited directory, every `*.intent.md` beside an audited file, and every shared intent those files say applies to them.
Where a statement says "see `CONTRACT.md` §N", the contract section is the statement; when the user names a contract, audit an implementation against it directly, treating each operation's valid domain, must-support set, error mapping, and precedence as separate statements and the conformance suite's coverage of each as part of the evidence.

## Verify

Split each file into normative statements, one per bullet or sentence, skipping purpose prose, and give each a stable ID (`xtask/INTENT.md#dependencies`, `CONTRACT.md#6.3-errors`).
For each: cite `path:line`; decide **conforms**, **violates**, **partial** (some paths or configurations), **not yet realised** (the intent marks it as a target or deferral), or **cannot verify** (say what is missing); for a diff, mark **introduced**, **fixed**, or **pre-existing**.
Statements that need design judgement rather than code reading are audited only when the diff plainly bears on them, and labelled as judgement.
Note `INVARIANT:` and `UNTESTED:` comments that relate; they are the code's own claims.
"Probably fine" is cannot verify.
Check every feature set and build the statement spans.

Also report **intent rot** (names, paths, sections the intent cites that no longer exist) and **not covered** (design-level changes in the diff that no statement speaks to: new public surface, dependency, fallback, configuration).

## Report

```md
## Intent drift audit: <scope>

Audited against: `<file>` (<n> statements), ...

| ID | Statement (abridged) | Status | Evidence | Note |
|---|---|---|---|---|
| xtask/INTENT.md#dependencies | Only lexopt, anyhow, xshell, tinyjson | Violates (introduced) | `xtask/Cargo.toml:14` | adds `serde_json` |

### Violations
<Per violation: what intent requires, what the code does, smallest conforming change as a proposal.>

### Intent rot
### Not covered by intent
```

Lead with violations and partials, then cannot verify, then not yet realised, then conforms.
A clean audit is two lines plus the table.
When the human wants the mapping kept, the table becomes an `EVIDENCE.md` beside the intent, one row per claim with the directive, intent line, and code paths that realise it and `[unsure]` on inferred rows.

When the audit runs because you are about to change governed code, a violation you would introduce is a stop: surface the statement ID, evidence, and options to the human.
