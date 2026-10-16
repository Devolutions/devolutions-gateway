---
name: intent-drift-audit
description: Audit code, a diff, or a PR against the applicable INTENT.md and *.intent.md files and report conforms, violates, partial, or cannot-verify per statement with file:line evidence, ready for a PR comment. Use for intent conformance checks, automated review, or before modifying governed code.
---

# Intent drift audit

Read `intent-files` first.
Intent holds even when tests pass, so this audit reads code against each statement with evidence instead of trusting the suite.
It reports; it never edits intent and never silently fixes code during a review.

## Scope

Paths under audit: the diff, the named crate or module, or the subtree.
State which revision you audited; if the checkout may be behind, fetch the intent files and the code from the remote default branch or the PR head.
Applicable intent is cumulative: every `INTENT.md` from the root down to each audited directory, every `*.intent.md` beside an audited file, and every shared `docs/<feature>/INTENT.md` they link to.
Where a statement says "see `CONTRACT.md` §N", the contract section is the statement.

## Checklist

Split each file into normative statements, one per bullet or sentence; skip purpose prose.
Give each a stable ID (`streaming.intent.md#A3`).
Classify before reading code:

- **Static**: readable from code or manifests (dependency bans, "classified once", "features are additive").
- **Behavioural**: needs a traced path or a targeted check ("rejected before the upgrade", "replay changes no state").
- **Judgement**: needs design knowledge; audit only when the diff plainly bears on it, and label it as such.

## Verify

For each statement: cite `path:line`; decide **conforms**, **violates**, **partial** (some paths or configurations), or **cannot verify** (say what is missing); for a diff, mark **introduced**, **fixed**, or **pre-existing**.
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
| streaming.intent.md#A3 | No extension mapping outside `RecordingFileType` | Violates (introduced) | `src/streaming.rs:142-150` | compares `.webm` as a raw string |

### Violations
<Per violation: what intent requires, what the code does, smallest conforming change as a proposal.>

### Intent rot
### Not covered by intent
```

Lead with violations and partials, then cannot verify, then conforms.
A clean audit is two lines plus the table.

When the audit runs because you are about to change governed code, a violation you would introduce is a stop: surface the statement ID, evidence, and options to the human.
