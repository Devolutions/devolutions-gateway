---
name: contract-review
description: Review a normative CONTRACT.md for overreach, unspecified failure paths, duplicated lists, examples standing in for rules, one-implementation bias, and untestable wording; returns findings with proposed rewordings, never edits. Use when asked to review, critique, tighten, or prepare a rewrite of a contract or protocol specification.
---

# Contract review

A contract is implemented and tested by parties who read only it, so every ambiguity becomes a divergence between implementations.
Output is findings and proposals; the human decides, and semantic changes land in their own PR ahead of code.

## Gather

State the revision reviewed.
Collect the contract, the `INTENT.md` it serves, the conformance suite or test vectors derived from it, and each implementation.
Run every state-changing operation through the gap questions in `contract-authoring/references/critique-lenses.md`; `contract-authoring/references/patterns.md` lists what earlier reviews had to fix.

## Lenses

Apply each to every normative sentence; quote it.

- **Party**: which second party in scope must agree to this sentence?
  None means it is one party's own realisation (config, storage, CLI) and belongs in that party's intent file.
  Parties and example implementations are named without schedule ("e.g.: DVLS, PSU", never "DVLS now, PSU later"); timeline is not contract.
- **Overreach**: a claim stronger than the mechanism guarantees ("prevents oracles" for "does not say which check failed"); propose the narrowed form.
- **Open set**: an error, outcome, or input class not drawn from a closed, defined set; "bad input" is not a classification.
- **Order for precedence**: an evaluation order where only which-outcome-wins matters, or two outcomes equally valid for one input.
- **Unowned field**: a stored field with no statement of who initialises it and which operations update it or must not.
- **Second copy**: a list, mapping, or encoding defined twice; keep one and point.
- **Example as rule**: a transcript or template whose free aspects (order, case, whitespace) are not stated; propose the statement and vectors that vary them.
- **One-implementation bias**: a library's behaviour, a number, or a rationale true for one backend; ask whether it was written to fit one implementation.
- **Unmeasured cause**: a rationale citing a mechanism nobody measured.
- **Untestable**: "handles", "supports", "properly", a condition without a stated outcome, or two outcomes in one sentence; propose an observable with a bound and the conformance case that checks it.
- **Scope creep**: admin, UI, mock control, implementer choices, or any section that neither constrains a party in scope nor is exercised by a conformance test; propose the owning component's intent file or deletion.
- **Intent gap**: a rule the contract needs that `INTENT.md` lacks; the human amends the intent first.

## Report

Order by consequence: party and unspecified failure paths, then overreach, open sets and second copies, then wording.

```md
### <N>. <lens> — §<section>

> <quoted sentence>

<Why, citing an implementation, a test, or the intent when relevant.>

**Proposed:** <reworded sentence>, or move to <section or artifact>, or delete.
```

Close with what is strong as written, the questions only the human can settle, and a verdict: freeze, freeze after corrections, or rewrite.
