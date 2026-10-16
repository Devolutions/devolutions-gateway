---
name: grill-intent
description: Round-based interview that surfaces durable design intent before writing INTENT.md or *.intent.md, then drafts them with provenance. Use when the user wants to think through or bootstrap intent files rather than have them guessed from a brief.
---

# Grill for intent

Read `intent-files` first.
Intent is the human's; a draft from a vague brief is the agent's design under the human's name.
Interview until every durable decision has been answered, then draft.

## The tree

Root questions, from which everything else branches:

- **Boundary**: which unit, and what is deliberately outside it?
- **Role**: why does it exist; what is lost if it is folded into a neighbour?
- **Must remain true**: what would make the software wrong even with green tests?
- **Chosen among alternatives**: where was one way picked over a reasonable other, and why?
- **Non-goals**: what is unsupported or was cut?
- **Properties**: security, compatibility, concurrency and lifecycle, dependency boundaries, extension points.
- **Future**: which directions must not be precluded?
- **Precision**: what must be exact, and what stays a constraint for a contract or the implementation?

## Rounds

The frontier is every question whose prerequisites are settled.
Ask the whole frontier in one round, numbered, each with a recommended answer worded so "yes" accepts it:

```text
❓ **Q1** - **<title>**: <body, with choices when useful>

➡️ <recommended answer>
```

Wait for answers, recompute the frontier, repeat.
Facts are your job: look up dependencies, features, callers, and siblings before asking; decisions are the human's.

## Grill like a reviewer

- An absolute: ask which boundary it protects and what falsifies it; recommend the scoped form.
- A claim about how code works: check the code and surface disagreement; "isn't always true" means find the actual rule.
- Wishing or future tense: ask whether the behaviour exists; if so, state it normatively, otherwise mark it as not implemented.
- A rule without a reason: ask for the reason first.
- A list of variants: ask whether the rule is the list or a property each variant satisfies.
- Process ("run X after Y"): belongs in `AGENTS.md`; note and move on.
- Exact detail (fields, limits, status codes): note for a later `CONTRACT.md` (see `contract-authoring`) and return to the decision behind it.
- Design still moving (names, packaging, two shapes): say so and keep grilling; do not draft mid-churn.

Record provenance throughout: verbatim words, accepted proposals (quote the acceptance), proposals seen but undiscussed, gaps you filled.
Only the first two become intent text.

## Finish

When the frontier is empty: summarise each decision in one line with its provenance, propose placement per `intent-files`, and ask for confirmation.
Then draft per `intent-files`, with the `REVIEW.md` from its templates, run `intent-review` on the result, and hand over as drafts for the human to adopt.
