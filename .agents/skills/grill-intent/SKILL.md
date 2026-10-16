---
name: grill-intent
description: Round-based interview that surfaces durable design intent before writing INTENT.md or *.intent.md, then drafts them with provenance. Use when the user wants to think through or bootstrap intent files rather than have them guessed from a brief.
---

# Grill for intent

Intent is the human's; a draft from a vague brief is the agent's design under the human's name.
Interview until every durable commitment has been put to the human and answered, then draft per `intent-files`.
A commitment is a statement that rules out a plausible, locally correct change the human deliberately rejects; if nothing in the interview produces one, the right outcome is no file.

## The tree

Root questions, from which everything else branches:

- **Boundary**: which unit, and what is deliberately outside it?
- **Role**: why does it exist; what is lost if it is folded into a neighbour?
- **Must remain true**: what would make the software wrong even with green tests?
- **Rejected alternatives**: where was one way picked over a reasonable other, and why does the other stay excluded?
- **Non-goals**: what is unsupported or was cut?
- **Properties**: security, compatibility, concurrency and lifecycle, dependency boundaries, extension points.
- **Future**: which directions must not be precluded?
- **Vocabulary**: which terms does this unit introduce, and what rule does each definition carry?
- **Independence**: which other party must agree to anything here, so that a `CONTRACT.md` is warranted, and which interfaces have no such party and stay intent?

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

- An absolute: ask which boundary it protects and what falsifies it; recommend the scoped form or the configurations it applies to.
- A claim about how code works that the code contradicts: surface it and ask which is wrong, the code or the claim.
- Wishing or future tense: ask whether the behaviour exists; if so state it normatively, otherwise mark it as a target.
- A tentative want ("I'd like", "I have in mind", "may"): ask whether it is a requirement, a permission, or a preference, and word it so.
- A rule without a reason: ask what alternative it excludes and why.
- A list of variants: ask whether the rule is the list or a property each variant satisfies.
- "Requires a decision", "run X after Y", anything about contributors: process; note it for `AGENTS.md` and ask for the software property behind it.
- Exact detail (fields, limits, status codes): note it for a `CONTRACT.md` if independence warrants one, and return to the decision behind it.
- Design still moving (names, packaging, two shapes): say so and keep grilling; do not draft mid-churn.

Record provenance throughout: verbatim words, accepted proposals (quote the acceptance), proposals seen but undiscussed, gaps you filled.
Only the first two become intent text.

## Finish

When the frontier is empty: summarise each commitment in one line with its provenance, propose placement, and ask for confirmation.
Then draft, write the handoff note from `intent-files/references/handoff.md`, and hand over as drafts the human adopts by approving each commitment.
When a design is shared by several components, draft it once as an `INTENT.<feature>.md` part and list the directories that will symlink to it.
