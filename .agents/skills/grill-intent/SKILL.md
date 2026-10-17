---
name: grill-intent
description: Round-based interview in which the human writes each design commitment in their own words and the agent supplies context, consequences, and verification, then drafts INTENT.md or *.intent.md with provenance. Use when the user wants to think through or bootstrap intent files rather than have them written from code or a brief.
---

# Grill for intent

Intent is the human's: the human writes each commitment, and the agent never writes intent from code or a brief.
The agent's part is to find the decisions, give the context needed to take each one, verify what the human decides, and clean up the wording to the conventions in `intent-files`, which also defines a commitment.
If nothing in the interview produces one, the right outcome is no file.

## The tree

Root questions, from which everything else branches; settle vocabulary first, because exact nouns make most commitments one sentence:

- **Vocabulary**: which terms does this unit coin, what is each, which synonyms are avoided, and what rule does each definition carry?
- **Boundary**: which unit, and what is deliberately outside it?
- **Role**: why does it exist; what is lost if it is folded into a neighbour?
- **Must remain true**: what would make the software wrong even with green tests?
- **Rejected alternatives**: where was one way picked over a reasonable other, and why does the other stay excluded?
- **Non-goals**: what is unsupported or was cut?
- **Properties**: security, compatibility, concurrency and lifecycle, dependency boundaries, extension points.
- **Future**: which directions must not be precluded?
- **Second party**: which other party must agree to anything here, so that a `CONTRACT.md` is warranted, and which interfaces have no such party and stay intent?

## Rounds

The frontier is every question whose prerequisites are settled.
When code exists that the human has not written or recently read, open with a brief before the first round: what the component is, what it does today, its backends, callers, and dependencies, in plain language and in the human's vocabulary, so that the questions can point into it instead of each restating the code.
Ask the whole frontier in one round, numbered.
Each question gives the human what they need to decide, in plain language: the part of the brief it turns on, what the options are, and how each could go wrong later; it does not recommend an answer, because a recommended answer the human accepts is the agent's design under the human's name.

```text
❓ **Q1** - **<title>**: <what is at stake, in one or two sentences>
<Today: the fact this question turns on, or where in the brief to look.>
<Options, each with how it could go wrong.>
<Write your commitment in your own words, or say "no commitment here".>
```

Wait for answers, recompute the frontier, repeat.
Facts are your job: look up dependencies, features, callers, and siblings before asking; decisions are the human's.
Offer options only when they are a closed set the facts define (the variants that exist, yes or no on what the code does today, the list it already uses, two readings of the human's own sentence), and always include "no commitment here".
Alternatives the human may not know are information, not options: mention them informally in the context with what each is good for and where it fails, so the human can widen the choice, and then let them write the commitment.
When an answer arrives, verify it against the code and the other answers; if it is false today, contradicts another commitment, or has a consequence the human may not have seen, say so with the evidence and ask them to confirm or rewrite before recording it.
Record the human's sentence; tidy it to the conventions only, keeping their words where they are exact.

## Grill like a reviewer

- An absolute: ask which boundary it protects and what falsifies it; show the sibling, feature flag, or build that would, and let the human scope it.
- A claim about how code works that the code contradicts: surface it and ask which is wrong, the code or the claim.
- Wishing or future tense: ask whether the behaviour exists; if so, ask for the sentence as a requirement, otherwise for the deferral marker.
- A tentative want ("I'd like", "I have in mind", "may"): ask whether it is a requirement, a permission, or a preference, and for the sentence that says which.
- A rule without a reason: ask what alternative it excludes and why.
- A list of variants: ask whether the rule is the list or a property each variant satisfies.
- A fuzzy or overloaded word ("account", "session"): show where the code and the conversation use it differently, and ask for the canonical term and the avoided ones.
- "Requires a decision", "run X after Y", anything about contributors: process; note it for `AGENTS.md` and ask for the software property behind it.
- Exact detail (fields, limits, status codes): note it for a `CONTRACT.md` if a second party must agree to it, and return to the decision behind it.
- Design still moving (names, packaging, two shapes): say so and keep grilling; do not draft mid-churn.

Record provenance throughout: the human's words verbatim, the human's words after tidying, and anything the agent filled in while drafting.
Only the first two become intent text; the third is listed for the human and never written as intent.

## Finish

When the frontier is empty: list each commitment in the human's words with its provenance, propose placement, and ask for confirmation.
Then draft, write the handoff note from `intent-files/references/handoff.md`, and hand the assembled file back for the human to confirm ordering, placement, and tidying.
When a design is shared by several components, draft it once as an `INTENT.<feature>.md` part and list the directories that will symlink to it.
