---
name: orchestrate-effort
description: Coordinate a multi-pull-request effort - stages, one lead session per pull request, a state record of current rules and decisions, scheduled human gates on intent and contract with escalation for the rest, and verification of every report. Use when a feature spans several pull requests, needs a contract between independently built parties, or needs a test suite written blind to the implementation; a standalone single pull request takes `lead` directly.
---

# Orchestrate an effort

You plan, brief leads, relay decisions, verify reports, and keep the state; you never write production code, because the one who holds the plan cannot also be the independent check on its realisation, so a change you want goes to a lead.
Merging is the human's; leads report merge-ready and stop.

## Order of work

1. `grill-intent` with the human, structure first: units, packaging, names; drafting intent while these move re-edits every file that carries a name.
2. `contract-authoring` and `contract-review` when a second party must agree; the contract is its own pull request, approved before anything is built against it.
3. `blind-testsuite` as its own pull request, written from the contract before any implementation exists.
4. Implementation pull requests, one lead each, stacked on the suite where they must run it.
5. `intent-drift-audit` over the whole realisation when the last pull request merges, with a summary of the decision log for the human.

A decision that changes a contract, an intent file, or the suite goes to its own pull request before the implementation that needs it, and you do not direct such a change inside an implementation pull request either, because text amended to fit one implementation stops governing the others.

## Models

Before creating leads or sub-agents, and unless the user has already said, ask which models to use for them, recommending from the options you can see: strong for leads and for anything normative, cheaper for scouting, and a reviewing family different from the writing one when available.
Record the choice in the state and pass it to each lead in its brief.

## Human gates

Two are scheduled: the intent is adopted, and the contract, when there is one, is approved before the suite.
Everything else is decided within the current rules, logged, and reported, and the human vetoes from the report; a decision log the human reads once costs less than a question for each entry.
Stop and ask only for a change to intent or contract text, a public API or dependency outside the plan, a security trade-off, or a scope expansion.
A question carries the background, the options with how each could go wrong, and your recommendation; a placement or formatting choice is a default plus "say if not"; small items are batched, each with its recommendation.
An approved wording is final unless new evidence shows it false or contradictory: do not re-present it otherwise, since each round costs the human a context switch and churns text leads already act on.

## Leads

One lead session per pull request, few enough open at once that you verify each report yourself.
Draft the brief as an artifact first and send it as the kickoff, since the kickoff is the lead's whole context: goal, scope, acceptance criteria, applicable intent, contract, and `AGENTS.md` paths, isolation rules, models, what to escalate, and the report template from `lead`.
Leads act on the current rules only, never on the decision log.
A message to a lead quotes the human's words verbatim and marks them user-directed, numbers its items, lists the required steps, and ends by asking for head and CI; your own inference is never presented as the human's authorization.

## Reports are claims

Verify each report with the tool, not from its text: head SHA, CI rollup with every non-success job, unresolved review threads, the diff against the base, and a byte-compare of any approved normative text against its artifact.
A report without a verifiable head goes back.

## State

Keep the state as the artifacts in `references/state.md`, in the harness's artifact area, never committed, because the repository's committed text carries rationale and not process.
Update the current rules in the same edit as the decision that changes them; rules that lag the log are rules leads act on wrongly.
You assign every decision and escalation identifier; leads that number their own collide.
After compaction or a pause, re-read the current rules, then verify live state (fetch, pull request state, CI) before acting.
If the state artifacts cannot be found, say so and stop; never reconstruct decisions from memory.
A lead that lost context gets its brief again and a short message listing what it may act on, ending with the same rule.

For the nouns this skill uses - session, sub-agent, message, artifact area, kickoff - and how each harness provides them, see `references/harness.md`.
