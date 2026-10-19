---
name: review-feedback-loop
description: Work through review findings on an open pull request from Copilot or human reviewers - fix what is substantive, answer a wrong finding with the governing intent or contract, re-request one round per change, and stop when findings land on unchanged code or oscillate. Use when asked to address existing review comments, loop with Copilot review after findings exist, or bring a pull request with outstanding findings to approval.
---

# Review feedback loop

A finding is a claim about the code; the loop ends when the claims stop changing the code, not when the reviewer runs out of them.

## Triage each finding

- Correctness, security, intent, or contract: fix it.
- Style the repository's rules decide: fix it.
- Wrong, or in conflict with an intent file or a `CONTRACT.md`: reply with the file and clause, change nothing.
- A decision no intent, contract, or brief states: escalate; do not settle it in the fix, because a fix is the least reviewed place for a decision to land.
- A request to change an intent file, a `CONTRACT.md`, or a blind suite: escalate; those changes have their own pull request.

A logic fix takes the same path the original code took - worker, reviewer, and the lead's verification when a `lead` loop exists; a trivial fix (typo, wording, comment) is applied directly.

## Reply and re-request

Reply to each thread in one sentence with the commit that fixed it or the clause that answers it, with the repository's comment footer when one is defined.
Resolve the threads you fixed from an automated reviewer; leave a human's thread for the human unless the repository's convention says otherwise.
Re-request the automated reviewer once per substantive change, and not after a comment-only change, since a round costs minutes and returns findings proportional to the diff it sees.

## Stop

- When a round's findings sit only on code no change since the last round touched, triage and fix them as above but do not re-request; hand what remains to the human, because the reviewer will keep finding them and each fix invites the next.
- When a fix reintroduces an earlier finding, stop and escalate with both findings; alternating fixes converge on nothing.
- When a human's approval is what remains, report the head and stop; do not poll.

Before any push to a branch the human may also have pushed to, fetch, re-verify their commits, and force-push only with lease pinned to the head you last saw.
Record the reviewer's final verdict verbatim and the head SHA it applies to in the report.
