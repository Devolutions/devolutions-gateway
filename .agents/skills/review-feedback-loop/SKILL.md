---
name: review-feedback-loop
description: Work through findings on an open pull request from Copilot or human reviewers - fix what is substantive, answer a wrong finding with the governing intent or contract, re-request once per change, stop on unchanged-code findings or oscillation. Use when asked to address review comments or bring a pull request with outstanding findings to approval.
---

# Review feedback loop

A finding is a claim about the code; the loop ends when the claims stop changing the code, not when the reviewer runs out of them.

## Triage

- Correctness, security, intent, contract, or style the repository's rules decide: fix.
- Wrong, or in conflict with an intent file or `CONTRACT.md`: reply with the file and clause, change nothing.
- A decision no intent, contract, or brief states: escalate, because a fix is the least reviewed place for a decision to land.
- A change to an intent file, `CONTRACT.md`, or blind suite: escalate; it belongs to the pull request that owns the text.

A logic fix takes the path the original code took - worker, reviewer, lead verification - when a `lead` loop exists; a trivial fix (typo, wording, comment) is applied directly.

## Reply and re-request

Reply to each thread in one sentence with the fixing commit or the answering clause, with the repository's comment footer when one is defined.
Resolve the automated threads you fixed; leave a human's thread for the human unless the repository's convention says otherwise.
Re-request the automated reviewer once per substantive change and not after a comment-only one, since a round costs minutes and returns findings proportional to the diff it sees.

## Stop

- Findings only on code no change since the last round touched: triage and fix them, but do not re-request; hand what remains to the human, because the reviewer will keep finding them and each fix invites the next.
- A fix that reintroduces an earlier finding: escalate with both; alternating fixes converge on nothing.
- Only a human's approval remains: report the head and stop; do not poll.

Before pushing to a branch the human may also have pushed to, fetch, re-verify their commits, and force-push only with lease pinned to the head you last saw.
Record the reviewer's final verdict verbatim with the head SHA it applies to.
