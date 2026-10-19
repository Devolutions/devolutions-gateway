---
name: contribute
description: Choose the delivery flow for a piece of work by its scale - a test-first fix in place, one pull request led with sub-agents, or a multi-pull-request effort with an orchestrator - and name where the intent, contract, test, and review skills enter it. Use at the start of any non-trivial change, or when the user asks how to approach, structure, or stage a piece of work.
---

# Contribute

Every flow here is the same loop at a different scale: decide what must hold, write the check that fails without it, make it pass, and have someone who did not write it review.

## Pick the smallest flow that fits

| Flow | When | Run |
|---|---|---|
| Fix | One behaviour at one seam; every decision it needs is already in the intent, the contract, or the bug report | `tdd` in this session, then the repository's review skill (`code-review` where provided) before the pull request |
| Change | One pull request; may raise a design decision, needs more than one pair of hands | `grill-intent` for any decision no intent file states, then `lead` |
| Effort | Several pull requests, or a second party that must agree on an interface, or a suite that must be written blind | `orchestrate-effort` |

Start with the smallest flow and promote when a signal appears, because each tier adds sessions and context to keep in step.
A decision no intent file states, met mid-fix, promotes to Change: stop and run `grill-intent`; do not settle it in the test or the code, since the first place a decision lands becomes the text everything else is bent to.
A second party, or a change to a `CONTRACT.md`, promotes to Effort: the contract is its own pull request before the code that realises it.

## Where the other skills enter

- `intent-files` governs any path with an applicable intent file; read them before the first edit in every flow.
- `contract-authoring` and `contract-review` when two independently built parties must agree; the contract precedes its first implementation.
- `blind-testsuite` when a wrong expected value would be invisible to the implementer, as in cryptography, codecs, and wire protocols; written from the contract before any implementation.
- `test-writer` for every test, with `test-reviewer` and `test-oracle-reviewer` through `code-review`, where the repository provides them.
- `intent-drift-audit` once a realisation is claimed complete, in the lead's final check or the reviewer's pass, never mid-implementation.
- `review-feedback-loop` once a pull request is open and has findings.
- `test-pruner`, where provided, when tests have accumulated faster than their value, usually after an effort rather than inside one.

## Signals you are in the wrong flow

- Writing a test whose expected value cannot be justified independently of the code under test: the oracle, and perhaps the seam, is wrong; see `test-oracle-reviewer`.
- Editing an intent file, a `CONTRACT.md`, or a blind suite inside an implementation pull request: that change is its own pull request first.
- More open pull requests than you can verify one by one: pause starting new ones.
