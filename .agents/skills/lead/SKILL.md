---
name: lead
description: Deliver one pull request from a brief with sub-agents - plan, workers and testers, a fresh-context reviewer on a frozen snapshot, your own verification, the pull request, the review-feedback loop, and a report the reader can verify. Use when a change needs its own session and more than one pair of hands, whether an orchestrator assigned it or the user did.
---

# Lead

You own one pull request from brief to merge-ready, and you are its last check.
A session leads one pull request; a second one gets a second session, so that each report, review loop, and branch has one owner.

## Start

Read the brief, then every applicable intent file, `CONTRACT.md`, and `AGENTS.md` for the paths in scope.
Use the models the brief names; when it names none, ask the user before creating any sub-agent, recommending from the options you can see: strong for reviewers and for anything that touches normative text, and a reviewer from a different model family than the writer when one is available, because a reviewer of the writer's family shares its blind spots.
Write the plan as an artifact in the harness's artifact area, outside the tree and never committed, with the acceptance criteria restated as checks you will run.

## Decisions

A decision the brief, the intent files, and the contract do not settle is not yours: stop and escalate with the options, how each could go wrong, and a recommendation, and do not let a worker encode it in a test or in code meanwhile, since whatever lands first becomes the text the rest is bent to.
Within autonomy - naming inside repository conventions, test structure, which published vector, a classification a stated rule decides, non-semantic documentation - decide, record it in the plan, and flag it in the report.
A change to an intent file, a `CONTRACT.md`, or a blind suite never rides this pull request: escalate it, and let this pull request wait or stack on the one that carries it.

## Sub-agents

One task per sub-agent, briefed from a file in the artifact area using `references/templates.md`; a brief points at paths rather than copying them, so the sub-agent reads the current text.
Workers write code and tests in your worktree or branch and never push or open the pull request; testers follow `test-writer` where the repository provides it, and suite authors `blind-testsuite`.
The brief lists what the sub-agent must not read as well as what it must, because isolation is only what the brief denies.

## Review loop

Review a commit, not a working tree: the worker commits, hands over the range, and stops editing until the verdict, since a change during review means the reviewer judged something that no longer exists.
The reviewer gets the range, the acceptance criteria, the applicable intent, contract, and `AGENTS.md` paths, and an instruction to run the repository's review skill (`code-review` where provided); it never gets the worker's transcript or reasoning, because the writer's framing anchors a reviewer before it has read the evidence.
Findings come back as blocking or non-blocking; blocking ones go back to the worker, non-blocking ones are fixed or the reason not to is recorded in the plan.
Set the round cap in the plan before the first round.
At the cap, the fixes still outstanding go to a fresh reviewer rather than out unreviewed, because post-cap fixes are exactly where unreviewed defects land.
A round that reintroduces an earlier finding ends the loop: escalate with both findings.

## Your verification

Verdicts are claims; verify before opening the pull request, whatever the loop returned.
Build, run the full suite, read the whole diff, and read line by line any code that handles untrusted input, keys, authentication, or a `CONTRACT.md` surface.
Check each acceptance criterion against evidence you produced, byte-compare any approved normative text copied into the tree against its approved artifact, and run `intent-drift-audit` when the paths are governed, since the realisation is now claimed complete.

## Pull request and report

Open the pull request following the repository's conventions; the body carries purpose, acceptance criteria with evidence, deviations from the brief, and open questions.
Run `review-feedback-loop` once findings arrive.
Report with `references/templates.md`: the head SHA and the CI run are what let the reader verify instead of trust, and every non-success job is named, because a summary count hides the one that matters.
Merging is the human's; report, mark the status waiting, and stop rather than polling for approval.
