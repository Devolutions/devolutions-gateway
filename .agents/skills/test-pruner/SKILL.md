---
name: test-pruner
description: Prune, strengthen, and consolidate tests using oracle classification and mutation evidence, cargo-mutants for Rust and Stryker.NET for C#, for one crate, project, or module or for one change's diff. Use when asked to remove redundant tests, consolidate tests into cases or properties, audit test value, clean up AI-written tests, finalize a change's tests before its pull request opens, or get a mutation-backed review of a pull request's tests. For a quick oracle-only check, use `test-oracle-reviewer` instead.
---

# Test pruner

Scope each run to one crate, project, or module, or to one change's diff, so mutation runs stay affordable and results stay reviewable.
Decide from two independent measurements: whether the expected value is justified independently of the code, and which faults only this test catches.
Mutation testing alone cannot tell a test that matches itself from a correct one, and oracle review alone cannot tell which tests are the sole guard for a fault.
Tool mechanics and case forms: `references/cargo-mutants.md` for Rust, `references/stryker.md` for C#; load only the language in scope.

The skill has two modes.
In editing mode, run on tests you own, such as a change's diff before its pull request opens, you commit the deletions, consolidations and strengthenings yourself and hand the evidence tables to whoever posts the pull request comment.
In review mode, run on another's pull request, you post a review and edit nothing.
Run mutants in a clone of their own, with absolute paths for every file operation, since an applied mutant left in a shared checkout corrupts every other run there.

## Measure

Invoke `test-oracle-reviewer` on every test in scope and record independent, self-derived, or unknown with evidence.
Run the mutation tool as the reference describes, adding domain mutants from `references/domain-mutants.md` because generic mutants miss most domain faults.
Build the kill matrix of mutant by test from the tool's outputs; it needs no per-test reruns.
For tests with several assertions, record which assertion fails for each kill.
Run the scoped suite repeatedly on the clean tree, for example 15 times, to find flaky tests before trusting any kill.

## Decide

Keep independent tests; merge them into cases of one parametrized test only when they check the same property and differ only in data.
Never delete an independent test on mutant evidence: the mutant sample is tiny next to the real fault space, and a spec vector costs nothing to keep.
Strengthen a self-derived test with unique kills by replacing its expected value with an independent one; if none exists, keep it and mark it `// oracle: self-derived; sole guard for <faults>`, naming each fault in words, since mutant ids renumber with every run.
A strengthened test that fails is a finding, never a task to make it pass.
Report it to whoever owns the decision, a worker to its lead and a lead to its coordinator or the human, with the test, the independent expected value and its source, and the code's actual output; change neither test nor code to make it pass until that owner decides, because whichever is edited first becomes the specification.
Delete a self-derived test with no unique kills.
A test of unknown oracle with unique kills has already passed the challenge; strengthen it.
Challenge a test of unknown oracle without unique kills, unless it is protected below, since its fate does not depend on the answer.

Deletion is a set decision, not a per-test verdict.
Two tests that both catch mutant M each have zero unique kills, and deleting both loses M.
Choose the deletion set so the caught mutants afterward equal the caught mutants before.
The same rule applies to assertions: a self-derived one that never fails across its test's kills is a deletion candidate.

Never propose deleting a regression test tied to an issue or fuzz crash, a test of untrusted-input parsing or bounds checks, or a doctest; strengthen or merge those only.
Treat a suite that deliberately uses snapshots as a change detector: dedupe it, do not delete it.
Report flaky tests separately; deleting one hides a bug.

## Challenge

Give a fresh-context agent the test, the code under test, and the mutants the rest of the suite already catches, and ask for one mutant that this test catches and the others miss, as a patch only.
Apply and run the patch yourself; arguments do not count.
Add any mutant it finds to the domain catalog regardless of the verdict.
If it finds none, ask the human who wrote or prompted the test for the source of its expected value, and accept a source you can check, never a confirmation.
Without one, delete the test, or hand a protected test to the file's CODEOWNERS.

## Consolidate

Use a property test only for a real property; an assertion that re-implements the unit is a self-derived test with random inputs.
Round-trip passes symmetric bugs, so every codec module keeps spec or capture vectors.
Do not add a never-panics or never-throws property where a fuzz target already covers it.

## Invariant and output

The caught-mutant set never shrinks except through deletions a human approves in a pull request.
Rerun the caught set after every deletion set and every consolidation, verify by rerunning rather than reasoning, and revert on any loss; compare runs made with identical tool settings over the same scope.
Triage surviving mutants as equivalent, unconstrained (it changes only text no requirement fixes), coverage gap, or bug lead; a mutant that survives because its code is unreachable is a bug lead.
Close each coverage gap with a test whose expected value is independent, written with `test-writer`; a gap no independent source decides is reported instead.
A suite of independent tests yields few deletions, so expect most of a pass's change to be consolidations and gap tests.

In editing mode, make separate commits for deletions, consolidations, and strengthenings, each as soon as it is verified, so an interrupted run loses little; they are different reviews.
Put the oracle table, kill matrix, challenge results, survivors, and found bugs in a pull request comment; the pull request body is the squash commit.
Change only tests and source comments; never modify non-test source otherwise.

In review mode, post one review: inline comments on the affected tests, with the tables in `<details>` blocks.
Deletions, consolidations, strengthenings, and small non-test changes that enable an independent oracle become requests to the author, with the current caught set as the bar.
