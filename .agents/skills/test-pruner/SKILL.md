---
name: test-pruner
description: Prune, strengthen, and consolidate the tests of one Rust crate or module using oracle classification and cargo-mutants evidence. Use when the user asks to remove redundant tests, dedupe or consolidate tests with rstest or proptest, audit test value, or clean up AI-written tests. For reviewing the tests of a single pull request, use `test-oracle-reviewer` instead.
---

# Test pruner

Work on one crate or module per run so mutation runs stay affordable and pull requests stay reviewable.
Decide from two independent measurements: whether the expected value is justified independently of the code, and which faults only this test catches.
Mutation testing alone cannot tell a test that matches itself from a correct one, and oracle review alone cannot tell which tests are the sole guard for a fault.

## Measure

Invoke `test-oracle-reviewer` on every test in scope and record independent, self-derived, or unknown with evidence.
Run cargo-mutants on the scoped source to get the caught set, adding domain mutants from `references/mutants.md` because generic mutants are weak on codec code.
For the self-derived and unknown tests only, build the kill matrix of mutant by test described there; cargo-mutants reports per suite, and attributing every test is the cost explosion to avoid.

## Decide

Keep independent tests; merge them into rstest cases only when they check the same property and differ only in data.
Never delete an independent test on mutant evidence: the mutant sample is tiny next to the real fault space, and a spec vector costs nothing to keep.
Strengthen a self-derived test with unique kills by replacing its expected value with an independent one; if none exists, keep it and mark it `// oracle: self-derived; sole guard for <mutants>`.
A strengthened test that fails is a finding, never a task to make it pass.
Delete a self-derived test with no unique kills.
Challenge a test of unknown oracle.

Deletion is a set decision, not a per-test verdict.
Two tests that both catch mutant M each have zero unique kills, and deleting both loses M.
Choose the deletion set so the caught mutants afterward equal the caught mutants before.

Never propose deleting a regression test tied to an issue or fuzz crash, a test of untrusted-input parsing or bounds checks, or a doctest; strengthen or merge those only.
Treat a suite that deliberately uses snapshots as a change detector: dedupe it, do not delete it.
Report flaky tests separately; deleting one hides a bug.

## Challenge

Give a fresh-context agent the test, the code under test, and the mutants the rest of the suite already catches, and ask for one mutant that this test catches and the others miss, as a patch.
Run the patch; arguments do not count.
Add any mutant it finds to the domain catalog regardless of the verdict.
If it finds none, send the case to the test's human author with what is asserted, the oracle finding, its kills, and the failed challenge.
If the author was an agent, route to CODEOWNERS; an agent confirming its own test is worthless.

## Consolidate

Keep `#[case::name]` on rstest cases so failures stay readable.
Use proptest only for a real property; an assertion that re-implements the unit is a self-derived test with random inputs.
Round-trip passes symmetric bugs, so every codec module keeps spec or capture vectors.
Do not add a never-panics property where a fuzz target already covers it.

## Invariant and output

The caught-mutant set never shrinks except through deletions a human approves in a pull request.
Rerun the caught set after every deletion set and every consolidation, verify by rerunning rather than reasoning, and revert on any loss.
Open separate pull requests for deletions, consolidations, and strengthenings; they are different reviews.
Put the oracle table, kill matrix, challenge results, and found bugs in the pull request description.
Change only tests and source comments; never modify non-test source otherwise.
