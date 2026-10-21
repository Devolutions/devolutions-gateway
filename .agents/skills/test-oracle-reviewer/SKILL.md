---
name: test-oracle-reviewer
description: Judge whether a test's expected value is justified independently of the code under test, and define the `// oracle:` marker that records its source. Use when reviewing tests added or changed in a pull request, auditing a module's tests, marking a test's source, or whenever expected bytes, snapshots, or mock values may have been copied from the implementation's own output.
---

# Test oracle reviewer

A test whose expected value came from the code under test detects change, not bugs.
For each test, ask whether the expected value can be justified without running the code.

Independent sources: a spec example, an external capture, a hand-derived value, an input the test chose itself and asserts was honored, a real property such as round-trip or `encode` writing exactly `size()` bytes, or a reference model.
Self-derived sources: a snapshot of current output, a value computed through the code or a shared helper, a production constant or message copied into the test, a mock that returns what is then asserted, `is_ok()` or `!is_empty()` on an input that no requirement says must succeed, or a restatement of what a derive or the type system guarantees.

Verify instead of guessing.
Check comments and `git log -p` for the origin, then check the value against the governing spec section: decode a byte vector field by field and show the breakdown, or cite the specification section that defines the behavior.
A value pasted from the code's output is independent once it checks out against the spec, and a spec vector nobody re-read is not; verification is the property, origin is only a hint.
A search-engine or AI summary is not a source; cite the primary document.

Classify each test as independent, self-derived, or unknown, with evidence, and report per assertion when a test mixes classes.
When a value checks out, add its marker, as below, so the next review is cheap.
When a value is wrong, report a bug; do not adjust the value or the code.
Unknown is an outcome, not a guess in either direction.

## Markers

Mark where an expected value comes from with `// oracle: <kind> <reference>` on the test, on a case row, or on one assertion when a test mixes sources, so one search finds every test that rests on a source.
Strong kinds name an independent source, and a test, case, or assertion marked with one is deleted only when its source changes or is shown not to decide what it asserts:

- `spec <document> §<section>`: normative text other than a contract or intent file, such as an RFC, a Microsoft open specification, or `docs/JMUX-spec.md`.
- `contract <path> §<section>`: a `CONTRACT*.md`.
- `intent <path> §<section>`: a statement in an intent file.
- `regression <issue or crash file>`: a bug report or fuzz crash.
- `reference <implementation, capture, or model>`: what another implementation or a reference model does, recorded or compared live.
- `property <statement>`: a property no document states, such as a round-trip or an input the test chose being honored.

A hand-derived value or a checked snapshot takes the kind of the source it was checked against.

Weak kinds name a self-derived source, which detects change rather than bugs, so any intentional change, such as a refactor or a new feature, may delete a test, case, or assertion marked with one without justification unless `test-pruner` protects it:

- `mutant <faults in words>`: a test or assertion kept to catch mutants that no strong source decides.
- `scaffold`: a test or assertion written for feedback while implementing that no strong source decides.

Mark a strong source whenever one decides the value, so a test found through a mutant but decided by a spec is `spec`, because whether a test may go depends on whether a source still requires it, not on how it was found.
An unmarked test starts as unknown: verify it as above, and turn a citation in another form into the marker it supports.
A marker is a claim: verify it like any other origin.

## Review

In a pull request review, comment on each self-derived test that an independent source decides, naming that source, and on each changed test without a marker; leave the fix to the author.
When that source needs a small non-test change, such as an injectable deadline the test can choose, request the change.
For mutation evidence on the same pull request, use `test-pruner` in review mode.
