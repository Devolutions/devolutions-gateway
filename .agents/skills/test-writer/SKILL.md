---
name: test-writer
description: Design Rust tests that catch bugs, choosing between an example test, `rstest` cases, an `expect-test` snapshot, a `proptest` property, and a fuzz target. Use whenever adding or changing Rust unit, integration, snapshot, or property tests.
---

# Test writer

First name the bug the test catches that existing tests miss; without one it costs runtime and maintenance and guards nothing.
Take the expected value from a source independent of the code under test, as `test-oracle-reviewer` defines; a value derived from the implementation detects change, not bugs.
Reach nothing beyond loopback, because an external host makes a failure unreproducible.

## Properties

Look for a property before writing example tests, because a property holds across generated inputs while examples show only the cases someone thought of.
Candidates are a round-trip through encode and decode, a size computation matching the bytes written, and an invariant from the applicable intent or contract file that speaks of inputs or state, such as one that must survive any sequence of operations.
Test a property with `proptest`, reusing the crate's existing strategies and adding new ones beside them, so each type's generator is written once.
With no property that must hold across many inputs, write example tests; a `proptest` whose assertion re-implements the code under test checks the code against itself.
A parser of untrusted input gets a fuzz target in `fuzz/` rather than a never-panics `proptest`, because the fuzzer is coverage-guided and keeps a corpus, which a few hundred random cases are not.

## Snapshots

Snapshot structured values such as a parsed config, a decoded message, or a CLI error with `expect-test`; the expected value sits beside the assertion and `UPDATE_EXPECT=1` rewrites every stale one after a representation change.
Taking or updating a snapshot is the oracle, so read and check it, because `UPDATE_EXPECT=1` accepts whatever the code produced; when a spec or capture defines the value, assert that instead.
Move a snapshot or blob longer than a screen into a sibling file through `expect_file!` or `include_bytes!`, so the source shows the test rather than its data; keep short byte vectors inline so each field can carry its comment.

## Examples and cases

Parametrize with `rstest` only when every case checks the same behavior with different data, and name each case with `#[case::name]` so a failure names the case, not an index.
A body that branches on its parameters, through an `if`, a `match`, or an optional expected value, is several tests behind one name, so a failure reports a case instead of the behavior that broke; write one test per behavior and share setup through a helper.
A `#[values]` cross product is right only when every combination is a real scenario; one that needs an `if` to skip or adjust a combination is that branching.
Keep each regression test standalone and named for its issue, because its setup reproduces the bug's exact conditions and a case table would generalize them away.