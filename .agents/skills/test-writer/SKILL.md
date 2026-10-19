---
name: test-writer
description: Design Rust tests that catch bugs, choosing between an example test, `rstest` cases, an `expect-test` snapshot, a `proptest` property, and a fuzz target. Use whenever adding or changing Rust tests, including unit tests, testsuite integration tests, snapshot tests, and property tests.
---

# Test writer

Before writing a test, name the bug it catches that existing tests miss; a test without one costs runtime and maintenance and guards nothing.
Take the expected value from a source independent of the code under test, as `test-oracle-reviewer` defines it, because a value derived from the implementation detects change rather than bugs.
A test depends on nothing outside the repository and the loopback interface, because an external resource makes a failure unreproducible.

## Properties

Read the invariants in the applicable `INTENT.md`, `*.intent.md`, or `CONTRACT.md` and test each one the change touches with `proptest`, because a statement that must hold for every input is shown by generated inputs, not by a handful of examples.
Other properties worth a `proptest` are a round-trip through encode and decode, a size computation matching the bytes written, and an operation that must be idempotent or order-independent.
Reuse the strategies in `crates/*-generators` and add new ones there, so each type's generator is written once.
Without a property that must hold across many inputs, write example tests instead; a `proptest` whose assertion re-implements the code under test checks the code against itself.
A parser of untrusted input gets a fuzz target in `fuzz/` (see `fuzz/README.md`) rather than a never-panics `proptest`, because the fuzzer is coverage-guided and keeps a corpus, which a few hundred random cases are not.

## Snapshots

Snapshot a structured value such as a parsed config, a decoded message, a CLI error, or a `Debug` of a response with `expect-test`, because the expected value sits in the source next to the assertion and `UPDATE_EXPECT=1` rewrites every stale one, so a representation change costs one run and a diff review.
Taking or updating a snapshot is the oracle: read it as the expected value and check it, because `UPDATE_EXPECT=1` accepts whatever the code produced; when a spec or capture defines the value, assert that value instead.
Move a snapshot or captured blob longer than a screen into a sibling file through `expect_file!` or `include_bytes!`, so the source shows the test rather than its data; keep short byte vectors inline where each field can carry its comment.

## Examples and cases

Parametrize with `rstest` only when every case checks the same behavior with different data, and name each case with `#[case::name]`, because a failure then names the case instead of an index.
A body that branches on its parameters, through an `if`, a `match`, or an optional expected value, is several tests behind one name, so a failure reports a case instead of the behavior that broke; write one test per behavior and move shared setup into a helper.
A `#[values]` cross product is only right when every combination is a real scenario; one that needs an `if` to skip or adjust a combination is the branching above.
Keep each regression test standalone with the issue in its name or a comment, because that is what points a failure at the bug.
