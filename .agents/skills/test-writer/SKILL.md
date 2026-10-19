---
name: test-writer
description: Design Rust tests that catch bugs, choosing between an example test, `rstest` cases, and a `proptest` property. Use whenever adding or changing Rust tests, including unit tests, testsuite integration tests, and property tests.
---

# Test writer

Before writing a test, name the bug it catches that existing tests miss; a test without one costs runtime and maintenance and guards nothing.
Take the expected value from a source independent of the code under test, as `test-oracle-reviewer` defines it, because a value derived from the implementation detects change rather than bugs.

## Properties

Read the invariants in the applicable `INTENT.md`, `*.intent.md`, or `CONTRACT.md` and test each one the change touches with `proptest`, because a statement that must hold for every input is shown by generated inputs, not by a handful of examples.
Other properties worth a `proptest` are a round-trip through encode and decode, a size computation matching the bytes written, and an operation that must be idempotent or order-independent.
Reuse the strategies in `crates/*-generators` and add new ones there, so each type's generator is written once.
Without a property that must hold across many inputs, write example tests instead; a `proptest` whose assertion re-implements the code under test checks the code against itself.

## Examples and cases

Parametrize with `rstest` only when every case checks the same behavior with different data, and name each case with `#[case::name]`, because a failure then names the case instead of an index.
A body that branches on its parameters, through an `if`, a `match`, or an optional expected value, is several tests behind one name, so a failure reports a case instead of the behavior that broke; write one test per behavior and move shared setup into a helper.
A `#[values]` cross product is only right when every combination is a real scenario; one that needs an `if` to skip or adjust a combination is the branching above.
Keep each regression test standalone with the issue in its name or a comment, because that is what points a failure at the bug.
