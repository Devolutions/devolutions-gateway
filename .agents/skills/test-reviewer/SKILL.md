---
name: test-reviewer
description: Review whether new Rust tests earn their place and how they are split and parametrized. Use when adding or changing Rust tests, reviewing a diff that does, or when asked to review test organization, `rstest`, or `proptest` usage.
---

# Test reviewer

Review only changed tests unless the user requests a broader audit.

Each new test must catch a bug that existing tests miss; flag one whose bug nobody can name, because it costs runtime and maintenance and guards nothing.
Run `test-oracle-reviewer` on each new or changed test to check where its expected values come from.

Parametrize with `rstest` only when every case checks the same behavior with different data.
A parametrized body that branches on its parameters, through an `if`, a `match`, or an optional expected value, is several tests behind one name, so a failure reports a case instead of the behavior that broke; split it into one test per behavior.
Remove duplication between those tests with a shared setup helper rather than another parametrized test.
Keep each regression test standalone, because its own name and issue reference point a failure at the bug.
Flag unnamed `#[case]`s and `#[values]` cross products, because a failure then reports only a case index or a combination nobody chose to test.
Use `proptest` only for a real property such as a round-trip, because a property that re-implements the code under test checks the code against itself.

Report each violation with its exact location and a concrete correction, and group repeated instances that share one correction.
