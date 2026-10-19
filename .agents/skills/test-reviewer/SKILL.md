---
name: test-reviewer
description: Review how Rust tests are split and parametrized. Use when a diff adds or changes Rust tests, or when asked to review test organization or `rstest` parametrization.
---

# Test reviewer

Review only changed tests unless the user requests a broader audit.

Parametrize with `rstest` only when every case checks the same behavior with different data.
A parametrized body that branches on its parameters, through an `if`, a `match`, or an optional expected value, is several tests behind one name, so a failure reports a case instead of the behavior that broke; split it into one test per behavior.
Remove duplication between those tests with a shared setup helper rather than another parametrized test.
Keep each regression test standalone, because its own name and issue reference point a failure at the bug.
Flag unnamed `#[case]`s and `#[values]` cross products, because a failure then reports only a case index or a combination nobody chose to test.

Report each violation with its exact location and a concrete correction, and group repeated instances that share one correction.
