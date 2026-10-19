---
name: test-reviewer
description: Review Rust test structure for readability and clear coverage. Use when a diff adds or changes tests, or when asked to review test organization or parametrization.
---

# Test reviewer

Review only changed tests unless the user requests a broader audit.

Insist on splitting scenarios into focused tests or setup functions when combining them obscures behavior.
Insist on simplifying parametrization when it hides coverage or makes failures harder to reproduce.
Distinct behaviors, boundaries, and regressions has to be in explicit tests instead of forcing them into one case matrix.
Parameterized cases with `rstest` has to have test bodies linear.

Report each violation with its exact location and a concrete correction, and group repeated instances that share one correction.
