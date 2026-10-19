---
name: test-reviewer
description: Review changed Rust tests against the `test-writer` rules, including a named bug, an independent oracle, non-branching `rstest` bodies, checked snapshots, and properties tested with `proptest`. Use when a diff or pull request adds or changes Rust tests, or when asked to review test organization or parametrization.
---

# Test reviewer

Invoke `test-writer` and use its rules as review criteria without following its generation workflow.
Review only changed tests unless the user requests a broader audit.
Run `test-oracle-reviewer` on each new or changed test; this skill covers the shape of a test, not where its expected values come from.
When a test's name and assertions do not say which bug it catches, ask the author rather than guessing one.
When the change touches an invariant stated in an applicable intent or contract file and no test checks it, ask what test pins it and whether it is a property that `proptest` could exercise across generated inputs.
A new or changed `expect-test` snapshot is a behavior claim; check that the pull request intends it and that the value is right.
Report each violation with its exact location and a concrete correction, and group repeated instances that share one correction.
Return no findings when the changed tests already comply.
