The check enforces, in CI, the oracle markers that `.agents/skills/test-oracle-reviewer/SKILL.md` teaches; the rules below and that skill are one rule, and a difference between them is a defect.
Whether the cited source actually decides a test's expected value is not checked, because only a reader can judge it; that stays with review.

<a id="languages"></a>
## Languages

The check covers tests in Rust, C#, and PowerShell (Pester).
A marker is a line comment of the test's language: `// oracle: <kind> <reference>` in Rust and C#, `# oracle: <kind> <reference>` in PowerShell.
A marker sits on a test, on one case of a parametrized test, or on one assertion.
A Pester test is an `It` block, and a case is one entry of its `-ForEach` or `-TestCases` data.
Only tracked files are read, because a file that is ignored or not committed exists locally but not in CI.

<a id="grammar"></a>
## Grammar

The kinds are exactly `spec`, `contract`, `intent`, `regression`, `reference`, `property`, `mutant`, and `scaffold`.
A `spec` names a document, such as `RFC 9421` or `X.690`, and a spec under `docs/` takes its path instead.
A `spec` name that looks like a URL, carries an `@` ref, or ends in a file name outside `docs/` is rejected, because it would escape resolution.
`contract` and `intent` take a path, to a `CONTRACT*.md` file for `contract` and to an `INTENT*.md` or `*.intent*.md` file for `intent`.
`spec`, `contract`, and `intent` cite a section as `<document> §<section>`.
Every kind but `scaffold` takes a reference.
A `regression` names a Jira key, an issue as `#123` or `owner/repo#123`, or a committed crash file under `fuzz/`.
A `property` names exactly one of `round-trip`, `idempotent`, `involution`, `commutative`, `associative`, or `monotonic`, and anything else is rejected.
Any `scaffold` marker fails the check, because none may merge.

<a id="paths"></a>
## Paths and sections

A path is given from the repository root, with forward slashes and exact case.
A `§<section>` resolves, in this order, to an anchor `<a id="…"></a>` whose id equals `<section>` exactly, otherwise to a heading whose text matches in any case, otherwise to a heading that starts with that number, so `§3.2` matches `3.2 Framing`.
An anchor names the heading that follows it, so an anchor with no heading after it names nothing.
The check fails when the path does not exist or nothing matches.
An anchor id is unique within its own document, and only there: two anchors with the same id in one file a marker may cite, under `docs/` or a contract or intent file, fail the check, because the citation could resolve to either, while the same id in two files is allowed, because a citation names its file.

<a id="pins"></a>
## Pinned references

A file in another repository is cited as `<owner>/<repo>@<sha>:<path> §<section>`, for the kinds that take a path.
`<sha>` is a commit SHA of at least 12 hex digits; branches and tags are rejected, because they move.
An unpinned cross-repository reference fails.
The file is fetched at that commit and `§` resolves there by the same rules; a commit never changes, so the result is deterministic.
Fetched files are cached by `<owner>/<repo>@<sha>:<path>`.
When the token lacks the privilege to read that repository, the reference gets only a syntax check.
A bad token or a rate limit fails the check rather than skip, because skipping on it would let every pin pass unchecked.

<a id="new-tests"></a>
## New tests

On a pull request, every new test carries a marker.
An existing unmarked test blocks nothing, and moving a test or editing its attributes or body does not make it new, unless its name also gains a test in the same change.
When the check cannot tell a new test from an edited or moved one, it counts it as new, so a doubt costs a marker rather than letting an unmarked test through.

<a id="drift"></a>
## Drift report

A scheduled report, not a pull-request gate, compares each pinned section at its commit with the same section on that repository's default branch.
An unchanged section gets a proposed mechanical pin bump.
A changed, moved, or removed section lists its test for a person to re-check against the new text.
The report is one table per repository, with the test, the marker, and its status.

<a id="tooling"></a>
## Tooling

The check is a PowerShell script, not an xtask, because it then runs with no build step ahead of every other CI job.
