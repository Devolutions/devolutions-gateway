---
name: blind-testsuite
description: Write or extend a conformance suite from a CONTRACT.md and published sources only, by an author who never sees an implementation, kept read-only while implementations are built against it. Use when a contract has or will have several implementations, or a wrong expected value would be invisible to the implementer, as in cryptography, codecs, and wire protocols.
---

# Blind test suite

The suite is the contract made executable, so implementations are judged against it and not the other way round.
`test-writer` decides each test's shape and `test-oracle-reviewer` what counts as an independent value; this skill is the isolation around them.

## What the author sees

The `CONTRACT.md`, the interface it is written against (the contract crate or module, its types and documentation), and published sources: specifications, vendored vectors, captures.
Not an implementation, an earlier implementation, or the pull request that produced the contract, because each carries a reading of the contract the suite would then confirm rather than test.
When an implementation exists, the author is a fresh context in a worktree at a commit without it; a do-not-read list supplements that and does not replace it, since a context that has seen the implementation cannot unsee it.

## Expected values

From a published source cited in the test, a property the contract states, or a derivation whose method the contract or cited standard fixes, recorded beside the vector so a reviewer can redo it; never from a computation only an implementation of the contract could perform, because checking such a value means implementing the contract again.
A derived vector accounts for every coupled field the change touches - length, checksum, signature - or its outcome is not what the derivation claims.
Where no published answer exists, compare outputs across implementations; a differential check never stands alone, because a bug shared by both passes it.
A hand-written negative input differs from an independently valid control in the targeted dimension only, so the test can fail only for the reason it names.
Vendored sources keep origin, version, and checksum recorded, are taken whole or cut at their own section boundaries, and are never edited, because an edited or sliced vector loses the provenance that makes it an oracle.
Record a boundary a test deliberately leaves unchecked where the contract lists known gaps, so silence is not taken for coverage.

## Review and merge

The reviewer runs `test-reviewer` where provided and checks the contract both ways: every clause has a test or a recorded gap, every test cites its clause.
Write the suite before the implementation; merge it once one implementation runs it green, so a test no conforming implementation can pass is found before it binds every later one.

## Read-only during implementation

An implementation pull request never edits the suite or the contract.
A test that looks wrong, or a clause with no test, is escalated with the vector or clause, expected and observed values, and the cited source; the fix is its own pull request by a fresh author with the same inputs and its own reviewer.
