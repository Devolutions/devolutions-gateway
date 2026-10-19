---
name: blind-testsuite
description: Write or extend a conformance test suite from a CONTRACT.md and published sources only, by an author who never sees any implementation, and keep it read-only while implementations are built against it. Use when a contract has or will have more than one implementation, or when a wrong expected value would be invisible to the implementer, as in cryptography, codecs, and wire protocols.
---

# Blind test suite

The suite is the contract made executable, so the implementations are judged against it and not the other way round.
`test-writer` decides each test's shape and `test-oracle-reviewer` what counts as an independent value; this skill is the isolation around them.

## What the author may see

The author's inputs are the `CONTRACT.md`, the interface it is written against (the contract crate or module, its types and documentation), and published sources: specifications, vendored vectors, captures.
Not an implementation, not an earlier implementation of the same contract, not the pull request or discussion that produced the contract, because each of those carries an author's reading of the contract that the suite would then confirm rather than test.
When an implementation already exists, the author is a fresh context working in a worktree at a commit where it does not; a do-not-read list in the brief supplements that and does not replace it, since a context that has seen the implementation cannot unsee it.

## Expected values

An expected outcome comes from a published source cited in the test, from a property the contract states, or from a derivation whose method the contract or the cited standard fixes, recorded beside the vector so a reviewer can redo it.
Never from a computation that only an implementation of the contract could perform, because checking such a value means implementing the contract again.
A derived vector accounts for every coupled field - a length, a checksum, a signature - that the change touches, or its expected outcome is not what the derivation claims.
Where no published answer exists, compare outputs across implementations; such a differential check never stands alone, because a bug shared by both passes it.

## Inputs the author writes

A hand-written negative input differs from an independently valid control in the targeted dimension only, so the test can fail only for the reason it names.
Vendored sources keep their origin, version, and checksum recorded, are taken whole or cut only at their own section boundaries, and are never edited, because an edited or sliced vector loses the provenance that makes it an oracle.
Record a boundary a test deliberately leaves unchecked where the contract lists its known gaps, so a reader does not take silence for coverage.

## Review and merge

The suite's reviewer runs `test-reviewer` where the repository provides it and checks the contract both ways: every clause has a test or a recorded gap, and every test cites the clause it checks.
Write the suite before the implementation; merge it once one implementation has run it green, because a test no conforming implementation can pass is found before it binds every later one.

## Read-only during implementation

An implementation pull request never edits the suite or the contract.
A test that looks wrong is escalated with the vector or clause, the expected value, the observed value, and the cited source; the fix, when the test is wrong, is its own pull request by a fresh author with the same inputs and its own reviewer.
A gap the implementer notices - a clause with no test - is escalated the same way and added through the suite's own pull request.
