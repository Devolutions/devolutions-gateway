---
name: tdd
description: Red-green loop for one behaviour at an agreed seam - a failing test first, the least code that passes it, refactoring outside the loop. Use for bug fixes and small features built test-first, or whenever the user says test-first, red-green, or TDD.
---

# Test-driven development

`test-writer`, where the repository provides it, decides what a good test is, and `test-oracle-reviewer` where its expected value may come from; this skill is the loop around them.

## Seam

Before the first test, name the seam: the public boundary where the behaviour is observed.
Take it from the intent or contract file that describes the unit, the bug report, or the existing public interface; ask the user only when choosing between candidate seams would create or change a design decision, and then say what each catches and misses.
A test against internals passes on wrong behaviour and fails on a harmless refactor, so no test goes below the seam.

## Red

Write one test for one behaviour and run it.
Read the failure: the assertion on the behaviour must be what fails.
A compile error, a missing fixture, or a panic in setup is not red, unless compilation failure is the behaviour under test, since it goes away once that other problem is fixed and proves nothing about the behaviour.
For a bug, the red test reproduces it at the seam with an expected value that `test-oracle-reviewer` would class as independent, never one read from the output of the code once fixed; a value read off the fix only shows the fix did what it did.
A behaviour the test needs a decision for, and no intent, contract, or report states it, stops the loop: ask, or run `grill-intent`, before writing the assertion, because the test becomes the specification the code is bent to.

## Green

Write the least code that passes this test and nothing for the test you expect next.
When the least code is plainly a stub, that is the signal for the next test, not a reason to write more code now.
Run the one test while iterating; run the unit's suite before each commit so the loop leaves only green commits.

## One slice at a time

One test, one change, repeat.
Do not write all the tests first and then the code: tests written in bulk check the shape you imagined, so they go insensitive to what the code actually does and fix the test structure before you understand the implementation.
Each new test responds to what the last cycle showed.

## Refactor outside the loop

Refactoring is its own commit after green, with the suite green before and after.
A design finding met during implementation or raised by `code-review` is acted on in that separate commit, so a refactor never hides behind a behaviour change.
