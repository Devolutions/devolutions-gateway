# Devolutions Gateway

Reusable agent skills live in `.agents/skills/`; use the matching skill before committing, opening a pull request, posting a GitHub comment, or writing prose.

## Intent files

`INTENT.md` and `*.intent.md` files contain human-owned intent for the software.
Read all applicable intent files before modifying code.
Do not create, modify, or delete intent files.
If a requested change conflicts with intent, stop and surface the conflict for human resolution.

## Rust

Format with nightly rustfmt (`cargo +nightly fmt --all`); stable `cargo fmt` produces different output and fails CI.
Think before silencing a lint, then use `#[expect(clippy::<lint>, reason = "...")]` so the suppression explains itself and expires when it stops being needed.
Write Rust with the `rust-style` skill.
Integration tests are centralized in the `testsuite` crate; see `testsuite/AGENTS.md`.

## Git

Reference the Jira ticket in a commit footer as `Issue: DGW-123`; the `commit-footer` skill covers footers.
