# Devolutions Gateway

Reusable agent skills live in `.agents/skills/`; use the matching skill before committing, opening a pull request, posting a GitHub comment, or writing prose.

## Intent files

`INTENT.md` and `*.intent.md` files contain human-owned intent for the software.
Read all applicable intent files before modifying code.
Do not create, modify, or delete intent files.
If a requested change conflicts with intent, stop and surface the conflict for human resolution.

## Writing for the repository

Committed text (code, comments, docs, commit messages) and PR titles and descriptions never refer to work stages, decision identifiers, agent roles, sessions or planning documents.
State rationale, not history.

Code comments and doc comments follow the same rule as Markdown: each sentence starts on its own line and wraps only where it would exceed the line-length limit.

## Rust

Format with nightly rustfmt (`cargo +nightly fmt --all`); stable `cargo fmt` produces different output and fails CI.
Think before silencing a lint, then use `#[expect(clippy::<lint>, reason = "...")]` so the suppression explains itself and expires when it stops being needed.
Write Rust with the `rust-style` skill.
Integration tests are centralized in the `testsuite` crate; see `testsuite/AGENTS.md`.

## Untested-property comments

When code must keep a property that no test checks, mark it with an `UNTESTED:` comment at that code, because passing tests prove nothing about it.
The comment states the property, why it matters, and what to check when changing the code.
List `UNTESTED:` properties in a PR comment as well, not in the PR description, because the description becomes the squash commit body.

```rust
// UNTESTED: decryption is blinded with the OS generator.
// Blinding changes no output; it is the rsa crate's countermeasure against timing attacks on the private key.
// When changing this call, keep `decrypt_blinded` with the generator from `os_rng()`.
```

## Git

Reference the Jira ticket in a commit footer as `Issue: DGW-123`; the `commit-footer` skill covers footers.
