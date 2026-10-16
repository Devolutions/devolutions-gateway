---
name: agents-md
description: Discipline for writing and updating AGENTS.md so it holds only what an agent cannot infer - policy, gotchas, and pointers - and stays under about 40 lines. Use when creating, editing, or adapting an AGENTS.md, instead of /init.
---

# AGENTS.md

`AGENTS.md` is loaded on every task, so every line is a cost paid everywhere.
Modern agents explore, read manifests, and run `--help` on their own; telling them how is bloat.
`/init` output is the anti-pattern: product overview, repo map, command lists, and a lossy copy of the style guide.

## The test

A line earns its place when both hold:

> Would it cost a CI round-trip or a production incident to discover?
> Does no skill or always-read file already state it?

Put positively: there is no way the agent learns this unless we write it.

## What belongs

- A gotcha with its consequence: "Format with nightly rustfmt; stable `cargo fmt` produces different output and fails CI."
- A policy with its reason: "Use `#[expect(lint, reason = "...")]` so the suppression explains itself and expires when it stops being needed."
- A non-standard layout, as one pointer: "Integration tests are centralized in `testsuite`; see `testsuite/AGENTS.md`."
- Repository rules for agents that no tool enforces: intent-file handling, writing conventions for committed text, comment markers such as `INVARIANT:` and `UNTESTED:`.
- The one repo-specific fact a shared skill defers to the repo, when it fits in a line; otherwise a repo-local skill.
- One opener saying where skills live, for agents that do not discover them.

## What does not

- What the product is, the workspace listing, a directory map, "additional resources".
- Commands the tool prints itself or that any agent knows (`cargo test`, `pnpm install`).
- "Follow standard conventions."
- Examples without the rule behind them; agents copy the example, including its mistakes.
- Anything a skill holds, and lossy summaries of `STYLE.md`.
- Inventories (crates, scopes, excluded members); write the rule or point at the authoritative list.

## Division of labour

```text
AGENTS.md    always loaded     policy, gotchas, pointers          < 40 lines
skill        loaded on match   self-contained rules for one task  no outbound pointers unless conditional
STYLE.md     loaded by a reviewer skill when a rule's intent is unclear
```

Load each file at the latest point where it pays for itself.
An always-loaded file pointing at a 700-line guide is a cost on every task; let the reviewer skill point there.
A directory with its own policy gets a nested `AGENTS.md` and one pointer from the root.

## Writing

- Verify every surviving sentence against the tree and the remote default branch; `/init` files go stale within weeks.
- A good line is a non-obvious fact plus its consequence; a bad line is a listing.
- Name the concrete behaviour or anti-pattern; "what are we asking the agent to do?" must have an answer.
- Rationale, not history; declarative present; one sentence per line.
- When adapting another repository's file, report deviations with reasons instead of copying: a line true there may be false here.

See `references/before-after.md` for a 151-line file reduced to 27, with the reason each block was cut or kept.
