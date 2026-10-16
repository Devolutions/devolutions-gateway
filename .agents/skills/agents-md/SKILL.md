---
name: agents-md
description: Discipline for writing and updating AGENTS.md so it holds only what an agent cannot infer - policy, gotchas, and pointers - and stays under about 40 lines. Use when creating, editing, or adapting an AGENTS.md, instead of /init.
---

# AGENTS.md

`AGENTS.md` is loaded on every task, so every line is a cost paid everywhere.
Measured on real repositories (arXiv 2602.11988): developer-written files raised resolve rate about 4% and cost about 20%; LLM-generated files lowered resolve rate; repository overviews did not help.
What helped agents was locating the right place to change, not writing better patches.

## The test

A line earns its place when both hold:

> Would it cost a CI round-trip or a production incident to discover?
> Does no skill or always-read file already state it?

Put positively: there is no way the agent learns this unless we write it.

## What belongs, in order of value

- A pointer to a non-standard layout: "Integration tests are centralized in `testsuite`; see `testsuite/AGENTS.md`."
- A gotcha with its consequence: "Format with nightly rustfmt; stable `cargo fmt` produces different output and fails CI."
- A policy with its reason: "Use `#[expect(lint, reason = "...")]` so the suppression explains itself and expires when it stops being needed."
- Repository rules no tool enforces: intent-file handling, writing conventions for committed text, comment markers such as `INVARIANT:` and `UNTESTED:`.
- The one repo-specific fact a shared skill defers to the repo, when it fits in a line; otherwise a repo-local skill.
- One opener saying where skills live, for agents that do not discover them.

What `/init` generates is the blacklist: product overview, directory map, command lists, "follow standard conventions", inventories of crates or scopes, and lossy summaries of `STYLE.md`.
Examples without the rule behind them are the costliest lines; agents copy the example, mistakes included.

## Division of labour

```text
AGENTS.md    always loaded     policy, gotchas, pointers          < 40 lines
skill        loaded on match   self-contained rules for one task  no outbound pointers unless conditional
STYLE.md     loaded by a reviewer skill when a rule's intent is unclear
```

Load each file at the latest point where it pays for itself; an always-loaded file pointing at a 700-line guide is a cost on every task.
A directory with its own policy gets a nested `AGENTS.md` and one pointer from the root.

## Keeping it true

- Verify every surviving sentence against the tree and the remote default branch; `/init` files go stale within weeks.
- When a line documents a workaround, fix the code instead; the file is a list of smells not yet fixed.
- When adapting another repository's file, report deviations with reasons instead of copying: a line true there may be false here.

`references/before-after.md` holds one 151-line file reduced to 27, with the reason each block was cut or kept and the maintainer's verbatim pushbacks; read it when unsure what counts as discoverable.
