---
name: agents-md-review
description: Audit an existing AGENTS.md or CLAUDE.md line by line for wrong, stale, discoverable, duplicated, or content-free guidance and propose the pruned file. Use when asked to review, prune, shrink, or clean up one.
---

# AGENTS.md review

A line in `AGENTS.md` earns its place only if it would cost a CI round-trip or an incident to discover and no skill or always-read file already states it.
Every other line is paid on every task, and a wrong example is the costliest because agents copy it.

## Verify, then classify

Audit the file on the remote default branch; if the local copy differs, report it as stale and move on.
Check each block against reality before judging it; one piece of evidence per verdict is enough, and a config that would render an example wrong suffices without hunting for observed breakage.

- Examples and formats against the config that consumes them (changelog generator, release tooling, CI workflows): **Wrong**.
- Lists against the tree and the remote default branch: **Stale**.
- Claimed conventions against history (`gh pr list --state merged --limit 60 --json headRefName,title`): **Never a convention**.
- Rules against the installed skills and always-read files: **Duplicated**.
- Everything else against the test above: **Discoverable**, **Content-free**, or **Plain command**.
- An always-loaded pointer to a long guide: **Misplaced**; it belongs in the skill that needs it.

Also look for what is **Missing**: policy the organisation applies elsewhere (intent-file rules, writing conventions, comment markers) and non-standard layouts with no pointer.
`agents-md/references/before-after.md` is one repository's worked answer; re-verify every row against the repository in front of you, never paste it.

## Report

```md
| Block | Verdict | Evidence |
|---|---|---|
| `Issue: #456 (GitHub issue)` | Wrong | `cliff.toml` renders every `Issue:` as a Jira URL |
| Scope list `dgw, agent, jetsocat, webapp` | Stale | `installer`, `agent-installer` missing; `commit-scope` skill has the table |
| Branch naming | Never a convention | 2 of 60 merged PR branches carry a Jira key |
| Nightly rustfmt line | Keep | stable fmt fails CI; no skill states it |
```

Then propose the full pruned file, list what moved to a skill or a nested `AGENTS.md`, and list what needs a human decision.
Do not apply the changes unless asked.
