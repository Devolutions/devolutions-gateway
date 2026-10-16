---
name: agents-md-review
description: Audit an existing AGENTS.md line by line for wrong, stale, discoverable, duplicated, or content-free guidance and propose the pruned file. Use when asked to review, prune, shrink, or clean up an AGENTS.md.
---

# AGENTS.md review

Read `agents-md` for what earns a line; this skill is the audit.
Every line in `AGENTS.md` is paid on every task, and a wrong example is the costliest line because agents copy it.

## Verify, then classify

Audit the file on the remote default branch; if the local copy differs, report it as stale and move on.
Take each sentence or block and check it against reality before judging it; one piece of evidence per verdict is enough, and the config that would render an example wrong suffices without hunting for observed breakage.

- Examples and formats against the config that consumes them (`cliff.toml`, `release-plz.toml`, CI workflows); a footer example that renders a broken changelog link is **wrong**.
- Lists against the tree and the remote default branch; a scope, crate, or exclusion list that disagrees is **stale**.
- Claimed conventions against history (`gh pr list --state merged --limit 60 --json headRefName,title`); a branch-naming rule nobody follows was **never a convention**.
- Rules against the installed skills and always-read files; a restatement is **duplicated**.
- Everything else against the two questions in `agents-md`; what fails them is **discoverable**, **content-free**, or a **plain command**.
- Pointers against their cost: an always-loaded file pointing at a long guide is **misplaced**; move the pointer to the skill that needs it.

Also look for what is **missing**: policy the organisation applies elsewhere (intent-file rules, writing conventions, comment markers) that this file lacks, and non-standard layouts with no pointer.
The worked example in `agents-md/references/before-after.md` is one repository's answer; re-verify every row against the repository in front of you, never paste it.

## Report

Verdicts: **Wrong**, **Stale**, **Never a convention**, **Duplicated**, **Discoverable**, **Content-free**, **Plain command**, **Misplaced**, **Keep**.

```md
| Block | Verdict | Evidence |
|---|---|---|
| `Issue: #456 (GitHub issue)` | Wrong | `cliff.toml` renders every `Issue:` as a Jira URL |
| Scope list `dgw, agent, jetsocat, webapp` | Stale | `installer`, `agent-installer` missing; `commit-scope` skill has the table |
| Branch naming | Never a convention | 2 of 60 merged PR branches carry a Jira key |
| `## Project Overview` | Discoverable | workspace listing |
| Nightly rustfmt line | Keep | stable fmt fails CI; no skill states it |
```

Then propose the full pruned file, and list what moved to a skill or a nested `AGENTS.md` and what needs a human decision.
Do not apply the changes unless asked.
