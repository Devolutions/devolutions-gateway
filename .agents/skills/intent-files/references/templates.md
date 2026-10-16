# Templates

Skeletons for the shapes that recur.
Delete sections that have nothing to say; a two-section file is better than a padded one.

## Crate or component `INTENT.md`

```md
# <crate>

## Purpose

<What it is, in one sentence.>
<Why it exists and what depends on it, in one to three sentences.>

## Invariants

- <Durable constraint stated as an observable.>
  <Why, and what it rules out.>
- <...>

## Non-goals

- <Deliberately unsupported behaviour, with the reason when it is not obvious.>
```

## Module `<name>.intent.md`

```md
# <Module> intent

## Scope

These rules apply to <the path or surface> implemented by `<file>`.
They do not define <adjacent concerns>.

## <Contract or behaviour section>

<Exact rules where exactness is the point; a small table is fine.>

- Adding a new <variant> requires an explicit decision about <what>.
- A new or unrecognised <variant> must not silently <fall back / be accepted>.

## Architectural invariants

- <Single source of truth for X.>
- <Classification happens once and determines Y and Z.>

> **Boundary:** <The most likely misreading, and where that concern actually lives.>
```

## Feature-level `INTENT.md` spanning several crates

```md
# <Feature>

## Background

<Two to five sentences: the problem, the actors, the deployment shape.>

## Terminology

- **<Term>**: <one-sentence definition>.

## Security invariants

1. <Numbered so other files can cite them.>
2. <...>

## Non-goals

- <Cut features and deferred directions, each with its constraint on V1 if any.>

## Crates

- `<crate>`: <one line>; see its `INTENT.md`.
```

## Rationale `INTENT.md` next to `CONTRACT.md`

```md
# <Feature> – Design Rationale

[CONTRACT.md][contract] defines <the protocol or interface>.
This file explains the main design choices and the reasons behind them.
It repeats contract details only when needed to explain a design choice.

## <Topic>

- <Decision.>
  <Reason, and what alternative it rules out.>

<a id="<feature>-<topic>"></a>

[contract]: CONTRACT.md
[contract-<topic>]: CONTRACT.md#<feature>-<topic>
```

## Exception section appended to an existing intent

```md
## Exception: <what>

<The rule being relaxed, named exactly.>
<What the exception allows and where it sits (feature, module).>
<What enforces its limits today.>
Removing this exception requires <condition A> or <condition B>.
```

## `AGENTS.md` section for a repository adopting intent files

```md
## Intent files

Read all applicable `INTENT.md` and `*.intent.md` files before modifying code.

Do not create, modify, delete, or rename intent files.

If a requested change conflicts with intent, stop and surface the conflict for human resolution.
```

## Draft handoff: `REVIEW.md`

Write this next to a set of drafts so the human can adopt them deliberately.

```md
# Intent drafts: review notes

<One line: what these drafts were checked against (decision log, contract version, code at commit).>
Per the repository convention, these remain drafts until a human edits and commits them.

## Corrections (a draft contradicted a later decision)

| Draft said | Now | Decided in |
|---|---|---|

## Additions (decisions made since the drafts)

- <...>

## Left out on purpose

<What was deliberately kept in the contract or the plan instead.>

## For the human to decide

1. <Placement questions.>
2. <Gaps the drafter filled that were never discussed.>
```

## Draft handoff: provenance table

Keep this while drafting; attach it or fold it into `REVIEW.md`.

| Level | Meaning | Where it goes |
|---|---|---|
| 1 | The human's own words, quoted verbatim | Strongest source; may become intent directly |
| 2 | Agent proposal the human explicitly accepted, acceptance quoted | May become intent |
| 3 | Agent proposal present in a plan the human approved but never discussed on its own | List for the human to confirm |
| 4 | Filled in by the agent while drafting, never discussed | List for the human to confirm; never silently committed |
