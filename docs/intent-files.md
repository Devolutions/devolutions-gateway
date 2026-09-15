# INTENT.md: Durable Human Intent for AI-Assisted Codebases

`INTENT.md` records the parts of a software design that humans have deliberately made durable.
Agents may read it and implement it, but they must not create, modify, delete, or rename it.

`INTENT.md` is optional.
Its absence does not block AI-assisted contributions.
Its presence means that a human has explicitly defined intent for that scope.

> `INTENT.md` specifies the desired software.
> `AGENTS.md` specifies desired agent behavior.
> Source code and implementation tests realize the software.

## What belongs in INTENT.md

`INTENT.md` contains normative statements about what the software should be.
It can range from broad design constraints to exact specifications.

Typical content includes:

- required behavior;
- API, protocol, and data contracts;
- schemas and externally visible semantics;
- architectural invariants and dependency boundaries;
- concurrency and lifecycle requirements;
- security properties;
- compatibility requirements;
- deliberate design choices and tradeoffs;
- non-goals and explicitly unsupported behavior.

For example:

````md
## API contract

`POST /sessions` requires a Bearer JWT.

A successful response returns HTTP 201:

```json
{
  "id": "uuid",
  "state": "connecting"
}
```

Changes to the route, authentication requirement, response schema, or status-code semantics are changes to intent.

## Architectural invariants

This crate must remain `no_std` compatible.

This crate must not perform I/O.

Protocol parsing must remain independent of transport.

Only one invocation of the session-creation handler may be in flight at a time.
````

These statements remain requirements regardless of whether a human or an agent writes the implementation.

`INTENT.md` does not need to be a complete specification.
It may specify only the parts of the design that humans consider important enough to preserve explicitly.

Its incompleteness is about **coverage**, not precision or authority.
Where `INTENT.md` specifies an exact API boundary, schema, state transition, or protocol behavior, drift is a defect unless a human deliberately changes the intent.

A useful test is:

> If the implementation passed its current tests but violated this statement, would we still consider the software wrong?

If yes, the statement is a strong candidate for `INTENT.md`.

Implementation details that are incidental to the current code usually do not belong there.
A specific helper, file layout, or internal abstraction belongs in `INTENT.md` only when preserving it is itself a deliberate design decision.

## Human-owned, optional, and authoritative

`INTENT.md` must remain human-owned.

Agents must not generate intent files on behalf of humans.
Otherwise, the presence of `INTENT.md` would no longer show that durable human design work took place.

This rule does not mean that intent can never change.
It means that changing intent is a human design action, not an implementation action delegated to an agent.

`INTENT.md` is therefore:

> Optional, human-owned, and authoritative when present.

A contribution without `INTENT.md` can still be valid and useful.
Its absence means only that no durable human intent artifact has been established for that scope and that some design work may remain implicit or unresolved.

If a requested change conflicts with applicable intent, the agent should surface the conflict for human resolution instead of rewriting the intent to fit the implementation.

## Relationship with AGENTS.md

`AGENTS.md` tells agents how to work.
It should not become a second design specification.

For example:

```md
Read all applicable `INTENT.md` and `*.intent.md` files before modifying code.

Do not create, modify, delete, or rename intent files.

If a requested change conflicts with intent, surface the conflict for human resolution.

Run `cargo check --no-default-features` after modifying a `no_std` crate.

Run the relevant fuzz targets after changing a parser.
```

The distinction is simple:

```text
INTENT.md:
    This crate must remain `no_std` compatible.

AGENTS.md:
    Run `cargo check --no-default-features` after changing this crate.
```

`INTENT.md` states what must remain true of the software.
`AGENTS.md` states what the agent must do while working on it.

A useful classification question is:

> Would this statement still matter if the contributor were a human instead of an agent?

If yes, it probably belongs in `INTENT.md`.
If it describes how an agent should navigate, modify, validate, or reason about the repository, it belongs in `AGENTS.md`.

## Tests have different authority

Tests written alongside an implementation are normally part of that implementation artifact.
An LLM can write code and unit tests that share the same mistaken interpretation of a requirement.

Independent conformance or contract tests are different.
Their expectations come from an authoritative specification, API contract, or protocol rather than from the implementation under test.

For example:

```text
RDPEUSB specification
        |
        v
independently derived conformance suite
        |
        v
public API / protocol boundary
        |
        v
implementation + implementation tests
```

The important property is independence of derivation, not whether a human or LLM wrote the test.

A test suite generated from the RDPEUSB specification while treating the implementation as a black box can provide strong independent evidence.
A human-written test derived from the current implementation may still be only an implementation test.

Independent conformance tests act as executable constraints.
They complement `INTENT.md` rather than replace it.

## Scope and naming

Use `INTENT.md` at meaningful component boundaries such as a crate, module, service, or subsystem.

A more specific `foo.intent.md` may be useful when intent belongs to one logical artifact or artifact family.

```text
service/
    INTENT.md
    router.rs
    router.intent.md
```

Do not create intent files mechanically for every source file.
Their presence should reflect actual human design work.

Applicable intent files are cumulative.
A more specific file does not silently override broader intent.
Contradictions require human resolution.

## The resulting model

```text
             durable human intent
                     |
                 INTENT.md
                     |
        desired behavior, contracts,
       specifications, and invariants
                     |
             +-------+-------+
             |               |
             v               v
      independent       source code +
      conformance       implementation
         tests             tests
             |               |
             +-------+-------+
                     |
                     v
              running software


AGENTS.md
    |
    +---- tells agents how to work on these artifacts
          and preserve applicable intent
```

Skills can sit above this repository-specific model.
A skill teaches an agent how to perform a class of work.
`AGENTS.md` tells it how to work in a particular repository.
`INTENT.md` records what humans deliberately want the software to be.

This separation lets teams accept partial and heavily AI-assisted contributions while preserving a clear signal of where durable human design thinking has been captured.
