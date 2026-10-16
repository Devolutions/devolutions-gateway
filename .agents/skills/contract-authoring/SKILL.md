---
name: contract-authoring
description: Author or revise a normative CONTRACT.md - an exact, testable specification of an interface, protocol, or provider boundary that independent implementations and a conformance suite derive from. Use when designing a spec, contract, protocol document, or provider API that several components or backends must agree on.
---

# Contract authoring

A contract is the normative text: a backend author implements from it alone, and the conformance suite derives its expectations from it and the standards it cites, never from an implementation.
`INTENT.md` beside it explains the choices; the contract states the rules.

## Process

1. **Scout before writing.**
   Inventory every call site the contract will serve, with `file:line`.
   Read each reference implementation or host at a pinned version and record, per operation, whether it is native, argument mapping, workaround, or unsupported, with evidence.
   Host conventions (naming case, pagination, proxies that rewrite paths) become rules; a reference you did not read becomes a false universal.
2. **Settle the design by interview**, one frontier of decisions per round, as in `grill-intent`.
   Number every clarification and log who decided it.
3. **Draft, then critique with two lenses**: overkill and gaps.
   Run every state-changing operation through `references/critique-lenses.md`.
4. **Freeze** once the design is approved.
   Afterwards it changes only for implementation defects, in its own PR ahead of the code that needs it.
   Implementers never edit the contract or the test suite to make code pass; they escalate with evidence from the cited source.

## Content rules

- Per operation: the valid domain, the must-support set, the exact error for each class of invalid input from a closed error set, and the precedence of outcomes.
  Phrase precedence as which outcome wins, not as an evaluation order.
- Implementation-defined cases are listed with their exact allowed outcome set, never with examples, and are excluded from differential tests.
- For every stored field: who initialises it, which operations update it, and which must not.
- Every list exists once; a second copy of the error list drifted and lost a code.
- The contract is the single source for the API: once the crate exists it carries no code, every public item cites its section, and a check enforces it.
- When the contract needs a rule the intent lacks, the human amends `INTENT.md` first.
- An example is not a rule: state what is free (order, case, whitespace) and add vectors that vary it, or a conforming library will reproduce none of them.
- Put the exception where the rule is: "terminal, except during pending-key recovery".
- Strict where it matters, extensible elsewhere: optional fields older receivers ignore, but authentication data stays strict.
- A derivable operation stays out unless a written exception (performance, validated-module boundary, a security property) sits next to it.
- Leave out one library's behaviour and numbers, admin and UI surfaces, implementer choices, and process.
- A rationale must be as true as its rule; measure before citing a cause.

## Testability

Each rule maps to a conformance case, worded as an observable with a bound: "encode writes exactly `size()` bytes", never "handles" or "supports".
Shared vectors cover positive and negative cases, are deterministic, and an independent script recomputes them.
The conformance section ties every claim to how it is tested, lists known gaps, and marks what is verified by review only.

`references/shape.md` lists the moves two shipped contracts converged on; read it when structuring a new one.
