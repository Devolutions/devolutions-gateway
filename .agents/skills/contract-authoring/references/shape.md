# Contract shape

Two shipped contracts, a protocol (`docs/agent-identity/CONTRACT.md` in Devolutions/devolutions-gateway) and a provider boundary (`picky-crypto/CONTRACT.md` in Devolutions/picky-rs), converged on the same order: conventions and definitions, closed sets (identifiers, errors, encodings), one section per operation, composition, conformance, a short rationale pointer to `INTENT.md`.
Read one of them for the full skeleton; the moves below are what they share.

- The opening paragraph names the three artifacts: "`CONTRACT.md` defines the protocol; `INTENT.md` explains the choices; `test-vectors.json` holds shared data."
- General rules that apply to every operation sit once at the top with "these rules are not repeated", so per-operation sections stay short.
- Precedence as which outcome wins: "a bounds error always wins; a capacity limit may win over a structure error; this fixes which outcome wins, not the order among a backend's checks".
- Implementation-defined outcomes as closed sets per input: "loading returns `InvalidKey` or succeeds; signing returns `InvalidKey` or a signature that verifies under (n, e)".
- Stored-field ownership as a sentence naming the operations: "renewal, confirm and check-in update `last_seen_at`; an idempotent enrollment replay and stream closure do not".
- Exceptions inline with the rule they relax, with the condition that would remove them.
- Product-specific surfaces (admin API, mock) in their own late sections, marked as outside the product-neutral contract.
- Section anchors `<a id="<feature>-<topic>">` so intent files link without breaking on renumbering.
