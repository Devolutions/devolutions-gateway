# Contract shapes

Two shipped contracts, different domains, same skeleton: conventions and definitions first, closed sets next, then one section per operation, then composition, then conformance, then rationale pointers.

## Protocol contract (Agent Identity, `docs/agent-identity/CONTRACT.md`)

```md
# <Feature> — Contract

## History            version, date, author
## Definitions        base64 vs base64url, authority, SPKI, <data-dir>
## 1. Protocol conventions     JSON case, optional fields, unknown fields, timestamps, IDs, encodings
## 2. <Credential or token>    format, regex, limits; 2.1 Authority behavior: storage, validity, idempotence, tombstones, evaluation precedence, concurrency properties
## 3. Metadata                 bounds, who sets and updates each field
## 4. Certificates             profile
## 5. Agent-facing HTTP API    one subsection per route; 5.4 Errors: the only list of codes, HTTP mappings, retry rules
## 6. Signature profile        covered components, verification order, what is free
## 7. Channel                  service schema, URL, sequence, termination, availability
## 8. Renewal and rotation     agent side, server state, root rotation
## 9. Admin API                product-specific, kept for testing only
## 10. Agent local behavior    configuration, pending files, stored identities, CLI, metadata sent
## 11. Mock server             conformance only
```

Opening sentence pattern: "`CONTRACT.md` defines the protocol; `INTENT.md` explains the choices; `test-vectors.json` holds shared data."

## Provider contract (`picky-crypto/CONTRACT.md`)

```md
# `<crate>` contract

<It is normative: a backend author implements from this document alone; the conformance suite derives from it and the cited standards.>

## 1. Scope              what the contract consists of, section by section
## 2. General rules      apply to every operation, not repeated: outputs, no panics, advertised means implemented, valid domain and must-support set
## 3. Algorithm identifiers     closed set; 3.1 Extensibility
## 4. Errors             closed set, when each is returned, precedence
## 5. Encodings          one per concept
## 6. Capability traits  one subsection per capability: domain, must-support set, errors, implementation-defined outcomes
## 7. Private keys       including hardware keys
## 8. Provider value     composition, policy
## 9. Process-wide default
## 10. Helpers           written only against the public API
## 11. Providers built around the contract
## 12. Conformance testing      every claim tied to its test, known gaps, verified by review
## 13. Design rationale  short; the long form is INTENT.md
## Appendix A. Public API
```

## Common moves

- "These rules apply to every operation and are not repeated" at the top of general rules, so per-operation sections stay short.
- Precedence stated as "a bounds error always wins; a capacity limit may win over a structure error; this fixes which outcome wins, not the order among a backend's checks".
- Implementation-defined outcomes as closed sets per input: "loading returns `InvalidKey` or succeeds; signing returns `InvalidKey` or a signature that verifies under (n, e)".
- Stored-field ownership as a sentence naming the operations: "renewal, confirm and check-in update `last_seen_at`; an idempotent enrollment replay and stream closure do not".
- Exceptions inline with the rule they relax, with the condition that would remove them.
- Section anchors `<a id="<feature>-<topic>">` so intent files and skills link without breaking on renumbering.
