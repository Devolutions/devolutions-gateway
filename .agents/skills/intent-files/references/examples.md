# Examples the maintainer wrote

Only files Benoit Cortier wrote or rewrote himself appear here; files other contributors drafted from an LLM skeleton are deliberately excluded.
Read the file at the path given; what follows is only why it works.

## `picky-crypto-rustcrypto/INTENT.md` (Devolutions/picky-rs)

One commitment after review: `fips()` is always false, with the reason RustCrypto has no validated module, so the FIPS policy rejects it.
Two generic bullets were cut ("a backend is a thin adapter", "it passes the conformance suite") because the contract crate's intent already owns the first and CI the second; what remains is the one fact specific to this crate.
Its first Purpose sentence ("backend implemented on top of the RustCrypto crates") is path-level information and could go too; the feature policy below it is the real commitment.

## `picky-crypto-bundle/INTENT.md` (Devolutions/picky-rs)

Six commitments, each checkable against `Cargo.toml` and `lib.rs`, each saying what it rules out: fixed composition order, no default features (so feature unioning stays deterministic), additive features, no cryptographic code, installs nothing itself, applies no policy.
The last replaced "the bundle's `fips()` is false", which one configuration falsified; "a non-FIPS convenience that claims nothing" is the honest form.
Detail that would drift (§11 semantics) is a pointer into `CONTRACT.md`, not a copy.

## `picky-crypto/INTENT.md` (Devolutions/picky-rs)

The contract crate's intent, next to a 950-line `CONTRACT.md`.
Headings exist because there are enough commitments to need retrieval: a design principle in one bold sentence with its consequences and a test ("argument mapping never inspects the input beyond checking algorithm-fixed lengths and constant bytes"), a minimality rule with its three written exceptions, provider shape, process-wide default, invariants, non-goals.
It is long because the decisions are many, not because the template demanded sections.

## `docs/agent-identity/INTENT.md` (Devolutions/devolutions-gateway, PR #2000)

Rationale beside a protocol contract shared by four components.
Every bullet is a commitment with the alternative it excludes: "the token is deliberately not a JWT" (and why a signed token cannot work before enrollment), "the host and path are not signed because reverse proxies and IIS virtual directories can rewrite them", "the mock authority and agent implement the protocol independently" (so shared code cannot hide the same defect twice).
An earlier draft restated the contract (token format, operations table); the maintainer made `CONTRACT.md` self-contained and kept here only the choices and their reasons.
Component intents link here with stable anchors and say in a sentence that this file applies to them.
