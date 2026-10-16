# Intent file examples

Each example is a real file that survived maintainer review, followed by what makes it work.
Spacing and line breaks are normalised here, and a file may have grown since; when reviewing, read the committed version, not this copy.
Read the one closest to the shape you need.

## 1. Module-level `*.intent.md` with a scope and a boundary

`devolutions-gateway/src/streaming.intent.md`, next to `streaming.rs`.

```md
# Recording streaming intent

## Scope

These rules apply to the `/shadow` WebSocket streaming path implemented by `streaming.rs`.

This includes:

- recording file-type classification
- streamability decisions
- streaming implementation selection
- terminal input-format selection

They do not define the following:

- JREC push behaviour
- JREC pull behaviour
- artifact storage
- download MIME types
- consumer-side rendering.

## Streaming contract

Only WebM, asciicast, and TRP recording artifacts are accepted by the `/shadow` streaming path.

| Recording file type | Extension | Streaming behaviour |
| --- | --- | --- |
| `WebM` | `.webm` | WebM streaming |
| `Asciicast` | `.cast` | Terminal streaming using asciinema input |
| `TRP` | `.trp` | Terminal streaming using TRP input |
| `SessionRecordingLog` | `.slog` | Explicitly rejected by the `/shadow` streaming path |

- A recognised `RecordingFileType` is not automatically supported by `/shadow` streaming.
  Each recognised recording file type must have explicitly defined behaviour for the `/shadow` streaming path.
- Files with missing or unrecognised extensions must be rejected before WebSocket streaming begins.

## Architectural invariants

- Recording artifact streaming must use the canonical `RecordingFileType` extension mapping as its source of truth.
- A recording file must be classified once.
  The resulting `RecordingFileType` must determine whether the artifact is supported, which streaming implementation is used, and which terminal input format is used.
- Streaming validation, streamer selection, and terminal input selection must not maintain separate extension mappings or independently compare known recording extensions as raw strings.
- Adding a new `RecordingFileType` requires an explicit decision about whether it is supported by the `/shadow` streaming path and, if supported, how it is streamed.
- A new or unsupported recording file type must not silently fall back to an existing streaming implementation or terminal input format.

> **Boundary:** Session Recording Log artifacts are supported elsewhere in Gateway through the JREC recording flow.
> Their rejection by `/shadow` applies only to the WebSocket streaming path covered by this document.
```

Why it works:

- The scope names one path and one file, and lists what the rules do not define, so nobody applies them to JREC.
- The table is a small, exact inventory where exactness is the point; the bullet right after turns it into a rule that survives the next variant ("each recognised type must have explicitly defined behaviour").
- "Adding a new X requires an explicit decision" is the shape to use whenever the risk is silent fallback.
- The boundary note pre-empts the most likely misreading.

## 2. Crate `INTENT.md` with a single invariant and its reason

`picky-crypto-rustcrypto/INTENT.md`.

```md
# picky-crypto-rustcrypto

## Purpose

`picky-crypto` backend implemented on top of the RustCrypto crates.

It implements every algorithm of the contract that RustCrypto provides when the `all` feature is enabled, including legacy algorithms (MD4, MD5, RC4, 3DES, RC2) needed by NTLM, Kerberos and legacy PKCS#12.
No family is enabled by default; each feature adds a family of entries.

## Invariants

- `fips()` always returns `false`, because RustCrypto has no FIPS 140 validated module, so the FIPS policy rejects any provider containing its entries.
```

Why it works:

- Earlier drafts repeated "a backend is a thin adapter" and "it passes the full conformance suite" in every backend file.
  Both were cut: the contract crate's intent already defines the adapter rule, and CI already enforces conformance.
  What remains is the one fact specific to this crate.
- The invariant started as a bare rule, drew "explain why", and gained its reason.

## 3. Crate `INTENT.md` for a composition crate

`picky-crypto-bundle/INTENT.md`.

```md
# picky-crypto-bundle

## Purpose

A single, named provider composed from the workspace's backends and fill-in providers, exposed through one `provider()` function.

It is what the convenience features of consuming libraries install: each forwards to this crate's features, so every library installs the same provider and the result does not depend on which library installs first.
Binaries may install it explicitly or build their own composition.

## Invariants

- Its composition is fixed and documented: every enabled backend in a fixed order (aws-lc, then ring, then RustCrypto), each a fallback for the previous, then the key-based KDFs that `picky-crypto-composed` builds over that composition, then `picky-crypto-ffdh` using the first random entry available.
- It has no default features.
  Each backend and each fill-in provider is behind its own feature, and `all` enables everything available.
- Features are additive: enabling a feature only adds entries, so dependents that enable different features still get one deterministic provider, though an earlier backend's entry can refuse inputs a later one accepted (`CONTRACT.md` §11).
- It contains no cryptographic code.
  It only assembles providers from the crates above.
- It installs nothing itself.
  Only the convenience features of consuming libraries install it.
- It is a non-FIPS convenience and applies no policy.
  FIPS binaries install a FIPS-capable backend with the FIPS policy explicitly.
```

Why it works:

- Every invariant is checkable by reading `Cargo.toml` and `lib.rs`, and each says what it rules out.
- The last bullet replaced "the bundle's `fips()` is false", which one configuration (an aws-lc FIPS build alone) falsified.
  "Claims nothing" is the honest statement.
- Detail that would drift (§11 semantics) is a pointer, not a copy.

## 4. Rationale `INTENT.md` next to a `CONTRACT.md`

`docs/agent-identity/INTENT.md` (excerpt).

```md
# Agent Identity – Design Rationale

[CONTRACT.md][contract] defines the protocol, and [test-vectors.json][vectors] contains shared test data.
This file explains the main design choices and the reasons behind them.
It repeats contract details only when needed to explain a design choice.

## Enrollment tokens

- The token is deliberately not a JWT.
  The authority already needs stored state for use limits, deletion and retry recovery, and an unenrolled agent has no authority key with which to verify a signed token.
- Deleting a token keeps a tombstone.
  This lets a device recover a lost enrollment response without allowing the deleted token to create another device.

## Request authentication

- The host and path are not signed because reverse proxies and IIS virtual directories can rewrite them.
  A different key for each authority prevents reuse with another authority, and the operation tag prevents reuse at another endpoint.
- The authority authenticates a device through a registered current or pending certificate and proof of its private key.
  The agent does not send the certificate itself to the authority, and validating a certificate chain alone does not prove that the device is still authorized.

## Conformance

- The mock authority and agent implement the protocol independently and share only the channel schema.
  This prevents shared protocol code from hiding the same defect on both sides.

<a id="agent-identity-request-authentication"></a>

[contract]: CONTRACT.md
[contract-token]: CONTRACT.md#agent-identity-enrollment-token
```

Why it works:

- The previous draft restated the contract (token format, operations table, conventions) under the heading "decisions it must preserve".
  The maintainer made the contract self-contained and rewrote this file as rationale only.
- One decision per bullet, reason on the next line, every time.
- Stable anchors let crate intents link here without breaking on rename.

## 5. Named exception appended to an existing intent

`picky-ssh-putty-exception.md`, a section added to picky's intent.

```md
## Exception: SSH and PuTTY private keys

The `ssh` and `putty` features protect encrypted private keys with bcrypt-pbkdf, AES-CTR and Argon2, which the `picky-crypto` contract does not define.
These features therefore do not go through the provider: they use RustCrypto crates directly.
`PrivateKey::from_rsa_components`, which SSH and PuTTY key decoding use, falls under the same exception: it completes the key's CRT values with RustCrypto crates, outside the provider.
It sits behind its own picky feature, enabled by default and by `ssh` and `putty`.
This is the only exception to "depends on the contract crate only" in picky.
These features are not FIPS-capable and must never be enabled in a FIPS binary; the FIPS dependency-ban fixture verifies this.
Removing this exception requires either adding these primitives to the contract as capabilities (`CONTRACT.md` §3.1) or removing these features; if SSH and PuTTY keys move onto the provider instead, `PrivateKey::from_rsa_components` completes keys with `picky-crypto-rsa-crt`.
```

Why it works:

- The exception sits with the rule it relaxes and names the rule exactly.
- It says what enforces it today and what would have to change to remove it, so it cannot silently become permanent or silently disappear.

## 6. The `AGENTS.md` counterpart

What goes in `AGENTS.md`, not intent, for the same repository.

```md
## Intent files

Read all applicable `INTENT.md` and `*.intent.md` files before modifying code.

Do not create, modify, delete, or rename intent files.

If a requested change conflicts with intent, stop and surface the conflict for human resolution.
```

```text
INTENT.md:  This crate must remain `no_std` compatible.
AGENTS.md:  Run `cargo check --no-default-features` after changing this crate.
```

The first would matter for a human contributor; the second tells an agent how to validate.
