# Agent Identity contract: intent

[CONTRACT.md](CONTRACT.md) is the complete, product-neutral specification between Devolutions Agent and an authority, with [test-vectors.json](test-vectors.json).
This file records the decisions it must preserve.

DVLS and PSU implement the contract unchanged; only the base URL differs.
The agent, the mock authority and the conformance tester are each derived from it independently.

Changes to the formats, operations, semantics or error codes below are changes to intent.

## Conventions

- JSON uses snake_case keys, as elsewhere in Devolutions Gateway.
  Optional fields are omitted, never `null`.
  Receivers ignore unknown fields.
- Each operation has one relative path, identical across authorities, under `api/agent-identity/v1/`.

## Enrollment token

Format: `dvaet1.<bag>.<secret>`

- `dvaet1`: Devolutions Agent Enrollment Token, format version 1.
  Recognizable by secret scanners.
  A format change bumps the version.
- `bag`: unpadded base64url of a JSON object; `u` holds the authority's base URL.
  The bag is not signed; the agent uses it for routing only.
- `secret`: opaque to the agent.
  Authorities store only its SHA-256.

The whole token is sent as a bearer credential on `enroll`, and nowhere else.

The token is deliberately not a JWT.
The authority must look the token up anyway (use counter, deletion), and the agent can't verify a signature before it is enrolled.

## Operations

| Operation | Authentication | Purpose |
|---|---|---|
| `trust-anchor` | None | The currently published roots: one normally, two during a root rotation |
| `enroll` | Enrollment token | CSR and metadata in; device ID, certificate chain and config out |
| `renew` | Signed with the current key | CSR for a new key in; a pending certificate out |
| `confirm` | Signed with the new key | Makes the pending certificate current |
| `check-in` | Signed with the current key | Metadata in; config and renewal request out |

### `trust-anchor`

- Intended for third-party relying parties.
- Chain validation against these roots does not reflect revocation.
  It is not proof that a device is still authorized.

### `enroll`

- A use is consumed only when a device is created, atomically with its creation.
- The authority mints the device UUID.
- Retrying with the same token and the same CSR key returns the same device, consumes no use, and changes nothing on the device.
  A CSR proves past possession of the key, not present possession, so a replay never updates the device.
- Such a retry succeeds even if the token has since been exhausted, expired or deleted: a lost response is always recoverable.
  Deleted tokens are kept for that purpose only.
- An authority never certifies the same public key twice, even after the device is deleted.
- The friendly name is evaluated at enrollment from the token's format and kept on the authority.
  The agent never receives it, and neither renewal nor the channel ever changes it.

### `renew`

- The CSR carries the new key.
- It returns a `pending` certificate; it never makes it current.
  Retrying with the same CSR returns the same pending certificate.
- Accepted with a certificate expired for less than its own lifetime (`notAfter − notBefore`): the grace window.
  Beyond it, the device needs a new token.

### `confirm`

- The only operation that makes a certificate current.
  Because it is signed with the new key, a certificate becomes current only once the device has proven it holds that key.
- Idempotent.
- It retires the previous certificate; streams opened with it are asked to reconnect, then closed.

### `check-in`

- Reports the device's metadata and returns its current config and whether a renewal is requested.
- Only used by devices without a working agent channel, at most once a day.
  With a working channel, the channel carries both.
- Nothing else is delivered over HTTP.

## Config

- Returned by `enroll`, then kept current over the agent channel (reconciled at every connection, pushed on change) or, without a working channel, through `check-in`.
- `version` is the schema version.
  `revision` strictly increases for a device on every change; the agent keeps only a newer revision.
- `agent_channel_url` is optional.
  Its absence means no agent channel for that authority, whatever the reason.
- Products may add their own fields (e.g. a PSU channel URL); the agent ignores those it doesn't know.

## Errors

| Code | Meaning |
|---|---|
| `token_invalid` | Unknown or deleted token |
| `token_exhausted` | Use cap reached |
| `token_expired` | Token past its expiry |
| `device_revoked` | Device is revoked |
| `device_unknown` | No registered certificate for this key (e.g. deleted device) |
| `certificate_expired` | Certificate expired, and outside the grace window where one applies |
| `signature_invalid` | RFC 9421 verification failed |
| `clock_skew` | `created`/`expires` outside the accepted window; carries the server time |
| `invalid_request` | Malformed request, CSR or metadata |

## Metadata

- Keys: `hostname`, `fqdn`, `domain`, `os_name`, `os_version`, `arch`, `agent_version`, `machine_id` (SMBIOS UUID on Windows, machine-id on Linux).
- The agent always sends `hostname`, `os_name`, `os_version`, `arch` and `agent_version`, collected at the time of each request.
- Sent at `enroll`, `renew` and `check-in`, and in every channel `Hello`.
  The authority keeps the latest.
- The authority rejects anything unreasonable: sizes, control characters, unexpected shapes.
- Metadata is never used for authorization.

## Device certificates

- Leaf: P-256, `CN=<device uuid>`, SAN URI `urn:uuid:<device uuid>`, EKU clientAuth.
- A leaf's `notAfter` never exceeds its issuing root's `notAfter`.
- Chains are leaf-first; the number of CA tiers is the authority's choice.
- The certificate thumbprint is the SHA-256 of the certificate's DER encoding.

## RFC 9421 profile

- Headers: `Signature-Input` and `Signature`.
  On gRPC, they are sent as request metadata with the same values.
- Parameters, all required:
  - `alg="ecdsa-p256-sha256"` (raw r‖s);
  - `keyid`: unpadded base64url of the certificate thumbprint;
  - `created`, `expires` (short window), `nonce` (single use);
  - `tag`: one per operation (`renew`, `connect`, `confirm`, `check-in`).
- Covered components are exactly `@method`, plus `content-digest` (RFC 9530, sha-256) for operations with a body.
  The authority enforces that list itself; it never trusts the list the request declares.
- `@authority` and `@path` are deliberately not covered, because reverse proxies and IIS virtual directories rewrite them.
  Per-authority keys prevent replay against another authority; `tag` prevents replay against another operation.

## Device authentication

A signed request is authenticated as a device if and only if all of the following hold:

- `keyid` matches a certificate the authority registered as `current` or `pending`;
- that certificate's device is not revoked;
- the signature verifies with that certificate's public key;
- the certificate is unexpired, or, for `renew` only, expired within the grace window.

The agent never sends its certificate to authenticate to the authority.
Chain validation alone is not authentication.

## Channel

The agent channel is defined by `agent-channel-proto` and served at `config.agent_channel_url`.
