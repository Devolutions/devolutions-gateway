NOTE: Interim copy, never merged here.
This is the intent of DVLS's Agent Identity module; it moves into the RDM repository unchanged except for this note.
Nothing in this repository depends on it except the mock authority, which replicates DVLS's management API as `crates/agent-identity-mock/INTENT.md` describes.

## Overview

This module makes DVLS an Agent Identity authority.
Below, `CONTRACT.agent-identity.md` is `docs/agent-identity/CONTRACT.agent-identity.md` and "the shared intent" is `docs/agent-identity/INTENT.agent-identity.md`, both in the `Devolutions/devolutions-gateway` repository; read both before changing this module.
The rules every authority applies the same way live in the `Devolutions.AgentIdentity` library, published from that repository; this module adds storage, hosting and management.

## Terminology

- **Management API**: the HTTP API that administrators and tools use to manage enrollment tokens, identities and root rotation.
  It is product-specific: DVLS's management API is a model that PSU may follow, with no obligation.
  Avoid "admin API".
- **Identity status**: one of four values, distinct from the certificate statuses `pending`, `current` and `retired` that `CONTRACT.agent-identity.md` defines; their wire spelling follows DVLS's public API contract:
  - `active`: not revoked, and holds an unexpired current or pending certificate, so it can authenticate;
  - `grace`: not revoked, and holds no unexpired certificate but one within renewal grace, so it can only renew;
  - `expired`: not revoked, and beyond renewal grace; only a new enrollment brings the device back;
  - `revoked`.

## Root CA

- DVLS runs a single-tier CA: one P-256 root, valid 10 years, `CN=<product> Agent Identity Root <n>`, where `<n>` is the root generation number, signs identity certificates directly.
  An intermediate CA would sit on the same server as the root and add no security; the agent accepts chains of any length, so one can still be added later.
- DVLS creates the root when the first enrollment token is created, so a root exists before any agent can enroll, and a DVLS that never uses the feature holds no root.
- The root private key is stored only encrypted, with AES-256-GCM under a key derived by HKDF from DVLS's data encryption key, and no API exports it.
  When the data encryption key changes, the root key is re-encrypted like everything else.
- When the root key cannot be decrypted, only the operations that need it fail: enrollment, renewal and root rotation.
  The rest of DVLS keeps working, existing identities keep authenticating, and administrators see the error.
- DVLS warns administrators ahead of the root's expiry, and starts a rotation automatically at least one certificate lifetime before the root expires, so that the root's expiry never shortens a certificate.
- `authority_id` is generated once and stored in the DVLS settings.

## Certificates and channel

- The certificate lifetime is set in days.
  A test-only setting allows a lifetime in seconds for the conformance suite's expiry tests, and is hard to enable by mistake.
- DVLS offers the agent channel (`config.agent_channel_url`) whenever its hosting supports gRPC channels; which hosting setups and versions qualify is left to the implementation.
- The administrator setting "Agent channel enabled", on by default, turns the channel off behind reverse proxies that break gRPC, which DVLS cannot detect.

## Load

- Rotation notifications are sent to connected identities at a configurable rate, 10 identities per second by default.
- DVLS answers renewals beyond its capacity with `503 unavailable` and `Retry-After`.

## Later

- Multi-node DVLS support for Agent Identity is wanted later.
- Two identities for the same device are an anomaly.
  Later, DVLS flags identities that may belong to the same device with a warning, for example when the last-seen time is old or a newer identity has the same machine name; an administrator decides what to revoke or delete.

## Management API

The management API is part of DVLS's public API, so that administrators and tools script it like any other DVLS operation.
It follows DVLS's public API contract (`DVLS/Server/server/Common/PublicApi/CONTRACT.md`) for routes, models, paging, errors, enum spelling and authentication, and DVLS's public OpenAPI document is its exact reference; this section holds the decisions behind it.

- Four permissions follow DVLS's View and Manage convention for Agent Tunnel agents, with revocation and root rotation separate:
  - View: read enrollment tokens, identities, the rotation status and Agent Identity's settings;
  - Manage: create and delete enrollment tokens; rename identities, request their renewal, and delete revoked identities; change Agent Identity's settings;
  - Revoke: revoke identities;
  - Rotate root: start a root rotation.

  Roles grant them to users and application identities; built-in administrators hold all four.
- Agent Identity's settings are "Agent channel enabled", the certificate lifetime in days and the rotation notification rate.

### Enrollment tokens

- The full token is returned only when the token is created.
- A token's expiry is chosen when it is created, at most 365 days ahead, so that no token lasts forever.
  DVLS suggests 90 days to the administrator: a token in an Intune deployment enrolls every device that joins later, and a device whose token has expired is not retried once its install has succeeded.
- DVLS warns administrators before a token that is still enrolling devices expires.
- A token allows from 1 to 1,000,000 uses.
- A token's friendly-name format follows the shared intent, "Enrollment"; a format with an unpaired brace or an unknown placeholder is rejected.
- A token's config contributes the product-specific fields of each identity enrolled with it.
- Tokens are immutable after creation; deletion is the only change.

### Identities

- The management API names each record an identity, like the wire names; "device" stays free for a later view that groups identities by machine.
- Each identity receives a strictly increasing creation key when inserted, and listings sort by that key; the creation time is non-decreasing in this order.
  A page walk returns every identity that existed when the walk started at least once, and exactly once when no enrollment overlaps the walk; only a deletion during the walk can make it miss one.
  An identity whose enrollment overlaps the walk may be missing from it or make the next page repeat one entry; clients deduplicate by `id`.
  Identity IDs remain UUIDs and are not used as the listing sort key.
- An identity is `connected` while it has at least one live stream authenticated by its channel proof (`CONTRACT.agent-identity.md` §7.3 step 4); a stream counts only after that step succeeds.
- The friendly name is 1 to 255 Unicode scalar values, and is readable and renamable only through this API.
- An identity can be deleted only once revoked.
- Requesting a renewal sets the request-renewal flag (`CONTRACT.agent-identity.md` §8.2) and sends `RenewRequested{reason:"admin"}` on each authenticated live stream.

### Rotation

- One rotation runs at a time.
- An administrator may set the deadline; a deadline at or before the current time requests an emergency rotation.
  Without one, the deadline is the rotation maximum: the latest `notAfter` among unexpired current or pending certificates of non-revoked identities issued by the old root, or the current time when there are none.
  A deadline after the rotation maximum is refused.
- The rotation status reports how many non-revoked identities still hold an unexpired current or pending certificate issued by the old root; rotation completes when that count reaches 0 (`CONTRACT.agent-identity.md` §8.3).
