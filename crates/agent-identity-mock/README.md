# agent-identity-mock

Mock server for the [Agent Identity V1 contract][contract], used as the conformance oracle.
It implements the agent-facing protocol, the [DVLS management API][dvls-management] and the [mock controls][mock-control] in memory.
It shares only `crates/agent-channel-proto` (the generated gRPC types) with the agent.

## Usage

```
agent-identity-mock --listen 127.0.0.1:0 --path-prefix /mock --app-key <key> --app-secret <secret> --state-dir <dir>
```

| Flag | Meaning |
|---|---|
| `--listen <addr:port>` | TCP bind address; it must be a loopback address because the mock control surface is unauthenticated, and port `0` picks a free port. |
| `--path-prefix <prefix>` | Every route lives under this prefix (e.g. `/mock`); requests outside it get a bare 404. Must start with `/` and not end with `/`. |
| `--app-key <key>` | Key of the application identity that [logs in](#login) to the management API; the keys that hold fewer permissions derive from it. |
| `--app-secret <secret>` | Secret of the application identity, shared by all its keys. |
| `--token-lifetime-secs <secs>` | How long a `tokenId` lasts after its login; `420` (DVLS's 7 minutes) by default. |
| `--state-dir <dir>` | Where `ready.json` and the TLS CA PEM are written; created if missing. |

On startup the server generates a TLS CA and a server certificate for `localhost`, `127.0.0.1` and the listen address, and serves HTTPS on a single port with ALPN `h2` and `http/1.1` (REST and gRPC share the port).
Like a DVLS that has never used Agent Identity, it holds no root until the first enrollment token or `__mock__/reset` creates one.
It then writes `<state-dir>/ready.json` atomically (temp file + rename):

```json
{ "base_url": "https://<listen address>:<port>/mock", "tls_ca_pem": "<abs path to CA PEM>", "authority_id": "<uuid>" }
```

`tls_ca_pem` is what an agent trusts through `__debug__.identity.extra_trusted_root`.
`authority_id` is stable for the process lifetime, including across `__mock__/reset`.

## Clock

All time in the mock is the mock clock, real time plus an offset, except the [`tokenId` lifetime](#login).
`POST __mock__/time/advance` adds to the offset and `faults.clock_skew_secs` adds a skew on top.
Signature windows, certificate validity, token expiry, renewal grace, rotation deadlines, `server_time` and `lastSeenOn` all use it.
A certificate is unexpired while `now ≤ notAfter`, and `notBefore` is never checked (§6).
A stream closes with `certificate_expired` once the clock reaches the certificate's `notAfter`, because §7.4 closes a stream no later than then; a stream opened at `notAfter` therefore closes right after its `Challenge`.
Advancing or freezing the clock immediately closes expired streams and re-evaluates rotation deadlines and early completion.
`POST __mock__/time/freeze` is a test-only boundary probe that pins the mock clock to an exact Unix second and reports the published root thumbprints in the same state transition; reset restores real-time tracking.

## Routes

All paths below are relative to `base_url` (i.e. they include the path prefix).

### Agent-facing (CONTRACT.agent-identity.md §5), no management API credential

| Method | Path | Notes |
|---|---|---|
| GET | `/api/agent-identity/v1/trust-anchor` | `{ "roots": [ { "certificate" (base64 DER), "thumbprint", "not_before", "not_after" } ] }`; none before the first root exists, and two while a rotation is in progress. |
| POST | `/api/agent-identity/v1/enroll` | `Authorization: Bearer <dvaet1 token>`; body `{ "csr": "<base64 DER PKCS#10>", "metadata": {...} }`. |
| POST | `/api/agent-identity/v1/renew` | RFC 9421-signed with `tag="renew"`; `Content-Digest` over the exact body bytes. |
| POST | `/api/agent-identity/v1/confirm` | RFC 9421-signed with `tag="confirm"` and an empty body; `204` for promotion or an idempotent retry. |
| POST | `/api/agent-identity/v1/check-in` | RFC 9421-signed with `tag="check-in"` and a digested `{ "metadata": {...} }` body; returns effective `config` and `renewal_requested`. |

Non-2xx agent-facing responses carry `{ "error", "message", "server_time" }` with the §5.4 codes.
An unexpected failure, such as issuing from an expired root or a handler panic, is `500 unavailable`.
Enrollment, renewal and check-in require a `metadata` object, which may be empty.
A body that repeats a member name at any depth, holds more than 64 nested objects and arrays, counting the top-level object, or holds a string that is not valid Unicode, such as an escaped lone surrogate, is `invalid_request` (§1).
So is a `csr` that is not canonical `base64` or a CSR key that is not an uncompressed P-256 point (§1, §4).
A token authenticates by its exact secret text alone: the bag is never checked, and another encoding of the same secret bytes is `token_invalid` (§2).
Metadata is limited to 16 KiB in aggregate, and agent-facing request bodies are limited to 64 KiB.
A larger body gets `413 invalid_request` before authentication; otherwise an authentication error wins over an invalid body, CSR or metadata (§5.4).
Enrollment returns `config.version`, `config.revision` and optional `config.agent_channel_url`, never a top-level channel URL.
Friendly names are stored server-side and appear only in the management API.
Config revisions start at 1 and increase only on effective changes; `ConfigUpdate` follows `Welcome` for stale Hellos and is pushed to live streams after a change.
A token's optional `config` object supplies product-specific fields to its enrolled identities; it cannot set `version`, `revision` or `agent_channel_url`.
The mock holds no config whose `ConfigUpdate` envelope, measured with a 36-character `id`, would exceed 64 KiB (§7.1).
A change that would grow one past that is refused and changes nothing.
An enrollment whose token config no longer fits, because the channel offer or the version override grew it, is `500 unavailable` and does not count against the token's `maxUses`.
The mock uses a test-only unbounded push queue so config bursts cannot silently detach authenticated streams or discard termination messages.
`POST __mock__/config` adds unknown fields so tests can check that agents preserve them.
Only confirm promotes a pending certificate: old streams receive `Reconnect{reason:"certificate_rotated"}` and close with `OK` after 60 mock-clock seconds if still open.
A stream awaiting `Hello` closes once the clock reaches its certificate's `notAfter`, and for revocation or deletion when its `Hello` arrives or times out (§7.4).
These closures come ahead of any handshake failure, and revocation or deletion wins over expiry.
A stream whose certificate is retired during that wait completes the handshake, then receives the same `Reconnect` and closes with `OK` 60 mock-clock seconds after it.
An agent message that cannot be decoded closes an authenticated stream with `INVALID_ARGUMENT` + `invalid_request` (§7.4).
Channel envelopes are at most 64 KiB of serialized protobuf in each direction, without gRPC's 5-byte prefix (§7.1).
A larger agent message counts as one that cannot be decoded: `UNAUTHENTICATED` + `signature_invalid` in place of `Hello`, and `INVALID_ARGUMENT` + `invalid_request` after `Welcome`.
The channel gRPC method is `POST <prefix>/devolutions.agent.channel.v1.AgentChannel/Connect` with `signature-input`/`signature` metadata (`tag="connect"`); open failures are gRPC statuses with `error-code` and `server-time` trailers (§7.4).

### Login

DVLS's login opens the sessions that authenticate the [management API](#management-api), with the operations and models of DVLS's public OpenAPI document:

| Method | Path | Notes |
|---|---|---|
| POST | `/api/v1/login` | Body `LoginParameters`, `{ appKey, appSecret }`; 200 → `LoginResult`, `{ tokenId }`. A missing or empty `appKey` or `appSecret`, or a member `LoginParameters` does not define, is 400 with no body, and a wrong key or secret is 401 with a `PublicApiError` body, `{ "message" }`. |
| POST | `/api/v1/logout` | Closes the session the `tokenId` header names; 200 with no `Content-Type` and no body, even without a `tokenId` or with one that names no open session, so a logout is idempotent. |

Each login opens another session with a new random `tokenId`, and earlier sessions stay open.
A `tokenId` expires `--token-lifetime-secs` after its login, however often it is used.
The lifetime runs on real time, not the mock clock, because tests advance the mock clock by days.

The application identity's keys derive from `--app-key`, so a test can hold any subset of the four permissions without setup; each logs in with `--app-secret`:

| Key | Permissions |
|---|---|
| `<app-key>` | All four, like a DVLS built-in administrator. |
| `<app-key>.<scope>` | Those in `<scope>`: `none`, or a `+`-separated list of `view`, `manage`, `revoke` and `rotate-root`, such as `view+revoke`. |
| `<app-key>-unprivileged` | None, like `<app-key>.none`. |

Any other key, including a scope with an empty or unknown permission name, fails to log in.

### Management API

The [DVLS management API][dvls-management] has the operations, models, enums, paging and errors of DVLS's OpenAPI document for Agent Identity (`v1`, 14 operations), under `/api/v1/agent-identity`.
A request carries the `tokenId` of a [session](#login) in the `tokenId` header.
A request without one, even with an `Authorization` header, is 401 with no `Content-Type` and no body.
A repeated, unknown, expired or logged-out `tokenId` is 401 with `Content-Type: application/json; charset=utf-8` and exactly `{"message":"Missing or invalid token"}`.
Invalid parameters are 400 with a `PublicApiValidationError` body, `{ "errors": [ { "field", "message" } ] }`, where `field` names the camelCase member or query parameter, `config.<key>` for a token config entry, or is `null` for a malformed body or query string.
Every other error is 403, 404, 409 or 422 with a `PublicApiError` body, `{ "message" }`.
A request body is a JSON object; a member its schema does not define is 400, and so is a member name repeated at any depth, more than 64 nested objects and arrays, or a string that is not valid Unicode, as CONTRACT.agent-identity.md §1 requires of agent-facing bodies.
Each operation requires the permission the table lists, and a session without it gets 403 before the request is processed.

Enums are PascalCase.
An identity's `status` is `Active` (an unexpired current or pending certificate), `Grace` (no unexpired certificate, but one within renewal grace), `Expired` (beyond renewal grace) or `Revoked`, as the DVLS intent's "Terminology" defines.
A certificate's `status` is `Pending`, `Current` or `Retired`, a token's `state` is `Active`, `Exhausted` or `Expired` (which wins), and the rotation's `phase` is `Idle` or `Rotating`.
Timestamps are RFC 3339 UTC with `Z` and named `*On`; certificate and root validity is `validFrom` and `validUntil`.
A date-time parameter is UTC unless it carries an offset, and keeps its fraction of a second: token expiries, rotation deadlines and last-seen filters compare and return it exactly.
List operations take `pageNumber` (default 1), `pageSize` (default 25, at most 100 identities or 500 tokens), `sortOrder` (`1` ascending by default, `0` descending) and `sortField`, and return `{ currentPage, data, pageSize, totalCount, totalPage }`.
A page past the last is 400, and page 1 of an empty list is its last page.
A query parameter with an empty value is present, so an empty integer or enum value is 400.
An ID that is not a GUID is 404, like an unknown one.

| Method | Path | Permission | Notes |
|---|---|---|---|
| POST | `/api/v1/agent-identity/enrollment-token` | Manage | Body `{ name (1..255 scalar values, not blank), maxUses (1..1_000_000), expiresOn? (future, ≤ now + 365 d, default now + 90 d), friendlyNameFormat? (≤ 1024 scalar values), config? }`; 201 → `{ enrollmentToken, token }`, the only response with the full `dvaet1` token. A friendly-name format with an unpaired brace or an unknown placeholder is 400. `config` holds at most 32 string entries, each key matching `^[a-z][a-z0-9_]{0,63}$` other than `version`, `revision` and `agent_channel_url`, each value at most 1024 bytes without control characters. A `config` that would give its identities a config past one channel envelope is 400 on `config`. The first token creates the root, and is 409 when it cannot (`root_key_unavailable`). |
| GET | `/api/v1/agent-identity/enrollment-token` | View | Page of the tokens that are not deleted; `sortField` is `createdOn` (default), `name` or `expiresOn`, with ties in creation order. |
| GET | `/api/v1/agent-identity/enrollment-token/{id}` | View | `AgentIdentityEnrollmentToken`, without the full token; 404 when unknown or deleted. |
| DELETE | `/api/v1/agent-identity/enrollment-token/{id}` | Manage | 204, or 404 when unknown or already deleted; the token can still replay its own existing current key without side effects, while a new key gets `token_invalid`. |
| GET | `/api/v1/agent-identity` | View | Page of identities in creation order (`sortField` is `createdOn` only). Query: `view=Summary\|Full`, repeated `metadataKey`, repeated `status`, repeated `enrollmentTokenId`, `issuerThumbprint` (the current certificate's issuer), `lastSeenFrom` and `lastSeenTo` (inclusive), and `search` (case-insensitive friendly-name substring); filters combine with AND. The Summary view carries `id`, `friendlyName`, `status`, `isConnected`, `lastSeenOn`, `certificate { issuerThumbprint, validUntil }` while the identity has a current certificate, and the requested `metadata` keys, omitted when none match. |
| GET | `/api/v1/agent-identity/{id}` | View | Full view: the Summary members, all `metadata`, `certificates` (newest first), `createdOn`, `enrollmentTokenId`, `enrollmentTokenName`, `isRenewalRequested`, and `revokedOn` once revoked. |
| PATCH | `/api/v1/agent-identity/{id}` | Manage | `{ friendlyName? }` (1..255 scalar values without leading or trailing white space); absent or `null` changes nothing; 200 → Full view. |
| POST | `/api/v1/agent-identity/{id}/revoke` | Revoke | 204, idempotent; closes live streams PERMISSION_DENIED + `identity_revoked`. |
| DELETE | `/api/v1/agent-identity/{id}` | Manage | 204, or 409 unless the identity is revoked. |
| POST | `/api/v1/agent-identity/{id}/request-renewal` | Manage | 202; sets the flag and pushes `RenewRequested{reason:"admin"}` to live streams; 409 when the identity is revoked. |
| POST | `/api/v1/agent-identity/rotation` | Rotate root | Body `{ deadlineOn? }`, `{}` for the rotation maximum: the latest `notAfter` among the old root's unexpired current or pending certificates of non-revoked identities, or now when there are none. A deadline at or before now is an emergency rotation. 202 → `AgentIdentityRotation`; 409 while rotating, without a root, or with `root_key_unavailable`; 422 for a deadline after the rotation maximum. |
| GET | `/api/v1/agent-identity/rotation` | View | `{ phase, startedOn?, deadlineOn?, oldRoot?, newRoot?, oldRootActiveIdentityCount }`, each root `{ thumbprint, validFrom, validUntil }`; the count includes each non-revoked identity with an unexpired current or pending old-root certificate, and is 0 while `Idle`. |
| GET | `/api/v1/agent-identity/settings` | View | `{ authorityId, isAgentChannelEnabled, isAgentChannelAvailable, certificateLifetimeDays, rotationNotificationsPerSecond }`, by default `true`, `true`, `90` and `10`. |
| PATCH | `/api/v1/agent-identity/settings` | Manage | `{ isAgentChannelEnabled?, certificateLifetimeDays? (1..365), rotationNotificationsPerSecond? (1..1000) }` → settings. An `isAgentChannelEnabled` that would grow a config past one channel envelope is 400 on that member, and nothing changes. |

The channel is offered (`isAgentChannelAvailable`) while `isAgentChannelEnabled` is on and the `channel_available` fault, which stands for the hosting, is on.
A change of the offer adds or removes `agent_channel_url` in every config, bumps revisions and pushes `ConfigUpdate`, and channel openings are refused while the channel is not offered.
`certificateLifetimeDays` applies to certificates issued afterwards, and `rotationNotificationsPerSecond` to rotation notifications; the `leaf_lifetime_secs` and `rotation_rate_limit_per_sec` faults override them.
A rotation completes immediately when no active old-root identity remains, including at rotation start, and publishes only the new root.
Certificate issuance and token-use consumption share the state lock; issued key hashes stay reserved, and original issuance times remain stored after identity deletion.

### Mock control ([mock controls][mock-control]), no auth

| Method | Path | Notes |
|---|---|---|
| POST | `/__mock__/faults` | Merges `drop_next_response`, `fail_next_response`, `clock_skew_secs`, `leaf_lifetime_secs`, `channel_available`, `channel_broken`, `malformed_channel_url`, `rotation_rate_limit_per_sec`, `config_version` and `root_key_unavailable`; absent keys retain their value, and `null` clears optional fields. `leaf_lifetime_secs` (seconds) overrides the `certificateLifetimeDays` setting and `rotation_rate_limit_per_sec` the `rotationNotificationsPerSecond` setting, without the settings' bounds. `channel_available` is whether the hosting supports the channel; toggling it changes the channel offer as the [management API](#management-api) describes. `config_version` (an unsigned integer) replaces `config.version` in every config the mock delivers, and setting it to a different version or clearing it bumps every identity's config revision and pushes `ConfigUpdate`; `channel_broken` only rejects new streams. Set `malformed_channel_url` to `true` for an HTTP URL, `"query"` for an HTTPS URL with a query, or `"fragment"` for an HTTPS URL with a fragment in new enrollments; `false` or `null` clears it. `root_key_unavailable` (a boolean) makes the root key undecryptable: enrollment and renewal fail with `500 unavailable`, root rotation and the creation of a first root with 409. A `channel_available` or `config_version` change that would grow a config past one channel envelope is 400 `invalid_request` and keeps its fault unchanged. |
| POST | `/__mock__/config` | `{ "fields": {...} }` merges non-reserved fields into each identity's config; effective changes bump revisions and push `ConfigUpdate`. Fields that would grow a config past one channel envelope are 400 `invalid_request`, and no config changes. |
| POST | `/__mock__/config/stale` | `{ "identity_id": "<uuid>", "revision": <lower integer> }` sends a stale `ConfigUpdate` with `mock_stale_marker` without changing server config; returns `{ "sent": <count> }`. A stale config past one channel envelope is 400 `invalid_request` and is not sent. |
| POST | `/__mock__/reset` | Clears tokens, identities, nonces, faults, settings, rotation and the clock offset, and creates a fresh root; keeps `authority_id`, the TLS certificate, and the application identity and its sessions; live streams close with `identity_unknown`. The body is empty or `{ "without_root"?: <bool> }`; `true` leaves no root, as at startup, until the first token creates one. Responds `{ "authority_id" }`. |
| POST | `/__mock__/time/advance` | `{ "secs": <int> }` moves the mock clock and immediately applies stream expiry, rotation deadlines and early completion; responds `{ "now": <unix>, "server_time": "<RFC 3339>" }`. |
| POST | `/__mock__/time/freeze` | `{ "now": <unix second> }` pins time and returns `{ "now", "published_roots": ["<thumbprint>", ...] }` after applying expiry and rotation deadlines at that exact second. |
| GET | `/__mock__/events?identity_id=<uuid>` | Returns `{ "events": [...] }` in increasing `seq` order: `stream_opened`, `stream_authenticated` (with `applied_config_revision`), `stream_closed` (with `status` and optional `error_code`), `cert_status_changed`, `reconnect_sent`, `renew_received`, `config_changed`, `config_update_sent`, `stale_config_update_sent`, and `check_in_received` (with `renewal_requested`). |
| POST / GET | `/__mock__/handshake` | POST `{ "pause": true\|false }` holds valid Hello proofs before authentication, and checks a held `Hello` against revocation, deletion and `notAfter` again on release; GET and POST report `paused` and `paused_stream_ids` so tests can match held proofs to opened streams. Reset releases the barrier. |
| POST | `/__mock__/retry-barrier` | `{ "endpoint": "enroll"\|"renew"\|"confirm", "pause": true\|false }` makes retries after a dropped response or injected confirm failure receive an unprocessed, empty HTTP 503 until released; reset clears it. |
| GET | `/__mock__/requests?token_id=<uuid>` | Reports per-token `enroll` attempts and `enroll_identity_revoked` rejections, total `enroll_total`, `enroll_retry_503`, `renew`, raw `renew_attempt_keyids` (test-only, not authentication), `renew_retry_503`, `confirm`, `confirm_retry_503`, `check_in`, `connect`, `channel_attempts` (every gRPC request, including wrong paths), `redirect_hits`, ordered `request_sequence` (with `confirm_204` result markers), `authenticated_connects`, `correlated_acks`, `overlap_open` (only after proof), `active_streams`, and `paused_hellos`; omit `token_id` for totals. Reset clears all counters. |
| GET / POST | `/__mock__/redirect-target` | Counts `redirect_hits` when an agent incorrectly follows an injected enrollment redirect; responds 418. |
| POST | `/__mock__/reconnect` | `{ "identity_id": "<uuid>" }` pushes `Reconnect{reason:"mock"}` to the identity's live streams; responds 202. |

`drop_next_response` processes the next matching request, then aborts the connection without replying.
`fail_next_response` rejects it before processing with `{ "endpoint": "enroll"|"renew"|"confirm"|"check-in", "status": 300..599, "error"?: "<§5.4 code>", "retry_after_secs"?: <seconds> }`.
A `3xx` fault redirects to `__mock__/redirect-target`, and `retry_after_secs` sets the `Retry-After` header.
Without `error`, the injected response body is deliberately empty and nonconforming so tests can verify transient agent handling.
Arm the retry barrier before `drop_next_response` to prevent a fast retry from succeeding before the tester stops or revokes the agent.
`enroll_identity_revoked` counts enroll rejections for a previously issued key of a revoked or deleted identity, including retries after a lost response.
Rotation pushes follow `rotationNotificationsPerSecond` (10 by default) per rolling second and continue after an emergency deadline until the queue drains.
The old root's signing key is discarded when rotation starts.

## Signature oracle

`src/oracle/` is a test-only verifier of CONTRACT.agent-identity.md §4, §6 and §7.3, written independently of the agent's RFC 9421 library and implementation and not intended for production use.
For signed requests it checks, in order, (1) strict syntax, parameters, algorithm and covered components, (2) endpoint tag, (3) signature window, (4) certificate registration, status, revocation and validity, (5) renew/check-in content digest and P-256 signature, then (6) replay nonce insertion only after verification.
For channels it verifies the P-256 proof over the §7.3 domain separator, zero byte, challenge and connect nonce; the channel service owns the handshake and state updates.
For CSRs it checks the PKCS#10 structure, P-256 subject key, required signature algorithm and self-signature over the request info as received, while ignoring the subject and attributes, whose contents need not be canonical DER (§4).
The RFC 9421 Appendix B.2.4 vector exercises its raw P-256 verifier without widening the request profile.
Its crate-local runtime API is `verify_request`, `verify_channel_proof`, `check_csr`, `content_digest_header`, `Endpoint`, `Rejection`, `RegisteredCert`, `CertStatus`, `NonceStore` and `AuthenticatedIdentity`.
Vector tests also use the test-only `verify_raw_signature` entry to check the RFC example and the positive fixtures' exact signed bases.
Callers supply the certificate lookup, nonce store and current Unix time; the oracle performs no I/O or asynchronous work.
The oracle depends only on `p256`, `sha2`, `base64`, `uuid`, `x509-cert` and `der` outside the standard library, and never on other mock modules or workspace crates.
X.509 and DER supply CSR structure types; P-256 performs signature verification.

## Tests

`cargo test -p agent-identity-mock` replays every signature, proof and CSR vector through the verifier and validators used by the server.
It also pins the login, each management API operation, error class, paging bound, permission and setting effect to DVLS's OpenAPI documents.

[contract]: ../../docs/agent-identity/CONTRACT.agent-identity.md
[dvls-management]: https://github.com/Devolutions/RDM/blob/0acd9d2474bf9fd4a030e146a28097bf4ddf391a/DVLS/Server/server/Common/AgentIdentity/INTENT.md#management-api
[mock-control]: INTENT.md#mock-only-control
