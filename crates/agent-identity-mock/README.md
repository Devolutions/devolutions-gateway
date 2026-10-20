# agent-identity-mock

Mock server for the [Agent Identity V1 contract][contract], used as the conformance oracle.
It implements the agent-facing protocol, the [DVLS management API][dvls-management] and the [mock controls][mock-control] in memory.
It shares only `crates/agent-channel-proto` (the generated gRPC types) with the agent.

## Usage

```
agent-identity-mock --listen 127.0.0.1:0 --path-prefix /mock --admin-token <secret> --state-dir <dir>
```

| Flag | Meaning |
|---|---|
| `--listen <addr:port>` | TCP bind address; it must be a loopback address because the mock control surface is unauthenticated, and port `0` picks a free port. |
| `--path-prefix <prefix>` | Every route lives under this prefix (e.g. `/mock`); requests outside it get a bare 404. Must start with `/` and not end with `/`. |
| `--admin-token <secret>` | Secret from which the [management API](#management-api) credentials derive. |
| `--state-dir <dir>` | Where `ready.json` and the TLS CA PEM are written; created if missing. |

On startup the server generates a TLS CA and a server certificate for `localhost`/`127.0.0.1` and serves HTTPS on a single port with ALPN `h2` and `http/1.1` (REST and gRPC share the port).
It then writes `<state-dir>/ready.json` atomically (temp file + rename):

```json
{ "base_url": "https://127.0.0.1:<port>/mock", "tls_ca_pem": "<abs path to CA PEM>", "authority_id": "<uuid>" }
```

`tls_ca_pem` is what an agent trusts through `__debug__.identity.extra_trusted_root`.
`authority_id` is stable for the process lifetime, including across `__mock__/reset`.

## Clock

All time in the mock is the mock clock: real time plus an offset.
`POST __mock__/time/advance` adds to the offset and `faults.clock_skew_secs` adds a skew on top.
Signature windows, certificate validity, token expiry, renewal grace, rotation deadlines, `server_time` and `last_seen_at` all use it.
A certificate is unexpired while `now ≤ notAfter`, and `notBefore` is never checked (§6).
A stream closes, and a channel opening is refused with `certificate_expired`, once the clock reaches the certificate's `notAfter`, because §7.4 closes a stream no later than then.
Advancing or freezing the clock immediately closes expired streams and re-evaluates rotation deadlines and early completion.
`POST __mock__/time/freeze` is a test-only boundary probe that pins the mock clock to an exact Unix second and reports the published root thumbprints in the same state transition; reset restores real-time tracking.

## Routes

All paths below are relative to `base_url` (i.e. they include the path prefix).

### Agent-facing (CONTRACT.md §5), no management API credential

| Method | Path | Notes |
|---|---|---|
| GET | `/api/agent-identity/v1/trust-anchor` | `{ "roots": [ { "certificate" (base64 DER), "thumbprint", "not_before", "not_after" } ] }`; two roots while a rotation is in progress. |
| POST | `/api/agent-identity/v1/enroll` | `Authorization: Bearer <dvaet1 token>`; body `{ "csr": "<base64 DER PKCS#10>", "metadata": {...} }`. |
| POST | `/api/agent-identity/v1/renew` | RFC 9421-signed with `tag="renew"`; `Content-Digest` over the exact body bytes. |
| POST | `/api/agent-identity/v1/confirm` | RFC 9421-signed with `tag="confirm"` and an empty body; `204` for promotion or an idempotent retry. |
| POST | `/api/agent-identity/v1/check-in` | RFC 9421-signed with `tag="check-in"` and a digested `{ "metadata": {...} }` body; returns effective `config` and `renewal_requested`. |

Non-2xx agent-facing responses carry `{ "error", "message", "server_time" }` with the §5.4 codes.
Enrollment, renewal and check-in require a `metadata` object, which may be empty.
Metadata is limited to 16 KiB in aggregate, and agent-facing request bodies are limited to 64 KiB.
A larger body gets `413 invalid_request` before authentication; otherwise an authentication error wins over an invalid body, CSR or metadata (§5.4).
Enrollment returns `config.version`, `config.revision` and optional `config.agent_channel_url`, never a top-level channel URL.
Friendly names are stored server-side and appear only in the management API.
Config revisions start at 1 and increase only on effective changes; `ConfigUpdate` follows `Welcome` for stale Hellos and is pushed to live streams after a change.
A token's optional `config` object supplies product-specific fields to its enrolled identities; it cannot set `version`, `revision` or `agent_channel_url`.
The mock uses a test-only unbounded push queue so config bursts cannot silently detach authenticated streams or discard termination messages.
`POST __mock__/config` adds unknown fields so tests can check that agents preserve them.
Only confirm promotes a pending certificate: old streams receive `Reconnect{reason:"certificate_rotated"}` and close with `OK` after 60 mock-clock seconds if still open.
The channel gRPC method is `POST <prefix>/devolutions.agent.channel.v1.AgentChannel/Connect` with `signature-input`/`signature` metadata (`tag="connect"`); open failures are gRPC statuses with `error-code` and `server-time` trailers (§7.4).

### Management API

The [DVLS management API][dvls-management] takes `Authorization: Bearer <credential>`.
Missing or invalid credentials return 401 `{ "error", "message" }`; all management API errors use that shape with the matching HTTP status.
Each route requires the permission the table lists, and a credential without it gets 403 `forbidden` before the request is processed.
The mock derives its credentials from `--admin-token`, so a test can hold any subset of the four permissions without setup:

| Credential | Permissions |
|---|---|
| `<admin-token>` | All four, like a DVLS built-in administrator. |
| `<admin-token>.<scope>` | Those in `<scope>`: `none`, or a `+`-separated list of `view`, `manage`, `revoke` and `rotate-root`, such as `view+revoke`. |
| `<admin-token>-unprivileged` | None, like `<admin-token>.none`. |

Any other credential, including a scope with an empty or unknown permission name, is invalid.
Each identity's `status` is `active` (an unexpired current or pending certificate), `grace` (no unexpired certificate, but one within renewal grace), `expired` (beyond renewal grace) or `revoked`, as the DVLS intent's "Terminology" defines.

| Method | Path | Permission | Notes |
|---|---|---|---|
| POST | `/api/v3/agent-identity/enrollment-tokens` | Manage | Body `{ name, maxUses (1..1_000_000), expiresAt (RFC 3339, ≤ now+365 d), friendlyNameFormat?, config? }`; 201 → `{ "token": "<full dvaet1 token>", "record": TokenRecord }`; the full token is returned only here. Unknown `friendlyNameFormat` placeholders → 400. |
| GET | `/api/v3/agent-identity/enrollment-tokens` | View | `pageNumber` (≥ 1, default 1), `pageSize` (1..100, default 25); DVLS page shape `{ data, currentPage, pageSize, totalCount, totalPages }`. |
| GET | `/api/v3/agent-identity/enrollment-tokens/{id}` | View | `TokenRecord`; 404 when unknown or deleted. |
| DELETE | `/api/v3/agent-identity/enrollment-tokens/{id}` | Manage | 204; the token is hidden but can replay its own existing current key without side effects, while a new key gets `token_invalid`. |
| GET | `/api/v3/agent-identity/identities` | View | Query: `pageNumber`, `pageSize`, `view=summary\|full`, `metadata=k1,k2`, `status=active\|grace\|expired\|revoked`, `enrollmentTokenId`, `issuer=<root thumbprint>`, `lastSeenBefore`, `lastSeenAfter`, `q` (case-insensitive friendly-name substring); ordered by creation. |
| GET | `/api/v3/agent-identity/identities/{id}` | View | Full view. |
| PATCH | `/api/v3/agent-identity/identities/{id}` | Manage | `{ "friendlyName" }` (1..255 chars) → full view. |
| POST | `/api/v3/agent-identity/identities/{id}/revoke` | Revoke | 204, idempotent; closes live streams PERMISSION_DENIED + `identity_revoked`. |
| DELETE | `/api/v3/agent-identity/identities/{id}` | Manage | 204, or 409 unless the identity is revoked. |
| POST | `/api/v3/agent-identity/identities/{id}/request-renewal` | Manage | 202; sets the flag and pushes `RenewRequested{reason:"admin"}` to live streams. |
| POST | `/api/v3/agent-identity/ca/rotation` | Rotate root | Body `{ "deadline"?: "<RFC 3339>" \| "now" }`; 202 → `Rotation`; 400 if the deadline exceeds the latest unexpired current or pending old-root certificate; 409 while rotating. |
| GET | `/api/v3/agent-identity/ca/rotation` | View | `{ phase: "idle"\|"rotating", oldRoot?, newRoot?, deadline?, activeIdentitiesOnOldRoot }`; the count includes each non-revoked identity with an unexpired current or pending old-root certificate. |

A rotation completes immediately when no active old-root identity remains, including at rotation start, and publishes only the new root.
Certificate issuance and token-use consumption share the state lock; issued key hashes stay reserved, and original issuance times remain stored after identity deletion.

### Mock control ([mock controls][mock-control]), no auth

| Method | Path | Notes |
|---|---|---|
| POST | `/__mock__/faults` | Merges `drop_next_response`, `fail_next_response`, `clock_skew_secs`, `leaf_lifetime_secs`, `channel_available`, `channel_broken`, `malformed_channel_url`, `rotation_rate_limit_per_sec` and `config_version`; absent keys retain their value, and `null` clears optional fields. Toggling `channel_available` bumps every identity's config revision; `config_version` (an unsigned integer) replaces `config.version` in every config the mock delivers, and setting it to a different version or clearing it bumps every identity's config revision and pushes `ConfigUpdate`; `channel_broken` only rejects new streams. Set `malformed_channel_url` to `true` for an HTTP URL, `"query"` for an HTTPS URL with a query, or `"fragment"` for an HTTPS URL with a fragment in new enrollments; `false` or `null` clears it. |
| POST | `/__mock__/config` | `{ "fields": {...} }` merges non-reserved fields into each identity's config; effective changes bump revisions and push `ConfigUpdate`. |
| POST | `/__mock__/config/stale` | `{ "identity_id": "<uuid>", "revision": <lower integer> }` sends a stale `ConfigUpdate` with `mock_stale_marker` without changing server config; returns `{ "sent": <count> }`. |
| POST | `/__mock__/reset` | Clears tokens, identities, nonces, faults, rotation and the clock offset, and creates a fresh root; keeps `authority_id`, the TLS certificate and the admin token; live streams close with `identity_unknown`. Responds `{ "authority_id" }`. |
| POST | `/__mock__/time/advance` | `{ "secs": <int> }` moves the mock clock and immediately applies stream expiry, rotation deadlines and early completion; responds `{ "now": <unix>, "server_time": "<RFC 3339>" }`. |
| POST | `/__mock__/time/freeze` | `{ "now": <unix second> }` pins time and returns `{ "now", "published_roots": ["<thumbprint>", ...] }` after applying expiry and rotation deadlines at that exact second. |
| GET | `/__mock__/events?identity_id=<uuid>` | Returns `{ "events": [...] }` in increasing `seq` order: `stream_opened`, `stream_authenticated` (with `applied_config_revision`), `stream_closed` (with `status` and optional `error_code`), `cert_status_changed`, `reconnect_sent`, `renew_received`, `config_changed`, `config_update_sent`, `stale_config_update_sent`, and `check_in_received` (with `renewal_requested`). |
| POST / GET | `/__mock__/handshake` | POST `{ "pause": true\|false }` holds valid Hello proofs before authentication; GET and POST report `paused` and `paused_stream_ids` so tests can match held proofs to opened streams. Reset releases the barrier. |
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
Rotation pushes default to 10 per rolling second and continue after an emergency deadline until the queue drains.
The old root's signing key is discarded when rotation starts.

## Signature oracle

`src/oracle/` is a test-only verifier of CONTRACT.md §4, §6 and §7.3, written independently of the agent's RFC 9421 library and implementation and not intended for production use.
For signed requests it checks, in order, (1) strict syntax, parameters, algorithm and covered components, (2) endpoint tag, (3) signature window, (4) certificate registration, status, revocation and validity, (5) renew/check-in content digest and P-256 signature, then (6) replay nonce insertion only after verification.
For channels it verifies the P-256 proof over the §7.3 domain separator, zero byte, challenge and connect nonce; the channel service owns the handshake and state updates.
For CSRs it checks the PKCS#10 structure, P-256 subject key, required signature algorithm and self-signature while ignoring the subject and extensions (§4).
The RFC 9421 Appendix B.2.4 vector exercises its raw P-256 verifier without widening the request profile.
Its crate-local runtime API is `verify_request`, `verify_channel_proof`, `check_csr`, `content_digest_header`, `Endpoint`, `Rejection`, `RegisteredCert`, `CertStatus`, `NonceStore` and `AuthenticatedIdentity`.
Vector tests also use the test-only `verify_raw_signature` entry to check the RFC example and the positive fixtures' exact signed bases.
Callers supply the certificate lookup, nonce store and current Unix time; the oracle performs no I/O or asynchronous work.
The oracle depends only on `p256`, `sha2`, `base64`, `uuid`, `x509-cert` and `der` outside the standard library, and never on other mock modules or workspace crates.
X.509 and DER supply CSR structure types; P-256 performs signature verification.

## Tests

`cargo test -p agent-identity-mock` replays every signature, proof and CSR vector through the verifier and validators used by the server.

[contract]: ../../docs/agent-identity/CONTRACT.md
[dvls-management]: ../../docs/agent-identity/INTENT.DVLS.md#management-api
[mock-control]: INTENT.md#mock-only-control
