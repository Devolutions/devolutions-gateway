# agent-identity-mock

Mock server for the Agent Identity V1 contract (`docs/agent-identity/CONTRACT.md`), used as the conformance oracle.
It implements §2–§9 and §11 in memory, strictly and literally.
It shares only `crates/agent-channel-proto` (the generated gRPC types) with the agent.

## Usage

```
agent-identity-mock --listen 127.0.0.1:0 --path-prefix /mock --admin-token <secret> --state-dir <dir>
```

| Flag | Meaning |
|---|---|
| `--listen <addr:port>` | TCP bind address; port `0` picks a free port. |
| `--path-prefix <prefix>` | Every route lives under this prefix (e.g. `/mock`); requests outside it get a bare 404. Must start with `/` and not end with `/`. |
| `--admin-token <secret>` | Bearer token required by the admin API. |
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
Advancing or freezing the clock immediately closes expired streams and re-evaluates rotation deadlines and early completion.
`POST __mock__/time/freeze` is a test-only boundary probe that pins the mock clock to an exact Unix second and reports the published root thumbprints in the same state transition; reset restores real-time tracking.

## Routes

All paths below are relative to `base_url` (i.e. they include the path prefix).

### Agent-facing (CONTRACT.md §5), no admin auth

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
Enrollment returns `config.version`, `config.revision` and optional `config.agent_channel_url`, never a top-level channel URL.
Friendly names are stored server-side and appear only in the admin device API.
Config revisions start at 1 and increase only on effective changes; `ConfigUpdate` follows `Welcome` for stale Hellos and is pushed to live streams after a change.
The mock uses a test-only unbounded push queue so config bursts cannot silently detach authenticated streams or discard termination messages.
`POST __mock__/config` adds unknown fields so tests can check that agents preserve them.
Only confirm promotes a pending certificate: old streams receive `Reconnect{reason:"certificate_rotated"}` and close with `OK` after 60 mock-clock seconds if still open.
The channel gRPC method is `POST <prefix>/devolutions.agent.channel.v1.AgentChannel/Connect` with `signature-input`/`signature` metadata (`tag="connect"`); open failures are gRPC statuses with an `error-code` trailer (§7.4).

### Admin (CONTRACT.md §9), `Authorization: Bearer <admin-token>`

Missing or invalid admin auth returns 401 `{ "error", "message" }`; all admin errors use that shape with the matching HTTP status.
For permission tests, `<admin-token>-unprivileged` is authenticated without Agent identity management permission and returns 403.

| Method | Path | Notes |
|---|---|---|
| POST | `/api/v3/agent-identity/enrollment-tokens` | Body `{ name, maxUses (1..1_000_000), expiresAt (RFC 3339, ≤ now+365 d), friendlyNameFormat?, config? }`; 201 → `{ "token": "<full dvaet1 token>", "record": TokenRecord }`; the full token is returned only here. Unknown `friendlyNameFormat` placeholders → 400. |
| GET | `/api/v3/agent-identity/enrollment-tokens` | `pageNumber` (≥ 1, default 1), `pageSize` (1..100, default 25); DVLS page shape `{ data, currentPage, pageSize, totalCount, totalPages }`. |
| GET | `/api/v3/agent-identity/enrollment-tokens/{id}` | `TokenRecord`; 404 when unknown or deleted. |
| DELETE | `/api/v3/agent-identity/enrollment-tokens/{id}` | 204; the token is hidden but can replay its own existing current key without side effects, while a new key gets `token_invalid`. |
| GET | `/api/v3/agent-identity/devices` | Query: `pageNumber`, `pageSize`, `view=summary\|full`, `metadata=k1,k2`, `status=active\|revoked\|expired`, `enrollmentTokenId`, `issuer=<root thumbprint>`, `lastSeenBefore`, `lastSeenAfter`, `q` (case-insensitive friendly-name substring); ordered by creation. |
| GET | `/api/v3/agent-identity/devices/{id}` | Full view. |
| PATCH | `/api/v3/agent-identity/devices/{id}` | `{ "friendlyName" }` (1..255 chars) → full view. |
| POST | `/api/v3/agent-identity/devices/{id}/revoke` | 204, idempotent; closes live streams PERMISSION_DENIED + `device_revoked`. |
| DELETE | `/api/v3/agent-identity/devices/{id}` | 204, or 409 unless the device is revoked. |
| POST | `/api/v3/agent-identity/devices/{id}/request-renewal` | 202; sets the flag and pushes `RenewRequested{reason:"admin"}` to live streams. |
| POST | `/api/v3/agent-identity/ca/rotation` | Body `{ "deadline"?: "<RFC 3339>" \| "now" }`; 202 → `Rotation`; 400 if the deadline exceeds the latest unexpired current or pending old-root certificate; 409 while rotating. |
| GET | `/api/v3/agent-identity/ca/rotation` | `{ phase: "idle"\|"rotating", oldRoot?, newRoot?, deadline?, activeDevicesOnOldRoot }`; the count includes each non-revoked device with an unexpired current or pending old-root certificate. |

A rotation completes immediately when no active old-root device remains, including at rotation start, and publishes only the new root.
Certificate issuance and token-use consumption share the state lock; issued SPKI SHA-256 hashes remain reserved after device deletion.

### Mock control (CONTRACT.md §11), no auth

| Method | Path | Notes |
|---|---|---|
| POST | `/__mock__/faults` | Merges `drop_next_response`, `fail_next_response`, `clock_skew_secs`, `leaf_lifetime_secs`, `channel_available`, `channel_broken`, `malformed_channel_url` and `rotation_rate_limit_per_sec`; absent keys retain their value, and `null` clears optional fields. Toggling `channel_available` bumps every device's config revision; `channel_broken` only rejects new streams, while `malformed_channel_url` injects an HTTP channel URL in new enrollments. |
| POST | `/__mock__/config` | `{ "fields": {...} }` merges non-reserved fields into each device's config; effective changes bump revisions and push `ConfigUpdate`. |
| POST | `/__mock__/config/stale` | `{ "device_id": "<uuid>", "revision": <lower integer> }` sends a stale `ConfigUpdate` with `mock_stale_marker` without changing server config; returns `{ "sent": <count> }`. |
| POST | `/__mock__/reset` | Clears tokens, devices, nonces, faults, rotation and the clock offset, and creates a fresh root; keeps `authority_id`, the TLS certificate and the admin token; live streams close with `device_unknown`. Responds `{ "authority_id" }`. |
| POST | `/__mock__/time/advance` | `{ "secs": <int> }` moves the mock clock and immediately applies stream expiry, rotation deadlines and early completion; responds `{ "now": <unix>, "server_time": "<RFC 3339>" }`. |
| POST | `/__mock__/time/freeze` | `{ "now": <unix second> }` pins time and returns `{ "now", "published_roots": ["<thumbprint>", ...] }` after applying expiry and rotation deadlines at that exact second. |
| GET | `/__mock__/events?device_id=<uuid>` | Returns `{ "events": [...] }` in increasing `seq` order: `stream_opened`, `stream_authenticated` (with `applied_config_revision`), `stream_closed` (with `status` and optional `error_code`), `cert_status_changed`, `reconnect_sent`, `renew_received`, `config_changed`, `config_update_sent`, `stale_config_update_sent`, and `check_in_received` (with `renewal_requested`). |
| POST / GET | `/__mock__/handshake` | POST `{ "pause": true\|false }` holds valid Hello proofs before authentication; GET and POST report `paused` and `paused_stream_ids` so tests can match held proofs to opened streams. Reset releases the barrier. |
| POST | `/__mock__/retry-barrier` | `{ "endpoint": "enroll"\|"renew"\|"confirm", "pause": true\|false }` makes retries after a dropped response or injected confirm failure receive an unprocessed, empty HTTP 503 until released; reset clears it. |
| GET | `/__mock__/requests?token_id=<uuid>` | Reports per-token `enroll` attempts and `enroll_device_revoked` rejections, total `enroll_total`, `enroll_retry_503`, `renew`, raw `renew_attempt_keyids` (test-only, not authentication), `renew_retry_503`, `confirm`, `confirm_retry_503`, `check_in`, `connect`, `redirect_hits`, ordered `request_sequence` (with `confirm_204` result markers), `authenticated_connects`, `correlated_acks`, `overlap_open` (only after proof), `active_streams`, and `paused_hellos`; omit `token_id` for totals. Reset clears all counters. |
| GET / POST | `/__mock__/redirect-target` | Counts `redirect_hits` when an agent incorrectly follows an injected enrollment redirect; responds 418. |
| POST | `/__mock__/reconnect` | `{ "device_id": "<uuid>" }` pushes `Reconnect{reason:"mock"}` to the device's live streams; responds 202. |

`drop_next_response` processes the next matching request, then aborts the connection without replying.
`fail_next_response` rejects it before processing with `{ "endpoint": "enroll"|"renew"|"confirm"|"check-in", "status": 300..599, "error"?: "<§5.4 code>", "retry_after_secs"?: <seconds> }`.
A `3xx` fault redirects to `__mock__/redirect-target`, and `retry_after_secs` sets the `Retry-After` header.
Without `error`, the injected response body is deliberately empty and nonconforming so tests can verify transient agent handling.
Arm the retry barrier before `drop_next_response` to prevent a fast retry from succeeding before the tester stops or revokes the agent.
`enroll_device_revoked` counts enroll rejections for a previously issued key of a revoked or deleted device, including retries after a lost response.
Rotation pushes default to 10 per rolling second and continue after an emergency deadline until the queue drains.
The old root's signing key is discarded when rotation starts.

## Signature oracle

`src/oracle/` is a test-only verifier of CONTRACT.md §4, §6 and §7.3, written independently of the agent's RFC 9421 library and implementation and not intended for production use.
For signed requests it checks, in order, (1) strict syntax, parameters, algorithm and covered components, (2) endpoint tag, (3) signature window, (4) certificate registration, status, revocation and validity, (5) renew/check-in content digest and P-256 signature, then (6) replay nonce insertion only after verification.
For channels it verifies the P-256 proof over the §7.3 domain separator, zero byte, challenge and connect nonce; the channel service owns the handshake and state updates.
For CSRs it checks the PKCS#10 structure, P-256 subject key, required signature algorithm and self-signature while ignoring the subject and extensions (§4).
The RFC 9421 Appendix B.2.4 vector exercises its raw P-256 verifier without widening the request profile.
Its crate-local runtime API is `verify_request`, `verify_channel_proof`, `check_csr`, `content_digest_header`, `Endpoint`, `Rejection`, `RegisteredCert`, `CertStatus`, `NonceStore` and `AuthenticatedDevice`.
Vector tests also use the test-only `verify_raw_signature` entry to check the RFC example and the positive fixtures' exact signed bases.
Callers supply the certificate lookup, nonce store and current Unix time; the oracle performs no I/O or asynchronous work.
The oracle depends only on `p256`, `sha2`, `base64`, `uuid`, `x509-cert`, `der` and `spki` outside the standard library, and never on other mock modules or workspace crates.
The X.509, DER and SPKI crates supply CSR structure types; P-256 performs signature verification.

## Tests

`cargo test -p agent-identity-mock` replays every signature, proof and CSR vector through the verifier and validators used by the server.
