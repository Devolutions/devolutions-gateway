# Agent Identity — Contract (draft v0.5)

Status: v0.5; E1–E9 decisions applied; clarifications C1–C20 (orchestrator, 2026-09-25), all approved by Benoit: C17 `confirm` (replaces C3's promote-on-first-use), C18 `config.agent_channel_url`, C19 config revisions with `ConfigUpdate` and the `GET config` fallback, C20 channel renames.
Owner: top-level orchestrator.
Changes go lead → top-level → Benoit.
Once approved, it is committed to devolutions-gateway at `docs/agent-identity/CONTRACT.md` with the `.proto` and test vectors next to it.

## 1. Conventions

- JSON bodies are UTF-8, `Content-Type: application/json`, snake_case keys; enum values are snake_case strings.
- Optional fields are omitted when absent (never `null`).
- Receivers ignore unknown JSON fields unless stated otherwise.
- Timestamps are RFC 3339 UTC strings (`2026-09-24T12:00:00Z`).
- IDs are lowercase hyphenated UUIDs.
- `base64url` means RFC 4648 §5 without padding; `base64` means RFC 4648 §4 with padding.
- Certificates and CSRs are DER, encoded `base64` in JSON.
- A certificate thumbprint is `base64url(SHA-256(certificate DER))`.

## 2. Enrollment token

```
<prefix>.<bag>.<secret>
```

- `prefix` (decided): `dvaet1` = **D**e**v**olutions **A**gent **E**nrollment **T**oken, format version **1**.
  Registered with secret scanners (pattern `dvaet1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}`); a future format change bumps the version (`dvaet2`), and agents reject versions they don't know.
  It's product-neutral (PSU issues the same prefix) and distinct from Agent Tunnel's JWT tokens (`eyJ...`).
- `bag`: `base64url(JSON)`, unsigned, routing only.
  V1 fields: `u` (required): product base URL, `https`, no query or fragment, e.g. `https://host/dvls`.
  The agent ignores other fields.
- `secret`: `base64url` of 32 random bytes; opaque to the agent.
- Total length ≤ 4096 bytes.
  The agent rejects a malformed token locally (`token_malformed`, local only, permanent).
- The server stores only `SHA-256(secret)`.
- Acceptance, consumption and idempotence follow the V1 plan (row exists, `used_count < max_uses`, `now < expires_at`; use consumed in the device-creating transaction; same CSR public key returns the existing device without consuming a use).
- Evaluation order (C1): (1) authenticate the token (row exists and `SHA-256(secret)` matches) → else `token_invalid`; (2) validate the body, CSR and metadata → else `invalid_request`; (3) idempotence lookup on the CSR public key; (4) `token_expired`; (5) `token_exhausted`; (6) create the device.
  Idempotence is checked before expiry and exhaustion so a lost response on a `max_uses = 1` token can be retried.
- Idempotence match (C1), against every certificate the server has issued:
  - Key of the current certificate of a non-revoked device → `200` with that device, its friendly name and its current chain; no use consumed; metadata and `last_seen_at` updated.
  - Any certificate key of a revoked device → `device_revoked`.
  - Key of a pending or retired certificate of a non-revoked device → `invalid_request` (a public key belongs to exactly one certificate lineage; it's never reused).
  - Key of a certificate of a deleted device → `device_revoked` (C15): issued public keys stay reserved after deletion; the server keeps each one's SPKI SHA-256 and the time it was first issued, and purging old entries is out of scope for V1.
- Idempotence applies only when the matching device is not revoked; for a revoked device, enroll returns `device_revoked`.

## 3. Metadata

- JSON object of string → string.
- Known keys: `hostname`, `fqdn`, `domain`, `os_name`, `os_version`, `arch`, `agent_version`, `machine_id`.
- Limits: ≤ 32 keys; key matches `^[a-z][a-z0-9_]{0,63}$`; value ≤ 1024 UTF-8 bytes, no C0/C1 control characters; whole object ≤ 8 KiB, measured as the sum of the UTF-8 byte lengths of all keys and values (C6).
- `metadata` is required in enroll and renew bodies (an object, possibly empty); absent or not an object → `invalid_request` (C7).
- Anything else (nested values, non-strings, limits exceeded) → `invalid_request`.
- Unknown keys within limits are stored as-is (informational only).
- Friendly name: evaluated once at enrollment from the token's format.
  Placeholders `{<known key>}` and `{token_name}`; `{{` and `}}` escape braces; an unpaired `{` or `}` is rejected at token creation like an unknown placeholder.
  Unknown placeholders are rejected at token creation; missing values evaluate to empty.
  The result is trimmed and truncated to 255 characters; an empty result falls back to the device ID.
  "Characters" means Unicode scalar values, here and in `PATCH /devices/{id}`; truncation never splits one (C6).
  Default format: `{hostname}`.

## 4. Certificates

- Chains are leaf-first, any length; the agent never assumes a tier count.
- DVLS: root P-256, 10 years, `CN=<product> Agent Identity Root <n>`, created on first use.
- Leaf: P-256, `CN=<device_id>`, SAN URI `urn:uuid:<device_id>`, EKU clientAuth, KeyUsage digitalSignature, validity default 90 days, capped at the issuing root's `notAfter`.
- The server ignores CSR subject and extensions; it only takes the public key (P-256 required, else `invalid_request`) and verifies the CSR self-signature (else `invalid_request`).
- The CSR signature algorithm is `ecdsa-with-SHA256`; anything else → `invalid_request` (C5).
- The leaf lifetime is a server setting (default 90 days); conformance runs against a real server pass the configured value to the tester.

## 5. Agent-facing HTTP API (product-neutral)

Base: the token's `u`.
Paths (identical for every product):

| Method | Path | Auth |
|---|---|---|
| GET | `{u}/api/agent-identity/v1/trust-anchor` | none |
| POST | `{u}/api/agent-identity/v1/enroll` | `Authorization: Bearer <token>` |
| POST | `{u}/api/agent-identity/v1/renew` | RFC 9421, `tag="renew"` |
| POST | `{u}/api/agent-identity/v1/confirm` | RFC 9421, `tag="confirm"`, signed with the new key (§5.5) |
| GET | `{u}/api/agent-identity/v1/config` | RFC 9421, `tag="config"` (§5.6) |

### 5.1 `GET trust-anchor`

`200`:

```json
{ "roots": [ { "certificate": "<base64 DER>", "thumbprint": "<base64url>", "not_before": "...", "not_after": "..." } ] }
```

One root normally, two during a rotation.
Documented limitation: chain validation against these roots does not reflect revocation.

### 5.2 `POST enroll`

Request:

```json
{ "csr": "<base64 DER PKCS#10>", "metadata": { "hostname": "..." } }
```

`200` (new device, or idempotent replay):

```json
{
  "authority_id": "<uuid>",
  "device_id": "<uuid>",
  "friendly_name": "...",
  "certificate_chain": ["<base64 DER leaf>", "<base64 DER root>"],
  "config": { "version": 1, "revision": 1, "agent_channel_url": "https://host/dvls" }
}
```

- `authority_id` is stable for a server instance (DVLS: generated once, stored in settings).
- `config` is versioned (`version` is the schema version); the agent ignores unknown fields.
- `config.revision` (C19): unsigned integer, assigned by the server, strictly increasing per device whenever the device's effective config changes.
  The agent replaces its stored config only with a higher revision.
  Delivery of later revisions is covered in §7.3 (agent channel) and §5.6 (HTTP fallback).
- `config.agent_channel_url` (C18) is the base URL of the agent channel (§7). It's absent when the server doesn't offer the agent channel to this device, whatever the reason (the topology can't host it, it's disabled, or a product authenticates agents over its own channel); the agent then opens no agent channel for that authority.
  Products may add their own fields later (e.g. a PSU channel URL); both can coexist.

### 5.3 `POST renew`

- Signed with the current key (§6), `tag="renew"`, `content-digest` covering the exact body bytes.
- Request: `{ "csr": "...", "metadata": { ... } }` for the new key.
- `200`: `{ "certificate_chain": [ ... ] }`.
- Idempotent on the new public key.
- CSR key rules (C2): the key of the device's pending certificate → `200` replaying that pending chain (lost-response retry); the key of any other certificate the server has issued (this device's current or retired ones, or any certificate of another device) → `invalid_request`; otherwise a new pending certificate is issued.
- At most one `pending` certificate per device: a renew with a different new key retires the previous pending certificate.
- Accepted with a `current` or `pending` certificate that is unexpired, or expired by less than its own lifetime (`now < notAfter + (notAfter − notBefore)`).
- Renew never promotes a certificate; only `confirm` does (§5.5).

### 5.4 Errors

Body for every non-2xx response:

```json
{ "error": "<code>", "message": "<human text>", "server_time": "<RFC 3339>" }
```

`server_time` is always present; agents use it only for `clock_skew`.
This body is on every non-2xx response under `{u}/api/agent-identity/v1/`, including framework-level failures (C8): malformed JSON or body → `400 invalid_request`; unknown route → `404 invalid_request`; wrong method → `405 invalid_request`; body too large → `413 invalid_request`.

| Code | HTTP | Meaning | Agent class |
|---|---|---|---|
| `token_invalid` | 401 | Unknown or deleted token, bad secret | permanent |
| `token_exhausted` | 403 | `used_count = max_uses` | permanent |
| `token_expired` | 401 | `now ≥ expires_at` | permanent |
| `device_revoked` | 403 | Device revoked | terminal |
| `device_unknown` | 401 | Certificate not registered, or device deleted | terminal |
| `certificate_expired` | 401 | Expired (for `connect`, `confirm`, `config`) or beyond grace (for `renew`) | re-enroll required, except on `confirm` (renew again with a fresh key, §8) |
| `signature_invalid` | 401 | Bad signature, wrong `tag`, bad digest, replayed nonce, malformed params | transient |
| `clock_skew` | 401 | `created`/`expires` outside tolerance | transient, adjust clock |
| `invalid_request` | 400 | Malformed body, CSR or metadata | transient (agent bug; keep retrying with backoff) |

`token_*` codes on a pending enrollment are permanent (the pending file is deleted).
`device_revoked` and `device_unknown` record `rejected` on the stored identity (§10.3); the agent stops renewing and reconnecting for that authority.

### 5.5 `POST confirm` (C17)

- Signed with the **pending** certificate's key (§6), `tag="confirm"`, components `("@method")`, empty body.
- The signing certificate must be the device's `pending` or `current` certificate and unexpired (no grace), else §6 step 4 errors.
- Pending → it becomes `current`, the previous `current` becomes `retired`, and the server:
  - sends `Reconnect{reason:"certificate_rotated"}` on streams opened with the retired certificate;
  - closes those still open 60 s later with `OK`.
- Already current → no-op (idempotent retry after a lost response).
- `204` in both cases.
- `confirm` is the only operation that promotes a certificate; renew and channel connect never do.

### 5.6 `GET config` (C19, HTTP fallback)

- Signed with the current key (§6), `tag="config"`, components `("@method")`, no body.
- The signing certificate must be `current` or `pending` and unexpired (no grace).
- `200`: `{ "config": { ... } }`, the device's effective config (same shape as in §5.2, with its current `revision`).
- It's the fallback for authorities without a working agent channel; with a working channel, config arrives through §7.3.
  When the agent polls:
  - no `config.agent_channel_url`: at service start, then every 24 h (±10% jitter);
  - `config.agent_channel_url` present but no stream authenticated for 1 h: once, then every 24 h (±10% jitter) until a stream authenticates;
  - otherwise, never.

## 6. RFC 9421 profile

- Label `sig`.
- `Signature-Input: sig=(<components>);created=<int>;expires=<int>;nonce="<base64url 16 random bytes>";keyid="<thumbprint>";alg="ecdsa-p256-sha256";tag="<renew|connect|confirm|config>"`.
- Components: `renew` → `("@method" "content-digest")`; `connect`, `confirm` and `config` → `("@method")`.
- `Content-Digest: sha-256=:<base64>:` (RFC 9530).
- Signature: ECDSA P-256 over SHA-256 of the signature base, raw 64-byte `r‖s`.
- Agent sets `expires = created + 60`.
- Server checks, in this order:
  1. Parse; exactly one signature labelled `sig`; all parameters present; `alg` matches → else `signature_invalid`.
  2. `tag` matches the endpoint → else `signature_invalid`.
  3. `0 < expires − created ≤ 300`; `created ≤ now + 60`; `expires ≥ now − 60` → else `clock_skew` (C4 adds the lower bound).
  4. Resolve `keyid` to a registered certificate with status `current` or `pending` → else `device_unknown`; device not revoked → else `device_revoked`; validity per endpoint → else `certificate_expired`.
  5. Verify `content-digest` (renew) and the signature → else `signature_invalid`.
  6. Atomically insert `(keyid, nonce)` into the nonce store; conflict → `signature_invalid`.
     Entries are kept until `expires + 60`.
- Nonces are committed only after the signature verifies (step 6), so garbage requests cannot burn nonces.
- On `clock_skew`, the agent may retry once with `created` offset by `server_time − local_time`.
- Libraries (approved, E4): Rust `httpsig` (signature base + custom `SigningKey`, `httpsig-hyper` for `content-digest` on `renew`); .NET NSign for signature base and ECDSA verification.
  Only the policy checks above (tag, window, key resolution, nonce commit) are our code; any other gap is escalated.
- Shared test vectors (`docs/agent-identity/test-vectors.json`): fixed P-256 key, fixed requests for all four tags, exact signature base strings, valid signatures, a channel proof (§7.3), and negative cases (including cross-tag cases between every pair of tags); plus RFC 9421 Appendix B.2.4 as a sanity check.
  In negative cases, `signature_base` is the base that was originally signed, not what a verifier recomputes from the altered request.

## 7. Channel (gRPC)

### 7.1 Service

Package `devolutions.agent.channel.v1` (C20).
The `.proto` is the single source for every language: Rust (`agent-channel-proto` crate) and .NET (`Devolutions.Agent.Channel` NuGet package, built from the same file in devolutions-gateway).

```proto
syntax = "proto3";
package devolutions.agent.channel.v1;

option csharp_namespace = "Devolutions.Agent.Channel.V1";

import "google/protobuf/timestamp.proto";

service AgentChannel {
  rpc Connect(stream AgentMessage) returns (stream ServerMessage);
}

message AgentMessage {
  string id = 1;
  optional string correlation_id = 2;
  oneof payload {
    Hello hello = 10;
    Ack ack = 11;
  }
}

message ServerMessage {
  string id = 1;
  optional string correlation_id = 2;
  oneof payload {
    Welcome welcome = 10;
    Ack ack = 11;
    RenewRequested renew_requested = 12;
    Reconnect reconnect = 13;
    Challenge challenge = 14;
    ConfigUpdate config_update = 15;
  }
}

// C19: the device's effective config (§5.2 shape) as a UTF-8 JSON object.
message ConfigUpdate {
  string config_json = 1;
}

message Challenge {
  // 32 random bytes, fresh per stream.
  bytes challenge = 1;
}

message Hello {
  map<string, string> metadata = 1;
  repeated string capabilities = 2;
  map<string, uint64> applied_state_versions = 3;
  // Proof of key possession bound to this stream (§7.3).
  bytes proof = 4;
}

message Welcome {
  google.protobuf.Timestamp server_time = 1;
}

message Ack {}

message RenewRequested {
  // "admin" or "rotation".
  string reason = 1;
}

message Reconnect {
  string reason = 1;
}
```

### 7.2 URL and path prefix

- gRPC path: `<agent_channel_url path>/devolutions.agent.channel.v1.AgentChannel/Connect`.
  With `agent_channel_url = https://host/dvls`, the `:path` is `/dvls/devolutions.agent.channel.v1.AgentChannel/Connect`; the agent's tower layer adds the prefix.
- The opening request carries `signature-input`, `signature` metadata with `tag="connect"`.

### 7.3 Sequence

1. The agent opens the stream with the signed opening request (§6, `tag="connect"`) and sends nothing until it receives `Challenge`.
2. The server verifies the signature (§6), then sends `Challenge` as its first message.
3. The agent sends `Hello` with `correlation_id` = Challenge `id` and `proof` = ECDSA P-256 / SHA-256, raw 64-byte `r‖s`, by the same key, over the bytes:
   `"devolutions-agent-identity/v1/channel-proof" ‖ 0x00 ‖ challenge (32 bytes) ‖ connect nonce (UTF-8 bytes of the `nonce` parameter)`.
4. The server verifies `proof` with the public key of the certificate that authenticated the opening request.
   On success it replies `Welcome` (`correlation_id` = Hello `id`), updates metadata, `last_seen_at` and `connected`, and only then treats the stream as authenticated.
   On failure, or if no `Hello` arrives within 10 s, it closes the stream with `UNAUTHENTICATED` + `error-code: signature_invalid`.
5. If the request-renewal flag is set, the server sends `RenewRequested` after `Welcome` on every connect until the device confirms a newer certificate; the agent replies `Ack` (`correlation_id` = message `id`).
6. `Reconnect` asks the agent to open a new stream; the agent opens it, then closes the old one.
   The agent uses the same routine after its own `confirm` succeeds.
7. Config (C19): `Hello.applied_state_versions["config"]` carries the agent's stored `config.revision`.
   If the device's current revision is higher, the server sends `ConfigUpdate` after `Welcome`.
   When the device's effective config changes, the server bumps the revision and sends `ConfigUpdate` on the device's live streams.
   The agent stores it if the revision is higher, replies `Ack` (`correlation_id` = message `id`), and applies it:
   - `agent_channel_url` removed: it closes the stream and stops connecting;
   - `agent_channel_url` changed: it reconnects to the new URL, opening the new stream before closing the old one;
   - `agent_channel_url` added (only reachable through §5.6): it connects.
- No server push, metadata update or `connected` state happens before step 4 succeeds.
- Rationale: the header signature isn't bound to the stream; the fresh challenge makes captured opening headers (TLS-terminating proxies, TLS inspection, header logs) useless for opening a stream.
- An active intermediary in the path is out of scope (it can read the plaintext anyway); TLS channel binding is a possible later addition.
- Envelope `id` values are UUIDs.
- Unknown payloads are ignored.
- Push is an optimization; `Hello`/`Welcome` reconciliation is authoritative.
- Test vectors (§6) include a channel proof case.

### 7.4 Termination

- Auth failures at open: gRPC status `UNAUTHENTICATED` (or `PERMISSION_DENIED` for `device_revoked`) with trailer `error-code: <§5.4 code>`.
- Revocation: the server closes live streams with `PERMISSION_DENIED` + `error-code: device_revoked`.
- A stream closes no later than its certificate's `notAfter` (`UNAUTHENTICATED` + `certificate_expired`).
- When `confirm` promotes a pending certificate (§5.5), the previous `current` certificate is retired; its streams get `Reconnect{reason:"certificate_rotated"}` and are closed with `OK` 60 s later if still open.
- Agent: HTTP/2 keepalive every 30 s; reconnect with jittered exponential backoff (1 s → 5 min); stops on `device_revoked` / `device_unknown`.

### 7.5 Availability

- DVLS emits `config.agent_channel_url` only when it runs on Kestrel, or IIS in-process on Windows build ≥ 20348 (Server 2022) / ≥ 22000 (Windows 11), and an admin setting "Agent channel enabled" (default on) is not turned off; the setting covers reverse proxies that break gRPC.
- No fallback transport.

## 8. Renewal and rotation

As in the V1 plan (DVLS `pending`/`current`/`retired`, grace = one leaf lifetime; manual rotation with deadline, rate-limited `RenewRequested`, old root removed at deadline, pinned old-root certificates accepted until their expiry), with the agent steps replaced as below.
Agent renewal (C17):
1. Trigger at `notBefore + 2/3 × lifetime + jitter` (jitter uniform in `[0, 1/12 × lifetime]`), or on `RenewRequested`.
2. Generate the new key and record it as `pending` (§10.3 write-before-create).
3. `POST renew` with its CSR, signed with the current key; retry with the same CSR on failure.
4. Store the returned chain on the `pending` slot.
5. `POST confirm` signed with the new key; retry with backoff.
   While the outcome of a `confirm` is unknown, the agent sends no other signed request to that authority and opens no stream; it retries `confirm` first, since `confirm` is idempotent.
6. On `204`: `pending` becomes `current`, the old key moves to `previous` and is deleted right away (§10.3 delete-before-remove).
7. Reconnect the agent channel, if any, with the new certificate: open the new stream, then close the old one.
Failure handling:
- Transient errors on `renew` or `confirm`: retry with backoff; the old certificate and stream keep working.
- `certificate_expired` on `confirm`, or a pending key that's unusable locally: delete the pending key and slot, then renew again with a fresh key, signed with the current certificate while it's valid or within its grace (C2 retires the old pending certificate server-side).
- `device_revoked` or `device_unknown`: terminal (§5.4).
Server side:
- A `pending` certificate becomes `current` only through `confirm` (§5.5, C17 replaces the earlier C3 "first authentication" rule).
- The request-renewal flag is cleared when a certificate issued after the flag was set is confirmed.
Rotation:
- Rotation `deadline`: RFC 3339 or the literal `"now"`; a value ≤ now is an emergency; absent → the maximum.
- Rotation maximum (C10): the latest `notAfter` among the unexpired current or pending certificates of non-revoked devices issued by the old root (now when there are none); an explicit later deadline → `400`.
- Early completion (C10): when `activeDevicesOnOldRoot` is 0, at rotation start or later, the rotation completes at once, exactly as if its deadline had passed.
  The count can't grow back, because new certificates come only from the new root and revocation is final.
  Devices whose old-root certificate has expired but is still within the renew grace keep renewing onto the new root after completion, because authentication is pin-based.
- Rotation pushes (C10): `RenewRequested{reason:"rotation"}` goes to connected old-root devices at a bounded rate (server setting; the mock defaults to 10/s) and keeps draining after the deadline, until every device connected on the old root has been notified; the persistent flag covers the rest.
- At rotation start, the old root's private key is destroyed; the server keeps only what's needed to recognize pinned old-root certificates.

## 9. Admin HTTP API (DVLS-specific; mock implements it identically)

This API follows DVLS conventions (camelCase keys, DVLS paging) rather than §1.

Base: `{u}/api/v3/agent-identity`.
Auth: DVLS session token from application-identity (or user) login, `Authorization: Bearer`.
Every endpoint requires a new administrative permission "Agent identity management" (E2), assignable to users and application identities through roles; built-in administrators have it implicitly.
Missing permission → `403`.
Errors: DVLS v3 conventions; the mock returns `{ "error", "message" }` with the same HTTP status.

### 9.1 Enrollment tokens

- `POST /enrollment-tokens` body `{ name, maxUses (1..1_000_000), expiresAt (≤ now + 365 d), friendlyNameFormat?, config? }` → `201 { token: "<full token>", record: TokenRecord }`; the full token is returned only here.
- `GET /enrollment-tokens?pageNumber&pageSize` → page of `TokenRecord`.
- `GET /enrollment-tokens/{id}` → `TokenRecord`; `DELETE /enrollment-tokens/{id}` → `204`.
- `TokenRecord`: `{ id, name, maxUses, usedCount, expiresAt, state: "active"|"exhausted"|"expired", friendlyNameFormat, config, createdAt, createdBy }`.

### 9.2 Devices

- `GET /devices` query: `pageNumber` (≥ 1, default 1), `pageSize` (1..100, default 25) **[DVLS convention replaces cursor]**, `view=summary|full`, `metadata=k1,k2`, `status=active|revoked|expired`, `enrollmentTokenId`, `issuer=<root thumbprint>`, `lastSeenBefore`, `lastSeenAfter`, `q` (friendly-name substring, case-insensitive).
  Ordered by creation (C9): each device gets a strictly increasing creation key when it's inserted (e.g. an identity column), and listings sort by it; `created_at` is non-decreasing in that order.
  A page walk returns every device that existed when the walk started at least once, and exactly once when no enrollment overlaps the walk; only a deletion during the walk can make it miss one.
  A device whose enrollment overlaps the walk may be missing from it, or make the next page repeat one entry; clients deduplicate by `id`.
  Device IDs stay UUIDs; a server may mint UUIDv7 (RFC 9562) for index locality, but the sort key stays separate (SQL Server doesn't order `uniqueidentifier` bytewise).
- Page shape (DVLS convention): `{ data: [...], currentPage, pageSize, totalCount, totalPages }`.
- Summary: `{ id, friendlyName, status, connected, lastSeenAt, certificate: { notAfter, issuer } }` plus `metadata` subset when requested.
- Full adds `metadata`, `certificates: [{ thumbprint, serialNumber, notBefore, notAfter, issuer, status }]`, `enrollmentToken: { id, name }`, `createdAt`, `revokedAt`, `renewalRequested`.
- `status=expired`: not revoked and no `current` certificate unexpired.
- `GET /devices/{id}` → full; `PATCH /devices/{id}` `{ friendlyName }` (1..255) → full.
- `view=full` always includes all metadata; `metadata=k1,k2` only extends `summary`.
- `pageNumber` beyond the last page returns an empty `data` array.
- `POST /devices/{id}/revoke` → `204` (idempotent); `DELETE /devices/{id}` → `204`, or `409` unless revoked.
- `POST /devices/{id}/request-renewal` → `202`.

### 9.3 Rotation

- `POST /ca/rotation` `{ deadline? }` → `202 Rotation`; `409` if one is in progress.
- `GET /ca/rotation` → `Rotation`: `{ phase: "idle"|"rotating", oldRoot?: { thumbprint, notAfter }, newRoot?: { thumbprint, notAfter }, deadline?, activeDevicesOnOldRoot }`.
- `activeDevicesOnOldRoot` counts non-revoked devices with an unexpired current or pending certificate issued by the old root (C10).

## 10. Agent local contract (observable by the conformance tester)

### 10.1 Configuration (`agent.json`)

```json
{
  "Identity": { "Enabled": true, "KeyBackend": "KeyStore" },
  "__debug__": {
    "identity": {
      "renewal_after_secs": 5,
      "disable_jitter": true,
      "extra_trusted_root": "C:\\path\\mock-cas.pem",
      "backoff_max_secs": 2,
      "pending_poll_interval_ms": 200,
      "acl_grant_current_user": true,
      "key_name_prefix": "DevolutionsAgentTest-3f2a9c1e-",
      "config_poll_interval_secs": 5,
      "channel_failure_config_poll_after_secs": 3
    }
  }
}
```

- `__debug__.identity.config_poll_interval_secs` and `channel_failure_config_poll_after_secs` (test use, C19): replace the 24 h and 1 h values of §5.6; with either set, the ±10% jitter is off.

- `__debug__.identity.key_name_prefix` (test use, C15): replaces the default key-name prefix `DevolutionsAgent-Identity-` (§10.3); the tester sets a unique prefix per run and deletes only keys with it.
- `__debug__.identity.metadata_override_path` (test use, C16): path to a JSON object of string values, read at every send (enroll, renew, `Hello`).
  Its known keys (§10.5) replace the collected values; unknown keys are ignored.
  A missing or unreadable file means no override.
  This lets the tester prove that metadata is collected at send time.

- `__debug__.identity.extra_trusted_root`: path to a PEM file with one or more certificates; each one is added to the TLS trust store in addition to the OS store (test use; multi-authority runs put both mock CAs in one bundle).
- `__debug__.identity.acl_grant_current_user` (Windows only, test use): the key-store key DACL and the pending-file reader also grant the agent process's user, so CI can run the agent as a normal process.
  The pending file is still written with a protected DACL; the tester adds the same user when it stands in for the MSI.
  Like the other `__debug__` knobs, it's never set by the MSI.

- `KeyBackend`: `KeyStore` (Windows default; Microsoft Software KSP, machine key, non-exportable) or `File` (default elsewhere; PKCS#8 `0600`).
- `Identity.Enabled` default `true`: the task is idle without a pending file or stored identity.

### 10.2 Pending-enrollment file

- Linux/macOS: `<data-dir>/identity/pending-enrollment.json`, mode `0600`, owned by the account the agent service runs as (root in production; the CI user in tests), content `{ "version": 1, "token": "<token>" }` (C12).
  The agent doesn't enforce the owner.
- Windows: `<data-dir>\identity\pending-enrollment.dat`, protected DACL granting SYSTEM full control only, content = DPAPI `CryptProtectData(json, entropy = "Devolutions.Agent.PendingEnrollment.v1", CRYPTPROTECT_LOCAL_MACHINE)`.
- The service reads it at start-up and polls for it (default every 5 s).
- It enrolls with retry; deletes on success or `token_*` / `token_malformed`; keeps it on anything else.
- Enrollment key (C15):
  - When the agent first processes a pending file, it generates the enrollment key and records `{ "version": 1, "token_sha256": "...", "key_name": "..." }` in `<data-dir>/identity/enrollment-in-progress.json` (written like `identity.json`; no secret).
  - Every retry of that pending file, including after a restart, uses that key, so a lost response is recovered through enroll idempotence (§2).
  - A pending file with a different token hash discards the in-progress record and its key, and starts over with a new key.
  - On success, the key becomes the new identity's `current` key; the in-progress record is deleted with the pending file.
  - `device_revoked` on enroll is also permanent: the device this enrollment created was revoked before the agent got the response, and coming back needs a different token.
    The agent stores no identity.
  - Every permanent outcome deletes the pending file, the in-progress record and the enrollment key.
- Same token hash as any stored identity, rejected or not → deleted without any request (the authority is only known after enrollment).
- A different token enrolls; on success its identity replaces the stored identity for the returned `authority_id` (old keys deleted).
- The token is never logged, not even partially; the tester greps agent logs for it.

### 10.3 Stored identities

- `<data-dir>/identity/authorities/<authority_id>/identity.json`:

```json
{
  "version": 1,
  "authority_id": "...", "device_id": "...", "friendly_name": "...",
  "base_url": "https://host/dvls", "config": { "version": 1, "agent_channel_url": "https://host/dvls" },
  "token_sha256": "<base64url SHA-256 of the full token string>",
  "rejected": { "code": "device_revoked", "at": "2026-09-24T12:00:00Z" },
  "keys": {
    "current": { "key_name": "...", "certificate_chain": ["..."] },
    "pending": { "key_name": "...", "certificate_chain": ["..."] } ,
    "previous": { "key_name": "...", "certificate_chain": ["..."] }
  }
}
```

- `rejected` is absent until the server answers a `renew` or channel `connect` with `device_revoked` or `device_unknown` (or closes a live stream with one of them); `code` is that error code.
  The agent can't observe revocation otherwise.
  Once `rejected` is set, the agent never renews or reconnects for that identity; only a new enrollment with a different token replaces it.
- `pending` and `previous` are optional; `pending.certificate_chain` is absent until renew succeeds; `previous` exists only between a successful `confirm` and the deletion of the old key (crash safety).
- `config` is stored exactly as received (unknown fields included), and replaced only by a higher `revision` (C19).
- Key names (C15): `DevolutionsAgent-Identity-<key_uuid>`, where `key_uuid` is a random UUID generated with each key.
  The authority isn't known when the enrollment key is created, and key-store keys can't be renamed.
  The file backend stores `<data-dir>/identity/keys/<key_name>.p8`.
- Key records (C15): the agent writes a key's name to its record (`identity.json` or `enrollment-in-progress.json`) before creating the key, and deletes a key before removing its name from the record.
  So a crash never leaves an unrecorded key, and every existing key with the agent's prefix is recorded.
  A recorded key that doesn't exist yet (or anymore) is regenerated or dropped at start-up.
- Writes are atomic (write temp + rename).

### 10.4 CLI

- `devolutions-agent identity enroll <token>` (decided, E3; `enroll` stays Agent Tunnel's): validates the token format, writes the pending file, prints where it was written, exits 0.

### 10.5 Metadata sent by the agent (C14)

- The agent sends a metadata object (§3) at enroll, at renew and in every `Hello`, collected at send time (so it reflects current values).
- Always present, non-empty: `hostname`, `os_name`, `os_version`, `arch`, `agent_version`.
- Present when the OS provides a value: `fqdn`, `domain`, `machine_id`.
- No other keys in V1.
- Value conventions (informational, but stable so servers can display and filter them consistently):
  - `hostname`: the OS host name, without domain.
  - `arch`: Rust `std::env::consts::ARCH` naming (`x86_64`, `aarch64`, `x86`).
  - `agent_version`: the agent's own product version string, the same one the binary's version resource and package report.
  - `machine_id`: Windows SMBIOS system UUID, lowercase hyphenated; Linux `/etc/machine-id` as-is; macOS `IOPlatformUUID`, lowercase hyphenated.
- The agent never sends a value that violates §3:
  - It removes C0/C1 control characters and truncates to 1024 UTF-8 bytes on a character boundary.
  - An optional key whose value is empty after that is omitted.
  - A required key that ends up empty gets the value `unknown`.

## 11. Mock server (conformance only)

- Implements §5, §7 and §9 per contract; shares only the `.proto` with the agent.
- Serves under a configurable path prefix (the conformance run uses `/mock`), so the agent's path-prefix handling is exercised; the Docker DVLS target has no prefix.
- Mock-only control API under `{u}/__mock__/`:
  - `POST faults` `{ drop_next_response?: "enroll"|"renew"|"confirm"|"config", clock_skew_secs?, leaf_lifetime_secs?, channel_available?, channel_broken?, rotation_rate_limit_per_sec? }`.
    `channel_available: false` makes new enroll responses omit `config.agent_channel_url` and makes channel opens fail with `UNAVAILABLE`.
    Changing `channel_available` bumps every device's config revision (the URL appears or disappears) and pushes `ConfigUpdate` on live streams, like a DVLS admin toggling "Agent channel enabled".
    `channel_broken: true` (C19) makes channel opens fail with `UNAVAILABLE` without changing the config, like a proxy that breaks gRPC.
  - `POST config` `{ "fields": { ... } }` (C19): merges extra fields (not `version`, `revision` or `agent_channel_url`) into every device's effective config, bumps the revisions and pushes `ConfigUpdate` on live streams; used to check propagation and the preservation of unknown fields.
  - `POST faults` also takes `fail_next_response?: { endpoint: "enroll"|"renew"|"confirm"|"config", status: <int>, error?: <§5.4 code> }` (C13): one-shot, the request isn't processed; with `error`, the body is the §5.4 shape, otherwise empty.
  - `POST reset`.
  - `POST time/advance` `{ secs }` (for grace and deadline tests); stream expiry and rotation deadlines are re-evaluated immediately on advance.
  - `GET events?device_id=<uuid>` (C13): ordered channel and certificate events for that device (`stream_opened`, `stream_authenticated`, `stream_closed` with status, `cert_status_changed`), each with a monotonic sequence number, so make-before-break is asserted from ordering rather than polling.
- Mock-only tests are skipped against DVLS.
- The mock may expose more test-only instrumentation (e.g. `__mock__/handshake`), documented in its README and used only by mock-only tests; it's not part of this contract.
