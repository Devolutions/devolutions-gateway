# Agent Identity — Contract (v0.3)

Status: v0.3, approved at the Phase 0 gate; decisions E1–E7 applied.
Changes go through the contract owner and require approval.
The channel `.proto` lives in `crates/agent-identity-channel-proto/proto/channel.proto` and the shared test vectors in `docs/agent-identity/test-vectors.json`.
Items marked **[proposed]** are Phase 0 choices not fixed by the V1 plan.

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
- Idempotence applies only when the matching device is not revoked; for a revoked device, enroll returns `device_revoked`.

## 3. Metadata

- JSON object of string → string.
- Known keys: `hostname`, `fqdn`, `domain`, `os_name`, `os_version`, `arch`, `agent_version`, `machine_id`.
- Limits **[proposed]**: ≤ 32 keys; key matches `^[a-z][a-z0-9_]{0,63}$`; value ≤ 1024 UTF-8 bytes, no C0/C1 control characters; whole object ≤ 8 KiB.
- Anything else (nested values, non-strings, limits exceeded) → `invalid_request`.
- Unknown keys within limits are stored as-is (informational only).
- Friendly name: evaluated once at enrollment from the token's format.
  Placeholders `{<known key>}` and `{token_name}`; `{{` and `}}` escape braces.
  Unknown placeholders are rejected at token creation; missing values evaluate to empty.
  The result is trimmed and truncated to 255 characters; an empty result falls back to the device ID.
  Default format **[proposed]**: `{hostname}`.

## 4. Certificates

- Chains are leaf-first, any length; the agent never assumes a tier count.
- DVLS: root P-256, 10 years, `CN=<product> Agent Identity Root <n>`, created on first use.
- Leaf: P-256, `CN=<device_id>`, SAN URI `urn:uuid:<device_id>`, EKU clientAuth, KeyUsage digitalSignature, validity default 90 days, capped at the issuing root's `notAfter`.
- The server ignores CSR subject and extensions; it only takes the public key (P-256 required, else `invalid_request`) and verifies the CSR self-signature (else `invalid_request`).

## 5. Agent-facing HTTP API (product-neutral)

Base: the token's `u`.
Paths **[proposed]** (identical for every product):

| Method | Path | Auth |
|---|---|---|
| GET | `{u}/api/agent-identity/v1/trust-anchor` | none |
| POST | `{u}/api/agent-identity/v1/enroll` | `Authorization: Bearer <token>` |
| POST | `{u}/api/agent-identity/v1/renew` | RFC 9421, `tag="renew"` |

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
  "channel_url": "https://host/dvls",
  "config": { "version": 1 }
}
```

- `authority_id` is stable for a server instance (DVLS: generated once, stored in settings).
- `channel_url` is absent when the server cannot host the channel (see §7.5).
- `config` is versioned; V1 has no other fields.

### 5.3 `POST renew`

- Signed with the current key (§6), `tag="renew"`, `content-digest` covering the exact body bytes.
- Request: `{ "csr": "...", "metadata": { ... } }` for the new key.
- `200`: `{ "certificate_chain": [ ... ] }`.
- Idempotent on the new public key.
- At most one `pending` certificate per device: a renew with a different new key retires the previous pending certificate.
- Accepted with a `current` or `pending` certificate that is unexpired, or expired by less than its own lifetime (`now < notAfter + (notAfter − notBefore)`).

### 5.4 Errors

Body for every non-2xx response:

```json
{ "error": "<code>", "message": "<human text>", "server_time": "<RFC 3339>" }
```

`server_time` is always present; agents use it only for `clock_skew`.

| Code | HTTP | Meaning | Agent class |
|---|---|---|---|
| `token_invalid` | 401 | Unknown or deleted token, bad secret | permanent |
| `token_exhausted` | 403 | `used_count = max_uses` | permanent |
| `token_expired` | 401 | `now ≥ expires_at` | permanent |
| `device_revoked` | 403 | Device revoked | terminal |
| `device_unknown` | 401 | Certificate not registered, or device deleted | terminal |
| `certificate_expired` | 401 | Expired (for `connect`) or beyond grace (for `renew`) | re-enroll required |
| `signature_invalid` | 401 | Bad signature, wrong `tag`, bad digest, replayed nonce, malformed params | transient |
| `clock_skew` | 401 | `created`/`expires` outside tolerance | transient, adjust clock |
| `invalid_request` **[proposed]** | 400 | Malformed body, CSR or metadata | transient (agent bug; keep retrying with backoff) |

`token_*` codes on a pending enrollment are permanent (the pending file is deleted).
`device_revoked` and `device_unknown` record `rejected` on the stored identity (§10.3); the agent stops renewing and reconnecting for that authority.

## 6. RFC 9421 profile

- Label `sig`.
- `Signature-Input: sig=(<components>);created=<int>;expires=<int>;nonce="<base64url 16 random bytes>";keyid="<thumbprint>";alg="ecdsa-p256-sha256";tag="<renew|connect>"`.
- Components: `renew` → `("@method" "content-digest")`; `connect` → `("@method")`.
- `Content-Digest: sha-256=:<base64>:` (RFC 9530).
- Signature: ECDSA P-256 over SHA-256 of the signature base, raw 64-byte `r‖s`.
- Agent sets `expires = created + 60`.
- Server checks, in this order:
  1. Parse; exactly one signature labelled `sig`; all parameters present; `alg` matches → else `signature_invalid`.
  2. `tag` matches the endpoint → else `signature_invalid`.
  3. `expires − created ≤ 300`; `created ≤ now + 60`; `expires ≥ now − 60` → else `clock_skew`.
  4. Resolve `keyid` to a registered certificate with status `current` or `pending` → else `device_unknown`; device not revoked → else `device_revoked`; validity per endpoint → else `certificate_expired`.
  5. Verify `content-digest` (renew) and the signature → else `signature_invalid`.
  6. Atomically insert `(keyid, nonce)` into the nonce store; conflict → `signature_invalid`.
     Entries are kept until `expires + 60`.
- Nonces are committed only after the signature verifies (step 6), so garbage requests cannot burn nonces.
- On `clock_skew`, the agent may retry once with `created` offset by `server_time − local_time`.
- Libraries (approved, E4): Rust `httpsig` (signature base + custom `SigningKey`, `httpsig-hyper` for `content-digest` on `renew`); .NET NSign for signature base and ECDSA verification.
  Only the policy checks above (tag, window, key resolution, nonce commit) are our code; any other gap is escalated.
- Shared test vectors (`docs/agent-identity/test-vectors.json`): fixed P-256 key, fixed requests for both tags, exact signature base strings, valid signatures, a channel proof (§7.3), and negative cases; plus RFC 9421 Appendix B.2.4 as a sanity check.

## 7. Channel (gRPC)

### 7.1 Service

Package **[proposed]** `devolutions.agent.identity.channel.v1`.
The `.proto` is the single source for every language: Rust (`agent-identity-channel-proto` crate) and .NET (`Devolutions.AgentIdentity.Channel` NuGet package, built from the same file in devolutions-gateway).

```proto
syntax = "proto3";
package devolutions.agent.identity.channel.v1;

option csharp_namespace = "Devolutions.AgentIdentity.Channel.V1";

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
  }
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

- gRPC path: `<channel_url path>/devolutions.agent.identity.channel.v1.AgentChannel/Connect`.
  With `channel_url = https://host/dvls`, the `:path` is `/dvls/devolutions.agent.identity.channel.v1.AgentChannel/Connect`; the agent's tower layer adds the prefix.
- The opening request carries `signature-input`, `signature` metadata with `tag="connect"`.

### 7.3 Sequence

1. The agent opens the stream with the signed opening request (§6, `tag="connect"`) and sends nothing until it receives `Challenge`.
2. The server verifies the signature (§6), then sends `Challenge` as its first message.
3. The agent sends `Hello` with `correlation_id` = Challenge `id` and `proof` = ECDSA P-256 / SHA-256, raw 64-byte `r‖s`, by the same key, over the bytes:
   `"devolutions-agent-identity/v1/channel-proof" ‖ 0x00 ‖ challenge (32 bytes) ‖ connect nonce (UTF-8 bytes of the `nonce` parameter)`.
4. The server verifies `proof` with the public key of the certificate that authenticated the opening request.
   On success it replies `Welcome` (`correlation_id` = Hello `id`), updates metadata, `last_seen_at` and `connected`, and only then treats the stream as authenticated.
   On failure, or if no `Hello` arrives within 10 s, it closes the stream with `UNAUTHENTICATED` + `error-code: signature_invalid`.
5. If the request-renewal flag is set, the server sends `RenewRequested` after `Welcome` on every connect until the device renews; the agent replies `Ack` (`correlation_id` = message `id`).
6. `Reconnect` asks the agent to open a new stream; the agent opens it, then closes the old one.
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
- When a `pending` certificate authenticates, the previous `current` certificate is retired and its streams are closed with `OK` (the agent has already switched: make-before-break).
- Agent: HTTP/2 keepalive every 30 s; reconnect with jittered exponential backoff (1 s → 5 min); stops on `device_revoked` / `device_unknown`.

### 7.5 Availability

- DVLS emits `channel_url` only when it runs on Kestrel, or IIS in-process on Windows build ≥ 20348 (Server 2022) / ≥ 22000 (Windows 11), and an admin setting "Agent channel enabled" (default on) is not turned off **[proposed]**; the setting covers reverse proxies that break gRPC.
- No fallback transport.

## 8. Renewal and rotation

As in the V1 plan (agent steps 1–6, DVLS `pending`/`current`/`retired`, grace = one leaf lifetime; manual rotation with deadline, rate-limited `RenewRequested`, old root removed at deadline, pinned old-root certificates accepted until their expiry).
Additions:
- Renewal trigger: `notBefore + 2/3 × lifetime + jitter`, jitter uniform in `[0, 1/12 × lifetime]`.
- The request-renewal flag is cleared when a certificate issued after the flag was set first authenticates.
- Rotation `deadline`: RFC 3339 or the literal `"now"`; a value ≤ now is an emergency; absent → the maximum.

## 9. Admin HTTP API (DVLS-specific; mock implements it identically)

This API follows DVLS conventions (camelCase keys, DVLS paging) rather than §1.

Base **[proposed]**: `{u}/api/v3/agent-identity`.
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
  Ordered by `(createdAt, id)` ascending, so new enrollments never shift earlier pages.
- Page shape (DVLS convention): `{ data: [...], currentPage, pageSize, totalCount, totalPages }`.
- Summary: `{ id, friendlyName, status, connected, lastSeenAt, certificate: { notAfter, issuer } }` plus `metadata` subset when requested.
- Full adds `metadata`, `certificates: [{ thumbprint, serialNumber, notBefore, notAfter, issuer, status }]`, `enrollmentToken: { id, name }`, `createdAt`, `revokedAt`, `renewalRequested`.
- `status=expired`: not revoked and no `current` certificate unexpired.
- `GET /devices/{id}` → full; `PATCH /devices/{id}` `{ friendlyName }` (1..255) → full.
- `POST /devices/{id}/revoke` → `204` (idempotent); `DELETE /devices/{id}` → `204`, or `409` unless revoked.
- `POST /devices/{id}/request-renewal` → `202`.

### 9.3 Rotation

- `POST /ca/rotation` `{ deadline? }` → `202 Rotation`; `409` if one is in progress.
- `GET /ca/rotation` → `Rotation`: `{ phase: "idle"|"rotating", oldRoot?: { thumbprint, notAfter }, newRoot?: { thumbprint, notAfter }, deadline?, activeDevicesOnOldRoot }`.

## 10. Agent local contract (observable by the conformance tester)

### 10.1 Configuration (`agent.json`) **[proposed]**

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
      "acl_grant_current_user": true
    }
  }
}
```

- `__debug__.identity.extra_trusted_root`: path to a PEM file with one or more certificates; each one is added to the TLS trust store in addition to the OS store (test use; multi-authority runs put both mock CAs in one bundle).
- `__debug__.identity.acl_grant_current_user` (Windows only, test use): the key-store key DACL and the pending-file reader also grant the agent process's user, so CI can run the agent as a normal process.
  The pending file is still written with a protected DACL; the tester adds the same user when it stands in for the MSI.
  Like the other `__debug__` knobs, it's never set by the MSI.

- `KeyBackend`: `KeyStore` (Windows default; Microsoft Software KSP, machine key, non-exportable) or `File` (default elsewhere; PKCS#8 `0600`).
- `Identity.Enabled` default `true`: the task is idle without a pending file or stored identity.

### 10.2 Pending-enrollment file

- Linux/macOS: `<data-dir>/identity/pending-enrollment.json`, owner root, mode `0600`, content `{ "version": 1, "token": "<token>" }`.
- Windows: `<data-dir>\identity\pending-enrollment.dat`, protected DACL granting SYSTEM full control only, content = DPAPI `CryptProtectData(json, entropy = "Devolutions.Agent.PendingEnrollment.v1", CRYPTPROTECT_LOCAL_MACHINE)`.
- The service reads it at start-up and polls for it (default every 5 s).
- It enrolls with retry; deletes on success or `token_*` / `token_malformed`; keeps it on anything else.
- Same token hash as any stored identity, rejected or not → deleted without any request (the authority is only known after enrollment).
- A different token enrolls; on success its identity replaces the stored identity for the returned `authority_id` (old keys deleted).
- The token is never logged, not even partially; the tester greps agent logs for it.

### 10.3 Stored identities

- `<data-dir>/identity/authorities/<authority_id>/identity.json`:

```json
{
  "version": 1,
  "authority_id": "...", "device_id": "...", "friendly_name": "...",
  "base_url": "https://host/dvls", "channel_url": "https://host/dvls", "config": { "version": 1 },
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
- `pending` and `previous` are optional; `pending.certificate_chain` is absent until renew succeeds.
- Key names: `DevolutionsAgent-Identity-<authority_id>-<generation>`; file backend stores `<authority dir>/keys/<key_name>.p8`.
- Writes are atomic (write temp + rename).

### 10.4 CLI

- `devolutions-agent identity enroll <token>` (decided, E3; `enroll` stays Agent Tunnel's): validates the token format, writes the pending file, prints where it was written, exits 0.

## 11. Mock server (conformance only)

- Implements §5, §7 and §9 per contract; shares only the `.proto` with the agent.
- Serves under a configurable path prefix (the conformance run uses `/mock`), so the agent's path-prefix handling is exercised; the Docker DVLS target has no prefix.
- Mock-only control API under `{u}/__mock__/`:
  - `POST faults` `{ drop_next_response?: "enroll"|"renew", clock_skew_secs?, leaf_lifetime_secs?, channel_available?, rotation_rate_limit_per_sec? }`.
  - `POST reset`.
  - `POST time/advance` `{ secs }` (for grace and deadline tests).
- Mock-only tests are skipped against DVLS.
