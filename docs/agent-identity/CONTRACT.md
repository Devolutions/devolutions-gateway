# Agent Identity — Contract

## History

- v1.0 (2026-09-25) by @CBenoit

## Definitions

- `base64` means standard Base64 (RFC 4648 §4) with padding.
- `base64url` means URL- and filename-safe Base64 alphabet (RFC 4648 §5) without padding.
- An authority is the product server that enrolls and authenticates agents; "server" means the authority unless stated otherwise.
- SPKI means the DER-encoded X.509 `SubjectPublicKeyInfo` structure.
- `<data-dir>` means the agent's configured data directory.

## 1. Protocol conventions

Unless stated otherwise, implementations must follow these conventions.

- JSON bodies are UTF-8, `Content-Type: application/json`, snake_case keys; enum values are snake_case strings.
- Optional fields are omitted when absent (never write `null`, but accept it).
- Receivers ignore unknown JSON fields unless stated otherwise.
- Timestamps are RFC 3339 UTC strings (e.g.: `2026-09-24T12:00:00Z`).
- IDs are lowercase hyphenated UUIDs.
- Certificates and CSRs are DER, encoded `base64` in JSON.
- A certificate thumbprint is `base64url(SHA-256(certificate DER))`.

<a id="agent-identity-enrollment-token"></a>

## 2. Enrollment token

```
<prefix>.<bag>.<secret>
```

- `prefix`: `dvaet1` = **D**e**v**olutions **A**gent **E**nrollment **T**oken, format version **1**.
  - A complete V1 token matches `^dvaet1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$`.
  - Agents reject prefixes they do not support.
  - Product-neutral (e.g.: DVLS and PSU use the same prefix).
- `bag`: `base64url` of a UTF-8 JSON object, unsigned and used only for routing.
  The agent ignores unknown fields.
  V1 fields:
  - `u` (required): absolute `https` product base URL without a query or fragment, e.g. `https://host/dvls`.
- `secret`: `base64url` of 32 random bytes; opaque to the agent.
- Total length ≤ 4096 bytes.
  The agent rejects malformed tokens locally without contacting the server and treats the failure as permanent.

### 2.1 Authority behavior

- The server stores only `SHA-256(secret)`.
- A token can create a device only when it exists, has not been deleted, has not expired, and `used_count < max_uses`.
- A token use is consumed in the transaction that creates the device.
- Re-enrollment with the same token and CSR public key returns the existing device without consuming another use.
- Deleting a token retains its secret hash and `deleted_at` as a tombstone.
  A deleted token authenticates only for an idempotent replay of a device that it created; every other use returns `token_invalid`.
- The server evaluates enrollment in this order: (1) authenticate the token by finding its row and matching `SHA-256(secret)`, otherwise return `token_invalid`; (2) validate the body, CSR and metadata, otherwise return `invalid_request`; (3) look up the CSR public key for idempotence; (4) return `token_invalid` if the token is deleted, then `token_expired` if it is expired; (5) return `token_exhausted` if its uses are exhausted; (6) create the device.
  The idempotence lookup precedes deletion, expiry and exhaustion checks so a lost response can always be retried with the same token.
- The server matches the CSR public key against every certificate it has issued:
  - The key of the current certificate of a non-revoked device enrolled with the same token → `200` with that device and its current chain, without consuming a use or changing metadata or `last_seen_at`.
    A CSR proves past possession of the key, not present possession.
  - The key of a device enrolled with a different token → `invalid_request`.
  - Any certificate key of a revoked device → `device_revoked`.
  - The key of a pending or retired certificate of a non-revoked device → `invalid_request`.
    A public key belongs to exactly one certificate lineage and is never reused.
  - The key of a certificate of a deleted device → `device_revoked`.
    The server retains the SPKI SHA-256 and original issuance time of every issued public key after device deletion; V1 defines no purge operation for these records.
- Servers must preserve these properties under concurrency:
  - Every issued public key is unique by SPKI SHA-256 across current, pending, retired and deleted-device certificates.
  - Concurrent device creations cannot increase `used_count` beyond `max_uses`.
  - Of two concurrent enrollments with the same CSR key, exactly one creates the device and the other receives the §2 replay result.
    Concurrent renewals with the same CSR key behave the same way (§5.3).
  - No certificate is issued by the old root after a root rotation starts.

## 3. Metadata

- JSON object of string → string.
- Known keys: `hostname`, `fqdn`, `domain`, `os_name`, `os_version`, `arch`, `agent_version`, `machine_id`.
- Limits: ≤ 32 keys; key matches `^[a-z][a-z0-9_]{0,63}$`; value ≤ 1024 UTF-8 bytes with no C0/C1 control characters; whole object ≤ 16 KiB, measured as the sum of the UTF-8 byte lengths of all keys and values.
- `metadata` is required in enroll, renew and check-in bodies and may be an empty object; an absent or non-object value → `invalid_request`.
- Anything else (nested values, non-strings, limits exceeded) → `invalid_request`.
- Unknown keys within these limits are stored as-is and never used for authorization.
- The server replaces stored metadata after each successful new enrollment, renewal, check-in or authenticated `Hello`.
  An idempotent enrollment replay does not update metadata.
- Friendly name: evaluated once at enrollment from the token's format.
  Placeholders are `{<known metadata key>}` and `{token_name}`, where `token_name` is the enrollment token's name.
  `{{` and `}}` escape braces; an unpaired brace or unknown placeholder is rejected at token creation.
  Missing metadata values evaluate to empty.
  The result is trimmed and truncated to 255 characters; an empty result falls back to the device ID.
  "Characters" means Unicode scalar values here and in `PATCH /devices/{id}`, and truncation never splits one.
  Default format: `{hostname}`.

## 4. Certificates

- Chains are leaf-first, any length; the agent never assumes a tier count.
- DVLS: root P-256, 10 years, `CN=<product> Agent Identity Root <n>`, created on first use, where `<n>` is the root generation number.
- Leaf: P-256, `CN=<device_id>`, SAN URI `urn:uuid:<device_id>`, EKU clientAuth, KeyUsage digitalSignature, validity default 90 days, capped at the issuing root's `notAfter`.
- The server ignores CSR subject and extensions; it only takes the public key (P-256 required, else `invalid_request`) and verifies the CSR self-signature (else `invalid_request`).
- The CSR signature algorithm is `ecdsa-with-SHA256`; anything else → `invalid_request`.
- The leaf lifetime is a server setting with a default of 90 days.

## 5. Agent-facing HTTP API (product-neutral)

Base: the token's `u`.
Paths (identical for every product):

| Method | Path                                     | Auth                                                      |
| ------ | ---------------------------------------- | --------------------------------------------------------- |
| GET    | `{u}/api/agent-identity/v1/trust-anchor` | none                                                      |
| POST   | `{u}/api/agent-identity/v1/enroll`       | `Authorization: Bearer <token>`                           |
| POST   | `{u}/api/agent-identity/v1/renew`        | RFC 9421, `tag="renew"`                                   |
| POST   | `{u}/api/agent-identity/v1/confirm`      | RFC 9421, `tag="confirm"`, signed with the new key (§5.5) |
| POST   | `{u}/api/agent-identity/v1/check-in`     | RFC 9421, `tag="check-in"` (§5.6)                         |

### 5.1 `GET trust-anchor`

`200`:

```json
{
  "roots": [
    {
      "certificate": "<base64 DER>",
      "thumbprint": "<base64url>",
      "not_before": "...",
      "not_after": "..."
    }
  ]
}
```

The response contains one root normally and two during a rotation.
Validating a chain against these roots does not establish that the device has not been revoked.

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
  "certificate_chain": ["<base64 DER leaf>", "<base64 DER root>"],
  "config": {
    "version": 1,
    "revision": 1,
    "agent_channel_url": "https://host/dvls"
  }
}
```

- `authority_id` is stable for a server instance (DVLS: generated once, stored in settings).
- The server generates `device_id` when it creates the device, and the ID remains stable for that device.
- The friendly name is evaluated and stored at enrollment (§3) and exposed only through the admin API (§9).
  It is not returned to the agent because (1) that’s not particularly useful, and (2) an administrator can rename the device later, possibly rendering the information stale.
- `config` is versioned, and `version` identifies its schema; the agent ignores unknown fields.
- `config.revision` is an unsigned integer assigned by the server and strictly increases per device whenever the device's effective config changes.
  The agent replaces its stored config only with a higher revision.
  Later revisions are delivered through the agent channel (§7.3) or check-in (§5.6).
- `config.agent_channel_url` is the base URL of the agent channel (§7).
  It is absent when the server does not offer the channel to this device, and the agent then opens no agent channel for that authority.
  It must be an absolute `https` URL without a query or fragment; an agent receiving any other value treats it as absent and logs a warning.
  Product-specific config fields, such as a PSU channel URL, may coexist with it.
- The agent's identity HTTP client never follows redirects and treats a `3xx` response as transient.
  It validates the server certificate and host name against the OS trust store.

### 5.3 `POST renew`

- Signed with the current key (§6), except for the pending-key recovery defined in §8, using `tag="renew"` and `content-digest` over the exact body bytes.
- Request: `{ "csr": "...", "metadata": { ... } }` for the new key.
- `200`: `{ "certificate_chain": [ ... ] }`.
- Idempotent on the new public key.
- Every accepted renew request, including an idempotent retry that returns the existing pending chain, replaces the device's metadata and sets `last_seen_at` to the current server time.
- The key of the device's pending certificate → `200` replaying that pending chain after a lost response; the key of any other certificate the server has issued, including this device's current or retired certificates and every certificate of another device, → `invalid_request`; any other key receives a new pending certificate.
- At most one `pending` certificate per device: a renew with a different new key retires the previous pending certificate.
- Accepted with a `current` or `pending` certificate that is unexpired, or expired by less than its own lifetime (`now < notAfter + (notAfter − notBefore)`).
- Renew never promotes a certificate; only `confirm` does (§5.5).

<a id="agent-identity-errors"></a>

### 5.4 Errors

Body for every non-2xx response:

```json
{ "error": "<code>", "message": "<human text>", "server_time": "<RFC 3339>" }
```

`server_time` is always present; agents use it only for `clock_skew`.
This body is present on every non-2xx response under `{u}/api/agent-identity/v1/`, including framework-level failures: malformed JSON or body → `400 invalid_request`; unknown route → `404 invalid_request`; wrong method → `405 invalid_request`; body too large → `413 invalid_request`.

| Code                  | HTTP | Meaning                                                                      | Agent class                                       |
| --------------------- | ---- | ---------------------------------------------------------------------------- | ------------------------------------------------- |
| `token_invalid`       | 401  | Unknown or deleted token, bad secret                                         | permanent                                         |
| `token_exhausted`     | 403  | `used_count = max_uses`                                                      | permanent                                         |
| `token_expired`       | 401  | `now ≥ expires_at`                                                           | permanent                                         |
| `device_revoked`      | 403  | Device revoked                                                               | terminal                                          |
| `device_unknown`      | 401  | Certificate not registered, or device deleted                                | terminal                                          |
| `certificate_expired` | 401  | Expired (for `connect`, `confirm`, `check-in`) or beyond grace (for `renew`) | see below                                         |
| `signature_invalid`   | 401  | Bad signature, wrong `tag`, bad digest, replayed nonce, malformed params     | transient                                         |
| `clock_skew`          | 401  | `created`/`expires` outside tolerance                                        | transient, adjust clock                           |
| `invalid_request`     | 400  | Malformed body, CSR or metadata                                              | transient (agent bug; keep retrying with backoff) |

`token_*` codes on a pending enrollment are permanent (the pending file is deleted).

`device_revoked` and `device_unknown` record `rejected` on the stored identity (§10.3); the agent stops renewing and reconnecting for that authority.

`certificate_expired`:

- On `connect` or `check-in`: the agent renews immediately (§8), signing with the expired certificate, which renew still accepts within its grace; it retries the operation only after `confirm`.
- On `renew`: the certificate is beyond grace.
  The agent records `rejected { code: "certificate_expired" }` and stops; only a new enrollment with a different token recovers.
- On `confirm`: see §8.

Any failure not classified above is transient, including an unrecognized or unparseable `4xx`, `429`, any `5xx`, a `3xx`, and network or TLS errors.
The agent retries transient failures with jittered exponential backoff and honors `Retry-After` when present.
Servers accept request bodies up to 64 KiB on these endpoints; a larger body → `413 invalid_request`.

### 5.5 `POST confirm`

- Signed with the **pending** certificate's key (§6), `tag="confirm"`, components `("@method")`, empty body.
- The signing certificate must be the device's `pending` or `current` certificate and unexpired (no grace), else §6 step 4 errors.
- Pending → it becomes `current`, the previous `current` becomes `retired`, and the server:
  - sends `Reconnect{reason:"certificate_rotated"}` on streams opened with the retired certificate;
  - closes those still open 60 s later with `OK`.
- Already current → no-op (idempotent retry after a lost response).
- `204` in both cases.
- `confirm` is the only operation that promotes a certificate; renew and channel connect never do.

### 5.6 `POST check-in` (HTTP fallback)

- Signed with the current key (§6), `tag="check-in"`, components `("@method" "content-digest")`.
- Request: `{ "metadata": { ... } }` (§3, §10.5; required).
- The signing certificate must be `current` or `pending` and unexpired (no grace).
- The server updates the device's metadata and `last_seen_at`, as for a `Hello` (§7.3).
  Unlike an idempotent enroll replay, a check-in carries a fresh signature and nonce, so it proves present possession of the key.
- `200`:

```json
{
  "config": {
    "version": 1,
    "revision": 3,
    "agent_channel_url": "https://host/dvls"
  },
  "renewal_requested": false
}
```

- `config`: the device's effective config (same shape as in §5.2, with its current `revision`); the agent stores and applies it as for a `ConfigUpdate` (§7.3 step 7).
- `renewal_requested`: the device's request-renewal flag (§9.2, and set by rotation); when `true`, the agent starts a renewal (§8).
- It's the only HTTP fallback; with a working channel, config and renewal requests arrive through §7.3 and the agent never checks in.
  When the agent checks in:
  - no `config.agent_channel_url`: at service start, then every 24 h (±10% jitter);
  - `config.agent_channel_url` present but no stream authenticated for 1 h: once, then every 24 h (±10% jitter) until a stream authenticates;
  - otherwise, never.
- Scope: nothing else is delivered over HTTP; features that need push (e.g. PEDM policy) require a working agent channel.

<a id="agent-identity-signatures"></a>

## 6. RFC 9421 profile

- Label `sig`.
- `Signature-Input: sig=(<components>);created=<int>;expires=<int>;nonce="<base64url 16 random bytes>";keyid="<thumbprint>";alg="ecdsa-p256-sha256";tag="<renew|connect|confirm|check-in>"`.
- Components: `renew` and `check-in` → `("@method" "content-digest")`; `connect` and `confirm` → `("@method")`.
- `Content-Digest: sha-256=:<base64>:` (RFC 9530).
- Signature: ECDSA P-256 over SHA-256 of the signature base, raw 64-byte `r‖s`.
- Agent sets `expires = created + 60`.
- Server checks, in this order:
  1. Parse; exactly one signature labelled `sig`; all parameters present; `alg` matches; the covered components are **exactly** the tag's list above, in that order, each once → else `signature_invalid`.
     A verifier never relies on the client-declared list alone: an under-covered request, such as `renew` covering only `@method`, must fail here.
     For `renew` and `check-in`, exactly one `Content-Digest` member using `sha-256` is required.
  2. `tag` matches the endpoint → else `signature_invalid`.
  3. `0 < expires − created ≤ 300`; `created ≤ now + 60`; `expires ≥ now − 60` → else `clock_skew`.
  4. Resolve `keyid` to a registered certificate with status `current` or `pending` → else `device_unknown`; device not revoked → else `device_revoked`; validity per endpoint → else `certificate_expired`.
  5. Verify `content-digest` for `renew` and `check-in`, then verify the signature → else `signature_invalid`.
  6. Atomically insert `(keyid, nonce)` into the nonce store; conflict → `signature_invalid`.
     Entries are kept until `expires + 60`.
- Nonces are committed only after the signature verifies (step 6), so garbage requests cannot burn nonces.
- On `clock_skew`, the agent may retry once with `created` offset by `server_time − local_time`.
- Implementations must enforce the policy checks above in addition to the RFC validation provided by their signature libraries.
- Implementations must pass the shared test vectors in `docs/agent-identity/test-vectors.json`: a fixed P-256 key, fixed requests for all four tags, exact signature base strings, valid signatures, a channel proof (§7.3), negative cases including every cross-tag pair, and RFC 9421 Appendix B.2.4 as a sanity check.
  In negative cases, `signature_base` is the base that was originally signed, not what a verifier recomputes from the altered request.

<a id="agent-identity-channel"></a>

## 7. Channel (gRPC)

### 7.1 Service

The gRPC package is `devolutions.agent.channel.v1`.
All language bindings, including the Rust `agent-channel-proto` crate and .NET `Devolutions.Agent.Channel` package, must use the following schema.

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

// The device's effective config (§5.2 shape) as a UTF-8 JSON object.
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
  With `agent_channel_url = https://host/dvls`, the `:path` is `/dvls/devolutions.agent.channel.v1.AgentChannel/Connect`; the agent prepends the URL path when constructing `:path`.
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
7. `Hello.applied_state_versions["config"]` carries the agent's stored `config.revision`.
   If the device's current revision is higher, the server sends `ConfigUpdate` after `Welcome`.
   When the device's effective config changes, the server bumps the revision and sends `ConfigUpdate` on the device's live streams.
   The agent stores it if the revision is higher, replies `Ack` (`correlation_id` = message `id`), and applies it:
   - `agent_channel_url` removed: it closes the stream and stops connecting;
   - `agent_channel_url` changed: it reconnects to the new URL, opening the new stream before closing the old one;
   - `agent_channel_url` added (only reachable through §5.6 check-in): it connects.

- No server push, metadata update or `connected` state happens before step 4 succeeds.
- Rationale: the header signature isn't bound to the stream; the fresh challenge makes captured opening headers (TLS-terminating proxies, TLS inspection, header logs) useless for opening a stream.
- An active intermediary in the path is out of scope because it can read the plaintext, and V1 does not provide TLS channel binding.
- Envelope `id` values are UUIDs.
- Unknown payloads are ignored.
- Push is an optimization; `Hello`/`Welcome` reconciliation is authoritative.

### 7.4 Termination

- Auth failures at open: gRPC status `UNAUTHENTICATED` (or `PERMISSION_DENIED` for `device_revoked`) with trailer `error-code: <§5.4 code>`.
- Revocation: the server closes live streams with `PERMISSION_DENIED` + `error-code: device_revoked`.
- A stream closes no later than its certificate's `notAfter` (`UNAUTHENTICATED` + `certificate_expired`).
- When `confirm` promotes a pending certificate (§5.5), the previous `current` certificate is retired; its streams get `Reconnect{reason:"certificate_rotated"}` and are closed with `OK` 60 s later if still open.
- The agent sends an HTTP/2 keepalive every 30 s and reconnects with jittered exponential backoff from 1 s to 5 min.
  It stops reconnecting on `device_revoked` or `device_unknown`.

### 7.5 Availability

- DVLS emits `config.agent_channel_url` only when it runs on Kestrel, or IIS in-process on Windows build ≥ 20348 (Server 2022) / ≥ 22000 (Windows 11), and an admin setting "Agent channel enabled" (default on) is not turned off; the setting covers reverse proxies that break gRPC.
- There is no fallback channel transport; §5.6 check-in carries only config and renewal requests.

## 8. Renewal and rotation

### 8.1 Agent renewal

1. Trigger at `notBefore + 2/3 × lifetime + jitter` (jitter uniform in `[0, 1/12 × lifetime]`), or on `RenewRequested`.
2. Generate the new key and record it as `pending` (§10.3 write-before-create).
3. `POST renew` with its CSR, signed with the current key; retry with the same CSR on failure.
4. Store the returned chain on the `pending` slot.
5. `POST confirm` signed with the new key; retry with backoff.
   While the outcome of a `confirm` is unknown, the agent sends no other signed request to that authority and opens no stream; it retries `confirm` first, since `confirm` is idempotent.
6. On `204`, `pending` becomes `current`; the agent records the old key as `previous`, deletes it, and then removes `previous` according to the §10.3 delete-before-remove rule.
7. Reconnect the agent channel, if any, with the new certificate by opening the new stream before closing the old one.

#### Failure handling

- On a transient `renew` or `confirm` error, the agent retries with backoff while the old certificate and stream remain in use.
- `certificate_expired` on `confirm` means the pending certificate expired before it was confirmed.
  The agent cannot know whether an earlier `confirm` succeeded after a lost response, so it renews **signed with the pending key**; the server accepts a pending or current certificate within its renewal grace, whichever state it holds.
  - On success, the agent continues at step 4 with the new pending certificate and deletes the previous pending key after the next `confirm` succeeds.
  - On `certificate_expired` beyond grace, the agent records `rejected { code: "certificate_expired" }`.
  - On `device_unknown`, the server holds neither certificate, so the agent retries the same renewal signed with the old current key while that certificate remains within grace.
- If a pending key is unusable locally, the agent deletes the key and its slot, then renews with a fresh key signed by the current certificate while it is valid or within renewal grace.
  Issuing the new pending certificate retires the previous pending certificate as specified in §5.3.
- `device_revoked` and `device_unknown` are terminal (§5.4).

### 8.2 Server certificate state

- DVLS records each issued device certificate as `pending`, `current` or `retired`.
- A `pending` certificate becomes `current` only through `confirm` (§5.5).
- Renewal grace lasts for the certificate's own lifetime, as defined in §5.3.
- The request-renewal flag is cleared when the device confirms a certificate issued after the flag was set.

### 8.3 Root rotation

- Rotation is started through the admin API (§9.3).
- The `deadline` is an RFC 3339 timestamp or the literal `"now"`; a value at or before the current time requests an emergency rotation.
  When omitted, it defaults to the rotation maximum.
- The rotation maximum is the latest `notAfter` among unexpired current or pending certificates of non-revoked devices issued by the old root, or the current time when there are none.
  An explicit deadline after this maximum → `400`.
- At rotation start, the server creates and publishes the new root alongside the old root, destroys the old root's private key, and issues every new certificate from the new root.
- The server sets the request-renewal flag for each non-revoked device with a current or pending certificate issued by the old root.
  It sends `RenewRequested{reason:"rotation"}` to connected affected devices at a bounded, configurable rate and continues until every such connected device has been notified.
  The persistent request-renewal flag covers devices that are disconnected or not yet notified.
- When `activeDevicesOnOldRoot` reaches 0, whether at rotation start or later, rotation completes immediately as though its deadline had passed.
  This count cannot increase because all new certificates use the new root and revocation is final.
- Rotation also completes when its deadline passes.
  Completion removes the old root from `GET trust-anchor`.
- The server continues to recognize registered certificates issued by the old root after completion without requiring that root to remain published.
  The endpoint-specific validity rules still apply, and a device whose old-root certificate is expired but within renewal grace can renew onto the new root.

## 9. Admin HTTP API (DVLS-specific)

This API uses camelCase JSON keys and the `pageNumber`/`pageSize` pagination defined in §9.2; the other protocol conventions in §1 still apply.

Base: `{u}/api/v3/agent-identity`.
Auth: DVLS session token from application-identity (or user) login, `Authorization: Bearer`.
Every endpoint requires the "Agent identity management" permission, which roles may grant to users and application identities; built-in administrators have it implicitly.
Missing permission → `403`.
This contract defines endpoint-specific error statuses but does not standardize DVLS admin error bodies.
The mock returns `{ "error": "<code>", "message": "<human text>" }` with the specified HTTP status.

### 9.1 Enrollment tokens

- `POST /enrollment-tokens` body `{ name, maxUses (1..1_000_000), expiresAt (≤ now + 365 d), friendlyNameFormat?, config? }` → `201 { token: "<full token>", record: TokenRecord }`; the full token is returned only here.
  `friendlyNameFormat` follows §3, and `config` contributes the product-specific fields in each enrolled device's effective config.
- `GET /enrollment-tokens?pageNumber&pageSize` → page of `TokenRecord`.
- `GET /enrollment-tokens/{id}` → `TokenRecord`; `DELETE /enrollment-tokens/{id}` → `204`.
- `TokenRecord`: `{ id, name, maxUses, usedCount, expiresAt, state: "active"|"exhausted"|"expired", friendlyNameFormat, config, createdAt, createdBy }`.

### 9.2 Devices

- `GET /devices` query: `pageNumber` (≥ 1, default 1), `pageSize` (1..100, default 25), `view=summary|full`, `metadata=k1,k2`, `status=active|revoked|expired`, `enrollmentTokenId`, `issuer=<root thumbprint>`, `lastSeenBefore`, `lastSeenAfter`, `q` (friendly-name substring, case-insensitive).
  Each device receives a strictly increasing creation key when inserted, and listings sort by that key; `created_at` is non-decreasing in this order.
  A page walk returns every device that existed when the walk started at least once, and exactly once when no enrollment overlaps the walk; only a deletion during the walk can make it miss one.
  A device whose enrollment overlaps the walk may be missing from it or make the next page repeat one entry; clients deduplicate by `id`.
  Device IDs remain UUIDs and are not used as the listing sort key.
- Page shape: `{ data: [...], currentPage, pageSize, totalCount, totalPages }`.
- Summary: `{ id, friendlyName, status, connected, lastSeenAt, certificate: { notAfter, issuer } }` plus the requested `metadata` subset.
  `connected` is true while the device has at least one authenticated live stream.
- Full adds `metadata`, `certificates: [{ thumbprint, serialNumber, notBefore, notAfter, issuer, status }]`, `enrollmentToken: { id, name }`, `createdAt`, `revokedAt`, `renewalRequested`.
- Device status is `revoked` after revocation, `expired` when not revoked and no current certificate is unexpired, and `active` otherwise.
- `GET /devices/{id}` → full; `PATCH /devices/{id}` `{ friendlyName }` (1..255) → full.
- `view=full` always includes all metadata; `metadata=k1,k2` only extends `summary`.
- `pageNumber` beyond the last page returns an empty `data` array.
- `POST /devices/{id}/revoke` → `204` (idempotent); `DELETE /devices/{id}` → `204`, or `409` unless revoked.
- `POST /devices/{id}/request-renewal` sets the request-renewal flag, sends `RenewRequested{reason:"admin"}` on each authenticated live stream and returns `202`.

### 9.3 Rotation

- `POST /ca/rotation` `{ deadline? }` → `202 Rotation`; `409` if one is in progress.
- `GET /ca/rotation` → `Rotation`: `{ phase: "idle"|"rotating", oldRoot?: { thumbprint, notAfter }, newRoot?: { thumbprint, notAfter }, deadline?, activeDevicesOnOldRoot }`.
- `activeDevicesOnOldRoot` counts non-revoked devices with an unexpired current or pending certificate issued by the old root.

## 10. Agent local behavior

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
      "metadata_override_path": "C:\\path\\metadata.json",
      "check_in_interval_secs": 5,
      "channel_failure_check_in_after_secs": 3
    }
  }
}
```

The unsupported `__debug__.identity` section provides conformance controls and is honored in every build.
The installer never writes this section, and the agent logs a warning at start-up whenever the section contains a setting.

- `renewal_after_secs`: replaces the scheduled renewal time in §8.1 with the specified number of seconds after the certificate's `notBefore`.
- `disable_jitter`: disables renewal, check-in and retry jitter.
- `backoff_max_secs`: caps identity-operation retry backoff at the specified number of seconds.
- `pending_poll_interval_ms`: replaces the default 5 s pending-directory poll interval (§10.2).
- `check_in_interval_secs` and `channel_failure_check_in_after_secs`: replace the 24 h and 1 h values in §5.6.
  Setting either field disables check-in jitter.
- `key_name_prefix`: replaces the default `DevolutionsAgent-Identity-` key-name prefix (§10.3).
- `metadata_override_path`: path to a JSON object of string values that the agent reads before every enroll, renew, check-in and `Hello`.
  Known keys (§10.5) replace collected values, unknown keys are ignored, and a missing or unreadable file means no override.
- `extra_trusted_root`: path to a PEM file containing one or more certificates that the agent adds to the TLS trust store in addition to the OS roots.
- `acl_grant_current_user` (Windows only): additionally grants the agent process's user access to key-store keys and pending-enrollment files.
  Pending files still use a protected DACL.

- `KeyBackend`: `KeyStore` (Windows default; Microsoft Software KSP, machine key, non-exportable) or `File` (default elsewhere; PKCS#8 `0600`).
- `Identity.Enabled` default `true`: the task is idle without a pending file or stored identity.

### 10.2 Pending-enrollment files

- One file per token, named by the SHA-256 of the full token's UTF-8 bytes in lowercase hexadecimal (`<hex>`):
  - Linux/macOS: `<data-dir>/identity/pending/<hex>.json`, mode `0600`, owned by the account that runs the agent service, with content `{ "version": 1, "token": "<token>" }`.
    The agent does not enforce file ownership.
  - Windows: `<data-dir>\identity\pending\<hex>.dat`, protected DACL granting SYSTEM full control only unless `acl_grant_current_user` is enabled, content = DPAPI `CryptProtectData(json, entropy = "Devolutions.Agent.PendingEnrollment.v1", CRYPTPROTECT_LOCAL_MACHINE)` of the same JSON.
    `.dat` because the content is an opaque DPAPI blob, not JSON.
  - Writing the same token twice (e.g. an Intune re-run) overwrites the same file.
- The service reads the directory at start-up and polls it (default every 5 s).
- Each pending file is independent: its own enrollment key, in-progress record and retry backoff.
  Requests are sent one at a time, and a pending file in transient backoff doesn't block the others.
- The agent retries enrollment, deletes the pending state on success, a permanent token error or a locally malformed token, and keeps it after any other failure.
- Enrollment key:
  - When the agent first processes a pending file, it generates the enrollment key and records `{ "version": 1, "token_sha256": "...", "key_name": "..." }` in `<data-dir>/identity/pending/<hex>.in-progress.json` (written like `identity.json`; no secret).
  - Every retry of that pending file, including after a restart, uses that key, so a lost response is recovered through enroll idempotence (§2).
  - Nothing is discarded before enrollment completes; the authority is only known from the enroll response.
  - On success, the key becomes the new identity's `current` key; the in-progress record is deleted with the pending file.
  - `device_revoked` on enroll is also permanent because the device created by this enrollment was revoked before the agent received the response.
    The agent stores no identity, and recovery requires a different token.
  - Every permanent outcome deletes the pending file, its in-progress record and its enrollment key.
- If a pending token has the same hash as any stored identity, whether active or rejected, the agent deletes the pending state without sending a request.
- The agent enrolls a token with a different hash; on success, the new identity replaces any stored identity for the returned `authority_id`, and the agent deletes the old identity's keys.
  If two pending tokens enroll with the same authority, the last one to complete wins; the other device record stays on the server for the admin to revoke or delete.
- The token is never logged, even partially.

### 10.3 Stored identities

- `<data-dir>/identity/authorities/<authority_id>/identity.json`:

```json
{
  "version": 1,
  "authority_id": "...",
  "device_id": "...",
  "base_url": "https://host/dvls",
  "config": {
    "version": 1,
    "revision": 1,
    "agent_channel_url": "https://host/dvls"
  },
  "token_sha256": "<base64url SHA-256 of the full token's UTF-8 bytes>",
  "rejected": { "code": "device_revoked", "at": "2026-09-24T12:00:00Z" },
  "keys": {
    "current": { "key_name": "...", "certificate_chain": ["..."] },
    "pending": { "key_name": "...", "certificate_chain": ["..."] },
    "previous": { "key_name": "...", "certificate_chain": ["..."] }
  }
}
```

- `rejected` is absent until the server rejects the identity permanently: `device_revoked` or `device_unknown` on any signed request, channel open or live stream, or `certificate_expired` on a renewal beyond grace; `code` is that error code.
  The agent can't observe revocation otherwise.
  Once `rejected` is set, the agent never renews or reconnects for that identity; only a new enrollment with a different token replaces it.
- `pending` and `previous` are optional; `pending.certificate_chain` is absent until renew succeeds; `previous` exists only between a successful `confirm` and the deletion of the old key (crash safety).
- `config` is stored exactly as received, including unknown fields, and replaced only by a higher `revision`.
- Key names have the form `DevolutionsAgent-Identity-<key_uuid>`, where `key_uuid` is a random UUID generated with each key.
  The authority isn't known when the enrollment key is created, and key-store keys can't be renamed.
  The file backend stores `<data-dir>/identity/keys/<key_name>.p8`.
- The agent writes a key's name to its record (`identity.json` or `pending/<hex>.in-progress.json`) before creating the key, and deletes a key before removing its name from the record.
  So a crash never leaves an unrecorded key, and every existing key with the agent's prefix is recorded.
  A recorded key that doesn't exist yet (or anymore) is regenerated or dropped at start-up.
- Writes are atomic (write temp + rename).

### 10.4 CLI

- `devolutions-agent identity enroll <token>` validates the token format, writes the pending file, prints its path and exits with status 0.
  For an invalid token or write failure, it does not report success and exits with a nonzero status.

### 10.5 Metadata sent by the agent

- The agent sends a metadata object (§3) at enroll, at renew, at check-in and in every `Hello`, collected at send time (so it reflects current values).
- Always present, non-empty: `hostname`, `os_name`, `os_version`, `arch`, `agent_version`.
- Present when the OS provides a value: `fqdn`, `domain`, `machine_id`.
- No other keys in V1.
- Values use these stable representations so servers can display and filter them consistently:
  - `hostname`: the OS host name, without domain.
  - `arch`: Rust `std::env::consts::ARCH` naming (`x86_64`, `aarch64`, `x86`).
  - `agent_version`: the agent's own product version string, the same one the binary's version resource and package report.
  - `machine_id`: Windows SMBIOS system UUID, lowercase hyphenated; Linux `/etc/machine-id` as-is; macOS `IOPlatformUUID`, lowercase hyphenated.
- The agent never sends a value that violates §3:
  - It removes C0/C1 control characters and truncates to 1024 UTF-8 bytes on a character boundary.
  - An optional key whose value is empty after that is omitted.
  - A required key that ends up empty gets the value `unknown`.

## 11. Mock server (conformance only)

- The mock independently implements §5, §7 and §9; the channel schema in §7.1 is its only implementation artifact shared with the agent.
- It serves under a configurable path prefix, which the conformance configuration sets to `/mock`.
- The mock-only control API is under `{u}/__mock__/`:
  - `POST faults` accepts `{ drop_next_response?: "enroll"|"renew"|"confirm"|"check-in", clock_skew_secs?, leaf_lifetime_secs?, channel_available?, channel_broken?, rotation_rate_limit_per_sec?, fail_next_response?: { endpoint: "enroll"|"renew"|"confirm"|"check-in", status: <int>, error?: <§5.4 code> } }`.
    - `drop_next_response` processes the next request to that endpoint but drops its response.
    - `clock_skew_secs` offsets the mock's wall clock by the specified number of seconds.
    - `leaf_lifetime_secs` sets the lifetime of subsequently issued leaf certificates.
    - `channel_available: false` makes new enroll responses omit `config.agent_channel_url` and makes channel opens fail with `UNAVAILABLE`.
      Changing `channel_available` bumps every device's config revision, adds or removes the URL, and pushes `ConfigUpdate` on live streams.
    - `channel_broken: true` makes channel opens fail with `UNAVAILABLE` without changing device config.
    - `rotation_rate_limit_per_sec` sets the maximum number of rotation notifications sent per second and defaults to 10.
    - `fail_next_response` returns the specified one-shot failure without processing the request.
      When `error` is present, the response uses the §5.4 body; otherwise its body is empty to exercise the agent's handling of a nonconforming error.
  - `POST config` with `{ "fields": { ... } }` merges fields other than `version`, `revision` and `agent_channel_url` into every device's effective config, increments each revision and pushes `ConfigUpdate` on live streams.
  - `POST reset` clears mutable mock state and restores the default fault settings.
  - `POST time/advance` with `{ secs }` advances mock time and immediately re-evaluates stream expiry and rotation deadlines.
  - `GET events?device_id=<uuid>` returns that device's ordered channel and certificate events: `stream_opened`, `stream_authenticated`, `stream_closed` with status, and `cert_status_changed`.
    Each event has a monotonic sequence number so make-before-break ordering can be verified without polling.
