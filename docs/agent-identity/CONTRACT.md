# Agent Identity — Contract

## History

- v1.0 (2026-09-25) by @CBenoit
- v1.1 (2026-10-17): scoped to the agent–authority interface; the DVLS admin API, the agent's local behavior and the mock server moved to intent files; the channel schema is referenced from `channel.proto`; wording fixes from the contract audit.

## Parties

This contract defines what two independently built parties must agree on:

- the agent (Devolutions Agent), which enrolls and authenticates;
- an authority (e.g.: DVLS, PSU), which enrolls and authenticates agents.

Third-party relying parties may also read the published roots (§5.1).
Each party's own realization (the agent's local files, configuration and CLI; an authority's storage, administration and hosting) is that party's intent, not contract.

## Definitions

- `base64` means standard Base64 (RFC 4648 §4) with padding.
- `base64url` means URL- and filename-safe Base64 alphabet (RFC 4648 §5) without padding.
- An authority is the product server that enrolls and authenticates agents; "server" means the authority unless stated otherwise.
- SPKI means the DER-encoded X.509 `SubjectPublicKeyInfo` structure.

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
- `secret`: `base64url` of 32 random bytes; opaque to the agent beyond this format.
- Total length ≤ 4096 bytes.
  The agent rejects malformed tokens locally without contacting the server and treats the failure as permanent.

### 2.1 Authority behavior

- A token has a name, a use limit (`max_uses`), an expiry, an optional friendly-name format (§3) and an optional product-specific contribution to each enrolled device's config (§5.2).
  None of them changes after creation, and a deleted token is never restored, so the `token_*` outcomes of §5.4 are permanent.
- The server stores only `SHA-256(secret)`.
- A token can create a device only when it exists, has not been deleted, has not expired, and `used_count < max_uses`.
- A token use is consumed in the transaction that creates the device.
- Re-enrollment with the same token and CSR public key returns the existing device without consuming another use.
- Deleting a token retains its secret hash and `deleted_at` as a tombstone.
  A deleted token authenticates only for an idempotent replay of a device that it created; every other use returns `token_invalid`, whatever the CSR public key matches.
- When several outcomes apply to one enrollment, the earliest in this list wins: (1) `token_invalid` when no token matches `SHA-256(secret)`; (2) `invalid_request` for an invalid body, CSR or metadata; (3) the result of the CSR public key lookup below, except that a deleted token gets `token_invalid` for anything but an idempotent replay; (4) `token_invalid` for a deleted token, then `token_expired` for an expired one; (5) `token_exhausted`; (6) a new device.
  The lookup outranks deletion, expiry and exhaustion so that a lost response can be retried with the same token after that token is deleted, expired or exhausted.
- The server matches the CSR public key against every certificate it has issued using the first matching rule below:
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
- Limits: ≤ 32 keys; key matches `^[a-z][a-z0-9_]{0,63}$`; value ≤ 1024 UTF-8 bytes with no C0, DEL (U+007F) or C1 control characters; whole object ≤ 16 KiB, measured as the sum of the UTF-8 byte lengths of all keys and values.
- `metadata` is required in enroll, renew and check-in bodies and may be an empty object; an absent or non-object value → `invalid_request`.
- Anything else (nested values, non-strings, limits exceeded) → `invalid_request`.
- Unknown keys within these limits are stored as-is and never used for authorization.
- The server replaces stored metadata after each successful new enrollment, renewal, check-in or authenticated `Hello`.
  An idempotent enrollment replay does not update metadata.
- `last_seen_at` is the server time of the most recent accepted agent action that establishes or proves possession of the device key.
  Device creation initializes it; accepted renew, confirm and check-in requests, authenticated `Hello` messages and later agent messages on an authenticated stream update it.
  An idempotent enrollment replay and stream closure do not update it.
- Friendly name: evaluated once at enrollment from the token's format.
  Placeholders are `{<known metadata key>}` and `{token_name}`, where `token_name` is the enrollment token's name.
  `{{` and `}}` escape braces; an unpaired brace or unknown placeholder is rejected at token creation.
  Missing metadata values evaluate to empty.
  The result is trimmed and truncated to 255 characters; an empty result falls back to the device ID.
  "Characters" means Unicode scalar values, and truncation never splits one.
  Default format: `{hostname}`.

### 3.1 Metadata sent by the agent

- The agent sends a metadata object at enroll, at renew, at check-in and in every `Hello`, collected at send time (so it reflects current values).
- Always present, non-empty: `hostname`, `os_name`, `os_version`, `arch`, `agent_version`.
- Present when the OS provides a value: `fqdn`, `domain`, `machine_id`.
- No other keys in V1.
- Values use these stable representations so servers can display and filter them consistently:
  - `hostname`: the OS host name, without domain.
  - `arch`: `x86_64`, `aarch64` or `x86`; any other architecture reports its Rust `std::env::consts::ARCH` value.
  - `agent_version`: the agent's own product version string, the same one the binary's version resource and package report.
  - `machine_id`: Windows SMBIOS system UUID, lowercase hyphenated; Linux `/etc/machine-id` as-is; macOS `IOPlatformUUID`, lowercase hyphenated.
- The agent never sends a value that violates §3:
  - It removes C0, DEL and C1 control characters and truncates to 1024 UTF-8 bytes on a character boundary.
  - An optional key whose value is empty after that is omitted.
  - A required key that ends up empty gets the value `unknown`.

## 4. Certificates

- Chains are leaf-first, any length; the agent never assumes a tier count.
- The root profile and the number of CA tiers are each authority's choice.
- Leaf: P-256, `CN=<device_id>`, SAN URI `urn:uuid:<device_id>`, EKU clientAuth, KeyUsage digitalSignature; its lifetime is a server setting with a default of 90 days, capped at the issuing root's `notAfter`.
- The server ignores CSR subject and extensions; it only takes the public key (P-256 required, else `invalid_request`) and verifies the CSR self-signature (else `invalid_request`).
- The CSR signature algorithm is `ecdsa-with-SHA256`; anything else → `invalid_request`.

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

- `authority_id` is stable for a server instance.
- The server generates `device_id` when it creates the device, and the ID remains stable for that device.
- The friendly name (§3) is not returned to the agent.
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
- Every accepted renew request, including an idempotent retry that returns the existing pending chain, replaces the device's metadata (§3).
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
| `device_unknown`      | 401  | Certificate not registered, or device deleted                                | terminal except during pending-key recovery       |
| `certificate_expired` | 401  | Expired (for `connect`, `confirm`, `check-in`) or beyond grace (for `renew`) | see below                                         |
| `signature_invalid`   | 401  | Bad signature, wrong `tag`, bad digest, replayed nonce, malformed params     | transient                                         |
| `clock_skew`          | 401  | `created`/`expires` outside tolerance                                        | transient, adjust clock                           |
| `invalid_request`     | 400  | Malformed body, CSR or metadata                                              | transient (agent bug; keep retrying with backoff) |

`token_*` codes are permanent: the agent never retries that token.

A terminal outcome ends the identity for that authority: the agent never renews, checks in or reconnects for it again, and only a new enrollment with a different token replaces it.
`device_revoked` is terminal.
A `device_unknown` response to the pending-key renewal used by §8.1 recovery is not terminal; the agent first retries the same renewal with the old current key.
Any other `device_unknown`, including one returned by that retry, is terminal.

`certificate_expired`:

- On `connect` or `check-in`: the agent renews immediately (§8), signing with the expired certificate, which renew still accepts within its grace; it retries the operation only after `confirm`.
- On `renew`: the certificate is beyond grace.
  It is terminal.
- On `confirm`: see §8.

Any failure not classified above is transient, including an unrecognized or unparseable `4xx`, `429`, any `5xx`, a `3xx`, and network or TLS errors.
The agent retries transient failures with jittered exponential backoff and honors `Retry-After` when present, up to its maximum retry backoff.
Servers accept request bodies up to 64 KiB on these endpoints; a larger body → `413 invalid_request`.

### 5.5 `POST confirm`

- Signed with the **pending** certificate's key (§6), `tag="confirm"`, components `("@method")`, empty body.
- The signing certificate must be the device's `pending` or `current` certificate and unexpired (no grace), else §6 step 4 errors.
- Pending → it becomes `current`, and the previous `current` becomes `retired`; §7.4 specifies what happens to streams opened with the retired certificate.
- Already current → no-op (idempotent retry after a lost response).
- `204` in both cases.
- `confirm` is the only operation that promotes a certificate; renew and channel connect never do.

### 5.6 `POST check-in` (HTTP fallback)

- Signed with the current key (§6), `tag="check-in"`, components `("@method" "content-digest")`.
- Request: `{ "metadata": { ... } }` (§3; required).
- The signing certificate must be `current` or `pending` and unexpired (no grace).
- The server replaces the device's metadata (§3).
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
- `renewal_requested`: the device's request-renewal flag (§8.2); when `true`, the agent starts a renewal (§8).
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
- Signature parameters may appear in any order; each parameter listed above appears exactly once, and no other parameter is allowed.
  A verifier builds `@signature-params` from the received member (RFC 9421 §2.3); the line above shows one order.
- Components: `renew` and `check-in` → `("@method" "content-digest")`; `connect` and `confirm` → `("@method")`.
- `Content-Digest: sha-256=:<base64>:` (RFC 9530).
- Signature: ECDSA P-256 over SHA-256 of the signature base, raw 64-byte `r‖s`.
- Agent sets `expires = created + 60`.
- Server checks; when several fail, the error of the earliest failing step is returned, and step 6 runs only after steps 1–5 pass:
  1. Parse; exactly one signature labelled `sig`; exactly the listed parameters, each once; `alg` matches; the covered components are **exactly** the tag's list above, in that order, each once → else `signature_invalid`.
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

The gRPC package is `devolutions.agent.channel.v1`, and its schema is [`crates/agent-channel-proto/proto/channel.proto`](../../crates/agent-channel-proto/proto/channel.proto) at this contract's revision.
Every language binding, including the Rust `agent-channel-proto` crate and the .NET `Devolutions.Agent.Channel` package, is generated from that file.
The service is `AgentChannel.Connect`, one bidirectional stream of `AgentMessage` and `ServerMessage` envelopes.

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
   On success it replies `Welcome` (`correlation_id` = Hello `id`), replaces the device's metadata (§3), and only then treats the stream as authenticated.
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

- No server push or metadata update happens before step 4 succeeds.
- Rationale: the header signature isn't bound to the stream; the fresh challenge makes captured opening headers (TLS-terminating proxies, TLS inspection, header logs) insufficient to authenticate a stream.
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
  It stops reconnecting on a terminal outcome (§5.4).

## 8. Renewal and rotation

### 8.1 Agent renewal

1. Trigger at `notBefore + 2/3 × lifetime + jitter` (jitter uniform in `[0, 1/12 × lifetime]`), or on `RenewRequested`.
2. Generate the new key and record it as `pending` before sending any request.
3. `POST renew` with its CSR, signed with the current key; retry with the same CSR on failure.
4. Store the returned chain on the `pending` slot.
5. `POST confirm` signed with the new key; retry with backoff.
   While the outcome of a `confirm` is unknown, the agent sends no other signed request to that authority and opens no stream; it retries `confirm` first, since `confirm` is idempotent.
6. On `204`, `pending` becomes `current`, and the agent deletes the old key.
7. Reconnect the agent channel, if any, with the new certificate by opening the new stream before closing the old one.

#### Failure handling

- On a transient `renew` or `confirm` error, the agent retries with backoff while the old certificate and stream remain in use.
- `certificate_expired` on `confirm` means the pending certificate expired before it was confirmed.
  The agent cannot know whether an earlier `confirm` succeeded after a lost response, so it renews **signed with the pending key**; the server accepts a pending or current certificate within its renewal grace, whichever state it holds.
  - On success, the agent continues at step 4 with the new pending certificate and deletes the previous pending key after the next `confirm` succeeds.
  - On `certificate_expired` beyond grace, the identity is terminal (§5.4).
  - On `device_unknown`, the server holds neither certificate, so the agent retries the same renewal signed with the old current key while that certificate remains within grace.
- If a pending key is unusable locally, the agent deletes the key and its slot, then renews with a fresh key signed by the current certificate while it is valid or within renewal grace.
  Issuing the new pending certificate retires the previous pending certificate as specified in §5.3.
- Otherwise, `device_revoked` and `device_unknown` are terminal (§5.4).

### 8.2 Server certificate state

- The server records each issued device certificate as `pending`, `current` or `retired`.
- A `pending` certificate becomes `current` only through `confirm` (§5.5).
- Renewal grace lasts for the certificate's own lifetime, as defined in §5.3.
- The server sets a device's request-renewal flag when it wants that device to renew, for example at an administrator's request or at rotation start (§8.3).
- The request-renewal flag is cleared when the device confirms a certificate issued after the flag was set.

### 8.3 Root rotation

- The authority starts a rotation and chooses its deadline.
- At rotation start, the server creates and publishes the new root alongside the old root, destroys the old root's private key, and issues every new certificate from the new root.
- The server sets the request-renewal flag for each non-revoked device with a current or pending certificate issued by the old root.
  It sends `RenewRequested{reason:"rotation"}` to connected affected devices at a bounded rate and continues until every such connected device has been notified.
  The persistent request-renewal flag covers devices that are disconnected or not yet notified.
- When no non-revoked device holds an unexpired current or pending certificate issued by the old root, whether at rotation start or later, rotation completes immediately as though its deadline had passed.
  This count cannot increase because all new certificates use the new root and revocation is final.
- Rotation also completes when its deadline passes.
  Completion removes the old root from `GET trust-anchor`.
- The server continues to recognize registered certificates issued by the old root after completion without requiring that root to remain published.
  The endpoint-specific validity rules still apply, and a device whose old-root certificate is expired but within renewal grace can renew onto the new root.
