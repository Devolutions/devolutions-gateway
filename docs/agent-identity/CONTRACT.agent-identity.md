# Agent Identity — Contract

## Parties

This contract defines what two independently built parties must agree on:

- the agent (Devolutions Agent), which enrolls and authenticates;
- an authority (e.g.: DVLS, PSU), which enrolls and authenticates agents.

Third-party relying parties may also read the published roots (§5.1).
Each party's own realization (the agent's local files, configuration and CLI; an authority's storage, administration and hosting) is that party's intent, not contract.

## Definitions

- **Agent**: Devolutions Agent, installed on a device.
- **Authority**: the product server that enrolls and authenticates agents; "server" means the authority unless stated otherwise.
- **Device**: a machine where the agent is installed.
  The agent holds at most one identity per authority, but an authority can hold several identities of one device, for example after a re-enrollment with a different token.
- **Identity**: one device's enrollment with one authority, identified by the `identity_id` the authority mints.
  It has one current certificate and key at a time; renewal replaces them.
  *Avoid:* "device" for an identity.
- **Certificate status**: each certificate the authority issues to an identity is `pending` (issued by renew, not yet confirmed), `current` (the one the identity authenticates with) or `retired` (replaced by a confirmed certificate).
  An identity has at most one `pending` and one `current` certificate.
- **Effective config**: the config the authority holds for an identity at a given moment, with its `revision` (§5.2).
- **Authenticated stream**: an agent channel stream after the authority has verified its channel proof (§7.3 step 4).
- `base64` means standard Base64 (RFC 4648 §4) with padding.
- `base64url` means URL- and filename-safe Base64 alphabet (RFC 4648 §5) without padding.
- SPKI means the DER-encoded X.509 `SubjectPublicKeyInfo` structure.

## 1. Protocol conventions

Unless stated otherwise, implementations must follow these conventions.

- JSON bodies are UTF-8, `Content-Type: application/json`, snake_case keys; enum values are snake_case strings.
- Optional fields are omitted when absent (never write `null`, but accept it).
- Receivers ignore unknown JSON fields unless stated otherwise.
- A JSON request body that repeats a member name at any depth, such as `csr` twice or one metadata key twice, → `invalid_request`, so that no proxy, log or second parser reads a different value than the authority.
- A JSON request body nested more than 64 levels deep, or holding a string that is not valid Unicode, such as an escaped lone surrogate, in any member, including an unknown one → `invalid_request`, for the same reason: parsers disagree on both.
- Timestamps are RFC 3339 UTC strings ending in `Z` (e.g.: `2026-09-24T12:00:00Z`).
- IDs are lowercase hyphenated UUIDs.
- Certificates and CSRs are DER, encoded `base64` in JSON.
- Senders use the canonical form of every `base64` and `base64url` value, so that each byte string has one encoding; a request body holding another form → `invalid_request`.
- A certificate thumbprint is `base64url(SHA-256(certificate DER))`.

<a id="agent-identity-enrollment-token"></a>

## 2. Enrollment token

```
<prefix>.<bag>.<secret>
```

- `prefix`: `dvaet1` = **D**e**v**olutions **A**gent **E**nrollment **T**oken, format version **1**.
  - A complete `dvaet1` token matches `^dvaet1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$`.
  - Agents reject prefixes they do not support.
  - Product-neutral (e.g.: DVLS and PSU use the same prefix).
- `bag`: `base64url` of a UTF-8 JSON object, unsigned and used only for routing.
  The agent ignores unknown fields.
  Fields:
  - `u` (required): absolute `https` product base URL without a query, a fragment or a trailing slash, e.g. `https://host/dvls`; the agent removes trailing slashes from a `u` that has them, so that `https://host/` and `https://host` name the same authority.
- `secret`: `base64url` of 32 random bytes; opaque to the agent beyond this format.
  The authority authenticates a token by its exact `secret` text alone and never checks the `bag`, which carries only routing data.
- Total length ≤ 4096 bytes.
  The agent rejects malformed tokens locally without contacting the server and treats the failure as permanent.

### 2.1 Authority behavior

- A token has a use limit (`max_uses`), an expiry and an optional product-specific contribution to each enrolled identity's config (§5.2).
  None of them changes after creation, and a deleted token is never restored, so the `token_*` outcomes of §5.4 are permanent.
- A token can create an identity only when it exists, has not been deleted, has not expired, and fewer than `max_uses` identities have been created with it.
- Only the creation of a new identity counts toward `max_uses`; an enrollment replay, a failed enrollment, a renewal, a confirmation, a check-in and channel activity never do.
- Re-enrollment with the same token and CSR public key returns the existing identity without counting a use.
- Deleting a token retains its secret hash and `deleted_at` as a tombstone.
  A deleted token authenticates only for an idempotent replay of an identity that it created; every other use returns `token_invalid`, whatever the CSR public key matches.
- When several outcomes apply to one enrollment, the earliest in this list wins: (1) `token_invalid` when the `Authorization` header is missing, repeated, not `Bearer`, or holds no token whose `SHA-256(secret)` matches; (2) `invalid_request` for an invalid body, CSR or metadata; (3) the result of the CSR public key lookup below, except that a deleted token gets `token_invalid` for anything but an idempotent replay; (4) `token_invalid` for a deleted token, then `token_expired` for an expired one; (5) `token_exhausted`; (6) a new identity.
- The server matches the CSR public key against every certificate it has issued using the first matching rule below:
  - The key of the current certificate of a non-revoked identity enrolled with the same token → `200` with that identity and its current chain, without counting a use or changing metadata.
  - The key of a non-deleted identity enrolled with a different token → `invalid_request`; a deleted identity's key falls to the last rule, since the server keeps no token for it.
  - Any certificate key of a revoked identity → `identity_revoked`.
  - The key of a pending or retired certificate of a non-revoked identity → `invalid_request`.
    A public key belongs to exactly one certificate lineage and is never reused.
  - The key of a certificate of a deleted identity → `identity_revoked`.
    The server retains the SPKI SHA-256 and original issuance time of every issued public key after identity deletion; no operation purges these records.
- Servers must preserve these properties under concurrency:
  - Every issued public key is unique by SPKI SHA-256 across current, pending, retired and deleted-identity certificates.
  - Concurrent identity creations never create more than `max_uses` identities with one token.
  - Of two concurrent enrollments with the same CSR key, exactly one creates the identity and the other receives the §2 replay result.
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

### 3.1 Metadata sent by the agent

- The agent sends a metadata object at enroll, at renew, at check-in and in every `Hello`, collected at send time (so it reflects current values).
- Always present, non-empty: `hostname`, `os_name`, `os_version`, `arch`, `agent_version`.
- Present when the OS provides a value: `fqdn`, `domain`, `machine_id`.
- The agent sends no other keys.
- Values use these stable representations so servers can display and filter them consistently:
  - `hostname`: the OS host name, without domain.
  - `arch`: `x86_64`, `aarch64` or `x86`; another architecture reports a lowercase name that the authority treats as opaque.
  - `agent_version`: the agent's own product version string, the same one the binary's version resource and package report.
  - `machine_id`: Windows SMBIOS system UUID, lowercase hyphenated; Linux `/etc/machine-id` as-is; macOS `IOPlatformUUID`, lowercase hyphenated.
- The agent never sends a value that violates §3:
  - It removes C0, DEL and C1 control characters and truncates to 1024 UTF-8 bytes on a character boundary.
  - An optional key whose value is empty after that is omitted.
  - A required key that ends up empty gets the value `unknown`.

## 4. Certificates

- Chains are leaf-first, any length; the agent never assumes a tier count.
- The root profile and the number of CA tiers are each authority's choice.
- Leaf: P-256, `CN=<identity_id>`, SAN URI `urn:uuid:<identity_id>`, EKU clientAuth, KeyUsage digitalSignature; its lifetime is a server setting with a default of 90 days, capped at the issuing root's `notAfter`.
  The leaf carries no other extension except an authority key identifier and a subject key identifier; in particular it carries no basicConstraints, so a leaf can never act as a CA.
- The server ignores the CSR's subject and attributes, including an `extensionRequest` with an empty `Extensions` list, which common CSR builders emit, and it does not require their contents in canonical DER form, such as a sorted `SET OF`, since nothing it decides depends on them; it only takes the public key (an uncompressed P-256 point required, else `invalid_request`, so that each key has exactly one SPKI SHA-256) and verifies the CSR self-signature (else `invalid_request`).
- The CSR signature algorithm is `ecdsa-with-SHA256`; anything else → `invalid_request`.
- The agent's CSR carries an empty attribute set: the `[0]` field RFC 2986 requires is present and empty (`A0 00`), so that a strict PKCS#10 parser accepts it; an empty `extensionRequest` breaks RFC 5280's `SIZE (1..MAX)`.

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
Validating a chain against these roots does not establish that the identity has not been revoked.

### 5.2 `POST enroll`

Request:

```json
{ "csr": "<base64 DER PKCS#10>", "metadata": { "hostname": "..." } }
```

`200` (new identity, or idempotent replay):

```json
{
  "authority_id": "<uuid>",
  "identity_id": "<uuid>",
  "certificate_chain": ["<base64 DER leaf>", "<base64 DER root>"],
  "config": {
    "version": 1,
    "revision": 1,
    "agent_channel_url": "https://host/dvls"
  }
}
```

- Every field is required except `config.agent_channel_url` and product-specific config fields.
- `authority_id` is the authority's UUID; it never changes for that authority, across restarts, upgrades, nodes, backup restores and disaster recovery, and a different `authority_id` denotes a different authority.
- The server generates `identity_id` when it creates the identity, and the ID remains stable for that identity.
- The friendly name is not returned to the agent.
- `config.version` identifies the config schema and is `1`; the agent ignores unknown config fields.
  A config with any other `version` is a transient failure (§5.4), and the agent keeps its stored config.
- `config.revision` is an unsigned 64-bit integer that strictly increases per identity whenever the identity's effective config changes; the agent assumes no starting value or step.
  The agent replaces its stored config only with a higher revision.
  Later revisions are delivered through the agent channel (§7.3) or check-in (§5.6).
- `config.agent_channel_url` is the base URL of the agent channel (§7).
  It is absent when the server does not offer the channel to this identity, and the agent then opens no agent channel for that authority.
  It must be an absolute `https` URL without a query or fragment; an agent receiving any other value treats it as absent and logs a warning.
  Product-specific config fields, such as a PSU channel URL, may coexist with it.
- The agent's identity HTTP client never follows redirects and treats a `3xx` response as transient.
  It validates the server certificate and host name against the OS trust store.

### 5.3 `POST renew`

- Authentication: §6, `tag="renew"`; the request is signed with the current key, except for the pending-key recovery defined in §8.1.
- Request: `{ "csr": "...", "metadata": { ... } }` for the new key.
- `200`: `{ "certificate_chain": [ ... ] }`.
- Every accepted renew request, including an idempotent retry that returns the existing pending chain, replaces the identity's metadata (§3).
- If the CSR key is the key of the identity's pending certificate, the server returns `200` with that pending chain (a retry after a lost response).
- If the CSR key is the key of any other certificate the server has issued, including this identity's current or retired certificates and every certificate of another identity, the server returns `invalid_request`.
- If the CSR key was never issued, the server issues a new pending certificate and retires the identity's previous pending certificate, if any.
- Renew never promotes a certificate; only `confirm` does (§5.5).

<a id="agent-identity-errors"></a>

### 5.4 Errors

Body for every non-2xx response:

```json
{ "error": "<code>", "message": "<human text>", "server_time": "<RFC 3339>" }
```

`server_time` is always present; agents use it only for `clock_skew`.
This body is present on every non-2xx response under `{u}/api/agent-identity/v1/`, including framework-level failures: malformed JSON or body → `400 invalid_request`; unknown route → `404 invalid_request`; wrong method → `405 invalid_request`; body too large → `413 invalid_request`; an unexpected server failure → `500 unavailable`.

| Code                  | HTTP | Meaning                                                                      | Agent class                                       |
| --------------------- | ---- | ---------------------------------------------------------------------------- | ------------------------------------------------- |
| `token_invalid`       | 401  | Unknown or deleted token, bad secret                                         | permanent                                         |
| `token_exhausted`     | 403  | The token has created `max_uses` identities                                  | permanent                                         |
| `token_expired`       | 401  | `now ≥ expires_at`                                                           | permanent                                         |
| `identity_revoked`    | 403  | Identity revoked                                                             | terminal                                          |
| `identity_unknown`    | 401  | Certificate not registered, or identity deleted                              | terminal except during pending-key recovery       |
| `certificate_expired` | 401  | Expired (for `connect`, `confirm`, `check-in`) or beyond grace (for `renew`) | see below                                         |
| `signature_invalid`   | 401  | Bad signature, wrong `tag`, bad digest, replayed nonce, malformed params     | transient                                         |
| `clock_skew`          | 401  | `created`/`expires` outside tolerance                                        | transient, adjust clock                           |
| `invalid_request`     | 400  | Malformed body, CSR or metadata                                              | transient (agent bug; keep retrying with backoff) |
| `unavailable`         | 5xx  | The server can't serve the request now: overloaded, or a part it needs fails | transient                                         |

`token_*` codes are permanent: the agent never retries that token.

A terminal outcome ends the identity for that authority: the agent never renews, checks in or reconnects for it again, and only a new enrollment with a different token replaces it.
`identity_revoked` is terminal.
An `identity_unknown` response to the pending-key renewal used by §8.1 recovery is not terminal; the agent first retries the same renewal with the old current key.
Any other `identity_unknown`, including one returned by that retry, is terminal.

`certificate_expired`:

- On `connect` or `check-in`: the agent renews immediately (§8), signing with the expired certificate, which renew still accepts within its grace; it retries the operation only after `confirm`.
- On `renew`: the certificate is beyond grace.
  It is terminal.
- On `confirm`: see §8.

Any failure not classified above is transient, including an unrecognized or unparseable `4xx`, `429`, any `5xx`, a `3xx`, and network or TLS errors.
A `2xx` response whose body lacks a required field or holds a field outside its domain is also transient, and the agent changes no state for it.
On a transient failure, the agent retries later; when the response carries `Retry-After`, it waits at least that long, up to its own maximum retry delay.
Servers accept request bodies up to 64 KiB on these endpoints; a larger body → `413 invalid_request`.

When several outcomes apply to one request, a body larger than 64 KiB returns `413 invalid_request` first; otherwise an authentication error (§2.1 for enroll, §6 for signed operations) wins over an invalid body, CSR or metadata.

### 5.5 `POST confirm`

- Authentication: §6, `tag="confirm"`, signed with the **pending** certificate's key; the body is empty, and a non-empty body → `invalid_request` with no state change.
- Pending → it becomes `current`, and the previous `current` becomes `retired`; §7.4 specifies what happens to streams opened with the retired certificate.
- Already current → no-op (idempotent retry after a lost response).
- `204` in both cases.
- `confirm` is the only operation that promotes a certificate; renew and channel connect never do.

### 5.6 `POST check-in` (HTTP fallback)

- Authentication: §6, `tag="check-in"`; the agent signs with its current key.
- Request: `{ "metadata": { ... } }` (§3; required).
- The server replaces the identity's metadata (§3).
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

- `config`: the identity's effective config (same shape as in §5.2, with its current `revision`); the agent stores and applies it as for a `ConfigUpdate` (§7.3 step 7).
- `renewal_requested`: the identity's request-renewal flag (§8.2); when `true`, the agent starts a renewal (§8).
- It's the only HTTP fallback: the agent checks in only while it has no authenticated stream for that identity, and with a working channel, config and renewal requests arrive through §7.3.
- Scope: nothing else is delivered over HTTP; features that need push (e.g. PEDM policy) require a working agent channel.

<a id="agent-identity-signatures"></a>

## 6. RFC 9421 profile

- Label `sig`.
- `Signature-Input: sig=(<components>);created=<int>;expires=<int>;nonce="<base64url 16 random bytes>";keyid="<thumbprint>";alg="ecdsa-p256-sha256";tag="<renew|connect|confirm|check-in>"`.
- Signature parameters may appear in any order; each parameter listed above appears exactly once, and no other parameter is allowed.
  A verifier builds `@signature-params` from the received member (RFC 9421 §2.3); the line above shows one order.
- Components: `renew` and `check-in` → `("@method" "content-digest")`; `connect` and `confirm` → `("@method")`.
  A header the operation does not cover, such as `Content-Digest` on `confirm`, is ignored.
- `Content-Digest: sha-256=:<base64>:` (RFC 9530).
- Byte sequences in `Signature` and `Content-Digest` use `base64` with padding, in its canonical form; any other encoding fails step 1 below.
- Signature: ECDSA P-256 over SHA-256 of the signature base, raw 64-byte `r‖s`.
- Agent sets `expires = created + 60`.
- A certificate is unexpired while `now ≤ notAfter`, as in RFC 5280 §4.1.2.5.
  `notBefore` is not checked: the authority issued the certificate itself, so a future `notBefore` only reflects its own clock, and rejecting it would lock devices out over an authority-side fault.
- Each signed operation has exactly one tag, one component list, and one rule for the certificate it accepts:

| Operation       | `tag`      | Covered components             | Accepted certificate                                                                                                   |
| --------------- | ---------- | ------------------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| `renew`         | `renew`    | `("@method" "content-digest")` | `current` or `pending`, unexpired or expired by less than its own lifetime (`now < notAfter + (notAfter − notBefore)`) |
| `confirm`       | `confirm`  | `("@method")`                  | `pending` or `current`, unexpired                                                                                      |
| `check-in`      | `check-in` | `("@method" "content-digest")` | `current` or `pending`, unexpired                                                                                      |
| channel opening | `connect`  | `("@method")`                  | `current` or `pending`, unexpired                                                                                      |

- Server checks; when several fail, the error of the earliest failing step is returned, and step 6 runs only after steps 1–5 pass:
  1. Parse: `Signature-Input` and `Signature` each hold exactly one member, labelled `sig`; exactly the listed parameters, each once, `created` and `expires` as integers and the others as strings; no parameter on the `Signature` member or on a covered component; `keyid` is a thumbprint and `nonce` is `base64url` of 16 bytes, each in its only canonical encoding; canonical `base64`; `alg` matches; the covered components are **exactly** the operation's list in the table, in that order, each once → else `signature_invalid`.
     A malformed `keyid` fails here rather than at step 4, so that an agent bug never draws a terminal `identity_unknown`.
     A verifier never relies on the client-declared list alone: an under-covered request, such as `renew` covering only `@method`, must fail here.
     For `renew` and `check-in`, `Content-Digest` holds exactly one member, `sha-256`, without parameters.
     The verifier detects a repeated parameter, dictionary member or label on the raw field value, since an RFC 8941 parser keeps only the last occurrence.
  2. `tag` matches the operation → else `signature_invalid`.
  3. `0 < expires − created ≤ 300`; `created ≤ now + 60`; `expires ≥ now − 60` → else `clock_skew`.
  4. Resolve `keyid` to a registered certificate with status `current` or `pending` → else `identity_unknown`; identity not revoked → else `identity_revoked`; the certificate meets the operation's rule in the table → else `certificate_expired`.
  5. Verify `content-digest` for `renew` and `check-in`, then verify the signature → else `signature_invalid`.
  6. Accept each `(keyid, nonce)` pair at most once; a pair already accepted → `signature_invalid`.
- Nonces are committed only after the signature verifies (step 6), so garbage requests cannot burn nonces.
- On `clock_skew`, the agent may retry once with `created` offset by `server_time − local_time`, taking `server_time` from the error body (§5.4) or, on a refused channel opening, from the `server-time` trailer (§7.4).
- Implementations must enforce the policy checks above in addition to the RFC validation provided by their signature libraries.

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
2. The server verifies the signature (§6), then sends `Challenge` as its first message, with 32 random bytes fresh for this stream.
3. The agent sends `Hello` with `correlation_id` = Challenge `id` and `proof` = ECDSA P-256 / SHA-256, raw 64-byte `r‖s`, by the same key, over the bytes:
   `"devolutions-agent-identity/v1/channel-proof" ‖ 0x00 ‖ challenge (32 bytes) ‖ connect nonce (UTF-8 bytes of the `nonce` parameter)`.
4. The server verifies `proof` with the public key of the certificate that authenticated the opening request.
   On success it replies `Welcome` (`correlation_id` = Hello `id`), replaces the identity's metadata (§3), and only then treats the stream as authenticated.
   If the first agent message is not a `Hello`, its `correlation_id` is not the Challenge `id`, its proof doesn't verify, or no `Hello` arrives within 10 s, the server closes the stream with `UNAUTHENTICATED` + `error-code: signature_invalid`.
   Otherwise, if the `Hello` metadata violates §3, the server closes the stream with `INVALID_ARGUMENT` + `error-code: invalid_request`.
   Neither failure changes the identity's state.
5. If the request-renewal flag is set, the server sends `RenewRequested` after `Welcome` on every connect until the identity confirms a newer certificate; the agent replies `Ack` (`correlation_id` = message `id`).
6. `Reconnect` asks the agent to open a new stream; the agent opens it, then closes the old one.
   The agent uses the same routine after its own `confirm` succeeds.
7. `Hello.applied_state_versions["config"]` carries the agent's stored `config.revision`.
   If the identity's current revision is higher, the server sends `ConfigUpdate` after `Welcome`.
   When the identity's effective config changes, the server bumps the revision and sends `ConfigUpdate` on the identity's live streams.
   The agent stores it if the revision is higher, replies `Ack` (`correlation_id` = message `id`), and applies it:
   - `agent_channel_url` removed: it closes the stream and stops connecting;
   - `agent_channel_url` changed: it reconnects to the new URL, opening the new stream before closing the old one;
   - `agent_channel_url` added (only reachable through §5.6 check-in): it connects.

- No server push or metadata update happens before step 4 succeeds.
- Envelope `id` values are UUIDs.
- Unknown payloads are ignored.
- Push is an optimization; `Hello`/`Welcome` reconciliation is authoritative.

### 7.4 Termination

- Auth failures at open: gRPC status `UNAUTHENTICATED` (or `PERMISSION_DENIED` for `identity_revoked`) with trailers `error-code: <§5.4 code>` and `server-time: <RFC 3339>`.
- Revocation: the server closes live streams with `PERMISSION_DENIED` + `error-code: identity_revoked`.
- A stream closes no later than its certificate's `notAfter` (`UNAUTHENTICATED` + `certificate_expired`).
- These two closures also apply to a stream still awaiting `Hello`, ahead of the failures of §7.3 step 4: the server closes it at its certificate's `notAfter`, and checks revocation and deletion when `Hello` arrives or the wait times out; an identity revoked and then deleted before that check gets `UNAUTHENTICATED` + `identity_unknown`.
- When `confirm` promotes a pending certificate (§5.5), the previous `current` certificate is retired; its streams get `Reconnect{reason:"certificate_rotated"}` and are closed with `OK` 60 s later if still open.
  A stream whose certificate is retired while it awaits `Hello` still completes the handshake, then gets the same treatment.
- After a stream closes, the agent reconnects unless the identity is terminal (§5.4).

## 8. Renewal and rotation

### 8.1 Agent renewal

1. The agent renews on its own schedule, on `RenewRequested`, and when check-in returns `renewal_requested: true`.
2. `POST renew` with a CSR for a new key, signed with the current key; on failure, retry with the same CSR.
3. `POST confirm` signed with the new key; retry with backoff.
   While the outcome of a `confirm` is unknown, the agent sends no other signed request to that authority and opens no stream; it retries `confirm` first, since `confirm` is idempotent.
4. After `204`, the agent signs with the new key only, and reconnects the agent channel, if any, by opening the new stream before closing the old one.

#### Failure handling

- The agent never checks a certificate's validity itself; it sends the request, and the server's answer decides whether a certificate is unexpired or within grace, because the server's clock is the one that counts.
- On a transient `renew` or `confirm` error, the agent retries with backoff while the old certificate and stream remain in use.
- `certificate_expired` on `confirm` means the pending certificate expired before it was confirmed.
  The agent cannot know whether an earlier `confirm` succeeded after a lost response, so it renews **signed with the pending key**; the server accepts a pending or current certificate within its renewal grace, whichever state it holds.
  - On success, the agent continues at step 3 with the new pending certificate.
  - On `certificate_expired` beyond grace, the identity is terminal (§5.4).
  - On `identity_unknown`, the server holds neither certificate, so the agent retries the same renewal signed with the old current key; `certificate_expired` on that retry is terminal.
- If the agent can't use its pending key, it renews with a fresh key signed by the current certificate.
  Issuing the new pending certificate retires the previous pending certificate as specified in §5.3.
- Otherwise, `identity_revoked` and `identity_unknown` are terminal (§5.4).

### 8.2 Server certificate state

- A `pending` certificate becomes `current` only through `confirm` (§5.5).
- Renewal grace lasts for the certificate's own lifetime, as defined in §6.
- The server sets an identity's request-renewal flag when it wants that identity to renew, for example at an administrator's request or at rotation start (§8.3).
- The request-renewal flag is cleared when the identity confirms a certificate issued after the flag was set.

### 8.3 Root rotation

- The authority starts a rotation and chooses its deadline.
- At rotation start, the server publishes the new root alongside the old root, and every certificate it issues from then on chains to the new root.
- The server sets the request-renewal flag for each non-revoked identity with a current or pending certificate issued by the old root.
  It sends `RenewRequested{reason:"rotation"}` to connected affected identities and continues until every such connected identity has been notified.
  The persistent request-renewal flag covers identities that are disconnected or not yet notified.
- When no non-revoked identity holds an unexpired current or pending certificate issued by the old root, whether at rotation start or later, rotation completes immediately as though its deadline had passed.
- Rotation also completes when its deadline passes.
  Completion removes the old root from `GET trust-anchor`.
- The server continues to recognize registered certificates issued by the old root after completion without requiring that root to remain published.
  The endpoint-specific validity rules still apply, and an identity whose old-root certificate is expired but within renewal grace can renew onto the new root.
