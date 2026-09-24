# agent-identity-mock

Mock server for the Agent Identity V1 contract (`docs/agent-identity/CONTRACT.md`), used as the conformance oracle.
It implements §2–§9 and §11 in memory, strictly and literally.
It shares only `crates/agent-identity-channel-proto` (the generated gRPC types) with the agent.

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

## Routes

All paths below are relative to `base_url` (i.e. they include the path prefix).

### Agent-facing (CONTRACT.md §5), no admin auth

| Method | Path | Notes |
|---|---|---|
| GET | `/api/agent-identity/v1/trust-anchor` | `{ "roots": [ { "certificate" (base64 DER), "thumbprint", "not_before", "not_after" } ] }`; two roots while a rotation is in progress. |
| POST | `/api/agent-identity/v1/enroll` | `Authorization: Bearer <dvaet1 token>`; body `{ "csr": "<base64 DER PKCS#10>", "metadata"?: {...} }`. |
| POST | `/api/agent-identity/v1/renew` | RFC 9421-signed with `tag="renew"`; `Content-Digest` over the exact body bytes. |

Non-2xx agent-facing responses carry `{ "error", "message", "server_time" }` with the §5.4 codes.
The channel gRPC method is `POST <prefix>/devolutions.agent.identity.channel.v1.AgentChannel/Connect` with `signature-input`/`signature` metadata (`tag="connect"`); open failures are gRPC statuses with an `error-code` trailer (§7.4).

### Admin (CONTRACT.md §9), `Authorization: Bearer <admin-token>`

Missing or invalid admin auth returns 401 `{ "error", "message" }`; all admin errors use that shape with the matching HTTP status.

| Method | Path | Notes |
|---|---|---|
| POST | `/api/v3/agent-identity/enrollment-tokens` | Body `{ name, maxUses (1..1_000_000), expiresAt (RFC 3339, ≤ now+365 d), friendlyNameFormat?, config? }`; 201 → `{ "token": "<full dvaet1 token>", "record": TokenRecord }`; the full token is returned only here. Unknown `friendlyNameFormat` placeholders → 400. |
| GET | `/api/v3/agent-identity/enrollment-tokens` | `pageNumber` (≥ 1, default 1), `pageSize` (1..100, default 25); DVLS page shape `{ data, currentPage, pageSize, totalCount, totalPages }`. |
| GET | `/api/v3/agent-identity/enrollment-tokens/{id}` | `TokenRecord`; 404 when unknown or deleted. |
| DELETE | `/api/v3/agent-identity/enrollment-tokens/{id}` | 204; enrollment with it afterwards yields `token_invalid`. |
| GET | `/api/v3/agent-identity/devices` | Query: `pageNumber`, `pageSize`, `view=summary\|full`, `metadata=k1,k2`, `status=active\|revoked\|expired`, `enrollmentTokenId`, `issuer=<root thumbprint>`, `lastSeenBefore`, `lastSeenAfter`, `q` (case-insensitive friendly-name substring); ordered by `(createdAt, id)`. |
| GET | `/api/v3/agent-identity/devices/{id}` | Full view. |
| PATCH | `/api/v3/agent-identity/devices/{id}` | `{ "friendlyName" }` (1..255 chars) → full view. |
| POST | `/api/v3/agent-identity/devices/{id}/revoke` | 204, idempotent; closes live streams PERMISSION_DENIED + `device_revoked`. |
| DELETE | `/api/v3/agent-identity/devices/{id}` | 204, or 409 unless the device is revoked. |
| POST | `/api/v3/agent-identity/devices/{id}/request-renewal` | 202; sets the flag and pushes `RenewRequested{reason:"admin"}` to live streams. |
| POST | `/api/v3/agent-identity/ca/rotation` | Body `{ "deadline"?: "<RFC 3339>" \| "now" }`; 202 → `Rotation`; 409 while one is in progress. |
| GET | `/api/v3/agent-identity/ca/rotation` | `{ phase: "idle"\|"rotating", oldRoot?, newRoot?, deadline?, activeDevicesOnOldRoot }`. |

### Mock control (CONTRACT.md §11), no auth

| Method | Path | Notes |
|---|---|---|
| POST | `/__mock__/faults` | Merges fields: `{ drop_next_response?: "enroll"\|"renew"\|null, clock_skew_secs?: int\|null, leaf_lifetime_secs?: int\|null, channel_available?: bool, rotation_rate_limit_per_sec?: int\|null }`; absent keys keep their value, `null` clears; responds with the merged faults. `drop_next_response` is one-shot: the next such request is processed and committed, then the connection aborts without a response. |
| POST | `/__mock__/reset` | Clears tokens, devices, nonces, faults, rotation and the clock offset, and creates a fresh root; keeps `authority_id`, the TLS certificate and the admin token; live streams close with `device_unknown`. Responds `{ "authority_id" }`. |
| POST | `/__mock__/time/advance` | `{ "secs": <int> }` moves the mock clock; rotation deadlines are applied lazily on the next request and by a 1 s ticker. Responds `{ "now": <unix>, "server_time": "<RFC 3339>" }`. |

## Tests

`cargo test -p agent-identity-mock` runs the in-crate vector test, which replays every case of `docs/agent-identity/test-vectors.json` through the same verifier, channel-proof and CSR-check functions the server uses.
