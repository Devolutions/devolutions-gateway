NOTE: Interim file.
It holds the DVLS-specific material taken out of the Agent Identity contract and intents; it is not merged into master and moves to the DVLS repository.
The agent never depends on anything here.
In this repository, only the mock authority replicates the parts the conformance tester drives, as described in its own intent.

## DVLS as an authority

- DVLS runs a single-tier CA: a P-256 root, valid 10 years, `CN=<product> Agent Identity Root <n>`, created on first use, where `<n>` is the root generation number.
- The root private key is stored encrypted with AES-256-GCM under a key derived by HKDF from the data encryption key; failing to decrypt it is fatal.
- `authority_id` is generated once and stored in the DVLS settings.
- Each issued device certificate is recorded as `pending`, `current` or `retired`.
- DVLS emits `config.agent_channel_url` only when it runs on Kestrel, or IIS in-process on Windows build ≥ 20348 (Server 2022) / ≥ 22000 (Windows 11), and the admin setting "Agent channel enabled" (default on) is not turned off.
  The setting covers reverse proxies that break gRPC.
- The rate at which rotation notifications are sent to connected devices is configurable.
- Multi-node DVLS is not supported by Agent Identity for now.
- Code downstream of authentication takes an `AuthenticatedDevice` that only the request validator can construct.
  No API treats a device ID read from the wire as an identity.

## Admin HTTP API

This API uses camelCase JSON keys and the `pageNumber`/`pageSize` pagination defined under Devices; the protocol conventions of `CONTRACT.md` §1 otherwise apply.

Base: `{u}/api/v3/agent-identity`.
Auth: DVLS session token from application-identity (or user) login, `Authorization: Bearer`.
Every endpoint requires the "Agent identity management" permission, which roles may grant to users and application identities; built-in administrators have it implicitly.
Missing permission → `403`.
Admin error bodies are not standardized; the mock returns `{ "error": "<code>", "message": "<human text>" }` with the specified HTTP status.

### Enrollment tokens

- `POST /enrollment-tokens` body `{ name, maxUses (1..1_000_000), expiresAt (≤ now + 365 d), friendlyNameFormat?, config? }` → `201 { token: "<full token>", record: TokenRecord }`; the full token is returned only here.
  `friendlyNameFormat` follows `CONTRACT.md` §3, and `config` contributes the product-specific fields in each enrolled device's effective config.
  A format with an unpaired brace or an unknown placeholder → `400`.
- `GET /enrollment-tokens?pageNumber&pageSize` → page of `TokenRecord`.
- `GET /enrollment-tokens/{id}` → `TokenRecord`; `DELETE /enrollment-tokens/{id}` → `204`.
- `TokenRecord`: `{ id, name, maxUses, usedCount, expiresAt, state: "active"|"exhausted"|"expired", friendlyNameFormat, config, createdAt, createdBy }`.
- Tokens are immutable after creation; deletion is the only change.

### Devices

- `GET /devices` query: `pageNumber` (≥ 1, default 1), `pageSize` (1..100, default 25), `view=summary|full`, `metadata=k1,k2`, `status=active|revoked|expired`, `enrollmentTokenId`, `issuer=<root thumbprint>`, `lastSeenBefore`, `lastSeenAfter`, `q` (friendly-name substring, case-insensitive).
  Each device receives a strictly increasing creation key when inserted, and listings sort by that key; `created_at` is non-decreasing in this order.
  A page walk returns every device that existed when the walk started at least once, and exactly once when no enrollment overlaps the walk; only a deletion during the walk can make it miss one.
  A device whose enrollment overlaps the walk may be missing from it or make the next page repeat one entry; clients deduplicate by `id`.
  Device IDs remain UUIDs and are not used as the listing sort key.
- Page shape: `{ data: [...], currentPage, pageSize, totalCount, totalPages }`.
- Summary: `{ id, friendlyName, status, connected, lastSeenAt, certificate: { notAfter, issuer } }` plus the requested `metadata` subset.
  `connected` is true while the device has at least one live stream authenticated by its channel proof (`CONTRACT.md` §7.3 step 4); a stream counts only after that step succeeds.
- Full adds `metadata`, `certificates: [{ thumbprint, serialNumber, notBefore, notAfter, issuer, status }]`, `enrollmentToken: { id, name }`, `createdAt`, `revokedAt`, `renewalRequested`.
- Device status is `revoked` after revocation, `expired` when not revoked and no current certificate is unexpired, and `active` otherwise.
- `GET /devices/{id}` → full; `PATCH /devices/{id}` `{ friendlyName }` (1..255 Unicode scalar values) → full.
  The friendly name is readable and renamable only through this API.
- `view=full` always includes all metadata; `metadata=k1,k2` only extends `summary`.
- `pageNumber` beyond the last page returns an empty `data` array.
- `POST /devices/{id}/revoke` → `204` (idempotent); `DELETE /devices/{id}` → `204`, or `409` unless revoked.
- `POST /devices/{id}/request-renewal` sets the request-renewal flag (`CONTRACT.md` §8.2), sends `RenewRequested{reason:"admin"}` on each authenticated live stream and returns `202`.

### Rotation

- `POST /ca/rotation` `{ deadline? }` → `202 Rotation`; `409` if one is in progress.
- The `deadline` is an RFC 3339 timestamp or the literal `"now"`; a value at or before the current time requests an emergency rotation.
  When omitted, it defaults to the rotation maximum.
- The rotation maximum is the latest `notAfter` among unexpired current or pending certificates of non-revoked devices issued by the old root, or the current time when there are none.
  An explicit deadline after this maximum → `400`.
- `GET /ca/rotation` → `Rotation`: `{ phase: "idle"|"rotating", oldRoot?: { thumbprint, notAfter }, newRoot?: { thumbprint, notAfter }, deadline?, activeDevicesOnOldRoot }`.
- `activeDevicesOnOldRoot` counts non-revoked devices with an unexpired current or pending certificate issued by the old root; rotation completes when it reaches 0 (`CONTRACT.md` §8.3).
