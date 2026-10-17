## Trust and transport

- TLS server authentication uses the OS trust store, with no additional pinning.
  The test-only `__debug__.identity.extra_trusted_root` adds roots for the conformance mock and is never a production trust path.
  An authority whose TLS server certificate doesn't validate against the OS trust store is not supported.
  Identity roots are trusted as received over that TLS connection.
- Identity HTTP requests go through the agent's configured proxy, like the agent's other outbound HTTP, so that a device that reaches its authority only through a proxy can enroll.

## Identities

- The agent holds one identity per authority, keyed by the authority ID returned at enrollment.
  Enrolling with one authority never affects identities held for another.
- Certificates and chains are stored in the agent data directory, not in a Windows certificate store.
  Private keys stay in their key backend (see `agent-identity-keys`).
- When the authority permanently rejects an identity (the terminal outcomes of the contract's error section), the agent records the rejection and never renews or reconnects for that identity again; the agent can't observe revocation any other way.
  Only an enrollment with a different token replaces a rejected identity.

## Local state

The location and format of the files below are stable, because the conformance tester stands in for the installer and observes the agent through them.
`<data-dir>` means the agent's configured data directory.

### Pending-enrollment files

- `<hex>` is the SHA-256 of the full token's UTF-8 bytes encoded as lowercase hexadecimal, and is the only encoding of a token hash the agent stores: file names and every `token_sha256` field use it.
- One file per token, named `<hex>`:
  - Linux and macOS: `<data-dir>/identity/pending/<hex>.json`, mode `0600`, with content `{ "version": 1, "token": "<token>" }`.
    The agent does not enforce the file's owner, and ignores and keeps a file with any group or other permission bit.
  - Windows: `<data-dir>\identity\pending\<hex>.dat`, whose content is DPAPI `CryptProtectData(json, entropy = "Devolutions.Agent.PendingEnrollment.v1", CRYPTPROTECT_LOCAL_MACHINE)` of the same JSON; `.dat` because the content is an opaque blob, not JSON.
    The agent accepts exactly two forms and ignores and keeps any other file:
    - owned by SYSTEM or by the agent's user, with a protected DACL granting full control to SYSTEM only, plus the agent's user under `__debug__.identity.acl_grant_current_user`;
    - owned by a member of Administrators, with the same DACL plus a zero-access OWNER RIGHTS entry, which removes the owner's implicit right to read the file or rewrite its DACL.
  - The Windows `identity\pending` directory is a drop box: protected, SYSTEM full control, and Administrators add-file only, with no list or read access, so an elevated `identity enroll` can submit a token but never read one.
    The service provisions it at start-up.
- Writing the same token again leaves one pending file for that token.
- The service reads the directory at start-up and polls it, by default every 5 s.
- Each pending file is independent: its own enrollment key, in-progress record and retry backoff.
  Requests are sent one at a time, and a file in transient backoff doesn't block the others.
- When the agent first processes a pending file, it generates the enrollment key and records `{ "version": 1, "token_sha256": "<hex>", "key_name": "..." }` in `<data-dir>/identity/pending/<hex>.in-progress.json`.
  Every retry of that file, including after a restart, uses that key, so a lost enrollment response is recovered through the authority's enrollment idempotence.
  Nothing is discarded before enrollment completes, because the authority is known only from the enrollment response.
- Outcomes:
  - On success, the key becomes the new identity's `current` key, and the pending file and in-progress record are deleted.
  - A permanent outcome is a `token_*` error, `device_revoked` (the device this enrollment created was revoked before the agent received the response), or a locally malformed token.
    It deletes the pending file, its in-progress record and its enrollment key, and writes a rejection marker; the agent stores no identity, and recovery requires a different token.
  - A Windows pending file that cannot be decrypted is deleted with an error log and no rejection marker, because the token it holds may be valid; re-running the install command recovers.
  - A pending file in an accepted form whose content the agent cannot use (its name is not the hash of the token it holds, its version is unsupported, its content is not a JSON object, or it is oversized) is deleted with a warning log and no rejection marker.
    Only `identity enroll` writes pending files, so such a file was written by hand and never becomes usable, and a correct file for the same token can still enroll.
  - Any other failure keeps the pending state, and the agent retries.
- A rejection marker is `<data-dir>/identity/rejected/<hex>.json` = `{ "version": 1, "token_sha256": "<hex>", "code": "<code>", "at": "<RFC 3339>" }`, where `code` is the contract error code or `token_malformed`.
  It holds no secret and is never deleted; tokens are immutable at the authority, so a permanent outcome never becomes wrong.
  A marker is written only under the hash of a token read from a file named by that hash.
- If a pending token's hash matches a stored identity, active or rejected, or a rejection marker, the agent deletes the pending state without sending a request.
  Re-running the same install command (Intune re-runs, upgrades) is therefore a no-op.
- A token with a different hash always enrolls, as a new device.
  On success, the new identity replaces any stored identity for the returned `authority_id`, and the agent deletes the old identity's keys.
  If two pending tokens enroll with the same authority, the last one to complete wins; the other device record stays on the authority for an administrator to revoke or delete.

### Stored identities

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
  "token_sha256": "<hex>",
  "rejected": { "code": "device_revoked", "at": "2026-09-24T12:00:00Z" },
  "keys": {
    "current": { "key_name": "...", "certificate_chain": ["..."] },
    "pending": { "key_name": "...", "certificate_chain": ["..."] },
    "previous": { "key_name": "...", "certificate_chain": ["..."] }
  }
}
```

- `rejected` is absent until the authority rejects the identity permanently; `code` is the error code that rejected it.
- `pending` and `previous` are optional; `pending.certificate_chain` is absent until renew succeeds; `previous` exists only between a successful `confirm` and the deletion of the old key, for crash safety.
- `config` is stored as received, including unknown fields, and replaced only by a higher `revision`.
- Key names have the form `DevolutionsAgent-Identity-<key_uuid>`, where `key_uuid` is a random UUID generated with each key.
  The authority isn't known when the enrollment key is created, and key-store keys can't be renamed.
  The file backend stores `<data-dir>/identity/keys/<key_name>.p8`.
- The agent writes a key's name to its record (`identity.json` or the in-progress record) before creating the key, and deletes a key before removing its name from the record.
  A crash therefore never leaves an unrecorded key, and every existing key with the agent's prefix is recorded.
  A recorded key that doesn't exist yet, or anymore, is regenerated or dropped at start-up.
- Writes are atomic: write a temporary file, then rename it.
