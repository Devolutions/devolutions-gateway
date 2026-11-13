## Trust and transport

- TLS server authentication uses the OS trust store, with no additional pinning.
  A test-only extra trusted root adds roots for the conformance mock and is never a production trust path.
  An authority whose TLS server certificate doesn't validate against the OS trust store is not supported.
  Identity roots are trusted as received over that TLS connection, except as the rule on enrollments for a known authority ID at another base URL requires.
- Identity HTTP requests go through the agent's configured proxy, like the agent's other outbound HTTP, so that a device that reaches its authority only through a proxy can enroll.
  A configured proxy they cannot use, such as one with an unsupported scheme, is a transient error and never a reason to connect directly.
  Windows automatic proxy configuration, a PAC script or WPAD discovery, is not evaluated yet: until it is, the agent connects directly and logs a warning once per run, because such scripts usually send internal authorities direct and refusing would block enrollment on most managed networks.

<a id="identities"></a>

## Identities

- The agent holds one identity per authority, keyed by the authority ID returned at enrollment.
  Enrolling with one authority never affects identities held for another.
- Certificates and chains are stored in the agent data directory, not in a Windows certificate store.
  Private keys stay in the device-key backend that created them, and the agent records that backend with each key and opens each key from it, because the key storage policy can change while a key lives (see `device-key`).
- When the agent needs a device-key backend that is unavailable on the machine, to open a key recorded in it or to create a key in it, it logs an error and raises a system event once per run for each backend and identity or pending file, and never substitutes another backend, because that would silently weaken or change where the device's keys live.
  An identity whose current or pending key is recorded in such a backend, or under a well-formed name (`CONTRACT.agent-identity.md` §5.7) that the agent doesn't know, is left as it is and not used, and the agent checks that backend again on each pending-directory poll; the identity is never recorded as `key_lost`, because the key may still exist there.
  A pending file whose in-progress record names such a backend waits, as after a transient failure.
  A key that can't be created in its backend is retried as after a transient failure.
  One unavailable backend never stops identities whose keys are in another, because without a setting an unavailable backend is a fault local to the keys in it.
- When the authority permanently rejects an identity (the terminal outcomes of the contract's error section), the agent records the rejection and never renews or reconnects for that identity again; the agent can't observe revocation any other way.
  It keeps the identity's keys and slots, so the identity file stays the record of every key it owns, until a new identity replaces it or the agent is uninstalled.
  Only an enrollment with a different token replaces a rejected identity.
- When an identity's current key no longer exists in the backend recorded for it, the agent records the identity as rejected with the code `key_lost` instead of deleting it, so the same token stays a no-op and recovery needs a different token, as after a revocation.

<a id="key-storage"></a>

## Key storage

- Without a key storage policy, or when a policy that isn't required lists no available backend, the agent creates a key in the first available of the Windows software provider, then the file backend, because a Windows software provider key cannot be exported while a key file is protected only by permissions.
  TPM is not in this ranking, so that a TPM key is created only where a policy asks for one, until its rank is decided with TPM-backed keys.
  Every enrollment key is created this way, because the authority's policy is known only from the enrollment response.
- Every other new key of an identity, created at a renewal, at pending-key recovery or to replace an unusable pending key, follows `CONTRACT.agent-identity.md` §5.7 with the policy in the identity's stored config.
- When a renewal is due and the identity's required key storage policy lists no available backend, the agent sends nothing, keeps its current key, and checks again with the transient-failure backoff and whenever it stores a config, so that it renews once a listed backend becomes available or a new config releases it.
- The agent renews an identity without waiting for its schedule or a request when the policy in its stored config is required, the current key's backend is not in its list, and a listed backend is available; it checks this at start-up and whenever it stores a config.
  This renewal waits like any other for the wait between renewals (§Schedules), and first for a renewal jitter drawn uniformly from `[0, 15 min]`, so that a policy change reaching many agents at once doesn't make them all renew at the same moment.
- The agent logs a warning when it treats a malformed policy as absent.

## Schedules

- An identity renews `2/3 × lifetime` after its certificate's anchor, plus a jitter drawn uniformly from `[0, lifetime / 12]`, or as soon as the authority requests a renewal.
  The lifetime is `notAfter − notBefore`; the anchor is the earlier of `notBefore` and the moment the agent stored or loaded the certificate in its current run, so that an authority clock ahead of the agent's doesn't delay renewal.
  That moment is not persisted, so after a restart the anchor uses the load time; it still never passes `notBefore`, and the agent keeps no extra state for a clock skew that only matters until `notBefore` arrives.
  A renewal starts no sooner than 10 minutes after the identity's previous renewal completed in the current run, whether the schedule, the authority or a `certificate_expired` refusal asks for it, so that an authority cannot keep the agent renewing in a tight loop, for example with a certificate whose lifetime is zero; a test-only override of the scheduled renewal time is exempt, and a test-only setting shortens the wait.
- A transient failure is retried after `2^n` seconds for the `n`-th consecutive failure, multiplied by a jitter drawn uniformly from `[0.5, 1.5]`, waiting at least a `Retry-After` delay when the authority sends one, and never longer than 1 h.
  Retry state lives in memory, so a restart retries at once.
- Check-in runs only while the identity has no authenticated stream:
  - without `config.agent_channel_url`, when the identity's runner starts (at service start or after a new enrollment), and then every 24 h ±10%; after a `ConfigUpdate` removes the URL, check-in resumes on the schedule already running;
  - with `config.agent_channel_url` but no stream authenticated for 1 h, counted from the runner's start, from the last check-in or `ConfigUpdate` that added or changed the URL, or from the loss of the last authenticated stream, once, and then every 24 h ±10% until a stream authenticates.

## Local state

The location and format of the files below are stable, because the conformance tester stands in for the installer and observes the agent through them.
`<data-dir>` means the agent's configured data directory.

- The agent provisions its identity directories and, at start-up, resets wrong permissions on them, without changing any authority directory under them.
  An identity directory owned by another account is never repaired, and stops all identity processing until it is fixed, because the account that created it can keep a handle that still changes it after a reset.
- Before it uses stored identities, the agent checks that every `<data-dir>/identity/authorities/<authority_id>/` directory is owned by its account and protected from other users.
  One that fails the check is never repaired, and stops all identity processing until it is fixed, because skipping it would let a local attacker hide or forge an identity, for example hide a rejected identity so that its token enrolls again.
  The running agent repeats the check before every use of its state and on each pending-directory poll, stops every identity and its streams while any directory fails it, and resumes without a restart once all pass.
  A directory passes only if it is owned by the agent's account and is, on Unix, closed to group and other, or on Windows, protected by exactly the DACL the agent provisions; a link, a reparse point, a non-directory and, on a case-insensitive file system, any case variant of its name are all checked.
- An `identity.json` that fails the same check is treated like an untrusted authority directory: never repaired, never read as absent, and it stops all identity processing until it is fixed.
  So is an `identity.json` or in-progress record of the agent's own whose content it can't use, such as one without a required field or with a `key_storage` that isn't a well-formed name, because reading it as absent could enroll its token again as a second identity.
- The agent ignores a rejection marker or in-progress record that it doesn't own or that other users can access, as if it were absent, and never deletes one as cleanup; its own write of that file replaces it.
  Trusting one would let a local attacker reject a token or supply its enrollment key, while an attacker able to write one could delete it anyway, so ignoring it opens nothing new.
- Every state change holds an exclusive lock on the identity directory: the file `<data-dir>/identity/.agent-identity.lock` on Linux and macOS, and on Windows an unshared handle on `<data-dir>/identity` itself; on Windows, a busy lock is retried for 30 s.
- Size limits: a pending file holds at most 16 KiB of plaintext, an in-progress record 16 KiB, `identity.json` 2 MiB, and a rejection marker 1 KiB.

### Pending-enrollment files

- `<hex>` is the SHA-256 of the full token's UTF-8 bytes encoded as lowercase hexadecimal, and is the only encoding of a token hash the agent stores: file names and every `token_sha256` field use it.
- One file per token, named `<hex>`:
  - Linux and macOS: `<data-dir>/identity/pending/<hex>.json`, mode `0600`, with content `{ "version": 1, "token": "<token>" }`.
    The file is owned by the agent's account or root; the agent ignores and keeps a file owned by any other account or with any group or other permission bit.
    The file holds the token in plaintext, protected only by its permissions, until the authority answers; that is accepted.
  - Windows: `<data-dir>\identity\pending\<hex>.dat`, whose content is DPAPI `CryptProtectData(json, entropy = "Devolutions.Agent.PendingEnrollment.v1", CRYPTPROTECT_LOCAL_MACHINE)` of the same JSON; `.dat` because the content is an opaque blob, not JSON.
    The agent accepts exactly two forms and ignores and keeps any other file:
    - owned by SYSTEM or by the agent's user, with a protected DACL granting full control to SYSTEM only, plus the current user under a test-only access grant;
    - owned by a member of Administrators, with the same DACL plus a zero-access OWNER RIGHTS entry, which removes the owner's implicit right to read the file or rewrite its DACL.
  - The Windows `identity\pending` directory is a drop box: protected, SYSTEM full control, and Administrators add-file only, with no list or read access, so an elevated `identity enroll` can submit a token but never read one.
    The service provisions it at start-up.
- Writing the same token again leaves one pending file for that token.
- The service reads the directory at start-up and polls it, by default every 5 s.
- Each pending file is independent: its own enrollment key, in-progress record and retry backoff.
  Requests are sent one at a time, and a file in transient backoff doesn't block the others.
- When the agent first processes a pending file, it generates the enrollment key and records `{ "version": 1, "token_sha256": "<hex>", "key_name": "...", "key_storage": "<name>" }` in `<data-dir>/identity/pending/<hex>.in-progress.json`.
  Every retry of that file, including after a restart, uses that key, so a lost enrollment response is recovered through the authority's enrollment idempotence.
  Nothing is discarded before enrollment completes, because the authority is known only from the enrollment response.
- Outcomes:
  - On success, the key becomes the new identity's `current` key, and the pending file and in-progress record are deleted.
  - A permanent outcome is a `token_*` error, `identity_revoked` (the identity this enrollment created was revoked before the agent received the response), a locally malformed token, or an enrollment the agent refuses for claiming a known authority ID from another base URL.
    It deletes the pending file, its in-progress record and its enrollment key, and writes a rejection marker; the agent stores no identity, and recovery requires a different token.
  - A Windows pending file that cannot be decrypted is deleted with an error log and no rejection marker, because the token it holds may be valid; re-running the install command recovers.
  - A pending file in an accepted form whose content the agent cannot use (its name is not the hash of the token it holds, its version is unsupported, its content is not a JSON object, or it is oversized) is deleted with a warning log and no rejection marker.
    Only `identity enroll` writes pending files, so such a file was written by hand and never becomes usable, and a correct file for the same token can still enroll.
  - Any other failure keeps the pending state, and the agent retries.
- A rejection marker is `<data-dir>/identity/rejected/<hex>.json` = `{ "version": 1, "token_sha256": "<hex>", "code": "<code>", "at": "<RFC 3339>" }`, where `code` is the contract error code or one of the local codes `token_malformed`, `authority_conflict` and `authority_url_mismatch`.
  It holds no secret and is never deleted while the agent stays installed; tokens are immutable at the authority, so a permanent outcome never becomes wrong.
  A marker is written only under the hash of a token read from a file named by that hash.
- If a pending token's hash matches a stored identity, active or rejected, or a rejection marker, the agent deletes the pending state without sending a request.
  Re-running the same install command (Intune re-runs, upgrades) is therefore a no-op.
- A token with a different hash always enrolls, as a new identity.
  On success, the new identity replaces any stored identity for the returned `authority_id`, and the agent deletes the old identity's keys.
  If two pending tokens enroll with the same authority, the last one to complete wins; the other identity stays on the authority for an administrator to revoke or delete.
- When an enrollment returns the ID of an identity the agent holds for a different base URL, the agent accepts it only if a signature path runs from the new leaf, through certificates of the new chain that are CAs (basicConstraints with `cA` set, and `keyCertSign` when they carry key usage), to a root it already holds for that ID; otherwise it refuses the enrollment and keeps the stored identity and its keys.
  The roots it holds for an ID are the last certificates of that identity's current, pending and previous chains, and validity periods are not checked.
  Without this rule, a hostile or compromised authority could claim another authority's ID and take its place on the device; the chain shows the server obtained a certificate from that authority's CA, so a legitimate move to a new base URL keeps working, and requiring CA certificates keeps a device's own certificate and key from standing in for that CA.
  Two gaps are accepted: a move while the device holds only a root from before a rotation, which needs the device's state cleared, and a hostile authority that claims another authority's ID before the real one enrolls, which makes the real enrollment fail loudly.
- Every enrollment's CSR and leaf name the `u` of the token the agent used: the authority refuses a CSR naming another URL, and the agent refuses a certificate naming another URL with marker code `authority_url_mismatch`, so that a server holding another authority's token cannot relay the device's request.

### Stored identities

- `<data-dir>/identity/authorities/<authority_id>/identity.json`:

```json
{
  "version": 1,
  "authority_id": "...",
  "identity_id": "...",
  "base_url": "https://host/dvls",
  "config": {
    "version": 1,
    "revision": 1,
    "agent_channel_url": "https://host/dvls"
  },
  "token_sha256": "<hex>",
  "rejected": { "code": "identity_revoked", "at": "2026-09-24T12:00:00Z" },
  "keys": {
    "current": { "key_name": "...", "key_storage": "file", "certificate_chain": ["..."] },
    "pending": { "key_name": "...", "key_storage": "file", "certificate_chain": ["..."] },
    "previous": { "key_name": "...", "key_storage": "windows_software_provider", "certificate_chain": ["..."] }
  }
}
```

- `rejected` is absent until the authority rejects the identity permanently or its current key is lost; `code` is the error code that rejected it, or `key_lost`.
- `pending` and `previous` are optional; `pending.certificate_chain` is absent until renew succeeds; `previous` exists between a successful `confirm` and the deletion of the old key, for crash safety, and during pending-key recovery, when it holds the expired pending key until the next `confirm` succeeds.
- `key_storage`, required in each key slot and in an in-progress record, names the backend that holds the key, as `CONTRACT.agent-identity.md` §5.7 names it.
- `config` is stored as received, including unknown fields, and replaced only by a higher `revision`.
- `base_url` is the enrollment token's `u` as received, without its trailing slashes, and request paths are joined onto it as text, so that a path prefix reaches the authority byte for byte.
  The stored value and the joined text keep the host's case, its port and percent-encoding as received; the HTTP client may still lowercase the host and drop a default port on the wire, which RFC 9110 §4.2.3 treats as the same origin.
- Key names are device-key names `devolutions-agent-identity_<key_uuid>`: Agent Identity owns the prefix `devolutions-agent-identity`, and `key_uuid` is a random UUID generated with each key, because the authority isn't known when the enrollment key is created.
  The file backend stores `<data-dir>/identity/keys/<key_name>.p8`.
- The agent writes a key's name and backend to its record (`identity.json` or the in-progress record) before creating the key, and deletes a key before removing its name from the record.
  A crash therefore never leaves an unrecorded key, and every existing key with the agent's prefix is recorded with its backend, except the old key of a confirmed renewal whose backend is unavailable: the agent drops its record without opening the key, because keeping the record would hold every later renewal back, and start-up deletes the key once its backend is available again.
  At start-up, a recorded pending or enrollment key that doesn't exist yet in its backend is regenerated there, and a missing current key makes the identity `key_lost`.
- One Devolutions Agent runs per machine, and it owns every device key with its prefix on the machine: at start-up it deletes each one that no `identity.json` or in-progress record names with its backend, in every backend available on the machine.
- During a renewal, the new key is recorded as `pending` before the renew request is sent, and the returned chain is stored on that slot.
  When `confirm` succeeds, `pending` becomes `current` and the old key moves to `previous` until it is deleted.
- During pending-key recovery (contract §8.1), the expired pending key moves to `previous` and the fresh key is recorded as `pending`, so that a restart resumes the recovery from the file.
  The agent keeps the expired pending key and the current key until the fresh pending certificate is confirmed, because either may still have to sign the recovery renewal; once the next `confirm` succeeds, it deletes the expired pending key, then promotes as usual.
  If recovery must start again before a `confirm` succeeds, the newest expired pending key replaces the one in `previous` and the older one is deleted: the server holds the newest as pending or current, whichever state it reached, so it signs the next recovery renewal within grace.
- If a pending key is unusable locally (missing from its recorded backend while that backend is available, refused when opened, or not matching the pending certificate's public key), the agent deletes the key and its slot before renewing with a fresh key.
  A failure to sign is not unusable: it is transient and retried.
- Writes are atomic: write a temporary file, then rename it.
  An interrupted write leaves the previous file and at most a temporary named after it; start-up and reconciliation remove such temporaries, and that cleanup removes only files whose names follow the agent's own scheme for them.
  On Windows, replacing a file that another process holds open, such as an antivirus scanner, is retried for a bounded time before it fails.
