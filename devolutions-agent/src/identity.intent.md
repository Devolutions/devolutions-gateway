## CLI

- The only command added is `identity enroll`, with the token as its argument or `-`.
  It validates the token format, writes a pending-enrollment file, which the service then consumes, prints the file's path and exits with status 0.
  For an invalid token or a write failure, it does not report success and exits with a nonzero status.
- `identity enroll -` reads the token from the first line of standard input, so that the token never appears in a process listing or an installer log.
- On Windows, an elevated administrator submits through the service's drop box; until the service has provisioned it, the command fails with an error asking to start the service once, and never creates the directory itself.
- The existing `enroll` command belongs to Agent Tunnel and does not change.
- The CLI does not grow beyond what an end user reasonably needs.
  Testability comes from configuration, not from extra commands.

## Configuration

- Agent Identity has its own section in `agent.json`: `"Identity": { "Enabled": true, "KeyBackend": "KeyStore" }`.
  - `Enabled` defaults to `true`; the task is idle without a pending-enrollment file or a stored identity.
  - `KeyBackend` is a regular option: `KeyStore` (Windows default; Microsoft Software KSP, machine key, non-exportable) or `File` (default elsewhere; PKCS#8 with owner-only permissions).
- Test-only knobs live exclusively under `__debug__.identity`, as nested fields.
  - Like the agent's other `__debug__` knobs, they are unsupported and honored in every build; writing the configuration already requires administrator rights.
  - The agent logs a warning at start-up whenever the section contains a setting.
  - The installer never sets them.
  - The extra trusted root and the key-access grant for the current user exist only for tests; they are never a production trust or custody path.
- The knobs, which the conformance tester relies on:
  - `renewal_after_secs`: replaces the scheduled renewal time with the specified number of seconds after the certificate's `notBefore`.
  - `disable_jitter`: disables renewal, check-in and retry jitter.
  - `backoff_max_secs`: caps identity-operation retry backoff, including `Retry-After`, at the specified number of seconds.
  - `pending_poll_interval_ms`: replaces the default 5 s pending-directory poll interval.
  - `check_in_interval_secs` and `channel_failure_check_in_after_secs`: replace the 24 h and 1 h check-in values; setting either disables check-in jitter.
  - `key_name_prefix`: replaces the default `DevolutionsAgent-Identity-` key-name prefix.
  - `metadata_override_path`: path to a JSON object of string values that the agent reads before every enroll, renew, check-in and `Hello`; known metadata keys replace collected values, unknown keys are ignored, and a missing or unreadable file means no override.
  - `extra_trusted_root`: path to a PEM file with one or more certificates added to the TLS trust store in addition to the OS roots.
  - `acl_grant_current_user` (Windows only): additionally grants the agent process's user access to key-store keys and pending-enrollment files, which still use a protected DACL.

## Installer

- The token is passed as the `IDENTITY_ENROLLMENT_TOKEN` property, which is hidden so that it never appears in installer logs.
- The MSI hands the token to `identity enroll -` running as SYSTEM.
  It never writes the pending-enrollment file itself and never enrolls by itself.
- Uninstalling wipes all local identities and their keys, without contacting any authority.
  A major upgrade keeps them.
