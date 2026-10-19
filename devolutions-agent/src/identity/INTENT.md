This module owns Agent Identity in the agent binary: the identity service task, the `identity` command and the `Identity` and `__debug__.identity` configuration are all defined here.
The agent's generic command-line and configuration modules only route to them, so that every change to Agent Identity in the agent binary happens in this directory, under this intent.

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

- Agent Identity has its own section in `agent.json`: `"Identity": { "Enabled": true, "KeyBackend": "WindowsSoftwareProvider" }`.
  - `Enabled` defaults to `true`; the task is idle without a pending-enrollment file or a stored identity.
  - `KeyBackend` is a regular option that names a device-key backend by its technology: `WindowsSoftwareProvider` (the Windows default) or `File` (the default elsewhere); `Tpm` is added later.
    The agent reads every value on every platform; a backend that can't exist on the platform, or isn't available on the machine, is reported through the device-key crate's distinguishable error and stops the identity feature, as `crates/agent-identity/INTENT.md` specifies.
- Test-only knobs live exclusively under `__debug__.identity`, as nested fields.
  - Like the agent's other `__debug__` knobs, they are unsupported and honored in every build; writing the configuration already requires administrator rights.
  - The agent logs a warning at start-up whenever the section contains a setting.
  - The installer never sets them.
  - The extra trusted root and the access grant for the current user exist only for tests; they are never a production trust or custody path.
- The knobs, which the conformance tester relies on:
  - `renewal_after_secs`: replaces the scheduled renewal time with the specified number of seconds after the certificate's `notBefore`.
  - `disable_jitter`: disables renewal, check-in and retry jitter.
  - `backoff_max_secs`: caps identity-operation retry backoff, including `Retry-After`, at the specified number of seconds.
  - `pending_poll_interval_ms`: replaces the default 5 s pending-directory poll interval.
  - `check_in_interval_secs` and `channel_failure_check_in_after_secs`: replace the 24 h and 1 h check-in values; setting either disables check-in jitter.
  - `key_name_prefix`: replaces Agent Identity's `devolutions-agent-identity` key-name prefix, so that a test run creates and finds only its own keys; the value follows the device-key prefix form.
  - `metadata_override_path`: path to a JSON object of string values that the agent reads before every enroll, renew, check-in and `Hello`; known metadata keys replace collected values, unknown keys are ignored, and a missing or unreadable file means no override.
  - `extra_trusted_root`: path to a PEM file with one or more certificates added to the TLS trust store in addition to the OS roots.
  - `acl_grant_current_user` (Windows only): additionally grants the agent process's user access to pending-enrollment files and identity state, which still use a protected DACL.
    It does not concern device keys, whose access rule always grants the caller's account.
