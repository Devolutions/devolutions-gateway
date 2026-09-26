# Agent Identity in Devolutions Agent

This file covers how Agent Identity surfaces in the agent binary and its installer.
The feature itself is specified in [crates/agent-identity/INTENT.md](../../crates/agent-identity/INTENT.md).

## CLI

- The only command added is `identity enroll <token>`.
  It writes a pending-enrollment file, which the service then consumes.
- The existing `enroll` command belongs to Agent Tunnel and does not change.
- The CLI does not grow beyond what an end user reasonably needs.
  Testability comes from configuration, not from extra commands.

## Configuration

- Agent Identity has its own configuration section.
- Selecting the key backend (Windows key store or file) is a regular option.
- Test-only knobs live exclusively under `__debug__.identity`, as nested fields.
  - Like the agent's other `__debug__` knobs, they are unsupported and honored in every build; writing the configuration already requires administrator rights.
  - The agent logs a warning at start-up when any of them is set.
  - The installer never sets them.
  - The extra trusted root and the key-access grant for the current user exist only for tests; they are never a production trust or custody path.

## Installer

- The token is passed as the `IDENTITY_ENROLLMENT_TOKEN` property, which is hidden so that it never appears in installer logs.
- The MSI writes the protected pending-enrollment file.
  It never enrolls by itself.
- Uninstalling wipes all local identities and their keys, without contacting any authority.
  A major upgrade keeps them.
