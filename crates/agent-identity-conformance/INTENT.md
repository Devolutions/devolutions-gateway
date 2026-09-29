# Agent Identity conformance tester

This is the independent conformance suite for Agent Identity.
Its expectations derive only from these sources, never from the implementation under test:

- [CONTRACT.md](../../docs/agent-identity/CONTRACT.md) and its test vectors;
- `agent-channel-proto`;
- the DVLS admin API;
- the agent's documented CLI, configuration and files.

## Shape

- A binary with a custom harness, like `proxy-tester`, that exits with a failure status when any test fails.
- Parameters: base URL, admin credentials, agent binary path, target (mock or DVLS).
- Black box on both sides:
  - it drives the real agent binary through a generated configuration, pending-enrollment files, and the `identity enroll` command;
  - it drives the authority through its admin API.
- It depends on no agent implementation crate.
- What it observes, in order of preference:
  1. the admin API;
  2. the agent's files;
  3. logs, as a last resort.
- Tests that need mock fault injection are skipped when the target is DVLS.
  A run that skips a test for a missing fixture fails as incomplete, so a partial run never reports success.
- The `testsuite` crate builds the mock and the tester, runs the mock, runs the tester against it, and requires every test to pass.
  No dependency is added to `testsuite` for this.
- The suite must pass on Linux with the file key backend, and on Windows with the Windows key-store backend, against debug and release agent builds.

## Coverage

- **Tokens:**
  - use cap, including concurrent enrollments;
  - a failed enrollment consumes no use;
  - distinct errors for deleted, exhausted and expired tokens;
  - a lost enrollment response is recoverable with the same token and key, even after the token is exhausted, expired or deleted, and the replay changes nothing;
  - no public key is ever certified twice.
- **Pending-enrollment files:**
  - consumed and deleted on success and on permanent errors, kept on transient ones;
  - a lost response is recovered across an agent restart;
  - the token never appears in logs;
  - the same token again does nothing, even for a rejected identity;
  - a different token creates a new device and replaces the local identity;
  - files for different tokens don't block each other.
- **Impersonation:** device A cannot authenticate as device B, whether with a leaked token, with its own certificate, with any other certificate issued by the root, or by naming B in its requests.
- **Replay and signatures:**
  - a reused nonce and an exceeded window are rejected;
  - a signature for one operation is rejected by every other;
  - captured channel opening headers don't open a stream without the key;
  - a request that covers fewer components than the profile requires is rejected.
- **Renewal:**
  - the happy path;
  - lost `renew` and `confirm` responses are retried without lockout;
  - only `confirm` makes the new certificate current, and the old key is deleted right after it;
  - the channel is reopened make before break;
  - renewal within the grace window succeeds, beyond it fails;
  - a pending certificate that expires before `confirm` is recovered;
  - a renewal request reaches a connected device, one that connects later, and one without a channel.
- **Revocation:**
  - closes the stream and blocks renewal;
  - the agent stops reconnecting and renewing;
  - deletion is allowed only for revoked devices, and a deleted device is unknown.
- **Channel:**
  - no stream is authenticated without the proof;
  - `Hello` refreshes metadata and the connected state;
  - no channel when the config has no channel URL.
- **Config:**
  - revisions only increase;
  - changes reach the agent over the channel, and through `check-in` without one;
  - the agent checks in only without a working channel.
- **Rotation:**
  - both roots are published;
  - new certificates come from the new root;
  - devices migrate on connect, on schedule, and through `check-in`;
  - the status counts are correct;
  - the rotation completes at the deadline, or as soon as no active device remains on the old root;
  - old-root certificates remain renewable afterwards;
  - emergency deadline.
- **Admin API:**
  - pagination stays stable during concurrent enrollment;
  - views, filters and bounds;
  - every route requires the admin permission.
- **Keys:** non-exportable, restricted, and matching the certificate on Windows; owner-only files elsewhere; no key is left orphaned.
- **Multiple authorities:** identities for two authorities coexist, including across agent restarts.
