This is the independent conformance suite for Agent Identity.
Its expectations derive only from these sources, never from the implementation under test:

- [CONTRACT.agent-identity.md](../../docs/agent-identity/CONTRACT.agent-identity.md) and the shared test vectors;
- `agent-channel-proto`;
- DVLS's management API, as `agent-identity-mock` replicates it;
- the agent's CLI, configuration and files, as `devolutions-agent/src/identity/INTENT.md` and `crates/agent-identity/INTENT.md` define them.

The mock implements the contract's agent-facing operations and channel independently of the agent.

## Shape

- A binary with a custom harness, like `proxy-tester`, that exits with a failure status when any test fails.
- Parameters: agent binary path, target (mock or DVLS), and one or more authorities, each with its base URL, management API credentials and what it offers, such as its leaf lifetime and whether it runs a channel.
- Each test declares what it needs from an authority and runs against the first one that offers it; when none does, it reports SKIP naming the missing capability, which counts as a missing fixture, so one run against several differently configured authorities can cover every test.
- When an agent test fails, the suite keeps that test's agent data directory and logs and prints where, because a failure seen only once in a long run against a real authority is otherwise lost.
- Credentials stay out of the suite's output, which lands in CI logs: a usage error never echoes a credential value, and an `--authority` description names the environment variable holding its secret instead of carrying it, so the description itself never holds one.
- Black box on both sides:
  - it drives the real agent binary through a generated configuration, pending-enrollment files, and the `identity enroll` command;
  - it drives the authority through its management API, and the mock also through its control surface.
- Management APIs are product-specific, so the suite reaches each authority's through a module for that authority: DVLS's now, which the mock replicates, and PSU's once its management API is settled.
  Tests never call a management API directly.
- It depends on no agent implementation crate.
- What it observes, in order of preference:
  1. the management API;
  2. the agent's files;
  3. logs, as a last resort.
- Tests that need mock fault injection are N/A when the target is DVLS, as tests its module declares unsupported.
  A run that skips a test for a missing fixture or privilege fails as incomplete unless `--allow-incomplete` is passed, so a partial run never reports success by default.
  N/A is reserved for a test that does not apply to the platform, or that the authority's module declares unsupported, such as an expiry test against an authority that cannot issue short-lived certificates.
- The `testsuite` crate builds the mock and the tester, runs the mock, runs the tester against it, and requires every test to pass.
  No dependency is added to `testsuite` for this.
- The suite must pass on Linux with the file backend, and on Windows with the Windows software provider backend.
- Without an explicit rotation window, the rotation tests ask for a deadline at most 75 % of the leaf lifetime ahead, rounded down and capped at 60 s, so that it falls before the rotation maximum of an authority issuing short-lived leaves; a lifetime too short to leave a whole second needs an explicit window.

## Coverage

- **Tokens:**
  - use cap, including concurrent enrollments;
  - a failed enrollment consumes no use;
  - distinct errors for revoked, exhausted and expired tokens;
  - a lost enrollment response is recoverable with the same token and key, even after the token is exhausted, expired or revoked, and the replay changes nothing;
  - no public key is ever certified twice.
- **Pending-enrollment files:**
  - consumed and deleted on success and on permanent errors, kept on transient ones;
  - a lost response is recovered across an agent restart;
  - the token never appears in logs;
  - the same token again does nothing, even for a rejected identity or after a permanent enrollment outcome;
  - a different token creates a new identity, which replaces the stored identity for that authority;
  - files for different tokens don't block each other.
- **Impersonation:** identity A cannot authenticate as identity B, whether with a leaked token, with its own certificate, with any other certificate issued by the root, or by naming B in its requests.
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
  - a renewal request reaches a connected identity, one that connects later, and one without a channel.
- **Revocation:**
  - closes the stream and blocks renewal;
  - the agent stops reconnecting and renewing;
  - deletion is allowed only for revoked identities, and a deleted identity is unknown.
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
  - identities migrate on connect, on schedule, and through `check-in`;
  - the status counts are correct;
  - the rotation completes at the deadline, or as soon as no active identity remains on the old root;
  - old-root certificates remain renewable afterwards;
  - emergency deadline.
- **Management API:**
  - pagination stays stable during concurrent enrollment;
  - views, filters and bounds;
  - identity statuses, including `grace`;
  - every route requires its permission.
- **Keys:** non-exportable, accessible only to the agent's account and SYSTEM (root on Linux and macOS), and matching the certificate; no key is left orphaned.
- **Multiple authorities:** identities for two authorities coexist, including across agent restarts.
