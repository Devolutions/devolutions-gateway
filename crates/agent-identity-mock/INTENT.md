This binary is a reference authority for the conformance tester.

## What it implements

- The agent-facing operations and the agent channel, exactly as [CONTRACT.md](../../docs/agent-identity/CONTRACT.md) specifies.
- The DVLS management interface the conformance tester drives, under `{u}/api/v3/agent-identity`, so that the same tests run against the mock and against DVLS:
  - enrollment tokens: create (the full token is returned only then), list, read and delete; tokens are immutable after creation, and a friendly-name format with an unpaired brace or an unknown placeholder is rejected;
  - devices: list with page-number pagination, views, metadata selection and filters, read, rename, revoke, delete (only once revoked), and request renewal;
  - root rotation: start with an optional deadline, and read its status, including the number of non-revoked devices still holding an unexpired current or pending certificate from the old root;
  - every route requires the management permission, and a missing permission is `403`;
  - a device listing walked page by page returns every device that existed when the walk started at least once, and exactly once when no enrollment overlaps the walk;
  - a device is `connected` only while it has a live stream authenticated by its channel proof.
- It serves under a configurable path prefix, to exercise authorities hosted in a virtual directory, and several instances can run side by side to exercise multiple authorities.
- Code downstream of authentication takes an `AuthenticatedDevice` that only the oracle can construct; no handler treats a device ID read from the wire as an identity.

## Independent derivation

- The mock depends on no agent crate other than `agent-channel-proto`.
- It does not reuse the agent's request and response types, or its signing code.
- It verifies signatures and channel proofs with its own oracle, written from the contract, not with the `httpsig` crate the agent signs with.
  A signature-base bug shared by both sides would otherwise pass the suite.
- The oracle is self-contained and LLM-owned: pure functions, no I/O, time passed in, and no dependency on the rest of the mock.
  Humans treat it as a black box; trust in it comes from its narrow API and from the shared test vectors it must pass.

## Mock-only control

A separate, unauthenticated control surface under `{u}/__mock__/` lets the tester:

- drop the next response to an operation after processing its request, or fail it without processing it, either with a contract error body or with an empty body to exercise the agent's handling of a nonconforming error;
- skew the mock's clock, freeze it, or advance it, which immediately re-evaluates stream expiry and rotation deadlines;
- shorten the lifetime of subsequently issued certificates;
- make the channel unavailable, which removes `agent_channel_url` from every device's config and pushes the change, or break it without changing any config;
- set the rotation notification rate;
- inject product-specific config fields into every device's effective config, which bumps revisions and pushes the change;
- reset all mutable state;
- read a device's ordered channel and certificate events, each with a monotonic sequence number, so that make-before-break ordering can be checked without polling.

The control surface may also offer other test-only controls and observations that the tester needs, such as per-operation request counters, pausing the channel handshake or a retry, a redirect target, a server-initiated reconnect, or a stale config.
This control surface is never part of the contract, and its request shapes are documented in the mock's README.
