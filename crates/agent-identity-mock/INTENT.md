This binary is a reference authority for the conformance tester.

## What it implements

- The agent-facing operations and the agent channel, exactly as [CONTRACT.agent-identity.md](../../docs/agent-identity/CONTRACT.agent-identity.md) specifies.
- DVLS's management API as it is, so that the same tests run against the mock and against DVLS.
  Its decisions are in DVLS's Agent Identity intent (`docs/agent-identity/INTENT.DVLS.md` until it moves to the RDM repository), and its exact shape is DVLS's OpenAPI document:
  - enrollment tokens: create (the full token is returned only then), list, read and delete; tokens are immutable after creation, and a friendly-name format with an unpaired brace or an unknown placeholder is rejected;
  - identities: list with page-number pagination, views, metadata selection and filters, read, rename, revoke, delete (only once revoked), and request renewal; each identity's status is active, in grace, expired or revoked, as DVLS's intent defines them;
  - root rotation: start with an optional deadline, and read its status, including the number of non-revoked identities still holding an unexpired current or pending certificate from the old root;
  - every route requires DVLS's permission for it (View, Manage, Revoke or Rotate root), and a missing permission is `403`;
  - an identity listing walked page by page returns every identity that existed when the walk started at least once, and exactly once when no enrollment overlaps the walk;
  - an identity is `connected` only while it has a live stream authenticated by its channel proof.
- It serves under a configurable path prefix, to exercise authorities hosted in a virtual directory, and several instances can run side by side to exercise multiple authorities.
- Code downstream of authentication takes an `AuthenticatedIdentity` that only the oracle can construct; no handler treats an `identity_id` read from the wire as authenticated.

## Independent derivation

- The mock depends on no agent crate other than `agent-channel-proto`.
- It does not reuse the agent's request and response types, or its signing code.
- It verifies signatures and channel proofs with its own oracle, written from the contract, not with the `httpsig` crate the agent signs with.
  A signature-base bug shared by both sides would otherwise pass the suite.
- The oracle is a self-contained set of pure functions: no I/O, time passed in, no dependency on the rest of the mock, and it passes the shared test vectors.

## Mock-only control

The mock listens on loopback addresses only, because its control surface is unauthenticated.

On its management API, an application key `<app-key>.<scope>` holds only the permissions its scope names, so the tester can exercise every permission check without provisioning application identities.

A separate, unauthenticated control surface under `{u}/__mock__/` lets the tester:

- drop the next response to an operation after processing its request, or fail it without processing it, either with a contract error body or with an empty body to exercise the agent's handling of a nonconforming error;
- skew the mock's clock, freeze it, or advance it, which immediately re-evaluates stream expiry and rotation deadlines;
- shorten the lifetime of subsequently issued certificates;
- make the channel unavailable, which removes `agent_channel_url` from every identity's config and pushes the change, or break it without changing any config;
- set the rotation notification rate;
- inject product-specific config fields into every identity's effective config, which bumps revisions and pushes the change;
- reset all mutable authority state, keeping management API login sessions so that the tester stays logged in;
- read an identity's ordered channel and certificate events, each with a monotonic sequence number, so that make-before-break ordering can be checked without polling.

The control surface may also offer other test-only controls and observations that the tester needs, such as per-operation request counters, pausing the channel handshake or a retry, a redirect target, a server-initiated reconnect, or a stale config; none of them changes agent-facing protocol behavior.
This control surface is never part of the contract, and its request shapes are documented in the mock's README.
