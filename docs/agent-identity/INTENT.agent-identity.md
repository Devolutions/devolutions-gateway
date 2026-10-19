## Overview

Devolutions Agent is installed on user devices.
Agent Identity gives a device a durable identity with an authority: the device enrolls with the authority, which owns a root CA and issues the identity an X.509 certificate.
Enrollment must work unattended for N machines from one reusable token, typically through an `msiexec` command deployed with Microsoft Intune.
After enrollment, the agent authenticates to the authority with that identity, renews it automatically, and keeps a bidirectional channel open so that either side can send a message at any time.
Features that need push, such as PEDM policies, require that channel.

`docs/agent-identity/CONTRACT.md` defines what the agent and an authority must agree on, and `docs/agent-identity/test-vectors.json` holds their shared test data.

Agent Tunnel currently has its own enrollment, against a root owned by Gateway.
Later, it is expected to move onto Agent Identity, and its current enrollment to be deprecated:

- DVLS registers each identity's certificate thumbprint with the Gateway, and keeps it current on every renewal, revocation and deletion;
- DVLS delivers the Gateway URL through the identity's config;
- the agent authenticates to the Gateway over mTLS with the device key of its identity; Agent Tunnel's existing keys are not imported.

A relying party such as the Gateway never accepts the request authentication or channel proofs the agent sends to its authority.
It authenticates the device with a protocol bound to itself, so that neither side can relay the other's authentication.

The design must not preclude this migration.

## Terminology

- **Authority**: a server implementing the contract and owning the root(s) that issue identity certificates (e.g.: DVLS, PSU).
  Authorities use different base URLs and may provide product-specific configuration and management APIs, but never a product-specific variant of the agent-facing protocol.
  An authority keeps one `authority_id` for its whole life, across restarts, upgrades, nodes, backup restores and disaster recovery; a different `authority_id` is a different authority, because the agent keys its identities by it.
- **Enrollment token**: a reusable, use-capped, expiring credential that authorizes enrollment and nothing else.
- **Device**: a machine where Devolutions Agent is installed (an endpoint).
  A device can hold one identity per authority, for example one with DVLS and one with PSU at the same time.
- **Identity**: the enrollment of one device with one authority: the authority's record, under the UUID the authority mints, and the agent's state for it.
  An identity has one current device key at a time, and each renewal replaces it.
  *Avoid:* "device" for the authority's record.
- **Pending-enrollment file**: a file through which the `identity enroll` command hands a token to the agent service.
- **Agent channel**: the bidirectional gRPC stream between the agent and an authority.

## Scope

Agent Identity covers enrollment, renewal, revocation, root rotation, config delivery, and the agent channel.

Later:

- a UI, including generating the install command;
- CRL and OCSP;
- an enrollment approval queue, if customers ask for one;
- PEDM payloads on the agent channel;
- TPM-backed keys;
- moving Agent Tunnel and other relying parties onto Agent Identity (see Overview).

Not intended:

- mTLS between the agent and the authority (see Request authentication);
- un-revocation, because revocation is final by design;
- a fallback transport for the agent channel: gRPC is the only channel for pushing things, which simplifies the implementation and avoids duplicating logic and transports, at the cost of dropping old setups.

## Security invariants

1. The private key is generated on the device, and the agent never sends or exports it.
   Enrollment and renewal carry a PKCS#10 CSR, which is the proof of possession.
2. The authority mints the identity's UUID and the certificate's subject.
   An identity is never derived from the enrollment token, from reported metadata, or from claims in the CSR, which supplies only a verified public key.
3. The enrollment token authorizes enrollment only.
   A leaked token can enroll new identities; it must never allow impersonating or altering an existing identity.
4. An authority authenticates a request only through a certificate it registered for that identity, looked up by thumbprint, and a signature by that certificate's key.
   The agent never sends its certificate to the authority, and validating a chain is not authentication: any certificate the root issued chains successfully, and a chain says nothing about revocation.
5. Revocation is final by design.
   It blocks authentication and renewal, closes live streams, and never makes an issued public key reusable.
   A device whose identity is revoked comes back only by enrolling again with a different token, as a new identity.
6. Reported metadata is informational (display, friendly-name evaluation).
   It is never used for authorization.
7. An agent channel stream is authenticated only once the device has signed a fresh challenge for that stream.
   Signed opening headers are not tied to one stream and can be captured by a TLS-terminating proxy, TLS inspection or a header log, so they never authenticate a stream on their own.
   No metadata update or server push happens before the challenge succeeds.
8. A stream is bound to the certificate that opened it and is closed no later than that certificate's `notAfter`.
9. Enrollment tokens never appear in logs, not even partially.

## Design choices

### Protocol growth

- The protocol grows through optional fields and payloads that older receivers ignore.
  Authentication data stays strict because accepting extra or missing signed data could weaken verification.

### Enrollment tokens

- Enrollment tokens are opaque and versioned by their prefix.
  The stable prefix makes tokens easy for secret scanners to recognize, and a new prefix lets older agents reject an incompatible format.
- The unsigned bag only tells the agent where to enroll; it never carries anything an authority trusts.
- The secret authenticates the token, and the authority stores only its hash.
- The token is deliberately not a JWT.
  The authority already needs stored state for use limits, deletion and retry recovery, and an unenrolled agent has no authority key with which to verify a signed token.
- Deleting a token keeps a tombstone.
  This lets a device recover a lost enrollment response without allowing the deleted token to create another identity.

### Enrollment

- A lost enrollment response can be recovered by retrying the same token and CSR while the created identity remains non-revoked, even after the token expires, reaches its use limit or is deleted.
  The retry consumes no extra use and changes no identity state because the CSR proves past possession of the key, not current possession.
- The authority creates the friendly name once during enrollment, and later metadata updates never rename the identity.
  The agent never receives the name, because an administrator can rename the identity and the agent's copy would go stale.
  The authority evaluates it from the token's friendly-name format, whose placeholders are `{<known metadata key>}` and `{token_name}`, the enrollment token's name.
  `{{` and `}}` escape braces, and a format with an unpaired brace or an unknown placeholder is rejected when the token is created.
  A missing metadata value evaluates to empty.
  The result is trimmed and truncated to 255 Unicode scalar values, never splitting one, and an empty result falls back to the identity ID.
  The default format is `{hostname}`.

### Certificate renewal

- Renewal first creates a pending certificate.
  Confirmation proves that the agent holds the new private key before the certificate becomes current.
- If a confirmation response is lost, the agent cannot know whether the authority promoted the certificate.
  The agent therefore retries confirmation before any other signed operation and can use the pending key to recover if that certificate expires.
- Renewal grace lasts for the authenticating certificate's own lifetime.
  This gives an offline device time to recover without requiring a new enrollment token immediately.

### Configuration and metadata

- `last_seen_at` moves only on actions that prove current possession of the device key; an enrollment replay and a stream closure prove none.
  Creating the identity initializes it; every accepted renew, confirm (including an already-current retry) and check-in, every authenticated `Hello`, and every later agent message on an authenticated stream sets it to the authority's current time.
- Check-in is only a fallback for configuration and renewal requests while no channel is working.
  Features that need server push require the agent channel.

### Errors

- The contract's error section is the only list of error codes, HTTP mappings and retry rules.
  Changing these rules can break compatibility because agents use them to decide whether to retry, discard a pending enrollment or reject a stored identity.

### Request authentication

- Every request to the authority is authenticated with the identity's device key, and that authentication keeps working behind a reverse proxy in front of the authority, including one that terminates TLS or rewrites the host and path, since DVLS often runs behind IIS.
- A captured request authentication can't be replayed: it is single-use per authority and expires quickly.
  Single use across the nodes of a multi-node authority comes later.
- A different key for each authority prevents reuse with another authority, and the operation tag prevents reuse at another endpoint.
- mTLS and TLS channel binding are not used, because a TLS-terminating proxy or IIS in front of the authority breaks them; neither is a bearer token, because a captured one replays.
- The authority records a nonce only after the request signature and any body digest are valid.
  Requests with an invalid signature or body digest therefore cannot consume nonce storage.
- The authority keeps each accepted nonce until 60 s after its signature expires, the last moment the freshness window could accept the same signature again.
- Published trust anchors help third parties validate certificate chains, but they carry no revocation information.

### Agent channel

- `Hello` and `Welcome` reconcile state after each connection.
  Push messages are only an optimization.
- Protecting against an active intermediary that can decrypt the TLS connection and relay or alter its traffic is not intended, because it would need TLS channel binding, which a TLS-terminating proxy or IIS in front of the authority breaks.

### Root rotation

- Rotation publishes the old and new roots together but destroys the old private key when rotation starts.
  Every new certificate therefore uses the new root immediately.
- Rotation ends when no non-revoked identity holds an unexpired current or pending certificate from the old root, or when its deadline passes.
  Removing the old root from the published trust anchors does not invalidate old-root certificates already registered with the authority.

### Conformance

- Shared positive and negative test vectors keep signature and channel-proof behavior consistent across languages.
- The mock authority and the agent implement the protocol independently and share only the channel schema, so that a misreading of the contract shared by both sides cannot pass the conformance suite.

## Implementation decisions

- Agent Identity crates use RustCrypto for keys, CSRs and certificates for now, and never depend on `picky`, which is a heavy dependency.
  Later, they implement against `picky-crypto`, a thin interface crate whose crypto backend (RustCrypto, ring, aws-lc-rs) can be swapped without changing their code.
- Concerns are split into self-contained crates.
- The channel crates are named `agent-channel-*`, not `agent-identity-*`, because the channel carries more than identity: renewal requests and config now, PEDM policies later.
