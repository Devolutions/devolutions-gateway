## Overview

Devolutions Agent is installed on user devices.
Agent Identity gives each device a durable identity rooted in an authority: the device enrolls with the authority, which owns a root CA and issues the device an X.509 certificate.
Enrollment must work unattended for N machines from one reusable token, typically through an `msiexec` command deployed with Microsoft Intune.
After enrollment, the agent authenticates to its authority with that identity, renews it automatically, and keeps a bidirectional channel open so that either side can send a message at any time.
Features that need push, such as PEDM policies, require that channel.

`docs/agent-identity/CONTRACT.md` defines what the agent and an authority must agree on, and `docs/agent-identity/test-vectors.json` holds their shared test data.

Agent Tunnel currently has its own enrollment, against a root owned by Gateway.
After V1, it is expected to move onto Agent Identity, and its current enrollment to be deprecated:

- DVLS registers each device's certificate thumbprint with the Gateway, and keeps it current on every renewal, revocation and deletion;
- DVLS delivers the Gateway URL through the device's config;
- the agent authenticates to the Gateway with its Agent Identity, over mTLS.

A relying party such as the Gateway never accepts the RFC 9421 signatures or channel proofs the agent sends to its authority.
It authenticates the device with a protocol bound to itself, so that neither side can relay the other's authentication.

V1 must not preclude this migration.

## Terminology

- **Authority**: a server implementing the contract and owning the root(s) that issue device certificates (e.g.: DVLS, PSU).
  Authorities use different base URLs and may provide product-specific configuration and management APIs, but never a product-specific variant of the agent-facing protocol.
- **Enrollment token**: a reusable, use-capped, expiring credential that authorizes enrollment and nothing else.
- **Device**: the authority-side record of an enrolled agent, identified by a UUID minted by the authority.
- **Identity**: the agent-side state for one authority: keys, certificate chains, config, base URL, authority ID, and the SHA-256 of the token it was enrolled with.
- **Pending-enrollment file**: a file through which the `identity enroll` command hands a token to the agent service.
- **Agent channel**: the bidirectional gRPC stream between the agent and an authority.

## Scope

V1 covers enrollment, renewal, revocation, root rotation, config delivery, and the agent channel with skeleton messages only.

Non-goals for V1:

- any UI, including generating the install command;
- mTLS, CRL, OCSP;
- an enrollment approval queue;
- PEDM payloads on the agent channel;
- TPM-backed keys;
- migrating Agent Tunnel onto Agent Identity, and any other relying party;
- shared or federated roots: identities are independent, one per authority;
- de-duplication of reimaged devices;
- un-revocation;
- a fallback transport for the agent channel.

## Security invariants

1. The private key is generated on the device and never leaves it.
   Enrollment and renewal carry a PKCS#10 CSR, which is the proof of possession.
2. The authority mints the device UUID and the certificate identity.
   Identity is never derived from the enrollment token, from reported metadata, or from claims in the CSR, which supplies only a verified public key.
3. The enrollment token authorizes enrollment only.
   A leaked token can enroll new devices; it must never allow impersonating or altering an existing device.
4. An authority authenticates a device request only through a certificate it registered for that device, looked up by thumbprint, and a signature by that certificate's key.
   The agent never sends its certificate to the authority, and validating a chain is not authentication: any certificate the root issued chains successfully, and a chain says nothing about revocation.
5. Revocation is final.
   It blocks authentication and renewal, closes live streams, and never makes an issued public key reusable.
   A revoked device comes back only by enrolling again with a different token, as a new device.
6. Reported metadata is informational (display, friendly-name evaluation).
   It is never used for authorization.
7. An agent channel stream is authenticated only once the device has signed a fresh challenge for that stream.
   Signed opening headers are not tied to one stream and can be captured by a TLS-terminating proxy, TLS inspection or a header log, so they never authenticate a stream on their own.
   No metadata update or server push happens before the challenge succeeds.
8. A stream is bound to the certificate that opened it and is closed no later than that certificate's `notAfter`.
9. Enrollment tokens never appear in logs, not even partially.

## Design choices

### Protocol growth

- V1 grows through optional fields and payloads that older receivers ignore.
  Authentication data stays strict because accepting extra or missing signed data could weaken verification.

### Enrollment tokens

- Enrollment tokens are opaque and versioned by their prefix.
  The stable prefix makes tokens easy for secret scanners to recognize, and a new prefix lets older agents reject an incompatible format.
- The unsigned bag only tells the agent where to enroll; it never carries anything an authority trusts.
- The token is deliberately not a JWT.
  The authority already needs stored state for use limits, deletion and retry recovery, and an unenrolled agent has no authority key with which to verify a signed token.
- Deleting a token keeps a tombstone.
  This lets a device recover a lost enrollment response without allowing the deleted token to create another device.

### Enrollment

- A lost enrollment response can be recovered by retrying the same token and CSR while the created device remains non-revoked, even after the token expires, reaches its use limit or is deleted.
  The retry consumes no extra use and changes no device state because the CSR proves past possession of the key, not current possession.
- The authority creates the friendly name once during enrollment, and later metadata updates never rename the device.
  The agent never receives the name, because an administrator can rename the device and the agent's copy would go stale.

### Certificate renewal

- Renewal first creates a pending certificate.
  Confirmation proves that the agent holds the new private key before the certificate becomes current.
- If a confirmation response is lost, the agent cannot know whether the authority promoted the certificate.
  The agent therefore retries confirmation before any other signed operation and can use the pending key to recover if that certificate expires.
- Renewal grace lasts for the authenticating certificate's own lifetime.
  This gives an offline device time to recover without requiring a new enrollment token immediately.

### Configuration and metadata

- `last_seen_at` moves only on actions that prove current possession of the device key; an enrollment replay and a stream closure prove none.
- Check-in is only a fallback for configuration and renewal requests while no channel is working.
  Features that need server push require the agent channel.

### Errors

- The contract's error section is the only list of error codes, HTTP mappings and retry rules.
  Changing these rules can break compatibility because agents use them to decide whether to retry, discard a pending enrollment or reject a stored identity.

### Request authentication

- Each signed request covers the required request data, expires quickly and carries a one-time nonce, so it cannot be replayed.
- The host and path are not signed because reverse proxies and IIS virtual directories can rewrite them.
  A different key for each authority prevents reuse with another authority, and the operation tag prevents reuse at another endpoint.
- The authority records a nonce only after the request signature and any body digest are valid.
  Requests with an invalid signature or body digest therefore cannot consume nonce storage.
- Published trust anchors help third parties validate certificate chains, but they carry no revocation information.

### Agent channel

- `Hello` and `Welcome` reconcile state after each connection.
  Push messages are only an optimization.
- V1 does not protect against an active intermediary that can decrypt the TLS connection and relay or alter its traffic.

### Root rotation

- Rotation publishes the old and new roots together but destroys the old private key when rotation starts.
  Every new certificate therefore uses the new root immediately.
- Rotation ends when no non-revoked device holds an unexpired current or pending certificate from the old root, or when its deadline passes.
  Removing the old root from the published trust anchors does not invalidate old-root certificates already registered with the authority.

### Conformance

- Shared positive and negative test vectors keep signature and channel-proof behavior consistent across languages.
- The mock authority and the agent implement the protocol independently and share only the channel schema, so that a misreading of the contract shared by both sides cannot pass the conformance suite.

## Implementation decisions

- Keys, CSRs and certificates use RustCrypto crates (`p256`, `ecdsa`, `x509-cert`, `der`, `spki`, `pkcs8`, `sha2`).
  `picky` is not used.
- Concerns are split into self-contained crates.
- The channel crates are named `agent-channel-*`, not `agent-identity-*`, because the channel carries more than identity: renewal requests and config now, PEDM policies later.

| Crate                        | Responsibility                                                                        |
| ---------------------------- | ------------------------------------------------------------------------------------- |
| `agent-identity`             | Token parsing, CSR, per-authority storage, REST client, enrollment, renewal, check-in |
| `agent-identity-keys`        | Key custody                                                                           |
| `agent-identity-httpsig`     | RFC 9421 signing profile and tower layer                                              |
| `agent-channel-proto`        | Channel schema, for Rust and .NET                                                     |
| `agent-channel-client`       | Channel client, depends on `agent-channel-proto`                                      |
| `agent-identity-mock`        | Mock authority (binary)                                                               |
| `agent-identity-conformance` | Conformance tester (binary)                                                           |
