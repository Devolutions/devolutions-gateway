# Agent Identity

## Background

Devolutions Agent is installed on user devices.
Agent Identity gives each device a durable identity rooted in an authority: the device enrolls with the authority, which owns a root CA and issues the device an X.509 certificate.
Enrollment must work unattended for N machines from one reusable token, typically through an `msiexec` command deployed with Microsoft Intune.

After enrollment, the agent authenticates to its authority with that identity, renews it automatically, and keeps a bidirectional channel open so that either side can send a message at any time.
The channel is expected to work in typical deployments.
Features that need push, such as PEDM policies, require it.

Agent Identity and Agent Tunnel are distinct trust boundaries.
Agent Tunnel enrolls server endpoints with a Gateway instance, whose root is owned by Gateway.
Agent Identity enrolls user devices with DVLS, whose root is owned by DVLS.
They may share implementation pieces (key generation and custody), not operational behavior.

## Specification

The complete wire-level specification is [CONTRACT.md](../../docs/agent-identity/CONTRACT.md).
[contract.intent.md](../../docs/agent-identity/contract.intent.md) records the decisions it must preserve.
This file, `contract.intent.md` and the intent files of the crates listed below are cumulative.

## Terminology

- **Authority**: a server implementing the contract and owning the root(s) that issue device certificates.
  DVLS is the first authority; PSU will implement the same contract.
  Authorities differ only by base URL.
- **Enrollment token**: a reusable, use-capped, expiring credential that authorizes enrollment and nothing else.
- **Device**: the authority-side record of an enrolled agent, identified by a UUID minted by the authority.
- **Identity**: the agent-side state for one authority: keys, certificate chains, config, base URL, authority ID, and the SHA-256 of the token it was enrolled with.
- **Pending-enrollment file**: a file through which the installer, or the `identity enroll` command, hands a token to the agent service.
- **Agent channel**: the bidirectional gRPC stream between the agent and an authority.

## Scope

V1 covers enrollment, renewal, revocation, root rotation, config delivery, and the agent channel with skeleton messages only.

Non-goals for V1:

- any UI, including generating the install command;
- mTLS, CRL, OCSP;
- an enrollment approval queue;
- PEDM payloads on the agent channel;
- TPM-backed keys;
- migrating Agent Tunnel onto Agent Identity;
- shared or federated roots, or an authority trusting identities issued by another: identities are independent, one per authority;
- de-duplication of reimaged devices;
- un-revocation;
- multi-node DVLS;
- a fallback transport for the agent channel.

## Security invariants

1. The private key is generated on the device and never leaves it.
   Enrollment and renewal carry a PKCS#10 CSR, which is the proof of possession.
2. The authority mints the device UUID.
   Identity is never derived from the enrollment token or from reported metadata.
3. The enrollment token authorizes enrollment only.
   A leaked token can enroll new devices; it must never allow impersonating or altering an existing device.
4. Device requests are authenticated only as specified in [contract.intent.md](../../docs/agent-identity/contract.intent.md) (Device authentication): the authority looks up the certificate it registered for the device, by thumbprint.
   Chain validation alone is not authentication: any certificate the root issued chains successfully.
5. Code downstream of authentication takes an `AuthenticatedDevice` that only the validator can construct.
   No API treats a device ID read from the wire as an identity.
6. Revocation is final.
   It blocks authentication and renewal and closes live streams.
   A revoked device comes back only by enrolling again with a different token, as a new device.
7. Reported metadata is informational (display, friendly-name evaluation).
   It is never used for authorization.
8. TLS server authentication uses the OS trust store, with no additional pinning.
   An authority whose TLS server certificate doesn't validate against it is not supported.
   Identity roots are trusted as received over that TLS connection.
9. An agent channel stream is authenticated only once the device has proven possession of its key for that stream.
   Signed opening headers alone never authenticate a stream: they can be captured by a TLS-terminating proxy, TLS inspection, or a header log.
10. A stream is bound to the certificate that opened it and is closed no later than that certificate's `notAfter`.
11. Enrollment tokens never appear in logs, not even partially.

## Agent-side behavior

### Identities

- The agent holds one identity per authority, keyed by the authority ID returned at enrollment.
  Enrolling with one authority never affects identities held for another.
- Certificate chains are leaf-first and of any length.
  The agent does not assume a number of CA tiers.
- Certificates and chains are stored in the agent data directory, not in a Windows certificate store.
  Private keys stay in their key backend (see `agent-identity-keys`).
- Every key the agent creates is recorded in its state before it is created, so a crash never leaves an orphaned key.
- When the authority rejects an identity (revoked, unknown, or expired beyond the renewal grace window), the agent records the rejection and stops renewing and reconnecting for that authority.
  Only an enrollment with a different token replaces a rejected identity.

### Pending-enrollment files

- One file per token.
  Their location and format are stable and documented, because the conformance tester stands in for the installer through them.
- Written protected: readable only by SYSTEM, with machine-scope DPAPI, on Windows; owner-only elsewhere.
- The service consumes each file and enrolls, retrying on transient errors.
  Each file has its own enrollment key, reused across retries and restarts, so a lost enrollment response is recovered without consuming another use.
- A file is deleted after a successful enrollment or a permanent error, and kept on transient errors.
- If a stored identity was enrolled with the same token (compared by SHA-256), the file is deleted without enrolling, whatever that identity's state.
  Re-running the same install command (Intune re-runs, upgrades) is therefore a no-op.
- A different token always enrolls, as a new device.
  Once its enrollment completes, and the authority is therefore known, its identity replaces the one held for that authority.
  The previous device record is left on the authority.

### Renewal

1. Renewal triggers at 2/3 of the certificate's lifetime plus random jitter, or when the authority requests it.
2. A new key is generated and recorded as `pending` before any request is sent.
3. `renew` is called with the pending key's CSR, signed with the current key.
   Failures are retried with the same CSR.
4. `confirm` is called, signed with the new key.
   It is the only step that makes the new certificate current.
   Until its outcome is known, the agent sends nothing else signed to that authority.
5. The old key is deleted right after `confirm` succeeds.
6. The agent channel is reopened with the new certificate: the new stream is opened before the old one is closed (make before break).

Within one certificate lifetime after expiry (the grace window), an identity still renews with its expired certificate.
Beyond it, only an enrollment with a new token recovers.

### Config

- The authority provides a versioned config for each device, whose revision increases on every change.
  The agent keeps only a newer revision.
- The config decides whether the agent opens an agent channel with that authority, and where.
- With a working agent channel, config changes and renewal requests arrive over the channel.
- Without one, the agent checks in over HTTP at most once a day to report its metadata and fetch its config and any renewal request.
  Nothing else is delivered over HTTP.

## Implementation decisions

- Keys, CSRs and certificates use RustCrypto crates (`p256`, `ecdsa`, `x509-cert`, `der`, `spki`, `pkcs8`, `sha2`).
  `picky` is not used.
- Concerns are split into self-contained crates.
- The channel crates are named `agent-channel-*`, not `agent-identity-*`, because the channel carries more than identity: renewal requests and config now, PEDM policies later.

| Crate | Responsibility |
|---|---|
| `agent-identity` | Token parsing, CSR, per-authority storage, REST client, enrollment, renewal, check-in |
| `agent-identity-keys` | Key custody |
| `agent-identity-httpsig` | RFC 9421 signing profile and tower layer |
| `agent-channel-proto` | Channel contract, for Rust and .NET |
| `agent-channel-client` | Channel client, depends on `agent-channel-proto` |
| `agent-identity-mock` | Mock authority (binary) |
| `agent-identity-conformance` | Conformance tester (binary) |
