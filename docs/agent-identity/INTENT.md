[CONTRACT.md][contract] defines the protocol, and [test-vectors.json][vectors] contains shared test data.
This file explains the main design choices and the reasons behind them.
It repeats contract details only when needed to explain a design choice.

## Scope

- Authorities use the same agent-facing protocol, each at its own base URL.
  They may still add product-specific configuration and management APIs.
- V1 can grow through optional fields and payloads that older receivers ignore.
  Authentication data stays strict because accepting extra or missing signed data could weaken verification.

## Enrollment tokens

- Enrollment tokens are opaque, and use the versioned format in the [token contract][contract-token].
  The stable prefix makes tokens easy for secret scanners to recognize.
  A new prefix lets older agents reject an incompatible token format.
- The unsigned bag only tells the agent where to enroll.
  The secret authenticates the token, and the authority stores only its hash.
- The token is deliberately not a JWT.
  The authority already needs stored state for use limits, deletion and retry recovery, and an unenrolled agent has no authority key with which to verify a signed token.
- Deleting a token keeps a tombstone.
  This lets a device recover a lost enrollment response without allowing the deleted token to create another device.

## Enrollment

- The authority assigns the authority ID, device ID and certificate identity.
  A CSR supplies a verified public key, but the authority does not trust identity claims from the CSR.
- A token use is consumed only when a device is created, in the same transaction.
- A lost enrollment response can be recovered by retrying the same token and CSR while the created device remains non-revoked, even after the token expires, reaches its use limit or is deleted.
  The retry consumes no extra use and changes no device state because the CSR proves past possession of the key, not current possession.
- An issued public key remains reserved and is never certified again, even after device deletion.
- The authority creates the friendly name once during enrollment.
  The agent never receives it, and later metadata updates never rename the device; only a caller with appropriate permissions can do that.

## Certificate renewal

- Renewal first creates a pending certificate.
  Confirmation proves that the agent holds the new private key before the certificate becomes current.
- Retrying renewal with the same pending key returns the same certificate chain.
  Renewing with another key retires the earlier pending certificate.
- If a confirmation response is lost, the agent cannot know whether the authority promoted the certificate.
  The agent therefore retries confirmation before any other signed operation and can use the pending key to recover if that certificate expires.
- Renewal grace lasts for the authenticating certificate's own lifetime.
  This gives an offline device time to recover without requiring a new enrollment token immediately.
- Revocation is final.
  It closes authenticated streams and does not make issued public keys reusable.

## Configuration and metadata

- Configuration has a schema version and a revision that increases whenever the effective configuration changes.
  The agent keeps unknown fields and accepts only a newer revision.
- A missing `agent_channel_url` means that the authority is not offering a channel to that device.
- Metadata is inventory data collected when the agent sends it.
  A successful enrollment, renewal, check-in or authenticated `Hello` replaces the stored metadata, but an enrollment replay does not.
  Renewal, check-in and authenticated `Hello` also update `last_seen_at` because they prove current possession of the device key.
  Metadata is never used for authorization.
- Check-in is only a fallback for configuration and renewal requests while no channel is working.
  Features that need server push require the agent channel.

## Errors and recovery

- The [error contract][contract-errors] is the only list of error codes, HTTP mappings and retry rules.
  Changing these rules can break compatibility because agents use them to decide whether to retry, discard a pending enrollment or reject a stored identity.
- Permanent token errors end pending enrollment.
  Revocation and renewal beyond grace reject a stored identity.
  `device_unknown` normally rejects the stored identity.
  If it occurs during pending-key recovery, the agent first retries renewal with the key that was current before renewal.
- Every agent-facing HTTP error response contains `server_time`, which the agent may use only for one retry after `clock_skew`.

## Request authentication

- The [RFC 9421 profile][contract-signatures] defines the signed request format and verification order.
  Each signature covers the required request data, expires quickly and includes a one-time value so it cannot be reused.
- The host and path are not signed because reverse proxies and IIS virtual directories can rewrite them.
  A different key for each authority prevents reuse with another authority, and the operation tag prevents reuse at another endpoint.
- The authority records a nonce only after the request signature and any body digest are valid.
  Requests with an invalid signature or body digest therefore cannot consume nonce storage.
- The authority authenticates a device through a registered current or pending certificate and proof of its private key.
  The agent does not send the certificate itself, and validating a certificate chain alone does not prove that the device is still authorized.
- Published trust anchors help third parties validate certificate chains, but they do not include revocation information.

## Agent channel

- The [gRPC schema][contract-channel] defines the agent channel for every language.
- The signed opening request identifies the device key but is not tied to one stream.
  The authority therefore waits for a signature over a fresh challenge before it treats the stream as authenticated.
  Captured opening headers are not enough to authenticate another stream.
- No metadata update, connected state or server push happens before the challenge succeeds.
- `Hello` and `Welcome` reconcile state after each connection.
  Push messages are only an optimization.
- V1 does not protect against an active intermediary that can decrypt the TLS connection and relay or alter its traffic.

## Root rotation

- Rotation publishes the old and new roots together but destroys the old private key when rotation starts.
  Every new certificate therefore uses the new root immediately.
- Affected devices keep a renewal flag until they confirm a new certificate.
  Connected devices also receive rate-limited renewal notifications.
- Rotation ends when `activeDevicesOnOldRoot` reaches zero or the deadline passes.
  Removing the old root from the published trust anchors does not invalidate old-root certificates already registered with the authority.

## Local state

- Pending tokens and private keys use the platform protections defined by the contract, and the agent never logs a full or partial enrollment token.
- Retry state survives restarts and reuses the same enrollment key so server-side retry recovery still works.
- The agent records a key before creating it, deletes a key before removing its record and writes state atomically.
  This ordering prevents a crash from leaving an untracked private key.
- A permanently rejected identity stays inactive until enrollment with a different token replaces it.

## Conformance

- Shared positive and negative test vectors keep signature and channel-proof behavior consistent across languages.
- The mock authority and agent implement the protocol independently and share only the channel schema.
  This prevents shared protocol code from hiding the same defect on both sides.

[contract]: CONTRACT.md
[contract-token]: CONTRACT.md#agent-identity-enrollment-token
[contract-errors]: CONTRACT.md#agent-identity-errors
[contract-signatures]: CONTRACT.md#agent-identity-signatures
[contract-channel]: CONTRACT.md#agent-identity-channel
[vectors]: test-vectors.json
