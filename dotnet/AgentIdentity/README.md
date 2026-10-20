# Devolutions.AgentIdentity

`Devolutions.AgentIdentity` implements what every Agent Identity authority must do the same way under [CONTRACT.md][contract], so that its hosts, such as DVLS and PSU, cannot drift apart on the protocol that Devolutions Agent speaks.
The contract is `docs/agent-identity/CONTRACT.md` in the [devolutions-gateway repository][repo], which also holds this library.

## What the library covers

- Enrollment tokens: `EnrollmentToken.Create` creates a token, `FriendlyNameFormat` parses and evaluates its friendly-name format, and `EnrollmentAuthorization.ReadBearerToken` reads it from an `enroll` request.
  The host stores the token's `SecretHash`, never its `Value`, which it shows once and never logs.
- Request authentication: `RequestAuthenticator` verifies the signed `renew`, `confirm` and `check-in` requests and the signed opening of an agent channel stream (CONTRACT.md [§6]).
- Request bodies: `EnrollRequestBody`, `RenewRequestBody` and `CheckInRequestBody` parse a body and validate its CSR (`CertificateSigningRequest`) and metadata (`AgentMetadata`).
- Decisions: `EnrollmentRules.Decide` decides an enrollment and `RenewalRules.Decide` a renewal, given the issued certificate that holds the CSR key.
- Certificates: `IdentityCertificateIssuer.Issue` issues the certificate of a new identity, or of the identity that a renew request proved.
- Responses: `IdentityConfig` holds an identity's config, and `ResponseBodies` writes the bodies of the `trust-anchor`, `enroll`, `renew` and `check-in` responses.
- Agent channel: `ChannelOpening` verifies the handshake that authenticates a stream, and `ChannelMessages` builds the `ConfigUpdate`, `RenewRequested` and `Reconnect` messages that the authority pushes.
- Errors: `AgentIdentityError` gives each error its code, HTTP status and message, and writes its JSON body and gRPC exception.
- Encodings: `AgentIdentityProtocol` computes certificate thumbprints and formats timestamps.

The host keeps everything else:

- Storage: identities, certificates and their statuses, the SPKI SHA-256 of every issued key, token hashes and tombstones, accepted nonces, metadata, configs and request-renewal flags.
- Hosting: routes, TLS, the gRPC service and its timers, and when to send each push message.
- Management: tokens, identities and root rotation, and the permissions that guard them.
- The root CA and its private key at rest; the library reaches the key only through `IRootSigner`.

## Host dependencies

The host provides these dependencies, with the guarantees the library relies on:

- `ICertificateRegistry` finds, by thumbprint, a certificate that the authority issued, in any status including `Retired`, or returns null when there is none or its identity was deleted.
  Index certificates by `AgentIdentityProtocol.ComputeThumbprint`, not by the SHA-1 `X509Certificate2.Thumbprint`.
  Each `RegisteredCertificate` holds the DER exactly as issued, and the current `Status` and `IdentityRevoked`, so that a revocation takes effect from the next request.
- `INonceStore.TryRecordAsync` records a `keyid` and `nonce` pair, or returns false when the pair is already recorded, in one atomic operation, and keeps the pair until `retainUntil`.
- `IRootSigner` holds the root that issues new certificates and a `SignatureGenerator` over its private key.
  Its `Certificate` must have a Subject Key Identifier extension, which becomes the Authority Key Identifier of each issued certificate; without one, `IdentityCertificateIssuer.Issue` throws `ArgumentException`.
  Once a root rotation starts, it holds the new root (CONTRACT.md [§8.3]).
- `TimeProvider` is the authority's clock, usually `TimeProvider.System`, which decides signature freshness, certificate validity and handshake deadlines.
  Take the `now` of `EnrollmentRules.Decide` and the `serverTime` of every error from the same clock, since the agent corrects its own clock from `server_time`.
- `RandomNumberGenerator` must be cryptographically secure, such as `RandomNumberGenerator.Create()`, since it supplies channel challenges, token secrets and certificate serial numbers.

`RequestAuthenticator` keeps no state between requests, so one instance can serve them all when its dependencies accept concurrent calls.
Exceptions from the registry and the nonce store propagate to the caller.

## Call order

Each HTTP request goes through the body size check, then authentication, then body parsing, so that the error precedence of CONTRACT.md [§5.4] holds: a body over 64 KiB fails first, and an authentication error wins over an invalid body, CSR or metadata.
When a step fails, answer with the `Error` of its result, as [Errors][errors] describes.

### `trust-anchor`

Answer with `ResponseBodies.TrustAnchor`, given the published roots: one normally, the old and the new during a rotation (CONTRACT.md [§5.1]).

### `enroll`

1. Answer a body longer than `AgentIdentityProtocol.MaxRequestBodyBytes` with `AgentIdentityError.BodyTooLarge`.
2. Pass the `Authorization` field lines, as received, to `EnrollmentAuthorization.ReadBearerToken`.
   Find the stored token by the result's `SecretHash`, deleted tokens included, and answer `AgentIdentityError.From(AgentIdentityErrorCode.TokenInvalid)` when there is none.
3. Parse the body with `EnrollRequestBody.Parse`.
4. Look up `Csr.SubjectPublicKeyInfoSha256` among the keys of every certificate the authority has issued, deleted identities included.
   Describe the match with `IssuedKeyMatch.ForIdentity` or `IssuedKeyMatch.ForDeletedIdentity`, or use null when there is none.
5. Pass the token's `EnrollmentTokenState`, the match and the current time to `EnrollmentRules.Decide`, and act on its `Outcome`:
   - `Reject`: answer with `Error`.
   - `ReturnExistingIdentity`: take identity `ExistingIdentityId`, and change nothing.
   - `CreateIdentity`: mint an identity ID, issue its certificate with `IdentityCertificateIssuer.Issue`, name it with `FriendlyNameFormat.Evaluate`, create its config with `IdentityConfig.Create`, and store it with its metadata and the key's `SubjectPublicKeyInfoSha256`.
     Create the identity and count the token use atomically, as CONTRACT.md [§2.1] requires of concurrent enrollments.
6. Answer with `ResponseBodies.Enroll`, given the authority ID and the identity's ID, current certificate chain, leaf first, and config (CONTRACT.md [§5.2]).

### Signed requests

`renew`, `confirm` and `check-in` start alike:

1. Build a `SignedHttpRequest` from the method, the `Signature-Input`, `Signature` and `Content-Digest` field lines, and the body bytes, all as received.
2. Pass it to `RequestAuthenticator.AuthenticateAsync` with `AgentOperation.Renew`, `AgentOperation.Confirm` or `AgentOperation.CheckIn`.
   It answers a body longer than `AgentIdentityProtocol.MaxRequestBodyBytes` with `AgentIdentityError.BodyTooLarge` before it checks the signature.
3. Parse a `renew` body with `RenewRequestBody.Parse` and a `check-in` body with `CheckInRequestBody.Parse`; a `confirm` body is empty.

Each then acts for the result's `Identity` only.

### `renew`

1. Look up the CSR key as for `enroll`, passing false for `enrolledWithPresentedToken`.
2. Pass `Identity` and the match to `RenewalRules.Decide`, and act on its `Outcome`:
   - `Reject`: answer with `Error`.
   - `ReturnPendingCertificate`: keep the identity's pending certificate, which holds the key.
   - `IssuePendingCertificate`: issue a certificate with the `IdentityCertificateIssuer.Issue` overload that takes the `AuthenticatedIdentity`, and store it as the identity's pending certificate, retiring the previous one.
     Store it atomically, as CONTRACT.md [§2.1] requires of concurrent renewals.
3. Replace the identity's metadata, and answer with `ResponseBodies.Renew`, given the pending certificate's chain (CONTRACT.md [§5.3]).

### `confirm`

When `Identity.CertificateStatus` is `CertificateStatus.Pending`, make the certificate current, retire the previous current certificate, and clear the request-renewal flag if it was set before the certificate was issued (CONTRACT.md [§8.2]).
Then send `ChannelMessages.Reconnect(ReconnectReason.CertificateRotated)` on each stream that the retired certificate opened, and close those streams with `OK` 60 s later (CONTRACT.md [§7.4]).
Answer `204`, also when the certificate was already current (CONTRACT.md [§5.5]).

### `check-in`

Replace the identity's metadata, and answer with `ResponseBodies.CheckIn`, given the identity's config and its request-renewal flag (CONTRACT.md [§5.6], [§8.2]).

### Agent channel

1. Pass the request method and the values of the `signature-input` and `signature` request headers, in received order, to `RequestAuthenticator.AuthenticateChannelOpeningAsync`.
2. Send the result's `Opening.Challenge` as the first message on the stream.
3. Pass the first agent message to `Opening.VerifyHelloAsync`.
   Call `Opening.HelloTimedOut` instead when no message arrives within `ChannelHandshake.HelloTimeout`, when `Opening.CertificateNotAfter` passes first, or when the agent ends the stream without a message.
   The first of these calls ends the handshake, and a second one throws `InvalidOperationException`.
4. On success, replace the identity's metadata with `Metadata`, send `Welcome`, and only then treat the stream as authenticated for `Identity`.
5. Send `ChannelMessages.RenewRequested` if the identity's request-renewal flag is set, and `ChannelMessages.ConfigUpdate` if the `Revision` of its config is higher than `applied_state_versions["config"]` of the `Hello` (CONTRACT.md [§7.3] steps 5 and 7).
6. If `Identity.CertificateStatus` is `CertificateStatus.Retired`, the certificate was retired during the handshake: also send `ChannelMessages.Reconnect(ReconnectReason.CertificateRotated)`, and close the stream with `OK` 60 s later, as for `confirm` (CONTRACT.md [§7.4]).
7. Close the stream no later than `Identity.CertificateNotAfter` with `AgentIdentityErrorCode.CertificateExpired`, and when the identity is revoked with `AgentIdentityErrorCode.IdentityRevoked` (CONTRACT.md [§7.4]).

A channel opening has no body: `VerifyHelloAsync` reads the registry again and checks the certificate's expiry and the deadline before the message and its proof, and the metadata of the `Hello` last, in the order of CONTRACT.md [§7.4] and [§7.3] step 4.

When an identity's config changes, create its `IdentityConfig` again with a higher `Revision`, and send `ChannelMessages.ConfigUpdate` on each authenticated stream of the identity.
`ChannelMessages.RenewRequested` takes `RenewalRequestReason.Rotation` for the notifications of a root rotation (CONTRACT.md [§8.3]), and `RenewalRequestReason.Admin` for an administrator's request.

## Errors

Over HTTP, every non-2xx response under `{u}/api/agent-identity/v1/` must carry an error body, including those of the web framework (CONTRACT.md [§5.4]).
Answer with status `HttpStatusCode`, header `Content-Type: application/json` and body `ToJsonBody(serverTime)`.
For a failure that the library does not report, use `AgentIdentityError.From` with its code, or one of these errors:

| Failure                                  | Error                     |
| ---------------------------------------- | ------------------------- |
| Path that no endpoint serves             | `UnknownRoute`, 404       |
| Method that the endpoint does not accept | `MethodNotAllowed`, 405   |
| Body that the web framework cannot read  | `MalformedBody`, 400      |
| Body larger than 64 KiB                  | `BodyTooLarge`, 413       |
| Unexpected exception                     | `UnexpectedFailure`, 500  |
| Overload or a missing dependency         | `ServiceUnavailable`, 503 |

The library writes no headers, so the host adds `Retry-After` to `ServiceUnavailable` when it sheds load.

Over gRPC, end the call by throwing `ToRpcException(serverTime)`, which carries the status of `ToGrpcStatusCode` and the trailers `error-code` and `server-time` (CONTRACT.md [§7.4]).
For a closure that the host decides, such as a revocation, build the error with `AgentIdentityError.From`.

Log `FailureDetail` beside the error: it names the rule that the request broke and never holds a token or a secret.

## Authenticated identities

Only the signature check, `RequestAuthenticator.AuthenticateAsync`, and the channel handshake, `ChannelOpening.VerifyHelloAsync`, create an `AuthenticatedIdentity`, which has no public constructor.
Code that acts for an identity should take one, so that it acts for the identity a signature proved, never for an identity ID that the agent or a caller sent.
The library does so itself: `RenewalRules.Decide` and the renewal overload of `IdentityCertificateIssuer.Issue` take the renewing `AuthenticatedIdentity`, and throw `ArgumentException` for one authenticated for another operation.
A verified channel opening yields only a `ChannelOpening`, whose identity stays hidden until the agent signs the stream's challenge, since signed opening headers are not tied to one stream and can be captured by a TLS-terminating proxy, TLS inspection or a header log (security invariant 7 of [INTENT.agent-identity.md][invariants]).
For the same reason, `AuthenticateAsync` throws `ArgumentOutOfRangeException` for `AgentOperation.Connect`.

## Build, test and pack

From the repository root, with the .NET 10 SDK:

```powershell
pwsh ./dotnet/AgentIdentity/build.ps1
dotnet test ./dotnet/AgentIdentity/AgentIdentity.sln
```

`build.ps1` builds the library in Release and packs it, with its symbol package, into `dotnet/AgentIdentity/Devolutions.AgentIdentity/bin/Release/`.
The tests also check the library against the shared vectors in `docs/agent-identity/test-vectors.json`.

The package depends on `Devolutions.Agent.Channel`, the gRPC types generated from the channel schema (CONTRACT.md [§7.1]): the handshake takes its `AgentMessage` and returns its `ServerMessage`.
Implement the `AgentChannel` service with that package; a feed that serves this package must serve that one too.

[contract]: ../../docs/agent-identity/CONTRACT.md
[repo]: https://github.com/Devolutions/devolutions-gateway
[§2.1]: ../../docs/agent-identity/CONTRACT.md#21-authority-behavior
[§5.1]: ../../docs/agent-identity/CONTRACT.md#51-get-trust-anchor
[§5.2]: ../../docs/agent-identity/CONTRACT.md#52-post-enroll
[§5.3]: ../../docs/agent-identity/CONTRACT.md#53-post-renew
[§5.4]: ../../docs/agent-identity/CONTRACT.md#agent-identity-errors
[§5.5]: ../../docs/agent-identity/CONTRACT.md#55-post-confirm
[§5.6]: ../../docs/agent-identity/CONTRACT.md#56-post-check-in-http-fallback
[§6]: ../../docs/agent-identity/CONTRACT.md#agent-identity-signatures
[§7.1]: ../../docs/agent-identity/CONTRACT.md#71-service
[§7.3]: ../../docs/agent-identity/CONTRACT.md#73-sequence
[§7.4]: ../../docs/agent-identity/CONTRACT.md#74-termination
[§8.2]: ../../docs/agent-identity/CONTRACT.md#82-server-certificate-state
[§8.3]: ../../docs/agent-identity/CONTRACT.md#83-root-rotation
[invariants]: ../../docs/agent-identity/INTENT.agent-identity.md#security-invariants
[errors]: #errors
