# SSH credential injection through Devolutions Gateway

## Status

This document captures the SSH credential-injection prototype, the verified end-to-end behavior, the target-identity problem, and the proposed RDM-aware production design.

The prototype works end to end with an unmodified native OpenSSH client, `jetsocat`, JMUX, Devolutions Gateway, and a Docker OpenSSH target.

The prototype is not production-ready because it does not yet preserve target host-key verification semantics.

Further SSH work is deferred while PowerShell and VNC credential injection are investigated first.

The prototype is preserved on branch `feat/ssh-credential-injection-poc` for later continuation.

## Problem statement

RDP credential injection already lets a client authenticate to Gateway with a proxy credential while Gateway authenticates to the target with a separate target credential.

We want the equivalent behavior for SSH without modifying the SSH client or the target SSH server.

The SSH client must behave as if it is connecting to a normal SSH server.

RDM must retain ownership of target host-key trust decisions and user-facing fingerprint confirmation.

Gateway must enforce the RDM decision before it sends the target credential.

## Terminology

The **proxy credential** is the credential known to the SSH client and validated by Gateway.

The **target credential** is the credential stored by RDM or DVLS and used only by Gateway to authenticate to the target.

The **Gateway host key** is the SSH server identity presented by Gateway to the native SSH client.

The **target host key** is the SSH server identity presented by the target to Gateway.

The **expected fingerprint** is the target host-key fingerprint already trusted by RDM or explicitly accepted by the user.

The **observed fingerprint** is the target host-key fingerprint obtained by Gateway during the current SSH key exchange.

## Existing Gateway paths

Credential provisioning currently follows this path:

```text
POST /jet/preflight
  -> api/preflight.rs:post_preflight
  -> api/preflight.rs:handle_operation
  -> CredentialStoreHandle::insert
  -> CredentialStore::insert
  -> store encrypted proxy and target credentials under the token jti
```

JMUX currently follows this path:

```text
GET /jet/jmux
  -> api/jmux.rs:handler
  -> api/jmux.rs:handle_socket
  -> jmux.rs:handle
  -> JmuxProxy::run
  -> StreamResolverTask::run
  -> resolve and connect the token-authorized destination
```

The SSH prototype adds this path after the JMUX target connection:

```text
JMUX target TCP stream
  -> outgoing stream interceptor
  -> ssh_proxy::run
  -> russh client authenticates to target
  -> russh server authenticates native client
  -> relay SSH channel requests, data, status, EOF, and close
```

## Prototype implementation

The prototype adds an optional outgoing-stream interceptor to `jmux-proxy`.

JMUX remains responsible for destination filtering, DNS resolution, TCP connection establishment, and traffic auditing.

For a token with `jet_ap=ssh` and a credential mapping stored under the same `jti`, Gateway inserts an SSH protocol proxy between the JMUX channel and the target TCP stream.

The downstream `russh` server validates the proxy username and password supplied by the unmodified SSH client.

The upstream `russh` client decrypts and uses the target username and password.

The prototype relays session-channel creation, standard data, extended data, EOF, close, PTY requests, environment variables, shell requests, exec requests, subsystem requests, window changes, signals, exit status, and exit signals.

The target OpenSSH server sends EOF and exit status without immediately sending channel close.

The proxy therefore forwards the terminal status and actively closes the downstream channel to avoid a lifecycle deadlock.

`russh` is pinned to `0.55.0` because newer releases conflict with the prerelease cryptographic dependency graph already used by Gateway.

## Verified prototype result

The target was a Docker `linuxserver/openssh-server` container bound to a loopback test port.

The client was the unmodified Windows native OpenSSH executable.

The verified connection was:

```text
Windows OpenSSH
  -> local jetsocat listener
  -> JMUX over WebSocket
  -> Gateway SSH credential proxy
  -> Docker OpenSSH target
```

The native client supplied only `proxy/proxy-secret`.

Gateway authenticated to the Docker target with `target/target-secret`.

Running `whoami` returned `target` and native OpenSSH exited with status `0`.

Supplying the wrong proxy password was rejected and native OpenSSH exited with status `255`.

The JMUX, preflight, and Gateway library test suites passed after the implementation.

## Prototype limitations

The prototype generates a new random Ed25519 Gateway host key for every proxied connection.

This breaks normal OpenSSH `known_hosts` behavior across sessions.

The prototype accepts every target host key in `TargetClient::check_server_key`.

This means Gateway can send the target credential to an impersonated or intercepted target.

The current JMUX path falls back to raw TCP forwarding when the SSH credential entry is absent.

Credential-injection mode must instead fail closed when credentials or target-identity policy are absent.

The current credential entry contains only proxy and target credentials, with no target host-key policy.

The current JMUX token contains the authorized target, protocol, TTL, recording policy, association ID, and token ID, but no expected SSH fingerprint.

## Goals

### Transparent SSH client

Native OpenSSH and embedded SSH clients must not implement a Devolutions-specific SSH extension.

The client must interact with a normal SSH server endpoint exposed through Gateway and `jetsocat`.

### Credential isolation

The SSH client must know only the proxy credential.

The target must receive only the target credential.

The target credential must never be returned to the client.

Provisioned state must remain scoped by token ID, target, protocol, and TTL.

### Target identity assurance

Gateway must verify the target host key before sending the target credential.

RDM must remain the source of truth for stored target fingerprints and user trust decisions.

### Existing RDM trust experience

A known matching fingerprint should connect without prompting.

An unknown fingerprint should be displayed for explicit user confirmation.

A changed fingerprint should display the previous and observed values with a strong warning.

A rejected or mismatched fingerprint must prevent target authentication.

### Stable Gateway identity

Gateway must present a stable, managed SSH host key to the native SSH client.

The client will validate Gateway, not the original target, because Gateway terminates the downstream SSH session.

### Auditability

Gateway should audit the target, expected fingerprint, observed fingerprint, verification result, token ID, association ID, and failure stage.

Passwords, private keys, and decrypted credentials must never be logged.

## Constraints

### Two independent SSH sessions

Credential injection requires two independent encrypted SSH sessions.

```text
SSH client <- session A -> Gateway <- session B -> target
```

The native SSH client cryptographically validates the host key used by Gateway in session A.

Gateway cryptographically validates the target host key in session B.

### The target public key cannot be presented as Gateway identity

A raw SSH public key does not contain an IP address or hostname.

The hostname or IP association normally lives in the client's `known_hosts` data.

Gateway can observe and transmit the target public key, but it cannot use that public key to complete the downstream key exchange without the corresponding target private key or equivalent signing authority.

Relaying the entire target key exchange would preserve the target fingerprint, but it would also make encryption end to end between the client and target and prevent credential injection.

### No assumptions about target management

The design cannot assume that the target uses an enterprise SSH host CA, centralized provisioning, or any Devolutions software.

The target may expose only an ordinary raw OpenSSH host key.

### First-use trust cannot be manufactured

When RDM has no stored fingerprint and no external source of trust, the first observation is necessarily trust on first use.

TOFU detects later changes but cannot prove that the first connection was free from an active network attacker.

### Gateway is inside the trust model

Gateway receives the target credential and is already a trusted security principal in this design.

RDM may trust Gateway's authenticated report of an observed target fingerprint.

This design does not protect against a malicious or compromised Gateway.

### Probe and actual connection are separate

A probe result cannot authorize a later connection by itself.

The actual JMUX SSH connection must repeat host-key verification against the user-confirmed expected fingerprint before authentication.

### Multiple target host keys

An SSH server may offer RSA, ECDSA, Ed25519, certificates, or multiple keys during a rotation.

The policy should support a non-empty set of allowed algorithm and fingerprint pairs rather than assuming one permanent key.

The probe and actual connection must use the same SSH algorithm configuration so they negotiate consistently.

## Non-goals

The design does not preserve end-to-end SSH encryption between the native client and target.

The design does not make the native OpenSSH host-key prompt display the target's original fingerprint.

The design does not require modifications to the target SSH server.

The design does not automatically solve the authenticity of a first-seen target key.

The design does not protect target credentials from a compromised Gateway.

## Proposed RDM-managed flow

RDM owns persistent target fingerprints and the user interface.

Gateway owns target observation and enforcement on the actual network path.

The native SSH client owns only Gateway host-key verification and proxy-credential authentication.

The intended trust chain is:

```text
Native SSH client validates Gateway
  -> RDM decides which target fingerprints are trusted
  -> Gateway enforces that decision against the actual target
  -> Gateway sends target credentials only after a match
```

## Proposed Gateway probe interface

Gateway should expose a target host-key probe such as `POST /jet/ssh/probe`.

The probe is not credential injection and must never receive or use target credentials.

The probe must be subject to the same signed destination authorization as the actual JMUX connection.

The request should carry a short-lived, one-time JMUX token with `jet_ap=ssh`.

Gateway must derive the target from the signed token rather than accepting an arbitrary host and port in the request body.

Gateway must fully validate the token signature, validity window, Gateway ID, revocation state, replay policy, application protocol, and destination.

The probe token should be consumed and discarded after the probe.

RDM should obtain a fresh JMUX token for the actual session after the user accepts the fingerprint.

The probe should reject wildcard destinations and ambiguous alternate destinations.

The probe should use strict connection and key-exchange timeouts and should be rate-limited and audited.

An illustrative request is:

```http
POST /jet/ssh/probe?token=<one-time-jmux-token>
```

An illustrative response is:

```json
{
  "target": "server01.example.com:22",
  "algorithm": "ssh-ed25519",
  "fingerprint": "SHA256:abc...",
  "public_key": "ssh-ed25519 AAAAC3...",
  "observed_at": "2026-07-14T18:00:00Z"
}
```

The implementation should connect to the token-authorized target, complete only the SSH version and key exchange, capture the target public key, calculate the canonical fingerprint, return it, and immediately close the connection.

The probe must not send a username, password, public-key authentication request, or keyboard-interactive response to the target.

## Proposed fingerprint-aware credential provisioning

The actual credential-injection session must receive a non-empty expected host-key policy.

A dedicated preflight operation such as `provision-ssh-credentials` keeps SSH-specific invariants out of the existing protocol-neutral `provision-credentials` operation.

An illustrative operation is:

```json
{
  "id": "<operation-id>",
  "kind": "provision-ssh-credentials",
  "token": "<fresh-actual-jmux-token>",
  "proxy_credential": {
    "kind": "username-password",
    "username": "proxy-user",
    "password": "proxy-password"
  },
  "target_credential": {
    "kind": "username-password",
    "username": "target-user",
    "password": "target-password"
  },
  "expected_host_keys": [
    {
      "algorithm": "ssh-ed25519",
      "fingerprint": "SHA256:abc..."
    }
  ],
  "time_to_live": 900
}
```

Gateway should store credentials and expected host keys together under the actual JMUX token ID.

The stored entry should be tagged as SSH credential-injection state so it cannot be interpreted as an RDP mapping or ordinary token entry.

The expected host-key set should expire with the credential entry.

## RDM state flow

RDM may proactively probe before every injected SSH session so it can detect a changed key before launching the native client.

This adds one extra SSH key exchange per session but gives the cleanest user experience.

An optimized implementation may probe only when no fingerprint is stored, provided that actual-session mismatches can be returned to RDM as structured control-plane failures.

The first-use flow is:

```text
RDM obtains one-time probe token
  -> Gateway probes and returns observed fingerprint
  -> Gateway drops probe connection
  -> RDM shows first-use confirmation
  -> user rejects: stop
  -> user accepts: RDM persists fingerprint
  -> RDM obtains a fresh actual JMUX token
  -> RDM provisions SSH credentials plus expected fingerprint
  -> RDM starts jetsocat and the native SSH client
```

The known-key flow is:

```text
RDM obtains observed fingerprint or uses the stored expected policy
  -> observed key matches stored key
  -> RDM provisions SSH credentials plus expected fingerprint
  -> Gateway repeats verification on the actual connection
  -> Gateway authenticates only after the match
```

The changed-key flow is:

```text
Gateway reports observed fingerprint
  -> RDM compares it with the stored fingerprint
  -> RDM shows old and new values
  -> user rejects: stop and preserve old fingerprint
  -> user accepts: replace or extend stored policy
  -> mint a fresh token and begin a new actual session
```

## Actual JMUX enforcement

The actual JMUX SSH connection must not trust the earlier probe connection.

It must obtain the target host key again during the real upstream SSH key exchange.

The required order is:

```text
connect target TCP stream
  -> complete target SSH key exchange
  -> calculate observed fingerprint
  -> compare against expected host-key policy
  -> mismatch: close before authentication
  -> match: authenticate with target credential
  -> start downstream SSH server and channel relay
```

The target password must not be sent before `check_server_key` succeeds.

If the key changes between probe and actual connection, the actual connection must fail even if the user accepted the earlier observation.

If an SSH JMUX token has credential-injection state but lacks expected host keys, Gateway must fail closed.

If an SSH JMUX token requires credential injection but has no credential entry, Gateway must fail closed rather than use raw TCP forwarding.

## Gateway host identity

The native SSH client sees Gateway as the SSH server and therefore stores or validates the Gateway host key.

Gateway must use a stable host key loaded from managed configuration or persisted Gateway state.

Generating a new host key for each session is not acceptable because it produces repeated `known_hosts` changes.

An SSH authentication banner may display the target, observed fingerprint, and verification status to the native client.

The banner is informational and does not replace RDM's trust decision or Gateway's actual target verification.

## Internal Gateway module design

The probe path and credential-injection path must share one SSH handshake and target-identity implementation.

Duplicating `russh` configuration or fingerprint logic would allow algorithm preferences and verification behavior to drift.

The implementation should be a deep module with a small interface and all cryptographic details hidden behind it.

An illustrative interface is:

```rust
ssh_target::handshake(stream, HostKeyPolicy::Observe).await
ssh_target::handshake(stream, HostKeyPolicy::Require(expected_keys)).await
```

The returned handshake should contain the observed host identity and the unauthenticated upstream SSH session.

The probe caller should return the observed identity and drop the unauthenticated session.

The credential proxy caller should receive a session only after the required host-key policy matches and should then perform target authentication.

The module implementation should own SSH algorithm configuration, public-key extraction, canonical fingerprint formatting, constant-time comparison, timeouts, mismatch errors, and structured audit fields.

The module interface should be the primary unit and integration test surface.

## Fingerprint representation

Gateway and RDM must agree on one canonical representation.

The preferred human-readable representation is the OpenSSH-style SHA-256 fingerprint `SHA256:<base64-without-padding>`.

The algorithm should be stored alongside the fingerprint.

Returning the complete public-key blob allows RDM to preserve richer known-host information and independently recompute the fingerprint.

Fingerprint parsing must reject malformed algorithms, digests, padding, whitespace, and non-canonical encodings.

Comparison should operate on decoded digest bytes rather than display strings.

## Error model

Gateway should distinguish at least these outcomes:

```text
ssh-probe-connect-failed
ssh-probe-handshake-failed
ssh-host-key-unknown
ssh-host-key-mismatch
ssh-host-key-policy-missing
ssh-target-authentication-failed
ssh-proxy-authentication-failed
ssh-channel-failed
```

Mismatch errors should carry the target, expected fingerprints, observed algorithm, and observed fingerprint through an authenticated control-plane result.

Errors returned to the native SSH stream should remain generic enough to avoid exposing internal credentials or policy details.

## Audit model

Probe events should record association ID, token ID, target, resolved IP, observed algorithm, observed fingerprint, outcome, and duration.

Actual-session events should record expected policy identifiers, observed identity, match result, and whether target authentication was attempted.

The audit record must make it possible to prove that no target authentication was attempted after a mismatch.

Credentials and decrypted secret material must not be included in audit records or tracing fields.

## Security invariants

Gateway never sends a target credential before target host-key verification succeeds.

The probe endpoint never performs target user authentication.

The probe target always comes from a fully validated signed token.

The probe token is not reused for the actual JMUX session.

The actual session always repeats target host-key verification.

SSH credential injection never falls back to raw TCP forwarding when required state is absent or invalid.

The expected fingerprint is bound to the same token ID and target as the credentials.

Gateway exposes a stable downstream SSH host identity.

RDM remains the persistent owner of target fingerprint trust and user decisions.

## Test strategy

Unit tests should cover fingerprint canonicalization, invalid encodings, algorithm binding, allowed-key sets, match, mismatch, and missing policy.

The SSH target module should be tested through its interface with both observe and require policies.

Integration tests should prove that probe completes key exchange without sending any user-authentication request.

Integration tests should prove that a matching actual key allows target authentication.

Integration tests should prove that a mismatch prevents target authentication and prevents credential use.

Integration tests should replace the target key between probe and actual connection and verify that the actual connection fails.

Integration tests should verify unknown, accepted, rejected, changed, rotation-set, expired-entry, and replayed-probe-token cases.

End-to-end tests should use a Docker OpenSSH target, `tokengen`, Gateway, `jetsocat`, and native OpenSSH.

The native test should verify successful command output, exit status propagation, wrong proxy-password rejection, stable Gateway host identity, and changed-target-key rejection.

## Open decisions for later continuation

The final route name and response schema for the probe remain to be selected.

The implementation must decide whether RDM probes every injected session or only first-use and mismatch recovery sessions.

The Gateway configuration and persistence model for its stable downstream SSH host key remains to be designed.

RDM's existing fingerprint storage format and multi-key behavior must be reused rather than duplicated.

The precise token replay behavior for a one-time probe token must be verified against the production token validator.

The structured channel by which an actual-session fingerprint mismatch reaches the RDM UI remains to be selected.

The rotation policy must define whether accepting a new key replaces the old key or temporarily permits both.

## Sequencing decision

The SSH prototype and design are preserved for later work.

SSH host-key-aware credential injection is intentionally deferred because the complete trust and UI workflow is larger than the initial protocol proxy.

PowerShell and VNC credential injection should be investigated and delivered before returning to the SSH production design.
