# Intention:


## Context and terminology

Logical Session: a logical session is defined when a connection reaches Gateway and is authenticated with the association token.

```rust
pub struct AssociationTokenClaims {
    pub jet_aid: Uuid,

    ..
    pub jet_ttl: SessionTtl,

    pub jet_reuse: ReconnectionPolicy,
    pub exp: i64,
    ..
    pub jti: Uuid,
}
```

Injected credentials: injected credentials are the actual credentials sent by the provisioner (DVLS) to Gateway, which are used later by a logical session to serve the purpose of granting access to a client without exposing the actual credentials.

## Decisions
1. Credential-injection support must follow the lifecycle of its logical session.

A logical session is established when Gateway accepts its association token for the initial connection.

As long as Gateway would authorize an initial connection or reconnect for that logical session, the same connection must remain possible with credential injection.

Association-token expiry does not terminate a reconnect window that belongs to an already established logical session.

When Gateway can no longer authorize any connection or reconnect for that logical session, it must immediately remove all credential-injection material owned by the session.

This DOES NOT mean that the injected credentials should live as long as the logical session continues.
A session's lifetime is defined by `jet_ttl`, but whether it can establish a connection or reconnection is defined by `jet_reuse` and `exp`.
The injected credentials should be removed when the session can no longer establish a connection or reconnection.

2. Provisioning for the same JTI should be permitted, but the policy for different kinds of provisioning should be defined on a per-kind basis.
For credential injection, the policy is that provisioning for the same JTI should be rejected.

3. If a connection requires credential injection but its required credentials are not available, the connection should fail immediately.
The connection should not continue without the required injection support.

4. The injected credentials naturally arrive earlier than the connection that uses them.
The second half of the lifetime of the injected credentials is defined in 1); we define the first half of the lifetime of the injected credentials here:

When injected credentials arrive through provisioning by the `provision-credentials` operation, we will have a `time_to_live` (TTL) for the injected credentials, which is defined by the caller of the `provision-credentials` operation.
The TTL here specifically defines how long the injected credentials should be kept in memory before they are checked out by a logical session.
Once a logical session checks out the injected credentials, their lifetime is defined by the logical session's lifetime, and the TTL no longer applies.
