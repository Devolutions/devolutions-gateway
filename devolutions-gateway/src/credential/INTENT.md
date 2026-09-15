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

Checkout: When an injected credential has arrived and is sitting in memory, and the association token arrives at Gateway and the lookup of the injected credential is successful, we consider the injected credential checked out by the logical session.

Staging/Stage: when an injected credential arrives at Gateway but checkout has not happened yet, we consider the injected credential to be in staging.

Remove/Eject: remove and eject here specifically mean actively removing the injected credentials/materials from memory and making sure they will not be accessible on a best-effort basis.

## Decisions
1. Credential-injection support must follow the lifecycle of its logical session.

A logical session is established when Gateway accepts its association token for the initial connection.

As long as Gateway would authorize an initial connection or reconnect for that logical session, the same connection must remain possible with credential injection.

When Gateway can no longer authorize any connection or reconnect for that logical session, it must immediately remove all credential-injection material owned by the session.

This DOES NOT mean that the injected credentials should live as long as the logical session continues.
A session's lifetime is defined by `jet_ttl`, but whether it can establish a connection or reconnection is defined by `jet_reuse` and `exp`.
The injected credentials should be removed when the session can no longer establish a connection or reconnection.

2. Provisioning for the same JTI should be permitted, but the policy for different kinds of provisioning should be defined on a per-kind basis.
For credential injection, the policy is that the old injected credentials should be removed when new injected credentials are provisioned for the same JTI.

3. If a connection requires credential injection but its required credentials are not available, the connection should fail immediately.
The connection should not continue without the required injection support.
An association token does not identify whether credential injection is required, so this rule only applies while Gateway still has credential-injection state for the JTI.

4. The injected credentials naturally arrive earlier than the connection that uses them.
The second half (checked out) of the lifetime of the injected credentials is defined in 1); we define the staging lifetime of the injected credentials here:

The amount of time that the injected credentials can stay in staging is defined by the provisioning TTL, which is supplied by the provisioner through the preflight provisioning operation.
When the provisioning TTL expires, Gateway must actively remove the staged material from memory.

5. A synthetic KDC should have only one instance per JTI at all times.
