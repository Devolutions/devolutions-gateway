# Agent channel client

This crate is the agent's side of the channel defined in `agent-channel-proto`.

## Behavior

- The client runs only for identities whose config has an `agent_channel_url`, and follows config changes: it stops when the URL disappears, moves when it changes, and starts when it appears.
- On every connection, it answers the challenge with a `Hello` carrying full metadata and the proof of key possession.
- It uses HTTP/2 keepalive and reconnects with jittered exponential backoff.
- `RenewRequested` triggers a renewal.
- After a renewal is confirmed, and on `Reconnect`, it opens the new stream before closing the old one (make before break).
- It applies `ConfigUpdate` and acknowledges it.
- It stops reconnecting once the identity is rejected.

## Implementation decisions

- Built on tonic.
  Signing and path prefixing are provided by `agent-identity-httpsig`.
