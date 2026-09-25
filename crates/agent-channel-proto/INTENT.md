# Agent channel contract

This crate defines the agent channel between the agent and an authority.
Like [contract.intent.md](../../docs/agent-identity/contract.intent.md), it is product-neutral.

Its `.proto` is the single source of the channel for every language: this crate, and the `Devolutions.Agent.Channel` NuGet package built from the same file for authorities written in .NET.
No other copy of the `.proto` exists.
It is also the only artifact the mock authority shares with the agent.

The channel carries more than identity (renewal requests and config now, PEDM policies later), hence the `agent-channel` name.

## Service

```proto
service AgentChannel {
  rpc Connect(stream AgentMessage) returns (stream ServerMessage);
}
```

Every message carries an `id`, an optional `correlation_id`, and a `oneof` payload.

## V1 payloads

| Payload | Direction | Purpose |
|---|---|---|
| `Challenge` | Authority → agent, first message | Fresh random bytes for this stream |
| `Hello` | Agent → authority | Metadata, capabilities, applied-state versions, proof of key possession |
| `Welcome` | Authority → agent | The stream is authenticated; carries the server time |
| `Ack` | Both | Acknowledgement |
| `RenewRequested` | Authority → agent | Renew now |
| `Reconnect` | Authority → agent | Reopen the stream |
| `ConfigUpdate` | Authority → agent | A newer config revision |

## Opening a stream

1. The opening request is signed with RFC 9421 (`tag="connect"`).
2. The authority answers with a fresh `Challenge`.
3. The agent answers with `Hello`, whose proof is a signature, with the same key, over the challenge and the opening request's nonce.
4. Only once the proof verifies does the authority send `Welcome`, record the device as connected, or push anything.

The proof binds the key to this stream.
Signed opening headers can be captured by a TLS-terminating proxy, TLS inspection or a header log; without the key, they no longer open a stream.
The proof rides in `Hello` so that authentication costs no extra round trip.

## Semantics

- Pushes from the authority are an optimization.
  The source of truth is reconciliation from the state the agent announces in `Hello`, including its config revision.
- Messages inside the stream are not individually signed and rely on TLS; this is a deliberate V1 tradeoff.
- A stream is bound to the certificate that opened it.
  The authority closes the stream in each of these cases:
  - at that certificate's `notAfter`;
  - when `confirm` retires the certificate, after asking the agent to reconnect;
  - when the device is revoked.
