This crate defines the agent channel between the agent and an authority.

Its `.proto` is the single source of the channel schema for every language: this crate, and the `Devolutions.Agent.Channel` NuGet package built from the same file for authorities written in .NET.
No other copy of the `.proto` exists; the contract refers to this file.
It is also the only artifact the mock authority shares with the agent.

Every message carries an `id`, an optional `correlation_id`, and a `oneof` payload.

| Payload          | Direction                        | Purpose                                                                 |
| ---------------- | -------------------------------- | ----------------------------------------------------------------------- |
| `Challenge`      | Authority → agent, first message | Fresh random bytes for this stream                                      |
| `Hello`          | Agent → authority                | Metadata, capabilities, applied-state versions, proof of key possession |
| `Welcome`        | Authority → agent                | The stream is authenticated; carries the server time                    |
| `Ack`            | Both                             | Acknowledgement                                                         |
| `RenewRequested` | Authority → agent                | Renew now                                                               |
| `Reconnect`      | Authority → agent                | Reopen the stream                                                       |
| `ConfigUpdate`   | Authority → agent                | A newer config revision                                                 |

- The proof of key possession rides in `Hello`, so that authenticating a stream costs no extra round trip.
- Messages inside the stream are not individually signed and rely on TLS; this is a deliberate V1 tradeoff.
