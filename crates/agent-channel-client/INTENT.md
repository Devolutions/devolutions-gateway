This crate is the agent's side of the channel defined in `agent-channel-proto`.

## Connection

- It connects through the agent's configured proxy, like the agent's identity HTTP requests.
- It sends an HTTP/2 keepalive every 30 s, and reconnects after a closed stream with a jittered exponential backoff from 1 s, unless the outcome is terminal.
  The backoff grows to 1 h when the response shows the path cannot carry gRPC, such as a reverse proxy that answers without HTTP/2 or gRPC, and to 5 min after network errors, server downtime, and any other transient refusal or closure of the stream, so that a device behind such a proxy stops retrying often while an outage still recovers quickly.
- The backoff doubles from 1 s and is multiplied by a jitter drawn uniformly from `[0.5, 1.5]` before its cap, as the agent's other retries are.
- The backoff restarts from 1 s only after a stream has stayed authenticated for 60 s, so that a stream that authenticates and then drops at once keeps backing off.
  After such a long-lived stream closes, the first reconnect waits a delay drawn uniformly from `[0, 30 s]`, so that an authority restart doesn't bring every agent back within the same second.
- A server message that cannot be decoded, or whose `id` is not a UUID, closes the stream as a transient failure without a reply, so the agent never echoes an unchecked `id` and never sends an envelope larger than `CONTRACT.agent-identity.md` §7.1 allows.
- Text from the authority, a status message or the reason of a push, is logged with control characters, bidirectional overrides and backslashes escaped and is cut to 256 characters, and an `error-code` that is not a lowercase snake_case code of at most 64 bytes is logged as invalid, so that an authority cannot forge log lines or flood the log.

## Handshake

- An opening that has not received `Welcome` 30 s after the connection started is a network error; until then, messages other than the expected `Challenge` and `Welcome` are ignored when their `id` is a UUID.
- A `Challenge` that is not 32 bytes closes the stream as a transient failure, without sending `Hello`.

## Closing

- Dropping a channel stops an opening or a wait to reopen at once; an authenticated stream first sends the acknowledgements already queued, then ends the agent's side and gives the authority up to 5 s to end its own, so that no acknowledgement queued before the drop is lost.
