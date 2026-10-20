This crate is the agent's side of the channel defined in `agent-channel-proto`.

- It connects through the agent's configured proxy, like the agent's identity HTTP requests.
- It sends an HTTP/2 keepalive every 30 s, and reconnects after a closed stream with a jittered exponential backoff from 1 s, unless the outcome is terminal.
  The backoff grows to 1 h when the response shows the path cannot carry gRPC, such as a reverse proxy that answers without HTTP/2 or gRPC, and to 5 min after network errors and server downtime, so that a device behind such a proxy stops retrying often while an outage still recovers quickly.
