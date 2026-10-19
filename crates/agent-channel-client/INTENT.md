This crate is the agent's side of the channel defined in `agent-channel-proto`.

- It connects through the agent's configured proxy, like the agent's identity HTTP requests.
- It sends an HTTP/2 keepalive every 30 s, and reconnects after a closed stream with a jittered exponential backoff from 1 s to 5 min, unless the outcome is terminal.
