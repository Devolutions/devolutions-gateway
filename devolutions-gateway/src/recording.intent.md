# Recording
Gateway recording is a continuous stream of bytes pushed from the client who pocesses the valid recording token.
The url is `/jet/jrec/push/{sessionId}?fileType={fileType}`.
We expect the `fileType` to be one of the following file types: `webm`, `asciicast`, `trp` and `slog`, which must be specified.
When connection is established with request of recordings for the session, if recording is not enabled within a short period of time, the connection will be closed with indication of violation of the recording policy.


# Artifacts
Artifacts are files that are not recordings, currently only have `ai-analysis` with combination to `slog` file type.
Currently, we do not have an api endpoint to push artifacts, but we will have one in the future.


# Ending a recording
We use WebSocket close code 4011 to indicate that the producer actively terminates the recording.
As soon as 4011 is received, the shadow viewers are notified immediately, and the associated session is closed subject to the recording policy.
Every other close, including a WebSocket close without a code or with code 1000, is treated as network flickering or a size change.
In that case, the liveness of the recording is subject to the reconnection timeout.
Gateway does not refuse a later push for the same session with a new token after 4011.
