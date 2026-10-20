# Recording
Gateway recording is a continuous stream of bytes pushed from the client who possesses the valid recording token.
The url is `/jet/jrec/push/{sessionId}?fileType={fileType}`.
We expect the `fileType` to be one of the following file types: `webm`, `cast`, `trp` and `slog`, which must be specified.
When connection is established with request of recordings for the session, if recording is not enabled within a short period of time, the connection will be closed with indication of violation of the recording policy.
Gateway only allows one recording to be pushed at a time per session.


# Artifacts
Artifacts are files that are not recordings, listed under `artifacts` in manifest instead of `files`.
The url is `/jet/jrec/push/{sessionId}?fileType=slog&artifact=events`; `events` is the only artifact that can be pushed, as the session events log.
`ai-analysis` is not pushed: it is only kept so older manifests still list it.
Artifacts of file type slog can be pushed by producers alongside the recordings, one artifact at a time.
Pushing an artifact does not satisfy the recording policy.

