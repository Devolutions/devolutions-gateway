# Recording
Gateway recording is a continuous stream of bytes pushed from the client who pocesses the valid recording token.
The url is `/jet/jrec/push/{sessionId}?fileType={fileType}`.
We expect the `fileType` to be one of the following file types: `webm`, `cast`, `trp` and `slog`, which must be specified.
When connection is established with request of recordings for the session, if recording is not enabled within a short period of time, the connection will be closed with indication of violation of the recording policy.


# Artifacts
Artifacts are files that are not recordings, currently only have `ai-analysis` with combination to `slog` file type.
We reuse the same url but with one extra query parameter, `/jet/jrec/push/{sessionId}?fileType={fileType}&kind={kind}`, where the `kind`, if not specified, we treat it as recordings.
Artifacts can be pushed without any recordings started.
Pushing artifacts should not trigger any recording policy as recordings.
Session shadowing does not support artifacts. 