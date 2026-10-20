# Recording
A recording is the byte stream a recorder pushes without the `artifact` query parameter.
The url is `/jet/jrec/push/{sessionId}?fileType={fileType}`.
We expect the `fileType` to be one of the following file types: `webm`, `cast`, `trp` and `slog`, which must be specified.
`slog` is just a file type, independent from whether a file is a recording or an artifact.
Each recording push connection writes one clip.
When connection is established with request of recordings for the session, if recording is not enabled within a short period of time, the connection will be closed with indication of violation of the recording policy.
Gateway only allows one recording to be pushed at a time per session.


# Artifacts
Artifacts are files that are not recordings, listed under `artifacts` in manifest instead of `files`.
A producer is anything that pushes a recording or a session event log.
The session event log is the only artifact that can be pushed, on `/jet/jrec/push/{sessionId}?fileType=slog&artifact=events`.
`ai-analysis` is an artifact Gateway writes itself; it cannot be pushed.
Gateway stores what the producer pushes and does not look at what is inside.
Each session event log push connection writes a new session event log.
Gateway only allows one session event log push at a time per session.
The session event log push uses its own push token, not the recording's.
The session event log push is independent from the recording push: it never interferes with the recording.
The session event log follows the recording: it is refused before the recording starts and cannot reconnect once the recording is over.
Pushing an artifact does not satisfy the recording policy.
