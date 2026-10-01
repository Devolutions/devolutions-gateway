# Recording
Gateway recording is a continuous stream of bytes pushed from the client who possesses the valid recording token.
The url is `/jet/jrec/push/{sessionId}?fileType={fileType}`.
We expect the `fileType` to be one of the following file types: `webm`, `cast`, `trp` and `slog`, which must be specified.
When connection is established with request of recordings for the session, if recording is not enabled within a short period of time, the connection will be closed with indication of violation of the recording policy.

## Reconnection

A producer may reconnect within the reconnect window of its push token (`jet_reuse`).
Each connection appends one clip, `recording-{n}.{extension}`, to the manifest, and the manifest is the ordered clip list.
Only one producer may be connected at a time.
When the producer stays away for the whole window, viewers are told the recording ended.
Gateway forgets the recording 10 seconds after the window ends.
A token that does not allow reconnection ends the recording when its producer disconnects.


# Artifacts
Artifacts are files that are not recordings, currently only have `ai-analysis` with combination to `slog` file type.
Currently, we do not have an api endpoint to push artifacts, but we will have one in the future.