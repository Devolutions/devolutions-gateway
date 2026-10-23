# Recording
A recording is a continuous stream of bytes pushed by a client that holds a valid recording token.
A recording contains one or more clips.
The URL is `/jet/jrec/push/{sessionId}?fileType={fileType}`.
The `fileType` is required and is one of `webm`, `asciicast`, `trp` and `slog`.
When a session whose token requires recording starts and no recording starts for it within a short time, Gateway closes the session as a recording policy violation.


# Artifacts
Artifacts are files that are not recordings; the only kind today is `ai-analysis`, stored with the `slog` file type.
An endpoint to push artifacts is wanted later.


# Ending a recording
We use WebSocket close code 4011 to indicate that the producer actively terminates the recording.
As soon as 4011 is received:
- the recording is no longer active;
- the shadow viewers are notified;
- the associated session is closed subject to the recording policy.

Every other close, including a WebSocket close without a code or with code 1000, and a connection lost without any close, is treated as a network interruption or a clip switch.
In that case, the recording stays active until its reconnection timeout passes.
Gateway does not refuse a later push for the same session with a new token after 4011.
