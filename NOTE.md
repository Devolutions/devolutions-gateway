# Shadow streaming findings

Verified on 2026-08-18 against `feat/video-streamer-session-protocol` at
`0de9685441ea20ee9315e04d6c38033407bd19da` with local uncommitted build inputs.
This is not a master result.

## Live-edge join sends the latest GOP

The current feature branch does not cut the outgoing stream at the frame where
the client joins.

```text
devolutions-gateway/src/streaming.rs:RecordingEventSource::new:198
  -> selects StartAt::LiveEdge:203-205
devolutions-gateway/src/streaming.rs:RecordingEventSource::next_event:221
  -> sends CaughtUp after reaching the current file end:231-241
crates/video-streamer/src/session.rs:stream_session:40
  -> crates/video-streamer/src/normalizer.rs:normalize:71
  -> normalize_events:121
  -> ClipNormalizer::new:251
  -> LiveEdge selects KeepLatestGop:264-267
  -> PendingGop::push:215
  -> keeps every frame from the last input key frame:217-230
  -> ClipNormalizer::caught_up:294
  -> sends every retained frame through process_frame:299-302
  -> process_frame:371
  -> decodes and re-encodes every retained frame:375-408
  -> OutputSegment::encode:501
  -> rebases the first retained timestamp to zero:502-503
  -> forces only that first output frame to be a key frame:512-522
```

The decoder needs the last real key frame and its dependent frames to rebuild
the image at the join point. Those earlier decoded images do not need to be
sent to the client. The outgoing stream needs a newly encoded key frame for the
latest complete image at the join point, followed by new live frames.

In `LIVE-001`, the web client rendered source frame 1 after 7,684 ms. The limit
for frequently changing frames is less than 5,000 ms. Packet inspection found
that the output retained the source GOP timeline instead of starting at the
join image.

## The feature protocol rejects the RDM pull sequence

The RDM package client sends `Start` and an initial `Pull` when connecting. It
sends another `Pull` after each metadata or chunk response.

```text
GatewayWebSocketStream.ConnectAsync:76
  -> sends Start:85-87
  -> sends initial Pull:89-91
GatewayWebSocketStream.ReceiveLoopAsync:293
  -> metadata sends Pull:329-333
  -> chunk sends Pull:334-339
crates/video-streamer/src/protocol.rs:stream_segments:37
  -> wait_for_response:69-75
  -> buffers one early Pull only:175-176
  -> rejects the next request before a response:177-178
  -> sends UnexpectedError:82-85
```

The `LIVE-001` RDM client received `UnexpectedError` and completed without a
rendered source frame. This protocol failure is separate from the web client's
live-edge delay.

## Evidence

- Harness: `D:\e2e-streamer-recorder-fixture`
- Run: `b71c5a4013f944f6842b6ac0617e3780`
- Scenario evidence: `20260818T202251.125036Z-live-001`
- Gateway executable SHA-256:
  `40638391338bc95f1cfc3b3a1cb1bfe05b6bbbc52f7fbb856369507896ab8667`

The next comparison must build Gateway from a clean current master worktree and
run the same streaming path without running the recording matrix.
