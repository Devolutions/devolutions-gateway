# video-streamer

This crate rewrites an unseekable WebM recording into a stream that can start playing immediately.

`webm_stream` still serves one growing file over the original Start/Pull protocol.
`stream_session` accepts a multi-clip recording event stream, reconnects across clips, and emits independent VP8 WebM segments over the same Start/Pull codes.

The input event grammar is:

```text
(ClipStarted Bytes* CaughtUp Bytes* ClipEnded)* SessionEnded
```

`ClipEnded` closes one input clip but does not end the recording session.
After `ClipEnded`, an existing viewer waits for a reconnecting `ClipStarted` until `SessionEnded` confirms the final end.

## Session protocol

The client sends `Start` (`00`) once.
After fully handling `Segment started` or `Chunk`, the client sends one `Pull` (`01`).
The client does not send `Pull` after `Error` or `Stream ended`.
The server sends exactly one response for each accepted request and buffers at most one early `Pull` while a response is pending.
An accepted queued `Pull` receives its own `Stream ended` response if the session ends before more segment data arrives.
If another overlapping request exceeds that limit, the current and queued requests receive `Error`, the excess request is rejected, and the stream fails.

`Segment started` (`01` + JSON) carries `{codec,sequence,width,height}` and begins an independent WebM segment.
The output `sequence` starts at zero, is independent of the input `ClipStarted.sequence`, and increments for each output segment.
A reconnecting clip or resolution change starts the next output segment.
Another `Segment started` message implicitly closes the previous segment.
Legacy `{codec}` metadata remains valid for one segment with sequence zero.

`Chunk` (`00` + bytes) belongs to the current segment.
`Stream ended` (`03`) cleanly closes the final segment and confirms that the recording session ended.
`Error` (`02` + JSON), an abrupt transport close, or a transport error does not confirm a clean session end.

## Prerequisites

This crate relies on `cadeau` and its XMF backend for VP8/VP9 decode+encode.
To override which XMF implementation is used at runtime, set `DGATEWAY_LIB_XMF_PATH` to an `xmf.dll` path before running tests or benches.

Example:

`$env:DGATEWAY_LIB_XMF_PATH = 'D:\library\cadeau\xmf.dll'`

## Tests

Run all tests:

`cargo test -p video-streamer`

Run the WebM streaming correctness suite:

`cargo test -p video-streamer --test webm_stream_correctness -- --nocapture`

Some tests are marked `#[ignore]` because they require large local assets or are intended for local investigation.
Run ignored tests with:

`cargo test -p video-streamer -- --ignored --nocapture`

Test assets live under `testing-assets\`.

## Logging and diagnostics

Most detailed diagnostics are compiled out by default to keep production logs clean.
To include extra diagnostics, build with `perf-diagnostics`:

`cargo test -p video-streamer --features perf-diagnostics -- --nocapture`

Then set `RUST_LOG` as needed.
Example:

`$env:RUST_LOG = 'video_streamer=trace'`

## Benchmarks

The main benchmark is `benches\vpx_reencode.rs`.
Run it with:

`cargo bench -p video-streamer --bench vpx_reencode --features bench -- --nocapture`

Benchmark output is intentionally quiet by default.
To print detailed per-run results, set `VIDEO_STREAMER_BENCH_VERBOSE`:

`$env:VIDEO_STREAMER_BENCH_VERBOSE = '1'`

To correlate benchmark results with internal timing, also enable `perf-diagnostics` (the `bench` feature enables it).
This is intentionally a build-time gate so production logs stay clean.
