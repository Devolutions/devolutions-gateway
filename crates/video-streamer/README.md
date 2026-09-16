# video-streamer

This crate rewrites an unseekable WebM recording into a stream that can start playing immediately.

`webm_stream` still serves one growing file over the original Start/Pull protocol.
`stream_session` accepts a multi-clip recording event stream, reconnects across clips, and emits independent VP8 WebM segments over the same Start/Pull codes.

The source is started only after the client sends a valid `Start` request.

`RecordingClip::new` accepts an owned `Read + Seek + Send + 'static` reader, including `std::fs::File`, `Cursor`, and test readers.

The source transfers each clip reader once in `ClipStarted` and never sends media payloads through an event.

`DataAvailable` is a wake-up marker, so the normalizer reads the current clip through the same reader until its current end.

The input event grammar is:

```text
(ClipStarted DataAvailable* CaughtUp DataAvailable* ClipEnded)* SessionEnded
```

The normalizer reads in at most 64 KiB chunks and caps each parser input window at 64 MiB plus 16 bytes of header room.
Replay may temporarily retain the original partial parser input and a second bounded replay window.
These application-owned buffers have fixed per-window bounds, but they are not a whole-process memory limit.
Native codec allocations and OS file caching are outside this claim.

Live-edge replay seeks the retained clip reader to the latest complete video keyframe and restores the original read head and parser state afterward.

A closed output receiver stops scanning and replay at parser and read checkpoints.
An active blocking file or native codec call can finish before cancellation is observed.

Readers are never reopened for replay, and output `Data` events are also limited to 64 KiB.
The normalizer can queue four output events before production blocks.
These shared slots hold segment metadata as well as data, so queued data payload is at most 256 KiB and may be lower for metadata or small writes.
The next request receives available output immediately without waiting for all four slots to fill.
This limit excludes the event being sent, parser and input windows, native codec allocations, and operating-system file caching.

`ClipEnded` closes one input clip but does not end the recording session.
After `ClipEnded`, an existing viewer waits for a reconnecting `ClipStarted` until `SessionEnded` confirms the final end.

## Session protocol

The client sends `Start` (`00`) once.
After fully handling `Segment started` or `Chunk`, the client sends one `Pull` (`01`).
The client does not send `Pull` after `Error` or `Stream ended`.
The server validates one request, waits for the next media message, sends one response, and then reads the next request.
Requests buffered by the transport remain unread while the server waits for or sends the current response.
`Error` and `Stream ended` answer the current request once and end the session without reading later requests.

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
