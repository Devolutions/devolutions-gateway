# video-streamer

This crate takes an unseekable WebM recording (typically from Chrome CaptureStream) and rewrites it into a “fresh” WebM stream that can start playing immediately.
It does this by parsing the incoming WebM, finding the correct cut point, and re-encoding frames.
The output stream begins with a keyframe and valid headers.

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
