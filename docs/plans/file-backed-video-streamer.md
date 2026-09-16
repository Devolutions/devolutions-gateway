# File-backed, request-driven video streaming

## Goal and scope

Handle each accepted client request by receiving the next media message and sending one response.
Keep recording data in the original clip files instead of retaining a live-edge GOP in memory.
Keep the existing typed protocol modules, consuming source startup, wire codes, encoder settings, clip rollover, and session-end rules.
Do not add arbitrary playback seeking, a spool file, dependencies, or changes to terminal streaming.

Latest update: requests are strictly serial, and the media producer prefetches up to four output events.
The serial protocol replaces the early-Pull scheduling work package below; the file-backed reader implementation remains in place.

## Baseline and design constraints

- Before this change, Gateway opened each clip and emitted 64 KiB byte events in `RecordingEventSource::next_event`.
- Before this change, `PendingGop` retained the last GOP's payload while finding the live edge.
- The existing positioned WebM iterator records keyframe offsets and seeks its reader for replay.
- The original output channel had capacity one and `EventWriter` accepted arbitrary write lengths.
- The remux job can replace a clip's path, so saved offsets must refer to a retained open handle.
- A file can contain multiple resolutions; decoding determines output-segment boundaries.
- The original request scheduler allowed one active request and one queued Pull; the latest ruling removes that extra queue.

Proposed constraints: use 64 KiB read/output windows and retain the existing 64 MiB per-element limit.
Enforce limits for partial and captured elements as well as ordinary payloads.
Do not impose a total recording-length or GOP-on-disk-length limit to enforce an in-memory limit.
Native codec allocations and OS file caching are outside this application-buffer claim.
Runtime correctness, native memory use, and Windows replacement behavior remain untested in this task.

## Work packages

### 1. Request scheduling — original Luna work package, superseded

- Remove `awaiting_response` without hiding an equivalent renamed flag.
- Validate Start before launching the source directly, then process one current request at a time.
- Keep the next media receive owned while waiting; accept at most one early Pull and detect disconnect/errors.
- Keep socket polling in request scheduling, not inside the media iterator or a misleading wait-for-segment method.
- Respond to the current and already accepted queued requests on failure; do not count an excess request.
- On normal end, finish the current and queued requests with StreamEnded.
- Retain a typed transport and byte codec at the edge.
- Add regression assertions for ordered delivery through pauses, queued Pull handling, failure, and disconnect.

### 2. Clip ownership and bounded replay — Luna, media/Gateway files

- Transfer one owned seekable reader per clip through the source interface instead of byte payload events.
- Keep file opening after valid Start, and file reads/seeks on the blocking media worker.
- Gateway publishes clip identity and availability/end notifications; it does not parse WebM.
- Replace `PendingGop` with one replay position plus the required track, codec, timestamp-scale, and cluster context.
- Scan available history with bounded windows; record the last complete keyframe and a complete replay endpoint.
- Replay through that endpoint using the same reader and a fresh parser, then restore the original read head and partial parser state.
- Handle a partially buffered BlockGroup without replaying it twice or treating its partial contents as a complete boundary.
- Drain final available bytes before closing a clip; preserve waiting for growth and waiting for the next clip.
- Split output writes into bounded chunks and retain capacity-one backpressure.
- Add no-codec fixtures for offset replay, growing/truncated tails, stable reader identity, limits, and ownership cleanup.
- Update the source-interface documentation and exports, not the unrelated legacy streamer.

### 3. Coordinator verification

- Read the actual request-to-read and response-to-send paths after both work packages.
- Verify all old byte-event call sites are adapted and no obsolete flag/startup machinery remains.
- Compare diffs and reject silent media or wire-contract changes outside this plan.
- Compile both changed crates including test code, without executing tests.
- Verify the benchmark feature still compiles, and run focused Clippy/format checks.
- Record the exact validation results and remaining runtime-validation limits here.

## Acceptance checks

- No source reads or normalization before valid Start.
- One response per accepted request and no advancing to a later output message because a Pull arrived late.
- Memory retains only bounded windows and constant-size replay metadata, not the full file or GOP payload.
- No fresh open of a clip path is used to replay saved offsets.
- Empty files, partial EBML, clip reconnects, and confirmed session end remain distinct.
- Early return, disconnect, and outer cancellation release source readers and producer ownership.
- Existing codec/sequence/error/transport regression cases are retained or adapted, not replaced with weaker assertions.

## Progress

- [x] Read current sources and pinned EBML positioning implementation.
- [x] Record approved scope and assign independent implementation packages.
- [x] Implement request-driven scheduling.
- [x] Implement owned clip readers and bounded replay.
- [x] Inspect integration and compile-check all affected targets.
- [x] Record final results; tests and benchmarks are not executed.

## Result and verification

Luna implemented the two work packages; the coordinator inspected integration and corrected remaining module-layout and formatting issues.

- `RecordingClip` owns a seekable reader; Gateway transfers it once and publishes availability markers instead of byte events.
- `serve_request` keeps one media receive pending until it sends a response, queues one early Pull, or handles a terminal condition.
- The normalizer scans history without retaining GOP payloads and replays through a known complete boundary on the same handle.
- Replay restores the original parser, partial input, and read head, including on failure.
- Bounded replay does not finalize the enclosing WebM document at an artificial window end.
- Input reads and queued output payloads are at most 64 KiB; each partial parser window is limited to 64 MiB plus 16 bytes.
- The producer can perform bounded read-ahead; this is not a one-file-read-per-Pull implementation.

Commands completed successfully for the file-backed implementation:

- `cargo check -p video-streamer --tests`
- `cargo check -p devolutions-gateway --tests`
- `cargo check -p video-streamer --bench vpx_reencode --features bench`
- `cargo clippy -p video-streamer --no-deps --tests -- -D warnings`
- `cargo clippy -p devolutions-gateway --no-deps --tests -- -D warnings`
- `rustup run nightly rustfmt --check --edition 2024 crates/video-streamer/src/lib.rs devolutions-gateway/src/streaming.rs`
- `git diff --check`

Cargo emitted incremental-cache finalization warnings: `Access is denied` (OS error 5).
No tests, benchmarks, application builds, commits, or pushes were performed.
The compiled regression cases cover replay selection/restoration, partial known/unknown-size block groups, a window ending inside a known-size cluster, cancellation checkpoints, bounded output, and request ordering.
Native VP8/VP9 playback, resident memory measurements, and Windows remux replacement behavior were not executed or measured.

## Latest result: serial consumption and media warm-up

Sol implemented the serial protocol and bounded media warm-up approved in `DECISIONS.md`.

- The loop validates one request, awaits `segments.next()`, sends its response, then receives another request.
- The protocol no longer uses a Pull queue, `select!`, or `awaiting_response`.
- Later requests, decode errors, and disconnects are observed on the next transport receive, not concurrently with pending media.
- Error and StreamEnded messages answer the current request only; unread requests are not drained or answered.
- The existing output channel now has four shared slots, with each data payload limited to 64 KiB.
- Queued data payload is at most 256 KiB per viewer; metadata and small writes may use less.
- Available output is consumable immediately, with no fill threshold or extra prefetch task.
- In-flight events, parser windows, and native codec memory are outside the queue limit.

Sol reported successful package formatting, video-streamer Clippy, both crate compile checks with `--tests`, and `git diff --check`.
The coordinator independently repeated both compile checks and the diff check successfully.
Regression code covers partial output, full-queue backpressure, ordered refill, buffered requests, and delayed error/disconnect handling.
Tests and benchmarks remain unexecuted; the four-slot budget is an initial default, not a measured optimum.