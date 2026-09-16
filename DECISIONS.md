# Decisions

## 2026-09-14: Explicit recording startup

User approval, verbatim:

> that is right, get gpt-luna to refactor this, you do the planning

Approved direction:

- A `RecordingSource` represents an unstarted recording source.
- A consuming `start(self)` begins source initialization and normalization after a valid client `Start`.
- Construction must not open or read recording clips or start the normalizer.
- One recording source can produce several output segments across reconnects and resolution changes.
- Keep media production separate from WebSocket request accounting.
- Preserve the existing Start/Pull codes, one response per accepted request, and one extra queued Pull.
- Preserve live-edge selection and recording-end rules; do not add arbitrary seeking or replace the media algorithm.
- Keep startup and running-stream cancellation responsible for releasing readers and producer tasks.

Implementation assignment: `gpt-luna` implements; the coordinating assistant plans and verifies the result.
Do not commit, push, post externally, build application binaries, or execute tests for this task.

## 2026-09-16: Await launch directly

User ruling, verbatim:

> yeah, like what you have here looks very very wrong, why no simply, when first request received, stream = Some(source.launch_stream().await?)
>
> something like this? do you agree? why can't it be like this?

User approval, verbatim:

> let's do it

- Validate the first `Start`, await stream creation in that branch, then store the running stream in `Some`.
- Remove the separate startup future, factory, event, and polling branch.
- Launch creates the stream; waiting for media, file growth, or reconnect belongs in stream consumption.
- Client messages received during launch are handled after launch returns, not concurrently with it.
- On launch failure, reply to accepted requests only; unread messages are not accepted requests.
- Keep request accounting separate from whether the stream has been launched.
- Dropping the session still cancels its owned launch future or releases the running stream.

This supersedes the earlier implementation's concurrent startup handling, not the media algorithm or wire codes.

## 2026-09-16: Typed messages and started streams

User ruling, verbatim:

> let's update it, also, for the stream, can you make the item directly use message instead of byte? so we don't need to do manual encoding here

- The started-session loop receives an existing stream, not an optional stream.
- Segment reception returns a message or error; `StreamEnded` already represents a clean end.
- The protocol loop receives `ClientMessage` and sends `ServerMessage`.
- Keep byte encoding and decoding in the transport adapter, preserving wire formats and distinct malformed-message and transport-error handling.
- Keep direct launch after a valid `Start` and existing request accounting and cleanup.

## 2026-09-16: Request-driven consumption

User ruling, verbatim:

> that is right, there should not have a #sym:awaiting_response
>
> on the contrarary, it should be incoming reqest? segment.next() and send back, you know what I mean? do you agree?

- Express the main flow as accepting a request, receiving the next media message, and sending its response.
- Remove the `awaiting_response` boolean rather than rename it or move the same flag elsewhere.
- Keep the bounded media queue, one early Pull limit, error replies, and disconnect handling.
- Consume media in order; do not seek or discard output because a request arrives late.

## 2026-09-16: File-backed media windows

User ruling, verbatim:

> yes, I believe that we can, such that, update the abstraction of segment, idealy, segments stream, or iterator, should NEVER save the entire buffer in memory, but rauther, maybe some header, and some windowed limited buffer, and meta data like offsets etc... wherever necessary. and on requested, seek and read on file, do you agree?

User approval, verbatim:

> good, create yourself a proper plan and drive gemini flash or gpt luna, the cheaper ones, to do the work

- Keep recording payload on disk and retain bounded working windows, headers, decoder state, and positions.
- Replace live-edge GOP payload retention with offset-based rereading through the same open clip handle.
- Read sequentially for normal progress; seek only for necessary positioning or replay.
- Preserve decoding and re-encoding; output segments are not slices of the original file.
- Bound application-owned input and output bytes, not merely channel item counts.
- Retain file identity across positioning; do not reopen a replaced path and trust old offsets.
- Preserve segment order, resolution changes, reconnects, incomplete-tail recovery, and explicit session end.
- Luna implements the plan; the coordinator verifies it without executing tests or benchmarks.

## 2026-09-16: Serial requests and bounded media warm-up

User's requested loop, verbatim:

```text
let message = transport.recv()
if message == pull
	let data = segment.next().await
	transport.send(data)
```

Implementation assignment, verbatim:

> get gpt sol to implement it

Buffer requirement, verbatim:

> good, get a segment a reletively reasonable buffer to warm up, not necessaryly the whole stream, but a reasonable buffer so that not all returns are comming from disk, understand?

- Receive a request, await the next media message, send the response, then receive the next request.
- Remove the protocol's extra request queue, pipelined-request machinery, and receive/media `select!`.
- Do not replace them with another concurrency mechanism or a renamed pending-response flag.
- This supersedes all earlier one-queued-Pull limits and concurrent disconnect/error handling while awaiting media.
- Keep typed wire messages, valid-Start launch, current-request error replies, final StreamEnded, and owned cleanup.
- Prefetch media only, using the existing bounded producer channel rather than a second cache.
- Send available output immediately; do not wait for a full warm-up buffer.
- Retain file-backed windows, offsets, and native codec state rather than buffering a whole recording.

Coordinator-selected initial budget: four output slots of at most 64 KiB each, at most 256 KiB of queued media payload per viewer.
This is an unbenchmarked default, not a total-memory bound; in-flight data, parser windows, and codec allocations are separate.
Sol implements this update; do not execute tests or benchmarks, commit, or push.