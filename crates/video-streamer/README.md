# video-streamer

`video-streamer` converts one logical recording session into a pull-driven stream of independent VP8 WebM segments.

The input may contain several append-only clips.
Each clip may contain VP8 or VP9 and may change resolution.
The output keeps one transport connection, always uses VP8, and starts a new fixed-size WebM segment at every clip or resolution boundary.

## Interface

Call `stream_session` with a recording event stream and a message transport.
The transport must implement `Stream<Item = Result<Bytes, E>> + Sink<Bytes, Error = E>`.

```rust
stream_session(recording_events, transport, SessionConfig::default()).await?;
```

The input must follow this grammar:

```text
(ClipStarted Bytes* CaughtUp Bytes* ClipEnded)* SessionEnded
```

Use `StartAt::LiveEdge` for the clip that was already growing when a consumer joined.
The streamer retains only that clip's latest group of pictures until `CaughtUp` arrives.
Use `StartAt::Beginning` for clips that start after the consumer joins.

The incremental decoder owns incomplete EBML bytes between `Bytes` events.
The caller never seeks, rolls back, or retries an incomplete element.
The decoder limits one buffered EBML element and one retained group of pictures to 64 MiB each.

## Wire protocol

Each transport item is one complete protocol message.
For WebSocket use, one item maps to one binary WebSocket message.
The first byte is its type code.

Client messages:

| Code | Message | Payload |
| ---: | --- | --- |
| `0` | Start | Empty |
| `1` | Pull | Empty |

Server messages:

| Code | Message | Payload |
| ---: | --- | --- |
| `0` | Chunk | WebM bytes |
| `1` | Segment started | `{"codec":"vp8","sequence":N,"width":W,"height":H}` |
| `2` | Error | `{"error":"UnexpectedError"}` |
| `3` | Stream ended | Empty |

`Start` requests the first `Segment started` message.
Each `Pull` requests exactly one later server message.
The next `Segment started` message ends the previous segment implicitly.
`Stream ended` ends the final segment and the session.

Every segment has its own EBML and Tracks headers.
Every segment begins with a keyframe and keeps one resolution.

## Prerequisites

This crate uses `cadeau` and its XMF backend for VP8 and VP9 decoding and VP8 encoding.
The streamer reads the dimensions of every decoded image so source resolution changes do not depend on codec header parsing.
Set `DGATEWAY_LIB_XMF_PATH` when the default XMF library is unavailable.

```powershell
$env:DGATEWAY_LIB_XMF_PATH = 'D:\library\cadeau\xmf.dll'
```

## Checks

```powershell
cargo +nightly fmt --all
cargo check -p video-streamer --tests
cargo clippy -p video-streamer --tests -- -D warnings
```
