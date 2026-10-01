# Recording streaming intent
## Scope

These rules apply to the `/shadow` WebSocket streaming path implemented by `streaming.rs`.

This includes:

- recording file-type classification
- streamability decisions
- streaming implementation selection
- terminal input-format selection
They do not define the following:

- JREC push behaviour
- JREC pull behaviour
- artifact storage
- download MIME types
- consumer-side rendering.

## Streaming contract

Only WebM, asciicast, and TRP recording artifacts are accepted by the `/shadow` streaming path.

| Recording file type | Extension | Streaming behaviour |
| --- | --- | --- |
| `WebM` | `.webm` | WebM streaming |
| `Asciicast` | `.cast` | Terminal streaming using asciinema input |
| `TRP` | `.trp` | Terminal streaming using TRP input |
| `SessionRecordingLog` | `.slog` | Explicitly rejected by the `/shadow` streaming path |

- A recognised`RecordingFileType` is not automatically supported by `/shadow` streaming. Each recognised recording file type must have explicitly defined behaviour for the `/shadow` streaming path.
- Files with missing or unrecognised extensions must be rejected before WebSocket streaming begins.

## Architectural invariants

- Recording artifact streaming must use the canonical `RecordingFileType` extension mapping as its source of truth.
- A recording file must be classified once. The resulting `RecordingFileType` must determine:
    - if the artifact is supported by the `/shadow` streaming path
    - which streaming implementation is used (when applicable)
    - which terminal input format is used (when applicable)

- Streaming validation, streamer selection, and terminal input selection must not maintain separate extension mappings or independently compare known recording extensions as raw strings.
- Adding a new `RecordingFileType` requires an explicit decision about whether it is supported by the `/shadow` streaming path and, if supported, how it is streamed.
- A new or unsupported recording file type must not silently fall back to an existing streaming implementation or terminal input format.
## Component boundaries
JREC artifact handling, storage, download content types, and consumer-side rendering are outside the scope of this document.


> **Boundary:** Session Recording Log artifacts are supported elsewhere in Gateway through the JREC recording flow. Their rejection by `/shadow` applies only to the WebSocket streaming path covered by this document.

## Multi-clip, size-variant WebM streaming

The `/shadow` WebM path must stream a recording session made of several input clips whose frame size may change.
The recording manager in `recording.rs` owns the clip lifecycle; streaming must follow it rather than reading a single file.

### Terms

- **Input clip**: one append-only WebM file pushed by a source; the recording session may gain more input clips when the source reconnects.
- **Output segment**: one complete VP8 WebM document with its own headers and one fixed frame size.
- **Segment boundary**: the point where one output segment ends and the next begins; it happens when an input clip ends or when the decoded frame size changes.

### Sources

Gateway must accept both known sources of size changes:

1. RDM starts a new input clip whenever the remote session size changes, and each clip header carries that clip's size.
2. Browsers record with the MediaRecorder API (`webapp/packages/web-recorder`) and change the frame size inside one input clip without a new header.

### Normalized output

Gateway must normalize both sources into one output shape:

```text
Legend:
-----  size A
=====  size B
^^^^^  size C
|      input clip boundary
+      client joins
[ ]    normalized output segment

Time ------------------------------------------------------------------>

RDM source: each size change creates a new input clip

Input:    ----------------------|======================|^^^^^^^^^^^^^^^^
          <------ clip 1 ------> <------ clip 2 ------> <--- clip 3 --->

Client 1:          +[-----------][======================][^^^^^^^^^^^^^^^^]
                   starts near
                   end of clip 1

Client 2:                              +[==============][^^^^^^^^^^^^^^^^]
                                       starts partway
                                       through clip 2


Browser source: sizes change inside one input clip

Input:    -----------------------=======================^^^^^^^^^^^^^^^^^
          <------------------- one input clip -------------------------->

Client 1:          +[------------][======================][^^^^^^^^^^^^^^^^]
                   starts near
                   end of size A

Client 2:                              +[===============][^^^^^^^^^^^^^^^^]
                                       starts partway
                                       through size B
```

- Each client must begin at its own live edge.
- Each output segment must contain exactly one frame size.
- RDM input clip boundaries and browser frame-size changes must produce the same output shape.
- Each client must have its own output segment sequence, starting at zero.

### Protocol versions

The client chooses the protocol version during the WebSocket handshake.

- A client that offers the WebSocket subprotocol `jrec-shadow.v2` must get shadow protocol v2, and the upgrade response must echo `jrec-shadow.v2`.
- A client that does not offer `jrec-shadow.v2` must get shadow protocol v1, and the upgrade response must not carry a subprotocol.
- Only the WebM path negotiates a version; terminal streaming must ignore offered subprotocols.
- A request rejected before streaming starts (close codes 4001, 4002, and 4003) must also echo an offered `jrec-shadow.v2`, so that browsers open the socket and see the close code.
- Gateway must never send `SegmentStarted` to a v1 client, because v1 clients fail on unknown message types.
- Browsers fail the handshake when an offered subprotocol is not echoed, and report it like any other connection failure; a browser client must therefore retry once without the offer to reach a Gateway that predates v2.

### Wire contract

Message codes:

| Direction | Code | Message | Payload |
| --- | --- | --- | --- |
| Client to server | `0` | `Start` | none |
| Client to server | `1` | `Pull` | none |
| Server to client | `0` | `Chunk` | WebM bytes of the current output segment |
| Server to client | `1` | `Metadata` | `{"codec":"vp8"}` |
| Server to client | `2` | `Error` | `{"error":"UnexpectedError"}` |
| Server to client | `3` | `StreamEnded` | none |
| Server to client | `4` | `SegmentStarted` | `{"codec":"vp8"}`; v2 only |

Request rules for both versions:

- The client must send `Start` once, then one `Pull` for each further message it wants.
- Gateway must answer `Start` with `Metadata`, and each `Pull` with exactly one message.
- Gateway must answer an invalid or out-of-order request with `Error` and then stop the stream.
- When the recording source or the normalizer fails, Gateway must answer the pending request with `Error` and then stop the stream.
- After `Error`, Gateway must not send `StreamEnded`.

Shadow protocol v1 transcript:

```text
Start -> Metadata
Pull  -> Chunk          (first bytes of output segment 0)
Pull  -> Chunk ...
Pull  -> StreamEnded    (at the first segment boundary, or when the session ends first)
```

Shadow protocol v2 transcript:

```text
Start -> Metadata
Pull  -> Chunk ...      (output segment 0; it has no SegmentStarted)
Pull  -> SegmentStarted (output segment 1 begins; segment 0 ended implicitly)
Pull  -> Chunk ...
Pull  -> StreamEnded    (only after the session ended and the last output segment finished)
```

- A v1 stream ends at the first segment boundary, so a v1 viewer gets `StreamEnded` when the source disconnects or the frame size changes.
- Before shadow protocol v2, a browser source that changed its frame size made Gateway close the stream with 1011, so ending a v1 stream at that boundary is an improvement for v1 viewers.
- Each output segment is a complete WebM document, so a v2 client must start a new decoder pipeline on `SegmentStarted`.
