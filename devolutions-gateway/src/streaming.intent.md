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


## Multi-clip, size variant streaming

We support streamings of multi-clip, size-variant source.
See how we do multi-clip recordings in `devolutions-gateway/src/recording.rs`. We support streaming as well for the same source.

### The source
We have two streaming sources that we currently support:
1. RDM, which whenver size of a remote connecti session changes, it creates a new clip with consistent size in the header. 
2. Chrome/Other browsers, chrome behaves differently, see `webapp/packages/web-recorder`, we use the media recorder API to record the session, the size changing behavior is not documented, but in experiencemnt and in practice, it will sliently change the size of the frame, the webm standard did not advise against this behavior, more lilely, it is undifined, and the client may or may not support it.

### The normalizer

Given the constrains above, we would like to unifiy the source and provide a single shape that the client can consume easily.
We use the following model:

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


Normalized client output:

- Each client begins at its own live edge.
- Each `[segment]` contains one fixed frame size.
- RDM input clip boundaries and browser frame-size changes produce the same
  normalized output shape.
- Every client has an independent output sequence beginning at zero.
```

We use Websocket subprotocols to implement backward compatibility, for the first version, which had no subprotocol, it will be treated as the first version of the streaming protocol. That is, no segment support. For the second version, we will introduce a new subprotocol `jrec-shadow.v2`, which fully takes advantage of the multi-clip protorol introduced above.

<a id="synthetic-key-frames"></a>
## Synthetic key frames (`jrec-shadow.v3`)

Some players only show a live stream after they have buffered a large block of bytes; Media Foundation waits for 256 KiB per read.
An RDP source sends a frame only when the screen repaints, so while the screen is still such a player shows nothing.
Protocol v3 lets the player ask for a key frame of the current picture so its read fills.

- A client opts in by offering the WebSocket subprotocol `jrec-shadow.v3`; `Pull` takes no parameter and there is no capability negotiation.
- Gateway compares the selected subprotocol by value, preferring `jrec-shadow.v3` over `jrec-shadow.v2`; any other or missing subprotocol is protocol v1.
- The client decides when a synthetic key frame is sent; Gateway never sends one on its own.
- A v3 client may send `PullOrKeyFrame` in place of `Pull`.
  When new data is ready, Gateway answers it exactly as it answers `Pull`.
  When no new data is ready, Gateway answers with a synthetic key frame of the current picture instead of waiting.
- Synthetic key frames are limited by a byte budget per viewer, hardcoded for now at 300,000 bytes per second.
  Each synthetic key frame is spaced from the previous one by its own size divided by the budget.
  Real source data does not count against the budget and is never held back by it.
  While the budget does not yet allow a synthetic key frame, `PullOrKeyFrame` waits until new data is ready or the budget allows one.
- Gateway sends no automatic refill frames to any viewer, whatever the protocol version; a quiet source produces output only when a v3 client asks for it.
