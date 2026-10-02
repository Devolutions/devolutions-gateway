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

We would like to support streamings of multi-clip, size-variant source.
See how we do recordings in `devolutions-gateway/src/recording.rs`. We now would like to support streaming as well for the same source.

### The source
We have two streaming sources that we currently support:
1. RDM, which whenver size of a remote connecti session changes, it creates a new clip with consistent size in the header. 
2. Chrome/Other browsers, chrome behaves differently, see `webapp/packages/web-recorder`, we use the media recorder API to record the session, the size changing behavior is not documented, but in experiencemnt and in practice, it will sliently change the size of the frame, the webm standard did not advise against this behavior, more lilely, it is undifined, and the client may or may not support it.

### The normalizer

Given the constrains above, we would like to unifiy the source and provide a single shape that the client can consume easily without breaking backward compatibility. 
We would use the following model:

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

The client always gets a guaranteed fixed size segment, for the first segment, we keep it backward compatible, the protocol will be extendned, such that, on new `pull` message, when the previous output segment ends, it will send a new `SegmentStarted` message.