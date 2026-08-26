# Recording streaming intent
This document captures the intended behaviour and architectural invariants for recording-file streaming in `streaming.rs`.

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