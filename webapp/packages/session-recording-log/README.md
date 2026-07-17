# @devolutions/session-recording-log

Framework-agnostic models, parser, ordering, and in-file search for Session Recording Log (`.slog`) files.

## Host contract

- Hosts detect `.slog` artifacts from `recording.json` file names (for example `recording-0.slog`).
- Hosts keep original bytes for download scenarios.
- Hosts decode UTF-8 text and pass the decoded NDJSON text to the parser.
- This package does not reconstruct downloadable `.slog` content.

## Architecture Decision Record 2 (ADR-2) canonical contract

- `parseSessionRecordingLog` returns:
  - `entries: ParsedSessionRecordingLogEntry[]` in original file order.
  - `warnings: SessionRecordingLogWarning[]` with structured `code`.
  - `completionState: 'complete' | 'ended-unexpectedly'`.
- `ParsedSessionRecordingLogEntry` exposes `entry`, `sourceLineNumber`, and `sourceIndex`.
- Public warning codes follow ADR-2 categories:
  - `malformed-line`
  - `missing-session-start`
  - `missing-session-end`
  - `duplicate-sequence`
  - `missing-sequence`
  - `sequence-order-mismatch`
  - `unknown-event-type`
  - `invalid-field`
  - `entry-limit-exceeded`
  - `string-truncated`
- Additive warning:
  - `unterminated-final-line` (informational; valid final line without newline is not semantically invalid).
  - Intended for Architecture Decision Record (ADR) addendum documentation rather than replacement of canonical malformed handling.

Schema-limit options:

- `maxLineLengthBytes`
- `maxStringLength`
- `maxParameterCount`
- `maxObjectDepth`
- `maxParsedEntries`
- `maxScannedLines`
- `maxMissingSequenceWarnings`
- `maxUnknownFieldCount`

## Review-driven hardening updates (2026-07-17)

- Added bounded missing-sequence emission to prevent unbounded gap loops on sparse large `seq` ranges.
- Replaced recursive depth traversal with iterative depth checks to prevent stack-overflow failure on deeply nested JSON.
- Added malformed-heavy input bounding with `maxScannedLines`, and finite default `maxParsedEntries`.
- Fixed empty-log lifecycle classification (`completionState: 'complete'` when no valid entries).
- Added top-level unknown field cap (`maxUnknownFieldCount`) with `entry-limit-exceeded` warning when truncated.
- Split unknown future events into explicit `unknown-event-type` warning code.
- Clarified alias intent: `SessionRecordingLogRecord` is retained for AD historical naming compatibility.

## Ratified v1 defaults (review decision)

Ratified as v1 canonical defaults for cross-host behavior:

- `maxLineLengthBytes`: `262144` (256 KiB)
- `maxStringLength`: `4096`
- `maxParameterCount`: `200`
- `maxObjectDepth`: `8`
- `maxParsedEntries`: `10000`
- `maxScannedLines`: `20000`
- `maxMissingSequenceWarnings`: `1000`
- `maxUnknownFieldCount`: `100`
- search default limit: `100`
- search max limit: `1000`

Callout: these values were elevated from implementation defaults to ratified policy as a direct follow-up to review-driven hardening.

## Search behavior

- Searches visible fields only:
  - `description`
  - `object`
  - `parameters` keys and values
  - `actor`
  - `host`
  - `sessionType`
  - `timestamp`
- Does not search `sourceText` or `unknownFields`.
- Supports optional filters:
  - `eventTypes` for lifecycle filtering
  - `warnings` + `onlyWithWarnings` for warning-linked filtering

## API

- `parseSessionRecordingLog(text, options?)`
- `getSessionRecordingLogDisplayEntries(parseResult)`
- `searchSessionRecordingLogEntries(entries, query, options?)`
- `isSessionRecordingLogFileName(fileName)`
