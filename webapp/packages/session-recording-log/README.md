# @devolutions/session-recording-log

Framework-agnostic models, parser, ordering, and in-file search for Session Recording Log (`.slog`) files, plus Gateway recording manifest classification.

## Features

- NDJSON parser that keeps valid entries even when other lines are malformed.
- Structured warning codes for parser behavior and host branching.
- Source metadata (`sourceLineNumber`, `sourceIndex`, `sourceText`) preserved for each parsed entry.
- Non-mutating display-order helper (sort by `seq`, tie-break on `sourceIndex`).
- Bounded in-memory search over visible fields with optional event/warning-linked filtering.
- Hardened bounds for large/malformed inputs (line size, string length, parameter count, depth, entry/scan caps).
- Gateway `recording.json` manifest classification into video, terminal, and log artifacts, grouped into the viewers a recording can offer.

## Usage

### Basic usage

```ts
import { parseSessionRecordingLog } from '@devolutions/session-recording-log';

const result = parseSessionRecordingLog(slogText);
console.log(result.completionState);
console.log(result.entries.length);
console.log(result.warnings.map((warning) => warning.code));
```

### Full runnable example

```ts
import {
  getSessionRecordingLogDisplayEntries,
  parseSessionRecordingLog,
  searchSessionRecordingLogEntries,
} from '@devolutions/session-recording-log';

const slogText = [
  '{"timestamp":"2026-07-15T21:17:49.777Z","seq":0,"event":"session.start","description":"Session started","actor":"Administrator","host":"IT-HELP-DC","sessionType":"ADConsole"}',
  '{"timestamp":"2026-07-15T21:19:14.351Z","seq":1,"event":"session.action","description":"Renamed Object","object":"Help Desk Ottawa","parameters":{"Members added":"Sarah O\'Connor, Bob Smith"}}',
  // Missing session.end on purpose.
].join('\n');

const parseResult = parseSessionRecordingLog(slogText);

// Parse status + warning surfacing.
console.log(parseResult.completionState); // 'ended-unexpectedly'
for (const warning of parseResult.warnings) {
  console.log(`${warning.code} line=${warning.sourceLineNumber ?? '-'} seq=${warning.seq ?? '-'}`);
}

// Non-mutating display order by seq/sourceIndex.
const displayEntries = getSessionRecordingLogDisplayEntries(parseResult);
console.log(displayEntries.map((entry) => `${entry.entry.seq}:${entry.entry.event}`));

// Basic search/filter.
const actionHits = searchSessionRecordingLogEntries(parseResult.entries, "o'connor", {
  eventTypes: ['session.action'],
});
const warningLinked = searchSessionRecordingLogEntries(parseResult.entries, '', {
  onlyWithWarnings: true,
  warnings: parseResult.warnings,
});

console.log(actionHits.length); // 1
console.log(warningLinked.length); // entries linked to parser warnings
```

## API Reference

Public API:

- `parseSessionRecordingLog(text, options?)`
- `getSessionRecordingLogDisplayEntries(parseResult)`
- `searchSessionRecordingLogEntries(entries, query, options?)`
- `isSessionRecordingLogFileName(fileName)`
- `classifyFileName(fileName)`
- `isSafeFileName(fileName)`
- `getArtifacts(manifest)`
- `getRecordingViewers(manifest)`
- `SessionRecordingKind`

Manifest types:

- `GatewayRecordingManifest`
- `GatewayRecordingManifestFile`
- `RecordingArtifact`
- `RecordingViewers`

### Recording manifest

A Gateway recording folder holds a `recording.json` manifest that lists its files in playback order:

```json
{
  "sessionId": "39174dbd-ac5f-4af8-a372-03dc89362a0f",
  "startTime": 1758470400,
  "duration": 161,
  "files": [
    { "fileName": "recording-0.webm", "startTime": 1758470400, "duration": 161 },
    { "fileName": "recording-1.slog", "startTime": 1758470400, "duration": 161 }
  ]
}
```

| Term | Meaning | Count for 5 `.webm` + 1 `.slog` |
| --- | --- | --- |
| file | One entry in `files` | 6 |
| artifact | One file plus its kind (`RecordingArtifact`) | 6 |
| viewer | The window that shows a recording: a player for media, the log viewer for `.slog` | 2 |

`getArtifacts(manifest)` turns a Gateway `recording.json` into one `RecordingArtifact` per file, in manifest order.
A `null` or `undefined` manifest returns `[]`.
File names are dropped before classification unless they use only ASCII letters, digits, `.`, `_`, and `-`, contain no `..`, and aren't just `.`, because a manifest name ends up in a token-bearing pull URL.

```ts
import { getArtifacts, SessionRecordingKind } from '@devolutions/session-recording-log';

const artifacts = getArtifacts(manifest);
const logs = artifacts.filter((artifact) => artifact.kind === SessionRecordingKind.Log);
```

`SessionRecordingKind` members name the concept, not the file extension:

| Kind | File extensions |
| --- | --- |
| `SessionRecordingKind.Video` | `.webm` |
| `SessionRecordingKind.Terminal` | `.trp`, `.cast` |
| `SessionRecordingKind.Log` | `.slog` |
| `SessionRecordingKind.Unknown` | anything else |

Kinds group files by the viewer that opens them, so `.trp` and `.cast` are both `Terminal` even though their content types differ.

This mirrors the C# `GatewayRecordingManifest` in Remote Desktop Manager, so both hosts classify a manifest identically.

### Recording viewers

`getRecordingViewers(manifest)` groups the same files into a `RecordingViewers` object: the viewers a recording can offer, at most one media player and one log viewer.
A recording with five video clips and one log offers two viewers, not six.

```ts
import { getRecordingViewers } from '@devolutions/session-recording-log';

const { media, log, unknownCount } = getRecordingViewers(manifest);
```

| Field | Contents |
| --- | --- |
| `media` | `{ kind, files, duration }` for video or terminal files, or `undefined` |
| `log` | `{ files, duration }` for `.slog` files, or `undefined` |
| `unknownCount` | Files not returned: unknown kinds, plus media files that differ from the first media file's kind |

Files keep manifest order.
A group's `duration` sums its files' durations, skipping any that are missing or not positive.
Unsafe file names are dropped and not counted.

Every viewer is returned.
Unlike C# `RecordingArtifact.SelectPrimary`, this package never picks one; the host lets the user choose.

Host contract:

- Hosts detect `.slog` artifacts from `recording.json` file names (for example `recording-0.slog`).
- Hosts keep original bytes for download scenarios.
- Hosts decode UTF-8 text and pass the decoded NDJSON text to the parser.
- This package does not reconstruct downloadable `.slog` content.

Architecture Decision Record 2 (ADR-2) canonical contract:

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
- `maxRetainedSourceTextBytes`
- `maxStringLength`
- `maxParameterCount`
- `maxObjectDepth`
- `maxParsedEntries`
- `maxScannedLines`
- `maxMissingSequenceWarnings`
- `maxUnknownFieldCount`
- `maxWarnings`

Ratified v1 defaults (review decision):

- `maxLineLengthBytes`: `262144` (256 KiB)
- `maxRetainedSourceTextBytes`: `8388608` (8 MiB)
- `maxStringLength`: `4096`
- `maxParameterCount`: `200`
- `maxObjectDepth`: `8`
- `maxParsedEntries`: `10000`
- `maxScannedLines`: `20000`
- `maxMissingSequenceWarnings`: `1000`
- `maxUnknownFieldCount`: `100`
- `maxWarnings`: `10000`
- search default limit: `100`
- search max limit: `1000`

## Project Structure

```txt
session-recording-log/
  src/
    fixtures/                  # sample .slog fixtures used by package tests
    parser.ts
    ordering.ts
    search.ts
    manifest.ts
    model.ts
    index.ts
    parser.test.ts
    helpers.test.ts
    manifest.test.ts
  README.md
  package.json
  package.dist.json
  tsconfig.json
  vite.config.ts
```

## Dependencies

- Runtime dependencies: none
- Dev dependencies: TypeScript, Vite, Vitest, Biome, `vite-plugin-dts`, `vite-plugin-static-copy`

## For Developers

From `webapp/`:

```bash
pnpm --filter @devolutions/session-recording-log check:write
pnpm --filter @devolutions/session-recording-log check
pnpm --filter @devolutions/session-recording-log test
pnpm --filter @devolutions/session-recording-log build
```

## Review-driven hardening updates (2026-07-17)

- Added bounded missing-sequence emission to prevent unbounded gap loops on sparse large `seq` ranges.
- Replaced recursive depth traversal with iterative depth checks to prevent stack-overflow failure on deeply nested JSON.
- Added malformed-heavy input bounding with `maxScannedLines`, and finite default `maxParsedEntries`.
- Fixed lifecycle classification so only empty/whitespace-only input is `complete`; non-empty input without `session.end` remains `ended-unexpectedly`.
- Added top-level unknown field cap (`maxUnknownFieldCount`) with `entry-limit-exceeded` warning when truncated.
- Split unknown future events into explicit `unknown-event-type` warning code.
- Clarified alias intent: `SessionRecordingLogRecord` is retained for AD historical naming compatibility.
