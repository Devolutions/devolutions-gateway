## What is searched

Search reads only the files listed under `artifacts` in `recording.json` whose type is `slog`.
Recording files listed under `files` are not searched, a `.slog` recording included.

Search does not interpret log content: it matches the query case-insensitively against the raw text of each line, so that any kind of artifact, present or future, can be searched.
Per-field search, such as matching an entry's `description` only, is not supported, since it would need Gateway to parse what producers write.

## Hits

A hit is a line that holds the query.
It carries the recording ID, the file name, the line number counting from 1, the byte offset of the line, and the line itself as a string.
Gateway does not check that a line is JSON: a `.slog` is NDJSON by format, but a line holds whatever its producer pushed, such as a half-written last line while the push is live.
A line longer than 256 KiB is matched on its first 256 KiB and returned cut, with `truncated: true`; the caller fetches the file for the whole line.

## Access

A valid token with the `gateway.recordings.search` scope is the only check, and DVLS decides who gets one.
Search has its own scope because `gateway.recordings.read` only lists recording IDs and must not reveal log contents.

## Request

`recordings` is `"all"` or a list of recording IDs, and stays open to new forms added without breaking existing callers.
`"all"` orders recordings newest first by start time, then by ID, so that the order is the same on every request; a list keeps its order and searches a repeated ID once.

The optional `startTime` range takes RFC 3339 date-times and keeps a recording when `from <= startTime < to`, using the start time in `recording.json`, never anything inside a log.
A missing end leaves that side of the range open.

## Limits

One search reads about 16 MiB of logs at most and returns at most 1,000 hits, so that searching every recording takes a bounded time.

## Later

Regular expressions or wildcards, a total hit count, and combining words are wanted later, and the request shape must not preclude them.
