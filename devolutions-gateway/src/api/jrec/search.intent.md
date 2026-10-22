## What is searched

Search reads only the files listed under `artifacts` in `recording.json` whose type is `slog`.
Recording files listed under `files` are not searched, a `.slog` recording included.
Each log is searched once, even when the request repeats its recording ID or the manifest lists it twice.
Search finds a recording and its logs where a recording pull does: in the folder named by the hyphenated recording ID, and only under a file name the pull accepts, so a log listed as `../outside.slog` is not searched.
A log that is missing or cannot be read is skipped and the search goes on, as `rg` and `grep` go on past a file they cannot open.

The query is matched literally, as `rg -F` and `grep -F` do, so its spaces are part of it and an empty query matches every line.
A line holding a JSON object is matched case-insensitively against the object's string values, at any depth and once unescaped; field names, numbers, booleans and null never match.
Any other line is matched case-insensitively against its raw text, so that any kind of artifact, present or future, can be searched.
A line cut at 256 KiB follows the same rule: what was read is matched by its string values when it parses as a JSON object, and as raw text otherwise.

Values are matched rather than raw text because users search the text they see: raw matching would make a field name such as `description` match every line, and would miss text that JSON escapes, such as `DOMAIN\user` stored as `DOMAIN\\user`.
The rule never depends on field names, so a producer can change the fields it writes without any change to search.
Per-field search, such as matching an entry's `description` only, is not supported: the fields a producer writes are unknown to Gateway, which only cares about values.

## Hits

A hit is a line that matches the query.
A hit carries the recording ID, the file name, the line number counting from 1, the byte offset of the line, and the raw line itself as a string.
Line numbers count from 1 like the slog package in `webapp/packages/session-recording-log`, so that a hit and that package's own search give a line the same number.
Gateway does not require a line to be JSON: a `.slog` is NDJSON by format, but a line holds whatever its producer pushed, such as a half-written last line while the push is live.
A line longer than 256 KiB is matched on its first 256 KiB and returned cut, with `truncated: true`; the caller fetches the file for the whole line.
The cut never splits a character, as `rg --max-columns-preview` does not.

## Access

A valid token with the `gateway.recordings.search` scope is the only check, and the provisioner that issues the token decides who gets one.
Search has its own scope because `gateway.recordings.read` only lists recording IDs and must not reveal log contents.

## Request

`recordings` is `"all"` or a list of recording IDs, and stays open to new forms added without breaking existing callers.
`"all"` orders recordings by start time, latest first, then by ID, the largest UUID as a 128-bit number first, so that the order is the same on every request.
A list keeps its order and searches a repeated ID once.
A request with a field Gateway does not know is rejected, as `rg` and `grep` reject an unknown flag, so that an option added later is never silently ignored by an older Gateway.

The optional `startTime` range takes RFC 3339 date-times and keeps a recording when `from <= startTime < to`, using the start time in `recording.json`, never anything inside a log.
A missing end leaves that side of the range open.

## Limits

One search reads about 16 MiB of logs at most and returns at most 1,000 hits, so that searching every recording takes a bounded time.

## Later

Regular expressions or wildcards, a total hit count, and combining words are wanted later, and the request shape must not preclude them.
Choosing which artifact kinds to search, or searching other sources such as the `.slog` recordings under `files`, is wanted later; the request shape must not preclude it either.
