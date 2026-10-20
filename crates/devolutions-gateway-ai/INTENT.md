# Background

The AI crate serves as an HTTP client and a runner for tasks that are related to AI.
We do not want to serve it as a generic LLM client only.
The crate provides methods for specific purposes, for example, to summarize a terminal session, or to generate AI analysis for a given recording video file.

## Tasks

### Analyze Recording

Analyze recording takes a parsed manifest file and its path to a recording folder.
It returns a stream of events that contains the progress of the analysis, and final results of the analysis and the potential errors that happened during the analysis.

The final result is a session log (`.slog`): a series of JSON objects with timestamps and a natural language description of the events that happened during the recording.
Every line of it says `"source":"ai"`, and `session.start` names the model, the prompt versions and the language, because whoever reads the file can always use the extra meta info.
Each prompt version is a hash of its prompt and its language rule, without the language itself, computed at compile time, so it always matches the prompt used.
Each action takes its time from the transcript line or the screenshot the model cites, never from the model, and that time is 100% aligned with the recording file: the timestamp minus the file's `startTime` in the manifest is where that line or screenshot is in the file, so whoever reads the log can jump there and check it.
The descriptions and the summary are written in the language the caller asks for, as any text of at most 10 characters such as `fr-CA`, `zh-Hant-TW` or `français`; a longer value is refused, and without one, the model is told to use English.
When the recording has actions, `session.end` carries a `summary` of them, in the same language, saying what the user did and on what; it assumes nothing about who reads it or how long it should be.
A summary that cannot be written fails the analysis like any other step, and no log comes out; after a transient failure, analysing again does not describe the actions it already has.

Analyze recording is trivial for terminal recordings.
We pre-process the .trp file to .cast, strip out some noise, then send it as text to the AI services.

Analyze video recordings breaks down the video into frames, and we apply motion detection algorithms to filter out idle or close enough frames.
Then we send the frames in chronological order to the AI services in batches.

