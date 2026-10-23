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
Each prompt version is a hash of its prompt and its language rule, without the language itself, computed at compile time, so it always matches the prompt used, and the prompt behind it can be traced in the public git history.
For now, the prompts are built into the Gateway; a prompt managed by the provisioner is a further improvement that can be considered.
Each `session.action` takes its time from the recording if it is a WebM video, never from the model: the AI only describes what changed between frames, and the time is that of the screenshot it cites, managed by Gateway; the timestamp minus the file's `startTime` in the manifest is where that screenshot is in the file, so whoever reads the log can jump there and check it.
For a terminal recording, the exact time of a `session.action` is difficult to manage: for now, the timeline depends on which transcript line the model cites, and further improvement can be considered.
The descriptions and the summary are written in the language the caller asks for, as any text of 1 to 10 characters such as `fr-CA`, `zh-Hant-TW` or `français`; an empty or longer value is refused, and without one, the model is told to use English.
When the recording has at least one `session.action`, `session.end` carries a `summary`; otherwise no summary is created, and `session.end` has no `summary` attribute.
The content of the summary depends completely on the model, on the previous AI-generated `session.action` analysis as text (not the original frames or cast files), and on the prompt.
Beyond trimming it and failing the analysis on an empty, cut-short or refused answer, we do not programmatically constrain anything the model outputs, nor can we meaningfully control it programmatically.
Generating the summary belongs to the same AI analysis task, as its last step, and its language MUST be the same as that of the `session.action` analysis, which is the language taken in with the AI analysis request; this is not negotiable.
Again, no AI-generated content can be meaningfully controlled programmatically: the language rules above, like everything else the model writes, are subject to the model's behavior, and we manage them on a best-effort basis with tuned prompts.
A failed summary is handled the same as a failed `session.action` request: transient error handling belongs to the HTTP request and the job, not to the summary.

Analyze recording is trivial for terminal recordings.
We pre-process the .trp file to .cast, strip out some noise, then send it as text to the AI services.
We parse asciicast and TRP recordings and never send the user's input to the model, even if that means losing understanding, because of passwords and safety: only the terminal output is sent.
For now, what the shell echoes back is output and is still sent; further protection will be considered in a separate change.

Analyze video recordings breaks down the video into frames, and we apply motion detection algorithms to filter out idle or close enough frames.
Then we send the frames in chronological order to the AI services in batches.

