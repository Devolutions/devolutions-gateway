# Background

The AI crate serves as an HTTP client and a runner for tasks that are related to AI. 
We do not want to serve it as a generic LLM client only. 
The crate provides methods for specific purposes, for example, to summarize a terminal session, or to generate AI analysis for a given recording video file.

## Tasks

### Analyze Recording

Analyze recording takes a parsed manifest file and its path to a recording folder.
It returns a stream of events that contains the progress of the analysis, and final results of the analysis and the potential errors that happened during the analysis.

The final result is a series of JSON objects with timestamps and a natural language description of the events that happened during the recording.

Analyze recording is trivial for terminal recordings. We just send the recording files to the AI service and get the results back.

Analyze video recordings breaks down the video into frames, and we apply motion detection altorithms to filter out idle or close enough frames. Then we send the the frames in chronological order to the AI services in batches.

