# Background

Jrec is the endpoint to push, streaming, read recordings and its associated files.


# AI analysis

An AI analysis is a task initiated by the provisioner.
It requires the scope token with access `gateway.tasks.recording-ai-analysis.start` to access the url `POST /jet/jrec/{session_id}/ai-analysis`; Naturally in order to read the task's state, it requires the scope token with access `gateway.tasks.recording-ai-analysis.read`.
The analyzed output belongs to the recording reading scope, however, the associated metadata, including but not limited to error messages, token usages etc. belong to the task reading scope.
The caller chooses the language of the analysis in the request, under the rules of `crates/devolutions-gateway-ai/INTENT.md`. The language is part of the Task like every other parameter, so the same Task ID sent again with another language, model or provider is a conflict.
A request sent again is compared on its parameters only: the API key and the base URL are never stored, so another key or base URL gets the same Task, which keeps the first ones.
A new Task answers 202 with its path in `Location`, and the same request again answers 200 with the same Task. A conflict answers 409 with a `code`: `task_id_conflict`, `recording_active`, or `analysis_in_progress` with the running `taskId`. A session without recording, or an unknown Task, answers 404. An invalid request answers 400 and records no Task. Unknown fields are ignored, so a newer provisioner works with an older Gateway. The provider is one of `openai`, `anthropic`, `mistral`, `gemini` or `openai-compatible`.
Every Task reports the tokens it used so far, whether it is running, succeeded or failed, so the provisioner can add up what all analyses cost, failed ones included. Requests whose usage the provider didn't report are counted apart, so a total is never shown as complete when it isn't. A succeeded Task also shows the log's file name, the model the provider reported, and the prompt versions.
