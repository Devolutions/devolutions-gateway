# Background

Jrec is the endpoint to push, streaming, read recordings and its associated files.


# AI analysis

An AI analysis is a task initiated by the provisioner.
It requires the scope token with access `gateway.tasks.recording-ai-analysis.start` to access the url `POST /jet/jrec/{session_id}/ai-analysis`; Naturally in order to read the task's state, it requires the scope token with access `gateway.tasks.recording-ai-analysis.read`.
The analyzed output belongs to the recording reading scope, however, the associated metadata, including but not limited to error messages, token usages etc. belong to the task reading scope.
The caller chooses the language of the analysis in the request; a language longer than 10 characters is refused, and the language is part of the Task, so the same Task ID sent again with another language is a conflict.