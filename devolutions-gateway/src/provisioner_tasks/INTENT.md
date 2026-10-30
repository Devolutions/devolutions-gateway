# Background
Provisioner Tasks (hereafter "Tasks") are tasks issued for Gateway to execute. Tasks's state are pesisted in `gateway.db`, see more at `../../../crates/provisioner-task-libsql/`. 


# Invariants

## Management
Once a provisioner gets a successful answer to its start request, the Task is never lost and never stuck, even if Gateway restarts: it ends in success or failure, within its limit of attempts and its deadline.
It may end in failure, such as `keyLost`.
Gateway does not handle a database failure, such as a failed write to `gateway.db` or to the job queue, since it cannot be handled reasonably.
Provisioner tasks run inside a job.
Recovery from a crashed Gateway is managed by the job queue: when Gateway starts, it delivers again every job it had not finished.
The job keeps only the ID of its Provisioner Task and the job token recorded with it, and runs the Provisioner Task only if the two tokens match.
The record keeps the attempts, the deadline, the payload and the end of a Provisioner Task, and each kind keeps its own progress, such as the working files of an AI analysis, so a job delivered again picks up where the last one left off.
A job delivered again in the middle of an attempt starts a new one, which counts toward the limit of attempts; with none left, the Provisioner Task fails as `internal`.
Recoverable errors are recovered within the task job itself, which waits and runs the next attempt up to the limit, and are never handed to the job queue.
The job returns an error to the job queue only when it cannot read or write the record, cannot publish the result of a success, or cannot finish what a Provisioner Task leaves to do once it ends; the job queue then runs the job again.
The handlers only record the Provisioner Task with its job and keep the secrets it needs, and never take part in its execution.
Reading a Provisioner Task past its deadline fails it.

## Failures
The error in the payload of a failed Provisioner Task is its permanent error, giving up included, as a closed set of kinds without text for people, because Gateway does not translate: the caller words it.


## Naming
A Provisioner Task is a long-running task a provisioner asks Gateway to do.
Its record, in `gateway.db`, and its job, on the job queue, are only the means to carry it out.

## Secrets
Secrets a Task needs, such as an API key or a base URL that may carry credentials, never reach the disk: not `gateway.db`, not the job, not the logs.
They are kept encrypted in memory, in the `SecretStore`, until the Task ends or reaches its deadline.
After a Gateway restart they are gone, and the Tasks that needed them fail; this is accepted.

## AI analysis
Only a finished recording is analyzed.
A session that mixes terminal and video recordings cannot be analyzed.
Two analyses of the same session never run at the same time.
An analysis keeps working files next to the recording, so a retry can pick up where it stopped. When a Task ends, it deletes its own working files, whether it succeeded or failed. A new Task first deletes any working files an earlier analysis left behind. A Task never deletes another Task's working files.
A session keeps one AI analysis: a new Task replaces the earlier one atomically once it succeeds. Keeping one analysis per language is a future extension that must stay possible.
The only guarantee on results is that a succeeded Task always has its result persisted: its log is listed in the manifest before `succeeded` is written. Any other outcome may leave anything behind, and the provisioner runs the analysis again.
A recoverable failure, such as a rate limit (429), is retried within the job, and each retry continues from the progress saved so far; only a new Task starts over. A Gateway restart loses the API key, so an unfinished Task fails with `keyLost` at its next attempt, without a retry; this is enforced for security, since the key never reaches the disk.
A rate limit, a server error, a lost connection or a request timeout is recoverable; a refused API key (401), a spent quota, or an answer the model cut short or refused is permanent.
An AI analysis fails if it hasn't started within 2 hours. Once it runs, it fails only after 30 minutes without progress, so a long recording that keeps making progress is never cut off. Each request to the AI times out after 10 minutes and is retried like any other recoverable failure.
An analysis does not wait for Gateway to remux the session's videos: it reads the tracks, the cluster timestamps and the blocks of a WebM in order, which a remux does not change, and a remux replaces the file by renaming its output over it, so an analysis that has the file open keeps reading what it opened.
