# Background
Provisioner tasks are tasks issued for Gateway to execute. Tasks's state are pesisted in `gateway.db`, see more at `../../../crates/provisioner-task-libsql/`. 


# Invariants

## Management
`ProvisionerTaskManager` MUST be the only place touches both the Task records and the job queue. It is also the only place that manages how tasks are executed in relation to the job queue.

A provisioner task only defines it's work: what one attempt does, and what to drop once its task ends. The coordination belongs to the `ProvisionerTaskManager`.

The task record is the source of truth; the `TaskJob` only wakes it up and holds no state.

One task at the same time only has one job to execute task.

Jobs doesn't have state, tasks do. 

An attempt error is recoverable or permanent: a recoverable one is retried with the job up to a limit, and a permanent one fails the Task at once. A failed Task's payload is that permanent error, giving up included, as a closed set of kinds without text for people, because Gateway does not translate: the caller words it.

When Gateway starts, it gives a new job to every unfinished Task that has none. This can happen if Gateway stopped after saving a Task but before saving its job. Gateway starts the job without checking whether the Task can still succeed: each kind of Task decides that for itself. For example, an AI analysis fails because its key is gone. If the new job can't be saved, the Task fails.


## Naming
`ProvisionerTask` is the work itself; `ProvisionerTaskRecord` is what is stored about it.

## Secrets
Secrets a Task needs, such as an API key or a base URL that may carry credentials, never reach the disk: not `gateway.db`, not the job, not the logs.
They are kept encrypted in memory, in the `SecretStore`, until the Task ends or reaches its deadline.
After a Gateway restart they are gone, and the Tasks that needed them fail; this is accepted.

## AI analysis
Only a finished recording is analyzed.
A session that mixes terminal and video recordings cannot be analyzed.
Two analyses of the same session never run at the same time.
An analysis keeps working files next to the recording, so a retry can pick up where it stopped. When a Task ends, it deletes its own working files, whether it succeeded or failed. A new Task first deletes any working files an earlier analysis left behind. A Task never deletes another Task's working files.
A session keeps one AI analysis: a new Task replaces the earlier one atomically once it succeeds, and a Task that fails leaves the earlier one in place. Keeping one analysis per language is a future extension that must stay possible.
A Task succeeds only once its success is recorded in `gateway.db`. Until then, its new log sits in the session unlisted and the earlier analysis stays. After that, the manifest lists the new log and drops the earlier one; if this last step is cut short, Gateway does it again when the Task ends and when Gateway starts.
A recoverable failure, such as a rate limit (429), is retried with the job, and each retry continues from the progress saved so far; only a new Task starts over. A Task that fails keeps its record, but removes everything it produced, leaving no file on disk, even if that wastes the money already spent, because an analysis missing a large part would mislead whoever searches it, more than the misses of a nondeterministic AI already do. A Gateway restart loses the API key, so an unfinished Task fails with `keyLost` at its next attempt, without a retry.
A rate limit, a server error, a lost connection or a request timeout is recoverable; a refused API key (401), a spent quota, or an answer the model cut short or refused is permanent.
An AI analysis fails if it hasn't started within 2 hours. Once it runs, it fails only after 30 minutes without progress, so a long recording that keeps making progress is never cut off. Each request to the AI times out after 10 minutes and is retried like any other recoverable failure.
An analysis waits until Gateway has finished remuxing the session's videos, because remuxing replaces the file the analysis reads. Waiting is not progress, since remuxing should not take that long.
