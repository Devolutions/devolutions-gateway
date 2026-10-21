# Background
Provisioner tasks are tasks issued for Gateway to execute. Tasks's state are pesisted in `gateway.db`, see more at `../../../crates/provisioner-task-libsql/`. 


# Invariants

## Management
`ProvisionerTaskRunner` MUST be the only place touches both the Task records and the job queue. It is also the only place that manages how tasks are executed in relation to the job queue.

A provisioner task only defines it's work: what one attempt does, and what to drop once its task ends. The coordination belongs to the `ProvisionerTaskRunner`.

The task record is the source of truth; the `ProvisionerTaskJob` only wakes it up and holds no state.

One task at the same time only has one job to execute task.

Jobs doesn't have state, tasks do. 


## Naming
`ProvisionerTask` is the work itself; `ProvisionerTaskRecord` is what is stored about it.

## Secrets
Secrets a Task needs, such as an API key, never reach the disk: not `gateway.db`, not the job, not the logs.
They are kept encrypted in memory, in the `SecretStore`, until the Task ends or reaches its deadline.
After a Gateway restart they are gone, and the Tasks that needed them fail; this is accepted.

## AI analysis
Only a finished recording is analyzed.
A session that mixes terminal and video recordings cannot be analyzed.
Two analyses of the same session never run at the same time.
A session keeps one AI analysis: a new Task removes the earlier one when it starts, and a Task that fails leaves nothing, so the session then has none. Keeping one analysis per language is a future extension that must stay possible.
A transient failure such as a rate limit (429) is retried with the job, and each retry resumes where the last attempt stopped; only a new Task starts over. A Gateway restart loses the API key, so an unfinished Task fails as "key lost" at its next attempt, without a retry, and leaves nothing.