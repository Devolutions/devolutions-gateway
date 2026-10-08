# Background
Provisioner tasks are tasks issued for Gateway to execute. Tasks's state are pesisted in `gateway.db`, see more at `../crates/provisioner-task-libsql/README.md`. 


# Invariants

## Management
`ProvisionerTaskRunner` MUST be the only place touches both the Task records and the job queue.
A provisioner task only defines it's work: what one attempt does, and what to drop once its task ends.
The task record is the source of truth; the `ProvisionerTaskJob` only wakes it up and holds no state.
One task at the same time only has one job to execute task.


## Naming
`ProvisionerTask` is the work itself; `ProvisionerTaskRecord` is what is stored about it.

## Secrets
Secrets a Task needs, such as an API key, never reach the disk: not `gateway.db`, not the job, not the logs.
They are kept encrypted in memory, in the provisioning store, until the Task ends or reaches its deadline.
After a Gateway restart they are gone, and the Tasks that needed them fail; this is accepted.

## AI analysis
Only a finished recording is analyzed.
A session that mixes terminal and video recordings cannot be analyzed.
Two analyses of the same session never run at the same time.