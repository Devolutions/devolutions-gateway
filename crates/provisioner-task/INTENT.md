# Background
Provisioner Tasks are work that a provisioner (DVLS, Hub) assigns to Gateway.

# Invariants
The provisioner chooses each Task's ID, so it can ask again without knowing whether its first request went through.

A Task is in one of these states: `Queued`, `Running`, `Succeeded`, `Failed`.
`Running`, `Succeeded` and `Failed` carry a payload whose shape belongs to the Task kind; `Queued` carries none.
Only these transitions exist:
- `Queued` -> `Running`
- `Queued` -> `Failed`
- `Running` -> `Running`, to replace the payload, such as with progress
- `Running` -> `Succeeded`
- `Running` -> `Failed`

Each Task has a deadline counted from when Gateway receives it.
An unfinished Task past its deadline is failed, so a lost job can't block its target forever.

# Tasks and jobs
A Task is not a job.
A Task keeps what was asked, how it went and how it ended, and stays for auditing after its job is gone; the job queue only schedules and retries the work.
