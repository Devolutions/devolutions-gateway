# Background
Provisioner Tasks (hereafter "Tasks") are work that a provisioner (DVLS, Hub) assigns to Gateway.

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

Each Task has a deadline.
While the Task runs, its deadline may move forward each time it makes progress.
Some work has no known length: a recording can be arbitrarily long, so any fixed deadline would leave some recordings impossible to analyze.
With a moving deadline, a Task fails only once it stops making progress, however long it runs.
An unfinished Task past its deadline is failed, so a lost job can't block its target forever.

# Tasks and jobs
A Task is not a job.
A Task keeps what was asked, how it went and how it ended, and stays for auditing after its job is gone; the job queue only delivers the job, and the job runs and retries the attempts itself.
