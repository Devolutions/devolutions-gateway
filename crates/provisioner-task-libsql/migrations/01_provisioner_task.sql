CREATE TABLE provisioner_task_records (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    params TEXT NOT NULL,
    state TEXT NOT NULL,
    payload TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    started_at INTEGER,
    finished_at INTEGER,
    deadline_at INTEGER NOT NULL,
    CHECK (state IN ('queued', 'running', 'succeeded', 'failed')),
    CHECK ((state IN ('succeeded', 'failed')) = (finished_at IS NOT NULL)),
    CHECK (json_valid(params) AND json_valid(payload)),
    CHECK (attempts >= 0)
);

CREATE UNIQUE INDEX provisioner_task_records_unfinished ON provisioner_task_records (kind, target)
    WHERE state IN ('queued', 'running');

CREATE TABLE provisioner_task_metadata (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
