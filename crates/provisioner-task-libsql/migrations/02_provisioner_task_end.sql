ALTER TABLE provisioner_task_records ADD COLUMN ended_at INTEGER CHECK (ended_at IS NULL OR finished_at IS NOT NULL);

CREATE INDEX provisioner_task_records_unended ON provisioner_task_records (finished_at)
    WHERE finished_at IS NOT NULL AND ended_at IS NULL;
