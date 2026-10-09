# Background
This crate stores provisioner Task records in `gateway.db`, implementing `ProvisionerTaskStore` from `provisioner-task`.
The states and transitions of a Task are defined in `../provisioner-task/INTENT.md`.

# Invariants

## Tables and migrations
The tables of this crate are named with the `provisioner_task_` prefix; the prefix is the compatibility boundary.
This crate alone creates and migrates its tables, and its migrations are append-only.
Its schema version is the `schema_version` row of `provisioner_task_metadata`, never the file's `PRAGMA user_version`.
This crate may depend on `gateway-db`, never the other way around.

## Records
For a given kind and target, at most one record can be unfinished.

A record past its deadline is failed.

Each change of state is atomic: a record is never seen half moved from one state to another.

## Secrets
Records never hold secrets: parameters and payloads are stored as given, in clear.