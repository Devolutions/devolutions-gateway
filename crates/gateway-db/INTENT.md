# Background
Gateway needs a database to store information for certain features.

# Invariants
`gateway-db` only owns the shared `gateway.db` file: it opens the file, applies the PRAGMAs, and hands out a connection per feature.

`gateway-db` must never depend on crates that implement feature behavior, such as `agent-tunnel`. Adapters (for example `agent-tunnel-libsql`) may depend on `gateway-db`, never the other way around.

For each domain table, the table should have its prefix in table's name, for example, `agent_tunnel_*` for agent tunnel domain tables. The prefix is the compatibility boundary.

`gateway-db` does not read or write `PRAGMA user_version`. Each adapter owns its migrations and tracks its own schema version within its prefixed tables, for example as a row in `agent_tunnel_metadata`. Migrations are append-only. NEVER remove or reorder a migration.
  

# Goals
All persistent state except the job queue and traffic audit should be stored in this database.


# Upgrade from 2026.3
If for 2026.3, user turned on the feature of agent-tunnel, then the database will be migrated from `agent_tunnel.db` to `gateway.db`. The migration will be done automatically on Gateway start up. This is one-off, atomic operation.

# Future
Later, `gateway-db` could take migrations from each adapter.
An adapter would pass its prefix and its list of migrations, and `gateway-db` would run them and track a version per prefix