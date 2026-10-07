# Background
Gateway needs a database to store information for certain features.

# Invariants
For each domain operations, the `gateway-db` crate should have its domain mod, for example `gateway_db::agent_tunnel::{functions}`.
For each domain table, the table should have its prefix in table's name, for example, `agent_tunnel_*` for agent tunnel domain tables.
The database migration files must live at `crates/gateway-db/migrations`. Any new migration file in `lib.rs` `MIGRATIONS` constant array, and it's append-only. NEVER remove, reorder any migration file from the list.
  

# Goals
All persistent state except the job queue and traffic audit should be stored in this database.


# Upgrade from 2026.3
If for 2026.3, user turned on the feature of agent-tunnel, then the database will be migrated from `agent_tunnel.db` to `gateway.db`. The migration will be done automatically on Gateway start up. This is one-off, atomic operation.