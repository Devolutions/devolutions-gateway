# gateway-db

This crate owns the shared `gateway.db` file and nothing else.
Read `INTENT.md` in this directory first.

- Never add a dependency on a crate that implements feature behavior, such as `agent-tunnel` or `agent-tunnel-libsql`.
  A feature's tables, migrations and schema version belong in its own adapter crate, which may depend on `gateway-db`.
- Never read or write `PRAGMA user_version` here: no single crate owns every table in the file.
- After changing `Cargo.toml`, run `cargo tree -p gateway-db --edges normal --depth 1` and check that only generic crates are listed.
