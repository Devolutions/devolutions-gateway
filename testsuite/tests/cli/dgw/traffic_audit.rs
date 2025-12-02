//! Traffic audit schema migration tests.
//!
//! These tests verify that the gateway correctly migrates the traffic audit
//! database from the old INTEGER id schema to the new ULID (BLOB) schema.

use anyhow::Context as _;
use testsuite::cli::{dgw_tokio_cmd, wait_for_tcp_port};
use tokio::process::Child;

/// The old schema with INTEGER PRIMARY KEY (before ULID migration).
///
/// This is the schema that was used before the ULID migration.
/// The gateway should automatically detect this and reset the database.
const OLD_SCHEMA_SQL: &str = r#"
CREATE TABLE traffic_events (
    id INTEGER PRIMARY KEY,
    session_id BLOB NOT NULL,
    outcome INTEGER NOT NULL CHECK (outcome IN (0, 1, 2)),
    protocol INTEGER NOT NULL CHECK (protocol IN (0, 1)),
    target_host TEXT NOT NULL,
    target_ip_family INTEGER NOT NULL CHECK (target_ip_family IN (4, 6)),
    target_ip BLOB NOT NULL,
    target_port INTEGER NOT NULL CHECK (target_port >= 0 AND target_port <= 65535),
    connect_at_ms INTEGER NOT NULL,
    disconnect_at_ms INTEGER NOT NULL,
    active_duration_ms INTEGER NOT NULL CHECK (active_duration_ms >= 0),
    bytes_tx INTEGER NOT NULL CHECK (bytes_tx >= 0),
    bytes_rx INTEGER NOT NULL CHECK (bytes_rx >= 0),
    enqueued_at_ms INTEGER NOT NULL DEFAULT (unixepoch('subsec') * 1000),
    locked_by TEXT NULL,
    lock_until_ms INTEGER NULL
) STRICT;

CREATE INDEX te_session_time ON traffic_events(session_id, connect_at_ms);
CREATE INDEX te_lease_scan ON traffic_events(lock_until_ms, id);
CREATE INDEX te_network_endpoint ON traffic_events(target_ip_family, target_ip, target_port, connect_at_ms);
CREATE INDEX te_outcome_time ON traffic_events(outcome, connect_at_ms);

PRAGMA user_version = 1;
"#;

/// Creates an old-schema database at the given path.
async fn create_old_schema_database(path: &str) -> anyhow::Result<()> {
    let conn = libsql::Builder::new_local(path)
        .build()
        .await
        .context("failed to open libSQL connection")?
        .connect()
        .context("failed to connect to libSQL")?;

    conn.execute_batch(OLD_SCHEMA_SQL)
        .await
        .context("failed to create old schema")?;

    Ok(())
}

/// Checks if the database has the new BLOB id schema.
///
/// Returns Ok(true) if the id column is BLOB, Ok(false) if INTEGER, or an error.
async fn check_schema_is_blob(path: &str) -> anyhow::Result<bool> {
    let conn = libsql::Builder::new_local(path)
        .build()
        .await
        .context("failed to open libSQL connection")?
        .connect()
        .context("failed to connect to libSQL")?;

    // Check if traffic_events table exists.
    let table_check = "SELECT name FROM sqlite_master WHERE type='table' AND name='traffic_events'";
    let mut rows = conn
        .query(table_check, ())
        .await
        .context("failed to check table existence")?;

    if rows.next().await.context("read table check")?.is_none() {
        anyhow::bail!("traffic_events table does not exist after migration");
    }

    // Check the id column type.
    let pragma = "PRAGMA table_info(traffic_events)";
    let mut rows = conn.query(pragma, ()).await.context("failed to query table info")?;

    while let Some(row) = rows.next().await.context("read table info row")? {
        let col_name: String = row.get(1).context("get column name")?;
        if col_name == "id" {
            let col_type: String = row.get(2).context("get column type")?;
            // New schema uses BLOB, old schema uses INTEGER.
            return Ok(col_type.eq_ignore_ascii_case("BLOB"));
        }
    }

    anyhow::bail!("id column not found in traffic_events table");
}

/// Starts a gateway instance using the given config directory.
///
/// The gateway will use the default `traffic_audit.db` path within the config directory.
/// Waits for the gateway to become ready by polling the health endpoint.
async fn start_gateway(config_dir: &std::path::Path) -> anyhow::Result<Child> {
    let config_path = config_dir.join("gateway.json");

    let tcp_port = find_unused_port();
    let http_port = find_unused_port();

    let config = format!(
        r#"{{
    "ProvisionerPublicKeyData": {{
        "Value": "mMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4vuqLOkl1pWobt6su1XO9VskgCAwevEGs6kkNjJQBwkGnPKYLmNF1E/af1yCocfVn/OnPf9e4x+lXVyZ6LMDJxFxu+axdgOq3Ld392J1iAEbfvwlyRFnEXFOJNyylqg3bY6LvnWHL/XZczVdMD9xYfq2sO9bg3xjRW4s7r9EEYOFjqVT3VFznH9iWJVtcSEKukmS/3uKoO6lGhacvu0HgjXXdgq0R8zvR4XRJ9Fcnf0f9Ypoc+i6L80NVjrRCeVOH+Ld/2fA9bocpfLarcVqG3RjS+qgOtpyCc0jWVFF4zaGQ7LUDFkEIYILkICeMMn2ll29hmZNzsJzZJ9s6NocgQIDAQAB"
    }},
    "Listeners": [
        {{
            "InternalUrl": "tcp://127.0.0.1:{tcp_port}",
            "ExternalUrl": "tcp://127.0.0.1:{tcp_port}"
        }},
        {{
            "InternalUrl": "http://127.0.0.1:{http_port}",
            "ExternalUrl": "http://127.0.0.1:{http_port}"
        }}
    ],
    "VerbosityProfile": "Debug",
    "__debug__": {{
        "disable_token_validation": true
    }}
}}"#
    );

    std::fs::write(&config_path, config).with_context(|| format!("write config to {}", config_path.display()))?;

    let process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_dir)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to start Devolutions Gateway")?;

    // Wait until the gateway is accepting connections on the HTTP port.
    wait_for_tcp_port(http_port).await?;

    Ok(process)
}

fn find_unused_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Test that the gateway migrates from INTEGER id to BLOB (ULID) id.
///
/// This test:
/// 1. Creates a database with the old INTEGER id schema at the default path
/// 2. Starts the gateway (which will use the default traffic_audit.db path)
/// 3. Stops the gateway
/// 4. Verifies the database now has the new BLOB id schema
#[tokio::test]
async fn old_integer_schema_is_reset_to_blob_schema() -> anyhow::Result<()> {
    // Create a temporary directory that will serve as the config directory.
    // The gateway will look for traffic_audit.db in this directory by default.
    let config_dir = tempfile::tempdir().context("create tempdir")?;
    let db_path = config_dir.path().join("traffic_audit.db");
    let db_path_str = db_path.to_str().unwrap();

    // 1) Create old schema database with seed data at the default path.
    create_old_schema_database(db_path_str).await?;

    // Verify the old schema has INTEGER id.
    let is_blob_before = check_schema_is_blob(db_path_str).await?;
    assert!(!is_blob_before, "database should have INTEGER id before gateway starts");

    // 2) Start the gateway (it will use the default traffic_audit.db path).
    let mut process = start_gateway(config_dir.path()).await?;

    // 3) Stop the gateway.
    process.kill().await.context("kill gateway process")?;
    let _ = process.wait().await;

    // 4) Verify the schema was migrated to BLOB.
    let is_blob_after = check_schema_is_blob(db_path_str).await?;
    assert!(is_blob_after, "database should have BLOB id after gateway migration");

    Ok(())
}
