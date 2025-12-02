//! Traffic audit schema migration tests.
//!
//! These tests verify that the gateway correctly migrates the traffic audit
//! database from the old INTEGER id schema to the new ULID (BLOB) schema.

use std::path::Path;

use anyhow::Context as _;
use testsuite::cli::{dgw_tokio_cmd, wait_for_tcp_port};
use testsuite::dgw_config::{DgwConfig, DgwConfigHandle, VerbosityProfile};
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
async fn create_old_schema_database(path: &Path) -> anyhow::Result<()> {
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
async fn check_schema_is_blob(path: &Path) -> anyhow::Result<bool> {
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

/// Starts a gateway instance using the given config handle.
///
/// The gateway will use the default `traffic_audit.db` path within the config directory.
/// Waits for the gateway to become ready by polling the HTTP port.
async fn start_gateway(config_handle: &DgwConfigHandle) -> anyhow::Result<Child> {
    let process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to start Devolutions Gateway")?;

    // Wait until the gateway is accepting connections on the HTTP port.
    wait_for_tcp_port(config_handle.http_port()).await?;

    Ok(process)
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
    // Initialize config (creates the temp directory and config file).
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .verbosity_profile(VerbosityProfile::DEBUG)
        .build()
        .init()
        .context("init config")?;

    let db_path = config_handle.config_dir().join("traffic_audit.db");

    // 1) Create old schema database at the default path.
    create_old_schema_database(&db_path).await?;

    // Verify the old schema has INTEGER id.
    let is_blob_before = check_schema_is_blob(&db_path).await?;
    assert!(!is_blob_before, "database should have INTEGER id before gateway starts");

    // 2) Start the gateway (it will use the default traffic_audit.db path).
    let mut process = start_gateway(&config_handle).await?;

    // 3) Stop the gateway.
    process.kill().await.context("kill gateway process")?;
    let _ = process.wait().await;

    // 4) Verify the schema was migrated to BLOB.
    let is_blob_after = check_schema_is_blob(&db_path).await?;
    assert!(is_blob_after, "database should have BLOB id after gateway migration");

    Ok(())
}
