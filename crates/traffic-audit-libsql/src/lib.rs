#[macro_use]
extern crate tracing;

use anyhow::Context as _;
use async_trait::async_trait;
use libsql::Connection;
use traffic_audit::{ClaimedEvent, TrafficAuditRepo, TrafficEvent};
use ulid::Ulid;
use uuid::Uuid;

pub use libsql;

// Migration constants - these will be used by the migration system
const MIGRATIONS: &[&str] = &[
    // Migration 0 - Initial schema
    include_str!("../migrations/01_traffic_events.sql"),
];

/// Implementation of [`TrafficAuditRepo`] repository using libSQL as the backend.
///
/// This follows the same patterns as the job-queue-libsql implementation,
/// providing multi-consumer safe claim/ack semantics with lease-based locking.
/// Events are stored temporarily and deleted after acknowledgment.
pub struct LibSqlTrafficAuditRepo {
    // WARNING: It’s not possible to share the Connection object, because we are using transactions.
    // SQLite / Turso databases do not support transactions on the same
    // connection object, you need to open a separate connection to the same database
    // for concurrent operations.
    conn: Connection,
    id_generator: std::sync::Mutex<ulid::Generator>,
}

impl LibSqlTrafficAuditRepo {
    /// Opens a new LibSQL connection and creates a repository instance.
    ///
    /// The path can be:
    /// - A file path for local SQLite (e.g., "/path/to/audit.db")
    /// - ":memory:" for in-memory database
    ///
    /// If an old schema (with INTEGER id column) is detected, the database file
    /// is automatically deleted and recreated with the new ULID-based schema.
    ///
    /// TODO(2027): Remove old schema detection and reset logic.
    /// This migration code can be safely removed after all deployed
    /// Gateways have been upgraded past this version.
    pub async fn open(path: &str) -> anyhow::Result<Self> {
        let conn = open_connection(path).await?;

        // Check for old schema and reset if necessary.
        if has_old_integer_schema(&conn).await? {
            warn!("Detected old traffic audit schema with INTEGER id; resetting database");

            // Drop the connection before deleting files.
            drop(conn);

            // Delete database files (main file + WAL + SHM).
            if path != ":memory:" {
                delete_database_files(path)?;
            }

            // Reopen with fresh connection.
            let conn = open_connection(path).await?;
            return Ok(Self {
                conn,
                id_generator: std::sync::Mutex::new(ulid::Generator::new()),
            });
        }

        return Ok(Self {
            conn,
            id_generator: std::sync::Mutex::new(ulid::Generator::new()),
        });

        async fn open_connection(path: &str) -> anyhow::Result<Connection> {
            libsql::Builder::new_local(path)
                .build()
                .await
                .context("failed to open libSQL connection")?
                .connect()
                .context("failed to connect to libSQL")
        }

        /// Checks if the database has the old schema with INTEGER id column.
        ///
        /// Returns `true` if the `traffic_events` table exists and has an INTEGER id column,
        /// indicating the old schema that needs to be reset.
        ///
        /// TODO(2027): Remove this method along with the schema reset logic.
        async fn has_old_integer_schema(conn: &Connection) -> anyhow::Result<bool> {
            // Check if the traffic_events table exists.
            let table_exists_query = "SELECT name FROM sqlite_master WHERE type='table' AND name='traffic_events'";

            let mut rows = conn
                .query(table_exists_query, ())
                .await
                .context("failed to check if traffic_events table exists")?;

            if rows
                .next()
                .await
                .context("failed to read table check result")?
                .is_none()
            {
                // Table doesn't exist, so no old schema.
                return Ok(false);
            }

            // Table exists, check if id column is INTEGER.
            let pragma_query = "PRAGMA table_info(traffic_events)";

            let mut rows = conn
                .query(pragma_query, ())
                .await
                .context("failed to query table info")?;

            while let Some(row) = rows.next().await.context("failed to read table info row")? {
                let col_name: String = row.get(1).context("failed to get column name")?;
                if col_name == "id" {
                    let col_type: String = row.get(2).context("failed to get column type")?;
                    // SQLite stores "INTEGER" for INTEGER PRIMARY KEY columns.
                    return Ok(col_type.eq_ignore_ascii_case("INTEGER"));
                }
            }

            // No id column found (unexpected), treat as no old schema.
            Ok(false)
        }

        /// Deletes the database file and associated WAL/SHM files.
        ///
        /// TODO(2027): Remove this method along with the schema reset logic.
        fn delete_database_files(path: &str) -> anyhow::Result<()> {
            use std::fs;
            use std::path::Path;

            let db_path = Path::new(path);

            // Delete main database file.
            if db_path.exists() {
                fs::remove_file(db_path).with_context(|| format!("failed to delete database file: {path}"))?;
                info!(%path, "Deleted old traffic audit database file");
            }

            // Delete WAL file if present.
            let wal_path = format!("{path}-wal");
            if Path::new(&wal_path).exists() {
                fs::remove_file(&wal_path).with_context(|| format!("failed to delete WAL file: {wal_path}"))?;
                trace!(%wal_path, "Deleted WAL file");
            }

            // Delete SHM file if present.
            let shm_path = format!("{path}-shm");
            if Path::new(&shm_path).exists() {
                fs::remove_file(&shm_path).with_context(|| format!("failed to delete SHM file: {shm_path}"))?;
                trace!(%shm_path, "Deleted SHM file");
            }

            Ok(())
        }
    }

    async fn apply_pragmas(&self) -> anyhow::Result<()> {
        const PRAGMAS: &str = "
            -- https://www.sqlite.org/pragma.html#pragma_journal_mode
            -- Use a write-ahead log instead of a rollback journal to implement transactions.
            PRAGMA journal_mode = WAL;

            -- https://www.sqlite.org/pragma.html#pragma_synchronous
            -- TLDR: journal_mode WAL + synchronous NORMAL is a good combination.
            -- WAL mode is safe from corruption with synchronous=NORMAL
            -- The synchronous=NORMAL setting is a good choice for most applications running in WAL mode.
            PRAGMA synchronous = NORMAL;

            -- https://www.sqlite.org/pragma.html#pragma_busy_timeout
            -- Prevents SQLITE_BUSY errors by giving a timeout to wait for a locked resource before
            -- returning an error, useful for handling multiple concurrent accesses.
            -- 15 seconds is a good value for a backend application like a job queue.
            PRAGMA busy_timeout = 15000;

            -- https://www.sqlite.org/pragma.html#pragma_cache_size
            -- Reduce the number of disks reads by allowing more data to be cached in memory (3MB).
            PRAGMA cache_size = -3000;

            -- https://www.sqlite.org/pragma.html#pragma_auto_vacuum
            -- Reclaims disk space gradually as rows are deleted, instead of performing a full vacuum,
            -- reducing performance impact during database operations.
            PRAGMA auto_vacuum = INCREMENTAL;

            -- https://www.sqlite.org/pragma.html#pragma_temp_store
            -- Store temporary tables and data in memory for better performance
            PRAGMA temp_store = MEMORY;
        ";

        trace!(sql_query = %PRAGMAS, "PRAGMAs query");

        let mut batch_rows = self
            .conn
            .execute_batch(PRAGMAS)
            .await
            .context("failed to batch execute SQL query")?;

        while let Some(rows) = batch_rows.next_stmt_row() {
            let Some(mut rows) = rows else {
                continue;
            };

            while let Ok(Some(row)) = rows.next().await {
                trace!(?row, "PRAGMA row");
            }
        }

        Ok(())
    }

    async fn migrate(&self) -> anyhow::Result<()> {
        let user_version = self.query_user_version().await?;

        match MIGRATIONS.get(user_version..) {
            Some(remaining) if !remaining.is_empty() => {
                info!(
                    user_version,
                    migration_count = MIGRATIONS.len() - user_version,
                    "Start migration"
                );

                for (sql_query, migration_id) in remaining.iter().zip(user_version..MIGRATIONS.len()) {
                    trace!(migration_id, %sql_query, "Apply migration");

                    self.conn
                        .execute_batch(sql_query)
                        .await
                        .with_context(|| format!("failed to execute migration {migration_id}"))?;

                    trace!(migration_id, "Applied migration");

                    self.update_user_version(migration_id + 1)
                        .await
                        .context("failed to update user version")?;
                }

                info!("Migration complete");
            }
            None => {
                warn!(user_version, "user_version is set to an unexpected value");
            }
            _ => {
                debug!(user_version, "Database is already up to date");
            }
        }

        Ok(())
    }

    async fn query_user_version(&self) -> anyhow::Result<usize> {
        let sql_query = "PRAGMA user_version";

        trace!(%sql_query, "Query user_version");

        let row = self
            .conn
            .query(sql_query, ())
            .await
            .context("failed to execute SQL query")?
            .next()
            .await
            .context("failed to read the row")?
            .context("no row returned")?;

        let value = row.get::<u64>(0).context("failed to read user_version value")?;

        Ok(usize::try_from(value).expect("number not too big"))
    }

    async fn update_user_version(&self, value: usize) -> anyhow::Result<()> {
        let value = u64::try_from(value).expect("number not too big");

        let sql_query = format!("PRAGMA user_version = {value}");

        trace!(%sql_query, "Update user_version");

        self.conn
            .execute(&sql_query, ())
            .await
            .context("failed to execute SQL query")?;

        Ok(())
    }
}

#[async_trait]
impl TrafficAuditRepo for LibSqlTrafficAuditRepo {
    async fn setup(&self) -> anyhow::Result<()> {
        self.apply_pragmas().await?;
        self.migrate().await?;
        Ok(())
    }

    async fn push(&self, event: TrafficEvent) -> anyhow::Result<()> {
        let id = self
            .id_generator
            .lock()
            .expect("non-poisoned")
            .generate()
            .context("generate ID")?;

        // Begin transaction
        self.conn
            .execute("BEGIN IMMEDIATE", ())
            .await
            .context("failed to begin transaction")?;

        let sql_query = "INSERT INTO traffic_events
            (id, session_id, outcome, protocol, target_host, target_ip_family, target_ip, target_port,
             connect_at_ms, disconnect_at_ms, active_duration_ms, bytes_tx, bytes_rx)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        let id_blob = ulid_to_blob(&id);
        let session_id_blob = uuid_to_blob(&event.session_id);
        let outcome_db = outcome_to_db(&event.outcome);
        let protocol_db = protocol_to_db(&event.protocol);
        let (target_ip_family, target_ip_blob) = ip_to_blob(&event.target_ip);

        let params = (
            id_blob,
            session_id_blob,
            outcome_db,
            protocol_db,
            event.target_host.clone(),
            target_ip_family,
            target_ip_blob,
            i64::from(event.target_port),
            event.connect_at_ms,
            event.disconnect_at_ms,
            event.active_duration_ms,
            i64::try_from(event.bytes_tx).unwrap_or(i64::MAX),
            i64::try_from(event.bytes_rx).unwrap_or(i64::MAX),
        );

        trace!(%event.session_id, %event.target_host, "Pushing traffic event");

        // Execute the insert
        match self.conn.execute(sql_query, params).await {
            Ok(_) => {
                // Commit transaction
                self.conn
                    .execute("COMMIT", ())
                    .await
                    .context("failed to commit transaction")?;
                Ok(())
            }
            Err(e) => {
                // Rollback on error
                let _ = self.conn.execute("ROLLBACK", ()).await;
                Err(e).context("failed to execute insert")
            }
        }
    }

    async fn claim(
        &self,
        consumer_id: &str,
        lease_duration_ms: u32,
        limit: usize,
    ) -> anyhow::Result<Vec<ClaimedEvent>> {
        let now = now_ms();
        let lock_until = now + i64::from(lease_duration_ms);

        trace!(consumer_id, lease_duration_ms, limit, "Starting claim operation");

        // Begin transaction for atomic claim operation
        self.conn
            .execute("BEGIN IMMEDIATE", ())
            .await
            .context("failed to begin claim transaction")?;

        // Step 1: Find available events ordered by ID ASC (ULID is lexicographically sortable)
        let find_query = "SELECT id FROM traffic_events
            WHERE (lock_until_ms IS NULL OR lock_until_ms <= ?)
            ORDER BY id ASC
            LIMIT ?";

        let mut rows = match self
            .conn
            .query(find_query, (now, i64::try_from(limit).unwrap_or(i64::MAX)))
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                let _ = self.conn.execute("ROLLBACK", ()).await;
                return Err(anyhow::Error::from(e).context("failed to find available events"));
            }
        };

        // Collect available IDs as BLOBs.
        let mut available_ids: Vec<Vec<u8>> = Vec::new();
        loop {
            let row = match rows.next().await {
                Ok(Some(row)) => row,
                Ok(None) => break,
                Err(e) => {
                    let _ = self.conn.execute("ROLLBACK", ()).await;
                    return Err(anyhow::Error::from(e).context("failed to read available event IDs"));
                }
            };

            let id_blob: Vec<u8> = row.get(0).context("failed to get event ID")?;
            available_ids.push(id_blob);
        }

        if available_ids.is_empty() {
            // No events to claim, commit and return empty.
            self.conn
                .execute("COMMIT", ())
                .await
                .context("failed to commit empty claim transaction")?;
            trace!("No events available to claim");
            return Ok(Vec::new());
        }

        // Step 2: Lock the available events
        let lock_query = format!(
            "UPDATE traffic_events
             SET locked_by = ?, lock_until_ms = ?
             WHERE id IN ({})",
            repeat_qm(available_ids.len())
        );

        let mut lock_params: Vec<libsql::Value> =
            vec![libsql::Value::from(consumer_id), libsql::Value::from(lock_until)];
        for id_blob in &available_ids {
            lock_params.push(libsql::Value::from(id_blob.clone()));
        }

        if let Err(e) = self.conn.execute(&lock_query, lock_params).await {
            let _ = self.conn.execute("ROLLBACK", ()).await;
            return Err(anyhow::Error::new(e).context("failed to lock events"));
        }

        // Step 3: Retrieve full event data for locked events
        let select_query = format!(
            "SELECT id, session_id, outcome, protocol, target_host,
                    target_ip_family, target_ip, target_port, connect_at_ms, disconnect_at_ms,
                    active_duration_ms, bytes_tx, bytes_rx
             FROM traffic_events
             WHERE id IN ({})
             ORDER BY id ASC",
            repeat_qm(available_ids.len())
        );

        let select_params: Vec<libsql::Value> =
            available_ids.iter().map(|id| libsql::Value::from(id.clone())).collect();

        let mut rows = match self.conn.query(&select_query, select_params).await {
            Ok(rows) => rows,
            Err(e) => {
                let _ = self.conn.execute("ROLLBACK", ()).await;
                return Err(anyhow::Error::new(e).context("failed to retrieve locked events"));
            }
        };

        // Parse events from rows
        let mut claimed_events = Vec::new();
        loop {
            let row = match rows.next().await {
                Ok(Some(row)) => row,
                Ok(None) => break,
                Err(e) => {
                    let _ = self.conn.execute("ROLLBACK", ()).await;
                    return Err(anyhow::Error::new(e).context("failed to read claimed event data"));
                }
            };

            // Parse the row into a ClaimedEvent
            let id_blob: Vec<u8> = row.get(0).context("failed to get event ID")?;
            let session_id_blob: Vec<u8> = row.get(1).context("failed to get session_id")?;
            let outcome_db: i64 = row.get(2).context("failed to get outcome")?;
            let protocol_db: i64 = row.get(3).context("failed to get protocol")?;
            let target_host: String = row.get(4).context("failed to get target_host")?;
            let target_ip_family: i64 = row.get(5).context("failed to get target_ip_family")?;
            let target_ip_blob: Vec<u8> = row.get(6).context("failed to get target_ip")?;
            let target_port: i64 = row.get(7).context("failed to get target_port")?;
            let connect_at_ms: i64 = row.get(8).context("failed to get connect_at_ms")?;
            let disconnect_at_ms: i64 = row.get(9).context("failed to get disconnect_at_ms")?;
            let active_duration_ms: i64 = row.get(10).context("failed to get active_duration_ms")?;
            let bytes_tx: i64 = row.get(11).context("failed to get bytes_tx")?;
            let bytes_rx: i64 = row.get(12).context("failed to get bytes_rx")?;

            // Convert database values back to domain types
            let id = blob_to_ulid(&id_blob)?;
            let session_id = blob_to_uuid(&session_id_blob)?;
            let outcome = db_to_outcome(outcome_db)?;
            let protocol = db_to_protocol(protocol_db)?;
            let target_ip = blob_to_ip(&target_ip_blob, target_ip_family)?;

            let event = TrafficEvent {
                session_id,
                outcome,
                protocol,
                target_host,
                target_ip,
                target_port: u16::try_from(target_port).unwrap_or(0),
                connect_at_ms,
                disconnect_at_ms,
                active_duration_ms,
                bytes_tx: u64::try_from(bytes_tx).unwrap_or(u64::MAX),
                bytes_rx: u64::try_from(bytes_rx).unwrap_or(u64::MAX),
            };

            claimed_events.push(ClaimedEvent { id, event });
        }

        // Commit the transaction
        self.conn
            .execute("COMMIT", ())
            .await
            .context("failed to commit claim transaction")?;

        debug!(
            consumer_id,
            claimed_count = claimed_events.len(),
            "Successfully claimed events"
        );

        Ok(claimed_events)
    }

    async fn ack(&self, ids: &[Ulid]) -> anyhow::Result<u64> {
        if ids.is_empty() {
            trace!("No IDs to acknowledge");
            return Ok(0);
        }

        trace!(ids = ?ids, "Acknowledging events");

        // Begin transaction
        self.conn
            .execute("BEGIN", ())
            .await
            .context("failed to begin ack transaction")?;

        let delete_query = format!("DELETE FROM traffic_events WHERE id IN ({})", repeat_qm(ids.len()));

        let params: Vec<libsql::Value> = ids.iter().map(|id| libsql::Value::from(ulid_to_blob(id))).collect();

        match self.conn.execute(&delete_query, params).await {
            Ok(deleted_count) => {
                // Commit transaction
                self.conn
                    .execute("COMMIT", ())
                    .await
                    .context("failed to commit ack transaction")?;

                debug!(
                    deleted_count,
                    requested_ids = ids.len(),
                    "Successfully acknowledged events"
                );

                Ok(deleted_count)
            }
            Err(e) => {
                // Rollback on error
                let _ = self.conn.execute("ROLLBACK", ()).await;
                Err(e).context("failed to delete acknowledged events")
            }
        }
    }

    async fn extend_lease(&self, ids: &[Ulid], consumer_id: &str, lease_duration_ms: i64) -> anyhow::Result<()> {
        if ids.is_empty() {
            trace!("No IDs to extend lease for");
            return Ok(());
        }

        let now = now_ms();
        let new_lock_until = now + lease_duration_ms;

        trace!(ids = ?ids, consumer_id, lease_duration_ms, "Extending lease");

        let update_query = format!(
            "UPDATE traffic_events
             SET lock_until_ms = ?
             WHERE id IN ({}) AND locked_by = ?",
            repeat_qm(ids.len())
        );

        let mut params: Vec<libsql::Value> = vec![libsql::Value::from(new_lock_until)];
        for id in ids {
            params.push(libsql::Value::from(ulid_to_blob(id)));
        }
        params.push(libsql::Value::from(consumer_id));

        let updated_count = self
            .conn
            .execute(&update_query, params)
            .await
            .context("failed to extend lease")?;

        debug!(
            updated_count,
            consumer_id,
            requested_ids = ids.len(),
            "Extended lease for events"
        );

        Ok(())
    }

    async fn purge(&self, cutoff_time_ms: i64) -> anyhow::Result<u64> {
        trace!(cutoff_time_ms, "Purging old unclaimed events");

        // Delete events that are old and not currently claimed
        let delete_query = "DELETE FROM traffic_events 
                           WHERE enqueued_at_ms < ? 
                           AND (locked_by IS NULL OR lock_until_ms <= ?)";

        let now = now_ms();
        let deleted_count = self
            .conn
            .execute(delete_query, (cutoff_time_ms, now))
            .await
            .context("failed to purge old events")?;

        if deleted_count > 0 {
            debug!(deleted_count, cutoff_time_ms, "Purged old unclaimed events");
        }

        Ok(deleted_count)
    }
}

/// Returns current time as milliseconds since Unix epoch.
///
/// Used for timestamp generation and lease expiry calculations.
fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_millis(),
    )
    .unwrap_or(i64::MAX)
}

/// Converts an IP address to binary representation for storage.
///
/// Returns (ip_family, blob) where family is 4 or 6, and blob is the raw bytes.
fn ip_to_blob(ip: &std::net::IpAddr) -> (i64, Vec<u8>) {
    match ip {
        std::net::IpAddr::V4(ipv4) => (4, ipv4.octets().to_vec()),
        std::net::IpAddr::V6(ipv6) => (6, ipv6.octets().to_vec()),
    }
}

/// Converts binary representation back to IP address.
///
/// Uses the ip_family parameter to determine IPv4 vs IPv6 interpretation.
fn blob_to_ip(blob: &[u8], ip_family: i64) -> anyhow::Result<std::net::IpAddr> {
    match ip_family {
        4 => {
            if blob.len() != 4 {
                anyhow::bail!("IPv4 address must be exactly 4 bytes, got {}", blob.len());
            }
            let octets = [blob[0], blob[1], blob[2], blob[3]];
            Ok(std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)))
        }
        6 => {
            if blob.len() != 16 {
                anyhow::bail!("IPv6 address must be exactly 16 bytes, got {}", blob.len());
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(blob);
            Ok(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        _ => anyhow::bail!("Invalid IP family: {}, must be 4 or 6", ip_family),
    }
}

/// Converts UUID to 16-byte binary representation for efficient storage.
fn uuid_to_blob(uuid: &Uuid) -> Vec<u8> {
    uuid.as_bytes().to_vec()
}

/// Converts 16-byte binary representation back to UUID.
fn blob_to_uuid(blob: &[u8]) -> anyhow::Result<Uuid> {
    if blob.len() != 16 {
        anyhow::bail!("UUID must be exactly 16 bytes, got {}", blob.len());
    }
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(blob);
    Ok(Uuid::from_bytes(bytes))
}

/// Converts ULID to 16-byte binary representation for storage.
fn ulid_to_blob(ulid: &Ulid) -> Vec<u8> {
    ulid.to_bytes().to_vec()
}

/// Converts 16-byte binary representation back to ULID.
fn blob_to_ulid(blob: &[u8]) -> anyhow::Result<Ulid> {
    let bytes: [u8; 16] = blob
        .try_into()
        .with_context(|| format!("ULID must be exactly 16 bytes, got {}", blob.len()))?;

    Ok(Ulid::from_bytes(bytes))
}

/// Generates SQL parameter placeholders for IN clauses.
///
/// Returns a string like "?,?,?" for n=3.
fn repeat_qm(n: usize) -> String {
    if n == 0 {
        return String::new();
    }
    let mut result = String::with_capacity(n * 2 - 1); // "?" + "," for each except last
    result.push('?');
    for _ in 1..n {
        result.push(',');
        result.push('?');
    }
    result
}

/// Maps EventOutcome enum to database integer representation.
fn outcome_to_db(outcome: &traffic_audit::EventOutcome) -> i64 {
    match outcome {
        traffic_audit::EventOutcome::ConnectFailure => 0,
        traffic_audit::EventOutcome::NormalTermination => 1,
        traffic_audit::EventOutcome::AbnormalTermination => 2,
    }
}

/// Maps database integer back to EventOutcome enum.
fn db_to_outcome(db_value: i64) -> anyhow::Result<traffic_audit::EventOutcome> {
    match db_value {
        0 => Ok(traffic_audit::EventOutcome::ConnectFailure),
        1 => Ok(traffic_audit::EventOutcome::NormalTermination),
        2 => Ok(traffic_audit::EventOutcome::AbnormalTermination),
        _ => anyhow::bail!("Invalid outcome value: {}", db_value),
    }
}

/// Maps TransportProtocol enum to database integer representation.
fn protocol_to_db(protocol: &traffic_audit::TransportProtocol) -> i64 {
    match protocol {
        traffic_audit::TransportProtocol::Tcp => 0,
        traffic_audit::TransportProtocol::Udp => 1,
    }
}

/// Maps database integer back to TransportProtocol enum.
fn db_to_protocol(db_value: i64) -> anyhow::Result<traffic_audit::TransportProtocol> {
    match db_value {
        0 => Ok(traffic_audit::TransportProtocol::Tcp),
        1 => Ok(traffic_audit::TransportProtocol::Udp),
        _ => anyhow::bail!("Invalid protocol value: {}", db_value),
    }
}
