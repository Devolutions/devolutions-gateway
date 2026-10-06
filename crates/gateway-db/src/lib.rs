//! Gateway's own database, `gateway.db`.
//!
//! When a feature needs to remember a little data, it keeps it here in tables named after the feature
//! (`agent_tunnel_*`, ...), with the code reading them in a module of the same name, so we don't end up with one
//! database file per feature. Queues are the exception: the job queue and the traffic audit tune their databases
//! for queue work, so they keep their own files.

#[macro_use]
extern crate tracing;

pub mod agent_tunnel;
pub mod provisioner_task;

use anyhow::{Context as _, bail};
use camino::{Utf8Path, Utf8PathBuf};
use libsql::{Connection, Database, TransactionBehavior, params};

const FILE_NAME: &str = "gateway.db";

/// Gateway 2026.3 kept the agent tunnel tables in a file of their own.
const LEGACY_AGENT_TUNNEL_FILE_NAME: &str = "agent_tunnel.db";

const PRAGMAS: &str = "
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = FULL;
    PRAGMA busy_timeout = 15000;
    PRAGMA foreign_keys = ON;
    PRAGMA temp_store = MEMORY;
";

/// Every schema change ever made to `gateway.db`, oldest first. Only ever append to it.
const MIGRATIONS: &[&str] = &[
    include_str!("../migrations/01_agent_tunnel.sql"),
    include_str!("../migrations/02_prefix_agent_tunnel_tables.sql"),
    include_str!("../migrations/03_provisioner_task.sql"),
];

/// The open `gateway.db`, ready to hand a connection to each feature that keeps tables in it.
#[derive(Debug)]
pub struct GatewayDb {
    database: Database,
}

impl GatewayDb {
    /// Opens `gateway.db` in `data_dir`, creating it or bringing its tables up to date.
    ///
    /// The first time a Gateway that ran 2026.3 starts, its `agent_tunnel.db` becomes `gateway.db`.
    pub async fn open(data_dir: &Utf8Path) -> anyhow::Result<Self> {
        let path = data_dir.join(FILE_NAME);
        adopt_legacy_agent_tunnel_database(&data_dir.join(LEGACY_AGENT_TUNNEL_FILE_NAME), &path).await?;
        Self::open_path(path.as_str()).await
    }

    /// Opens the database at `path`, creating it or bringing its tables up to date.
    ///
    /// With `:memory:`, every connection gets its own empty database with up-to-date tables, which is handy in tests.
    pub async fn open_path(path: &str) -> anyhow::Result<Self> {
        let database = libsql::Builder::new_local(path)
            .build()
            .await
            .with_context(|| format!("build database {path}"))?;
        let db = Self { database };

        db.connect().await?;

        Ok(db)
    }

    /// Gives a feature a connection of its own.
    ///
    /// SQLite tracks transactions per connection, so features sharing one connection would end up inside each
    /// other's transactions. Each feature should call this once and keep its connection.
    pub async fn connect(&self) -> anyhow::Result<Connection> {
        let conn = self.database.connect().context("connect to the gateway database")?;

        conn.execute_batch(PRAGMAS)
            .await
            .context("apply gateway database PRAGMAs")?;
        migrate(&conn).await?;

        Ok(conn)
    }
}

async fn migrate(conn: &Connection) -> anyhow::Result<()> {
    if schema_version(conn).await? == MIGRATIONS.len() {
        return Ok(());
    }

    loop {
        // Another connection may migrate at the same time, so the version is read again under the write lock.
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await
            .context("begin gateway database migration")?;
        let user_version = schema_version(&tx).await?;

        let Some(migration) = MIGRATIONS.get(user_version) else {
            if MIGRATIONS.len() < user_version {
                bail!(
                    "gateway database schema version {user_version} is newer than supported version {}",
                    MIGRATIONS.len()
                );
            }

            return Ok(());
        };

        let version = user_version + 1;
        tx.execute_batch(migration)
            .await
            .with_context(|| format!("apply gateway database migration {version}"))?;
        tx.execute_batch(&format!("PRAGMA user_version = {version}"))
            .await
            .with_context(|| format!("record gateway database migration {version}"))?;
        tx.commit()
            .await
            .with_context(|| format!("commit gateway database migration {version}"))?;
    }
}

async fn schema_version(conn: &Connection) -> anyhow::Result<usize> {
    let row = conn
        .query("PRAGMA user_version", ())
        .await
        .context("query gateway database schema version")?
        .next()
        .await
        .context("read gateway database schema version")?
        .context("gateway database schema version query returned no row")?;
    let user_version = row.get::<u64>(0).context("decode gateway database schema version")?;
    usize::try_from(user_version).context("gateway database schema version is too large")
}

/// Turns a 2026.3 `agent_tunnel.db` into `gateway.db`.
///
/// We write a complete copy, flush it to disk, and only then rename it into place, so `gateway.db` either doesn't
/// exist yet or is whole. The rename reaches the disk before the old files are removed, so a power loss never leaves
/// only a partial copy behind. If Gateway stops halfway, the next start simply does it again.
async fn adopt_legacy_agent_tunnel_database(legacy: &Utf8Path, path: &Utf8Path) -> anyhow::Result<()> {
    if !legacy.exists() {
        return Ok(());
    }

    if path.exists() {
        warn!(
            %legacy,
            "Ignoring an old agent tunnel database because gateway.db already exists; its Agents are not imported. Delete the file to silence this warning"
        );
        return Ok(());
    }

    let copy = Utf8PathBuf::from(format!("{path}.tmp"));
    remove_file_if_exists(&copy).with_context(|| format!("remove the incomplete copy {copy}"))?;

    let legacy_conn = libsql::Builder::new_local(legacy.as_str())
        .build()
        .await
        .with_context(|| format!("build database {legacy}"))?
        .connect()
        .with_context(|| format!("connect to database {legacy}"))?;
    legacy_conn
        .execute("VACUUM INTO ?1", params![copy.as_str()])
        .await
        .with_context(|| format!("copy {legacy} to {copy}"))?;
    drop(legacy_conn);

    // VACUUM INTO does not flush the file it writes.
    std::fs::OpenOptions::new()
        .write(true)
        .open(&copy)
        .and_then(|file| file.sync_all())
        .with_context(|| format!("flush {copy} to disk"))?;

    rename_durably(&copy, path).with_context(|| format!("rename {copy} to {path}"))?;

    for suffix in ["", "-wal", "-shm"] {
        let legacy_file = Utf8PathBuf::from(format!("{legacy}{suffix}"));

        if let Err(error) = remove_file_if_exists(&legacy_file) {
            warn!(%error, path = %legacy_file, "Failed to remove the old agent tunnel database file");
        }
    }

    info!(from = %legacy, to = %path, "Moved the agent tunnel database into the gateway database");

    Ok(())
}

/// Renames `from` to `to` and waits until the rename is on disk.
#[cfg(unix)]
fn rename_durably(from: &Utf8Path, to: &Utf8Path) -> std::io::Result<()> {
    std::fs::rename(from, to)?;

    // On Unix, the new name is only durable once its directory is flushed.
    let dir = match to.parent() {
        Some(dir) if !dir.as_str().is_empty() => dir,
        _ => Utf8Path::new("."),
    };
    std::fs::File::open(dir)?.sync_all()
}

/// Renames `from` to `to` and waits until the rename is on disk.
#[cfg(windows)]
fn rename_durably(from: &Utf8Path, to: &Utf8Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;

    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};

    let wide = |path: &Utf8Path| -> Vec<u16> {
        path.as_std_path()
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    };
    let from = wide(from);
    let to = wide(to);

    // SAFETY: Both paths are null-terminated UTF-16 strings that outlive the call.
    let succeeded = unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_WRITE_THROUGH) };

    if succeeded == 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

fn remove_file_if_exists(path: &Utf8Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_data_dir() -> (tempfile::TempDir, Utf8PathBuf) {
        let temp_dir = tempfile::tempdir().expect("create temporary directory");
        let data_dir = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).expect("temporary path is UTF-8");
        (temp_dir, data_dir)
    }

    async fn open_dir(data_dir: &Utf8Path) -> anyhow::Result<Connection> {
        GatewayDb::open(data_dir).await?.connect().await
    }

    async fn user_version(conn: &Connection) -> usize {
        schema_version(conn).await.expect("read schema version")
    }

    async fn table_exists(conn: &Connection, table: &str) -> bool {
        conn.query(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            params![table],
        )
        .await
        .expect("query tables")
        .next()
        .await
        .expect("read tables")
        .is_some()
    }

    /// Builds the `agent_tunnel.db` that Gateway 2026.3 leaves behind.
    async fn write_legacy_database(path: &Utf8Path) {
        let conn = libsql::Builder::new_local(path.as_str())
            .build()
            .await
            .expect("build legacy database")
            .connect()
            .expect("open legacy database");
        conn.execute_batch(PRAGMAS).await.expect("apply legacy PRAGMAs");
        conn.execute_batch(MIGRATIONS[0]).await.expect("create legacy tables");
        conn.execute(
            "INSERT INTO metadata (key, value) VALUES ('ca_spki_sha256', ?1)",
            params![vec![0xCAu8; 32]],
        )
        .await
        .expect("bind legacy CA");
        conn.execute_batch("PRAGMA user_version = 1")
            .await
            .expect("record legacy schema version");
    }

    #[tokio::test]
    async fn new_database_has_prefixed_agent_tunnel_tables() {
        let conn = GatewayDb::open_path(":memory:")
            .await
            .expect("open gateway database")
            .connect()
            .await
            .expect("connect to gateway database");

        assert_eq!(user_version(&conn).await, MIGRATIONS.len());
        assert!(table_exists(&conn, "agent_tunnel_metadata").await);
        assert!(table_exists(&conn, "agent_tunnel_accepted_agents").await);
        assert!(table_exists(&conn, "agent_tunnel_enrollment_attempts").await);
        assert!(table_exists(&conn, "agent_tunnel_deleted_agent_keys").await);
        assert!(table_exists(&conn, "provisioner_task").await);
        assert!(!table_exists(&conn, "metadata").await);
    }

    #[tokio::test]
    async fn legacy_agent_tunnel_database_becomes_gateway_database() {
        let (_temp_dir, data_dir) = temp_data_dir();
        let legacy = data_dir.join(LEGACY_AGENT_TUNNEL_FILE_NAME);
        write_legacy_database(&legacy).await;

        let conn = open_dir(&data_dir).await.expect("open gateway database");

        assert!(!legacy.exists());
        assert!(data_dir.join(FILE_NAME).exists());
        assert_eq!(user_version(&conn).await, MIGRATIONS.len());
        let ca = conn
            .query(
                "SELECT value FROM agent_tunnel_metadata WHERE key = 'ca_spki_sha256'",
                (),
            )
            .await
            .expect("query CA")
            .next()
            .await
            .expect("read CA")
            .expect("CA survives the move")
            .get::<Vec<u8>>(0)
            .expect("decode CA");
        assert_eq!(ca, vec![0xCAu8; 32]);
    }

    #[tokio::test]
    async fn interrupted_move_starts_over() {
        let (_temp_dir, data_dir) = temp_data_dir();
        let legacy = data_dir.join(LEGACY_AGENT_TUNNEL_FILE_NAME);
        write_legacy_database(&legacy).await;
        std::fs::write(data_dir.join(format!("{FILE_NAME}.tmp")), b"half written").expect("leave an incomplete copy");

        let conn = open_dir(&data_dir).await.expect("open gateway database");

        assert!(table_exists(&conn, "agent_tunnel_metadata").await);
        assert!(!data_dir.join(format!("{FILE_NAME}.tmp")).exists());
    }

    #[tokio::test]
    async fn existing_gateway_database_is_kept() {
        let (_temp_dir, data_dir) = temp_data_dir();
        drop(open_dir(&data_dir).await.expect("create gateway database"));
        let legacy = data_dir.join(LEGACY_AGENT_TUNNEL_FILE_NAME);
        write_legacy_database(&legacy).await;

        let conn = open_dir(&data_dir).await.expect("reopen gateway database");

        assert!(legacy.exists());
        let rows = conn
            .query("SELECT 1 FROM agent_tunnel_metadata", ())
            .await
            .expect("query CA")
            .next()
            .await
            .expect("read CA");
        assert!(rows.is_none());
    }

    #[tokio::test]
    async fn each_connection_has_its_own_transactions() {
        let (_temp_dir, data_dir) = temp_data_dir();
        let db = GatewayDb::open(&data_dir).await.expect("open gateway database");
        let first = db.connect().await.expect("connect first feature");
        let second = db.connect().await.expect("connect second feature");

        let tx = first
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .await
            .expect("begin a transaction on the first connection");
        let second_tx = second
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .await
            .expect("the second connection is not inside the first one's transaction");

        drop(second_tx);
        drop(tx);
    }

    #[tokio::test]
    async fn newer_schema_is_rejected() {
        let (_temp_dir, data_dir) = temp_data_dir();
        let conn = open_dir(&data_dir).await.expect("create gateway database");
        conn.execute_batch("PRAGMA user_version = 99")
            .await
            .expect("set unsupported schema version");
        drop(conn);

        let error = open_dir(&data_dir).await.expect_err("newer schema must be rejected");

        assert!(error.to_string().contains("newer than supported"));
    }
}
