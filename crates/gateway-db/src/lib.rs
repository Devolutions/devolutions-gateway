//! Gateway's own database, `gateway.db`.
//!
//! Features that need to remember a little data keep it here, in tables named after the feature (`agent_tunnel_*`,
//! ...), so we don't end up with one database file per feature. This crate only owns the file: it opens it, applies
//! the PRAGMAs and hands a connection to each feature. Each feature's tables, migrations and schema version live in
//! the feature's own adapter crate, such as `agent-tunnel-libsql`; the table prefix is the compatibility boundary.
//!
//! Queues are the exception: the job queue and the traffic audit tune their databases for queue work, so they keep
//! their own files.

use anyhow::Context as _;
use camino::Utf8Path;
use libsql::{Connection, Database};

/// The name of the database file in Gateway's data directory.
pub const FILE_NAME: &str = "gateway.db";

const PRAGMAS: &str = "
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = FULL;
    PRAGMA busy_timeout = 15000;
    PRAGMA foreign_keys = ON;
    PRAGMA temp_store = MEMORY;
";

/// The open `gateway.db`, ready to hand a connection to each feature that keeps tables in it.
#[derive(Debug)]
pub struct GatewayDb {
    database: Database,
}

impl GatewayDb {
    /// Opens `gateway.db` in `data_dir`, creating it if needed.
    pub async fn open(data_dir: &Utf8Path) -> anyhow::Result<Self> {
        Self::open_path(data_dir.join(FILE_NAME).as_str()).await
    }

    /// Opens the database at `path`, creating it if needed.
    ///
    /// With `:memory:`, every connection gets its own empty database, which is handy in tests.
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

        Ok(conn)
    }
}

/// Waits until the content of the file at `path` is on disk.
pub fn flush_file(path: &Utf8Path) -> std::io::Result<()> {
    std::fs::OpenOptions::new().write(true).open(path)?.sync_all()
}

/// Renames `from` to `to` and waits until the rename is on disk.
#[cfg(unix)]
pub fn rename_durably(from: &Utf8Path, to: &Utf8Path) -> std::io::Result<()> {
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
pub fn rename_durably(from: &Utf8Path, to: &Utf8Path) -> std::io::Result<()> {
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

/// Removes the file at `path`, if there is one.
pub fn remove_file_if_exists(path: &Utf8Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

#[cfg(test)]
mod tests {
    use camino::Utf8PathBuf;
    use libsql::TransactionBehavior;

    use super::*;

    fn temp_data_dir() -> (tempfile::TempDir, Utf8PathBuf) {
        let temp_dir = tempfile::tempdir().expect("create temporary directory");
        let data_dir = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).expect("temporary path is UTF-8");
        (temp_dir, data_dir)
    }

    async fn query_i64(conn: &Connection, sql: &str) -> i64 {
        conn.query(sql, ())
            .await
            .expect("run query")
            .next()
            .await
            .expect("read row")
            .expect("query returns a row")
            .get::<i64>(0)
            .expect("decode integer")
    }

    #[tokio::test]
    async fn open_creates_an_empty_database_without_a_schema_version() {
        let (_temp_dir, data_dir) = temp_data_dir();

        let conn = GatewayDb::open(&data_dir)
            .await
            .expect("open gateway database")
            .connect()
            .await
            .expect("connect to gateway database");

        assert!(data_dir.join(FILE_NAME).exists());
        assert_eq!(query_i64(&conn, "PRAGMA user_version").await, 0);
        assert_eq!(query_i64(&conn, "SELECT count(*) FROM sqlite_master").await, 0);
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

    #[test]
    fn copy_is_flushed_and_renamed_into_place() {
        let (_temp_dir, data_dir) = temp_data_dir();
        let from = data_dir.join("gateway.db.tmp");
        let to = data_dir.join(FILE_NAME);
        std::fs::write(&from, b"copy").expect("write the copy");

        flush_file(&from).expect("flush the copy");
        rename_durably(&from, &to).expect("rename the copy");

        assert!(!from.exists());
        assert_eq!(std::fs::read(&to).expect("read the target"), b"copy");
        remove_file_if_exists(&from).expect("a missing file is not an error");
    }
}
