//! The upgrade from Gateway 2026.3, which kept the agent tunnel tables in an `agent_tunnel.db` of their own.

use anyhow::{Context as _, bail};
use camino::{Utf8Path, Utf8PathBuf};
use libsql::{Connection, params};

use crate::record_schema_version;

/// Only Gateway 2026.3 wrote this file.
pub(crate) const LEGACY_FILE_NAME: &str = "agent_tunnel.db";

/// The only schema 2026.3 ever had, as its `PRAGMA user_version`.
const LEGACY_SCHEMA_VERSION: i64 = 1;

/// The conversion yields the tables of the first migration.
const CONVERTED_SCHEMA_VERSION: i64 = 1;

/// Turns the 2026.3 tables into the first version of the `agent_tunnel_*` tables.
const CONVERSION: &str = "
    ALTER TABLE metadata RENAME TO agent_tunnel_metadata;
    ALTER TABLE accepted_agents RENAME TO agent_tunnel_accepted_agents;
    ALTER TABLE enrollment_attempts RENAME TO agent_tunnel_enrollment_attempts;
    ALTER TABLE deleted_agent_keys RENAME TO agent_tunnel_deleted_agent_keys;
";

/// Turns the `agent_tunnel.db` left by Gateway 2026.3 in `data_dir` into `gateway.db`.
///
/// Call it before opening `gateway.db`: once `gateway.db` exists, the old file is ignored. It does nothing when there
/// is no old file.
///
/// We convert a copy, flush it to disk, and only then rename it into place, so `gateway.db` either doesn't exist yet
/// or is whole and in the new layout. The rename reaches the disk before the old files are removed, so a power loss
/// never leaves only a partial copy behind. If Gateway stops halfway, the next start simply does it again.
pub async fn import_2026_3_database(data_dir: &Utf8Path) -> anyhow::Result<()> {
    let legacy = data_dir.join(LEGACY_FILE_NAME);
    let path = data_dir.join(gateway_db::FILE_NAME);

    if !exists(&legacy)? {
        return Ok(());
    }

    if exists(&path)? {
        warn!(%legacy, "Ignoring agent_tunnel.db because gateway.db already exists");
        return Ok(());
    }

    let legacy_conn = connect(&legacy).await?;

    match legacy_schema_version(&legacy_conn).await? {
        // A first start that failed before creating the tables: there is nothing to import.
        0 => {
            if has_tables(&legacy_conn).await? {
                bail!("{legacy} has tables but no schema version");
            }

            drop(legacy_conn);

            if remove_with_sidecars(&legacy) {
                info!(%legacy, "Removed an empty agent tunnel database");
            }

            return Ok(());
        }
        LEGACY_SCHEMA_VERSION => {}
        version => bail!("unsupported schema version {version} in {legacy}"),
    }

    let copy = Utf8PathBuf::from(format!("{path}.tmp"));

    // A leftover journal of an interrupted attempt would be replayed into the new copy.
    for file in with_sidecars(&copy) {
        gateway_db::remove_file_if_exists(&file).with_context(|| format!("remove the incomplete copy {file}"))?;
    }

    legacy_conn
        .execute("VACUUM INTO ?1", params![copy.as_str()])
        .await
        .with_context(|| format!("copy {legacy} to {copy}"))?;
    drop(legacy_conn);

    convert(&copy).await?;

    gateway_db::flush_file(&copy).with_context(|| format!("flush {copy} to disk"))?;
    gateway_db::rename_durably(&copy, &path).with_context(|| format!("rename {copy} to {path}"))?;

    // A failed removal is only noise: gateway.db exists now, so the old files are ignored.
    let _ = remove_with_sidecars(&legacy);

    info!(from = %legacy, to = %path, "Moved the agent tunnel database into the gateway database");

    Ok(())
}

async fn convert(copy: &Utf8Path) -> anyhow::Result<()> {
    let conn = connect(copy).await?;

    // The changes must be in the file itself before the rename, not in a `-wal` file left behind. SQLite keeps the old
    // mode without an error when it can't switch, so we check the mode it reports.
    let journal_mode = conn
        .query("PRAGMA journal_mode = DELETE", ())
        .await
        .with_context(|| format!("use a rollback journal for {copy}"))?
        .next()
        .await
        .with_context(|| format!("read the journal mode of {copy}"))?
        .context("journal mode query returned no row")?
        .get::<String>(0)
        .context("decode the journal mode")?;
    if !journal_mode.eq_ignore_ascii_case("delete") {
        bail!("journal mode of {copy} is {journal_mode}, not delete");
    }

    let tx = conn.transaction().await.context("begin agent tunnel conversion")?;
    tx.execute_batch(CONVERSION)
        .await
        .context("add the agent tunnel table prefixes")?;
    record_schema_version(&tx, CONVERTED_SCHEMA_VERSION).await?;
    tx.execute_batch("PRAGMA user_version = 0")
        .await
        .context("clear the 2026.3 schema version")?;
    tx.commit().await.context("commit agent tunnel conversion")?;

    Ok(())
}

async fn connect(path: &Utf8Path) -> anyhow::Result<Connection> {
    libsql::Builder::new_local(path.as_str())
        .build()
        .await
        .with_context(|| format!("build database {path}"))?
        .connect()
        .with_context(|| format!("connect to database {path}"))
}

fn exists(path: &Utf8Path) -> anyhow::Result<bool> {
    path.try_exists().with_context(|| format!("look for {path}"))
}

async fn has_tables(conn: &Connection) -> anyhow::Result<bool> {
    let row = conn
        .query("SELECT 1 FROM sqlite_master LIMIT 1", ())
        .await
        .context("query the 2026.3 agent tunnel tables")?
        .next()
        .await
        .context("read the 2026.3 agent tunnel tables")?;

    Ok(row.is_some())
}

async fn legacy_schema_version(conn: &Connection) -> anyhow::Result<i64> {
    conn.query("PRAGMA user_version", ())
        .await
        .context("query the 2026.3 agent tunnel schema version")?
        .next()
        .await
        .context("read the 2026.3 agent tunnel schema version")?
        .context("schema version query returned no row")?
        .get::<i64>(0)
        .context("decode the 2026.3 agent tunnel schema version")
}

fn with_sidecars(path: &Utf8Path) -> [Utf8PathBuf; 4] {
    ["", "-journal", "-wal", "-shm"].map(|suffix| Utf8PathBuf::from(format!("{path}{suffix}")))
}

/// Removes the database at `path` with its journals; returns whether every file is gone.
fn remove_with_sidecars(path: &Utf8Path) -> bool {
    let mut removed = true;

    for file in with_sidecars(path) {
        if let Err(error) = gateway_db::remove_file_if_exists(&file) {
            warn!(%error, path = %file, "Failed to remove an old agent tunnel database file");
            removed = false;
        }
    }

    removed
}

#[cfg(test)]
mod tests {
    use agent_tunnel::authorization::AgentAuthorizationStore as _;
    use gateway_db::GatewayDb;
    use uuid::Uuid;

    use super::*;
    use crate::LibSqlAgentAuthorizationStore;

    /// The tables Gateway 2026.3 created in `agent_tunnel.db`.
    const LEGACY_SCHEMA: &str = "
        CREATE TABLE metadata (key TEXT PRIMARY KEY, value BLOB NOT NULL);
        CREATE TABLE accepted_agents (
            agent_id TEXT PRIMARY KEY,
            name TEXT NOT NULL COLLATE NOCASE UNIQUE,
            client_spki_sha256 BLOB NOT NULL,
            enrollment_jti TEXT NOT NULL UNIQUE,
            CHECK (length(name) BETWEEN 1 AND 255),
            CHECK (name = trim(name)),
            CHECK (length(client_spki_sha256) = 32)
        );
        CREATE TABLE enrollment_attempts (
            jti TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            request_sha256 BLOB NOT NULL,
            expires_at INTEGER NOT NULL,
            deleted INTEGER NOT NULL DEFAULT 0,
            CHECK (length(request_sha256) = 32),
            CHECK (deleted IN (0, 1))
        );
        CREATE TABLE deleted_agent_keys (
            client_spki_sha256 BLOB PRIMARY KEY,
            agent_id TEXT NOT NULL,
            CHECK (length(client_spki_sha256) = 32)
        );
    ";

    fn temp_data_dir() -> (tempfile::TempDir, Utf8PathBuf) {
        let temp_dir = tempfile::tempdir().expect("create temporary directory");
        let data_dir = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).expect("temporary path is UTF-8");
        (temp_dir, data_dir)
    }

    /// Writes the `agent_tunnel.db` that Gateway 2026.3 leaves behind, with one Agent, and returns its ID.
    async fn write_legacy_database(data_dir: &Utf8Path) -> Uuid {
        let conn = connect(&data_dir.join(LEGACY_FILE_NAME))
            .await
            .expect("open 2026.3 database");
        conn.execute_batch("PRAGMA journal_mode = WAL")
            .await
            .expect("use WAL like 2026.3");
        fill_legacy_database(&conn).await
    }

    /// Creates the 2026.3 tables with one Agent, and returns its ID.
    async fn fill_legacy_database(conn: &Connection) -> Uuid {
        let agent_id = Uuid::new_v4();
        conn.execute_batch(LEGACY_SCHEMA).await.expect("create 2026.3 tables");
        conn.execute(
            "INSERT INTO metadata (key, value) VALUES ('ca_spki_sha256', ?1)",
            params![vec![0xCAu8; 32]],
        )
        .await
        .expect("bind 2026.3 CA");
        conn.execute(
            "INSERT INTO accepted_agents (agent_id, name, client_spki_sha256, enrollment_jti) VALUES (?1, ?2, ?3, ?4)",
            params![
                agent_id.to_string(),
                "montreal-office",
                vec![0x11u8; 32],
                Uuid::new_v4().to_string()
            ],
        )
        .await
        .expect("store 2026.3 Agent");
        conn.execute_batch("PRAGMA user_version = 1")
            .await
            .expect("record 2026.3 schema version");
        agent_id
    }

    async fn open_gateway_db(data_dir: &Utf8Path) -> Connection {
        GatewayDb::open(data_dir)
            .await
            .expect("open gateway database")
            .connect()
            .await
            .expect("connect to gateway database")
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
    async fn agents_enrolled_on_2026_3_still_authorize_after_the_move() {
        let (_temp_dir, data_dir) = temp_data_dir();
        let agent_id = write_legacy_database(&data_dir).await;

        import_2026_3_database(&data_dir).await.expect("import 2026.3 database");

        for file in with_sidecars(&data_dir.join(LEGACY_FILE_NAME)) {
            assert!(!file.exists(), "{file} is removed");
        }
        let path = data_dir.join(gateway_db::FILE_NAME);
        let copy = Utf8PathBuf::from(format!("{path}.tmp"));
        for file in with_sidecars(&copy)
            .into_iter()
            .chain(with_sidecars(&path).into_iter().skip(1))
        {
            assert!(!file.exists(), "{file} is not left behind");
        }
        // Bytes 18 and 19 of the header are 1 for a rollback journal and 2 for WAL.
        let header = std::fs::read(&path).expect("read gateway.db");
        assert_eq!(header[18..20], [1, 1], "gateway.db is renamed in rollback journal mode");

        let conn = open_gateway_db(&data_dir).await;
        assert_eq!(query_i64(&conn, "PRAGMA user_version").await, 0);
        assert_eq!(
            query_i64(
                &conn,
                "SELECT value FROM agent_tunnel_metadata WHERE key = 'schema_version'"
            )
            .await,
            CONVERTED_SCHEMA_VERSION
        );
        assert_eq!(
            LibSqlAgentAuthorizationStore::bound_ca(&conn)
                .await
                .expect("read bound CA"),
            Some([0xCA; 32])
        );

        let store = LibSqlAgentAuthorizationStore::open(conn, [0xCA; 32])
            .await
            .expect("open Agent authorization store");
        let accepted = store
            .authorize(agent_id, [0x11; 32])
            .await
            .expect("authorize moved Agent")
            .expect("Agent is still accepted");
        assert_eq!(accepted.name, "montreal-office");
    }

    #[tokio::test]
    async fn agents_still_in_the_2026_3_wal_are_imported() {
        let (_source_dir, source) = temp_data_dir();
        let (_temp_dir, data_dir) = temp_data_dir();
        let legacy = source.join(LEGACY_FILE_NAME);
        let conn = connect(&legacy).await.expect("open 2026.3 database");
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA wal_autocheckpoint = 0")
            .await
            .expect("keep changes in the WAL");
        let agent_id = fill_legacy_database(&conn).await;

        // Copied while open, as if 2026.3 had crashed before writing its WAL into the database.
        for suffix in ["", "-wal"] {
            std::fs::copy(
                format!("{legacy}{suffix}"),
                format!("{}{suffix}", data_dir.join(LEGACY_FILE_NAME)),
            )
            .expect("copy the 2026.3 files");
        }
        drop(conn);
        assert!(
            std::fs::metadata(data_dir.join(format!("{LEGACY_FILE_NAME}-wal")))
                .expect("WAL copied")
                .len()
                > 0
        );

        import_2026_3_database(&data_dir).await.expect("import 2026.3 database");

        let store = LibSqlAgentAuthorizationStore::open(open_gateway_db(&data_dir).await, [0xCA; 32])
            .await
            .expect("open Agent authorization store");
        assert!(
            store
                .authorize(agent_id, [0x11; 32])
                .await
                .expect("authorize moved Agent")
                .is_some()
        );
    }

    #[tokio::test]
    async fn interrupted_move_starts_over() {
        let (_temp_dir, data_dir) = temp_data_dir();
        write_legacy_database(&data_dir).await;
        let copy = Utf8PathBuf::from(format!("{}.tmp", data_dir.join(gateway_db::FILE_NAME)));
        std::fs::write(&copy, b"half written").expect("leave an incomplete copy");
        std::fs::write(format!("{copy}-journal"), b"stale journal").expect("leave its journal");

        import_2026_3_database(&data_dir).await.expect("import 2026.3 database");

        for file in with_sidecars(&copy) {
            assert!(!file.exists(), "{file} is removed");
        }
        let conn = open_gateway_db(&data_dir).await;
        LibSqlAgentAuthorizationStore::open(conn, [0xCA; 32])
            .await
            .expect("open Agent authorization store");
    }

    #[tokio::test]
    async fn existing_gateway_database_is_kept() {
        let (_temp_dir, data_dir) = temp_data_dir();
        drop(open_gateway_db(&data_dir).await);
        write_legacy_database(&data_dir).await;

        import_2026_3_database(&data_dir).await.expect("ignore 2026.3 database");

        assert!(data_dir.join(LEGACY_FILE_NAME).exists());
        let conn = open_gateway_db(&data_dir).await;
        assert_eq!(
            LibSqlAgentAuthorizationStore::bound_ca(&conn)
                .await
                .expect("read bound CA"),
            None
        );
    }

    #[tokio::test]
    async fn empty_2026_3_database_is_removed() {
        let (_temp_dir, data_dir) = temp_data_dir();
        let conn = connect(&data_dir.join(LEGACY_FILE_NAME))
            .await
            .expect("create empty 2026.3 database");
        conn.execute_batch("PRAGMA journal_mode = WAL")
            .await
            .expect("write the database header");
        drop(conn);
        assert!(data_dir.join(LEGACY_FILE_NAME).exists());

        import_2026_3_database(&data_dir)
            .await
            .expect("import empty 2026.3 database");

        assert!(!data_dir.join(LEGACY_FILE_NAME).exists());
        assert!(!data_dir.join(gateway_db::FILE_NAME).exists());
    }

    #[tokio::test]
    async fn version_0_with_tables_is_refused() {
        let (_temp_dir, data_dir) = temp_data_dir();
        let conn = connect(&data_dir.join(LEGACY_FILE_NAME))
            .await
            .expect("create 2026.3 database");
        conn.execute_batch(LEGACY_SCHEMA).await.expect("create 2026.3 tables");
        drop(conn);

        let error = import_2026_3_database(&data_dir)
            .await
            .expect_err("tables without a schema version must be refused");

        assert!(error.to_string().contains("no schema version"));
        assert!(data_dir.join(LEGACY_FILE_NAME).exists());
    }

    #[tokio::test]
    async fn unknown_2026_3_schema_is_refused() {
        let (_temp_dir, data_dir) = temp_data_dir();
        let conn = connect(&data_dir.join(LEGACY_FILE_NAME))
            .await
            .expect("create 2026.3 database");
        conn.execute_batch("PRAGMA user_version = 7")
            .await
            .expect("set unknown schema version");
        drop(conn);

        let error = import_2026_3_database(&data_dir)
            .await
            .expect_err("unknown schema must be refused");

        assert!(error.to_string().contains("unsupported schema version 7"));
        assert!(data_dir.join(LEGACY_FILE_NAME).exists());
        assert!(!data_dir.join(gateway_db::FILE_NAME).exists());
    }
}
