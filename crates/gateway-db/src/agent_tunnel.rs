//! The agent tunnel's tables: accepted Agents, enrollment attempts and the CA they belong to.

use agent_tunnel::authorization::{
    AcceptedAgent, AgentAuthorizationStore, EnrollmentAttempt, EnrollmentConflict, EnrollmentOutcome, SpkiSha256,
};
use anyhow::{Context as _, bail};
use async_trait::async_trait;
use libsql::{Connection, TransactionBehavior, params};
use tokio::sync::Mutex;
use uuid::Uuid;

const CA_SPKI_SHA256_KEY: &str = "ca_spki_sha256";

/// Agent authorization kept in the `agent_tunnel_*` tables of `gateway.db`.
pub struct LibSqlAgentAuthorizationStore {
    conn: Mutex<Connection>,
}

impl LibSqlAgentAuthorizationStore {
    /// Opens the store on a `gateway.db` connection of its own, from [`GatewayDb::connect`](crate::GatewayDb::connect).
    ///
    /// The connection must already have up-to-date `agent_tunnel_*` tables; opening checks them and fails if they
    /// don't match. The stored Agents only make sense with the CA that signed their certificates, so the first open
    /// ties the store to `ca_spki_sha256`, and later opens refuse any other CA.
    pub async fn open(conn: Connection, ca_spki_sha256: SpkiSha256) -> anyhow::Result<Self> {
        let store = Self { conn: Mutex::new(conn) };

        store.validate_integrity_and_schema().await?;
        store.bind_ca(ca_spki_sha256).await?;

        Ok(store)
    }

    /// Returns the CA the stored Agents belong to, or `None` if the agent tunnel never ran.
    ///
    /// Once Agents are tied to a CA, Gateway must load that CA and never generate a new one.
    pub async fn bound_ca(conn: &Connection) -> anyhow::Result<Option<SpkiSha256>> {
        let stored = conn
            .query(
                "SELECT value FROM agent_tunnel_metadata WHERE key = ?1",
                params![CA_SPKI_SHA256_KEY],
            )
            .await
            .context("query Agent authorization CA identity")?
            .next()
            .await
            .context("read Agent authorization CA identity")?
            .map(|row| row.get::<Vec<u8>>(0))
            .transpose()
            .context("decode Agent authorization CA identity")?;

        stored
            .map(|stored| {
                SpkiSha256::try_from(stored)
                    .map_err(|_| anyhow::anyhow!("Agent authorization CA identity has an invalid length"))
            })
            .transpose()
    }

    async fn bind_ca(&self, ca_spki_sha256: SpkiSha256) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await
            .context("begin Agent authorization CA binding")?;

        match Self::bound_ca(&tx).await? {
            Some(stored) if stored == ca_spki_sha256 => return Ok(()),
            Some(_) => bail!("Agent authorization database belongs to a different CA"),
            None => {}
        }

        let has_agent_data = tx
            .query(
                "SELECT 1 FROM agent_tunnel_accepted_agents
                 UNION ALL SELECT 1 FROM agent_tunnel_deleted_agent_keys
                 UNION ALL SELECT 1 FROM agent_tunnel_enrollment_attempts
                 LIMIT 1",
                (),
            )
            .await
            .context("query Agent data before binding a CA")?
            .next()
            .await
            .context("read Agent data before binding a CA")?
            .is_some();
        if has_agent_data {
            bail!("Agent authorization database has Agent data but is missing CA metadata");
        }

        tx.execute(
            "INSERT INTO agent_tunnel_metadata (key, value) VALUES (?1, ?2)",
            params![CA_SPKI_SHA256_KEY, ca_spki_sha256.to_vec()],
        )
        .await
        .context("bind Agent authorization database to CA")?;
        tx.commit().await.context("commit Agent authorization CA binding")?;

        Ok(())
    }

    async fn validate_integrity_and_schema(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        let mut integrity_rows = conn
            .query("PRAGMA integrity_check", ())
            .await
            .context("check Agent authorization database integrity")?;
        let mut checked = false;
        while let Some(row) = integrity_rows
            .next()
            .await
            .context("read Agent authorization integrity result")?
        {
            let result = row
                .get::<String>(0)
                .context("decode Agent authorization integrity result")?;
            if result != "ok" {
                bail!("Agent authorization database integrity check failed: {result}");
            }
            checked = true;
        }
        if !checked {
            bail!("Agent authorization database integrity check returned no result");
        }

        const TABLE_PROBES: &[(&str, &str)] = &[
            (
                "agent_tunnel_metadata",
                "SELECT key, value FROM agent_tunnel_metadata LIMIT 0",
            ),
            (
                "agent_tunnel_accepted_agents",
                "SELECT agent_id, name, client_spki_sha256, enrollment_jti FROM agent_tunnel_accepted_agents LIMIT 0",
            ),
            (
                "agent_tunnel_enrollment_attempts",
                "SELECT jti, agent_id, request_sha256, expires_at, deleted FROM agent_tunnel_enrollment_attempts LIMIT 0",
            ),
            (
                "agent_tunnel_deleted_agent_keys",
                "SELECT agent_id, client_spki_sha256 FROM agent_tunnel_deleted_agent_keys LIMIT 0",
            ),
        ];
        for (table, probe) in TABLE_PROBES {
            conn.query(probe, ())
                .await
                .with_context(|| format!("validate Agent authorization table {table}"))?;
        }

        Self::validate_unique_index(&conn, "agent_tunnel_metadata", &["key"]).await?;
        Self::validate_unique_index(&conn, "agent_tunnel_accepted_agents", &["agent_id"]).await?;
        Self::validate_unique_index(&conn, "agent_tunnel_accepted_agents", &["name"]).await?;
        Self::validate_unique_index(&conn, "agent_tunnel_accepted_agents", &["enrollment_jti"]).await?;
        Self::validate_unique_index(&conn, "agent_tunnel_enrollment_attempts", &["jti"]).await?;
        Self::validate_unique_index(&conn, "agent_tunnel_deleted_agent_keys", &["client_spki_sha256"]).await?;

        Ok(())
    }

    async fn validate_unique_index(
        conn: &Connection,
        table: &'static str,
        expected_columns: &[&str],
    ) -> anyhow::Result<()> {
        let mut rows = conn
            .query(&format!("PRAGMA index_list('{table}')"), ())
            .await
            .with_context(|| format!("list Agent authorization indexes for {table}"))?;
        let mut unique_indexes = Vec::new();
        while let Some(row) = rows
            .next()
            .await
            .with_context(|| format!("read Agent authorization index for {table}"))?
        {
            if row
                .get::<i64>(2)
                .context("decode Agent authorization index uniqueness")?
                != 0
            {
                unique_indexes.push(row.get::<String>(1).context("decode Agent authorization index name")?);
            }
        }

        for index in unique_indexes {
            let escaped_index = index.replace('\'', "''");
            let mut columns = conn
                .query(&format!("PRAGMA index_info('{escaped_index}')"), ())
                .await
                .with_context(|| format!("inspect Agent authorization index {index}"))?;
            let mut actual_columns = Vec::new();
            while let Some(row) = columns
                .next()
                .await
                .with_context(|| format!("read Agent authorization index column for {index}"))?
            {
                actual_columns.push(
                    row.get::<String>(2)
                        .context("decode Agent authorization index column")?,
                );
            }
            if actual_columns
                .iter()
                .map(String::as_str)
                .eq(expected_columns.iter().copied())
            {
                return Ok(());
            }
        }

        bail!(
            "Agent authorization table {table} is missing a unique index on {}",
            expected_columns.join(", ")
        )
    }

    fn accepted_agent_from_row(row: &libsql::Row) -> anyhow::Result<AcceptedAgent> {
        let agent_id = row
            .get::<String>(0)
            .context("decode accepted Agent ID")?
            .parse()
            .context("parse accepted Agent ID")?;
        let name = row.get::<String>(1).context("decode accepted Agent name")?;
        let spki = row.get::<Vec<u8>>(2).context("decode accepted Agent SPKI SHA-256")?;
        let client_spki_sha256 = spki
            .try_into()
            .map_err(|_| anyhow::anyhow!("accepted Agent SPKI SHA-256 has an invalid length"))?;

        Ok(AcceptedAgent {
            agent_id,
            name,
            client_spki_sha256,
        })
    }
}

#[async_trait]
impl AgentAuthorizationStore for LibSqlAgentAuthorizationStore {
    async fn enroll(&self, attempt: EnrollmentAttempt) -> anyhow::Result<EnrollmentOutcome> {
        let accepted = AcceptedAgent {
            agent_id: attempt.agent_id,
            name: attempt.name.clone(),
            client_spki_sha256: attempt.client_spki_sha256,
        };
        let conn = self.conn.lock().await;
        conn.execute(
            "DELETE FROM agent_tunnel_enrollment_attempts
             WHERE expires_at < unixepoch() - 86400",
            (),
        )
        .await
        .context("purge expired Agent enrollment attempts")?;

        let existing_attempt = conn
            .query(
                "SELECT agent_id, request_sha256, deleted
                 FROM agent_tunnel_enrollment_attempts
                 WHERE jti = ?1",
                params![attempt.token_id.to_string()],
            )
            .await
            .context("query existing Agent enrollment attempt")?
            .next()
            .await
            .context("read existing Agent enrollment attempt")?;

        if let Some(row) = existing_attempt {
            let existing_agent_id = row.get::<String>(0).context("decode existing enrollment Agent ID")?;
            let existing_request_sha256 = row
                .get::<Vec<u8>>(1)
                .context("decode existing enrollment request SHA-256")?;
            let deleted = row.get::<i64>(2).context("decode existing enrollment deletion state")? != 0;

            if deleted
                || existing_agent_id != attempt.agent_id.to_string()
                || existing_request_sha256.as_slice() != attempt.request_sha256
            {
                return Ok(EnrollmentOutcome::Conflict(EnrollmentConflict::TokenReplay));
            }

            let existing_agent = conn
                .query(
                    "SELECT agent_id, name, client_spki_sha256
                     FROM agent_tunnel_accepted_agents
                     WHERE enrollment_jti = ?1",
                    params![attempt.token_id.to_string()],
                )
                .await
                .context("query Agent for enrollment retry")?
                .next()
                .await
                .context("read Agent for enrollment retry")?
                .as_ref()
                .map(Self::accepted_agent_from_row)
                .transpose()?;

            return Ok(match existing_agent {
                Some(existing_agent) if existing_agent == accepted => EnrollmentOutcome::Retry(existing_agent),
                _ => EnrollmentOutcome::Conflict(EnrollmentConflict::TokenReplay),
            });
        }

        let agent_id_exists = conn
            .query(
                "SELECT 1 FROM agent_tunnel_accepted_agents WHERE agent_id = ?1",
                params![attempt.agent_id.to_string()],
            )
            .await
            .context("check accepted Agent ID uniqueness")?
            .next()
            .await
            .context("read accepted Agent ID uniqueness")?
            .is_some();
        if agent_id_exists {
            return Ok(EnrollmentOutcome::Conflict(EnrollmentConflict::AgentId));
        }

        let agent_name_exists = conn
            .query(
                "SELECT 1 FROM agent_tunnel_accepted_agents WHERE name = ?1",
                params![attempt.name.clone()],
            )
            .await
            .context("check accepted Agent name uniqueness")?
            .next()
            .await
            .context("read accepted Agent name uniqueness")?
            .is_some();
        if agent_name_exists {
            return Ok(EnrollmentOutcome::Conflict(EnrollmentConflict::AgentName));
        }

        let deleted_key_exists = conn
            .query(
                "SELECT 1
                 FROM agent_tunnel_deleted_agent_keys
                 WHERE client_spki_sha256 = ?1",
                params![attempt.client_spki_sha256.to_vec()],
            )
            .await
            .context("check deleted Agent key")?
            .next()
            .await
            .context("read deleted Agent key")?
            .is_some();
        if deleted_key_exists {
            return Ok(EnrollmentOutcome::Conflict(EnrollmentConflict::DeletedKey));
        }

        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await
            .context("begin Agent enrollment transaction")?;

        tx.execute(
            "INSERT INTO agent_tunnel_enrollment_attempts (jti, agent_id, request_sha256, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                attempt.token_id.to_string(),
                attempt.agent_id.to_string(),
                attempt.request_sha256.to_vec(),
                attempt.token_expires_at,
            ],
        )
        .await
        .context("persist Agent enrollment attempt")?;
        tx.execute(
            "INSERT INTO agent_tunnel_accepted_agents (agent_id, name, client_spki_sha256, enrollment_jti)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                attempt.agent_id.to_string(),
                attempt.name,
                attempt.client_spki_sha256.to_vec(),
                attempt.token_id.to_string(),
            ],
        )
        .await
        .context("persist accepted Agent")?;
        tx.commit().await.context("commit Agent enrollment")?;

        Ok(EnrollmentOutcome::Created(accepted))
    }

    async fn authorize(&self, agent_id: Uuid, client_spki_sha256: SpkiSha256) -> anyhow::Result<Option<AcceptedAgent>> {
        let conn = self.conn.lock().await;
        let row = conn
            .query(
                "SELECT agent_id, name, client_spki_sha256
                 FROM agent_tunnel_accepted_agents
                 WHERE agent_id = ?1 AND client_spki_sha256 = ?2",
                params![agent_id.to_string(), client_spki_sha256.to_vec()],
            )
            .await
            .context("query accepted Agent credential")?
            .next()
            .await
            .context("read accepted Agent credential")?;

        row.as_ref().map(Self::accepted_agent_from_row).transpose()
    }

    async fn get(&self, agent_id: Uuid) -> anyhow::Result<Option<AcceptedAgent>> {
        let conn = self.conn.lock().await;
        let row = conn
            .query(
                "SELECT agent_id, name, client_spki_sha256
                 FROM agent_tunnel_accepted_agents
                 WHERE agent_id = ?1",
                params![agent_id.to_string()],
            )
            .await
            .context("query accepted Agent")?
            .next()
            .await
            .context("read accepted Agent")?;

        row.as_ref().map(Self::accepted_agent_from_row).transpose()
    }

    async fn list(&self) -> anyhow::Result<Vec<AcceptedAgent>> {
        let conn = self.conn.lock().await;
        let mut rows = conn
            .query(
                "SELECT agent_id, name, client_spki_sha256
                 FROM agent_tunnel_accepted_agents
                 ORDER BY name COLLATE NOCASE, agent_id",
                (),
            )
            .await
            .context("query accepted Agents")?;
        let mut agents = Vec::new();

        while let Some(row) = rows.next().await.context("read accepted Agent")? {
            agents.push(Self::accepted_agent_from_row(&row)?);
        }

        Ok(agents)
    }

    async fn delete(&self, agent_id: Uuid) -> anyhow::Result<Option<AcceptedAgent>> {
        let conn = self.conn.lock().await;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await
            .context("begin Agent deletion transaction")?;
        let row = tx
            .query(
                "SELECT agent_id, name, client_spki_sha256, enrollment_jti
                 FROM agent_tunnel_accepted_agents
                 WHERE agent_id = ?1",
                params![agent_id.to_string()],
            )
            .await
            .context("query Agent to delete")?
            .next()
            .await
            .context("read Agent to delete")?;

        let Some(row) = row else {
            return Ok(None);
        };

        let accepted = Self::accepted_agent_from_row(&row)?;
        let enrollment_jti = row.get::<String>(3).context("decode deleted Agent enrollment JTI")?;

        tx.execute(
            "INSERT OR IGNORE INTO agent_tunnel_deleted_agent_keys (client_spki_sha256, agent_id)
             VALUES (?1, ?2)",
            params![accepted.client_spki_sha256.to_vec(), agent_id.to_string()],
        )
        .await
        .context("remember deleted Agent key")?;
        tx.execute(
            "DELETE FROM agent_tunnel_accepted_agents WHERE agent_id = ?1",
            params![agent_id.to_string()],
        )
        .await
        .context("delete accepted Agent")?;
        tx.execute(
            "UPDATE agent_tunnel_enrollment_attempts SET deleted = 1 WHERE jti = ?1",
            params![enrollment_jti],
        )
        .await
        .context("prevent deleted Agent enrollment replay")?;
        tx.commit().await.context("commit Agent deletion")?;

        Ok(Some(accepted))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn connect(path: &str) -> anyhow::Result<Connection> {
        crate::GatewayDb::open_path(path).await?.connect().await
    }

    async fn open_store(path: &str, ca_spki_sha256: SpkiSha256) -> anyhow::Result<LibSqlAgentAuthorizationStore> {
        LibSqlAgentAuthorizationStore::open(connect(path).await?, ca_spki_sha256).await
    }

    fn enrollment(agent_id: Uuid) -> EnrollmentAttempt {
        EnrollmentAttempt {
            token_id: Uuid::new_v4(),
            token_expires_at: 1_999_999_999,
            agent_id,
            name: String::from("montreal-office"),
            client_spki_sha256: [0x11; 32],
            request_sha256: [0x22; 32],
        }
    }

    #[tokio::test]
    async fn accepted_agent_survives_reopen() {
        let temp_dir = tempfile::tempdir().expect("create temporary directory");
        let database_path = temp_dir.path().join("gateway.db");
        let database_path = database_path.to_str().expect("temporary database path is UTF-8");
        let ca_spki_sha256 = [0xCA; 32];
        let agent_id = Uuid::new_v4();

        let store = open_store(database_path, ca_spki_sha256)
            .await
            .expect("open Agent authorization store");
        let outcome = store.enroll(enrollment(agent_id)).await.expect("enroll Agent");
        assert!(matches!(outcome, EnrollmentOutcome::Created(_)));
        drop(store);

        let reopened = open_store(database_path, ca_spki_sha256)
            .await
            .expect("reopen Agent authorization store");
        let accepted = reopened
            .authorize(agent_id, [0x11; 32])
            .await
            .expect("authorize persisted Agent")
            .expect("Agent remains accepted");

        assert_eq!(accepted.agent_id, agent_id);
        assert_eq!(accepted.name, "montreal-office");
    }

    #[tokio::test]
    async fn identical_enrollment_retry_is_idempotent() {
        let store = open_store(":memory:", [0xCA; 32])
            .await
            .expect("open Agent authorization store");
        let attempt = enrollment(Uuid::new_v4());

        let created = store.enroll(attempt.clone()).await.expect("create Agent enrollment");
        assert!(matches!(created, EnrollmentOutcome::Created(_)));

        let retry = store.enroll(attempt).await.expect("retry Agent enrollment");
        assert!(matches!(retry, EnrollmentOutcome::Retry(_)));
    }

    #[tokio::test]
    async fn delete_prevents_original_enrollment_retry() {
        let store = open_store(":memory:", [0xCA; 32])
            .await
            .expect("open Agent authorization store");
        let attempt = enrollment(Uuid::new_v4());
        store.enroll(attempt.clone()).await.expect("create Agent enrollment");

        let deleted = store
            .delete(attempt.agent_id)
            .await
            .expect("delete accepted Agent")
            .expect("Agent was accepted");
        assert_eq!(deleted.agent_id, attempt.agent_id);
        assert!(
            store
                .authorize(attempt.agent_id, attempt.client_spki_sha256)
                .await
                .expect("query deleted Agent")
                .is_none()
        );

        let retry = store.enroll(attempt).await.expect("retry deleted enrollment");
        assert_eq!(retry, EnrollmentOutcome::Conflict(EnrollmentConflict::TokenReplay));
    }

    #[tokio::test]
    async fn accepted_agent_id_and_name_are_unique() {
        let store = open_store(":memory:", [0xCA; 32])
            .await
            .expect("open Agent authorization store");
        let first = enrollment(Uuid::new_v4());
        store.enroll(first.clone()).await.expect("enroll first Agent");

        let mut duplicate_id = enrollment(first.agent_id);
        duplicate_id.name = String::from("quebec-office");
        let outcome = store.enroll(duplicate_id).await.expect("check duplicate Agent ID");
        assert_eq!(outcome, EnrollmentOutcome::Conflict(EnrollmentConflict::AgentId));

        let mut duplicate_name = enrollment(Uuid::new_v4());
        duplicate_name.name = String::from("MONTREAL-OFFICE");
        let outcome = store.enroll(duplicate_name).await.expect("check duplicate Agent name");
        assert_eq!(outcome, EnrollmentOutcome::Conflict(EnrollmentConflict::AgentName));
    }

    #[tokio::test]
    async fn list_and_get_include_offline_accepted_agents() {
        let store = open_store(":memory:", [0xCA; 32])
            .await
            .expect("open Agent authorization store");
        let first = enrollment(Uuid::new_v4());
        let mut second = enrollment(Uuid::new_v4());
        second.name = String::from("quebec-office");
        second.client_spki_sha256 = [0x33; 32];
        second.request_sha256 = [0x44; 32];

        store.enroll(first.clone()).await.expect("enroll first Agent");
        store.enroll(second.clone()).await.expect("enroll second Agent");

        let agents = store.list().await.expect("list accepted Agents");
        assert_eq!(agents.len(), 2);
        assert!(agents.iter().any(|agent| agent.agent_id == first.agent_id));
        assert!(agents.iter().any(|agent| agent.agent_id == second.agent_id));

        let accepted = store
            .get(second.agent_id)
            .await
            .expect("get accepted Agent")
            .expect("second Agent exists");
        assert_eq!(accepted.name, "quebec-office");
        assert_eq!(accepted.client_spki_sha256, [0x33; 32]);
    }

    #[tokio::test]
    async fn enrollment_token_rejects_different_material() {
        let store = open_store(":memory:", [0xCA; 32])
            .await
            .expect("open Agent authorization store");
        let first = enrollment(Uuid::new_v4());
        store.enroll(first.clone()).await.expect("enroll Agent");

        let mut replay = first;
        replay.request_sha256 = [0x99; 32];
        let outcome = store.enroll(replay).await.expect("check enrollment replay");

        assert_eq!(outcome, EnrollmentOutcome::Conflict(EnrollmentConflict::TokenReplay));
    }

    #[tokio::test]
    async fn new_token_and_key_can_reenroll_deleted_agent() {
        let store = open_store(":memory:", [0xCA; 32])
            .await
            .expect("open Agent authorization store");
        let first = enrollment(Uuid::new_v4());
        store.enroll(first.clone()).await.expect("enroll Agent");
        store
            .delete(first.agent_id)
            .await
            .expect("delete Agent")
            .expect("Agent was accepted");

        let mut reenrollment = enrollment(first.agent_id);
        reenrollment.client_spki_sha256 = [0x77; 32];
        reenrollment.request_sha256 = [0x88; 32];
        let outcome = store
            .enroll(reenrollment)
            .await
            .expect("re-enroll Agent with new token and key");

        assert!(matches!(outcome, EnrollmentOutcome::Created(_)));
        assert!(
            store
                .authorize(first.agent_id, first.client_spki_sha256)
                .await
                .expect("authorize old Agent key")
                .is_none()
        );
        assert!(
            store
                .authorize(first.agent_id, [0x77; 32])
                .await
                .expect("authorize new Agent key")
                .is_some()
        );
    }

    #[tokio::test]
    async fn new_token_cannot_reenroll_deleted_agent_key() {
        let temp_dir = tempfile::tempdir().expect("create temporary directory");
        let database_path = temp_dir.path().join("gateway.db");
        let database_path = database_path.to_str().expect("temporary database path is UTF-8");
        let store = open_store(database_path, [0xCA; 32])
            .await
            .expect("open Agent authorization store");
        let first = enrollment(Uuid::new_v4());
        store.enroll(first.clone()).await.expect("enroll Agent");
        store
            .delete(first.agent_id)
            .await
            .expect("delete Agent")
            .expect("Agent was accepted");
        drop(store);

        let reopened = open_store(database_path, [0xCA; 32])
            .await
            .expect("reopen Agent authorization store");
        let replay = enrollment(first.agent_id);
        let outcome = reopened.enroll(replay).await.expect("check deleted Agent key");

        assert_eq!(outcome, EnrollmentOutcome::Conflict(EnrollmentConflict::DeletedKey));
    }

    #[tokio::test]
    async fn new_agent_id_cannot_reuse_deleted_agent_key() {
        let store = open_store(":memory:", [0xCA; 32])
            .await
            .expect("open Agent authorization store");
        let first = enrollment(Uuid::new_v4());
        store.enroll(first.clone()).await.expect("enroll Agent");
        store
            .delete(first.agent_id)
            .await
            .expect("delete Agent")
            .expect("Agent was accepted");

        let mut replay = enrollment(Uuid::new_v4());
        replay.name = String::from("quebec-office");
        let outcome = store.enroll(replay).await.expect("check deleted Agent key");

        assert_eq!(outcome, EnrollmentOutcome::Conflict(EnrollmentConflict::DeletedKey));
    }

    #[tokio::test]
    async fn database_rejects_another_ca() {
        let temp_dir = tempfile::tempdir().expect("create temporary directory");
        let database_path = temp_dir.path().join("gateway.db");
        let database_path = database_path.to_str().expect("temporary database path is UTF-8");
        let store = open_store(database_path, [0xCA; 32])
            .await
            .expect("open Agent authorization store");
        drop(store);

        let error = open_store(database_path, [0xBB; 32])
            .await
            .err()
            .expect("database must reject another CA");
        assert!(error.to_string().contains("different CA"));
    }

    #[tokio::test]
    async fn first_open_binds_the_ca() {
        let temp_dir = tempfile::tempdir().expect("create temporary directory");
        let database_path = temp_dir.path().join("gateway.db");
        let database_path = database_path.to_str().expect("temporary database path is UTF-8");

        let conn = connect(database_path).await.expect("open gateway database");
        let bound = LibSqlAgentAuthorizationStore::bound_ca(&conn)
            .await
            .expect("read bound CA");
        assert_eq!(bound, None);

        let store = LibSqlAgentAuthorizationStore::open(conn, [0xCA; 32])
            .await
            .expect("open Agent authorization store");
        drop(store);

        let conn = connect(database_path).await.expect("reopen gateway database");
        let bound = LibSqlAgentAuthorizationStore::bound_ca(&conn)
            .await
            .expect("read bound CA");
        assert_eq!(bound, Some([0xCA; 32]));
    }

    #[tokio::test]
    async fn database_with_agents_but_no_ca_is_rejected() {
        let temp_dir = tempfile::tempdir().expect("create temporary directory");
        let database_path = temp_dir.path().join("gateway.db");
        let database_path = database_path.to_str().expect("temporary database path is UTF-8");
        let store = open_store(database_path, [0xCA; 32])
            .await
            .expect("open Agent authorization store");
        store.enroll(enrollment(Uuid::new_v4())).await.expect("enroll Agent");
        drop(store);

        let conn = connect(database_path).await.expect("reopen gateway database");
        conn.execute(
            "DELETE FROM agent_tunnel_metadata WHERE key = ?1",
            params![CA_SPKI_SHA256_KEY],
        )
        .await
        .expect("delete CA metadata");

        let error = LibSqlAgentAuthorizationStore::open(conn, [0xBB; 32])
            .await
            .err()
            .expect("Agents without a CA must not be bound to a new CA");
        assert!(error.to_string().contains("missing CA"));
    }

    #[tokio::test]
    async fn agents_enrolled_on_2026_3_still_authorize_after_the_move() {
        let temp_dir = tempfile::tempdir().expect("create temporary directory");
        let data_dir =
            camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).expect("temporary path is UTF-8");
        let agent_id = Uuid::new_v4();

        let legacy = libsql::Builder::new_local(data_dir.join("agent_tunnel.db").as_str())
            .build()
            .await
            .expect("build 2026.3 database")
            .connect()
            .expect("open 2026.3 database");
        legacy
            .execute_batch(include_str!("../../gateway-db/migrations/01_agent_tunnel.sql"))
            .await
            .expect("create 2026.3 tables");
        legacy
            .execute(
                "INSERT INTO metadata (key, value) VALUES (?1, ?2)",
                params![CA_SPKI_SHA256_KEY, vec![0xCAu8; 32]],
            )
            .await
            .expect("bind 2026.3 CA");
        legacy
            .execute(
                "INSERT INTO accepted_agents (agent_id, name, client_spki_sha256, enrollment_jti) VALUES (?1, ?2, ?3, ?4)",
                params![agent_id.to_string(), "montreal-office", vec![0x11u8; 32], Uuid::new_v4().to_string()],
            )
            .await
            .expect("store 2026.3 Agent");
        legacy
            .execute_batch("PRAGMA user_version = 1")
            .await
            .expect("record 2026.3 schema version");
        drop(legacy);

        let conn = crate::GatewayDb::open(&data_dir)
            .await
            .expect("open gateway database")
            .connect()
            .await
            .expect("connect to gateway database");
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
    async fn database_rejects_missing_required_table() {
        let temp_dir = tempfile::tempdir().expect("create temporary directory");
        let database_path = temp_dir.path().join("gateway.db");
        let database_path = database_path.to_str().expect("temporary database path is UTF-8");
        let store = open_store(database_path, [0xCA; 32])
            .await
            .expect("open Agent authorization store");
        drop(store);

        let database = libsql::Builder::new_local(database_path)
            .build()
            .await
            .expect("open Agent authorization database");
        let conn = database.connect().expect("connect to Agent authorization database");
        conn.execute("DROP TABLE agent_tunnel_accepted_agents", ())
            .await
            .expect("drop required table");
        drop(conn);
        drop(database);

        let error = open_store(database_path, [0xCA; 32])
            .await
            .err()
            .expect("database must reject missing required table");
        assert!(error.to_string().contains("accepted_agents"));
    }

    #[tokio::test]
    async fn database_rejects_missing_required_unique_index() {
        let temp_dir = tempfile::tempdir().expect("create temporary directory");
        let database_path = temp_dir.path().join("gateway.db");
        let database_path = database_path.to_str().expect("temporary database path is UTF-8");
        let store = open_store(database_path, [0xCA; 32])
            .await
            .expect("open Agent authorization store");
        drop(store);

        let database = libsql::Builder::new_local(database_path)
            .build()
            .await
            .expect("open Agent authorization database");
        let conn = database.connect().expect("connect to Agent authorization database");
        conn.execute_batch(
            "
            ALTER TABLE agent_tunnel_accepted_agents RENAME TO agent_tunnel_accepted_agents_with_name_index;
            CREATE TABLE agent_tunnel_accepted_agents (
                agent_id TEXT PRIMARY KEY,
                name TEXT NOT NULL COLLATE NOCASE,
                client_spki_sha256 BLOB NOT NULL,
                enrollment_jti TEXT NOT NULL UNIQUE,
                CHECK (length(name) BETWEEN 1 AND 255),
                CHECK (name = trim(name)),
                CHECK (length(client_spki_sha256) = 32)
            );
            DROP TABLE agent_tunnel_accepted_agents_with_name_index;
            ",
        )
        .await
        .expect("remove required Agent name index");
        drop(conn);
        drop(database);

        let error = open_store(database_path, [0xCA; 32])
            .await
            .err()
            .expect("database must reject missing Agent name index");
        assert!(error.to_string().contains("name"));
    }
}
