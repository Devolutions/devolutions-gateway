use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

pub type SpkiSha256 = [u8; 32];
pub type DynAgentAuthorizationStore = Arc<dyn AgentAuthorizationStore>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedAgent {
    pub agent_id: Uuid,
    pub name: String,
    pub client_spki_sha256: SpkiSha256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentAttempt {
    pub token_id: Uuid,
    pub token_expires_at: i64,
    pub agent_id: Uuid,
    pub name: String,
    pub client_spki_sha256: SpkiSha256,
    pub request_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentConflict {
    AgentId,
    AgentName,
    DeletedKey,
    TokenReplay,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnrollmentOutcome {
    Created(AcceptedAgent),
    Retry(AcceptedAgent),
    Conflict(EnrollmentConflict),
}

#[async_trait]
pub trait AgentAuthorizationStore: Send + Sync {
    async fn enroll(&self, attempt: EnrollmentAttempt) -> anyhow::Result<EnrollmentOutcome>;

    async fn authorize(&self, agent_id: Uuid, client_spki_sha256: SpkiSha256) -> anyhow::Result<Option<AcceptedAgent>>;

    async fn get(&self, agent_id: Uuid) -> anyhow::Result<Option<AcceptedAgent>>;

    async fn list(&self) -> anyhow::Result<Vec<AcceptedAgent>>;

    async fn delete(&self, agent_id: Uuid) -> anyhow::Result<Option<AcceptedAgent>>;
}
