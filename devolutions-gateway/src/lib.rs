#[macro_use]
extern crate slog_scope;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

pub mod config;
pub mod generic_client;
pub mod http;
pub mod interceptor;
pub mod jet;
pub mod jet_client;
pub mod jet_rendezvous_tcp_proxy;
pub mod listener;
pub mod logger;
pub mod plugin_manager;
pub mod preconnection_pdu;
pub mod proxy;
pub mod rdp;
pub mod registry;
pub mod routing_client;
pub mod service;
pub mod token;
pub mod transport;
pub mod utils;
pub mod websocket_client;

pub use proxy::Proxy;

use chrono::{DateTime, Utc};
use lazy_static::lazy_static;
use std::collections::HashMap;
use token::ApplicationProtocol;
use tokio::sync::RwLock;
use utils::TargetAddr;
use uuid::Uuid;

// TODO: investigate if parking_lot::RwLock should be used instead
lazy_static! {
    pub static ref SESSIONS_IN_PROGRESS: RwLock<HashMap<Uuid, GatewaySessionInfo>> = RwLock::new(HashMap::new());
}

#[derive(Debug, Serialize, Clone)]
pub struct GatewaySessionInfo {
    association_id: Uuid,
    application_protocol: ApplicationProtocol,
    recording_policy: bool,
    filtering_policy: bool,
    start_timestamp: DateTime<Utc>,
    #[serde(flatten)]
    mode_details: ConnectionModeDetails,
}

#[derive(Debug, Serialize, Clone)]
#[serde(tag = "connection_mode")]
#[serde(rename_all = "lowercase")]
pub enum ConnectionModeDetails {
    Rdv,
    Fwd { destination_host: TargetAddr },
}

impl GatewaySessionInfo {
    pub fn new(association_id: Uuid, ap: ApplicationProtocol, mode_details: ConnectionModeDetails) -> Self {
        Self {
            association_id,
            application_protocol: ap,
            recording_policy: false,
            filtering_policy: false,
            start_timestamp: Utc::now(),
            mode_details,
        }
    }

    pub fn with_recording_policy(mut self, value: bool) -> Self {
        self.recording_policy = value;
        self
    }

    pub fn with_filtering_policy(mut self, value: bool) -> Self {
        self.filtering_policy = value;
        self
    }

    pub fn id(&self) -> Uuid {
        self.association_id
    }
}

pub async fn add_session_in_progress(session: GatewaySessionInfo) {
    let mut sessions = SESSIONS_IN_PROGRESS.write().await;
    sessions.insert(session.association_id, session);
}

pub async fn remove_session_in_progress(id: Uuid) {
    SESSIONS_IN_PROGRESS.write().await.remove(&id);
}
