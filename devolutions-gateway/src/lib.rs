#![recursion_limit = "1024"]

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
use token::{ApplicationProtocol, ConnectionMode, JetAssociationTokenClaims};
use tokio::sync::RwLock;
use uuid::Uuid;

lazy_static! {
    pub static ref SESSIONS_IN_PROGRESS: RwLock<HashMap<Uuid, GatewaySessionInfo>> = RwLock::new(HashMap::new());
}

#[derive(Serialize, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
pub enum SessionConnectionMode {
    Rdv,
    Fwd,
}

#[derive(Serialize, Clone)]
pub struct GatewaySessionInfo {
    association_id: Uuid,
    application_protocol: ApplicationProtocol,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination_host: Option<String>,
    connection_mode: SessionConnectionMode,
    recording_policy: bool,
    filtering_policy: bool,
    start_timestamp: DateTime<Utc>,
}

impl Default for GatewaySessionInfo {
    fn default() -> Self {
        GatewaySessionInfo {
            association_id: Uuid::new_v4(),
            application_protocol: ApplicationProtocol::Unknown,
            destination_host: None,
            // FIXME: we actually don't know the jet connection mode at this point.
            // A "default" session info is not very useful.
            connection_mode: SessionConnectionMode::Rdv,
            recording_policy: false,
            filtering_policy: false,
            start_timestamp: Utc::now(),
        }
    }
}

impl GatewaySessionInfo {
    pub fn id(&self) -> Uuid {
        self.association_id
    }
}

impl From<JetAssociationTokenClaims> for GatewaySessionInfo {
    fn from(association_token: JetAssociationTokenClaims) -> Self {
        let (destination_host, connection_mode) = match association_token.jet_cm {
            ConnectionMode::Rdv => (None, SessionConnectionMode::Rdv),
            ConnectionMode::Fwd { dst_hst, .. } => (Some(dst_hst), SessionConnectionMode::Fwd),
        };

        GatewaySessionInfo {
            association_id: association_token.jet_aid,
            application_protocol: association_token.jet_ap,
            destination_host,
            connection_mode,
            recording_policy: association_token.jet_rec,
            filtering_policy: association_token.jet_flt,
            start_timestamp: Utc::now(),
        }
    }
}

pub async fn add_session_in_progress(session: GatewaySessionInfo) {
    let mut sessions = SESSIONS_IN_PROGRESS.write().await;
    sessions.insert(session.association_id, session);
}

pub async fn remove_session_in_progress(id: Uuid) {
    SESSIONS_IN_PROGRESS.write().await.remove(&id);
}
