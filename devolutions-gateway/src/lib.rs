// Used by devolutions-gateway binary.
use ceviche as _;
// Used by tests.
#[cfg(test)]
use {devolutions_gateway_generators as _, http_body_util as _, proptest as _, tokio_test as _, tracing_cov_mark as _};

#[macro_use]
extern crate serde;
#[macro_use]
extern crate tracing;

#[cfg(feature = "openapi")]
pub mod openapi;

pub mod ai;
pub mod api;
pub mod config;
pub mod credential;
pub mod extract;
pub mod generic_client;
pub mod http;
pub mod interceptor;
pub mod jmux;
pub mod job_queue;
pub mod listener;
pub mod log;
pub mod middleware;
pub mod ngrok;
pub mod plugin_manager;
pub mod proxy;
pub mod rd_clean_path;
pub mod rdp_pcb;
pub mod rdp_proxy;
pub mod recording;
pub mod session;
pub mod streaming;
pub mod subscriber;
pub mod target_addr;
pub mod tls;
pub mod token;
pub mod traffic_audit;
pub mod utils;
pub mod ws;

use std::sync::Arc;

pub static SYSTEM_LOGGER: std::sync::LazyLock<Arc<dyn sysevent::SystemEventSink>> =
    std::sync::LazyLock::new(init_system_logger);

#[derive(Clone)]
pub struct DgwState {
    pub conf_handle: config::ConfHandle,
    pub token_cache: Arc<token::TokenCache>,
    pub jrl: Arc<token::CurrentJrl>,
    pub sessions: session::SessionMessageSender,
    pub subscriber_tx: subscriber::SubscriberSender,
    pub shutdown_signal: devolutions_gateway_task::ShutdownSignal,
    pub recordings: recording::RecordingMessageSender,
    pub job_queue_handle: job_queue::JobQueueHandle,
    pub credential_store: credential::CredentialStoreHandle,
    pub monitoring_state: Arc<network_monitor::State>,
    pub traffic_audit_handle: traffic_audit::TrafficAuditHandle,
}

#[doc(hidden)]
pub struct MockHandles {
    pub session_manager_rx: session::SessionMessageReceiver,
    pub recording_manager_rx: recording::RecordingMessageReceiver,
    pub subscriber_rx: subscriber::SubscriberReceiver,
    pub job_queue_rx: job_queue::JobQueueReceiver,
    pub traffic_audit_rx: traffic_audit::TrafficAuditReceiver,
    pub shutdown_handle: devolutions_gateway_task::ShutdownHandle,
}

impl DgwState {
    #[doc(hidden)]
    pub fn mock(json_config: &str) -> anyhow::Result<(Self, MockHandles)> {
        let conf_handle = config::ConfHandle::mock(json_config)?;
        let token_cache = Arc::new(token::new_token_cache());
        let jrl = Arc::new(parking_lot::Mutex::new(token::JrlTokenClaims::default()));
        let (session_manager_handle, session_manager_rx) = session::session_manager_channel();
        let (recording_manager_handle, recording_manager_rx) = recording::recording_message_channel();
        let (subscriber_tx, subscriber_rx) = subscriber::subscriber_channel();
        let (shutdown_handle, shutdown_signal) = devolutions_gateway_task::ShutdownHandle::new();
        let (job_queue_handle, job_queue_rx) = job_queue::JobQueueHandle::new();
        let (traffic_audit_handle, traffic_audit_rx) = traffic_audit::TrafficAuditHandle::new();
        let credential_store = credential::CredentialStoreHandle::new();
        let monitoring_state = Arc::new(network_monitor::State::new(Arc::new(MockMonitorsCache))?);

        let state = Self {
            conf_handle,
            token_cache,
            jrl,
            sessions: session_manager_handle,
            subscriber_tx,
            shutdown_signal,
            recordings: recording_manager_handle,
            job_queue_handle,
            traffic_audit_handle,
            credential_store,
            monitoring_state,
        };

        let handles = MockHandles {
            session_manager_rx,
            recording_manager_rx,
            subscriber_rx,
            job_queue_rx,
            traffic_audit_rx,
            shutdown_handle,
        };

        return Ok((state, handles));

        struct MockMonitorsCache;

        impl network_monitor::ConfigCache for MockMonitorsCache {
            fn store(&self, _: &network_monitor::MonitorsConfig) -> anyhow::Result<()> {
                Ok(())
            }
        }
    }
}

pub fn make_http_service(state: DgwState) -> axum::Router<()> {
    use std::time::Duration;

    use axum::error_handling::HandleErrorLayer;
    use tower::ServiceBuilder;
    use tower::timeout::TimeoutLayer;

    trace!("Make http service");

    axum::Router::new()
        .merge(api::make_router(state.clone()))
        .nest_service("/KdcProxy", api::kdc_proxy::make_router(state.clone()))
        .nest_service("/jet/KdcProxy", api::kdc_proxy::make_router(state.clone()))
        .layer(
            // NOTE: It is recommended to use `tower::ServiceBuilder` when applying multiple middlewares at once:
            // https://docs.rs/axum/0.6.20/axum/middleware/index.html#applying-multiple-middleware
            ServiceBuilder::new()
                .layer(axum::middleware::from_fn(middleware::log::log_middleware))
                .layer(middleware::cors::make_middleware())
                .layer(axum::middleware::from_fn_with_state(
                    state,
                    middleware::auth::auth_middleware,
                ))
                // This middleware goes above `TimeoutLayer` because it will receive errors returned by `TimeoutLayer`.
                .layer(HandleErrorLayer::new(|_: axum::BoxError| async {
                    hyper::StatusCode::REQUEST_TIMEOUT
                }))
                .layer(TimeoutLayer::new(Duration::from_secs(15))),
        )
}

fn init_system_logger() -> Arc<dyn sysevent::SystemEventSink> {
    cfg_if::cfg_if! {
        if #[cfg(all(not(debug_assertions), unix))] {
            let options = sysevent_syslog::SyslogOptions::default()
                .log_pid(true)
                .facility(sysevent::Facility::Daemon);
            match sysevent_syslog::Syslog::new(c"devolutions-gateway", options) {
                Ok(syslog) => Arc::new(syslog),
                Err(_) => Arc::new(sysevent::NoopSink),
            }
        } else if #[cfg(all(not(debug_assertions), windows))] {
            match sysevent_winevent::WinEvent::new("Devolutions Gateway") {
                Ok(winevent) => Arc::new(winevent),
                Err(_) => Arc::new(sysevent::NoopSink),
            }
        } else {
            Arc::new(sysevent::NoopSink)
        }
    }
}
