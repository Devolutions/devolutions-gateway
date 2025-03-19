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

pub mod api;
pub mod config;
pub mod credendials;
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
pub mod rdp_extension;
pub mod rdp_pcb;
pub mod recording;
pub mod session;
pub mod streaming;
pub mod subscriber;
pub mod target_addr;
pub mod tls;
pub mod token;
pub mod utils;
pub mod ws;

use std::sync::Arc;

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
}

#[doc(hidden)]
pub struct MockHandles {
    pub session_manager_rx: session::SessionMessageReceiver,
    pub recording_manager_rx: recording::RecordingMessageReceiver,
    pub subscriber_rx: subscriber::SubscriberReceiver,
    pub job_queue_rx: job_queue::JobQueueReceiver,
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

        let state = Self {
            conf_handle,
            token_cache,
            jrl,
            sessions: session_manager_handle,
            subscriber_tx,
            shutdown_signal,
            recordings: recording_manager_handle,
            job_queue_handle,
        };

        let handles = MockHandles {
            session_manager_rx,
            recording_manager_rx,
            subscriber_rx,
            job_queue_rx,
            shutdown_handle,
        };

        Ok((state, handles))
    }
}

pub fn make_http_service(state: DgwState) -> axum::Router<()> {
    use axum::error_handling::HandleErrorLayer;
    use std::time::Duration;
    use tower::timeout::TimeoutLayer;
    use tower::ServiceBuilder;

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
