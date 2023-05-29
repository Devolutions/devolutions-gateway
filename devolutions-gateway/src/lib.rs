use std::sync::Arc;

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate tracing;

#[cfg(feature = "openapi")]
pub mod openapi;

pub mod api;
pub mod config;
pub mod extract;
pub mod generic_client;
pub mod http;
pub mod interceptor;
pub mod jmux;
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
pub mod subscriber;
pub mod target_addr;
pub mod tls;
pub mod token;
pub mod utils;
pub mod ws;

#[derive(Clone)]
pub struct DgwState {
    pub conf_handle: config::ConfHandle,
    pub token_cache: Arc<token::TokenCache>,
    pub jrl: Arc<token::CurrentJrl>,
    pub sessions: session::SessionManagerHandle,
    pub subscriber_tx: subscriber::SubscriberSender,
    pub shutdown_signal: devolutions_gateway_task::ShutdownSignal,
}

pub fn make_http_service(state: DgwState) -> axum::Router<()> {
    trace!("make http service");

    axum::Router::new()
        .merge(api::make_router(state.clone()))
        .nest_service("/KdcProxy", api::kdc_proxy::make_router(state.conf_handle.clone()))
        .nest_service("/jet/KdcProxy", api::kdc_proxy::make_router(state.conf_handle.clone()))
        .layer(axum::middleware::from_fn_with_state(
            state,
            middleware::auth::auth_middleware,
        ))
        .layer(middleware::cors::make_middleware())
        .layer(axum::middleware::from_fn(middleware::log::log_middleware))
        .layer(
            tower::ServiceBuilder::new()
                .layer(axum::error_handling::HandleErrorLayer::new(
                    |error: tower::BoxError| async move {
                        debug!(%error, "timed out");
                        axum::http::StatusCode::REQUEST_TIMEOUT
                    },
                ))
                .timeout(std::time::Duration::from_secs(15)),
        )
}
