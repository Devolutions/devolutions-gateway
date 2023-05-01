pub mod config;
pub mod diagnostics;
pub mod fwd;
pub mod health;
pub mod heartbeat;
pub mod jmux;
pub mod jrec;
pub mod jrl;
pub mod kdc_proxy;
pub mod rdp;
pub mod session;
pub mod sessions;

pub fn make_router<S>(state: crate::DgwState) -> axum::Router<S> {
    axum::Router::new()
        .route("/jet/health", axum::routing::get(health::get_health))
        .route("/jet/heartbeat", axum::routing::get(heartbeat::get_heartbeat))
        .nest("/jet/jrl", jrl::make_router(state.clone()))
        .nest("/jet/jrec", jrec::make_router(state.clone()))
        .nest("/jet/config", config::make_router(state.clone()))
        .nest("/jet/session", session::make_router(state.clone()))
        .nest("/jet/sessions", sessions::make_router(state.clone()))
        .nest("/jet/diagnostics", diagnostics::make_router(state.clone()))
        .route("/jet/jmux", axum::routing::get(jmux::handler))
        .route("/jet/rdp", axum::routing::get(rdp::handler))
        .nest("/jet/fwd", fwd::make_router(state.clone()))
        .with_state(state)
}
