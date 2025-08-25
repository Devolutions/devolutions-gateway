pub mod config;
pub mod diagnostics;
pub mod fwd;
pub mod health;
pub mod heartbeat;
pub mod jmux;
pub mod jrec;
pub mod jrl;
pub mod kdc_proxy;
pub mod monitoring;
pub mod net;
pub mod preflight;
pub mod rdp;
pub mod session;
pub mod sessions;
pub mod update;
pub mod webapp;

pub fn make_router<S>(state: crate::DgwState) -> axum::Router<S> {
    let mut router = axum::Router::new()
        .route("/jet/health", axum::routing::get(health::get_health))
        .route("/jet/heartbeat", axum::routing::get(heartbeat::get_heartbeat))
        .route("/jet/preflight", axum::routing::post(preflight::post_preflight))
        .nest("/jet/jrl", jrl::make_router(state.clone()))
        .nest("/jet/jrec", jrec::make_router(state.clone()))
        .nest("/jet/config", config::make_router(state.clone()))
        .nest("/jet/session", session::make_router(state.clone()))
        .nest("/jet/sessions", sessions::make_router(state.clone()))
        .nest("/jet/diagnostics", diagnostics::make_router(state.clone()))
        .route("/jet/jmux", axum::routing::get(jmux::handler))
        .route("/jet/rdp", axum::routing::get(rdp::handler))
        .nest("/jet/fwd", fwd::make_router(state.clone()))
        .nest("/jet/webapp", webapp::make_router(state.clone()))
        .nest("/jet/net", net::make_router(state.clone()))
        .route("/jet/update", axum::routing::post(update::trigger_update_check));

    if state.conf_handle.get_conf().web_app.enabled {
        router = router.route(
            "/",
            axum::routing::get(|| async { axum::response::Redirect::temporary("/jet/webapp/client") }),
        );
    }

    if state.conf_handle.get_conf().debug.enable_unstable {
        router = router.nest("/jet/net/monitor", monitoring::make_router(state.clone()));
    }

    router.with_state(state)
}
