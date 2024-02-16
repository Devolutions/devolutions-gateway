use crate::DgwState;
use axum::Router;

pub mod ipconfig;
pub mod scan;

pub fn make_router<S>(state: DgwState) -> Router<S> {
    Router::new()
        .route("/", axum::routing::get(scan::handler))
        .route("/ipconfig", axum::routing::get(ipconfig::handler))
        .with_state(state)
}
