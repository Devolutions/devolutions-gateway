use axum::http::{header, Method};
use tower_http::cors::CorsLayer;

pub fn make_middleware() -> CorsLayer {
    CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::PATCH])
        .allow_headers([tower_http::cors::Any, header::AUTHORIZATION])
        .allow_origin(tower_http::cors::Any)
        .max_age(std::time::Duration::from_secs(7200))
        .allow_credentials(false)
}
