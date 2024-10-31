use tower_http::cors::{self, AllowHeaders, CorsLayer};

pub fn make_middleware() -> CorsLayer {
    CorsLayer::new()
        .allow_methods(cors::Any)
        .allow_headers(AllowHeaders::mirror_request())
        .allow_origin(cors::Any)
        .max_age(std::time::Duration::from_secs(7200))
        .allow_credentials(false)
}
