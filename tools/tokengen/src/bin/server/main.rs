// This Server binary is intended to be used as a standalone server for the provisioner key
// Primarily for development and testing purposes
#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "server")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use axum::http::Method;
    use server::{create_router, get_provisioner_key_path};
    use std::path::PathBuf;
    use std::sync::Arc;
    use tower_http::trace::TraceLayer;
    use tracing::info;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!(
                    "{}=debug,tower_http=debug,axum::rejection=trace",
                    env!("CARGO_CRATE_NAME")
                )
                .into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Read the provisioner key path from the configuration
    let provisioner_key_path: Arc<PathBuf> = get_provisioner_key_path().await?;

    // Create the router with subcommand routes
    let app = create_router(provisioner_key_path)
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_methods([Method::POST, Method::OPTIONS, Method::GET])
                .allow_headers(tower_http::cors::Any)
                .allow_origin(tower_http::cors::Any),
        )
        .layer(TraceLayer::new_for_http());

    // Run the app with hyper on localhost:8080
    let addr = "127.0.0.1:8080";
    let listner = tokio::net::TcpListener::bind(&addr).await?;
    info!("Listening on {}", addr);
    axum::serve(listner, app).await?;

    Ok(())
}
