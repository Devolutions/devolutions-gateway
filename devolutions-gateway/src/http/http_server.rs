use crate::config::Config;
use crate::http::controllers::association::AssociationController;
use crate::http::controllers::diagnostics::DiagnosticsController;
use crate::http::controllers::health::HealthController;
use crate::http::controllers::http_bridge::HttpBridgeController;
use crate::http::controllers::sessions::{LegacySessionsController, SessionsController};
use crate::http::controllers::sogar_token::TokenController;
use crate::http::middlewares::auth::AuthMiddleware;
use crate::http::middlewares::log::LogMiddleware;
use crate::http::middlewares::sogar_auth::SogarAuthMiddleware;
use crate::jet_client::JetAssociationsMap;
use saphir::server::Server as SaphirServer;
use slog_scope::info;
use sogar_core::registry::SogarController;
use std::sync::Arc;

pub const REGISTRY_NAME: &str = "devolutions_registry";
pub const NAMESPACE: &str = "videos";

pub fn configure_http_server(config: Arc<Config>, jet_associations: JetAssociationsMap) -> anyhow::Result<()> {
    SaphirServer::builder()
        .configure_middlewares(|middlewares| {
            info!("Loading HTTP middlewares");

            middlewares
                .apply(
                    AuthMiddleware::new(config.clone()),
                    vec!["/"],
                    vec!["/registry", "/health", "/jet/health"],
                )
                .apply(
                    SogarAuthMiddleware::new(config.clone()),
                    vec!["/registry"],
                    vec!["/registry/oauth2/token"],
                )
                .apply(LogMiddleware, vec!["/"], None)
        })
        .configure_router(|router| {
            info!("Loading HTTP controllers");

            let (diagnostics, legacy_diagnostics) = DiagnosticsController::new(config.clone());
            let (health, legacy_health) = HealthController::new(config.clone());
            let http_bridge = HttpBridgeController::new();
            let jet = AssociationController::new(config.clone(), jet_associations.clone());

            // sogar stuff
            let token_controller = TokenController::new(config.clone());
            let registry_name = config
                .sogar_registry_config
                .local_registry_name
                .clone()
                .unwrap_or_else(|| String::from(REGISTRY_NAME));
            let registry_namespace = config
                .sogar_registry_config
                .local_registry_image
                .clone()
                .unwrap_or_else(|| String::from(NAMESPACE));
            let sogar = SogarController::new(registry_name.as_str(), registry_namespace.as_str());

            info!("Configuring HTTP router");

            router
                .controller(diagnostics)
                .controller(health)
                .controller(http_bridge)
                .controller(jet)
                .controller(SessionsController)
                .controller(sogar)
                .controller(token_controller)
                .controller(legacy_health)
                .controller(legacy_diagnostics)
                .controller(LegacySessionsController)
        })
        .configure_listener(|listener| listener.server_name("Devolutions Gateway"))
        .build_stack_only()?;

    Ok(())
}
