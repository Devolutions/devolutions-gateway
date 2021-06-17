use crate::config::Config;
use crate::http::controllers::health::HealthController;
use crate::http::controllers::jet::JetController;
use crate::http::controllers::sessions::SessionsController;
use crate::http::controllers::sogar_token::TokenController;
use crate::http::middlewares::auth::AuthMiddleware;
use crate::http::middlewares::log::LogMiddleware;
use crate::http::middlewares::sogar_auth::SogarAuthMiddleware;
use crate::jet_client::JetAssociationsMap;
use saphir::server::Server as SaphirServer;
use slog_scope::info;
use sogar_core::registry::{SogarController, BLOB_GET_LOCATION_PATH, BLOB_PATH, MANIFEST_PATH, UPLOAD_BLOB_PATH};
use std::sync::Arc;

pub const REGISTRY_NAME: &str = "devolutions_registry";
pub const NAMESPACE: &str = "videos";

pub fn configure_http_server(config: Arc<Config>, jet_associations: JetAssociationsMap) -> Result<(), String> {
    SaphirServer::builder()
        .configure_middlewares(|middlewares| {
            info!("Loading HTTP middlewares");

            // Only the "create association" should requires authorization.
            let mut auth_include_path = vec!["/jet/association"];
            let mut auth_exclude_path = vec!["/jet/association/<association_id>/<anything>"];

            if config.unrestricted {
                auth_exclude_path.push("/jet/association/<association_id>");
            } else {
                auth_include_path.push("/jet/association/<association_id>");
            }

            middlewares
                .apply(
                    AuthMiddleware::new(config.clone()),
                    auth_include_path,
                    Some(auth_exclude_path),
                )
                .apply(
                    SogarAuthMiddleware::new(config.clone()),
                    vec![BLOB_PATH, BLOB_GET_LOCATION_PATH, UPLOAD_BLOB_PATH, MANIFEST_PATH],
                    vec!["registry/oauth2/token"],
                )
                .apply(LogMiddleware, vec!["/"], None)
        })
        .configure_router(|router| {
            info!("Loading HTTP controllers");
            let health = HealthController::new(config.clone());
            let jet = JetController::new(config.clone(), jet_associations.clone());
            let session = SessionsController::default();

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
            let token_controller = TokenController::new(config.clone());

            info!("Configuring HTTP router");
            router
                .controller(health)
                .controller(jet)
                .controller(session)
                .controller(sogar)
                .controller(token_controller)
        })
        .configure_listener(|listener| listener.server_name("Devolutions Gateway"))
        .build_stack_only()
        .map_err(|e| e.to_string())
}
