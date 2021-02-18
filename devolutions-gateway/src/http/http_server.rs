use crate::config::Config;
use crate::http::controllers::health::HealthController;
use crate::http::controllers::jet::JetController;
use crate::http::controllers::sessions::SessionsController;
use crate::http::middlewares::auth::AuthMiddleware;
use crate::jet_client::JetAssociationsMap;
use saphir::server::Server as SaphirServer;
use slog_scope::info;
use std::sync::Arc;

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

            middlewares.apply(
                AuthMiddleware::new(config.clone()),
                auth_include_path,
                Some(auth_exclude_path),
            )
        })
        .configure_router(|router| {
            info!("Loading HTTP controllers");
            let health = HealthController::new(config.clone());
            let jet = JetController::new(config.clone(), jet_associations.clone());
            let session = SessionsController::default();
            info!("Configuring HTTP router");
            router.controller(health).controller(jet).controller(session)
        })
        .configure_listener(|listener| listener.server_name("Devolutions Gateway"))
        .build_stack_only()
        .map_err(|e| e.to_string())
}
