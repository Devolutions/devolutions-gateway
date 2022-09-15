use crate::config::ConfHandle;
use crate::http::controllers::association::AssociationController;
use crate::http::controllers::config::ConfigController;
use crate::http::controllers::diagnostics::DiagnosticsController;
use crate::http::controllers::health::HealthController;
use crate::http::controllers::http_bridge::HttpBridgeController;
use crate::http::controllers::jrl::JrlController;
use crate::http::controllers::kdc_proxy::KdcProxyController;
use crate::http::controllers::session::SessionController;
use crate::http::controllers::sessions::{LegacySessionsController, SessionsController};
use crate::http::controllers::sogar_token::TokenController;
use crate::http::middlewares::auth::AuthMiddleware;
use crate::http::middlewares::cors::CorsMiddleware;
use crate::http::middlewares::log::LogMiddleware;
use crate::http::middlewares::sogar_auth::SogarAuthMiddleware;
use crate::jet_client::JetAssociationsMap;
use crate::session::SessionManagerHandle;
use crate::token::{CurrentJrl, TokenCache};
use saphir::server::Server as SaphirServer;
use sogar_core::registry::SogarController;
use std::sync::Arc;

pub fn configure_http_server(
    conf_handle: ConfHandle,
    associations: Arc<JetAssociationsMap>,
    token_cache: Arc<TokenCache>,
    jrl: Arc<CurrentJrl>,
    sessions: SessionManagerHandle,
) -> anyhow::Result<()> {
    SaphirServer::builder()
        .configure_middlewares(|middlewares| {
            info!("Loading HTTP middlewares");

            middlewares
                .apply(
                    AuthMiddleware::new(conf_handle.clone(), token_cache.clone(), jrl.clone()),
                    vec!["/"],
                    vec![
                        "/registry",
                        "/health",
                        "/jet/health",
                        "/jet/diagnostics/clock",
                        "/KdcProxy",
                        "/jet/KdcProxy",
                    ],
                )
                .apply(
                    SogarAuthMiddleware::new(conf_handle.clone()),
                    vec!["/registry"],
                    vec!["/registry/oauth2/token"],
                )
                .apply(CorsMiddleware, vec!["/"], None)
                .apply(LogMiddleware, vec!["/"], None)
        })
        .configure_router(|router| {
            info!("Loading HTTP controllers");

            let (diagnostics, legacy_diagnostics) = DiagnosticsController::new(conf_handle.clone());
            let (health, legacy_health) = HealthController::new(conf_handle.clone());
            let http_bridge = HttpBridgeController::new();
            let jet = AssociationController::new(conf_handle.clone(), associations.clone());
            let kdc_proxy = KdcProxyController {
                conf_handle: conf_handle.clone(),
                token_cache,
                jrl: jrl.clone(),
            };
            let duplicated_kdc_proxy = kdc_proxy.duplicated();
            let jrl = JrlController::new(conf_handle.clone(), jrl);
            let config = ConfigController::new(conf_handle.clone());

            let session_controller = SessionController {
                sessions: sessions.clone(),
            };

            let sessions_controller = SessionsController {
                sessions: sessions.clone(),
            };
            let legacy_sessions_controller = LegacySessionsController { sessions };

            // sogar stuff
            let conf = conf_handle.get_conf();
            let sogar_token = TokenController::new(conf_handle);
            let sogar = SogarController::new(&conf.sogar.registry_name, &conf.sogar.registry_image);

            info!("Configuring HTTP router");

            router
                .controller(diagnostics)
                .controller(health)
                .controller(http_bridge)
                .controller(jet)
                .controller(session_controller)
                .controller(sessions_controller)
                .controller(sogar)
                .controller(sogar_token)
                .controller(legacy_health)
                .controller(legacy_diagnostics)
                .controller(legacy_sessions_controller)
                .controller(kdc_proxy)
                .controller(duplicated_kdc_proxy)
                .controller(jrl)
                .controller(config)
        })
        .configure_listener(|listener| listener.server_name("Devolutions Gateway"))
        .build_stack_only()?;

    Ok(())
}
