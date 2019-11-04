use crate::http::controllers::health::HealthController;
use crate::http::controllers::sessions::SessionsController;
use saphir::Server as SaphirServer;
use saphir::ServerSpawn;
use slog_scope::{info};
use std::sync::Mutex;
use tokio::runtime::TaskExecutor;
use crate::http::controllers::jet::JetController;
use crate::jet_client::JetAssociationsMap;
use crate::config::Config;
use crate::http::middlewares::auth::AuthMiddleware;
use saphir::server::SslConfig;

pub struct HttpServer {
    pub server: SaphirServer,
    server_handle: Mutex<Option<ServerSpawn>>,
}

impl HttpServer {
    pub fn new(config: &Config, jet_associations: JetAssociationsMap, executor: TaskExecutor) -> HttpServer {
        let http_server = SaphirServer::builder()
            .configure_middlewares(|middlewares| {
                info!("Loading http middlewares");

                // Only the create association has to be authorized.
                let mut auth_include_path = vec!["/jet/association"];
                let mut auth_exclude_path = vec!["/jet/association/<association_id>/<anything>"];

                if config.unrestricted() {
                    auth_exclude_path.push("/jet/association/<association_id>");
                } else {
                    auth_include_path.push("/jet/association/<association_id>");
                }

                middlewares.apply(AuthMiddleware::new(config.clone()), auth_include_path, Some(auth_exclude_path))
            })
            .configure_router(|router| {
                info!("Loading http controllers");
                let health = HealthController::new();
                let jet = JetController::new(config.clone(), jet_associations.clone(), executor.clone());
                let session = SessionsController::new();
                info!("Configuring http router");
                router.add(health)
                    .add(jet)
                    .add(session)
            })
            .configure_listener(|list_config| {
                let listener_config = list_config.set_uri(&config.http_listener_url.to_string());

                let cert_config_opt = if let Some(cert_path) = &config.certificate.certificate_file {
                    Some(SslConfig::FilePath(cert_path.into()))
                } else if let Some(cert_data) = &config.certificate.certificate_data {
                    Some(SslConfig::FileData(cert_data.into()))
                } else {
                    None
                };

                let key_config_opt = if let Some(key_path) = &config.certificate.private_key_file {
                    Some(SslConfig::FilePath(key_path.into()))
                } else if let Some(key_data) = &config.certificate.private_key_data {
                    Some(SslConfig::FileData(key_data.into()))
                } else {
                    None
                };

                if let (Some(cert_config), Some(key_config)) = (cert_config_opt, key_config_opt) {
                    listener_config.set_ssl_config(cert_config, key_config)
                } else {
                    listener_config
                }
            })
            .build();

        HttpServer {
            server: http_server,
            server_handle: Mutex::new(None),
        }
    }

    pub fn start(&self, executor: TaskExecutor) -> Result<(), String> {
        let mut handle = self.server_handle.lock().unwrap();
        *handle = Some(self.server.spawn(executor).map_err(|e| e.to_string())?);
        Ok(())
    }

    pub fn stop(&self) {
        if let Some(handle) = self.server_handle.lock().unwrap().take() {
            handle.terminate();
        }
    }
}
