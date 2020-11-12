use crate::{
    config::Config,
    http::{
        controllers::{health::HealthController, jet::JetController, sessions::SessionsController},
        middlewares::auth::AuthMiddleware,
    },
    jet_client::JetAssociationsMap,
};
use saphir::{
    server::{SslConfig, Server as SaphirServer}
};
use slog_scope::info;
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;
use saphir::error::SaphirError;

pub struct HttpServer {
    pub server: Mutex<Option<SaphirServer>>,
    server_handle: Mutex<Option<JoinHandle<Result<(), SaphirError>>>>,
}

impl HttpServer {
    pub fn new(config: Arc<Config>, jet_associations: JetAssociationsMap) -> HttpServer {
        let http_server = SaphirServer::builder()
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
                router
                    .controller(health)
                    .controller(jet)
                    .controller(session)
            })
            .configure_listener(|listener| {
                let server_name = &config.api_listener.host_str()
                    .expect("API listener should be specified");
                let listener_config = listener.server_name(server_name);

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
            server: Mutex::new(Some(http_server)),
            server_handle: Mutex::new(None),
        }
    }

    pub fn start(&self) {
        let server = {
            let mut guard = self.server.lock().unwrap();
            guard.take().expect("Start server can't be called twice")
        };
        let mut handle = self.server_handle.lock().unwrap();
        handle.replace(tokio::spawn(server.run()));
    }

    pub fn stop(&self) {
        if let Some(handle) = self.server_handle.lock().unwrap().take() {
            handle.abort();
        }
    }
}
