use crate::{
    config::Config,
    http::{
        controllers::{health::HealthController, jet::JetController, sessions::SessionsController},
        middlewares::auth::AuthMiddleware,
    },
    jet_client::JetAssociationsMap,
};

use saphir::{
    error::SaphirError,
    server::{Server as SaphirServer, SslConfig},
};
use slog_scope::info;
use std::sync::{Arc, Mutex};
use tokio_02::{runtime::Runtime, task::JoinHandle};

pub struct HttpServer {
    pub server: Mutex<Option<SaphirServer>>,
    server_runtime: Option<Runtime>,
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
                router.controller(health).controller(jet).controller(session)
            })
            .configure_listener(|listener| {
                let listener_host = config.api_listener.host().expect("API listener should be specified");

                let listener_port = config.api_listener.port().unwrap_or(8080);
                let interface = format!("{}:{}", listener_host, listener_port);

                let listener_config = listener.interface(&interface).server_name("Saphir Server");

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
        let runtime = Runtime::new().expect("failed to create runtime for HTTP server");
        HttpServer {
            server: Mutex::new(Some(http_server)),
            server_runtime: Some(runtime),
            server_handle: Mutex::new(None),
        }
    }

    pub fn start(&self) {
        let server = {
            let mut guard = self.server.lock().unwrap();
            guard.take().expect("Start server can't be called twice")
        };
        let server_runtime = self
            .server_runtime
            .as_ref()
            .expect("Runtime must be present on start of HTTP server");
        let mut handle = self.server_handle.lock().unwrap();
        handle.replace(server_runtime.spawn(server.run()));
    }

    pub fn stop(&self) {
        if let Some(handle) = self.server_handle.lock().unwrap().take() {
            std::mem::drop(handle)
        }
    }
}
