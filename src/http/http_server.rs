use std::sync::Mutex;
use saphir::ServerSpawn;
use saphir::Server as SaphirServer;
use log::info;
use tokio::runtime::TaskExecutor;
use crate::http::controllers::health::HealthController;
use crate::http::controllers::sessions::SessionsController;

const HTTP_SERVER_PORT: u32 = 10256;

pub struct HttpServer {
    pub server: SaphirServer,
    server_handle: Mutex<Option<ServerSpawn>>,
}

impl HttpServer {
    pub fn new() -> HttpServer {
        let http_server = SaphirServer::builder()
            .configure_middlewares(|middlewares| {
                info!("Loading http middlewares");
                middlewares
            })
            .configure_router(|router| {
                info!("Loading http controllers");
                let health = HealthController::new();
                let session = SessionsController::new();
                info!("Configuring http router");
                router.add(health)
                    .add(session)
            })
            .configure_listener(|list_config| {
                list_config.set_uri(&format!("http://0.0.0.0:{}", HTTP_SERVER_PORT))
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