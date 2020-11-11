use crate::config::Config;
use saphir::{
    macros::controller,
    http::{StatusCode, Method},
    controller::Controller,
    body::Json
};
use std::sync::Arc;

struct HealthController {
    config: Arc<Config>
}

impl HealthController {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

#[controller(name="health")]
impl HealthController {
    #[get("/")]
    async fn get_health(&self) -> (u16, String) {
        let hostname = &self.config.hostname;
        let response_body = format!("Devolutions Gateway \"{}\" is alive and healthy.", hostname);
        (StatusCode::OK.as_u16(), response_body)
    }
}