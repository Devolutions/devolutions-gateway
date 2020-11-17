use crate::config::Config;
use saphir::{
    controller::Controller,
    http::{Method, StatusCode},
    macros::controller,
};
use std::sync::Arc;

pub struct HealthController {
    config: Arc<Config>,
}

impl HealthController {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

#[controller(name = "health")]
impl HealthController {
    #[get("/")]
    async fn get_health(&self) -> (u16, String) {
        build_health_response(&self.config)
    }
}

pub fn build_health_response(config: &Config) -> (u16, String) {
    let hostname = &config.hostname;
    let response_body = format!("Devolutions Gateway \"{}\" is alive and healthy.", hostname);
    (StatusCode::OK.as_u16(), response_body)
}
