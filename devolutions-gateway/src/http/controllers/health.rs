use crate::config::Config;
use saphir::controller::Controller;
use saphir::http::Method;
use saphir::macros::controller;
use std::sync::Arc;

pub struct HealthController {
    config: Arc<Config>,
}

impl HealthController {
    pub fn new(config: Arc<Config>) -> (Self, LegacyHealthController) {
        (
            Self { config: config.clone() },
            LegacyHealthController { inner: Self { config } },
        )
    }
}

#[controller(name = "jet/health")]
impl HealthController {
    #[get("/")]
    async fn get_health(&self) -> String {
        get_health_stub(self)
    }
}

fn get_health_stub(controller: &HealthController) -> String {
    format!(
        "Devolutions Gateway \"{}\" is alive and healthy.",
        controller.config.hostname
    )
}

// TODO: remove legacy controller after 2022/11/19

pub struct LegacyHealthController {
    inner: HealthController,
}

#[controller(name = "health")]
impl LegacyHealthController {
    #[get("/")]
    async fn get_health(&self) -> String {
        get_health_stub(&self.inner)
    }
}
