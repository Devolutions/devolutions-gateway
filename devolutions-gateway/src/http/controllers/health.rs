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
        get_health(self)
    }
}

/// Performs a health check
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/jet/health",
    responses(
        (status = 200, description = "Healthy message", body = String),
    ),
))]
fn get_health(controller: &HealthController) -> String {
    format!(
        "Devolutions Gateway \"{}\" is alive and healthy.",
        controller.config.hostname
    )
}

// NOTE: legacy controller starting 2021/11/25

pub struct LegacyHealthController {
    inner: HealthController,
}

#[controller(name = "health")]
impl LegacyHealthController {
    #[get("/")]
    async fn get_health(&self) -> String {
        get_health(&self.inner)
    }
}
