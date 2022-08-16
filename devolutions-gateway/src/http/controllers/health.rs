use crate::config::ConfHandle;
use saphir::controller::Controller;
use saphir::http::Method;
use saphir::macros::controller;

pub struct HealthController {
    conf_handle: ConfHandle,
}

impl HealthController {
    pub fn new(conf_handle: ConfHandle) -> (Self, LegacyHealthController) {
        (
            Self {
                conf_handle: conf_handle.clone(),
            },
            LegacyHealthController {
                inner: Self { conf_handle },
            },
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
    operation_id = "GetHealth",
    path = "/jet/health",
    responses(
        (status = 200, description = "Healthy message", body = String),
    ),
))]
fn get_health(controller: &HealthController) -> String {
    let conf = controller.conf_handle.get_conf();
    format!("Devolutions Gateway \"{}\" is alive and healthy.", conf.hostname)
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
