use crate::config::ConfHandle;
use saphir::body::Json;
use saphir::controller::Controller;
use saphir::http::Method;
use saphir::macros::controller;
use uuid::Uuid;

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
    async fn get_health(&self) -> Json<Identity> {
        get_health(self)
    }
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
pub struct Identity {
    id: Option<Uuid>,
    hostname: String,
}

/// Performs a health check
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "GetHealth",
    path = "/jet/health",
    responses(
        (status = 200, description = "Identity for this Gateway", body = Identity),
    ),
))]
fn get_health(controller: &HealthController) -> Json<Identity> {
    let conf = controller.conf_handle.get_conf();
    Json(Identity {
        id: conf.id,
        hostname: conf.hostname.clone(),
    })
}

// NOTE: legacy controller starting 2021/11/25

pub struct LegacyHealthController {
    inner: HealthController,
}

#[controller(name = "health")]
impl LegacyHealthController {
    #[get("/")]
    async fn get_health(&self) -> Json<Identity> {
        get_health(&self.inner)
    }
}
