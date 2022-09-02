use crate::config::ConfHandle;
use crate::http::HttpErrorStatus;
use saphir::body::Json;
use saphir::controller::Controller;
use saphir::http::Method;
use saphir::macros::controller;
use saphir::request::Request;
use saphir::responder::Responder;
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
    async fn get_health(&self, req: Request) -> Result<HealthResponse, HttpErrorStatus> {
        get_health(self, req)
    }
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
pub struct Identity {
    /// This Gateway's unique ID
    id: Option<Uuid>,
    /// This Gateway's hostname
    hostname: String,
}

enum HealthResponse {
    Identity(Identity),
    /// Legacy response for DVLS prior to 2022.3.x
    // TODO(axum): REST API compatibility tests
    HealthyMessage(String),
}

impl Responder for HealthResponse {
    fn respond_with_builder(
        self,
        builder: saphir::response::Builder,
        ctx: &saphir::http_context::HttpContext,
    ) -> saphir::response::Builder {
        match self {
            HealthResponse::Identity(identity) => Json(identity).respond_with_builder(builder, ctx),
            HealthResponse::HealthyMessage(message) => message.respond_with_builder(builder, ctx),
        }
    }
}

/// Performs a health check
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "GetHealth",
    tag = "Health",
    path = "/jet/health",
    responses(
        (status = 200, description = "Identity for this Gateway", body = Identity),
        (status = 400, description = "Invalid Accept header"),
    ),
))]
fn get_health(controller: &HealthController, req: Request) -> Result<HealthResponse, HttpErrorStatus> {
    let conf = controller.conf_handle.get_conf();
    match req.headers().get(http::header::ACCEPT).map(http::HeaderValue::as_bytes) {
        Some(b"application/json") => Ok(HealthResponse::Identity(Identity {
            id: conf.id,
            hostname: conf.hostname.clone(),
        })),
        None | Some(b"text/plain") | Some(b"text/*") | Some(b"*/*") => Ok(HealthResponse::HealthyMessage(format!(
            "Devolutions Gateway \"{}\" is alive and healthy.",
            conf.hostname
        ))),
        Some(header_value) => {
            debug!(header_value = String::from_utf8_lossy(header_value).into_owned());
            Err(HttpErrorStatus::bad_request("Unknown first value for Accept header"))
        }
    }
}

// NOTE: legacy controller starting 2021/11/25

pub struct LegacyHealthController {
    inner: HealthController,
}

#[controller(name = "health")]
impl LegacyHealthController {
    #[get("/")]
    async fn get_health(&self, req: Request) -> Result<HealthResponse, HttpErrorStatus> {
        get_health(&self.inner, req)
    }
}
