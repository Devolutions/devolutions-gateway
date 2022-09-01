use crate::config::dto::{DataEncoding, PubKeyFormat, Subscriber};
use crate::config::ConfHandle;
use crate::http::guards::access::{AccessGuard, TokenType};
use crate::http::HttpErrorStatus;
use crate::token::AccessScope;
use saphir::controller::Controller;
use saphir::http::Method;
use saphir::macros::controller;
use saphir::request::Request;
use tap::prelude::*;
use uuid::Uuid;

pub struct ConfigController {
    conf_handle: ConfHandle,
}

impl ConfigController {
    pub fn new(conf_handle: ConfHandle) -> Self {
        Self { conf_handle }
    }
}

#[controller(name = "jet/config")]
impl ConfigController {
    #[patch("/")]
    #[guard(AccessGuard, init_expr = r#"TokenType::Scope(AccessScope::ConfigWrite)"#)]
    async fn patch_config(&self, req: Request) -> Result<(), HttpErrorStatus> {
        patch_config(&self.conf_handle, req).await
    }
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ConfigPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_provisioner_public_key: Option<SubProvisionerKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscriber: Option<Subscriber>,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SubProvisionerKey {
    pub id: String,
    pub value: String,
    pub format: Option<PubKeyFormat>,
    pub encoding: Option<DataEncoding>,
}

const KEY_ALLOWLIST: &[&str] = &["Id", "SubProvisionerPublicKey", "Subscriber"];

/// Modifies configuration
#[cfg_attr(feature = "openapi", utoipa::path(
    patch,
    operation_id = "PatchConfig",
    tag = "Config",
    path = "/jet/config",
    request_body(content = ConfigPatch, description = "JSON-encoded configuration patch", content_type = "application/json"),
    responses(
        (status = 200, description = "Configuration has been patched with success"),
        (status = 400, description = "Bad patch request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 500, description = "Failed to patch configuration"),
    ),
    security(("scope_token" = ["gateway.config.write"])),
))]
async fn patch_config(conf_handle: &ConfHandle, req: Request) -> Result<(), HttpErrorStatus> {
    let req = req
        .load_body()
        .await
        .map_err(|e| HttpErrorStatus::bad_request(format!("Failed to read request body: {e}")))?;
    let body = req.body();

    let patch: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(body).map_err(|e| HttpErrorStatus::bad_request(format!("invalid JSON payload: {e}")))?;

    trace!(?patch, "received JSON config patch");

    if !patch.iter().all(|(key, _)| KEY_ALLOWLIST.contains(&key.as_str())) {
        return Err(HttpErrorStatus::bad_request(
            "patch request contains a key that is not allowed",
        ));
    }

    let mut new_conf = conf_handle
        .get_conf_file()
        .pipe_deref(serde_json::to_value)
        .map_err(HttpErrorStatus::internal)?
        .pipe(|val| {
            // ConfFile struct is a JSON object
            if let serde_json::Value::Object(obj) = val {
                obj
            } else {
                unreachable!("{val:?}");
            }
        });

    for (key, val) in patch {
        new_conf.insert(key, val);
    }

    let new_conf_file = serde_json::from_value(serde_json::Value::Object(new_conf))
        .map_err(|e| HttpErrorStatus::bad_request(format!("patch produced invalid configuration: {e}")))?;

    conf_handle
        .save_new_conf_file(new_conf_file)
        .map_err(|e| HttpErrorStatus::internal(format!("failed to save configuration file: {e:#}")))?;

    Ok(())
}
