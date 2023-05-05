use crate::config::dto::{DataEncoding, PubKeyFormat, Subscriber};
use crate::extract::ConfigWriteScope;
use crate::http::HttpError;
use crate::DgwState;
use axum::extract::State;
use axum::routing::patch;
use axum::{Json, Router};
use tap::prelude::*;
use uuid::Uuid;

pub fn make_router<S>(state: DgwState) -> Router<S> {
    Router::new().route("/", patch(patch_config)).with_state(state)
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct ConfigPatch {
    /// This Gateway's unique ID
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<Uuid>,
    /// The sub provisioner public key (may only be used to verify tokens when establishing a session)
    #[serde(skip_serializing_if = "Option::is_none")]
    sub_provisioner_public_key: Option<SubProvisionerKey>,
    /// Subscriber configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    subscriber: Option<Subscriber>,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct SubProvisionerKey {
    /// The key ID for this subkey
    id: String,
    /// The binary-to-text-encoded key data
    value: String,
    /// The format used for the key data
    format: Option<PubKeyFormat>,
    /// The binary-to-text encoding used for the key data
    encoding: Option<DataEncoding>,
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
async fn patch_config(
    _scope: ConfigWriteScope,
    State(DgwState { conf_handle, .. }): State<DgwState>,
    Json(patch): Json<serde_json::Map<String, serde_json::Value>>,
) -> Result<(), HttpError> {
    trace!(?patch, "received JSON config patch");

    if !patch.iter().all(|(key, _)| KEY_ALLOWLIST.contains(&key.as_str())) {
        return Err(HttpError::bad_request().msg("patch request contains a key that is not allowed"));
    }

    let mut new_conf = conf_handle
        .get_conf_file()
        .pipe_deref(serde_json::to_value)
        .map_err(HttpError::internal().err())?
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

    let new_conf_file = serde_json::from_value(serde_json::Value::Object(new_conf)).map_err(
        HttpError::bad_request()
            .with_msg("patch produced invalid configuration")
            .err(),
    )?;

    conf_handle.save_new_conf_file(new_conf_file).map_err(
        HttpError::internal()
            .with_msg("failed to save configuration file")
            .err(),
    )?;

    Ok(())
}
