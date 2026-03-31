use std::collections::HashMap;

use axum::Json;
use axum::body::Bytes;
use devolutions_agent_shared::{
    ProductUpdateInfo, UPDATE_MANIFEST_V2_MINOR_VERSION, UpdateManifest, UpdateManifestV2, UpdateProductKey,
    UpdateSchedule, UpdateStatus, VersionSpecification, default_schedule_window_start, get_update_status_file_path,
    get_updater_file_path,
};
use hyper::StatusCode;
use tokio::fs;

use crate::extract::{UpdateReadScope, UpdateScope};
use crate::http::{HttpError, HttpErrorBuilder};

// ── Shared async file I/O ─────────────────────────────────────────────────────

/// Read and parse `update.json` asynchronously.
///
/// Returns `(manifest, was_v2)` where `was_v2` indicates whether the file on disk was
/// already in V2 format.  Returns `503` when the file doesn't exist (agent not installed)
/// and `500` on any other I/O or parse error.  A legacy V1 file is transparently upgraded
/// to a V2 manifest in memory; the file on disk is rewritten on the next write.
async fn read_manifest() -> Result<(UpdateManifestV2, bool), HttpError> {
    let path = get_updater_file_path();
    let data = match fs::read(&path).await {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(
                HttpErrorBuilder::new(StatusCode::SERVICE_UNAVAILABLE).msg("failed to open update manifest file")
            );
        }
        Err(e) => {
            return Err(HttpError::internal()
                .with_msg("failed to read update manifest file")
                .build(e));
        }
    };
    match UpdateManifest::parse(&data).map_err(
        HttpError::internal()
            .with_msg("update manifest file contains invalid JSON")
            .err(),
    )? {
        UpdateManifest::ManifestV2(v2) => Ok((v2, true)),
        // V1 → V2 upgrade: carry products forward, leave Schedule as None.
        UpdateManifest::Legacy(v1) => {
            let mut products = HashMap::new();
            if let Some(gw) = v1.gateway {
                products.insert(UpdateProductKey::Gateway, gw);
            }
            if let Some(hs) = v1.hub_service {
                products.insert(UpdateProductKey::HubService, hs);
            }
            Ok((
                UpdateManifestV2 {
                    products,
                    ..UpdateManifestV2::default()
                },
                false,
            ))
        }
    }
}

/// Serialise `manifest` and write it back to `update.json` asynchronously.
///
/// Always resets `VersionMinor` to [`UPDATE_MANIFEST_V2_MINOR_VERSION`] so the agent
/// never sees a minor version it wasn't built against.
async fn write_manifest(mut manifest: UpdateManifestV2) -> Result<(), HttpError> {
    manifest.version_minor = UPDATE_MANIFEST_V2_MINOR_VERSION;
    let serialized = serde_json::to_string(&UpdateManifest::ManifestV2(manifest)).map_err(
        HttpError::internal()
            .with_msg("failed to serialize update manifest")
            .err(),
    )?;
    fs::write(get_updater_file_path(), serialized).await.map_err(
        HttpError::internal()
            .with_msg("failed to write update manifest file")
            .err(),
    )
}

// ── OpenAPI request / response types ─────────────────────────────────────────

/// Per-product version request.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct UpdateProductRequest {
    /// Target version: `"latest"` or `"YYYY.M.D"` / `"YYYY.M.D.R"`.
    pub version: VersionSpecification,
}

/// Known product names accepted by the update endpoint.
///
/// `Other` captures any product name not yet known to this gateway version;
/// it is forwarded to the agent unchanged so future agents can act on it.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum UpdateProduct {
    Gateway,
    HubService,
    Agent,
    /// A product name not recognised by this gateway version.
    Other(String),
}

impl<'de> serde::Deserialize<'de> for UpdateProduct {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = UpdateProduct;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "a product name string")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                Ok(match s {
                    "Gateway" => UpdateProduct::Gateway,
                    "HubService" => UpdateProduct::HubService,
                    "Agent" => UpdateProduct::Agent,
                    other => UpdateProduct::Other(other.to_owned()),
                })
            }
        }
        d.deserialize_str(V)
    }
}

impl serde::Serialize for UpdateProduct {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(match self {
            Self::Gateway => "Gateway",
            Self::HubService => "HubService",
            Self::Agent => "Agent",
            Self::Other(name) => name.as_str(),
        })
    }
}

/// Request body for the unified update endpoint.
///
/// Every key in `Products` is a product name. Known products (`Gateway`, `Agent`,
/// `HubService`) are processed natively; any other name is forwarded as-is to the
/// agent so future product types are supported transparently.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct UpdateRequest {
    /// Map of product name to version specification.
    #[serde(default)]
    pub products: HashMap<UpdateProduct, UpdateProductRequest>,
}

/// Response returned by the update endpoint.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
pub(crate) struct UpdateResponse {}

// ── Conversion: API types → shared manifest types ─────────────────────────────

impl From<UpdateProduct> for UpdateProductKey {
    fn from(p: UpdateProduct) -> Self {
        match p {
            UpdateProduct::Gateway => UpdateProductKey::Gateway,
            UpdateProduct::HubService => UpdateProductKey::HubService,
            UpdateProduct::Agent => UpdateProductKey::Agent,
            UpdateProduct::Other(s) => UpdateProductKey::Other(s),
        }
    }
}

impl From<UpdateProductKey> for UpdateProduct {
    fn from(k: UpdateProductKey) -> Self {
        match k {
            UpdateProductKey::Gateway => UpdateProduct::Gateway,
            UpdateProductKey::HubService => UpdateProduct::HubService,
            UpdateProductKey::Agent => UpdateProduct::Agent,
            UpdateProductKey::Other(s) => UpdateProduct::Other(s),
        }
    }
}

/// Apply updated products from the API request to `manifest`.
///
/// - **V2 on disk** (`was_v2 = true`): all products accepted.
/// - **V1 on disk** (`was_v2 = false`): only `Gateway` and `HubService` accepted; any other
///   product returns `400 Bad Request`.
fn apply_products(req: UpdateRequest, manifest: &mut UpdateManifestV2, was_v2: bool) -> Result<(), HttpError> {
    if was_v2 {
        manifest.products = req
            .products
            .into_iter()
            .map(|(k, v)| {
                (
                    UpdateProductKey::from(k),
                    ProductUpdateInfo {
                        target_version: v.version,
                    },
                )
            })
            .collect();
    } else {
        // Legacy path: only Gateway and HubService are valid in V1.
        manifest.products.clear();
        for (product, info) in req.products {
            let pi = ProductUpdateInfo {
                target_version: info.version,
            };
            match product {
                UpdateProduct::Gateway => {
                    manifest.products.insert(UpdateProductKey::Gateway, pi);
                }
                UpdateProduct::HubService => {
                    manifest.products.insert(UpdateProductKey::HubService, pi);
                }
                UpdateProduct::Agent => {
                    return Err(HttpErrorBuilder::new(StatusCode::BAD_REQUEST)
                        .msg("Agent updates require a V2-capable agent; upgrade the installed agent first"));
                }
                UpdateProduct::Other(name) => {
                    return Err(HttpError::bad_request()
                        .with_msg("product is not supported by the installed legacy agent")
                        .build(format!("product `{name}` requires a V2-capable agent")));
                }
            }
        }
    }
    Ok(())
}

/// Trigger an update for one or more Devolutions products.
///
/// Writes the requested version(s) into `Agent/update.json`, which is watched by Devolutions
/// Agent. When a requested version is higher than the installed version the agent proceeds
/// with the update.
///
/// **Body form** (preferred): pass a JSON body with a `Products` map.
///
/// **Query-param form** (legacy, gateway-only): `POST /jet/update?version=latest`.
/// This form updates only the Gateway product and is kept for backward compatibility.
///
/// Both forms cannot be used simultaneously; doing so returns HTTP 400.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    operation_id = "TriggerUpdate",
    tag = "Update",
    path = "/jet/update",
    params(
        ("version" = Option<String>, Query, deprecated, description = "Gateway-only target version; use the request body for multi-product updates"),
    ),
    request_body(content = Option<UpdateRequest>, description = "Products and target versions to update", content_type = "application/json"),
    responses(
        (status = 200, description = "Update request accepted", body = UpdateResponse),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 500, description = "Failed to write update manifest"),
        (status = 503, description = "Agent updater service is unavailable"),
    ),
    security(("scope_token" = ["gateway.update"])),
))]
pub(super) async fn trigger_update_check(
    uri: axum::http::Uri,
    _scope: UpdateScope,
    body: Bytes,
) -> Result<Json<UpdateResponse>, HttpError> {
    // Extract optional legacy `?version=` query param (gateway-only path).
    let query_version: Option<String> = uri.query().and_then(|q| {
        q.split('&').find_map(|kv| {
            kv.split_once('=')
                .filter(|(k, _)| *k == "version")
                .map(|(_, v)| v.to_owned())
        })
    });

    // Parse the JSON body; an absent or empty body is treated as an empty product map.
    let mut request: UpdateRequest = if body.is_empty() {
        UpdateRequest::default()
    } else {
        serde_json::from_slice(&body).map_err(HttpError::bad_request().with_msg("invalid request body").err())?
    };

    // Legacy query param: conflicts with an explicit body that already lists products.
    if let Some(v) = query_version {
        if !request.products.is_empty() {
            return Err(HttpErrorBuilder::new(StatusCode::BAD_REQUEST)
                .msg("cannot specify both query parameter and request body; use one or the other"));
        }
        // Build a Gateway-only update from the (deprecated) query param.
        let version: VersionSpecification = v.parse().map_err(
            HttpError::bad_request()
                .with_msg("invalid version in query parameter")
                .err(),
        )?;
        request
            .products
            .insert(UpdateProduct::Gateway, UpdateProductRequest { version });
    }

    // Read the existing manifest (503 when agent is not installed).
    // `was_v2` tells us if the file on disk was V2; determines which products are accepted.
    let (mut manifest, was_v2) = read_manifest().await?;
    apply_products(request, &mut manifest, was_v2)?;
    write_manifest(manifest).await?;

    Ok(Json(UpdateResponse {}))
}

/// Installed version of each product, as reported by Devolutions Agent.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct GetUpdateProductsResponse {
    /// Version of the `update_status.json` format in `"major.minor"` form (e.g. `"1.1"`).
    pub manifest_version: String,
    /// Map of product name to its currently installed version.
    #[serde(default)]
    pub products: HashMap<UpdateProduct, VersionSpecification>,
}

/// Retrieve the currently installed version of each Devolutions product.
///
/// Reads `update_status.json`, which is written by the Devolutions Agent on startup and
/// refreshed after every update run.  When the file does not exist (agent not installed
/// or is an older version), returns an empty product map.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "GetUpdateProducts",
    tag = "Update",
    path = "/jet/update",
    responses(
        (status = 200, description = "Installed product versions", body = GetUpdateProductsResponse),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 500, description = "Failed to read agent status file"),
        (status = 503, description = "Agent updater service is unavailable"),
    ),
    security(("scope_token" = ["gateway.update.read"])),
))]
pub(super) async fn get_update_products(_scope: UpdateReadScope) -> Result<Json<GetUpdateProductsResponse>, HttpError> {
    let path = get_update_status_file_path();
    let data = match fs::read(&path).await {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(HttpErrorBuilder::new(StatusCode::SERVICE_UNAVAILABLE).msg("failed to open agent status file"));
        }
        Err(e) => {
            return Err(HttpError::internal()
                .with_msg("failed to read agent status file")
                .build(e));
        }
    };
    let status = UpdateStatus::parse(&data).map_err(
        HttpError::internal()
            .with_msg("agent status file contains invalid JSON")
            .err(),
    )?;
    let manifest_version = status.version_string();
    let products = status
        .into_products()
        .into_iter()
        .map(|(k, v)| (UpdateProduct::from(k), v.target_version))
        .collect();
    Ok(Json(GetUpdateProductsResponse {
        manifest_version,
        products,
    }))
}

// ── Update schedule: types and handlers ──────────────────────────────────────

/// Current auto-update schedule for Devolutions Agent.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
pub(crate) struct GetUpdateScheduleResponse {
    /// Version of the `update_status.json` format in `"major.minor"` form (e.g. `"1.1"`).
    #[serde(rename = "ManifestVersion")]
    pub manifest_version: String,
    /// Enable periodic Devolutions Agent self-update checks.
    #[serde(rename = "Enabled")]
    pub enabled: bool,
    /// Minimum interval between auto-update checks, in seconds.
    ///
    /// `0` means check once at `UpdateWindowStart`.
    #[serde(rename = "Interval")]
    pub interval: u64,
    /// Start of the maintenance window as seconds past midnight (local time).
    #[serde(rename = "UpdateWindowStart")]
    pub update_window_start: u32,
    /// End of the maintenance window as seconds past midnight (local time, exclusive).
    /// `None` means no upper bound (single check at `UpdateWindowStart`).
    #[serde(rename = "UpdateWindowEnd", skip_serializing_if = "Option::is_none")]
    pub update_window_end: Option<u32>,
    /// Products the agent autonomously polls for new versions.
    #[serde(rename = "Products", default)]
    pub products: Vec<UpdateProduct>,
}

/// Desired auto-update schedule to apply to Devolutions Agent.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Deserialize)]
pub(crate) struct SetUpdateScheduleRequest {
    /// Enable periodic Devolutions Agent self-update checks.
    #[serde(rename = "Enabled")]
    pub enabled: bool,
    /// Minimum interval between auto-update checks, in seconds.
    ///
    /// `0` means check once at `UpdateWindowStart` (default).
    #[serde(rename = "Interval", default)]
    pub interval: u64,
    /// Start of the maintenance window as seconds past midnight in local time (default: `7200` = 02:00).
    #[serde(rename = "UpdateWindowStart", default = "default_schedule_window_start")]
    pub update_window_start: u32,
    /// End of the maintenance window as seconds past midnight in local time, exclusive.
    ///
    /// `null` (default) means no upper bound - a single check fires at `UpdateWindowStart`.
    /// When end < start the window crosses midnight.
    #[serde(rename = "UpdateWindowEnd", default)]
    pub update_window_end: Option<u32>,
    /// Products the agent autonomously polls for new versions (default: empty).
    #[serde(rename = "Products", default)]
    pub products: Vec<UpdateProduct>,
}

impl From<SetUpdateScheduleRequest> for UpdateSchedule {
    fn from(r: SetUpdateScheduleRequest) -> Self {
        Self {
            enabled: r.enabled,
            interval: r.interval,
            update_window_start: r.update_window_start,
            update_window_end: r.update_window_end,
            products: r.products.into_iter().map(UpdateProductKey::from).collect(),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
pub(crate) struct SetUpdateScheduleResponse {}

/// Retrieve the current Devolutions Agent auto-update schedule.
///
/// Reads the `Schedule` field from `update.json`.  When the field is absent the response
/// contains zeroed defaults (`Enabled: false`, interval `0`, window start `0`, no products).
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "GetUpdateSchedule",
    tag = "Update",
    path = "/jet/update/schedule",
    responses(
        (status = 200, description = "Current auto-update schedule", body = GetUpdateScheduleResponse),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 500, description = "Failed to read agent status file"),
        (status = 503, description = "Agent updater service is unavailable"),
    ),
    security(("scope_token" = ["gateway.update.read"])),
))]
pub(super) async fn get_update_schedule(_scope: UpdateReadScope) -> Result<Json<GetUpdateScheduleResponse>, HttpError> {
    let path = get_update_status_file_path();
    let data = match fs::read(&path).await {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(HttpErrorBuilder::new(StatusCode::SERVICE_UNAVAILABLE).msg("failed to open agent status file"));
        }
        Err(e) => {
            return Err(HttpError::internal()
                .with_msg("failed to read agent status file")
                .build(e));
        }
    };
    let status = UpdateStatus::parse(&data).map_err(
        HttpError::internal()
            .with_msg("agent status file contains invalid JSON")
            .err(),
    )?;
    let manifest_version = status.version_string();
    let schedule = status.schedule().cloned().unwrap_or_default();
    Ok(Json(GetUpdateScheduleResponse {
        manifest_version,
        enabled: schedule.enabled,
        interval: schedule.interval,
        update_window_start: schedule.update_window_start,
        update_window_end: schedule.update_window_end,
        products: schedule.products.into_iter().map(UpdateProduct::from).collect(),
    }))
}

/// Set the Devolutions Agent auto-update schedule.
///
/// Writes the `Schedule` field into `update.json`.  The agent watches this file and
/// applies the new schedule immediately, then persists it to `agent.json`.
///
/// All other fields in `update.json` are preserved; the `VersionMinor` field is reset to
/// the minor version this gateway build understands so the agent does not see an unknown
/// future version.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    operation_id = "SetUpdateSchedule",
    tag = "Update",
    path = "/jet/update/schedule",
    request_body = SetUpdateScheduleRequest,
    responses(
        (status = 200, description = "Auto-update schedule applied", body = SetUpdateScheduleResponse),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 500, description = "Failed to write update manifest"),
        (status = 503, description = "Agent updater service is unavailable"),
    ),
    security(("scope_token" = ["gateway.update"])),
))]
pub(super) async fn set_update_schedule(
    _scope: UpdateScope,
    Json(body): Json<SetUpdateScheduleRequest>,
) -> Result<Json<SetUpdateScheduleResponse>, HttpError> {
    let (mut manifest, _) = read_manifest().await?;
    manifest.schedule = Some(UpdateSchedule::from(body));
    write_manifest(manifest).await?;
    Ok(Json(SetUpdateScheduleResponse {}))
}
