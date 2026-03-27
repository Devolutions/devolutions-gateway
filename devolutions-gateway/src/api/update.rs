use std::collections::HashMap;

use axum::Json;
use axum::body::Bytes;
use devolutions_agent_shared::{
    ProductUpdateInfo, UpdateJson, UpdateManifest, UpdateManifestV2, UpdateProductKey,
    VersionSpecification, VersionedManifest, get_updater_file_path,
};
use hyper::StatusCode;

use crate::extract::UpdateScope;
use crate::http::{HttpError, HttpErrorBuilder};

// ── OpenAPI request / response types ─────────────────────────────────────────

/// Version specification string: `"latest"` or a specific version like `"2026.1.0"`.
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

/// Request body for the unified update endpoint.
///
/// Every key in `Products` is a product name. Known products (`Gateway`, `Agent`,
/// `HubService`) are processed natively; any other name is forwarded as-is to the
/// agent so future product types are supported transparently.
///
/// # Example
///
/// ```json
/// {
///   "Products": {
///     "Gateway": { "Version": "2026.1.0" },
///     "Agent":   { "Version": "latest"   }
///   }
/// }
/// ```
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct UpdateRequest {
    /// Map of product name → version specification.
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

/// Convert the API request to a V2 manifest.
fn into_v2(req: UpdateRequest) -> UpdateManifest {
    let products = req
        .products
        .into_iter()
        .map(|(k, v)| (UpdateProductKey::from(k), ProductUpdateInfo { target_version: v.version }))
        .collect();
    UpdateManifest::Manifest(VersionedManifest::V2(UpdateManifestV2 {
        products,
        ..UpdateManifestV2::default()
    }))
}

/// Convert the API request to a V1 manifest (for agents that have not yet upgraded to V2).
///
/// Known products go into named fields; unknown products are stored in
/// `other` as raw JSON (they survive the file round-trip to the agent).
fn into_v1(req: UpdateRequest) -> UpdateManifest {
    let mut json = UpdateJson::default();
    for (product, info) in req.products {
        let pi = ProductUpdateInfo { target_version: info.version };
        match product {
            UpdateProduct::Gateway => json.gateway = Some(pi),
            UpdateProduct::HubService => json.hub_service = Some(pi),
            UpdateProduct::Agent => json.agent = Some(pi),
            UpdateProduct::Other(_) => {
                // V1 format does not support unknown products; silently dropped.
            }
        }
    }
    UpdateManifest::Legacy(json)
}

/// Serialise the request into the on-disk format appropriate for the installed agent.
///
/// The format is determined by reading the existing `update.json` file:
/// - If it contains `"Version": "2"` the agent supports V2 → write V2.
/// - Otherwise (file is absent, empty, or V1) → write V1.
fn serialise_manifest(req: UpdateRequest, path: &camino::Utf8Path) -> anyhow::Result<String> {
    let use_v2 = std::fs::read(path)
        .ok()
        .and_then(|data| UpdateManifest::parse(&data).ok())
        .is_some_and(|m| matches!(m, UpdateManifest::Manifest(_)));

    let manifest = if use_v2 { into_v2(req) } else { into_v1(req) };
    Ok(serde_json::to_string(&manifest)?)
}

// ── Handler ───────────────────────────────────────────────────────────────────

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
        ("version" = Option<String>, Query, description = "[Legacy] Gateway-only target version; use the request body for multi-product updates"),
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

    // Parse the optional JSON body.
    let body_request: Option<UpdateRequest> = if body.is_empty() {
        None
    } else {
        Some(serde_json::from_slice(&body).map_err(
            HttpError::bad_request()
                .with_msg("invalid request body")
                .err(),
        )?)
    };

    // Both forms supplied simultaneously → 400.
    if query_version.is_some() && body_request.is_some() {
        return Err(HttpErrorBuilder::new(StatusCode::BAD_REQUEST)
            .msg("cannot specify both query parameter and request body; use one or the other"));
    }

    // Neither form supplied → 400.
    if query_version.is_none() && body_request.is_none() {
        return Err(HttpErrorBuilder::new(StatusCode::BAD_REQUEST).msg("no products specified"));
    }

    // Convert whichever form was used into an UpdateRequest.
    let request: UpdateRequest = if let Some(v) = query_version {
        // Legacy form: gateway-only update.
        let version: VersionSpecification = v.parse().map_err(
            HttpError::bad_request()
                .with_msg("invalid version in query parameter")
                .err(),
        )?;
        let mut products = HashMap::new();
        products.insert(UpdateProduct::Gateway, UpdateProductRequest { version });
        UpdateRequest { products }
    } else {
        body_request.expect("verified non-None above")
    };

    let updater_file_path = get_updater_file_path();

    if !updater_file_path.exists() {
        return Err(
            HttpErrorBuilder::new(StatusCode::SERVICE_UNAVAILABLE).msg("Agent updater service is not installed")
        );
    }

    let serialized = serialise_manifest(request, &updater_file_path).map_err(
        HttpError::internal()
            .with_msg("failed to serialize the update manifest")
            .err(),
    )?;

    std::fs::write(&updater_file_path, serialized).map_err(
        HttpError::internal()
            .with_msg("failed to write the new `update.json` manifest on disk")
            .err(),
    )?;

    Ok(Json(UpdateResponse {}))
}
