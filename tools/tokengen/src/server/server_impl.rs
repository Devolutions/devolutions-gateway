use axum::extract::{Extension, Json};
use axum::routing::post;
use axum::Router;
use serde::{Deserialize, Serialize};
use std::env;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

use crate::{generate_token, ApplicationProtocol, RecordingOperation, SubCommandArgs};

pub(crate) fn create_router(provisioner_key_path: Arc<PathBuf>, delegation_key_path: Option<PathBuf>) -> Router {
    Router::new()
        .route("/forward", post(forward_handler))
        .route("/rendezvous", post(rendezvous_handler))
        .route("/rdp_tls", post(rdp_tls_handler))
        .route("/scope", post(scope_handler))
        .route("/jmux", post(jmux_handler))
        .route("/jrec", post(jrec_handler))
        .route("/kdc", post(kdc_handler))
        .route("/jrl", post(jrl_handler))
        .route("/netscan", post(netscan_handler))
        .layer(Extension(provisioner_key_path))
        .layer(Extension(delegation_key_path))
}

pub(crate) async fn get_delegate_key_path() -> Result<Option<PathBuf>, Box<dyn Error>> {
    let config_dir = env::var("DGATEWAY_CONFIG_PATH").expect("DGATEWAY_CONFIG_PATH environment variable not set");

    let gateway_json_path = Path::new(&config_dir).join("gateway.json");

    let gateway_json_contents = tokio::fs::read_to_string(&gateway_json_path).await?;
    let gateway_config: serde_json::Value = serde_json::from_str(&gateway_json_contents)?;

    let delegate_private_key_file = gateway_config.get("DelegationPrivateKeyFile").and_then(|v| v.as_str());

    let delegate_key_path = delegate_private_key_file.map(PathBuf::from);
    let delegate_key_path = delegate_key_path.map(|p| {
        if p.is_relative() {
            gateway_json_path.parent().unwrap().join(p)
        } else {
            p
        }
    });

    Ok(delegate_key_path)
}

pub(crate) async fn get_provisioner_key_path() -> Result<Arc<PathBuf>, Box<dyn Error>> {
    let config_dir = env::var("DGATEWAY_CONFIG_PATH").expect("DGATEWAY_CONFIG_PATH environment variable not set");

    let gateway_json_path = Path::new(&config_dir).join("gateway.json");

    let gateway_json_contents = tokio::fs::read_to_string(&gateway_json_path).await?;
    let gateway_config: serde_json::Value = serde_json::from_str(&gateway_json_contents)?;

    let provisioner_private_key_file = gateway_config
        .get("ProvisionerPrivateKeyFile")
        .ok_or("ProvisionerPrivateKeyFile not found in gateway.json")?
        .as_str()
        .ok_or("ProvisionerPrivateKeyFile is not a string")?;

    let provisioner_key_path = PathBuf::from(provisioner_private_key_file);
    let provisioner_key_path = if provisioner_key_path.is_relative() {
        gateway_json_path.parent().unwrap().join(provisioner_key_path)
    } else {
        provisioner_key_path
    };

    Ok(Arc::new(provisioner_key_path))
}

#[derive(Deserialize)]
pub(crate) struct CommonRequest {
    #[serde(default)]
    validity_duration: Option<u64>,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    jet_gw_id: Option<Uuid>,
}

#[derive(Serialize)]
pub(crate) struct TokenResponse {
    token: String,
}

pub(crate) async fn forward_handler(
    Extension(provisioner_key_path): Extension<Arc<PathBuf>>,
    Extension(delegation_key_path): Extension<Option<PathBuf>>,
    Json(request): Json<ForwardRequest>,
) -> Result<Json<TokenResponse>, (axum::http::StatusCode, String)> {
    handle_subcommand(
        provisioner_key_path,
        delegation_key_path,
        request.common,
        SubCommandArgs::Forward {
            dst_hst: request.dst_hst,
            jet_ap: request.jet_ap,
            jet_ttl: request.jet_ttl,
            jet_aid: request.jet_aid,
            jet_rec: request.jet_rec,
            jet_reuse: request.jet_reuse,
            cert_thumb256: request.cert_thumb256,
        },
    )
    .await
}

pub(crate) async fn rendezvous_handler(
    Extension(provisioner_key_path): Extension<Arc<PathBuf>>,
    Extension(delegation_key_path): Extension<Option<PathBuf>>,
    Json(request): Json<RendezvousRequest>,
) -> Result<Json<TokenResponse>, (axum::http::StatusCode, String)> {
    handle_subcommand(
        provisioner_key_path,
        delegation_key_path,
        request.common,
        SubCommandArgs::Rendezvous {
            jet_ap: request.jet_ap,
            jet_aid: request.jet_aid,
            jet_rec: request.jet_rec,
        },
    )
    .await
}

pub(crate) async fn rdp_tls_handler(
    Extension(provisioner_key_path): Extension<Arc<PathBuf>>,
    Extension(delegation_key_path): Extension<Option<PathBuf>>,
    Json(request): Json<RdpTlsRequest>,
) -> Result<Json<TokenResponse>, (axum::http::StatusCode, String)> {
    handle_subcommand(
        provisioner_key_path,
        delegation_key_path,
        request.common,
        SubCommandArgs::RdpTls {
            dst_hst: request.dst_hst,
            prx_usr: request.prx_usr,
            prx_pwd: request.prx_pwd,
            dst_usr: request.dst_usr,
            dst_pwd: request.dst_pwd,
            jet_aid: request.jet_aid,
        },
    )
    .await
}

pub(crate) async fn scope_handler(
    Extension(provisioner_key_path): Extension<Arc<PathBuf>>,
    Extension(delegation_key_path): Extension<Option<PathBuf>>,
    Json(request): Json<ScopeRequest>,
) -> Result<Json<TokenResponse>, (axum::http::StatusCode, String)> {
    handle_subcommand(
        provisioner_key_path,
        delegation_key_path,
        request.common,
        SubCommandArgs::Scope { scope: request.scope },
    )
    .await
}

pub(crate) async fn jmux_handler(
    Extension(provisioner_key_path): Extension<Arc<PathBuf>>,
    Extension(delegation_key_path): Extension<Option<PathBuf>>,
    Json(request): Json<JmuxRequest>,
) -> Result<Json<TokenResponse>, (axum::http::StatusCode, String)> {
    handle_subcommand(
        provisioner_key_path,
        delegation_key_path,
        request.common,
        SubCommandArgs::Jmux {
            jet_ap: request.jet_ap,
            dst_hst: request.dst_hst,
            dst_addl: request.dst_addl,
            jet_ttl: request.jet_ttl,
            jet_aid: request.jet_aid,
            jet_rec: request.jet_rec,
        },
    )
    .await
}

pub(crate) async fn jrec_handler(
    Extension(provisioner_key_path): Extension<Arc<PathBuf>>,
    Extension(delegation_key_path): Extension<Option<PathBuf>>,
    Json(request): Json<JrecRequest>,
) -> Result<Json<TokenResponse>, (axum::http::StatusCode, String)> {
    handle_subcommand(
        provisioner_key_path,
        delegation_key_path,
        request.common,
        SubCommandArgs::Jrec {
            jet_rop: request.jet_rop,
            jet_aid: request.jet_aid,
            jet_reuse: request.jet_reuse,
        },
    )
    .await
}

pub(crate) async fn kdc_handler(
    Extension(provisioner_key_path): Extension<Arc<PathBuf>>,
    Extension(delegation_key_path): Extension<Option<PathBuf>>,
    Json(request): Json<KdcRequest>,
) -> Result<Json<TokenResponse>, (axum::http::StatusCode, String)> {
    handle_subcommand(
        provisioner_key_path,
        delegation_key_path,
        request.common,
        SubCommandArgs::Kdc {
            krb_realm: request.krb_realm,
            krb_kdc: request.krb_kdc,
        },
    )
    .await
}

pub(crate) async fn jrl_handler(
    Extension(provisioner_key_path): Extension<Arc<PathBuf>>,
    Extension(delegation_key_path): Extension<Option<PathBuf>>,
    Json(request): Json<JrlRequest>,
) -> Result<Json<TokenResponse>, (axum::http::StatusCode, String)> {
    handle_subcommand(
        provisioner_key_path,
        delegation_key_path,
        request.common,
        SubCommandArgs::Jrl {
            revoked_jti_list: request.jti,
        },
    )
    .await
}

pub(crate) async fn netscan_handler(
    Extension(provisioner_key_path): Extension<Arc<PathBuf>>,
    Extension(delegation_key_path): Extension<Option<PathBuf>>,
    Json(request): Json<NetScanRequest>,
) -> Result<Json<TokenResponse>, (axum::http::StatusCode, String)> {
    handle_subcommand(
        provisioner_key_path,
        delegation_key_path,
        request.common,
        SubCommandArgs::NetScan {},
    )
    .await
}

async fn handle_subcommand(
    provisioner_key_path: Arc<PathBuf>,
    delegation_key_path: Option<PathBuf>,
    common: CommonRequest,
    subcommand: SubCommandArgs,
) -> Result<Json<TokenResponse>, (axum::http::StatusCode, String)> {
    let validity_duration = common
        .validity_duration
        .map(std::time::Duration::from_secs)
        .unwrap_or(std::time::Duration::from_secs(3600));
    let kid = common.kid;
    let jet_gw_id = common.jet_gw_id;

    let token = generate_token(
        provisioner_key_path.as_ref(),
        validity_duration,
        kid,
        delegation_key_path.as_deref(),
        jet_gw_id,
        subcommand,
    )
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(TokenResponse { token }))
}

#[derive(Deserialize)]
pub(crate) struct ForwardRequest {
    #[serde(flatten)]
    common: CommonRequest,
    dst_hst: String,
    jet_ap: Option<ApplicationProtocol>,
    jet_ttl: Option<u64>,
    jet_aid: Option<Uuid>,
    jet_rec: bool,
    jet_reuse: Option<u32>,
    cert_thumb256: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct RendezvousRequest {
    #[serde(flatten)]
    common: CommonRequest,
    jet_ap: Option<ApplicationProtocol>,
    jet_aid: Option<Uuid>,
    jet_rec: bool,
}

#[derive(Deserialize)]
pub(crate) struct RdpTlsRequest {
    #[serde(flatten)]
    common: CommonRequest,
    dst_hst: String,
    prx_usr: String,
    prx_pwd: String,
    dst_usr: String,
    dst_pwd: String,
    jet_aid: Option<Uuid>,
}

#[derive(Deserialize)]
pub(crate) struct ScopeRequest {
    #[serde(flatten)]
    common: CommonRequest,
    scope: String,
}

#[derive(Deserialize)]
pub(crate) struct JmuxRequest {
    #[serde(flatten)]
    common: CommonRequest,
    jet_ap: Option<ApplicationProtocol>,
    dst_hst: String,
    dst_addl: Vec<String>,
    jet_ttl: Option<u64>,
    jet_aid: Option<Uuid>,
    jet_rec: bool,
}

#[derive(Deserialize)]
pub(crate) struct JrecRequest {
    #[serde(flatten)]
    common: CommonRequest,
    jet_rop: RecordingOperation,
    jet_aid: Option<Uuid>,
    jet_reuse: Option<u32>,
}

#[derive(Deserialize)]
pub(crate) struct KdcRequest {
    #[serde(flatten)]
    common: CommonRequest,
    krb_realm: String,
    krb_kdc: String,
}

#[derive(Deserialize)]
pub(crate) struct JrlRequest {
    #[serde(flatten)]
    common: CommonRequest,
    jti: Vec<Uuid>,
}

#[derive(Deserialize)]
pub(crate) struct NetScanRequest {
    #[serde(flatten)]
    common: CommonRequest,
}
