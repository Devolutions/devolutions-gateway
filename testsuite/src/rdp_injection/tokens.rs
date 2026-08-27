//! Unsigned JWTs for suites running with `disable_token_validation`.

use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context as _;
use base64::Engine as _;

use super::SERVICE_HOST;

pub fn next_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("00000000-0000-4000-a000-{n:012x}")
}

pub fn unsigned_jws(header: serde_json::Value, payload: serde_json::Value) -> anyhow::Result<String> {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = engine.encode(serde_json::to_vec(&header).context("serialize JWT header")?);
    let payload = engine.encode(serde_json::to_vec(&payload).context("serialize JWT payload")?);
    Ok(format!("{header}.{payload}.ZHVtbXlfc2lnbmF0dXJl"))
}

pub fn preflight_scope_token() -> anyhow::Result<String> {
    unsigned_jws(
        serde_json::json!({"alg":"RS256","typ":"JWT","cty":"SCOPE"}),
        serde_json::json!({
            "scope": "gateway.preflight",
            "exp": 9_999_999_999i64,
            "jti": next_id(),
        }),
    )
}

pub fn association_token(jti: &str, jet_aid: &str, dest_port: u16, jet_reuse: u32) -> anyhow::Result<String> {
    association_claims(jti, jet_aid, format!("127.0.0.1:{dest_port}"), jet_reuse)
}

pub fn association_token_for_host(jti: &str, jet_aid: &str, dest_port: u16, jet_reuse: u32) -> anyhow::Result<String> {
    association_claims(jti, jet_aid, format!("{SERVICE_HOST}:{dest_port}"), jet_reuse)
}

fn association_claims(jti: &str, jet_aid: &str, dst_hst: String, jet_reuse: u32) -> anyhow::Result<String> {
    unsigned_jws(
        serde_json::json!({"alg":"RS256","typ":"JWT","cty":"ASSOCIATION"}),
        serde_json::json!({
            "dst_hst": dst_hst,
            "exp": 9_999_999_999i64,
            "jet_aid": jet_aid,
            "jet_ap": "rdp",
            "jet_cm": "fwd",
            "jet_rec": "none",
            "jet_reuse": jet_reuse,
            "jti": jti,
            "nbf": 0,
        }),
    )
}

pub fn kdc_inject_token(association_jti: &str) -> anyhow::Result<String> {
    unsigned_jws(
        serde_json::json!({"alg":"RS256","typ":"JWT","cty":"KDC"}),
        serde_json::json!({
            "exp": 9_999_999_999i64,
            "jet_cred_id": association_jti,
            "jti": next_id(),
        }),
    )
}

pub fn kdc_proxy_url(http_port: u16, association_jti: &str) -> anyhow::Result<String> {
    let token = kdc_inject_token(association_jti)?;
    Ok(format!("http://127.0.0.1:{http_port}/jet/KdcProxy/{token}"))
}
