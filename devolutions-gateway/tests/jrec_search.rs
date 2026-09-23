#![allow(unused_crate_dependencies)]
#![allow(clippy::unwrap_used)]

use std::net::SocketAddr;
use std::path::Path;

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{self, Request, StatusCode};
use base64::Engine as _;
use devolutions_gateway::{DgwState, MockHandles};
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use tower::ServiceExt as _;
use uuid::Uuid;

const PROVISIONER_PUBLIC_KEY: &str = "mMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4vuqLOkl1pWobt6su1XO9VskgCAwevEGs6kkNjJQBwkGnPKYLmNF1E/af1yCocfVn/OnPf9e4x+lXVyZ6LMDJxFxu+axdgOq3Ld392J1iAEbfvwlyRFnEXFOJNyylqg3bY6LvnWHL/XZczVdMD9xYfq2sO9bg3xjRW4s7r9EEYOFjqVT3VFznH9iWJVtcSEKukmS/3uKoO6lGhacvu0HhjXXdgq0R8zvR4XRJ9Fcnf0f9Ypoc+i6L80NVjrRCeVOH+Ld/2fA9bocpfLarcVqG3RjS+qgOtpyCc0jWVFF4zaGQ7LUDFkEIYILkICeMMn2ll29hmZNzsJzZJ9s6NocgQIDAQAB";

const SEARCH_SCOPE: &str = "gateway.recordings.search";

fn make_router(recording_path: &Path, enable_unstable: bool) -> anyhow::Result<(Router, MockHandles)> {
    let config = json!({
        "ProvisionerPublicKeyData": { "Value": PROVISIONER_PUBLIC_KEY },
        "RecordingPath": recording_path,
        "Listeners": [
            { "InternalUrl": "tcp://*:8080", "ExternalUrl": "tcp://*:8080" },
            { "InternalUrl": "http://*:7171", "ExternalUrl": "https://*:7171" },
        ],
        "__debug__": {
            "disable_token_validation": true,
            "enable_unstable": enable_unstable,
        },
    });

    let (state, handles) = DgwState::mock(&config.to_string())?;
    let app =
        devolutions_gateway::make_http_service(state).layer(MockConnectInfo(SocketAddr::from(([0, 0, 0, 0], 3000))));

    Ok((app, handles))
}

fn scope_token(scope: &str) -> anyhow::Result<String> {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = engine.encode(r#"{"alg":"RS256"}"#);
    let payload = engine.encode(serde_json::to_vec(&json!({
        "type": "scope",
        "scope": scope,
        "exp": time::OffsetDateTime::now_utc().unix_timestamp() + 3600,
        "jti": Uuid::new_v4(),
    }))?);
    let signature = engine.encode(b"signature");
    Ok(format!("{header}.{payload}.{signature}"))
}

fn search_request(scope: &str, body: &Value) -> anyhow::Result<Request<Body>> {
    let request = Request::builder()
        .method("POST")
        .uri("/jet/jrec/search")
        .header("content-type", "application/json")
        .header(http::header::AUTHORIZATION, format!("Bearer {}", scope_token(scope)?))
        .body(Body::from(serde_json::to_vec(body)?))?;

    Ok(request)
}

async fn send(app: Router, request: Request<Body>) -> anyhow::Result<(StatusCode, Value)> {
    let response = app.oneshot(request).await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    let body = serde_json::from_slice(&body).unwrap_or(Value::Null);
    Ok((status, body))
}

/// Writes one recording folder with a manifest listing a single `.slog` file.
fn add_recording(recording_path: &Path, start_time: i64, log: &str) -> anyhow::Result<Uuid> {
    let id = Uuid::new_v4();
    let dir = recording_path.join(id.to_string());
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("recording-0.slog"), log)?;

    let manifest = json!({
        "sessionId": id,
        "startTime": start_time,
        "duration": 60,
        "files": [{ "fileName": "recording-0.slog", "startTime": start_time, "duration": 60 }],
    });
    std::fs::write(dir.join("recording.json"), manifest.to_string())?;

    Ok(id)
}

fn log_line(timestamp: &str, description: &str, object: &str) -> String {
    let entry = json!({
        "timestamp": timestamp,
        "seq": 0,
        "event": "session.action",
        "description": description,
        "object": object,
    });
    format!("{entry}\n")
}

#[tokio::test]
async fn searches_every_recording_newest_first_when_no_recording_is_listed() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let older = add_recording(
        dir.path(),
        100,
        &log_line("2026-07-15T10:00:00.000Z", "Changed password", "Bob Smith"),
    )?;
    let newer = add_recording(
        dir.path(),
        200,
        &log_line("2026-07-16T10:00:00.000Z", "Changed password", "Alice Jones"),
    )?;
    let (app, _handles) = make_router(dir.path(), true)?;

    let (status, body) = send(app, search_request(SEARCH_SCOPE, &json!({ "query": "PASSWORD" }))?).await?;

    assert_eq!(status, StatusCode::OK, "{body}");
    let hits = body["hits"].as_array().expect("hits array");
    assert_eq!(hits.len(), 2);
    assert_eq!(hits[0]["recordingId"], newer.to_string());
    assert_eq!(hits[1]["recordingId"], older.to_string());
    assert_eq!(hits[0]["fileName"], "recording-0.slog");
    assert_eq!(hits[0]["lineNumber"], 1);
    assert_eq!(hits[0]["entry"]["object"], "Alice Jones");
    assert_eq!(hits[0]["matchedFields"], json!(["description"]));
    assert_eq!(body["notFoundRecordingIds"], json!([]));
    assert_eq!(body["limitReached"], false);
    assert_eq!(body["scanLimitReached"], false);

    Ok(())
}

#[tokio::test]
async fn searches_only_the_listed_recordings_within_the_time_range() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let log = [
        log_line("2026-07-15T23:59:59.999Z", "Changed password", "Before"),
        log_line("2026-07-16T00:00:00.000Z", "Changed password", "Inside"),
        log_line("2026-07-17T00:00:00.000Z", "Changed password", "After"),
    ]
    .concat();
    let listed = add_recording(dir.path(), 100, &log)?;
    add_recording(dir.path(), 200, &log)?;
    let missing = Uuid::new_v4();
    let (app, _handles) = make_router(dir.path(), true)?;

    let body = json!({
        "recordingIds": [listed, missing],
        "query": "password",
        "from": "2026-07-16T00:00:00Z",
        "to": "2026-07-17T00:00:00Z",
    });
    let (status, body) = send(app, search_request(SEARCH_SCOPE, &body)?).await?;

    assert_eq!(status, StatusCode::OK, "{body}");
    let hits = body["hits"].as_array().expect("hits array");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0]["recordingId"], listed.to_string());
    assert_eq!(hits[0]["entry"]["object"], "Inside");
    assert_eq!(body["notFoundRecordingIds"], json!([missing]));

    Ok(())
}

#[tokio::test]
async fn rejects_an_empty_time_range() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let (app, _handles) = make_router(dir.path(), true)?;

    let body = json!({ "from": "2026-07-16T00:00:00Z", "to": "2026-07-16T00:00:00Z" });
    let (status, _) = send(app, search_request(SEARCH_SCOPE, &body)?).await?;

    assert_eq!(status, StatusCode::BAD_REQUEST);

    Ok(())
}

#[tokio::test]
async fn rejects_the_recordings_read_scope() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let (app, _handles) = make_router(dir.path(), true)?;

    let (status, _) = send(app, search_request("gateway.recordings.read", &json!({}))?).await?;

    assert_eq!(status, StatusCode::FORBIDDEN);

    Ok(())
}

#[tokio::test]
async fn requires_unstable_features() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let (app, _handles) = make_router(dir.path(), false)?;

    let (status, _) = send(app, search_request(SEARCH_SCOPE, &json!({}))?).await?;

    assert_eq!(status, StatusCode::NOT_FOUND);

    Ok(())
}
