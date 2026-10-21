//! Recording log search API tests.

use std::path::Path;

use anyhow::Context as _;
use base64::Engine as _;
use testsuite::cli::start_dgw;
use testsuite::dgw_config::{DgwConfig, DgwConfigHandle};
use uuid::Uuid;

const OLDER_RECORDING: Uuid = Uuid::from_u128(1);
const NEWER_RECORDING: Uuid = Uuid::from_u128(2);

/// Unsigned scope token; token validation is disabled in these tests.
fn scope_token(scope: &str) -> String {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = serde_json::json!({ "typ": "JWT", "alg": "RS256" });
    let payload = serde_json::json!({
        "type": "scope",
        "jti": Uuid::new_v4().to_string(),
        "iat": 1_733_669_999,
        "nbf": 1_733_669_999,
        "exp": 3_331_553_599i64,
        "scope": scope,
    });

    format!(
        "{}.{}.{}",
        b64.encode(header.to_string()),
        b64.encode(payload.to_string()),
        b64.encode("signature-not-checked"),
    )
}

fn write_recording(root: &Path, id: Uuid, manifest: serde_json::Value, files: &[(&str, &str)]) -> anyhow::Result<()> {
    let dir = root.join(id.to_string());
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("recording.json"), manifest.to_string())?;
    for (name, content) in files {
        std::fs::write(dir.join(name), content)?;
    }
    Ok(())
}

/// A recording whose only log is the AI analysis artifact `ai-analysis-0.slog` holding `log`.
fn write_analysis_recording(root: &Path, id: Uuid, start_time: i64, log: &str) -> anyhow::Result<()> {
    write_recording(
        root,
        id,
        serde_json::json!({
            "sessionId": id.to_string(),
            "startTime": start_time,
            "duration": 10,
            "files": [{ "fileName": "recording-0.webm", "startTime": start_time, "duration": 10 }],
            "artifacts": { "ai-analysis": [{ "fileName": "ai-analysis-0.slog" }] },
        }),
        &[("ai-analysis-0.slog", log)],
    )
}

/// Two recordings whose AI analysis logs hold the searched text.
/// The older one also holds it in a recorded `.slog`, in its video, and in a log outside the recording folder that
/// its manifest points to, to show that only the `.slog` artifacts of a recording are searched.
/// Its manifest also lists a log that is gone, and a third recording folder has no manifest, to show that neither
/// fails the search.
fn write_recordings(root: &Path) -> anyhow::Result<()> {
    std::fs::write(
        root.join("outside.slog"),
        r#"{"timestamp":"2026-07-15T16:15:35.140Z","seq":0,"event":"session.action","description":"Created User"}"#,
    )?;
    std::fs::create_dir(root.join(Uuid::from_u128(3).to_string()))?;

    write_recording(
        root,
        OLDER_RECORDING,
        serde_json::json!({
            "sessionId": OLDER_RECORDING.to_string(),
            "startTime": 100,
            "duration": 10,
            "files": [
                { "fileName": "recording-0.slog", "startTime": 100, "duration": 10 },
                { "fileName": "recording-1.webm", "startTime": 100, "duration": 10 },
            ],
            "artifacts": {
                "ai-analysis": [
                    { "fileName": "ai-analysis-1.slog" },
                    { "fileName": "ai-analysis-0.slog" },
                    { "fileName": "../outside.slog" },
                ],
            },
        }),
        &[
            (
                "recording-0.slog",
                r#"{"timestamp":"2026-07-15T16:15:41.054Z","seq":1,"event":"session.action","description":"Created User"}"#,
            ),
            ("recording-1.webm", "Created User"),
            (
                "ai-analysis-0.slog",
                concat!(
                    r#"{"timestamp":"2026-07-15T16:15:35.140Z","seq":0,"event":"session.start","description":"Session started"}"#,
                    "\n",
                    r#"{"timestamp":"2026-07-15T16:15:41.054Z","seq":1,"event":"session.action","description":"Created User","object":"Help Desk Ottawa"}"#,
                    "\n",
                ),
            ),
        ],
    )?;

    write_analysis_recording(
        root,
        NEWER_RECORDING,
        200,
        r#"{"timestamp":"2026-07-16T09:00:01.000Z","seq":1,"event":"session.action","description":"Opened Users","parameters":{"Action":"Created user"}}"#,
    )
}

/// Starts Gateway on `recordings`; the returned folder and process must outlive the test requests.
async fn start_on(
    recordings: tempfile::TempDir,
) -> anyhow::Result<(tempfile::TempDir, DgwConfigHandle, tokio::process::Child)> {
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .recording_path(recordings.path().to_owned())
        .build()
        .init()?;
    let process = start_dgw(&config_handle).await?;

    Ok((recordings, config_handle, process))
}

/// Starts Gateway on the recordings above.
async fn start_with_recordings() -> anyhow::Result<(tempfile::TempDir, DgwConfigHandle, tokio::process::Child)> {
    let recordings = tempfile::tempdir()?;
    write_recordings(recordings.path())?;

    start_on(recordings).await
}

async fn search(http_port: u16, scope: &str, request: serde_json::Value) -> anyhow::Result<reqwest::Response> {
    reqwest::Client::new()
        .post(format!("http://127.0.0.1:{http_port}/jet/jrec/search"))
        .bearer_auth(scope_token(scope))
        .json(&request)
        .send()
        .await
        .context("send search request")
}

/// `(recordingId, fileName, lineNumber)` of each hit.
fn hit_summaries(body: &serde_json::Value) -> anyhow::Result<Vec<(String, String, u64)>> {
    body["hits"]
        .as_array()
        .context("hits")?
        .iter()
        .map(|hit| {
            Ok((
                hit["recordingId"].as_str().context("recordingId")?.to_owned(),
                hit["fileName"].as_str().context("fileName")?.to_owned(),
                hit["lineNumber"].as_u64().context("lineNumber")?,
            ))
        })
        .collect()
}

#[tokio::test]
async fn searches_the_slog_artifacts_of_every_recording_newest_first() -> anyhow::Result<()> {
    let (_recordings, config_handle, _process) = start_with_recordings().await?;

    let response = search(
        config_handle.http_port(),
        "gateway.recordings.search",
        serde_json::json!({ "query": "created USER", "recordings": "all" }),
    )
    .await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().await?;
    assert_eq!(
        hit_summaries(&body)?,
        [
            (NEWER_RECORDING.to_string(), "ai-analysis-0.slog".to_owned(), 1),
            (OLDER_RECORDING.to_string(), "ai-analysis-0.slog".to_owned(), 2),
        ]
    );
    assert_eq!(body["limitReached"], false);

    Ok(())
}

#[tokio::test]
async fn searches_each_listed_recording_once() -> anyhow::Result<()> {
    let (_recordings, config_handle, _process) = start_with_recordings().await?;

    let response = search(
        config_handle.http_port(),
        "gateway.recordings.search",
        serde_json::json!({
            "query": "created user",
            "recordings": [OLDER_RECORDING.to_string(), OLDER_RECORDING.to_string()],
        }),
    )
    .await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().await?;
    assert_eq!(
        hit_summaries(&body)?,
        [(OLDER_RECORDING.to_string(), "ai-analysis-0.slog".to_owned(), 2)]
    );

    Ok(())
}

#[tokio::test]
async fn searches_only_the_recordings_started_in_the_time_range() -> anyhow::Result<()> {
    let recordings = tempfile::tempdir()?;
    for (id, start_time) in [(1, 100), (2, 200), (3, 300)] {
        write_analysis_recording(recordings.path(), Uuid::from_u128(id), start_time, "Created User")?;
    }
    let (_recordings, config_handle, _process) = start_on(recordings).await?;

    // From the start time 200 up to, but not including, 300.
    let response = search(
        config_handle.http_port(),
        "gateway.recordings.search",
        serde_json::json!({
            "query": "created user",
            "recordings": "all",
            "startTime": { "from": "1970-01-01T00:03:20Z", "to": "1970-01-01T00:05:00Z" },
        }),
    )
    .await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().await?;
    assert_eq!(
        hit_summaries(&body)?,
        [(Uuid::from_u128(2).to_string(), "ai-analysis-0.slog".to_owned(), 1)]
    );

    Ok(())
}

#[tokio::test]
async fn rejects_a_token_without_the_search_scope() -> anyhow::Result<()> {
    let (_recordings, config_handle, _process) = start_with_recordings().await?;

    let response = search(
        config_handle.http_port(),
        "gateway.recordings.read",
        serde_json::json!({ "query": "created", "recordings": "all" }),
    )
    .await?;
    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);

    Ok(())
}
