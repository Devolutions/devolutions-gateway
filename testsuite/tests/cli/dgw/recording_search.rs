//! Recording log search API tests.

use std::path::Path;

use anyhow::Context as _;
use base64::Engine as _;
use rstest::rstest;
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
/// The older one also holds it in its recorded `.slog`, in its video, and in a log outside the recording folder that
/// its manifest lists under both `files` and `artifacts`, to show that every `.slog` of a recording is searched, and
/// nothing else.
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
                { "fileName": "../outside.slog", "startTime": 100, "duration": 10 },
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

/// Follows `nextCursor` from the first page to the last, and returns every page.
async fn search_every_page(http_port: u16, mut request: serde_json::Value) -> anyhow::Result<Vec<serde_json::Value>> {
    let mut pages = Vec::new();

    loop {
        let response = search(http_port, "gateway.recordings.search", request.clone()).await?;
        anyhow::ensure!(
            response.status() == reqwest::StatusCode::OK,
            "status {}",
            response.status()
        );

        let page: serde_json::Value = response.json().await?;
        let next_cursor = page.get("nextCursor").cloned();
        pages.push(page);

        let Some(next_cursor) = next_cursor else {
            return Ok(pages);
        };
        anyhow::ensure!(pages.len() < 100, "paging does not end");
        request["cursor"] = next_cursor;
    }
}

/// `(recordingId, fileName, lineNumber)` of each hit of every page, in order.
fn hit_summaries_of(pages: &[serde_json::Value]) -> anyhow::Result<Vec<(String, String, u64)>> {
    Ok(pages
        .iter()
        .map(hit_summaries)
        .collect::<anyhow::Result<Vec<_>>>()?
        .concat())
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

// oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §What is searched
// oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Request
// oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Pages
#[tokio::test]
async fn searches_the_slog_files_of_every_recording_newest_first() -> anyhow::Result<()> {
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
            (OLDER_RECORDING.to_string(), "recording-0.slog".to_owned(), 1),
            (OLDER_RECORDING.to_string(), "ai-analysis-0.slog".to_owned(), 2),
        ]
    );
    assert!(body.get("nextCursor").is_none());

    Ok(())
}

// oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §What is searched
// oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Request
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
        [
            (OLDER_RECORDING.to_string(), "recording-0.slog".to_owned(), 1),
            (OLDER_RECORDING.to_string(), "ai-analysis-0.slog".to_owned(), 2),
        ]
    );

    Ok(())
}

// oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Request
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

// oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Pages
// oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Request
#[tokio::test]
async fn pages_through_every_hit_once() -> anyhow::Result<()> {
    let recordings = tempfile::tempdir()?;
    let log = "Created User\n".repeat(600);
    write_analysis_recording(recordings.path(), OLDER_RECORDING, 100, &log)?;
    write_analysis_recording(recordings.path(), NEWER_RECORDING, 200, &log)?;
    let (_recordings, config_handle, _process) = start_on(recordings).await?;

    let pages = search_every_page(
        config_handle.http_port(),
        serde_json::json!({ "query": "created user", "recordings": "all" }),
    )
    .await?;

    let page_sizes: Vec<_> = pages
        .iter()
        .map(|page| page["hits"].as_array().map_or(0, Vec::len))
        .collect();
    assert_eq!(page_sizes, [1_000, 200]);

    let expected: Vec<_> = [NEWER_RECORDING, OLDER_RECORDING]
        .into_iter()
        .flat_map(|id| (1..=600).map(move |line_number| (id.to_string(), "ai-analysis-0.slog".to_owned(), line_number)))
        .collect();
    assert_eq!(hit_summaries_of(&pages)?, expected);

    Ok(())
}

// oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Request
// oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Pages
#[tokio::test]
async fn pages_through_recordings_that_start_together_highest_id_first() -> anyhow::Result<()> {
    let recordings = tempfile::tempdir()?;
    for id in 1..=3 {
        write_analysis_recording(recordings.path(), Uuid::from_u128(id), 100, "Created User")?;
    }
    let (_recordings, config_handle, _process) = start_on(recordings).await?;

    let pages = search_every_page(
        config_handle.http_port(),
        serde_json::json!({ "query": "created user", "recordings": "all", "maxHits": 1 }),
    )
    .await?;

    assert_eq!(pages.len(), 3);
    assert_eq!(
        hit_summaries_of(&pages)?,
        [3u128, 2, 1].map(|id| (Uuid::from_u128(id).to_string(), "ai-analysis-0.slog".to_owned(), 1))
    );

    Ok(())
}

// oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §What is searched
// oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Request
// oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Pages
#[tokio::test]
async fn pages_through_listed_recordings_in_their_order() -> anyhow::Result<()> {
    let (_recordings, config_handle, _process) = start_with_recordings().await?;

    let pages = search_every_page(
        config_handle.http_port(),
        serde_json::json!({
            "query": "created user",
            "recordings": [OLDER_RECORDING.to_string(), NEWER_RECORDING.to_string()],
            "maxHits": 1,
        }),
    )
    .await?;

    assert_eq!(pages.len(), 3);
    assert_eq!(
        hit_summaries_of(&pages)?,
        [
            (OLDER_RECORDING.to_string(), "recording-0.slog".to_owned(), 1),
            (OLDER_RECORDING.to_string(), "ai-analysis-0.slog".to_owned(), 2),
            (NEWER_RECORDING.to_string(), "ai-analysis-0.slog".to_owned(), 1),
        ]
    );

    Ok(())
}

#[rstest]
#[case::other_query(serde_json::json!({ "query": "opened users", "recordings": "all" }))]
#[case::query_in_another_case(serde_json::json!({ "query": "Created User", "recordings": "all" }))]
#[case::other_recordings(serde_json::json!({
    "query": "created user",
    "recordings": [NEWER_RECORDING.to_string(), OLDER_RECORDING.to_string()],
}))]
#[case::other_start_time(serde_json::json!({
// oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Pages
    "query": "created user",
    "recordings": "all",
    "startTime": { "from": "1970-01-01T00:00:00Z" },
}))]
#[tokio::test]
async fn rejects_a_cursor_from_another_search(#[case] mut other_search: serde_json::Value) -> anyhow::Result<()> {
    let (_recordings, config_handle, _process) = start_with_recordings().await?;

    let response = search(
        config_handle.http_port(),
        "gateway.recordings.search",
        serde_json::json!({ "query": "created user", "recordings": "all", "maxHits": 1 }),
    )
    .await?;
    let first_page: serde_json::Value = response.json().await?;
    other_search["cursor"] = first_page["nextCursor"].clone();
    assert!(other_search["cursor"].is_string());

    let response = search(config_handle.http_port(), "gateway.recordings.search", other_search).await?;
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);

    Ok(())
}

// oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Pages
// oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §What is searched
#[tokio::test]
async fn resumes_after_the_cursor_recording_is_deleted() -> anyhow::Result<()> {
    let recordings = tempfile::tempdir()?;
    for (id, start_time) in [(1, 100), (2, 200), (3, 300)] {
        write_analysis_recording(recordings.path(), Uuid::from_u128(id), start_time, "Created User")?;
    }
    let (recordings, config_handle, _process) = start_on(recordings).await?;
    let mut request = serde_json::json!({ "query": "created user", "recordings": "all", "maxHits": 1 });

    let response = search(config_handle.http_port(), "gateway.recordings.search", request.clone()).await?;
    let first_page: serde_json::Value = response.json().await?;
    std::fs::remove_dir_all(recordings.path().join(Uuid::from_u128(2).to_string()))?;
    request["cursor"] = first_page["nextCursor"].clone();
    let next_pages = search_every_page(config_handle.http_port(), request).await?;

    let ai_analysis = |id| (Uuid::from_u128(id).to_string(), "ai-analysis-0.slog".to_owned(), 1);
    assert_eq!(hit_summaries(&first_page)?, [ai_analysis(3)]);
    assert_eq!(hit_summaries_of(&next_pages)?, [ai_analysis(1)]);

    Ok(())
}

/// Rewrites fields of a cursor, which is hex-encoded JSON, as a caller could.
fn edit_cursor(cursor: &serde_json::Value, edits: serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let mut fields: serde_json::Value = serde_json::from_slice(&hex::decode(cursor.as_str().context("cursor")?)?)?;
    for (field, value) in edits.as_object().context("edits")? {
        fields[field] = value.clone();
    }

    Ok(serde_json::Value::String(hex::encode(serde_json::to_vec(&fields)?)))
}

// oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §What is searched
#[tokio::test]
async fn does_not_follow_a_cursor_out_of_its_recording() -> anyhow::Result<()> {
    let (_recordings, config_handle, _process) = start_with_recordings().await?;
    let mut request = serde_json::json!({ "query": "created user", "recordings": "all", "maxHits": 1 });

    let response = search(config_handle.http_port(), "gateway.recordings.search", request.clone()).await?;
    let first_page: serde_json::Value = response.json().await?;
    // From the start of the file, so that reading `outside.slog` would find its line.
    request["cursor"] = edit_cursor(
        &first_page["nextCursor"],
        serde_json::json!({
            "fileName": "../outside.slog",
            "position": { "offset": 0, "lineNumber": 0, "inLongLine": false },
        }),
    )?;
    let response = search(config_handle.http_port(), "gateway.recordings.search", request).await?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = response.json().await?;
    assert!(hit_summaries(&body)?.is_empty());

    Ok(())
}

// oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Pages
#[tokio::test]
async fn rejects_a_cursor_for_a_recording_not_in_the_list() -> anyhow::Result<()> {
    let (_recordings, config_handle, _process) = start_with_recordings().await?;
    let mut request = serde_json::json!({
        "query": "created user",
        "recordings": [OLDER_RECORDING.to_string(), NEWER_RECORDING.to_string()],
        "maxHits": 1,
    });

    let response = search(config_handle.http_port(), "gateway.recordings.search", request.clone()).await?;
    let first_page: serde_json::Value = response.json().await?;
    request["cursor"] = edit_cursor(
        &first_page["nextCursor"],
        serde_json::json!({ "recordingId": Uuid::from_u128(3).to_string() }),
    )?;
    let response = search(config_handle.http_port(), "gateway.recordings.search", request).await?;

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);

    Ok(())
}

// oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Access
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
