//! Retained Gateway log API tests.

use anyhow::Context as _;
use base64::Engine as _;
use testsuite::cli::start_dgw;
use testsuite::dgw_config::{DgwConfig, DgwConfigHandle};
use uuid::Uuid;

const LOG_NAME: &str = "gateway.contract.log";
const LOG_CONTENT: &str = "diagnostics route contract\n";

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

async fn start_with_log_file() -> anyhow::Result<(DgwConfigHandle, tokio::process::Child)> {
    let config = DgwConfig::builder().disable_token_validation(true).build().init()?;
    std::fs::write(config.config_dir().join(LOG_NAME), LOG_CONTENT).context("write retained log")?;
    std::fs::write(config.config_dir().join("gateway.contract.log.tmp"), "ignored")
        .context("write non-retained file")?;
    let process = start_dgw(&config).await?;
    Ok((config, process))
}

// oracle: mutant omitting retained files, changing response fields, or returning different download bytes.
#[tokio::test]
async fn lists_and_downloads_retained_log_files() -> anyhow::Result<()> {
    let (config, _process) = start_with_log_file().await?;
    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{}/jet/diagnostics/logs/files", config.http_port());
    let token = scope_token("gateway.diagnostics.read");

    let response = client.get(&base).bearer_auth(&token).send().await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let files: serde_json::Value = response.json().await?;
    let files = files.as_array().context("log list is an array")?;
    let log = files
        .iter()
        .find(|file| file["name"] == LOG_NAME)
        .context("fixture log is listed")?;
    assert_eq!(log["size"], serde_json::json!(LOG_CONTENT.len()));
    assert!(log["modifiedUnixMillis"].as_i64().is_some());
    assert!(!files.iter().any(|file| file["name"] == "gateway.contract.log.tmp"));

    let response = client
        .get(format!("{base}/{LOG_NAME}"))
        .bearer_auth(&token)
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .context("content type")?,
        "text/plain; charset=utf-8"
    );
    assert_eq!(response.text().await?, LOG_CONTENT);

    let response = client
        .get(format!("{base}/gateway.missing.log"))
        .bearer_auth(&token)
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);

    Ok(())
}

// oracle: mutant bypassing diagnostics scope or extracting a malformed path before checking scope.
#[tokio::test]
async fn log_routes_enforce_diagnostics_scope_before_path_extraction() -> anyhow::Result<()> {
    let (config, _process) = start_with_log_file().await?;
    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{}/jet/diagnostics/logs/files", config.http_port());
    let wrong_scope = scope_token("gateway.sessions.read");

    for url in [base.clone(), format!("{base}/{LOG_NAME}"), format!("{base}/%FF")] {
        let response = client.get(&url).bearer_auth(&wrong_scope).send().await?;
        assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN, "{url}");
    }

    let response = client
        .get(format!("{base}/%FF"))
        .bearer_auth(scope_token("gateway.diagnostics.read"))
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);

    for url in [base.clone(), format!("{base}/{LOG_NAME}")] {
        let response = client.get(&url).send().await?;
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED, "{url}");
    }

    Ok(())
}
