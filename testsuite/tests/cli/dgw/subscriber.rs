use anyhow::Context as _;
use testsuite::cli::start_dgw;
use testsuite::dgw_config::{DgwConfig, ProxyMode, SubscriberConfig};
use testsuite::http::HttpRequestCapture;

#[tokio::test]
async fn subscriber_requests_identify_gateway() -> anyhow::Result<()> {
    let capture = HttpRequestCapture::bind().await?;
    let subscriber = SubscriberConfig::builder()
        .url(capture.url())
        .token("subscriber-token")
        .build();
    let config_handle = DgwConfig::builder()
        .subscriber(subscriber)
        .proxy_mode(ProxyMode::Off)
        .build()
        .init()
        .context("initialize Gateway configuration")?;
    let mut process = start_dgw(&config_handle).await?;

    let request = capture.receive().await;

    let _ = process.start_kill();
    let _ = process.wait().await;

    let request = request?;
    let user_agent = request
        .header("user-agent")
        .context("subscriber request has no User-Agent")?;
    let version = user_agent
        .strip_prefix("Devolutions-Gateway/")
        .context("subscriber User-Agent does not identify Devolutions Gateway")?;
    anyhow::ensure!(!version.is_empty(), "subscriber User-Agent does not include a version");

    Ok(())
}
