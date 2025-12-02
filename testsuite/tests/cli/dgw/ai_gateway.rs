//! AI Gateway smoke tests.
//!
//! These tests verify the basic functionality of the AI Gateway feature.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context as _;
use testsuite::cli::{dgw_tokio_cmd, wait_for_tcp_port};
use testsuite::dgw_config::{AiGatewayConfig, DgwConfig, DgwConfigHandle, VerbosityProfile};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::TcpListener;
use tokio::process::Child;

/// Spawn a mock OpenAI-compatible HTTP server.
async fn spawn_mock_openai_server(response_body: &str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let response_body = response_body.to_owned();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let response_body = response_body.clone();
            tokio::spawn(async move {
                // Read the HTTP request headers properly.
                let mut reader = BufReader::new(&mut stream);
                let mut content_length = 0;
                let mut received_auth_header = String::new();

                // Read HTTP headers (malformed headers are silently ignored in this test helper).
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                        break;
                    }
                    if line.to_lowercase().starts_with("content-length:") {
                        content_length = line
                            .split_once(':')
                            .and_then(|(_, v)| v.trim().parse().ok())
                            .unwrap_or(0);
                    }
                    if line.to_lowercase().starts_with("authorization:") {
                        received_auth_header = line
                            .split_once(':')
                            .map(|(_, v)| v.trim().to_owned())
                            .unwrap_or_default();
                    }
                    if line.trim().is_empty() {
                        break;
                    }
                }

                // Read the body if there is one.
                let mut body_buf = vec![0; content_length];
                if content_length > 0 {
                    let _ = reader.read_exact(&mut body_buf).await;
                }

                // Build a response that includes the received auth header for verification.
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );

                println!("Mock server received auth header: {received_auth_header}");
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
                let _ = stream.shutdown().await;
            });
        }
    });

    addr
}

/// Spawn a mock HTTP server that returns a specific status code.
async fn spawn_mock_status_server(status_code: u16, status_text: &str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let status_text = status_text.to_owned();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let status_text = status_text.clone();
            tokio::spawn(async move {
                // Read the HTTP request headers (malformed headers are silently ignored).
                let mut reader = BufReader::new(&mut stream);
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                        break;
                    }
                    if line.trim().is_empty() {
                        break;
                    }
                }

                let body = format!(r#"{{"error": "{}"}}"#, status_text);
                let response = format!(
                    "HTTP/1.1 {status_code} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );

                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
                let _ = stream.shutdown().await;
            });
        }
    });

    addr
}

/// Start a Devolutions Gateway instance with AI gateway enabled.
async fn start_gateway_with_ai(
    mock_server_addr: SocketAddr,
    gateway_api_key: Option<String>,
    openai_api_key: Option<String>,
) -> anyhow::Result<(DgwConfigHandle, Child)> {
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .verbosity_profile(VerbosityProfile::DEBUG)
        .enable_unstable(true)
        .ai_gateway(
            AiGatewayConfig::builder()
                .enabled(true)
                .gateway_api_key(gateway_api_key)
                .openai_endpoint(format!("http://{mock_server_addr}"))
                .openai_api_key(openai_api_key)
                .build(),
        )
        .build()
        .init()
        .context("init config")?;

    let process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to start Devolutions Gateway")?;

    // Wait until the gateway is accepting connections on the HTTP port.
    wait_for_tcp_port(config_handle.http_port()).await?;

    Ok((config_handle, process))
}

/// Make an HTTP request to the AI gateway endpoint.
async fn make_ai_request(
    gateway_port: u16,
    endpoint: &str,
    auth_header: Option<&str>,
    body: Option<&str>,
) -> anyhow::Result<(u16, String)> {
    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{gateway_port}")).await?;
    let (mut reader, mut writer) = stream.into_split();

    let method = if body.is_some() { "POST" } else { "GET" };
    let body_content = body.unwrap_or("");
    let content_length = body_content.len();

    let mut request = format!("{method} {endpoint} HTTP/1.1\r\nHost: 127.0.0.1:{gateway_port}\r\n");

    if let Some(auth) = auth_header {
        request.push_str(&format!("Authorization: {auth}\r\n"));
    }

    if body.is_some() {
        request.push_str("Content-Type: application/json\r\n");
        request.push_str(&format!("Content-Length: {content_length}\r\n"));
    }

    request.push_str("\r\n");
    request.push_str(body_content);

    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;

    // Read the response.
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let mut buf = [0u8; 1024];
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => response.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
            // Check if we've received the complete response.
            let response_str = String::from_utf8_lossy(&response);
            if response_str.contains("\r\n\r\n") {
                // Check if we have the body.
                if let Some(headers_end) = response_str.find("\r\n\r\n") {
                    let headers = &response_str[..headers_end];
                    if let Some(cl_line) = headers
                        .lines()
                        .find(|l| l.to_lowercase().starts_with("content-length:"))
                    {
                        let cl: usize = cl_line
                            .split_once(':')
                            .and_then(|(_, v)| v.trim().parse().ok())
                            .unwrap_or(0);
                        let body_start = headers_end + 4;
                        if response.len() >= body_start + cl {
                            break;
                        }
                    } else {
                        // No content-length, assume response is complete.
                        break;
                    }
                }
            }
        }
    })
    .await
    .context("timeout reading response")?;

    let response_str = String::from_utf8_lossy(&response).to_string();

    // Parse status code from response.
    let status_line = response_str.lines().next().unwrap_or("");
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Extract body.
    let body_start = response_str.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    let body = response_str[body_start..].to_string();

    Ok((status_code, body))
}

#[tokio::test]
async fn ai_gateway_openai_models_endpoint() -> anyhow::Result<()> {
    let mock_response = r#"{"object":"list","data":[{"id":"gpt-4","object":"model"}]}"#;
    let mock_server = spawn_mock_openai_server(mock_response).await;

    let (config_handle, _process) =
        start_gateway_with_ai(mock_server, None, Some("test-openai-key".to_owned())).await?;

    // Make a request to the AI gateway's OpenAI models endpoint.
    let (status, body) = make_ai_request(config_handle.http_port(), "/jet/ai/openai/v1/models", None, None).await?;

    assert_eq!(status, 200, "Expected 200 OK, got {status}");
    assert!(body.contains("gpt-4"), "Expected response to contain gpt-4 model");

    Ok(())
}

#[tokio::test]
async fn ai_gateway_openai_chat_completions() -> anyhow::Result<()> {
    let mock_response =
        r#"{"id":"chatcmpl-123","object":"chat.completion","choices":[{"message":{"content":"Hello!"}}]}"#;
    let mock_server = spawn_mock_openai_server(mock_response).await;

    let (config_handle, _process) =
        start_gateway_with_ai(mock_server, None, Some("test-openai-key".to_owned())).await?;

    let request_body = r#"{"model":"gpt-4","messages":[{"role":"user","content":"Hi"}]}"#;

    let (status, body) = make_ai_request(
        config_handle.http_port(),
        "/jet/ai/openai/v1/chat/completions",
        None,
        Some(request_body),
    )
    .await?;

    assert_eq!(status, 200, "Expected 200 OK, got {status}");
    assert!(
        body.contains("chat.completion"),
        "Expected response to contain chat.completion"
    );

    Ok(())
}

#[tokio::test]
async fn ai_gateway_requires_gateway_api_key() -> anyhow::Result<()> {
    let mock_response = r#"{"object":"list","data":[]}"#;
    let mock_server = spawn_mock_openai_server(mock_response).await;

    // Configure gateway with a required API key.
    let gateway_api_key = "secret-gateway-key";
    let (config_handle, _process) = start_gateway_with_ai(
        mock_server,
        Some(gateway_api_key.to_owned()),
        Some("test-openai-key".to_owned()),
    )
    .await?;

    // Request without authorization header should fail.
    let (status, _body) = make_ai_request(config_handle.http_port(), "/jet/ai/openai/v1/models", None, None).await?;

    assert_eq!(status, 401, "Expected 401 Unauthorized without API key, got {status}");

    // Request with wrong API key should fail.
    let (status, _body) = make_ai_request(
        config_handle.http_port(),
        "/jet/ai/openai/v1/models",
        Some("Bearer wrong-key"),
        None,
    )
    .await?;

    assert_eq!(
        status, 401,
        "Expected 401 Unauthorized with wrong API key, got {status}"
    );

    // Request with correct API key should succeed.
    let (status, _body) = make_ai_request(
        config_handle.http_port(),
        "/jet/ai/openai/v1/models",
        Some(&format!("Bearer {gateway_api_key}")),
        None,
    )
    .await?;

    assert_eq!(status, 200, "Expected 200 OK with correct API key, got {status}");

    Ok(())
}

#[tokio::test]
async fn ai_gateway_proxies_provider_errors() -> anyhow::Result<()> {
    // Spawn a mock server that returns an error.
    let mock_server = spawn_mock_status_server(429, "Too Many Requests").await;

    let (config_handle, _process) =
        start_gateway_with_ai(mock_server, None, Some("test-openai-key".to_owned())).await?;

    let (status, body) = make_ai_request(config_handle.http_port(), "/jet/ai/openai/v1/models", None, None).await?;

    assert_eq!(status, 429, "Expected 429 from provider to be proxied, got {status}");
    assert!(
        body.contains("Too Many Requests"),
        "Expected error message to be proxied"
    );

    Ok(())
}

#[tokio::test]
async fn ai_gateway_missing_api_key_returns_error() -> anyhow::Result<()> {
    // Spawn a mock server (won't be called).
    let mock_server = spawn_mock_openai_server(r#"{"should":"not reach"}"#).await;

    // Configure gateway WITHOUT an OpenAI API key.
    let (config_handle, _process) = start_gateway_with_ai(mock_server, None, None).await?;

    let (status, _body) = make_ai_request(config_handle.http_port(), "/jet/ai/openai/v1/models", None, None).await?;

    assert_eq!(
        status, 500,
        "Expected 500 Internal Server Error when API key is missing, got {status}"
    );

    Ok(())
}
