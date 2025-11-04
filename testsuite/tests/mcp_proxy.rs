use std::net::SocketAddr;
use std::time::Duration;

use mcp_proxy::{Config, McpProxy};

const DUMMY_REQUEST: &str = r#"{"jsonrpc": "2.0", "id": 1, "method": "x"}"#;
const MCP_PROXY_SHORTISH_TIMEOUT: Duration = Duration::from_millis(200);

async fn spawn_http_server(
    body: String,
    status_line: &'static str,
    headers: &'static [(&'static str, &'static str)],
    delay: Option<Duration>,
) -> SocketAddr {
    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            // Read the HTTP request headers properly.
            let mut reader = BufReader::new(&mut stream);
            let mut content_length = 0;

            // Read HTTP headers.
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).await.unwrap() == 0 {
                    break;
                }
                if line.starts_with("Content-Length:") {
                    content_length = line.trim().split(':').nth(1).unwrap().trim().parse().unwrap_or(0);
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

            if let Some(delay) = delay {
                println!("Server sleep for {delay:?}");
                tokio::time::sleep(delay).await;
            }

            let mut response = format!("{status_line}\r\n");
            for (k, v) in headers {
                response.push_str(&format!("{k}: {v}\r\n"));
            }
            response.push_str(&format!("Content-Length: {}\r\n", body.len()));
            response.push_str("\r\n");
            response.push_str(&body);

            println!("Server write response...");
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.flush().await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            let _ = stream.shutdown().await;
            println!("Server shutdown...");
        }
    });

    addr
}

#[tokio::test]
async fn http_plain_json_ok() {
    let server_response = r#"{"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "ping"}]}}"#;
    let addr = spawn_http_server(
        server_response.to_owned(),
        "HTTP/1.1 200 OK",
        &[("Content-Type", "application/json")],
        None,
    )
    .await;

    let mut proxy = McpProxy::init(Config::http(format!("http://{addr}"), Some(MCP_PROXY_SHORTISH_TIMEOUT)))
        .await
        .unwrap();

    let out = proxy
        .send_message(r#"{"jsonrpc": "2.0", "id": 1, "method": "tools/call"}"#)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(out.as_raw(), server_response);
}

#[tokio::test]
async fn http_sse_with_data() {
    let server_response = r#"{"result": {"ok": true}}"#;
    let sse = format!("event: message\r\ndata: {server_response}\r\n\r\n");
    let addr = spawn_http_server(sse, "HTTP/1.1 200 OK", &[("Content-Type", "text/event-stream")], None).await;

    let mut proxy = McpProxy::init(Config::http(format!("http://{addr}"), Some(MCP_PROXY_SHORTISH_TIMEOUT)))
        .await
        .unwrap();

    let out = proxy.send_message(DUMMY_REQUEST).await.unwrap().unwrap();
    assert_eq!(out.as_raw(), server_response);
}

#[tokio::test]
async fn http_sse_no_data_found_error() {
    let addr = spawn_http_server(String::new(), "HTTP/1.1 200 OK", &[], None).await;

    let mut proxy = McpProxy::init(Config::http(format!("http://{addr}"), Some(MCP_PROXY_SHORTISH_TIMEOUT)))
        .await
        .unwrap();

    let result = proxy
        .send_message(r#"{"jsonrpc": "2.0", "method": "x"}"#)
        .await
        .unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn http_notification() {
    let sse = "event: message\nretry: 1000\n\n".to_owned();
    let addr = spawn_http_server(sse, "HTTP/1.1 200 OK", &[("Content-Type", "text/event-stream")], None).await;

    let mut proxy = McpProxy::init(Config::http(format!("http://{addr}"), Some(MCP_PROXY_SHORTISH_TIMEOUT)))
        .await
        .unwrap();

    // HTTP errors are now returned as Err(ForwardError::Transient { message, .. }).
    match proxy.send_message(DUMMY_REQUEST).await {
        Err(mcp_proxy::SendError::Transient { message, .. }) => {
            let msg = message.expect("should have error message");
            assert!(msg.as_raw().contains("no data found in SSE response"));
        }
        other => panic!("expected transient error with message, got: {other:?}"),
    }
}

#[tokio::test]
async fn http_timeout_triggers() {
    // Server responds after 100ms but client timeout is 50ms.
    let addr = spawn_http_server(
        "{\"result\":{}}".to_owned(),
        "HTTP/1.1 200 OK",
        &[("Content-Type", "application/json")],
        Some(Duration::from_millis(100)),
    )
    .await;

    let mut proxy = McpProxy::init(Config::http(format!("http://{addr}"), Some(Duration::from_millis(50))))
        .await
        .unwrap();

    // HTTP errors are now returned as Err(ForwardError::Transient { message, .. }).
    match proxy.send_message(DUMMY_REQUEST).await {
        Err(mcp_proxy::SendError::Transient { message, source }) => {
            let msg = message.expect("should have error message");
            // HTTP client (ureq…) error text varies; assert on our added context.
            assert!(msg.as_raw().contains("failed to send request to MCP server"));
            // Also verify the source error contains timeout info.
            assert!(format!("{source:#}").contains("failed to send request to MCP server"));
        }
        other => panic!("expected transient error with message, got: {other:?}"),
    }
}

#[tokio::test]
async fn stdio_round_trip_json_line() {
    let (_dir_guard, command) = make_stdio_helper_script();
    let mut proxy = McpProxy::init(Config::spawn_process(command)).await.unwrap();

    // For Process transport: forward_request() writes, read_message() reads
    let response = proxy.send_message(DUMMY_REQUEST).await.unwrap();
    assert!(
        response.is_none(),
        "process transport dot not return the response immediately"
    );

    let out = proxy.read_message().await.unwrap();
    assert_eq!(out.as_raw(), r#"{"jsonrpc":"2.0","result":{"ok":true}}"#);

    fn make_stdio_helper_script() -> (tempfile::TempDir, String) {
        let dir = tempfile::TempDir::new().unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let path = dir.path().join("stdio_echo.sh");
            let script = r#"#!/bin/sh
# read line-by-line; ignore input, always reply a single JSON-RPC envelope per line
while IFS= read -r line; do
  printf '%s\n' '{"jsonrpc":"2.0","result":{"ok":true}}'
done
"#;
            std::fs::write(&path, script).unwrap();
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).unwrap();
            (dir, path.to_string_lossy().into_owned())
        }

        #[cfg(windows)]
        {
            let path = dir.path().join("stdio_echo.bat");
            let script = r#"@echo off
:loop
set /p line=
echo {"jsonrpc":"2.0","result":{"ok":true}}
goto loop
"#;
            std::fs::write(&path, script).unwrap();
            (dir, path.to_string_lossy().into_owned())
        }
    }
}
