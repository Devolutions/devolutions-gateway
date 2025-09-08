#![allow(unused_crate_dependencies)]
#![allow(clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::thread;
use std::time::Duration;

use mcp_proxy::{Config, McpProxy, McpRequest};
use serde_json::json;

fn spawn_http_server(
    body: String,
    status_line: &'static str,
    headers: &'static [(&'static str, &'static str)],
    delay: Option<Duration>,
) -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let addr = listener.local_addr().unwrap();

    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            // Read and discard request headers (until \r\n\r\n)
            let mut buf = [0u8; 1024];
            let mut req = Vec::new();
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        req.extend_from_slice(&buf[..n]);
                        if req.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                }
            }

            if let Some(delay) = delay {
                thread::sleep(delay);
            }

            let mut response = format!("{status_line}\r\n");
            for (k, v) in headers {
                response.push_str(&format!("{k}: {v}\r\n"));
            }
            response.push_str(&format!("Content-Length: {}\r\n", body.as_bytes().len()));
            response.push_str("\r\n");

            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(body.as_bytes());
            let _ = stream.flush();
        }
    });

    addr
}

#[tokio::test]
async fn http_plain_json_ok() {
    let body = json!({"result":{"tools":[{"name":"ping"}]}}).to_string();
    let addr = spawn_http_server(body, "HTTP/1.1 200 OK", &[("Content-Type", "application/json")], None);

    let mut proxy = McpProxy::new(Config::http(format!("http://{addr}"), None))
        .await
        .unwrap();

    let out = proxy
        .send_request(McpRequest {
            method: "tools/list".into(),
            params: serde_json::Value::Object(Default::default()),
        })
        .await
        .unwrap();

    assert_eq!(out["result"]["tools"][0]["name"], "ping");
}

#[tokio::test]
async fn http_sse_parsed() {
    let sse = "event: message\r\ndata: {\"result\": {\"ok\": true}}\r\n\r\n".to_owned();
    let addr = spawn_http_server(sse, "HTTP/1.1 200 OK", &[("Content-Type", "text/event-stream")], None);

    let mut proxy = McpProxy::new(Config::http(format!("http://{addr}"), None))
        .await
        .unwrap();

    let out = proxy
        .send_request(McpRequest {
            method: "x".into(),
            params: Default::default(),
        })
        .await
        .unwrap();

    assert_eq!(out["result"]["ok"], true);
}

#[tokio::test]
async fn http_empty_body_errors() {
    let addr = spawn_http_server(
        String::new(),
        "HTTP/1.1 200 OK",
        &[("Content-Type", "application/json")],
        None,
    );

    let mut proxy = McpProxy::new(Config::http(format!("http://{addr}"), None))
        .await
        .unwrap();

    let err = proxy
        .send_request(McpRequest {
            method: "x".into(),
            params: Default::default(),
        })
        .await
        .unwrap_err();

    assert!(err.to_string().contains("empty response body"));
}

#[tokio::test]
async fn http_timeout_triggers() {
    // Server responds after 200ms; client timeout is 50ms
    let addr = spawn_http_server(
        "{\"result\":{}}".to_owned(),
        "HTTP/1.1 200 OK",
        &[("Content-Type", "application/json")],
        Some(Duration::from_millis(200)),
    );

    let mut proxy = McpProxy::new(Config::http(format!("http://{addr}"), Some(Duration::from_millis(50))))
        .await
        .unwrap();

    let err = proxy
        .send_request(McpRequest {
            method: "x".into(),
            params: Default::default(),
        })
        .await
        .unwrap_err();

    // reqwest/ureq/hyper-specific text varies; assert on our added context
    assert!(err.to_string().contains("failed to send request to MCP server"));
}

#[tokio::test]
async fn microsoft_learn() {
    let mut proxy = McpProxy::new(Config::http(
        "https://learn.microsoft.com/api/mcp",
        Some(Duration::from_secs(5)),
    ))
    .await
    .unwrap();

    let out = proxy
        .send_request(McpRequest {
            method: "tools/list".to_owned(),
            params: Default::default(),
        })
        .await
        .unwrap();

    assert_eq!(out["result"]["tools"][0]["name"], "microsoft_docs_search");
}
