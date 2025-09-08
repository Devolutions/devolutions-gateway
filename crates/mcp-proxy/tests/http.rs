#![allow(unused_crate_dependencies)]
#![allow(clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::thread;
use std::time::Duration;

use mcp_proxy::{Config, McpProxy, McpRequest};
use std::collections::HashMap;

fn get_string_path(json: &tinyjson::JsonValue, path: &[&str]) -> String {
    let mut current = json;
    for &segment in path {
        if let Some(obj) = current.get::<HashMap<String, tinyjson::JsonValue>>() {
            current = obj.get(segment).unwrap();
        } else if let Some(arr) = current.get::<Vec<tinyjson::JsonValue>>() {
            let index: usize = segment.parse().unwrap();
            current = &arr[index];
        }
    }
    current.get::<String>().unwrap().clone()
}

fn get_bool_path(json: &tinyjson::JsonValue, path: &[&str]) -> bool {
    let mut current = json;
    for &segment in path {
        if let Some(obj) = current.get::<HashMap<String, tinyjson::JsonValue>>() {
            current = obj.get(segment).unwrap();
        } else if let Some(arr) = current.get::<Vec<tinyjson::JsonValue>>() {
            let index: usize = segment.parse().unwrap();
            current = &arr[index];
        }
    }
    *current.get::<bool>().unwrap()
}

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
                println!("Server sleep for {delay:?}");
                thread::sleep(delay);
            }

            let mut response = format!("{status_line}\r\n");
            for (k, v) in headers {
                response.push_str(&format!("{k}: {v}\r\n"));
            }
            response.push_str(&format!("Content-Length: {}\r\n", body.as_bytes().len()));
            response.push_str("\r\n");

            println!("Server write response...");
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(body.as_bytes());
            let _ = stream.flush();

            thread::sleep(Duration::from_millis(50));
            println!("Server shutdown...");
        }
    });

    addr
}

#[tokio::test]
async fn http_plain_json_ok() {
    let mut tools = HashMap::new();
    tools.insert("name".to_string(), tinyjson::JsonValue::String("ping".to_string()));

    let mut result = HashMap::new();
    result.insert(
        "tools".to_string(),
        tinyjson::JsonValue::Array(vec![tinyjson::JsonValue::Object(tools)]),
    );

    let mut response = HashMap::new();
    response.insert("result".to_string(), tinyjson::JsonValue::Object(result));

    let body = tinyjson::JsonValue::Object(response).stringify().unwrap();
    let addr = spawn_http_server(body, "HTTP/1.1 200 OK", &[("Content-Type", "application/json")], None);

    let mut proxy = McpProxy::init(Config::http(format!("http://{addr}"), None))
        .await
        .unwrap();

    let out = proxy
        .send_request(McpRequest {
            method: "tools/list".into(),
            params: tinyjson::JsonValue::Object(HashMap::new()),
        })
        .await
        .unwrap();

    assert_eq!(get_string_path(&out, &["result", "tools", "0", "name"]), "ping");
}

#[tokio::test]
async fn http_sse_parsed() {
    let sse = "event: message\r\ndata: {\"result\": {\"ok\": true}}\r\n\r\n".to_owned();
    let addr = spawn_http_server(sse, "HTTP/1.1 200 OK", &[("Content-Type", "text/event-stream")], None);

    let mut proxy = McpProxy::init(Config::http(format!("http://{addr}"), None))
        .await
        .unwrap();

    let out = proxy
        .send_request(McpRequest {
            method: "x".into(),
            params: tinyjson::JsonValue::Object(HashMap::new()),
        })
        .await
        .unwrap();

    assert_eq!(get_bool_path(&out, &["result", "ok"]), true);
}

#[tokio::test]
async fn http_empty_body_errors() {
    let addr = spawn_http_server(
        String::new(),
        "HTTP/1.1 200 OK",
        &[("Content-Type", "application/json")],
        None,
    );

    let mut proxy = McpProxy::init(Config::http(format!("http://{addr}"), None))
        .await
        .unwrap();

    let err = proxy
        .send_request(McpRequest {
            method: "x".into(),
            params: tinyjson::JsonValue::Object(HashMap::new()),
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

    let mut proxy = McpProxy::init(Config::http(format!("http://{addr}"), Some(Duration::from_millis(50))))
        .await
        .unwrap();

    let err = proxy
        .send_request(McpRequest {
            method: "x".into(),
            params: tinyjson::JsonValue::Object(HashMap::new()),
        })
        .await
        .unwrap_err();

    // reqwest/ureq/hyper-specific text varies; assert on our added context
    assert!(err.to_string().contains("failed to send request to MCP server"));
}

#[tokio::test]
async fn microsoft_learn() {
    let mut proxy = McpProxy::init(Config::http(
        "https://learn.microsoft.com/api/mcp",
        Some(Duration::from_secs(5)),
    ))
    .await
    .unwrap();

    let out = proxy
        .send_request(McpRequest {
            method: "tools/list".to_owned(),
            params: tinyjson::JsonValue::Object(HashMap::new()),
        })
        .await
        .unwrap();

    assert_eq!(
        get_string_path(&out, &["result", "tools", "0", "name"]),
        "microsoft_docs_search"
    );
}
