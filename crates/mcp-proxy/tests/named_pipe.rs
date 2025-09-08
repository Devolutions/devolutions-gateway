#![cfg(unix)]
#![allow(unused_crate_dependencies)]
#![allow(clippy::unwrap_used)]

use mcp_proxy::{Config, McpProxy, McpRequest};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

#[tokio::test]
async fn uds_named_pipe_round_trip() {
    // Create a UDS path and spawn a tiny server that speaks one-line JSON.
    let dir = TempDir::new().unwrap();
    let sock_path = dir.path().join("mcp.sock");

    let listener = UnixListener::bind(&sock_path).unwrap();

    let server = tokio::spawn(async move {
        if let Ok((stream, _addr)) = listener.accept().await {
            // Read one line request.
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            let _ = reader.read_line(&mut line).await;

            // Write one line response.
            let mut stream = reader.into_inner();
            let resp = r#"{"jsonrpc":"2.0","result":{"ok":true}}"#;
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.write_all(b"\n").await;
            let _ = stream.flush().await;
        }
    });

    // Build the proxy and send a request.
    let mut proxy = McpProxy::new(Config::named_pipe(sock_path.to_string_lossy().into_owned()))
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

    server.await.unwrap();
}
