#![cfg(unix)]
#![allow(unused_crate_dependencies)]
#![allow(clippy::unwrap_used)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use mcp_proxy::{Config, McpProxy, McpRequest};
use tempfile::TempDir;

fn make_stdio_helper_script() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("stdio_echo.sh");
    let script = r#"#!/bin/sh
# read line-by-line; ignore input, always reply a single JSON-RPC envelope per line
while IFS= read -r line; do
  printf '%s\n' '{"jsonrpc":"2.0","result":{"ok":true}}'
done
"#;
    fs::write(&path, script).unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).unwrap();
    (dir, path)
}

#[tokio::test]
async fn stdio_round_trip_json_line() {
    let (_dir, path) = make_stdio_helper_script();

    let mut proxy = McpProxy::new(Config::spawn_process(path.to_string_lossy().into_owned()))
        .await
        .unwrap();

    let out = proxy
        .send_request(McpRequest {
            method: "tools/list".into(),
            params: Default::default(),
        })
        .await
        .unwrap();

    assert_eq!(out["result"]["ok"], true);
}
