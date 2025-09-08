#![allow(unused_crate_dependencies)]
#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::fs;

use mcp_proxy::{Config, McpProxy, McpRequest};
use tempfile::TempDir;

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

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn make_stdio_helper_script() -> (TempDir, String) {
    let dir = TempDir::new().unwrap();

    #[cfg(unix)]
    {
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
        fs::write(&path, script).unwrap();
        (dir, path.to_string_lossy().into_owned())
    }
}

#[tokio::test]
async fn stdio_round_trip_json_line() {
    let (_dir, command) = make_stdio_helper_script();

    let mut proxy = McpProxy::init(Config::spawn_process(command)).await.unwrap();

    let out = proxy
        .send_request(McpRequest {
            method: "tools/list".into(),
            params: tinyjson::JsonValue::Object(HashMap::new()),
        })
        .await
        .unwrap();

    assert_eq!(get_bool_path(&out, &["result", "ok"]), true);
}
