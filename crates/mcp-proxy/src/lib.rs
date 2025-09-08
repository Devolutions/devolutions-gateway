use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Child;
use tracing::{debug, error, warn};

#[cfg(unix)]
use tokio::fs::OpenOptions;

#[cfg(unix)]
use tokio::net::UnixStream;

#[cfg(windows)]
use tokio::net::windows::named_pipe::ClientOptions;

use self::private::*;

#[derive(Serialize, Deserialize)]
pub struct McpRequest {
    pub method: String,
    pub params: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<i32>,
    pub method: String,
    pub params: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<serde_json::Value>,
}

impl JsonRpcResponse {
    pub fn to_string(&self) -> anyhow::Result<String> {
        serde_json::to_string(self).context("failed to serialize JSON-RPC response")
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    transport_mode: TransportMode,
}

#[derive(Debug, Clone)]
enum TransportMode {
    Http { url: String, timeout: Duration },
    SpawnProcess { command: String },
    NamedPipe { pipe_path: String },
}

const HTTP_DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

impl Config {
    pub fn http(url: impl Into<String>, timeout: Option<Duration>) -> Self {
        Self {
            transport_mode: TransportMode::Http {
                url: url.into(),
                timeout: timeout.unwrap_or(HTTP_DEFAULT_TIMEOUT),
            },
        }
    }

    pub fn spawn_process(command: String) -> Self {
        Self {
            transport_mode: TransportMode::SpawnProcess { command },
        }
    }

    pub fn named_pipe(pipe: String) -> Self {
        Self {
            transport_mode: TransportMode::NamedPipe { pipe_path: pipe },
        }
    }
}

pub struct McpProxy {
    transport: InnerTransport,
}

enum InnerTransport {
    Http { url: String, client: reqwest::Client },
    Process(ProcessMcpClient),
    NamedPipe(NamedPipeMcpClient),
}

impl McpProxy {
    pub async fn new(config: Config) -> Result<Self> {
        let transport = match config.transport_mode {
            TransportMode::Http { url, timeout } => InnerTransport::Http {
                url,
                client: reqwest::Client::builder()
                    .timeout(timeout)
                    .build()
                    .context("failed to create HTTP client")?,
            },
            TransportMode::SpawnProcess { command } => {
                InnerTransport::Process(ProcessMcpClient::spawn(&command).await?)
            }
            TransportMode::NamedPipe { pipe_path } => InnerTransport::NamedPipe(NamedPipeMcpClient { pipe_path }),
        };

        Ok(McpProxy { transport })
    }

    pub async fn send_request(&mut self, request: McpRequest) -> Result<serde_json::Value> {
        match &mut self.transport {
            InnerTransport::Http { url, client } => send_mcp_request_http(client, url, request).await,
            InnerTransport::Process(stdio_mcp_client) => send_mcp_request_stdio(stdio_mcp_client, request).await,
            InnerTransport::NamedPipe(named_pipe_mcp_client) => {
                send_mcp_request_named_pipe(named_pipe_mcp_client, request).await
            }
        }
    }

    pub async fn handle_jsonrpc_request_str(&mut self, line: &str) -> Result<Option<JsonRpcResponse>> {
        let req: JsonRpcRequest =
            serde_json::from_str(line).with_context(|| format!("failed to parse JSON-RPC request: \"{line}\""))?;
        self.handle_jsonrpc_request(req).await
    }

    pub async fn handle_jsonrpc_request(&mut self, request: JsonRpcRequest) -> Result<Option<JsonRpcResponse>> {
        match request.method.as_str() {
            "initialize" => {
                debug!("Handling initialize request");

                Ok(Some(JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: request.id,
                    result: Some(serde_json::json!({
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": {
                                "listChanged": true
                            },
                            "logging": {}
                        },
                        "serverInfo": {
                            "name": "mcp-proxy",
                            "version": "1.0.0"
                        }
                    })),
                    error: None,
                }))
            }
            "notifications/initialized" => {
                debug!("Received initialized notification");

                Ok(None)
            }
            "tools/list" => {
                match &self.transport {
                    InnerTransport::Http { url, .. } => {
                        debug!("Proxying tools/list request to {url}");
                    }
                    InnerTransport::Process(..) => {
                        debug!("Proxying tools/list request to spawned process's STDIO");
                    }
                    InnerTransport::NamedPipe(named_pipe_mcp_client, ..) => {
                        debug!(
                            "Proxying tools/list request to named pipe: {}",
                            named_pipe_mcp_client.pipe_path
                        );
                    }
                }

                let mcp_req = McpRequest {
                    method: "tools/list".to_owned(),
                    params: serde_json::Value::Object(serde_json::Map::new()),
                };

                match self.send_request(mcp_req).await {
                    Ok(result) => {
                        let result = unwrap_json_rpc_inner_result(result);

                        Ok(Some(JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: request.id,
                            result: Some(result),
                            error: None,
                        }))
                    }
                    Err(e) => {
                        error!("tools/list request failed: {e}");

                        Ok(Some(JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: request.id,
                            result: None,
                            error: Some(serde_json::json!({
                                "code": -32603,
                                "message": format!("Internal error: {e}")
                            })),
                        }))
                    }
                }
            }
            "tools/call" => {
                match &self.transport {
                    InnerTransport::Http { url, .. } => {
                        debug!("Proxying tools/call request to {url}");
                    }
                    InnerTransport::Process(..) => {
                        debug!("Proxying tools/call request to spawned process's STDIO");
                    }
                    InnerTransport::NamedPipe(named_pipe_mcp_client, ..) => {
                        debug!(
                            "Proxying tools/call request to named pipe: {}",
                            named_pipe_mcp_client.pipe_path
                        );
                    }
                }

                let mcp_req = McpRequest {
                    method: "tools/call".to_string(),
                    params: request.params.unwrap_or_default(),
                };

                match self.send_request(mcp_req).await {
                    Ok(result) => {
                        let result = unwrap_json_rpc_inner_result(result);

                        Ok(Some(JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: request.id,
                            result: Some(result),
                            error: None,
                        }))
                    }
                    Err(e) => {
                        error!("tools/call request failed: {e}");

                        Ok(Some(JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: request.id,
                            result: None,
                            error: Some(serde_json::json!({
                                "code": -32603,
                                "message": format!("Internal error: {e}")
                            })),
                        }))
                    }
                }
            }
            _ => {
                warn!("[WARN] Unknown method: {}", request.method);

                Ok(Some(JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: request.id,
                    result: None,
                    error: Some(serde_json::json!({
                        "code": -32601,
                        "message": format!("Method not found: {}", &request.method)
                    })),
                }))
            }
        }
    }
}

#[doc(hidden)]
pub mod private {
    use serde_json::Value;

    use super::*;

    pub struct ProcessMcpClient {
        stdin: tokio::process::ChildStdin,
        stdout: BufReader<tokio::process::ChildStdout>,

        // We use kill_on_drop, so we need to keep the Child alive as long as necessary.
        _process: Child,
    }

    impl ProcessMcpClient {
        pub async fn spawn(command: &str) -> Result<Self> {
            use tokio::process::Command;

            #[cfg(target_os = "windows")]
            let mut cmd = Command::new("cmd");
            #[cfg(target_os = "windows")]
            cmd.arg("/C");

            #[cfg(not(target_os = "windows"))]
            let mut cmd = Command::new("sh");
            #[cfg(not(target_os = "windows"))]
            cmd.arg("-c");

            cmd.arg(command)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .kill_on_drop(true);

            let mut process = cmd.spawn().context("failed to spawn MCP server process")?;

            let stdin = process.stdin.take().context("failed to get stdin")?;
            let stdout = process.stdout.take().context("failed to get stdout")?;
            let stdout = BufReader::new(stdout);

            Ok(ProcessMcpClient {
                _process: process,
                stdin,
                stdout,
            })
        }

        pub async fn send_request(&mut self, request: &str) -> Result<String> {
            self.stdin.write_all(request.as_bytes()).await?;
            self.stdin.write_all(b"\n").await?;
            self.stdin.flush().await?;

            let mut response = String::new();
            self.stdout.read_line(&mut response).await?;

            Ok(response.trim().to_string())
        }
    }

    pub struct NamedPipeMcpClient {
        pub pipe_path: String,
    }

    impl NamedPipeMcpClient {
        pub async fn send_request(&self, request: &str) -> Result<String> {
            #[cfg(unix)]
            {
                if let Ok(mut stream) = UnixStream::connect(&self.pipe_path).await {
                    stream.write_all(request.as_bytes()).await?;
                    stream.write_all(b"\n").await?;

                    let mut reader = BufReader::new(stream);
                    let mut response = String::new();
                    reader.read_line(&mut response).await?;

                    return Ok(response.trim().to_string());
                }

                let mut write_file = OpenOptions::new()
                    .write(true)
                    .open(&self.pipe_path)
                    .await
                    .with_context(|| format!("failed to open named pipe for writing: {}", self.pipe_path))?;

                write_file.write_all(request.as_bytes()).await?;
                write_file.write_all(b"\n").await?;
                write_file.flush().await?;

                let read_file = OpenOptions::new()
                    .read(true)
                    .open(&self.pipe_path)
                    .await
                    .with_context(|| format!("failed to open named pipe for reading: {}", self.pipe_path))?;

                let mut reader = BufReader::new(read_file);
                let mut response = String::new();
                reader.read_line(&mut response).await?;

                Ok(response.trim().to_string())
            }

            #[cfg(windows)]
            {
                let pipe_name = if self.pipe_path.starts_with(r"\\.\pipe\") {
                    self.pipe_path.clone()
                } else {
                    format!(r"\\.\pipe\{}", self.pipe_path)
                };

                let mut client = ClientOptions::new()
                    .open(&pipe_name)
                    .with_context(|| format!("failed to connect to Windows named pipe: {pipe_name}"))?;

                client.write_all(request.as_bytes()).await?;
                client.write_all(b"\n").await?;

                let mut reader = BufReader::new(client);
                let mut response = String::new();
                reader.read_line(&mut response).await?;

                Ok(response.trim().to_string())
            }

            #[cfg(not(any(unix, windows)))]
            {
                Err(anyhow::anyhow!(
                    "named pipe transport is not supported on this platform"
                ))
            }
        }
    }

    pub async fn send_mcp_request_http(
        client: &reqwest::Client,
        base_url: &str,
        req: McpRequest,
    ) -> Result<serde_json::Value> {
        let url = base_url.trim_end_matches('/');

        let rpc_request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(1),
            method: req.method.clone(),
            params: Some(req.params.clone()),
        };

        let res = client
            .post(url)
            .json(&rpc_request)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .send()
            .await
            .context("failed to send request to MCP server")?;

        let status = res.status();
        let body_text = res.text().await.context("failed to read response body")?;

        if body_text.trim().is_empty() {
            return Err(anyhow::anyhow!("empty response body from MCP server"));
        }

        let mut json_response: serde_json::Value = if body_text.starts_with("event:") || body_text.contains("data:") {
            let Some(json_data) = extract_sse_json_line(&body_text) else {
                return Err(anyhow::anyhow!("no data found in SSE response"));
            };

            serde_json::from_str(json_data)
                .with_context(|| format!("failed to parse SSE JSON data; status: {status}, data: {json_data}"))?
        } else {
            serde_json::from_str(&body_text)
                .with_context(|| format!("failed to parse JSON response; status: {status}, body: {body_text}"))?
        };

        if !status.is_success() {
            debug!("MCP server returned error: {status}");
            debug!("Response body: {body_text}");
        }

        // Apply custom text decoding.
        decode_content_texts(&mut json_response);

        Ok(json_response)
    }

    pub async fn send_mcp_request_stdio(
        stdio_client: &mut ProcessMcpClient,
        req: McpRequest,
    ) -> Result<serde_json::Value> {
        let rpc_request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(1),
            method: req.method.clone(),
            params: Some(req.params.clone()),
        };

        let request_json = serde_json::to_string(&rpc_request)?;
        let response_json = stdio_client.send_request(&request_json).await?;

        let json_response: serde_json::Value = serde_json::from_str(&response_json)
            .with_context(|| format!("failed to parse JSON response: {response_json}"))?;

        Ok(json_response)
    }

    pub async fn send_mcp_request_named_pipe(
        pipe_client: &NamedPipeMcpClient,
        req: McpRequest,
    ) -> Result<serde_json::Value> {
        let rpc_request = JsonRpcRequest {
            jsonrpc: "2.0".to_owned(),
            id: Some(1),
            method: req.method.clone(),
            params: Some(req.params.clone()),
        };

        let request_json = serde_json::to_string(&rpc_request)?;
        let response_json = pipe_client.send_request(&request_json).await?;

        let json_response: serde_json::Value = serde_json::from_str(&response_json)
            .with_context(|| format!("failed to parse JSON response: {response_json}"))?;

        Ok(json_response)
    }

    /// Extract the first `data: ...` JSON line from an SSE body (if present).
    pub fn extract_sse_json_line(body: &str) -> Option<&str> {
        body.lines().find_map(|l| l.strip_prefix("data: ").map(|s| s.trim()))
    }

    /// Perform the library's custom unescaping for result.content[].text.
    pub fn decode_content_texts(v: &mut Value) {
        if let Some(result) = v.get_mut("result") {
            if let Some(content) = result.get_mut("content") {
                if let Some(arr) = content.as_array_mut() {
                    for item in arr.iter_mut() {
                        if let Some(text) = item.get_mut("text") {
                            if let Some(s) = text.as_str() {
                                let decoded = s
                                    .replace("\\u0027", "'")
                                    .replace("\\u0060", "`")
                                    .replace("\\u0022", "\"")
                                    .replace("\\u003C", "<")
                                    .replace("\\u003E", ">")
                                    .replace("\\n", "\n");
                                *text = Value::String(decoded);
                            }
                        }
                    }
                }
            }
        }
    }

    /// If the value is a JSON-RPC envelope with a top-level "result", return that.
    pub fn unwrap_json_rpc_inner_result(mut v: Value) -> Value {
        match v.get_mut("result") {
            Some(result) => result.take(),
            None => v,
        }
    }
}
