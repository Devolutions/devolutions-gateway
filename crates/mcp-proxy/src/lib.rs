use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Child;
use tracing::{debug, error, warn};

#[cfg(unix)]
use tokio::fs::OpenOptions;

#[cfg(unix)]
use tokio::net::UnixStream;

#[cfg(windows)]
use tokio::net::windows::named_pipe::ClientOptions;

use self::internal::*;

pub struct McpRequest {
    pub method: String,
    pub params: tinyjson::JsonValue,
}

pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<i32>,
    pub method: String,
    pub params: Option<tinyjson::JsonValue>,
}

impl JsonRpcRequest {
    pub fn parse(json_str: &str) -> Result<Self> {
        let json: tinyjson::JsonValue = json_str.parse().context("failed to parse JSON")?;
        parse_jsonrpc_request(json)
    }
}

pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Option<i32>,
    pub result: Option<tinyjson::JsonValue>,
    pub error: Option<tinyjson::JsonValue>,
}

impl JsonRpcResponse {
    pub fn to_string(&self) -> anyhow::Result<String> {
        let mut obj = HashMap::new();
        obj.insert("jsonrpc".to_owned(), tinyjson::JsonValue::String(self.jsonrpc.clone()));

        if let Some(id) = self.id {
            obj.insert("id".to_owned(), tinyjson::JsonValue::Number(id as f64));
        } else {
            obj.insert("id".to_owned(), tinyjson::JsonValue::Null);
        }

        if let Some(result) = &self.result {
            obj.insert("result".to_owned(), result.clone());
        }

        if let Some(error) = &self.error {
            obj.insert("error".to_owned(), error.clone());
        }

        let json_obj = tinyjson::JsonValue::Object(obj);
        Ok(json_obj.stringify().unwrap())
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
    Http { url: String, agent: ureq::Agent },
    Process(ProcessMcpClient),
    NamedPipe(NamedPipeMcpClient),
}

impl McpProxy {
    pub async fn init(config: Config) -> Result<Self> {
        let transport = match config.transport_mode {
            TransportMode::Http { url, timeout } => {
                let agent = ureq::AgentBuilder::new().timeout(timeout).build();
                InnerTransport::Http { url, agent }
            }
            TransportMode::SpawnProcess { command } => {
                InnerTransport::Process(ProcessMcpClient::spawn(&command).await?)
            }
            TransportMode::NamedPipe { pipe_path } => InnerTransport::NamedPipe(NamedPipeMcpClient { pipe_path }),
        };

        Ok(McpProxy { transport })
    }

    pub async fn send_request(&mut self, request: McpRequest) -> Result<tinyjson::JsonValue> {
        match &mut self.transport {
            InnerTransport::Http { url, agent } => send_mcp_request_http(url, agent, request).await,
            InnerTransport::Process(stdio_mcp_client) => send_mcp_request_stdio(stdio_mcp_client, request).await,
            InnerTransport::NamedPipe(named_pipe_mcp_client) => {
                send_mcp_request_named_pipe(named_pipe_mcp_client, request).await
            }
        }
    }

    pub async fn handle_jsonrpc_request_str(&mut self, line: &str) -> Result<Option<JsonRpcResponse>> {
        let req =
            JsonRpcRequest::parse(line).with_context(|| format!("invalid JSON-RPC request format: \"{line}\""))?;

        self.handle_jsonrpc_request(req).await
    }

    pub async fn handle_jsonrpc_request(&mut self, request: JsonRpcRequest) -> Result<Option<JsonRpcResponse>> {
        match request.method.as_str() {
            "initialize" => {
                debug!("Handling initialize request");

                let capabilities = create_json_object(vec![
                    (
                        "tools",
                        create_json_object(vec![("listChanged", tinyjson::JsonValue::Boolean(true))]),
                    ),
                    ("logging", create_json_object(vec![])),
                ]);

                let server_info = create_json_object(vec![
                    ("name", tinyjson::JsonValue::String("mcp-proxy".to_owned())),
                    ("version", tinyjson::JsonValue::String("1.0.0".to_owned())),
                ]);

                let result = create_json_object(vec![
                    ("protocolVersion", tinyjson::JsonValue::String("2024-11-05".to_owned())),
                    ("capabilities", capabilities),
                    ("serverInfo", server_info),
                ]);

                Ok(Some(JsonRpcResponse {
                    jsonrpc: "2.0".to_owned(),
                    id: request.id,
                    result: Some(result),
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
                    params: create_json_object(vec![]),
                };

                match self.send_request(mcp_req).await {
                    Ok(result) => {
                        let result = unwrap_json_rpc_inner_result(result);

                        Ok(Some(JsonRpcResponse {
                            jsonrpc: "2.0".to_owned(),
                            id: request.id,
                            result: Some(result),
                            error: None,
                        }))
                    }
                    Err(e) => {
                        error!("tools/list request failed: {e}");

                        Ok(Some(JsonRpcResponse {
                            jsonrpc: "2.0".to_owned(),
                            id: request.id,
                            result: None,
                            error: Some(create_json_object(vec![
                                ("code", tinyjson::JsonValue::Number(-32603.0)),
                                ("message", tinyjson::JsonValue::String(format!("Internal error: {e}"))),
                            ])),
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
                    method: "tools/call".to_owned(),
                    params: request.params.unwrap_or_else(|| create_json_object(vec![])),
                };

                match self.send_request(mcp_req).await {
                    Ok(result) => {
                        let result = unwrap_json_rpc_inner_result(result);

                        Ok(Some(JsonRpcResponse {
                            jsonrpc: "2.0".to_owned(),
                            id: request.id,
                            result: Some(result),
                            error: None,
                        }))
                    }
                    Err(e) => {
                        error!("tools/call request failed: {e}");

                        Ok(Some(JsonRpcResponse {
                            jsonrpc: "2.0".to_owned(),
                            id: request.id,
                            result: None,
                            error: Some(create_json_object(vec![
                                ("code", tinyjson::JsonValue::Number(-32603.0)),
                                ("message", tinyjson::JsonValue::String(format!("Internal error: {e}"))),
                            ])),
                        }))
                    }
                }
            }
            _ => {
                warn!("Unknown method: {}", request.method);

                Ok(Some(JsonRpcResponse {
                    jsonrpc: "2.0".to_owned(),
                    id: request.id,
                    result: None,
                    error: Some(create_json_object(vec![
                        ("code", tinyjson::JsonValue::Number(-32601.0)),
                        (
                            "message",
                            tinyjson::JsonValue::String(format!("Method not found: {}", &request.method)),
                        ),
                    ])),
                }))
            }
        }
    }
}

fn parse_jsonrpc_request(json: tinyjson::JsonValue) -> Result<JsonRpcRequest> {
    let obj = json
        .get::<HashMap<String, tinyjson::JsonValue>>()
        .ok_or_else(|| anyhow::anyhow!("JSON-RPC request must be an object"))?;

    let jsonrpc = obj
        .get("jsonrpc")
        .and_then(|v| v.get::<String>())
        .cloned()
        .unwrap_or_else(|| "2.0".to_owned());

    let id = obj.get("id").and_then(|v| v.get::<f64>()).map(|f| *f as i32);

    let method = obj
        .get("method")
        .and_then(|v| v.get::<String>())
        .ok_or_else(|| anyhow::anyhow!("JSON-RPC request missing 'method' field"))?
        .clone();

    let params = obj.get("params").cloned();

    Ok(JsonRpcRequest {
        jsonrpc,
        id,
        method,
        params,
    })
}

fn create_json_object(pairs: Vec<(&str, tinyjson::JsonValue)>) -> tinyjson::JsonValue {
    let mut obj = HashMap::new();
    for (key, value) in pairs {
        obj.insert(key.to_owned(), value);
    }
    tinyjson::JsonValue::Object(obj)
}

fn serialize_jsonrpc_request(req: &JsonRpcRequest) -> Result<String> {
    let mut pairs = vec![
        ("jsonrpc", tinyjson::JsonValue::String(req.jsonrpc.clone())),
        ("method", tinyjson::JsonValue::String(req.method.clone())),
    ];

    if let Some(id) = req.id {
        pairs.push(("id", tinyjson::JsonValue::Number(id as f64)));
    }

    if let Some(params) = &req.params {
        pairs.push(("params", params.clone()));
    }

    let json_obj = create_json_object(pairs);
    Ok(json_obj.stringify().unwrap())
}

fn success_status_code(status: u16) -> bool {
    (200..300).contains(&status)
}

#[doc(hidden)]
pub mod internal {
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

            Ok(response.trim().to_owned())
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

                    return Ok(response.trim().to_owned());
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

                Ok(response.trim().to_owned())
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

                Ok(response.trim().to_owned())
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
        base_url: &str,
        agent: &ureq::Agent,
        req: McpRequest,
    ) -> Result<tinyjson::JsonValue> {
        let url = base_url.trim_end_matches('/');

        let rpc_request = JsonRpcRequest {
            jsonrpc: "2.0".to_owned(),
            id: Some(1),
            method: req.method.clone(),
            params: Some(req.params.clone()),
        };

        let request_json = serialize_jsonrpc_request(&rpc_request)?;
        let url_owned = url.to_string();
        let agent_clone = agent.clone();

        let body_text = tokio::task::spawn_blocking(move || -> Result<String> {
            let response = agent_clone
                .post(&url_owned)
                .set("Content-Type", "application/json")
                .set("Accept", "application/json, text/event-stream")
                .send_string(&request_json)
                .context("failed to send request to MCP server")?;

            let status_code = response.status();
            let body = response.into_string().context("failed to read response body")?;

            if !success_status_code(status_code) {
                debug!("MCP server returned error: {status_code}");
                debug!("Response body: {body}");
            }

            Ok(body)
        })
        .await
        .context("HTTP request task failed")??;

        if body_text.trim().is_empty() {
            return Err(anyhow::anyhow!("empty response body from MCP server"));
        }

        let mut json_response: tinyjson::JsonValue = if body_text.starts_with("event:") || body_text.contains("data:") {
            let Some(json_data) = extract_sse_json_line(&body_text) else {
                return Err(anyhow::anyhow!("no data found in SSE response"));
            };

            json_data
                .parse()
                .with_context(|| format!("failed to parse SSE JSON data; data: {json_data}"))?
        } else {
            body_text
                .parse()
                .with_context(|| format!("failed to parse JSON response; body: {body_text}"))?
        };

        // Apply custom text decoding.
        decode_content_texts(&mut json_response);

        Ok(json_response)
    }

    pub async fn send_mcp_request_stdio(
        stdio_client: &mut ProcessMcpClient,
        req: McpRequest,
    ) -> Result<tinyjson::JsonValue> {
        let rpc_request = JsonRpcRequest {
            jsonrpc: "2.0".to_owned(),
            id: Some(1),
            method: req.method.clone(),
            params: Some(req.params.clone()),
        };

        let request_json = serialize_jsonrpc_request(&rpc_request)?;
        let response_json = stdio_client.send_request(&request_json).await?;

        let json_response: tinyjson::JsonValue = response_json
            .parse()
            .with_context(|| format!("failed to parse JSON response: {response_json}"))?;

        Ok(json_response)
    }

    pub async fn send_mcp_request_named_pipe(
        pipe_client: &NamedPipeMcpClient,
        req: McpRequest,
    ) -> Result<tinyjson::JsonValue> {
        let rpc_request = JsonRpcRequest {
            jsonrpc: "2.0".to_owned(),
            id: Some(1),
            method: req.method.clone(),
            params: Some(req.params.clone()),
        };

        let request_json = serialize_jsonrpc_request(&rpc_request)?;
        let response_json = pipe_client.send_request(&request_json).await?;

        let json_response: tinyjson::JsonValue = response_json
            .parse()
            .with_context(|| format!("failed to parse JSON response: {response_json}"))?;

        Ok(json_response)
    }

    /// Extract the first `data: ...` JSON line from an SSE body (if present).
    pub fn extract_sse_json_line(body: &str) -> Option<&str> {
        body.lines().find_map(|l| l.strip_prefix("data: ").map(|s| s.trim()))
    }

    /// Perform the library's custom unescaping for result.content[].text.
    pub fn decode_content_texts(v: &mut tinyjson::JsonValue) {
        if let Some(result_obj) = v.get_mut::<HashMap<String, tinyjson::JsonValue>>() {
            if let Some(result) = result_obj.get_mut("result") {
                if let Some(result_inner) = result.get_mut::<HashMap<String, tinyjson::JsonValue>>() {
                    if let Some(content) = result_inner.get_mut("content") {
                        if let Some(arr) = content.get_mut::<Vec<tinyjson::JsonValue>>() {
                            for item in arr.iter_mut() {
                                if let Some(item_obj) = item.get_mut::<HashMap<String, tinyjson::JsonValue>>() {
                                    if let Some(text) = item_obj.get_mut("text") {
                                        if let Some(s) = text.get::<String>() {
                                            let decoded = s
                                                .replace("\\u0027", "'")
                                                .replace("\\u0060", "`")
                                                .replace("\\u0022", "\"")
                                                .replace("\\u003C", "<")
                                                .replace("\\u003E", ">")
                                                .replace("\\n", "\n");
                                            *text = tinyjson::JsonValue::String(decoded);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// If the value is a JSON-RPC envelope with a top-level "result", return that.
    pub fn unwrap_json_rpc_inner_result(mut v: tinyjson::JsonValue) -> tinyjson::JsonValue {
        if let Some(obj) = v.get_mut::<HashMap<String, tinyjson::JsonValue>>() {
            if let Some(result) = obj.remove("result") {
                return result;
            }
        }
        v
    }
}
