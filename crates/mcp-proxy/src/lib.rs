use core::fmt;
use std::fmt::Debug;
use std::process::Stdio;
use std::time::Duration;

use anyhow::Context as _;
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Child;
use tracing::{debug, error, trace, warn};

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

/// Wraps a normalized, raw MCP message
///
/// Display implementation write the message with leading and trailing whitespace removed.
/// Use `as_raw()` and `as_newline_terminated_raw` accordingly whether you need the newline for your transport or not.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Message {
    raw: String,
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        fmt::Display::fmt(self.raw.trim(), f)
    }
}

impl Message {
    /// The raw message is also normalized.
    pub fn normalize(mut raw_message: String) -> Self {
        // Ensure there is exactly one, single newline (\n) character at the end.
        while raw_message.ends_with('\n') || raw_message.ends_with('\r') {
            raw_message.pop();
        }
        raw_message.reserve_exact(1);
        raw_message.push('\n');

        Self { raw: raw_message }
    }

    pub fn as_newline_terminated_raw(&self) -> &str {
        &self.raw
    }

    pub fn as_raw(&self) -> &str {
        &self.raw[..self.raw.len() - 1]
    }
}

pub struct McpProxy {
    transport: InnerTransport,
}

/// Fatal error indicating the MCP proxy can no longer forward requests
#[derive(Debug)]
pub struct FatalError {
    /// Optional error message to send back to the client.
    ///
    /// `None` if the original request was a notification.
    pub response: Option<Message>,
}

#[allow(
    clippy::large_enum_variant,
    reason = "on Windows, ProcessMcpClient is large; however that’s fine, it’s not used in a hot loop"
)]
enum InnerTransport {
    Http { url: String, agent: ureq::Agent },
    Process(ProcessMcpClient),
    NamedPipe(NamedPipeMcpClient),
}

impl McpProxy {
    pub async fn init(config: Config) -> anyhow::Result<Self> {
        let transport = match config.transport_mode {
            TransportMode::Http { url, timeout } => {
                let agent = ureq::AgentBuilder::new().timeout(timeout).build();
                InnerTransport::Http { url, agent }
            }
            TransportMode::SpawnProcess { command } => {
                InnerTransport::Process(ProcessMcpClient::spawn(&command).await?)
            }
            TransportMode::NamedPipe { pipe_path } => {
                InnerTransport::NamedPipe(NamedPipeMcpClient::connect(&pipe_path).await?)
            }
        };

        Ok(McpProxy { transport })
    }

    pub async fn forward_request(&mut self, request: &str) -> Result<Option<Message>, FatalError> {
        const FORWARD_FAILURE_CODE: f64 = -32099.0;

        trace!(request, "Request from client");

        let request = request.trim();

        if request.is_empty() {
            debug!("Empty request from client");
            return Ok(None);
        }

        let request_id = match JsonRpcRequest::parse(request) {
            Ok(request) => {
                if let Some(id) = request.id {
                    debug!(
                        jsonrpc = request.jsonrpc,
                        method = request.method,
                        id,
                        "Request from client"
                    );
                } else {
                    debug!(
                        jsonrpc = request.jsonrpc,
                        method = request.method,
                        "Notification from client"
                    );
                }

                request.id
            }
            Err(e) => {
                let id = extract_id_best_effort(request);

                if let Some(id) = id {
                    warn!(error = format!("{e:#}"), id, "Malformed JSON-RPC request from client");
                } else {
                    warn!(error = format!("{e:#}"), "Malformed JSON-RPC request from client");
                }

                id
            }
        };

        let is_notification = request_id.is_none();

        let ret = match &mut self.transport {
            InnerTransport::Http { url, agent } => {
                match send_mcp_request_http(url, agent, request, is_notification).await {
                    Ok(response) => Ok(response.inspect(|response| trace!(%response, "Response from server"))),
                    Err(e) => {
                        error!(error = format!("{e:#}"), "Couldn't forward request");

                        // Because it’s not connection-based, HTTP errors are (currently) never fatal.
                        if let Some(id) = request_id {
                            let json_rpc_error_response = format!(
                                r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":{FORWARD_FAILURE_CODE},"message":"Forward failure: {e:#}"}}}}"#
                            );
                            Ok(Some(Message::normalize(json_rpc_error_response)))
                        } else {
                            Ok(None)
                        }
                    }
                }
            }
            InnerTransport::Process(stdio_mcp_client) => handle_io_result(
                stdio_mcp_client.send_request(request, is_notification).await,
                request_id,
            ),
            InnerTransport::NamedPipe(named_pipe_mcp_client) => handle_io_result(
                named_pipe_mcp_client.send_request(request, is_notification).await,
                request_id,
            ),
        };

        return ret;

        fn extract_id_best_effort(request_str: &str) -> Option<i32> {
            let idx = request_str.find("\"id\"")?;

            let mut rest = request_str[idx + "\"id\"".len()..].chars();

            loop {
                if rest.next()? == ':' {
                    break;
                }
            }

            let mut acc = String::new();

            loop {
                match rest.next() {
                    Some(',') => break,
                    Some(ch) => acc.push(ch),
                    None => break,
                }
            }

            acc.parse().ok()
        }

        fn handle_io_result(
            result: std::io::Result<Option<Message>>,
            request_id: Option<i32>,
        ) -> Result<Option<Message>, FatalError> {
            match result {
                Ok(response) => Ok(response.inspect(|response| trace!(%response, "Response from server"))),
                Err(io_error) => {
                    // Classify the error.
                    if is_fatal_io_error(&io_error) {
                        // Fatal error - connection is broken.
                        error!(error = %io_error, "MCP server connection broken");

                        let response = if let Some(id) = request_id {
                            let json_rpc_error_response = format!(
                                r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":{FORWARD_FAILURE_CODE},"message":"MCP server connection broken: {io_error}"}}}}"#
                            );
                            Some(Message::normalize(json_rpc_error_response))
                        } else {
                            None
                        };

                        Err(FatalError { response })
                    } else {
                        // Recoverable error - return error response.
                        error!(error = %io_error, "Couldn't forward request");

                        if let Some(id) = request_id {
                            let json_rpc_error_response = format!(
                                r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":{FORWARD_FAILURE_CODE},"message":"Forward failure: {io_error}"}}}}"#
                            );
                            Ok(Some(Message::normalize(json_rpc_error_response)))
                        } else {
                            Ok(None)
                        }
                    }
                }
            }
        }
    }
}

struct JsonRpcRequest {
    jsonrpc: String,
    id: Option<i32>,
    method: String,
}

impl JsonRpcRequest {
    fn parse(json_str: &str) -> anyhow::Result<Self> {
        let json: tinyjson::JsonValue = json_str.parse().context("failed to parse JSON")?;

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

        Ok(JsonRpcRequest { jsonrpc, id, method })
    }
}

struct ProcessMcpClient {
    stdin: tokio::process::ChildStdin,
    stdout: BufReader<tokio::process::ChildStdout>,

    // We use kill_on_drop, so we need to keep the Child alive as long as necessary.
    _process: Child,
}

impl ProcessMcpClient {
    async fn spawn(command: &str) -> anyhow::Result<Self> {
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

    async fn send_request(&mut self, request: &str, is_notification: bool) -> std::io::Result<Option<Message>> {
        self.stdin.write_all(request.as_bytes()).await?;
        self.stdin.write_all(b"\n").await?;
        self.stdin.flush().await?;

        if is_notification {
            Ok(None)
        } else {
            let mut response = String::new();
            self.stdout.read_line(&mut response).await?;
            Ok(Some(Message::normalize(response)))
        }
    }
}

struct NamedPipeMcpClient {
    #[cfg(unix)]
    stream: BufReader<tokio::net::UnixStream>,
    #[cfg(windows)]
    stream: BufReader<tokio::net::windows::named_pipe::NamedPipeClient>,
}

impl NamedPipeMcpClient {
    async fn connect(pipe_path: &str) -> anyhow::Result<Self> {
        #[cfg(unix)]
        {
            let stream = tokio::net::UnixStream::connect(pipe_path)
                .await
                .with_context(|| format!("open Unix socket: {pipe_path}"))?;
            Ok(Self {
                stream: BufReader::new(stream),
            })
        }

        #[cfg(windows)]
        {
            let pipe_name = if pipe_path.starts_with(r"\\.\pipe\") {
                pipe_path.to_owned()
            } else {
                format!(r"\\.\pipe\{}", pipe_path)
            };

            let stream = tokio::net::windows::named_pipe::ClientOptions::new()
                .open(&pipe_name)
                .with_context(|| format!("connect to Windows named pipe: {pipe_name}"))?;

            Ok(Self {
                stream: BufReader::new(stream),
            })
        }

        #[cfg(not(any(unix, windows)))]
        {
            anyhow::bail!("named pipe transport is not supported on this platform")
        }
    }

    async fn send_request(&mut self, request: &str, is_notification: bool) -> std::io::Result<Option<Message>> {
        #[cfg(any(unix, windows))]
        {
            self.stream.write_all(request.as_bytes()).await?;
            self.stream.write_all(b"\n").await?;

            if is_notification {
                Ok(None)
            } else {
                let mut response = String::new();
                self.stream.read_line(&mut response).await?;
                Ok(Some(Message::normalize(response)))
            }
        }

        #[cfg(not(any(unix, windows)))]
        {
            Err(std::io::Error::other(
                "named pipe transport is not supported on this platform",
            ))
        }
    }
}

async fn send_mcp_request_http(
    base_url: &str,
    agent: &ureq::Agent,
    request: &str,
    is_notification: bool,
) -> anyhow::Result<Option<Message>> {
    let url = base_url.trim_end_matches('/').to_owned();

    let agent = agent.clone();
    let request = request.to_owned();

    let body_text = tokio::task::spawn_blocking(move || -> anyhow::Result<String> {
        let response = agent
            .post(&url)
            .set("Content-Type", "application/json")
            .set("Accept", "application/json, text/event-stream")
            .send_string(&request)
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

    if is_notification {
        return Ok(None);
    }

    if body_text.trim().is_empty() {
        anyhow::bail!("empty response body from MCP server");
    }

    let json_response = if body_text.starts_with("event:") || body_text.contains("data:") {
        let Some(json_data) = extract_sse_json_line(&body_text) else {
            anyhow::bail!("no data found in SSE response");
        };

        json_data.to_owned()
    } else {
        body_text
    };

    return Ok(Some(Message::normalize(json_response)));

    fn success_status_code(status: u16) -> bool {
        (200..300).contains(&status)
    }
}

/// Extract the first `data: ...` JSON line from an SSE body (if present).
fn extract_sse_json_line(body: &str) -> Option<&str> {
    body.lines().find_map(|l| l.strip_prefix("data: ").map(|s| s.trim()))
}

/// Check if an I/O error is fatal (connection broken)
///
/// For process stdio and named pipe transports, these errors indicate the MCP server
/// is dead or the connection is permanently broken:
/// - `BrokenPipe`: The pipe was closed on the other end (server died or closed connection)
/// - `ConnectionReset`: The connection was forcibly closed by the peer
/// - `UnexpectedEof`: Reached end-of-file when more data was expected (server terminated)
///
/// Other I/O errors (like timeouts, permission errors, etc.) are considered recoverable
/// because they may be transient or fixable without restarting the proxy.
fn is_fatal_io_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof
    )
}
