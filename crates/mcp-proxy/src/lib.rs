//! MCP (Model Context Protocol) proxy library.
//!
//! This library provides a proxy for forwarding MCP messages between a client and server,
//! supporting multiple outgoing transport modes: HTTP, process stdio, and named pipes.
//!
//! ## Cancel Safety and Concurrent Reads
//!
//! The `read_message()` method is designed to be **cancel-safe** for use in `tokio::select!`
//! branches. This is achieved through internal buffering where each transport maintains its
//! own read buffer that persists across calls.
//!
//! ### Why Cancel Safety Matters
//!
//! When using `tokio::select!`, if one branch completes, the other branches are cancelled.
//! We need to be careful about operations like `BufReader::read_line()` (NOT cancel-safe) because they buffer data
//! internally - if cancelled mid-read, that buffered data is lost.
//!
//! ### Implementated Approach: Internal Buffering
//!
//! We use manual line-framing with persistent buffers:
//! - Each transport has a `read_buffer: Vec<u8>` field
//! - Use `AsyncRead::read()` (which IS cancel-safe) to read chunks
//! - Accumulate data in the buffer until we find a newline
//! - If cancelled, the buffer retains all data for the next call
//!
//! Example:
//! ```rust,ignore
//! async fn read_message(&mut self) -> Result<Message> {
//!     loop {
//!         // Check for complete line in buffer
//!         if let Some(pos) = self.read_buffer.iter().position(|&b| b == b'\n') {
//!             let line = extract_line(&mut self.read_buffer, pos);
//!             return Ok(Message::normalize(line));
//!         }
//!         // Read more data (cancel-safe)
//!         let n = self.stream.read(&mut temp_buf).await?;
//!         self.read_buffer.extend_from_slice(&temp_buf[..n]);
//!     }
//! }
//! ```
//!
//! ### Alternative Approach: Mutex + Channels
//!
//! ```rust,ignore
//! let proxy = Arc::new(Mutex::new(mcp_proxy));
//! tokio::spawn(async move {
//!     loop {
//!         let msg = proxy.lock().await.read_message().await?;
//!         tx.send(msg).await?;
//!     }
//! });
//! ```
//!
//! We rejected this because:
//! - More complex ownership model
//! - Extra tasks complicate error handling

use core::fmt;
use std::fmt::Debug;
use std::process::Stdio;
use std::time::Duration;

use anyhow::Context as _;
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt as _};
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
const FORWARD_FAILURE_CODE: f64 = -32099.0;

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

/// Error that can occur when sending a message.
#[derive(Debug)]
pub enum SendError {
    /// Fatal error - the proxy must stop as the connection is broken.
    Fatal {
        /// Optional error message to send back when a request ID is detected.
        message: Option<Message>,
        /// The underlying error for logging/debugging.
        source: anyhow::Error,
    },
    /// Transient error - the proxy can continue operating.
    Transient {
        /// Optional error message to send back when a request ID is detected.
        message: Option<Message>,
        /// The underlying error for logging/debugging.
        source: anyhow::Error,
    },
}

/// Error that can occur when reading a message.
#[derive(Debug)]
pub enum ReadError {
    /// Fatal error - the proxy must stop as the connection is broken.
    Fatal(anyhow::Error),
    /// Transient error - the proxy can continue operating.
    Transient(anyhow::Error),
}

enum InnerTransport {
    Http { url: String, agent: ureq::Agent },
    Process(ProcessMcpTransport),
    NamedPipe(NamedPipeMcpTransport),
}

impl McpProxy {
    pub async fn init(config: Config) -> anyhow::Result<Self> {
        let transport = match config.transport_mode {
            TransportMode::Http { url, timeout } => {
                let agent = ureq::AgentBuilder::new().timeout(timeout).build();
                InnerTransport::Http { url, agent }
            }
            TransportMode::SpawnProcess { command } => {
                let transport = ProcessMcpTransport::spawn(&command).await?;
                InnerTransport::Process(transport)
            }
            TransportMode::NamedPipe { pipe_path } => {
                let transport = NamedPipeMcpTransport::connect(&pipe_path).await?;
                InnerTransport::NamedPipe(transport)
            }
        };

        Ok(McpProxy { transport })
    }

    /// Send a message to the peer.
    ///
    /// For Process and NamedPipe transports, this method only writes the request.
    /// Use `read_message()` to read responses and peer-initiated messages.
    ///
    /// For HTTP transport, this method writes the request and immediately returns the response
    /// (since HTTP doesn't support concurrent reads and is strictly request/response oriented).
    // TODO(DGW-316): support for HTTP SSE (long polling) mode.
    pub async fn send_message(&mut self, message: &str) -> Result<Option<Message>, SendError> {
        trace!(message, "Outbound message");

        let message = message.trim();

        if message.is_empty() {
            debug!("Empty outbound message");
            return Ok(None);
        }

        // Try to parse as request first, then as response.
        let request_id = match JsonRpcMessage::parse(message) {
            Ok(request) => {
                match (request.id, request.method) {
                    (None, None) => {
                        warn!(
                            jsonrpc = request.jsonrpc,
                            "Sending a malformed JSON-RPC message (missing both `id` and `method`)"
                        )
                    }
                    (None, Some(method)) => {
                        debug!(jsonrpc = request.jsonrpc, method, "Sending a notification")
                    }
                    (Some(id), None) => debug!(jsonrpc = request.jsonrpc, id, "Sending a response"),
                    (Some(id), Some(method)) => debug!(jsonrpc = request.jsonrpc, method, id, "Sending a request"),
                };

                request.id
            }
            Err(error) => {
                // Not a JSON-RPC message, try best-effort ID extraction.
                let id = extract_id_best_effort(message);

                if let Some(id) = id {
                    warn!(error = format!("{error:#}"), id, "Sending a malformed JSON-RPC message");
                } else {
                    warn!(error = format!("{error:#}"), "Sending a malformed JSON-RPC message");
                }

                id
            }
        };

        let ret = match &mut self.transport {
            InnerTransport::Http { url, agent } => {
                // HTTP is request/response only - read the response immediately.

                // TODO(DGW-316): The HTTP transport actually support two modes.
                //   In one of them, we need to read the response immediately,
                //   and in the other we need to maintain a long-polling session,
                //   and we can likely rely on read_message() (needs investigation).

                let response_is_expected = request_id.is_some();

                match send_mcp_request_http(url, agent, message, response_is_expected).await {
                    Ok(response) => Ok(response.inspect(|msg| trace!(%msg, "Response from HTTP server"))),
                    Err(error) => {
                        // Because HTTP transport is not connection-based, HTTP errors are (currently) never fatal.
                        // We always "connect from scratch" for each message to forward.

                        error!(error = format!("{error:#}"), "Couldn't forward request");

                        let message = if let Some(id) = request_id {
                            let json_rpc_error_response = format!(
                                r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":{FORWARD_FAILURE_CODE},"message":"Forward failure: {error:#}"}}}}"#
                            );
                            Some(Message::normalize(json_rpc_error_response))
                        } else {
                            None
                        };

                        Err(SendError::Transient { message, source: error })
                    }
                }
            }
            InnerTransport::Process(stdio_mcp_transport) => {
                // Process transport: write only, read via read_message().
                handle_write_result(stdio_mcp_transport.write_request(message).await, request_id).map(|()| None)
            }
            InnerTransport::NamedPipe(named_pipe_mcp_transport) => {
                // NamedPipe transport: write only, read via read_message().
                handle_write_result(named_pipe_mcp_transport.write_request(message).await, request_id).map(|()| None)
            }
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

        fn handle_write_result(result: std::io::Result<()>, request_id: Option<i32>) -> Result<(), SendError> {
            match result {
                Ok(()) => Ok(()),
                Err(io_error) => {
                    // Classify the error.
                    if is_fatal_io_error(&io_error) {
                        let message = if let Some(id) = request_id {
                            let json_rpc_error_response = format!(
                                r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":{FORWARD_FAILURE_CODE},"message":"connection broken: {io_error}"}}}}"#
                            );
                            Some(Message::normalize(json_rpc_error_response))
                        } else {
                            None
                        };

                        Err(SendError::Fatal {
                            message,
                            source: anyhow::Error::new(io_error),
                        })
                    } else {
                        let message = if let Some(id) = request_id {
                            let json_rpc_error_response = format!(
                                r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":{FORWARD_FAILURE_CODE},"message":"Forward failure: {io_error}"}}}}"#
                            );
                            Some(Message::normalize(json_rpc_error_response))
                        } else {
                            None
                        };

                        Err(SendError::Transient {
                            message,
                            source: anyhow::Error::new(io_error),
                        })
                    }
                }
            }
        }
    }

    /// Read a message from the peer.
    ///
    /// This method blocks until a message is received from the peer.
    /// For HTTP transport, this method will never return (pending forever) as HTTP is request/response only.
    ///
    /// ## Cancel Safety
    ///
    /// This method is **cancel-safe** and can be used safely in `tokio::select!` branches.
    /// If the future is cancelled (e.g., when another branch in `select!` completes first),
    /// any partially-read data is preserved in an internal buffer and will be available
    /// on the next call.
    ///
    /// Example usage:
    /// ```rust,ignore
    /// loop {
    ///     tokio::select! {
    ///         // Both branches are cancel-safe
    ///         line = read_from_client() => { /* ... */ }
    ///         msg = proxy.read_message() => { /* ... */ }
    ///     }
    /// }
    /// ```
    pub async fn read_message(&mut self) -> Result<Message, ReadError> {
        let result = match &mut self.transport {
            InnerTransport::Http { .. } => {
                // HTTP transport doesn't support server-initiated messages.
                // This will never resolve, making it work correctly with tokio::select!.
                std::future::pending().await
            }
            InnerTransport::Process(stdio_mcp_transport) => stdio_mcp_transport.read_message().await,
            InnerTransport::NamedPipe(named_pipe_mcp_transport) => named_pipe_mcp_transport.read_message().await,
        };

        match result {
            Ok(message) => {
                trace!(%message, "Inbound message");
                Ok(message)
            }
            Err(io_error) => {
                if is_fatal_io_error(&io_error) {
                    Err(ReadError::Fatal(anyhow::Error::new(io_error)))
                } else {
                    Err(ReadError::Transient(anyhow::Error::new(io_error)))
                }
            }
        }
    }
}

/// Partial definition for a JSON-RPC message.
///
/// Could be a request, response or a notification, we do not need to distinguish that much in this module.
struct JsonRpcMessage {
    jsonrpc: String,        // Every JSON-RPC message have the jsonrpc field.
    id: Option<i32>,        // Requests and responses have an ID.
    method: Option<String>, // Requests and notifications have a method.
}

impl JsonRpcMessage {
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

        let method = obj.get("method").and_then(|v| v.get::<String>()).cloned();

        Ok(JsonRpcMessage { jsonrpc, id, method })
    }
}

struct ProcessMcpTransport {
    stdin: tokio::process::ChildStdin,
    stdout: tokio::process::ChildStdout,

    /// Internal buffer for cancel-safe line reading.
    /// Persists across `read_message()` calls to ensure data is not lost if the future is cancelled.
    read_buffer: Vec<u8>,

    // We use kill_on_drop, so we need to keep the Child alive as long as necessary.
    _process: Child,
}

impl ProcessMcpTransport {
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

        Ok(ProcessMcpTransport {
            _process: process,
            stdin,
            stdout,
            read_buffer: Vec::new(),
        })
    }

    async fn write_request(&mut self, request: &str) -> std::io::Result<()> {
        self.stdin.write_all(request.as_bytes()).await?;
        self.stdin.write_all(b"\n").await?;
        self.stdin.flush().await?;
        Ok(())
    }

    /// Read a complete message from the process stdout.
    ///
    /// This method is cancel-safe: it uses an internal buffer that persists across calls,
    /// so if the future is cancelled (e.g., in a `tokio::select!`), no data is lost.
    async fn read_message(&mut self) -> std::io::Result<Message> {
        loop {
            // Check if we have a complete line in the buffer (ends with '\n').
            if let Some(newline_pos) = self.read_buffer.iter().position(|&b| b == b'\n') {
                // Extract the line including the newline.
                let line_bytes: Vec<u8> = self.read_buffer.drain(..=newline_pos).collect();
                let line = String::from_utf8(line_bytes).map_err(std::io::Error::other)?;
                return Ok(Message::normalize(line));
            }

            // Need more data - read_buf from stdout (cancel-safe operation).
            let n = self.stdout.read_buf(&mut self.read_buffer).await?;

            if n == 0 {
                // EOF reached.
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed",
                ));
            }
        }
    }
}

struct NamedPipeMcpTransport {
    #[cfg(unix)]
    stream: tokio::net::UnixStream,
    #[cfg(windows)]
    stream: tokio::net::windows::named_pipe::NamedPipeClient,
    /// Internal buffer for cancel-safe line reading.
    /// Persists across `read_message()` calls to ensure data is not lost if the future is cancelled.
    read_buffer: Vec<u8>,
}

impl NamedPipeMcpTransport {
    async fn connect(pipe_path: &str) -> anyhow::Result<Self> {
        #[cfg(unix)]
        {
            let stream = tokio::net::UnixStream::connect(pipe_path)
                .await
                .with_context(|| format!("open Unix socket: {pipe_path}"))?;
            Ok(Self {
                stream,
                read_buffer: Vec::new(),
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
                stream,
                read_buffer: Vec::new(),
            })
        }

        #[cfg(not(any(unix, windows)))]
        {
            anyhow::bail!("named pipe transport is not supported on this platform")
        }
    }

    async fn write_request(&mut self, request: &str) -> std::io::Result<()> {
        #[cfg(any(unix, windows))]
        {
            self.stream.write_all(request.as_bytes()).await?;
            self.stream.write_all(b"\n").await?;
            Ok(())
        }

        #[cfg(not(any(unix, windows)))]
        {
            Err(std::io::Error::other(
                "named pipe transport is not supported on this platform",
            ))
        }
    }

    /// Read a complete message from the named pipe/unix socket.
    ///
    /// This method is cancel-safe: it uses an internal buffer that persists across calls,
    /// so if the future is cancelled (e.g., in a `tokio::select!`), no data is lost.
    async fn read_message(&mut self) -> std::io::Result<Message> {
        #[cfg(any(unix, windows))]
        {
            loop {
                // Check if we have a complete line in the buffer (ends with '\n').
                if let Some(newline_pos) = self.read_buffer.iter().position(|&b| b == b'\n') {
                    // Extract the line including the newline.
                    let line_bytes: Vec<u8> = self.read_buffer.drain(..=newline_pos).collect();
                    let line = String::from_utf8(line_bytes).map_err(std::io::Error::other)?;
                    return Ok(Message::normalize(line));
                }

                // Need more data - read_buf from stdout (cancel-safe operation).
                let n = self.stream.read_buf(&mut self.read_buffer).await?;

                if n == 0 {
                    // EOF reached.
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "connection closed",
                    ));
                }
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
    response_is_expected: bool,
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

    if !response_is_expected {
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
/// For process stdio and named pipe transports, these errors indicate the connection is permanently broken:
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
