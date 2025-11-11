use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use tokio::io::{AsyncBufReadExt, AsyncReadExt as _, AsyncWriteExt, BufReader};

// TODO(DGW-315): Add support for sending unsolicited messages.

const ERROR_CODE_INVALID_REQUEST: i32 = -32600;
const ERROR_CODE_METHOD_NOT_FOUND: i32 = -32601;
const ERROR_CODE_INVALID_PARAMS: i32 = -32602;

#[dynosaur::dynosaur(pub DynMcpTransport = dyn(box) McpTransport)]
#[allow(unreachable_pub)] // false positive.
pub trait McpTransport: Send + Sync {
    fn accept_client(&mut self) -> impl Future<Output = anyhow::Result<Box<DynMcpPeer<'static>>>> + Send;
}

#[dynosaur::dynosaur(pub DynMcpPeer = dyn(box) McpPeer)]
#[allow(unreachable_pub)] // false positive.
pub trait McpPeer: Send + Sync {
    fn read_message(&mut self) -> impl Future<Output = anyhow::Result<String>> + Send;
    fn write_message(&mut self, message: &str) -> impl Future<Output = anyhow::Result<()>> + Send;
    fn no_response(&mut self) -> impl Future<Output = anyhow::Result<()>> + Send {
        async { Ok(()) }
    }
}

/// A tool that the server can execute
pub trait McpTool: Send + Sync {
    fn name(&self) -> &'static str;
    fn descriptor(&self) -> ToolDescriptor;
    fn call(&self, params: serde_json::Value) -> ToolResult;
}

pub trait McpNotificationHandler: Send + Sync {
    fn handle(&self, method: &str, params: serde_json::Value);
}

impl<F> McpNotificationHandler for F
where
    F: Send + Sync + Fn(&str, serde_json::Value),
{
    fn handle(&self, method: &str, params: serde_json::Value) {
        (self)(method, params)
    }
}

#[derive(Clone)]
pub struct McpShutdownSignal(Arc<tokio::sync::Notify>);

impl Default for McpShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

impl McpShutdownSignal {
    pub fn new() -> Self {
        Self(Arc::new(tokio::sync::Notify::new()))
    }

    pub fn shutdown(&self) {
        self.0.notify_one();
    }
}

impl Drop for McpShutdownSignal {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// A MCP server for testing purposes that implements
/// the Model Context Protocol 2025-06-18 specification.
pub struct McpServer {
    transport: Box<DynMcpTransport<'static>>,
    config: Arc<ServerConfig>,
}

/// Configuration for the MCP server behavior
pub struct ServerConfig {
    /// Server information returned in initialize response.
    pub server_info: ServerInfo,
    /// Available tools that can be listed/called.
    pub tools: Vec<Box<dyn McpTool>>,
    /// Response delay simulation.
    pub response_delay: Option<Duration>,
    /// Notification handler.
    pub notification_handler: Option<Box<dyn McpNotificationHandler>>,
}

/// Server information metadata.
#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub name: &'static str,
    pub version: &'static str,
}

/// Describes the tool.
#[derive(Debug, Clone)]
pub struct ToolDescriptor {
    pub description: Option<&'static str>,
    pub input_schema: serde_json::Value,
}

impl ServerConfig {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_name(mut self, name: &'static str) -> Self {
        self.server_info.name = name;
        self
    }

    #[must_use]
    pub fn with_version(mut self, version: &'static str) -> Self {
        self.server_info.version = version;
        self
    }

    #[must_use]
    pub fn with_tool(mut self, tool: impl McpTool + 'static) -> Self {
        self.tools.push(Box::new(tool));
        self
    }

    #[must_use]
    pub fn with_response_delay(mut self, delay: Duration) -> Self {
        self.response_delay = Some(delay);
        self
    }

    #[must_use]
    pub fn with_notification_handler(mut self, handler: impl McpNotificationHandler + 'static) -> Self {
        self.notification_handler = Some(Box::new(handler));
        self
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            server_info: ServerInfo {
                name: "testsuite-mcp-server",
                version: "1.0.0",
            },
            tools: Vec::new(),
            response_delay: None,
            notification_handler: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ToolResult {
    pub content: Vec<ToolContent>,
    pub is_error: bool,
}

#[derive(Debug, Clone)]
pub enum ToolContent {
    Text(String),
}

impl McpServer {
    /// Create a new MCP server with the given transport
    pub fn new(transport: Box<DynMcpTransport<'static>>) -> Self {
        Self {
            transport,
            config: Arc::new(ServerConfig::default()),
        }
    }

    #[must_use]
    pub fn with_config(mut self, config: ServerConfig) -> Self {
        self.config = Arc::new(config);
        self
    }

    /// Start the server and return a handle for control
    pub fn start(self) -> anyhow::Result<McpShutdownSignal> {
        let shutdown_signal = McpShutdownSignal::new();

        tokio::spawn({
            let shutdown_signal = shutdown_signal.clone();
            async move {
                eprintln!("[MCP-SERVER] spawn task after.");
                if let Err(e) = self.run(shutdown_signal).await {
                    eprintln!("[MCP-SERVER] Error running the MCP server: {e:#}");
                }
            }
        });

        Ok(shutdown_signal)
    }

    pub async fn run(mut self, shutdown_signal: McpShutdownSignal) -> anyhow::Result<()> {
        eprintln!("[MCP-SERVER] Running.");

        loop {
            eprintln!("[MCP-SERVER] Wait for peer...");
            tokio::select! {
                peer = self.transport.accept_client() => {
                    let peer = peer.context("accept peer")?;

                    tokio::spawn({
                        let shutdown_signal = shutdown_signal.clone();
                        let config = Arc::clone(&self.config);
                        async move {
                            if let Err(e) = handle_peer(peer, shutdown_signal, &config).await {
                                eprintln!("[MCP-SERVER] Error handling connection: {e:#}");
                            }
                        }
                    });
                }
                _ = shutdown_signal.0.notified() => {
                    return Ok(());
                }
            }
        }
    }
}

async fn handle_peer(
    mut peer: Box<DynMcpPeer<'static>>,
    shutdown_signal: McpShutdownSignal,
    config: &ServerConfig,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            request = peer.read_message() => {
                let request = request.context("read peer request")?;
                let response = process_mcp_request(config, &request);
                if let Some(response) = response {
                    let response = serde_json::to_string(&response).unwrap();
                    peer.write_message(&response).await.context("write peer request")?;
                } else {
                    peer.no_response().await.context("notify no response")?;
                }
            }
            _ = shutdown_signal.0.notified() => {
                return Ok(());
            }
        }
    }
}

/// Process MCP JSON-RPC request.
fn process_mcp_request(config: &ServerConfig, request: &str) -> Option<serde_json::Value> {
    let request: Request<'_> = match serde_json::from_str(request) {
        Ok(request) => request,
        Err(error) => {
            return Some(serde_json::json!({
                "jsonrpc": "2.0",
                "error": {
                    "code": ERROR_CODE_INVALID_REQUEST,
                    "message": format!("invalid JSON-RPC format: {error:#}")
                }
            }));
        }
    };

    match request.id {
        Some(id) => {
            let response = match request.method {
                "initialize" => handle_initialize(config, id),
                "tools/list" => handle_tools_list(config, id),
                "tools/call" => handle_tools_call(config, id, request.params),
                _ => create_error_response(
                    id,
                    ERROR_CODE_METHOD_NOT_FOUND,
                    format!("Method '{}' not found", request.method),
                ),
            };

            return Some(response);
        }
        None => {
            eprintln!("[MCP-SERVER] Received notification: {}", request.method);

            if let Some(handler) = &config.notification_handler {
                handler.handle(request.method, request.params);
            }

            return None;
        }
    }

    #[derive(serde::Deserialize)]
    struct Request<'a> {
        method: &'a str,
        id: Option<u64>,
        #[serde(default)]
        params: serde_json::Value,
    }
}

fn handle_initialize(config: &ServerConfig, id: u64) -> serde_json::Value {
    let result = serde_json::json!({
        "protocolVersion": "2025-06-18",
        "serverInfo": {
            "name": config.server_info.name,
            "version": config.server_info.version
        },
        "capabilities": {
            "tools": {
                "listChanged": false,
            },
        },
    });

    create_success_response(id, result)
}

fn handle_tools_list(config: &ServerConfig, id: u64) -> serde_json::Value {
    let tools: Vec<serde_json::Value> = config
        .tools
        .iter()
        .map(|tool| {
            let name = tool.name();
            let descriptor = tool.descriptor();

            serde_json::json!({
                "name": name,
                "description": descriptor.description,
                "inputSchema": descriptor.input_schema
            })
        })
        .collect();

    let result = serde_json::json!({
        "tools": tools
    });

    create_success_response(id, result)
}

fn handle_tools_call(config: &ServerConfig, id: u64, params: serde_json::Value) -> serde_json::Value {
    let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");

    let Some(tool) = config.tools.iter().find(|tool| tool.name() == tool_name) else {
        return create_error_response(id, ERROR_CODE_INVALID_PARAMS, format!("Tool '{tool_name}' not found"));
    };

    let tool_result = tool.call(params);

    let result = serde_json::json!({
        "content": tool_result.content.into_iter().map(|content| match content {
            ToolContent::Text(text) => serde_json::json!({
                "type": "text",
                "text": text,
            }),
        }).collect::<Vec<_>>(),
        "isError": tool_result.is_error,
    });

    create_success_response(id, result)
}

fn create_success_response(id: u64, result: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })
}

fn create_error_response(id: u64, code: i32, message: String) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    })
}

/// Named pipe transport for MCP server.
///
/// Cannot handle more than one peer at once on Windows.
pub struct NamedPipeTransport {
    #[cfg(unix)]
    listener: tokio::net::UnixListener,
    #[cfg(unix)]
    _tempdir: tempfile::TempDir,

    #[cfg(windows)]
    used: Arc<std::sync::atomic::AtomicBool>,
    #[cfg(windows)]
    notify_ready: Arc<tokio::sync::Notify>,

    name: String,
}

impl NamedPipeTransport {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn bind() -> anyhow::Result<Self> {
        #[cfg(unix)]
        {
            let tempdir = tempfile::tempdir().context("create temporary directory for Unix socket")?;
            let path = tempdir.path().join("mcp.sock");
            let listener = tokio::net::UnixListener::bind(&path).context("failed to bind UNIX listener")?;
            let name = path.into_os_string().into_string().unwrap();

            Ok(Self {
                listener,
                name,
                _tempdir: tempdir,
            })
        }

        #[cfg(windows)]
        {
            let name = format!("dgw-testsuite-{}", fastrand::u64(..));
            let used = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let notify_ready = Arc::new(tokio::sync::Notify::new());

            Ok(Self {
                used,
                notify_ready,
                name,
            })
        }
    }
}

impl McpTransport for NamedPipeTransport {
    async fn accept_client(&mut self) -> anyhow::Result<Box<DynMcpPeer<'static>>> {
        #[cfg(unix)]
        {
            let (stream, _) = self.listener.accept().await.context("UNIX transport accept")?;

            Ok(DynMcpPeer::new_box(NamedPipePeer {
                stream: BufReader::new(stream),
            }))
        }

        #[cfg(windows)]
        {
            use tokio::net::windows::named_pipe::ServerOptions;

            loop {
                let used = self.used.swap(true, std::sync::atomic::Ordering::SeqCst);

                if used {
                    self.notify_ready.notified().await;
                } else {
                    break;
                }
            }

            let addr = format!(r"\\.\pipe\{}", self.name);

            let named_pipe = ServerOptions::new()
                .first_pipe_instance(true)
                .create(&addr)
                .context("create named pipe")?;

            named_pipe.connect().await.context("named pipe connect")?;

            Ok(DynMcpPeer::new_box(NamedPipePeer {
                stream: BufReader::new(named_pipe),
                used: Arc::clone(&self.used),
                notify_ready: Arc::clone(&self.notify_ready),
            }))
        }
    }
}

struct NamedPipePeer {
    #[cfg(unix)]
    stream: BufReader<tokio::net::UnixStream>,

    #[cfg(windows)]
    stream: BufReader<tokio::net::windows::named_pipe::NamedPipeServer>,
    #[cfg(windows)]
    used: Arc<std::sync::atomic::AtomicBool>,
    #[cfg(windows)]
    notify_ready: Arc<tokio::sync::Notify>,
}

impl McpPeer for NamedPipePeer {
    async fn read_message(&mut self) -> anyhow::Result<String> {
        let mut message = String::new();
        self.stream
            .read_line(&mut message)
            .await
            .context("read named pipe message")?;
        Ok(message)
    }

    async fn write_message(&mut self, message: &str) -> anyhow::Result<()> {
        self.stream.write_all(message.as_bytes()).await?;
        self.stream.write_all(b"\n").await?;
        self.stream.flush().await?;
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for NamedPipePeer {
    fn drop(&mut self) {
        self.used.store(false, std::sync::atomic::Ordering::SeqCst);
        self.notify_ready.notify_one();
    }
}

/// HTTP transport for MCP server.
pub struct HttpTransport {
    listener: tokio::net::TcpListener,
    error_responses: Vec<(String, HttpError)>,
}

/// HTTP-level errors for testing error conditions
#[derive(Clone)]
pub struct HttpError {
    pub status_code: u16,
    pub body: String,
}

impl HttpTransport {
    /// Create a new HTTP transport.
    pub async fn bind() -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        Ok(Self {
            listener,
            error_responses: Vec::new(),
        })
    }

    #[must_use]
    pub fn with_error_response(mut self, substring: impl Into<String>, http_error: HttpError) -> Self {
        self.error_responses.push((substring.into(), http_error));
        self
    }

    /// Get the HTTP URL for this transport.
    pub fn url(&self) -> String {
        format!("http://{}", self.local_addr())
    }

    /// Get the local address the transport is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.listener.local_addr().unwrap()
    }
}

impl McpTransport for HttpTransport {
    async fn accept_client(&mut self) -> anyhow::Result<Box<DynMcpPeer<'static>>> {
        let (stream, _) = self.listener.accept().await.context("HTTP transport accept")?;

        Ok(DynMcpPeer::new_box(HttpPeer {
            stream: BufReader::new(stream),
            error_responses: self.error_responses.clone(),
        }))
    }
}

struct HttpPeer {
    stream: BufReader<tokio::net::TcpStream>,
    error_responses: Vec<(String, HttpError)>,
}

impl McpPeer for HttpPeer {
    async fn read_message(&mut self) -> anyhow::Result<String> {
        // Read request line.
        let mut request_line = String::new();

        while request_line.is_empty() {
            self.stream.read_line(&mut request_line).await?;
        }

        if !request_line.starts_with("POST /") {
            // Send 405 Method Not Allowed
            let response = "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n";
            self.stream.write_all(response.as_bytes()).await?;
            anyhow::bail!("invalid method");
        }

        // Read headers.
        let mut content_length = 0;
        let mut content_type = String::new();

        loop {
            let mut header_line = String::new();
            self.stream.read_line(&mut header_line).await?;

            if header_line.trim().is_empty() {
                break; // End of headers
            }

            if let Some(value) = header_line.strip_prefix("Content-Length: ") {
                content_length = value.trim().parse::<usize>().unwrap_or(0);
            } else if let Some(value) = header_line.strip_prefix("Content-Type: ") {
                content_type = value.trim().to_owned();
            }
        }

        if !content_type.contains("application/json") {
            let response = "HTTP/1.1 415 Unsupported Media Type\r\nConnection: close\r\n\r\n";
            self.stream.write_all(response.as_bytes()).await?;
            anyhow::bail!("unsupported media type");
        }

        // Read body / message.
        let mut body = vec![0u8; content_length];
        self.stream.read_exact(&mut body).await?;
        let message = String::from_utf8(body)?;

        // Check for simulated error responses.
        for (substring, http_error) in &self.error_responses {
            if message.contains(substring) {
                let response = format!(
                    "HTTP/1.1 {}\r\nConnection: close\r\n\r\n{}",
                    http_error.status_code, http_error.body
                );
                self.stream.write_all(response.as_bytes()).await?;
                anyhow::bail!("simulated error");
            }
        }

        Ok(message)
    }

    async fn write_message(&mut self, message: &str) -> anyhow::Result<()> {
        let http_response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {message}",
            message.len(),
        );

        self.stream.write_all(http_response.as_bytes()).await?;

        Ok(())
    }

    // We need to send a response for the HTTP transport, even if empty.
    async fn no_response(&mut self) -> anyhow::Result<()> {
        let http_response = "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: 0\r\n\
             Connection: close\r\n\
             \r\n";

        self.stream.write_all(http_response.as_bytes()).await?;

        Ok(())
    }
}

pub struct EchoTool;

impl McpTool for EchoTool {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            description: Some("Echo back the input"),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "message": {"type": "string"}
                },
                "required": ["message"]
            }),
        }
    }

    fn call(&self, params: serde_json::Value) -> ToolResult {
        let message = params
            .get("arguments")
            .and_then(|a| a.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or("");

        ToolResult {
            content: vec![ToolContent::Text(message.to_owned())],
            is_error: false,
        }
    }
}

pub struct CalculatorTool;

impl McpTool for CalculatorTool {
    fn name(&self) -> &'static str {
        "calculator"
    }

    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            description: Some("Perform basic math operations"),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "operation": {"type": "string", "enum": ["add", "subtract", "multiply", "divide"]},
                    "a": {"type": "number"},
                    "b": {"type": "number"}
                },
                "required": ["operation", "a", "b"]
            }),
        }
    }

    fn call(&self, params: serde_json::Value) -> ToolResult {
        let args = params.get("arguments");
        let operation = args
            .and_then(|a| a.get("operation"))
            .and_then(|o| o.as_str())
            .unwrap_or("");
        let a = args.and_then(|a| a.get("a")).and_then(|n| n.as_f64()).unwrap_or(0.0);
        let b = args.and_then(|a| a.get("b")).and_then(|n| n.as_f64()).unwrap_or(0.0);

        let result = match operation {
            "add" => a + b,
            "subtract" => a - b,
            "multiply" => a * b,
            "divide" => {
                if b != 0.0 {
                    a / b
                } else {
                    f64::NAN
                }
            }
            _ => f64::NAN,
        };

        ToolResult {
            content: vec![ToolContent::Text(result.to_string())],
            is_error: false,
        }
    }
}
