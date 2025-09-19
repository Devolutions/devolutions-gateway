use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use tokio::io::{AsyncBufReadExt, AsyncReadExt as _, AsyncWriteExt, BufReader};

#[dynosaur::dynosaur(pub DynMcpTransport = dyn(box) McpTransport)]
#[allow(unreachable_pub)] // false positive.
pub trait McpTransport: Send {
    fn accept_client(&mut self) -> impl Future<Output = anyhow::Result<Box<DynMcpPeer<'static>>>> + Send;
}

#[dynosaur::dynosaur(pub DynMcpPeer = dyn(box) McpPeer)]
#[allow(unreachable_pub)] // false positive.
pub trait McpPeer: Send {
    fn read_message(&mut self) -> impl Future<Output = anyhow::Result<String>> + Send;
    fn write_message(&mut self, message: &str) -> impl Future<Output = anyhow::Result<()>> + Send;
}

#[derive(Clone)]
pub struct McpShutdownSignal(Arc<tokio::sync::Notify>);

impl McpShutdownSignal {
    pub fn new() -> Self {
        Self(Arc::new(tokio::sync::Notify::new()))
    }

    pub fn shutdown(&self) {
        self.0.notify_one();
    }
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
    named_pipe: tokio::net::windows::named_pipe::NamedPipeServer,

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
            use tokio::net::windows::named_pipe::ServerOptions;

            let named_pipe = ServerOptions::new()
                .first_pipe_instance(true)
                .create(&name)
                .context("create named pipe")?;

            named_pipe.connect().await.context("named pipe connect")?;
        }
    }
}

impl McpTransport for NamedPipeTransport {
    async fn accept_client(&mut self) -> anyhow::Result<Box<DynMcpPeer<'static>>> {
        let (stream, _) = self.listener.accept().await.context("UNIX transport accept")?;

        Ok(DynMcpPeer::new_box(NamedPipePeer {
            stream: BufReader::new(stream),
        }))
    }
}

struct NamedPipePeer {
    #[cfg(unix)]
    stream: BufReader<tokio::net::UnixStream>,
    #[cfg(windows)]
    stream: BufReader<tokio::net::windows::named_pipe::NamedPipeServer>,
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

/// HTTP transport for MCP server.
pub struct HttpTransport {
    listener: tokio::net::TcpListener,
}

impl HttpTransport {
    /// Create a new HTTP transport.
    pub async fn bind() -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        Ok(Self { listener })
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
        }))
    }
}

struct HttpPeer {
    stream: BufReader<tokio::net::TcpStream>,
}

impl McpPeer for HttpPeer {
    async fn read_message(&mut self) -> anyhow::Result<String> {
        // Read request line.
        let mut request_line = String::new();
        self.stream.read_line(&mut request_line).await?;

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
                content_type = value.trim().to_string();
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

        Ok(message)
    }

    async fn write_message(&mut self, message: &str) -> anyhow::Result<()> {
        // Send HTTP response.
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
}

/// A MCP server for testing purposes that implements
/// the Model Context Protocol 2025-06-18 specification.
pub struct McpServer {
    transport: Box<DynMcpTransport<'static>>,
    config: ServerConfig,
}

/// Configuration for the MCP server behavior
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Server information returned in initialize response
    pub server_info: ServerInfo,
    /// Protocol version to advertise
    pub protocol_version: String,
    /// Server capabilities to advertise
    pub capabilities: ServerCapabilities,
    /// Available tools that can be listed/called
    pub tools: Vec<Tool>,
    /// Available resources that can be listed/read
    pub resources: Vec<Resource>,
    /// Available prompts that can be listed/used
    pub prompts: Vec<Prompt>,
    /// HTTP response delay simulation
    pub response_delay: Option<Duration>,
    /// Whether to return HTTP errors for certain requests
    pub error_responses: HashMap<String, HttpError>,
}

/// Server information metadata
#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

/// Server capabilities as per MCP spec
#[derive(Debug, Clone)]
pub struct ServerCapabilities {
    /// Whether server supports listing/reading resources
    pub resources: Option<ResourcesCapability>,
    /// Whether server supports listing/getting prompts
    pub prompts: Option<PromptsCapability>,
    /// Whether server supports listing/calling tools
    pub tools: Option<ToolsCapability>,
    /// Whether server supports logging
    pub logging: Option<LoggingCapability>,
}

#[derive(Debug, Clone)]
pub struct ResourcesCapability {
    pub subscribe: bool,
    pub list_changed: bool,
}

#[derive(Debug, Clone)]
pub struct PromptsCapability {
    pub list_changed: bool,
}

#[derive(Debug, Clone)]
pub struct ToolsCapability {
    pub list_changed: bool,
}

#[derive(Debug, Clone)]
pub struct LoggingCapability;

/// A tool that the server can execute
#[derive(Debug, Clone)]
pub struct Tool {
    pub name: String,
    pub description: Option<String>,
    pub input_schema: serde_json::Value,
}

/// A resource that the server provides
#[derive(Debug, Clone)]
pub struct Resource {
    pub uri: String,
    pub name: String,
    pub description: Option<String>,
    pub mime_type: Option<String>,
}

/// A prompt template that the server provides
#[derive(Debug, Clone)]
pub struct Prompt {
    pub name: String,
    pub description: Option<String>,
    pub arguments: Option<Vec<PromptArgument>>,
}

#[derive(Debug, Clone)]
pub struct PromptArgument {
    pub name: String,
    pub description: Option<String>,
    pub required: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            server_info: ServerInfo {
                name: "testsuite-mcp-server".to_string(),
                version: "1.0.0".to_string(),
            },
            protocol_version: "2025-06-18".to_string(),
            capabilities: ServerCapabilities {
                resources: Some(ResourcesCapability {
                    subscribe: false,
                    list_changed: false,
                }),
                prompts: Some(PromptsCapability { list_changed: false }),
                tools: Some(ToolsCapability { list_changed: false }),
                logging: None,
            },
            tools: Vec::new(),
            resources: Vec::new(),
            prompts: Vec::new(),
            response_delay: None,
            error_responses: HashMap::new(),
        }
    }
}

/// MCP protocol errors
#[derive(Debug, Clone)]
pub struct McpError {
    pub code: i32,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

/// HTTP-level errors for testing error conditions
#[derive(Debug, Clone)]
pub struct HttpError {
    pub status_code: u16,
    pub body: String,
}

/// Tool execution result
#[derive(Debug, Clone)]
pub struct ToolResult {
    pub content: Vec<ToolContent>,
    pub is_error: bool,
}

#[derive(Debug, Clone)]
pub struct ToolContent {
    pub content_type: String,
    pub text: String,
}

impl McpServer {
    /// Create a new MCP server with the given transport
    pub fn new(transport: Box<DynMcpTransport<'static>>) -> Self {
        Self {
            transport,
            config: ServerConfig::default(),
        }
    }

    /// Create a new MCP server with custom configuration
    pub fn with_config(mut self, config: ServerConfig) -> Self {
        self.config = config;
        self
    }

    /// Add a tool to the server
    pub fn with_tool(mut self, tool: Tool) -> Self {
        self.config.tools.push(tool);
        self
    }

    /// Add a resource to the server
    pub fn with_resource(mut self, resource: Resource) -> Self {
        self.config.resources.push(resource);
        self
    }

    /// Add a prompt to the server
    pub fn with_prompt(mut self, prompt: Prompt) -> Self {
        self.config.prompts.push(prompt);
        self
    }

    /// Set response delay for testing timeouts
    pub fn with_response_delay(mut self, delay: Duration) -> Self {
        self.config.response_delay = Some(delay);
        self
    }

    /// Add an HTTP error response for a specific method
    pub fn with_http_error(mut self, method: String, error: HttpError) -> Self {
        self.config.error_responses.insert(method, error);
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
                        let config = self.config.clone();
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
                let response = process_mcp_request(&request, config);
                let response = serde_json::to_string(&response).unwrap();
                peer.write_message(&response).await.context("write peer request")?;
            }
            _ = shutdown_signal.0.notified() => {
                return Ok(());
            }
        }
    }
}

/// Process MCP JSON-RPC request.
fn process_mcp_request(request: &str, config: &ServerConfig) -> serde_json::Value {
    let request = match serde_json::Value::from_str(request) {
        Ok(request) => request,
        Err(error) => {
            return create_error_response(
                None,
                McpError::INVALID_REQUEST,
                &format!("invalid JSON-RPC format: {error:#}"),
            );
        }
    };

    // Extract method from request.
    let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("unknown");

    let id = request.get("id");

    // Check for configured HTTP errors.
    if let Some(error) = config.error_responses.get(method) {
        return create_error_response(id, error.status_code as i32, &error.body);
    }

    // Handle standard MCP methods.
    match method {
        "initialize" => handle_initialize(config, id),
        "tools/list" => handle_tools_list(config, id),
        "tools/call" => handle_tools_call(&request, config, id),
        "resources/list" => handle_resources_list(config, id),
        "prompts/list" => handle_prompts_list(config, id),
        _ => create_error_response(id, McpError::METHOD_NOT_FOUND, &format!("Method '{method}' not found")),
    }
}

/// Handle initialize request.
fn handle_initialize(config: &ServerConfig, id: Option<&serde_json::Value>) -> serde_json::Value {
    let result = serde_json::json!({
        "protocolVersion": config.protocol_version,
        "capabilities": {
            "resources": config.capabilities.resources.as_ref().map(|r| serde_json::json!({
                "subscribe": r.subscribe,
                "listChanged": r.list_changed
            })),
            "tools": config.capabilities.tools.as_ref().map(|t| serde_json::json!({
                "listChanged": t.list_changed
            })),
            "prompts": config.capabilities.prompts.as_ref().map(|p| serde_json::json!({
                "listChanged": p.list_changed
            })),
            "logging": config.capabilities.logging.as_ref().map(|_| serde_json::json!({}))
        },
        "serverInfo": {
            "name": config.server_info.name,
            "version": config.server_info.version
        }
    });

    create_success_response(id, result)
}

/// Handle tools/list request.
fn handle_tools_list(config: &ServerConfig, id: Option<&serde_json::Value>) -> serde_json::Value {
    let tools: Vec<serde_json::Value> = config
        .tools
        .iter()
        .map(|tool| {
            serde_json::json!({
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.input_schema
            })
        })
        .collect();

    let result = serde_json::json!({
        "tools": tools
    });

    create_success_response(id, result)
}

/// Handle tools/call request
fn handle_tools_call(
    request: &serde_json::Value,
    config: &ServerConfig,
    id: Option<&serde_json::Value>,
) -> serde_json::Value {
    let params = request.get("params");
    let tool_name = params
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("");

    // Find the tool
    if let Some(tool) = config.tools.iter().find(|t| t.name == tool_name) {
        // Execute tool based on its name (simple implementations for testing)
        let result = match tool.name.as_str() {
            "echo" => {
                let message = params
                    .and_then(|p| p.get("arguments"))
                    .and_then(|a| a.get("message"))
                    .and_then(|m| m.as_str())
                    .unwrap_or("no message");

                serde_json::json!({
                    "content": [{
                        "type": "text",
                        "text": message
                    }],
                    "isError": false
                })
            }
            "calculator" => {
                let args = params.and_then(|p| p.get("arguments"));
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

                serde_json::json!({
                    "content": [{
                        "type": "text",
                        "text": result.to_string()
                    }],
                    "isError": false
                })
            }
            _ => {
                serde_json::json!({
                    "content": [{
                        "type": "text",
                        "text": format!("Tool '{tool_name}' executed successfully")
                    }],
                    "isError": false
                })
            }
        };

        create_success_response(id, result)
    } else {
        create_error_response(
            id,
            McpError::METHOD_NOT_FOUND,
            &format!("Tool '{}' not found", tool_name),
        )
    }
}

/// Handle resources/list request
fn handle_resources_list(config: &ServerConfig, id: Option<&serde_json::Value>) -> serde_json::Value {
    let resources: Vec<serde_json::Value> = config
        .resources
        .iter()
        .map(|resource| {
            serde_json::json!({
                "uri": resource.uri,
                "name": resource.name,
                "description": resource.description,
                "mimeType": resource.mime_type
            })
        })
        .collect();

    let result = serde_json::json!({
        "resources": resources
    });

    create_success_response(id, result)
}

/// Handle prompts/list request
fn handle_prompts_list(config: &ServerConfig, id: Option<&serde_json::Value>) -> serde_json::Value {
    let prompts: Vec<serde_json::Value> = config
        .prompts
        .iter()
        .map(|prompt| {
            serde_json::json!({
                "name": prompt.name,
                "description": prompt.description,
                "arguments": prompt.arguments.as_ref().map(|args| {
                    args.iter().map(|arg| serde_json::json!({
                        "name": arg.name,
                        "description": arg.description,
                        "required": arg.required
                    })).collect::<Vec<_>>()
                })
            })
        })
        .collect();

    let result = serde_json::json!({
        "prompts": prompts
    });

    create_success_response(id, result)
}

/// Create success response
fn create_success_response(id: Option<&serde_json::Value>, result: serde_json::Value) -> serde_json::Value {
    let mut response = serde_json::json!({
        "jsonrpc": "2.0",
        "result": result
    });

    if let Some(id_val) = id {
        response["id"] = id_val.clone();
    }

    response
}

/// Create error response
fn create_error_response(id: Option<&serde_json::Value>, code: i32, message: &str) -> serde_json::Value {
    let mut response = serde_json::json!({
        "jsonrpc": "2.0",
        "error": {
            "code": code,
            "message": message
        }
    });

    if let Some(id_val) = id {
        response["id"] = id_val.clone();
    }

    response
}

impl McpError {
    /// Standard JSON-RPC error codes
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;

    /// Create a method not found error
    pub fn method_not_found(method: &str) -> Self {
        Self {
            code: Self::METHOD_NOT_FOUND,
            message: format!("Method '{}' not found", method),
            data: None,
        }
    }

    /// Create an invalid params error
    pub fn invalid_params(message: &str) -> Self {
        Self {
            code: Self::INVALID_PARAMS,
            message: message.to_string(),
            data: None,
        }
    }
}

// Convenience builders for common scenarios

impl Tool {
    /// Create a simple echo tool that returns its input
    pub fn echo() -> Self {
        Self {
            name: "echo".to_string(),
            description: Some("Echo back the input".to_string()),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "message": {"type": "string"}
                },
                "required": ["message"]
            }),
        }
    }

    /// Create a simple math calculator tool
    pub fn calculator() -> Self {
        Self {
            name: "calculator".to_string(),
            description: Some("Perform basic math operations".to_string()),
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
}

impl Resource {
    /// Create a simple text resource
    pub fn text(uri: &str, name: &str, _content: &str) -> Self {
        Self {
            uri: uri.to_string(),
            name: name.to_string(),
            description: Some(format!("Text resource: {}", name)),
            mime_type: Some("text/plain".to_string()),
        }
    }
}

impl Prompt {
    /// Create a simple greeting prompt
    pub fn greeting() -> Self {
        Self {
            name: "greeting".to_string(),
            description: Some("Generate a greeting message".to_string()),
            arguments: Some(vec![PromptArgument {
                name: "name".to_string(),
                description: Some("Name to greet".to_string()),
                required: true,
            }]),
        }
    }
}
