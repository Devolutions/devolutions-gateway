use anyhow::{Context as _, Result};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// A fake MCP server for testing purposes that speaks HTTP/1.1 and implements
/// the Model Context Protocol 2025-06-18 specification using blocking I/O.
pub struct FakeMcpServer {
    listener: TcpListener,
    config: ServerConfig,
}

/// Configuration for the fake MCP server behavior
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
pub struct LoggingCapability {}

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

impl FakeMcpServer {
    /// Create a new fake MCP server with default configuration
    pub fn new() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        Ok(Self {
            listener,
            config: ServerConfig::default(),
        })
    }

    /// Create a new fake MCP server with custom configuration
    pub fn with_config(config: ServerConfig) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        Ok(Self { listener, config })
    }

    /// Get the local address the server is bound to
    pub fn local_addr(&self) -> SocketAddr {
        self.listener.local_addr().unwrap()
    }

    /// Get the HTTP URL for this server
    pub fn url(&self) -> String {
        format!("http://{}", self.local_addr())
    }

    /// Add a tool to the server
    pub fn add_tool(mut self, tool: Tool) -> Self {
        self.config.tools.push(tool);
        self
    }

    /// Add a resource to the server
    pub fn add_resource(mut self, resource: Resource) -> Self {
        self.config.resources.push(resource);
        self
    }

    /// Add a prompt to the server
    pub fn add_prompt(mut self, prompt: Prompt) -> Self {
        self.config.prompts.push(prompt);
        self
    }

    /// Set response delay for testing timeouts
    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.config.response_delay = Some(delay);
        self
    }

    /// Add an HTTP error response for a specific method
    pub fn add_http_error(mut self, method: String, error: HttpError) -> Self {
        self.config.error_responses.insert(method, error);
        self
    }

    /// Start the server and return a handle for control
    pub fn start(self) -> Result<ServerHandle> {
        let addr = self.listener.local_addr()?;
        let shutdown_flag = Arc::new(Mutex::new(false));
        let shutdown_flag_clone = shutdown_flag.clone();

        let handle = thread::spawn(move || {
            self.run_server(shutdown_flag_clone);
        });

        Ok(ServerHandle {
            addr,
            shutdown_flag,
            thread_handle: Some(handle),
        })
    }

    /// Main server loop
    fn run_server(self, shutdown_flag: Arc<Mutex<bool>>) {
        // Set non-blocking mode for accept operations
        if let Err(e) = self.listener.set_nonblocking(true) {
            eprintln!("Failed to set non-blocking mode: {}", e);
            return;
        }

        loop {
            // Check shutdown flag
            if let Ok(should_shutdown) = shutdown_flag.lock() {
                if *should_shutdown {
                    break;
                }
            }

            match self.listener.accept() {
                Ok((stream, _addr)) => {
                    let config = self.config.clone();
                    thread::spawn(move || {
                        if let Err(e) = Self::handle_connection(stream, config) {
                            eprintln!("Error handling connection: {e:#}");
                        }
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No connections available, sleep briefly
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(e) => {
                    eprintln!("Error accepting connection: {}", e);
                    break;
                }
            }
        }
    }

    /// Handle a single HTTP connection
    fn handle_connection(mut stream: TcpStream, config: ServerConfig) -> Result<()> {
        let mut reader = BufReader::new(&stream);

        // Read request line
        let mut request_line = String::new();
        reader.read_line(&mut request_line)?;

        if !request_line.starts_with("POST /") {
            // Send 405 Method Not Allowed
            let response = "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n";
            stream.write_all(response.as_bytes())?;
            return Ok(());
        }

        // Read headers
        let mut content_length = 0;
        let mut content_type = String::new();

        loop {
            let mut header_line = String::new();
            reader.read_line(&mut header_line)?;

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
            stream.write_all(response.as_bytes())?;
            return Ok(());
        }

        // Read body
        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body)?;
        let body_str = String::from_utf8(body)?;

        // Add response delay if configured
        if let Some(delay) = config.response_delay {
            thread::sleep(delay);
        }

        // Parse JSON-RPC request
        let json_request: serde_json::Value = serde_json::from_str(&body_str).context("parse request")?;

        // Process the MCP request
        let response = Self::process_mcp_request(&json_request, &config);
        let response_json = serde_json::to_string(&response)?;

        // Send HTTP response
        let http_response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {response_json}",
            response_json.len(),
        );

        stream.write_all(http_response.as_bytes())?;
        Ok(())
    }

    /// Process MCP JSON-RPC request
    fn process_mcp_request(request: &serde_json::Value, config: &ServerConfig) -> serde_json::Value {
        // Extract method from request
        let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("unknown");

        let id = request.get("id");

        // Check for configured HTTP errors
        if let Some(error) = config.error_responses.get(method) {
            return Self::create_error_response(id, error.status_code as i32, &error.body);
        }

        // Handle standard MCP methods
        match method {
            "initialize" => Self::handle_initialize(request, config, id),
            "tools/list" => Self::handle_tools_list(request, config, id),
            "tools/call" => Self::handle_tools_call(request, config, id),
            "resources/list" => Self::handle_resources_list(request, config, id),
            "prompts/list" => Self::handle_prompts_list(request, config, id),
            _ => Self::create_error_response(
                id,
                McpError::METHOD_NOT_FOUND,
                &format!("Method '{}' not found", method),
            ),
        }
    }

    /// Handle initialize request
    fn handle_initialize(
        _request: &serde_json::Value,
        config: &ServerConfig,
        id: Option<&serde_json::Value>,
    ) -> serde_json::Value {
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

        Self::create_success_response(id, result)
    }

    /// Handle tools/list request
    fn handle_tools_list(
        _request: &serde_json::Value,
        config: &ServerConfig,
        id: Option<&serde_json::Value>,
    ) -> serde_json::Value {
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

        Self::create_success_response(id, result)
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

            Self::create_success_response(id, result)
        } else {
            Self::create_error_response(
                id,
                McpError::METHOD_NOT_FOUND,
                &format!("Tool '{}' not found", tool_name),
            )
        }
    }

    /// Handle resources/list request
    fn handle_resources_list(
        _request: &serde_json::Value,
        config: &ServerConfig,
        id: Option<&serde_json::Value>,
    ) -> serde_json::Value {
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

        Self::create_success_response(id, result)
    }

    /// Handle prompts/list request
    fn handle_prompts_list(
        _request: &serde_json::Value,
        config: &ServerConfig,
        id: Option<&serde_json::Value>,
    ) -> serde_json::Value {
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

        Self::create_success_response(id, result)
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
}

/// Handle to control a running fake MCP server
pub struct ServerHandle {
    addr: SocketAddr,
    shutdown_flag: Arc<Mutex<bool>>,
    thread_handle: Option<thread::JoinHandle<()>>,
}

impl ServerHandle {
    /// Get the server's HTTP URL
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Get the server's socket address
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Shutdown the server gracefully
    pub fn shutdown(mut self) {
        // Set shutdown flag
        if let Ok(mut flag) = self.shutdown_flag.lock() {
            *flag = true;
        }

        // Wait for thread to finish
        if let Some(handle) = self.thread_handle.take() {
            handle.join().unwrap();
        }
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        // Set shutdown flag on drop
        if let Ok(mut flag) = self.shutdown_flag.lock() {
            *flag = true;
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            server_info: ServerInfo {
                name: "fake-mcp-server".to_string(),
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
