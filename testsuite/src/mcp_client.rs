use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read, Write};

/// A fake MCP client for testing purposes that can communicate over
/// any Read/Write stream (stdin/stdout, TCP, pipes, etc.)
pub struct FakeMcpClient {
    reader: BufReader<Box<dyn Read>>,
    writer: Box<dyn Write>,
    config: ClientConfig,
    next_id: u64,
}

/// Configuration for the fake MCP client
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Client information to send during initialize
    pub client_info: ClientInfo,
    /// Protocol version to advertise
    pub protocol_version: String,
    /// Client capabilities to advertise
    pub capabilities: ClientCapabilities,
}

/// Client information metadata
#[derive(Debug, Clone, Serialize)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
}

/// Client capabilities as per MCP spec
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientCapabilities {
    /// Whether client supports sampling (letting server initiate actions)
    pub sampling: Option<SamplingCapability>,
    /// Whether client supports roots (filesystem/URI boundaries)
    pub roots: Option<RootsCapability>,
    /// Whether client supports elicitation (requesting additional user info)
    pub elicitation: Option<ElicitationCapability>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SamplingCapability {}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RootsCapability {
    pub list_changed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ElicitationCapability {}

/// JSON-RPC request
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<u64>,
    pub method: String,
    pub params: Option<serde_json::Value>,
}

/// JSON-RPC response
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Option<u64>,
    pub result: Option<serde_json::Value>,
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC error
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

/// Initialize request parameters
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeParams {
    pub protocol_version: String,
    pub capabilities: ClientCapabilities,
    pub client_info: ClientInfo,
}

/// Initialize response result
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    pub protocol_version: String,
    pub capabilities: serde_json::Value, // ServerCapabilities
    pub server_info: serde_json::Value,  // ServerInfo
}

/// Tools list response
#[derive(Debug, Clone, Deserialize)]
pub struct ToolsListResult {
    pub tools: Vec<serde_json::Value>,
}

/// Tool call parameters
#[derive(Debug, Clone, Serialize)]
pub struct ToolCallParams {
    pub name: String,
    pub arguments: serde_json::Value,
}

/// Tool call result
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolCallResult {
    pub content: Vec<serde_json::Value>,
    pub is_error: Option<bool>,
}

impl FakeMcpClient {
    /// Create a new fake MCP client with separate reader and writer
    pub fn new(reader: Box<dyn Read>, writer: Box<dyn Write>) -> Self {
        Self {
            reader: BufReader::new(reader),
            writer,
            config: ClientConfig::default(),
            next_id: 1,
        }
    }

    /// Configure the client with custom settings
    pub fn with_config(mut self, config: ClientConfig) -> Self {
        self.config = config;
        self
    }

    /// Connect to the MCP server and perform initialization handshake using the configured settings
    pub fn connect(&mut self) -> Result<InitializeResult> {
        let params = InitializeParams {
            protocol_version: self.config.protocol_version.clone(),
            capabilities: self.config.capabilities.clone(),
            client_info: self.config.client_info.clone(),
        };
        self.initialize(params)
    }

    /// Send a raw JSON-RPC request and get response
    fn send_request(&mut self, request: JsonRpcRequest) -> Result<JsonRpcResponse> {
        // Serialize request to JSON
        let json_body = serde_json::to_string(&request)?;

        // Write request as line
        writeln!(self.writer, "{json_body}")?;
        self.writer.flush()?;

        // Read response line
        let mut response_line = String::new();
        self.reader.read_line(&mut response_line)?;

        if response_line.trim().is_empty() {
            anyhow::bail!("empty response");
        }

        // Parse JSON response
        let response: JsonRpcResponse = serde_json::from_str(response_line.trim()).context("parse response")?;
        Ok(response)
    }

    /// Internal helper to send an initialize request
    fn initialize(&mut self, params: InitializeParams) -> Result<InitializeResult> {
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(self.next_id()),
            method: "initialize".to_string(),
            params: Some(serde_json::to_value(params)?),
        };

        let response = self.send_request(request)?;
        if let Some(error) = response.error {
            anyhow::bail!("JSON-RPC error {}: {}", error.code, error.message);
        }

        let result = response
            .result
            .ok_or_else(|| anyhow::anyhow!("missing result in response"))?;
        Ok(serde_json::from_value(result)?)
    }

    /// List available tools
    pub fn list_tools(&mut self) -> Result<ToolsListResult> {
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(self.next_id()),
            method: "tools/list".to_string(),
            params: None,
        };

        let response = self.send_request(request)?;
        if let Some(error) = response.error {
            anyhow::bail!("JSON-RPC error {}: {}", error.code, error.message);
        }

        let result = response
            .result
            .ok_or_else(|| anyhow::anyhow!("missing result in response"))?;
        Ok(serde_json::from_value(result)?)
    }

    /// Call a tool
    pub fn call_tool(&mut self, params: ToolCallParams) -> Result<ToolCallResult> {
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(self.next_id()),
            method: "tools/call".to_string(),
            params: Some(serde_json::to_value(params)?),
        };

        let response = self.send_request(request)?;
        if let Some(error) = response.error {
            anyhow::bail!("JSON-RPC error {}: {}", error.code, error.message);
        }

        let result = response
            .result
            .ok_or_else(|| anyhow::anyhow!("Missing result in response"))?;
        Ok(serde_json::from_value(result)?)
    }

    /// Send a notification (no response expected)
    pub fn send_notification(&mut self, method: String, params: Option<serde_json::Value>) -> Result<()> {
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: None, // Notifications have no ID
            method,
            params,
        };

        // Serialize request to JSON
        let json_body = serde_json::to_string(&request)?;

        // Write request as line
        writeln!(self.writer, "{}", json_body)?;
        self.writer.flush()?;

        Ok(())
    }

    /// Get next request ID
    fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            client_info: ClientInfo {
                name: "fake-mcp-client".to_string(),
                version: "1.0.0".to_string(),
            },
            protocol_version: "2025-06-18".to_string(),
            capabilities: ClientCapabilities {
                sampling: None,
                roots: Some(RootsCapability { list_changed: false }),
                elicitation: None,
            },
        }
    }
}

// Convenience constructors for common scenarios

impl InitializeParams {
    /// Create minimal initialize parameters
    pub fn minimal() -> Self {
        Self {
            protocol_version: "2025-06-18".to_string(),
            capabilities: ClientCapabilities {
                sampling: None,
                roots: None,
                elicitation: None,
            },
            client_info: ClientInfo {
                name: "test-client".to_string(),
                version: "1.0.0".to_string(),
            },
        }
    }
}

impl ToolCallParams {
    /// Create tool call parameters for echo tool
    pub fn echo(message: &str) -> Self {
        Self {
            name: "echo".to_string(),
            arguments: serde_json::json!({"message": message}),
        }
    }

    /// Create tool call parameters for calculator tool
    pub fn calculate(operation: &str, a: f64, b: f64) -> Self {
        Self {
            name: "calculator".to_string(),
            arguments: serde_json::json!({
                "operation": operation,
                "a": a,
                "b": b
            }),
        }
    }
}
