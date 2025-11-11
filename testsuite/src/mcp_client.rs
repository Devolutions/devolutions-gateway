use std::pin::Pin;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt as _, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

// TODO(DGW-315): Support for concurrent write/read with request ID tracking.

/// A MCP client for testing purposes that can communicate over
/// any AsyncRead/AsyncWrite stream (stdin/stdout, TCP, pipes, etc.).
pub struct McpClient {
    reader: BufReader<Pin<Box<dyn AsyncRead>>>,
    writer: Pin<Box<dyn AsyncWrite>>,
    config: ClientConfig,
    next_id: u64,
}

/// Configuration for the MCP client.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Client information to send during initialize.
    pub client_info: ClientInfo,
    /// Protocol version to advertise.
    pub protocol_version: String,
}

impl ClientConfig {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_name(mut self, name: &'static str) -> Self {
        self.client_info.name = name;
        self
    }

    #[must_use]
    pub fn with_version(mut self, version: &'static str) -> Self {
        self.client_info.version = version;
        self
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            client_info: ClientInfo {
                name: "testsuite-mcp-client",
                version: "1.0.0",
            },
            protocol_version: "2025-06-18".to_owned(),
        }
    }
}

/// Client information metadata.
#[derive(Debug, Clone, Serialize)]
pub struct ClientInfo {
    pub name: &'static str,
    pub version: &'static str,
}

/// JSON-RPC request.
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

/// JSON-RPC response.
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

/// Initialize response result.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    pub protocol_version: String,
    pub capabilities: serde_json::Value,
    pub server_info: serde_json::Value,
}

/// Tools list response.
#[derive(Debug, Clone, Deserialize)]
pub struct ToolsListResult {
    pub tools: Vec<serde_json::Value>,
}

/// Tool call parameters.
#[derive(Debug, Clone, Serialize)]
pub struct ToolCallParams {
    pub name: String,
    pub arguments: serde_json::Value,
}

impl ToolCallParams {
    /// Create tool call parameters for echo tool
    pub fn echo(message: &str) -> Self {
        Self {
            name: "echo".to_owned(),
            arguments: serde_json::json!({"message": message}),
        }
    }

    /// Create tool call parameters for calculator tool
    pub fn calculate(operation: &str, a: f64, b: f64) -> Self {
        Self {
            name: "calculator".to_owned(),
            arguments: serde_json::json!({
                "operation": operation,
                "a": a,
                "b": b
            }),
        }
    }
}

/// Tool call result.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolCallResult {
    pub content: Vec<serde_json::Value>,
    pub is_error: Option<bool>,
}

impl McpClient {
    /// Create a new MCP client with separate reader and writer.
    pub fn new(reader: Pin<Box<dyn AsyncRead>>, writer: Pin<Box<dyn AsyncWrite>>) -> Self {
        Self {
            reader: BufReader::new(reader),
            writer,
            config: ClientConfig::default(),
            next_id: 1,
        }
    }

    /// Configure the client with custom settings.
    #[must_use]
    pub fn with_config(mut self, config: ClientConfig) -> Self {
        self.config = config;
        self
    }

    /// Connect to the MCP server and perform initialization handshake using the configured settings.
    pub async fn connect(&mut self) -> Result<InitializeResult> {
        self.initialize().await
    }

    /// Send a raw JSON-RPC request and get response
    async fn send_request(&mut self, request: JsonRpcRequest) -> Result<JsonRpcResponse> {
        // Serialize request to JSON
        let mut request = serde_json::to_string(&request)?;
        request.push('\n');

        // Write request as line.
        self.writer.write_all(request.as_bytes()).await?;
        self.writer.flush().await?;

        // Read response line.
        let mut response_line = String::new();
        self.reader.read_line(&mut response_line).await?;

        if response_line.trim().is_empty() {
            anyhow::bail!("empty response");
        }

        // Parse JSON response.
        let response: JsonRpcResponse =
            serde_json::from_str(response_line.trim()).with_context(|| format!("parse response: {response_line:?}"))?;
        Ok(response)
    }

    /// Internal helper to send an initialize request.
    async fn initialize(&mut self) -> Result<InitializeResult> {
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_owned(),
            id: Some(self.next_id()),
            method: "initialize".to_owned(),
            params: Some(serde_json::json!({
                "protocol_version": self.config.protocol_version.clone(),
                "client_info": self.config.client_info.clone(),
            })),
        };

        let response = self.send_request(request).await?;
        if let Some(error) = response.error {
            anyhow::bail!("JSON-RPC error {}: {}", error.code, error.message);
        }

        let result = response.result.context("missing result in response")?;
        Ok(serde_json::from_value(result)?)
    }

    /// List available tools.
    pub async fn list_tools(&mut self) -> Result<ToolsListResult> {
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_owned(),
            id: Some(self.next_id()),
            method: "tools/list".to_owned(),
            params: None,
        };

        let response = self.send_request(request).await?;
        if let Some(error) = response.error {
            anyhow::bail!("JSON-RPC error {}: {}", error.code, error.message);
        }

        let result = response
            .result
            .ok_or_else(|| anyhow::anyhow!("missing result in response"))?;
        Ok(serde_json::from_value(result)?)
    }

    /// Call a tool.
    pub async fn call_tool(&mut self, params: ToolCallParams) -> Result<ToolCallResult> {
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_owned(),
            id: Some(self.next_id()),
            method: "tools/call".to_owned(),
            params: Some(serde_json::to_value(params)?),
        };

        let response = self.send_request(request).await?;
        if let Some(error) = response.error {
            anyhow::bail!("JSON-RPC error {}: {}", error.code, error.message);
        }

        let result = response
            .result
            .ok_or_else(|| anyhow::anyhow!("Missing result in response"))?;
        Ok(serde_json::from_value(result)?)
    }

    /// Send a notification (no response expected).
    pub async fn send_notification(
        &mut self,
        method: impl Into<String>,
        params: Option<serde_json::Value>,
    ) -> Result<()> {
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_owned(),
            id: None, // Notifications have no ID.
            method: method.into(),
            params,
        };

        // Serialize request to JSON.
        let mut request = serde_json::to_string(&request)?;
        request.push('\n');

        // Write request as line.
        self.writer.write_all(request.as_bytes()).await?;
        self.writer.flush().await?;

        Ok(())
    }

    /// Get next request ID.
    fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}
